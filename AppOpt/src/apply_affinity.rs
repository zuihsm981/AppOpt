use std::fs;
use std::io::Write as _;
use std::os::unix::fs::FileExt;

use crate::{MAX_PKG_LEN, MAX_THREAD_LEN};
use crate::config::AppConfig;
use crate::cpuset::{base_cpuset, CpuSet, CpuTopology};
use crate::rule_match::comm_to_pkg;

/// 调试日志: 同时输出到 stderr 和 /data/local/tmp/appopt_debug.log
/// (文件方式可靠, 不受 AppOpt 启动方式影响; stderr 仅前台终端可见)
macro_rules! kpm_log {
    ($($arg:tt)*) => {{
        let msg = format!($($arg)*);
        eprintln!("{}", msg);
        use std::io::Write as _;
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open("/data/local/tmp/appopt_debug.log")
        {
            let _ = f.write_all(msg.as_bytes());
            let _ = f.write_all(b"\n");
        }
    }};
}

/// 栈上构建 /proc/{pid}/{suffix} 路径读取文件
fn read_proc_file<'a>(pid: i32, suffix: &str, buf: &'a mut [u8]) -> Option<&'a [u8]> {
    let mut path = [0u8; 32];
    let mut cur = std::io::Cursor::new(&mut path[..]);
    write!(cur, "/proc/{}/{}", pid, suffix).ok()?;
    let len = cur.position() as usize;
    let path_str = std::str::from_utf8(&path[..len]).ok()?;
    let file = fs::File::open(path_str).ok()?;
    let n = file.read_at(buf, 0).ok()?;
    (n > 0).then_some(&buf[..n])
}

pub(crate) fn read_cmdline(pid: i32) -> Option<String> {
    let mut buf = [0u8; MAX_PKG_LEN];
    let bytes = read_proc_file(pid, "cmdline", &mut buf)?;
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    let cmdline = std::str::from_utf8(&bytes[..end]).ok()?;
    let name = cmdline.rsplit('/').next().unwrap_or(cmdline);
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(trimmed.to_string())
}

pub(crate) fn tid_comm(tid: i32) -> Option<String> {
    let mut buf = [0u8; MAX_THREAD_LEN];
    let bytes = read_proc_file(tid, "comm", &mut buf)?;
    let end = bytes
        .iter()
        .position(|&b| b == 0 || b == b'\n')
        .unwrap_or(bytes.len());
    let name = std::str::from_utf8(&bytes[..end]).ok()?;
    Some(name.trim().to_string())
}

pub(crate) fn task_tids(pid: i32) -> Option<Vec<i32>> {
    let mut path_buf = [0u8; 32];
    let mut cur = std::io::Cursor::new(&mut path_buf[..]);
    write!(cur, "/proc/{}/task", pid).ok()?;
    let len = cur.position() as usize;
    let task_path = std::str::from_utf8(&path_buf[..len]).unwrap();
    let task_dir = fs::read_dir(task_path).ok()?;
    Some(
        task_dir
            .flatten()
            .filter_map(|tent| tent.file_name().to_string_lossy().parse::<i32>().ok())
            .collect(),
    )
}

/// 对单线程应用亲和性，返回 true 表示 ESRCH 线程已退出
/// 顺序: 先放置 cpuset (归属), 再设置亲和性 (掩码)。
/// cpuset 写入始终执行 (确保归属, 首次 EINVAL 时后续 RENAME 可重试);
/// 亲和性已正确则跳过 sched_setaffinity (避免重复 syscall)。
pub fn affinity_set(
    tid: i32,
    cpus: &CpuSet,
    cpuset_dir: &str,
    topo: &CpuTopology,
) -> bool {
    let affinity_ok = CpuSet::get_affinity(tid).is_some_and(|curr| curr == *cpus);
    // 先放置 cpuset (把任务移入 AppOpt 子 cpuset, 始终执行)
    if topo.cpuset_enabled {
        let tasks_path = if cpuset_dir.is_empty() {
            format!("{}/tasks", base_cpuset())
        } else {
            format!("{}/{}/tasks", base_cpuset(), cpuset_dir)
        };
        // 构造待写入数据: tid + 换行 (cpuset tasks 文件格式)
        let data = format!("{}\n", tid);
        kpm_log!("cpuset-> '{}' data='{}'", tasks_path, data.trim_end());
        match fs::OpenOptions::new().append(true).open(&tasks_path) {
            Ok(mut f) => {
                if let Err(e) = f.write_all(data.as_bytes()) {
                    kpm_log!("cpuset! FAIL '{}' data='{}' errno={}", tasks_path, data.trim_end(), e.raw_os_error().unwrap_or(-1));
                } else {
                    kpm_log!("cpuset! OK  '{}' data='{}'", tasks_path, data.trim_end());
                }
            }
            Err(e) => {
                kpm_log!("cpuset! OPENFAIL '{}' errno={}", tasks_path, e.raw_os_error().unwrap_or(-1));
            }
        }
    } else {
        kpm_log!("cpuset! disabled cpus={}", cpus.to_range_string());
    }
    // 再设置 CPU 亲和性 (已正确则跳过)
    if !affinity_ok {
        if let Err(e) = cpus.set_affinity(tid) {
            kpm_log!("aff! tid={} sched_setaffinity ERR errno={}", tid, e.raw_os_error().unwrap_or(-1));
            return e.raw_os_error() == Some(libc::ESRCH);
        }
        kpm_log!("aff! tid={} sched_setaffinity OK cpus={}", tid, cpus.to_range_string());
    } else {
        kpm_log!("aff! tid={} already ok cpus={}", tid, cpus.to_range_string());
    }
    false
}

/// 遍历 /proc 匹配目标进程，返回 匹配数与总进程数
pub(crate) fn proc_walk(
    cfg: &AppConfig,
    filter: impl Fn(i32) -> bool,
    mut f: impl FnMut(i32, &str, bool),
) -> (usize, i32) {
    let Some(entries) = fs::read_dir("/proc").ok() else { return (0, 0) };
    let mut count = 0;
    let mut total: i32 = 0;
    for entry in entries.flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<i32>() else { continue };
        total += 1;
        if !filter(pid) { continue; }
        /* 用 comm_to_pkg 匹配: 支持 cmdline 精确匹配 + 子进程(pkg:suffix) + 截断 comm 前缀/后缀回退 */
        let comm = tid_comm(pid).unwrap_or_default();
        let Some(pkg) = comm_to_pkg(pid, &comm, cfg) else { continue };
        f(pid, &pkg, cfg.has_thread_rules.contains(&pkg));
        count += 1;
    }
    (count, total)
}
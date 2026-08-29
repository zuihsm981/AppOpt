use std::fs;
use std::io::Write as _;
use std::os::unix::fs::FileExt;

use crate::{MAX_PKG_LEN, MAX_THREAD_LEN};
use crate::config::AppConfig;
use crate::cpuset::{base_cpuset, CpuSet, CpuTopology};
use crate::rule_match::comm_to_pkg;

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
pub fn affinity_set(
    tid: i32,
    cpus: &CpuSet,
    cpuset_dir: &str,
    topo: &CpuTopology,
) -> bool {
    // sched_getaffinity 短路，已符合目标零开销返回
    if let Some(curr) = CpuSet::get_affinity(tid)
        && curr == *cpus {
            eprintln!("KPM affinity_set: tid={} already ok cpus={}", tid, cpus.to_range_string());
            return false;
        }
    if topo.cpuset_enabled {
        let tasks_path = if cpuset_dir.is_empty() {
            format!("{}/tasks", base_cpuset())
        } else {
            format!("{}/{}/tasks", base_cpuset(), cpuset_dir)
        };
        match fs::OpenOptions::new().append(true).open(&tasks_path) {
            Ok(mut f) => {
                if let Err(e) = writeln!(f, "{}", tid) {
                    eprintln!("KPM affinity_set: tid={} cpuset '{}' WRITE FAIL: {}", tid, tasks_path, e);
                } else {
                    eprintln!("KPM affinity_set: tid={} cpuset '{}' OK", tid, tasks_path);
                }
            }
            Err(e) => {
                eprintln!("KPM affinity_set: tid={} cpuset '{}' OPEN FAIL: {}", tid, tasks_path, e);
            }
        }
    } else {
        eprintln!("KPM affinity_set: tid={} cpuset_enabled=false cpus={}", tid, cpus.to_range_string());
    }
    if let Err(e) = cpus.set_affinity(tid) {
        eprintln!("KPM affinity_set: tid={} sched_setaffinity ERR {} (ESRCH={})", tid, e, e.raw_os_error() == Some(libc::ESRCH));
        return e.raw_os_error() == Some(libc::ESRCH);
    }
    eprintln!("KPM affinity_set: tid={} sched_setaffinity OK cpus={}", tid, cpus.to_range_string());
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
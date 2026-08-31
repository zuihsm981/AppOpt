use std::fs;
use std::os::unix::fs::FileExt;

use crate::{MAX_PKG_LEN, MAX_THREAD_LEN};
use crate::config::AppConfig;
use crate::cpuset::{CpuSet, CpuTopology};
use crate::rule_match::comm_to_pkg;

/// 栈上构建 /proc/{pid}/{suffix} 路径读取文件
fn read_proc_file<'a>(pid: i32, suffix: &str, buf: &'a mut [u8]) -> Option<&'a [u8]> {
    // 使用 format! 动态构建路径，避免固定缓冲区溢出的风险
    let path = format!("/proc/{}/{}", pid, suffix);
    let file = fs::File::open(&path).ok()?;
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
    // 使用 format! 动态构建路径
    let task_path = format!("/proc/{}/task", pid);
    let task_dir = fs::read_dir(&task_path).ok()?;
    Some(
        task_dir
            .flatten()
            .filter_map(|tent| tent.file_name().to_string_lossy().parse::<i32>().ok())
            .collect(),
    )
}

/// 对单线程设置 CPU 亲和性 (仅 sched_setaffinity; 不再写入 cpuset)。
/// 返回 true 表示 ESRCH 线程已退出。
/// 亲和性已正确则跳过 sched_setaffinity (避免重复 syscall)。
pub fn affinity_set(
    tid: i32,
    cpus: &CpuSet,
    _cpuset_dir: &str,
    _topo: &CpuTopology,
) -> bool {
    let affinity_ok = CpuSet::get_affinity(tid).is_some_and(|curr| curr == *cpus);
    // 只设置 CPU 亲和性 (已正确则跳过)
    if !affinity_ok {
        if let Err(e) = cpus.set_affinity(tid) {
            return e.raw_os_error() == Some(libc::ESRCH);
        }
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
        /* 用 comm_to_pkg 匹配: 完整包名/子进程走内存快速路径，截断 comm 才校验 cmdline */
        let comm = tid_comm(pid).unwrap_or_default();
        let Some(pkg) = comm_to_pkg(pid, &comm, cfg) else { continue };
        f(pid, &pkg, cfg.has_thread_rules.contains(&pkg));
        count += 1;
    }
    (count, total)
}
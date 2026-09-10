use std::fs;
use std::io::Write;
use std::os::unix::fs::FileExt;

use crate::{MAX_PKG_LEN, MAX_THREAD_LEN};
use crate::cpuset::{base_cpuset, CpuSet, CpuTopology};

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

/// cpuset tasks 路径 (cpuset_dir 为空 → base 目录)
fn cpuset_tasks_path(cpuset_dir: &str) -> String {
    if cpuset_dir.is_empty() {
        format!("{}/tasks", base_cpuset())
    } else {
        format!("{}/{}/tasks", base_cpuset(), cpuset_dir)
    }
}

/// 对单线程设置 CPU 亲和性。
/// use_cpuset 由调用方在「每个应用一次」的粒度上读取 (本应用全部线程共用),
/// 避免逐线程查全局开关; true = 先写 tasks 迁移 cpuset 再 sched_setaffinity,
/// false (默认) = 仅 sched_setaffinity (不写 cpuset)。
/// 返回 true 表示 ESRCH 线程已退出。
pub fn affinity_set(
    tid: i32,
    cpus: &CpuSet,
    cpuset_dir: &str,
    topo: &CpuTopology,
    use_cpuset: bool,
) -> bool {
    // 亲和性已正确 → 直接成功返回 (避免重复 syscall)
    if CpuSet::get_affinity(tid).is_some_and(|curr| curr == *cpus) {
        return false;
    }

    // 设置项开启: 先迁移 cpuset (写 tasks, 由 cpuset 控制器接管调度域)
    if use_cpuset
        && topo.cpuset_enabled
        && let Ok(mut f) = fs::OpenOptions::new().append(true).open(cpuset_tasks_path(cpuset_dir))
    {
        let _ = writeln!(f, "{}", tid);
    }

    // sched_setaffinity 收紧到目标核
    if let Err(e) = cpus.set_affinity(tid) {
        return e.raw_os_error() == Some(libc::ESRCH);
    }
    false
}

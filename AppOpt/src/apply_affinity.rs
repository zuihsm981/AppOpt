use std::fs;
use std::io::Write;
use std::os::unix::fs::FileExt;

use crate::{MAX_PKG_LEN, MAX_THREAD_LEN};
use crate::cpuset::{CpuSet, CpuTopology};

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

/// 对单线程设置 CPU 亲和性。
/// tasks_path 为该线程所属 cpuset 的 tasks 文件完整路径 (由调用方按目录缓存,
/// 避免每次拼接 + 读 base_cpuset)。
/// cpuset_enabled 时: 先写 tasks 迁移 cpuset, 再 sched_setaffinity;
/// 亲和性已正确则直接返回 (不写 cpuset, 也不重复设 cpus)。
/// 返回 true 表示 ESRCH 线程已退出。
pub fn affinity_set(tid: i32, cpus: &CpuSet, tasks_path: &str, topo: &CpuTopology) -> bool {
    // 亲和性已正确 → 直接成功返回 (不设置 cpuset, 避免重复 syscall)
    if CpuSet::get_affinity(tid).is_some_and(|curr| curr == *cpus) {
        return false;
    }
    // cpuset 启用: 先写 tasks 迁移 cpuset (由 cpuset 控制器接管调度域)
    if topo.cpuset_enabled {
        let _ = fs::OpenOptions::new()
            .append(true)
            .open(tasks_path)
            .and_then(|mut f| writeln!(f, "{}", tid));
    }
    // sched_setaffinity 收紧到目标核
    if let Err(e) = cpus.set_affinity(tid) {
        return e.raw_os_error() == Some(libc::ESRCH);
    }
    false
}

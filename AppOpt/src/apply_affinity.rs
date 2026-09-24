use std::fs;
use std::os::unix::fs::FileExt;

use crate::{MAX_PKG_LEN, MAX_THREAD_LEN};

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
/// 内核 struct sched_attr 的 Rust 布局镜像 (uapi/linux/sched.h), #[repr(C)] 保证
/// 字段顺序/对齐与内核一致, 直接作为 sched_setattr syscall 参数。注意: 内核
/// SCHED_ATTR_SIZE_VER0 = 48B 是不含 util 字段的旧版本; 本结构含
/// sched_util_min/max (5.3+), size 字段运行时取 size_of::<SchedAttr>() = 56。
#[derive(Default)]
#[repr(C)]
struct SchedAttr {
    size: u32,
    sched_policy: u32,
    sched_flags: u64,
    sched_nice: i32,
    sched_priority: u32,
    sched_runtime: u64,
    sched_deadline: u64,
    sched_period: u64,
    sched_util_min: u32,
    sched_util_max: u32,
}

/// 设置线程 uclamp (sched_util_min/max, 0..=1024) via sched_setattr。
/// flags = SCHED_FLAG_UTIL_CLAMP (0x60): 只更新 uclamp, 不动调度策略/参数。
/// 内核需 CONFIG_UCLAMP_TASK; 失败静默 (uclamp 是增强, 不影响亲和性,
/// 调用方不关心成败 —— 返回 () 而非 bool)。
pub fn set_uclamp(tid: i32, util_min: i32, util_max: i32) {
    if util_min < 0 && util_max < 0 {
        return;
    }
    const SCHED_FLAG_UTIL_CLAMP: u64 = 0x60; // MIN(0x20) | MAX(0x40)
    // size = 56 (含 sched_util_min/max 字段; 内核 5.3+ 才支持该字段, 4.19 无)
    let attr = SchedAttr {
        size: std::mem::size_of::<SchedAttr>() as u32,
        sched_flags: SCHED_FLAG_UTIL_CLAMP,
        sched_util_min: util_min.clamp(0, 1024) as u32,
        sched_util_max: util_max.clamp(0, 1024) as u32,
        ..Default::default()
    };
    let _ = unsafe { libc::syscall(libc::SYS_sched_setattr, tid, &attr as *const SchedAttr, 0) };
}

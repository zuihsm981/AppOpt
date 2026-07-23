use std::ffi::CString;
use std::sync::atomic::{AtomicBool, AtomicI32};
use std::sync::Mutex;

pub const BASE_CPUSET: &str = "/dev/cpuset/AppOpt";
pub const MAX_PKG_LEN: usize = 128;
pub const MAX_THREAD_LEN: usize = 32;
pub const CPU_SETSIZE: usize = 1024;
pub const CPU_WORD_BITS: usize = 64;
pub const CPU_WORDS: usize = CPU_SETSIZE / CPU_WORD_BITS;

#[allow(dead_code)]
pub const EBPF_EVENT_FORK: u32 = 1;
pub const EBPF_EVENT_EXEC: u32 = 2;

pub const DEAD_CLEANUP_INTERVAL: i64 = 15;

pub static CONFIG_UPDATED: AtomicBool = AtomicBool::new(false);
pub static INOTIFY_SUPPORTED: AtomicBool = AtomicBool::new(false);
pub static INOTIFY_FD: AtomicI32 = AtomicI32::new(-1);
pub static INOTIFY_WD: AtomicI32 = AtomicI32::new(-1);

/// POSIX fnmatch 封装，需预转换为 CString
pub fn fnmatch_c(pattern: &CString, string: &str) -> bool {
    const BUF_LEN: usize = 32;
    if string.len() >= BUF_LEN {
        return false;
    }
    let mut buf = [0u8; BUF_LEN];
    buf[..string.len()].copy_from_slice(string.as_bytes());
    unsafe { libc::fnmatch(pattern.as_ptr(), buf.as_ptr() as *const _, libc::FNM_NOESCAPE) == 0 }
}

/// 获取 Mutex 锁
pub fn lock_ignore_poison<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| {
        eprintln!("警告: 互斥锁中毒，尝试恢复...");
        e.into_inner()
    })
}

/// 单调时钟
pub fn current_time_secs() -> i64 {
    let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec as i64
}

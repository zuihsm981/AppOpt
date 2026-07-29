use std::ffi::CString;
use std::sync::atomic::{AtomicBool, AtomicI32};
use std::sync::{Mutex, OnceLock};

/// BASE_CPUSET 运行时路径，未设置时默认 /dev/cpuset/AppOpt
static BASE_CPUSET_PATH: OnceLock<String> = OnceLock::new();

pub const DEFAULT_CPUSET_NAME: &str = "AppOpt";
pub const MAX_PKG_LEN: usize = 128;
pub const MAX_THREAD_LEN: usize = 32;
pub const CPU_SETSIZE: usize = 1024;
pub const CPU_WORD_BITS: usize = 64;
pub const CPU_WORDS: usize = CPU_SETSIZE / CPU_WORD_BITS;

/// 设置 BASE_CPUSET 目录名，name 为空或含 / 时使用默认值
pub fn set_base_cpuset(name: &str) {
    if name.is_empty() || name.contains('/') {
        return;
    }
    let path = format!("/dev/cpuset/{}", name);
    let _ = BASE_CPUSET_PATH.set(path);
}

/// 获取 BASE_CPUSET 路径，未设置返回默认值
pub fn base_cpuset() -> &'static str {
    BASE_CPUSET_PATH
        .get()
        .map(|s| s.as_str())
        .unwrap_or("/dev/cpuset/AppOpt")
}

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

pub fn lock_ignore_poison<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| {
        eprintln!("警告: 互斥锁中毒，尝试恢复...");
        e.into_inner()
    })
}


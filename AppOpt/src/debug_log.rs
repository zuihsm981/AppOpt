//! 调试日志：追加写入 /data/local/tmp/appopt_debug.log。
//! 多线程（binder 线程池 / RefreshRate 线程 / 主线程）并发调用，
//! 依赖 O_APPEND 单次 write 原子性保证不交错。日志点应保持低频。

use std::ffi::CString;
use std::sync::atomic::{AtomicI32, Ordering};

static LOG_FD: AtomicI32 = AtomicI32::new(-1);

/// 打开日志文件（追加模式）。可重复调用，重复打开无害。
pub fn init_debug_log() {
    if LOG_FD.load(Ordering::Acquire) >= 0 {
        return;
    }
    let path = CString::new("/data/local/tmp/appopt_debug.log").unwrap();
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_APPEND | libc::O_CLOEXEC,
            0o644,
        )
    };
    if fd >= 0 {
        LOG_FD.store(fd, Ordering::Release);
    }
}

/// 输出一行日志：`[<monotonic_ms>] <msg>\n`。fd 未初始化时静默丢弃。
pub fn debug_log(msg: &str) {
    let fd = LOG_FD.load(Ordering::Acquire);
    if fd < 0 {
        return;
    }
    // 单调时钟毫秒，避免每次取系统时间（且无需 UTC 转换）
    let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
    unsafe {
        libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts);
    }
    let ms = (ts.tv_sec as i64) * 1000 + (ts.tv_nsec as i64) / 1_000_000;
    let mut line = String::with_capacity(msg.len() + 32);
    line.push('[');
    line.push_str(&ms.to_string());
    line.push_str("ms] ");
    line.push_str(msg);
    line.push('\n');
    let bytes = line.as_bytes();
    unsafe {
        let _ = libc::write(fd, bytes.as_ptr() as *const libc::c_void, bytes.len());
    }
}

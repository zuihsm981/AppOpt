//! 用户态进程退出监听 (仅 4.19 用户态模式启用, 替代内核 EXIT 事件):
//! 使用 pidfd_open(pid) (Android 4.19/6.6 内核均有) 关联内核 struct pid,
//! 进程退出即 epoll 唤醒, 防 PID 复用误判。纯用户态、事件驱动、零轮询、
//! 零内核模块。watch() 由主线程在 EV_FG 冷启动时为规则应用主 pid 注册;
//! 退出时经 socketpair 通知主线程清理该 uid 身份。pidfd_open 不可用时跳过
//! (退出清理由既有周期 /proc 扫描兜底)。

use std::collections::HashMap;
use std::ffi::CString;
use std::os::raw::c_int;
use std::sync::{Mutex, OnceLock};

/// 已注册 pid → 监听 fd (watch/事件清理共用)
static REG: Mutex<HashMap<i32, c_int>> = Mutex::new(HashMap::new());
/// epoll fd (由 spawn_exit 创建后设置)
static EPFD: OnceLock<Mutex<c_int>> = OnceLock::new();

fn set_epfd(fd: c_int) {
    let _ = EPFD.set(Mutex::new(fd));
}

fn reg_lock() -> std::sync::MutexGuard<'static, HashMap<i32, c_int>> {
    REG.lock().unwrap_or_else(|e| e.into_inner())
}

/// 退出监听日志: eprintln + /data/local/tmp/appopt_exit.log
fn elog(msg: &str) {
    use std::io::Write;
    eprintln!("[exit_probe] {}", msg);
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open("/data/local/tmp/appopt_exit.log")
    {
        let _ = writeln!(f, "[{:?}] {}", std::time::SystemTime::now(), msg);
    }
}

/// 为规则应用主 pid 注册退出监听 (幂等)。仅用户态模式由调用方按 KPM_ACTIVE 门控。
pub fn watch(pid: i32) {
    if pid <= 0 {
        return;
    }
    if reg_lock().contains_key(&pid) {
        return;
    }
    let Some(epfd) = EPFD.get() else { return }; // epoll 未就绪, 跳过 (下次枚举再注册)

    // 仅用 pidfd_open (syscall 434): 不可用 (ENOSYS) 则跳过注册
    let fd = unsafe { libc::syscall(434, pid, 0) as c_int };
    if fd < 0 {
        return;
    }
    let mut ev: libc::epoll_event = unsafe { std::mem::zeroed() };
    ev.events = (libc::EPOLLIN | libc::EPOLLHUP | libc::EPOLLERR) as u32;
    ev.u64 = pid as u64;
    if unsafe { libc::epoll_ctl(*epfd.lock().unwrap_or_else(|e| e.into_inner()), libc::EPOLL_CTL_ADD, fd, &mut ev) } == 0 {
        reg_lock().insert(pid, fd);
        elog(&format!("watch pid={} fd={}", pid, fd));
    } else {
        unsafe { libc::close(fd); }
    }
}

/// 退出监听线程入口。sock 为 socketpair 写端, pid 退出时 send pid (i32 LE 4B)。
pub fn spawn_exit(sock: c_int) {
    let name = CString::new("ExitProbe").unwrap();
    unsafe { libc::pthread_setname_np(libc::pthread_self(), name.as_ptr()); }

    let epfd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
    if epfd < 0 {
        return;
    }
    set_epfd(epfd);

    let mut events: [libc::epoll_event; 32] = unsafe { std::mem::zeroed() };
    loop {
        let n = unsafe { libc::epoll_wait(epfd, events.as_mut_ptr(), 32, -1) };
        if n < 0 {
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            break;
        }
        for i in 0..n as usize {
            let pid = events[i].u64 as i32;
            if pid <= 0 {
                continue;
            }
            // 移除并关闭监听 fd
            let fd = reg_lock().remove(&pid);
            if let Some(fd) = fd {
                unsafe { libc::close(fd); }
            }
            // 通知主线程: pid 已退出 → 清理该 uid 身份
            elog(&format!("exited pid={}", pid));
            let bytes = pid.to_ne_bytes();
            let _ = unsafe {
                libc::send(sock, bytes.as_ptr() as *const libc::c_void, 4, libc::MSG_DONTWAIT)
            };
        }
    }
    unsafe { libc::close(epfd); }
}

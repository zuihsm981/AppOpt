//! 用户态触摸/输入活动探测 (替代 4.19 上不可用的内核 input hook):
//! 以 root 打开 `/dev/input/event*` 原始输入设备, 任何输入事件 (触摸/按键)
//! 都视为用户活动 → 经 socketpair (AF_UNIX DGRAM) 把触发设备索引发给主线程
//! → 刷新线程重置空闲计时/恢复高刷。纯用户态, 与 KPM/内核 hook 无关。
//! 多 reader 语义: input core 会向所有打开设备的 fd 广播事件, 本模块
//! 只读取丢弃 (不消费), 不影响系统正常输入。

use std::os::raw::c_int;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

/// 用户态触摸监听状态: touch_probe 成功打开 event5 后置 true (web 状态页展示)
pub static TOUCH_LISTENING: AtomicBool = AtomicBool::new(false);

/// 触摸日志: eprintln (前台可见) + 追加 /data/local/tmp/appopt_touch.log
fn tlog(msg: &str) {
    use std::io::Write;
    eprintln!("[touch_probe] {}", msg);
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open("/data/local/tmp/appopt_touch.log")
    {
        let _ = writeln!(f, "[{:?}] {}", std::time::SystemTime::now(), msg);
    }
}

/// 触摸/输入活动探测线程入口。touch_sock 为 socketpair 写端, 活动时
/// send 触发设备索引 (i32 LE 4 字节); 主线程从读端 recv 并日志 eventN。
pub fn spawn_touch(touch_sock: c_int) {
    let name = std::ffi::CString::new("TouchProbe").unwrap();
    unsafe { libc::pthread_setname_np(libc::pthread_self(), name.as_ptr()); }

    let epfd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
    if epfd < 0 {
        return;
    }

    // 只监听触摸屏节点 /dev/input/event5 (实测确认; 按键等其它输入不再触发活动)
    let p = "/dev/input/event5";
    let c = match std::ffi::CString::new(p) {
        Ok(c) => c,
        Err(_) => return,
    };
    if !Path::new(p).exists() {
        tlog("/dev/input/event5 不存在");
        unsafe { libc::close(epfd); }
        return;
    }
    let fd = unsafe { libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_NONBLOCK) };
    if fd < 0 {
        tlog("打开 /dev/input/event5 失败");
        unsafe { libc::close(epfd); }
        return;
    }
    let mut ev: libc::epoll_event = unsafe { std::mem::zeroed() };
    ev.events = libc::EPOLLIN as u32;
    ev.u64 = 1;
    if unsafe { libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, fd, &mut ev) } != 0 {
        unsafe { libc::close(fd); }
        unsafe { libc::close(epfd); }
        return;
    }
    let fds: Vec<c_int> = vec![fd];
    TOUCH_LISTENING.store(true, Ordering::Relaxed);
    tlog("open /dev/input/event5 (触摸屏, 已监听)");

    let mut events: [libc::epoll_event; 16] = unsafe { std::mem::zeroed() };
    let mut buf = [0u8; 4096];

    loop {
        let n = unsafe { libc::epoll_wait(epfd, events.as_mut_ptr(), 16, -1) };
        if n < 0 {
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            break;
        }
        if n == 0 {
            continue;
        }
        // 清空就绪设备 (事件只读丢弃, 不消费系统输入)
        for i in 0..n as usize {
            let idx = events[i].u64 as usize;
            if idx >= 1 && idx <= fds.len() {
                loop {
                    let r = unsafe {
                        libc::read(fds[idx - 1], buf.as_mut_ptr() as *mut _, buf.len())
                    };
                    if r <= 0 {
                        break;
                    }
                }
            }
        }
        // 通知主线程: 有输入活动 (send 首个就绪设备索引, 供日志定位 eventN)
        for i in 0..n as usize {
            let idx = events[i].u64 as usize;
            if idx >= 1 && idx <= fds.len() {
                tlog(&format!("activity on /dev/input/event{}", idx - 1));
                let idx32 = (idx - 1) as i32;
                let bytes = idx32.to_ne_bytes();
                let _ = unsafe {
                    libc::send(
                        touch_sock,
                        bytes.as_ptr() as *const libc::c_void,
                        4,
                        libc::MSG_DONTWAIT,
                    )
                };
                break;
            }
        }
        // 节流: 避免高频触摸刷爆通知 (refresh handle_input 另有 1s 防抖)
        std::thread::sleep(std::time::Duration::from_millis(50));
    }

    for fd in fds {
        unsafe { libc::close(fd); }
    }
    unsafe { libc::close(epfd); }
}

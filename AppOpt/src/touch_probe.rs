//! 用户态触摸/输入活动探测 (替代 4.19 上不可用的内核 input hook):
//! root 打开 `/dev/input/eventX` (按 abs 能力探测触摸屏) 原始输入设备, 触摸事件 → socketpair 通知主线程
//! → 刷新率空闲计时重置/恢复高刷。纯用户态、事件驱动、零轮询。
//! 可按需启停: 刷新率活跃==空闲(无需 input 切换)时经控制 socket 暂停监听,
//! 切换应用后按新规则恢复监听。多 reader 语义: 事件只读丢弃, 不影响系统输入。

use std::os::raw::c_int;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};

/// 用户态触摸监听状态: 成功打开触摸屏 event 后置 true (web 状态页展示)
pub static TOUCH_LISTENING: AtomicBool = AtomicBool::new(false);
/// 当前监听的触摸屏 event 端口号 (-1=未找到/未监听); web 显示 "event* 状态"
static TOUCH_EVENT: AtomicI32 = AtomicI32::new(-1);

/// 当前监听的 event 名 ("event5"); 未找到返回空串
pub fn touch_event_name() -> String {
    let n = TOUCH_EVENT.load(Ordering::Relaxed);
    if n >= 0 {
        format!("event{}", n)
    } else {
        String::new()
    }
}
/// 监听开关 (refresh 线程按 timer_enabled 驱动): true=监听
static ENABLED: AtomicBool = AtomicBool::new(true);
/// 控制 socket 写端 (main L1 创建, set_ctrl_fd 注入)
static CTRL_FD: AtomicI32 = AtomicI32::new(-1);

pub fn set_ctrl_fd(fd: c_int) {
    CTRL_FD.store(fd, Ordering::Release);
}

/// 启用/暂停触摸监听: 更新开关 + 通知探测线程 ADD/DEL event (input 检测统一用户态)。
pub fn set_enabled(on: bool) {
    ENABLED.store(on, Ordering::Release);
    let fd = CTRL_FD.load(Ordering::Acquire);
    if fd >= 0 {
        let b: u8 = if on { 1 } else { 0 };
        let _ = unsafe { libc::send(fd, &b as *const u8 as *const _, 1, libc::MSG_DONTWAIT) };
    }
}

/// 判断 abs 能力掩码是否为触摸屏: 前 64 位覆盖 ABS_MT_POSITION_X=0x35 (多点)
/// 与 ABS_X/ABS_Y (0x00/0x01, 单点)。32/64 位内核的 /sys word 格式均覆盖。
fn is_touch_abs(abs: &str) -> bool {
    let mut words = abs.split_whitespace();
    let w0 = words
        .next()
        .and_then(|s| u64::from_str_radix(s, 16).ok())
        .unwrap_or(0);
    let w1 = words
        .next()
        .and_then(|s| u64::from_str_radix(s, 16).ok())
        .unwrap_or(0);
    let mask = w0 | (w1 << 32);
    (mask & (1u64 << 0x35)) != 0   // ABS_MT_POSITION_X
        || (mask & 0x3) != 0       // ABS_X / ABS_Y
}

/// 探测应监听的触摸屏 event 设备: 遍历 /sys/class/input/eventX 的 abs 能力。
/// 返回 (端口号, 设备路径); None = 未找到触摸屏 (不监听)。
fn event_for_touch() -> Option<(i32, String)> {
    for i in 0..32 {
        let abs_path = format!("/sys/class/input/event{}/device/capabilities/abs", i);
        if let Ok(abs) = std::fs::read_to_string(&abs_path) {
            if is_touch_abs(&abs) {
                return Some((i, format!("/dev/input/event{}", i)));
            }
        }
    }
    // 回退: event0 存在则尝试 (部分设备 abs 能力文件缺失但可读)
    if Path::new("/dev/input/event0").exists() {
        return Some((0, "/dev/input/event0".to_string()));
    }
    None
}

/// 触摸/输入活动探测线程入口。touch_sock 为 socketpair 写端 (活动通知),
/// ctrl_sock 为控制读端 (暂停/恢复监听)。
pub fn spawn_touch(touch_sock: c_int, ctrl_sock: c_int) {
    let name = std::ffi::CString::new("TouchProbe").unwrap();
    unsafe { libc::pthread_setname_np(libc::pthread_self(), name.as_ptr()); }

    let epfd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
    if epfd < 0 {
        return;
    }

    // 打开触摸屏节点 (按 abs 能力探测, 替代硬编码 event5)
    let Some((ev_idx, p)) = event_for_touch() else {
        unsafe { libc::close(epfd); }
        return;
    };
    let c = match std::ffi::CString::new(p) {
        Ok(c) => c,
        Err(_) => {
            unsafe { libc::close(epfd); }
            return;
        }
    };
    if !Path::new(&p).exists() {
        unsafe { libc::close(epfd); }
        return;
    }
    let fd = unsafe { libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_NONBLOCK) };
    if fd < 0 {
        unsafe { libc::close(epfd); }
        return;
    }
    TOUCH_EVENT.store(ev_idx, Ordering::Relaxed);
    TOUCH_LISTENING.store(true, Ordering::Relaxed);

    // 控制 fd 常驻 epoll; touch event 按 ENABLED 初始注册
    let mut cev: libc::epoll_event = unsafe { std::mem::zeroed() };
    cev.events = libc::EPOLLIN as u32;
    cev.u64 = 2; // ctrl
    if unsafe { libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, ctrl_sock, &mut cev) } != 0 {
        unsafe { libc::close(fd); }
        unsafe { libc::close(epfd); }
        return;
    }
    let mut listening = ENABLED.load(Ordering::Acquire);
    if listening {
        let mut ev: libc::epoll_event = unsafe { std::mem::zeroed() };
        ev.events = libc::EPOLLIN as u32;
        ev.u64 = 1; // touch event
        if unsafe { libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, fd, &mut ev) } == 0 {
            TOUCH_LISTENING.store(true, Ordering::Relaxed);
        } else {
            listening = false;
        }
    }

    let mut events: [libc::epoll_event; 8] = unsafe { std::mem::zeroed() };
    let mut buf = [0u8; 4096];

    loop {
        let n = unsafe { libc::epoll_wait(epfd, events.as_mut_ptr(), 8, -1) };
        if n < 0 {
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            break;
        }
        let mut activity = false;
        for i in 0..n as usize {
            if events[i].u64 == 2 {
                // 控制指令: 1=监听 0=暂停
                let mut cmd: u8 = 0;
                let _ = unsafe { libc::recv(ctrl_sock, &mut cmd as *mut u8 as *mut _, 1, 0) };
                let want = cmd == 1;
                if want && !listening {
                    let mut ev: libc::epoll_event = unsafe { std::mem::zeroed() };
                    ev.events = libc::EPOLLIN as u32;
                    ev.u64 = 1;
                    if unsafe { libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, fd, &mut ev) } == 0 {
                        listening = true;
                        TOUCH_LISTENING.store(true, Ordering::Relaxed); // 恢复 → UI 已监听
                    }
                } else if !want && listening {
                    unsafe { libc::epoll_ctl(epfd, libc::EPOLL_CTL_DEL, fd, std::ptr::null_mut()); }
                    listening = false;
                    TOUCH_LISTENING.store(false, Ordering::Relaxed); // 暂停 → UI 未监听
                }
            } else {
                // touch event: 清空事件 (只读丢弃)
                loop {
                    let r = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut _, buf.len()) };
                    if r <= 0 {
                        break;
                    }
                }
                activity = true;
            }
        }
        if activity {
            // 通知主线程: 有输入活动
            let v: u8 = 1;
            let _ = unsafe { libc::send(touch_sock, &v as *const u8 as *const _, 1, libc::MSG_DONTWAIT) };
            // 2s 节流: 通知后暂停读取 (期间事件在队列堆积, 只读丢弃), 降低高频触摸
            // 的唤醒/通知开销 (替代原内核 input 1s 节流; refresh handle_input 另有防抖)
            std::thread::sleep(std::time::Duration::from_millis(2000));
        }
    }

    unsafe { libc::close(fd); }
    unsafe { libc::close(epfd); }
}

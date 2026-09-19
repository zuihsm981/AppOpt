//! 用户态事件探测线程 (合并原 touch_probe + exit_probe):
//! 单个 epoll 统一监听 触摸 fd (/dev/input eventX) + pidfd 集合 (进程退出)
//! + 控制 fd (触摸启停)。事件经两个 socketpair 通知主循环:
//!   - touch_sock: 触摸活动 (1B) → 主循环 EV_TOUCH (刷新率空闲计时重置)
//!   - exit_sock:  主进程退出 (i32 LE 4B) → 主循环 EV_EXIT_PID (清 uid 身份)
//! 纯用户态、事件驱动、零轮询、零内核模块。watch() 由主线程在 EV_FG
//! 冷启动时为规则应用主 pid 注册 (跨线程 epoll_ctl, epfd 全局)。
//! 触摸可按需启停: 刷新率活跃==空闲(无需 input 切换)时经控制 socket 暂停监听,
//! 切换应用后按新规则恢复。多 reader 语义: 触摸事件只读丢弃, 不影响系统输入。

use std::collections::HashMap;
use std::os::raw::c_int;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::{Mutex, OnceLock};

/// 已注册 pid → 监听 fd (watch/事件清理共用)
static REG: std::sync::LazyLock<Mutex<HashMap<i32, c_int>>> =
    std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));
/// epoll fd (由 spawn_event 创建后设置; watch 跨线程 epoll_ctl 动态 add pidfd)
static EPFD: OnceLock<Mutex<c_int>> = OnceLock::new();

fn set_epfd(fd: c_int) {
    let _ = EPFD.set(Mutex::new(fd));
}

fn reg_lock() -> std::sync::MutexGuard<'static, HashMap<i32, c_int>> {
    REG.lock().unwrap_or_else(|e| e.into_inner())
}

/// 用户态触摸监听状态: 成功打开触摸屏 event 后置 true (web 状态页展示)
pub static TOUCH_LISTENING: AtomicBool = AtomicBool::new(false);
/// 当前监听的触摸屏 event 端口号 (-1=未找到/未监听); web 显示 "event* 状态"
static TOUCH_EVENT: AtomicI32 = AtomicI32::new(-1);
/// 监听开关 (refresh 线程按 timer_enabled 驱动): true=监听
static ENABLED: AtomicBool = AtomicBool::new(true);
/// 控制 socket 写端 (main 创建, set_ctrl_fd 注入; refresh set_enabled 使用)
static CTRL_FD: AtomicI32 = AtomicI32::new(-1);

/// 当前监听的 event 名 ("event5"); 未找到返回空串
pub fn touch_event_name() -> String {
    let n = TOUCH_EVENT.load(Ordering::Relaxed);
    if n >= 0 {
        format!("event{}", n)
    } else {
        String::new()
    }
}

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

/// 为规则应用主 pid 注册退出监听 (幂等)。全模式统一由调用方注册。
/// 跨线程 epoll_ctl: epfd 是内核对象, 任意线程可 ADD; 失败 (pidfd 不可用) 静默跳过。
pub fn watch(pid: i32) {
    if pid <= 0 {
        return;
    }
    if reg_lock().contains_key(&pid) {
        return;
    }
    let Some(epfd) = EPFD.get() else { return }; // epoll 未就绪, 跳过 (下次注册机会再注册)

    // 仅用 pidfd_open (syscall 434): 不可用 (ENOSYS) 则跳过注册
    let fd = unsafe { libc::syscall(434, pid, 0) as c_int };
    if fd < 0 {
        return;
    }
    let mut ev: libc::epoll_event = unsafe { std::mem::zeroed() };
    ev.events = (libc::EPOLLIN | libc::EPOLLHUP | libc::EPOLLERR) as u32;
    ev.u64 = pid as u64; // pidfd 事件标记 = pid 本身 (与 TAG_CTRL/TAG_TOUCH 不冲突)
    if unsafe { libc::epoll_ctl(*epfd.lock().unwrap_or_else(|e| e.into_inner()), libc::EPOLL_CTL_ADD, fd, &mut ev) } == 0 {
        reg_lock().insert(pid, fd);
    } else {
        unsafe { libc::close(fd); }
    }
}

/// 判断 abs 能力掩码是否为触摸屏: 只认 ABS_MT_POSITION_X (0x35, 多点触摸,
/// 现代触摸屏都有)。不认 ABS_X/ABS_Y (0x00/0x01) —— 加速度计/传感器也声明
/// 这两项, 避免误判。内核 %*pb 以 unsigned long 粒度打印, 64 位内核单 word
/// 完整覆盖 ABS_CNT=64, split_whitespace().next() 即完整掩码。
fn is_touch_abs(abs: &str) -> bool {
    let w0 = abs
        .split_whitespace()
        .next()
        .and_then(|s| u64::from_str_radix(s, 16).ok())
        .unwrap_or(0);
    (w0 & (1u64 << 0x35)) != 0   // ABS_MT_POSITION_X
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

/// 探测并打开触摸屏设备 (abs 能力探测, 替代硬编码 event5)。
/// 返回 (fd, 端口号); 失败返回 (-1, -1) —— 仅触摸活动检测退化, 不影响 pidfd。
fn open_touch() -> (c_int, i32) {
    let Some((ev_idx, p)) = event_for_touch() else { return (-1, -1) };
    let Ok(c) = std::ffi::CString::new(p.as_str()) else { return (-1, -1) };
    if !Path::new(&p).exists() {
        return (-1, -1);
    }
    let fd = unsafe { libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_NONBLOCK) };
    if fd < 0 {
        return (-1, -1);
    }
    TOUCH_EVENT.store(ev_idx, Ordering::Relaxed);
    (fd, ev_idx)
}

fn add_touch(epfd: c_int, touch_fd: c_int) -> bool {
    let mut ev: libc::epoll_event = unsafe { std::mem::zeroed() };
    ev.events = libc::EPOLLIN as u32;
    ev.u64 = TAG_TOUCH;
    unsafe { libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, touch_fd, &mut ev) == 0 }
}

// 事件标记 (ev.u64): pidfd 用 pid 本身 (正整数); 控制/触摸用保留标记
const TAG_CTRL: u64 = u64::MAX;
const TAG_TOUCH: u64 = u64::MAX - 1;
// 触摸节流时长: 通知后摘除触摸 fd 暂停监听, 降低高频触摸唤醒/通知开销
// (替代原内核 input 1s 节流; refresh handle_input 另有防抖)
const TOUCH_THROTTLE_MS: u64 = 2000;

/// 用户态事件探测线程入口 (单 epoll: 触摸 fd + pidfd 集合 + 控制 fd)。
/// touch_sock: 触摸活动通知写端 (1B); exit_sock: 主进程退出通知写端 (i32 LE 4B);
/// ctrl_sock: 控制读端 (暂停/恢复触摸监听)。fd 为 -1 表示该通道不可用 (不注册,
/// 相应功能退化, 不影响其余事件)。
pub fn spawn_event(touch_sock: c_int, ctrl_sock: c_int, exit_sock: c_int) {
    let name = std::ffi::CString::new("EventProbe").unwrap();
    unsafe { libc::pthread_setname_np(libc::pthread_self(), name.as_ptr()); }

    let epfd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
    if epfd < 0 {
        return;
    }
    set_epfd(epfd);

    // 触摸设备: 探测并打开 (失败不致命: 仅触摸活动检测退化)
    let (touch_fd, _ev_idx) = open_touch();

    // 控制 fd 常驻 epoll (触摸启停指令)
    if ctrl_sock >= 0 {
        let mut cev: libc::epoll_event = unsafe { std::mem::zeroed() };
        cev.events = libc::EPOLLIN as u32;
        cev.u64 = TAG_CTRL;
        unsafe { libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, ctrl_sock, &mut cev); }
    }

    // 触摸 fd 按 ENABLED 初始注册
    let mut listening = false;
    if touch_fd >= 0 && ENABLED.load(Ordering::Acquire) {
        listening = add_touch(epfd, touch_fd);
    }
    TOUCH_LISTENING.store(listening, Ordering::Relaxed);

    let mut events: [libc::epoll_event; 32] = unsafe { std::mem::zeroed() };
    let mut buf = [0u8; 4096];
    // 触摸节流: Some(到期时刻) 期间触摸 fd 从 epoll 摘除 (事件在队列堆积, 只读丢弃);
    // 用 epoll_wait 超时恢复, 不阻塞 pidfd/控制事件 (退出清理零延迟)。
    let mut throttle_until: Option<std::time::Instant> = None;

    loop {
        let timeout = match throttle_until {
            Some(t) => {
                let rem = t.saturating_duration_since(std::time::Instant::now());
                rem.as_millis().min(2000) as i32
            }
            None => -1,
        };
        let n = unsafe { libc::epoll_wait(epfd, events.as_mut_ptr(), 32, timeout) };
        if n < 0 {
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            break;
        }
        let now = std::time::Instant::now();
        if n == 0 {
            // 节流到期: 恢复触摸监听 (若仍启用且未在监听)
            throttle_until = None;
            if touch_fd >= 0 && ENABLED.load(Ordering::Acquire) && !listening {
                listening = add_touch(epfd, touch_fd);
                TOUCH_LISTENING.store(listening, Ordering::Relaxed);
            }
            continue;
        }
        let mut activity = false;
        for i in 0..n as usize {
            let tag = events[i].u64;
            if tag == TAG_CTRL {
                // 控制指令: 1=监听 0=暂停
                let mut cmd: u8 = 0;
                let _ = unsafe { libc::recv(ctrl_sock, &mut cmd as *mut u8 as *mut _, 1, 0) };
                let want = cmd == 1;
                if want && !listening && touch_fd >= 0 {
                    listening = add_touch(epfd, touch_fd);
                    TOUCH_LISTENING.store(listening, Ordering::Relaxed); // 恢复 → UI 已监听
                } else if !want && listening {
                    unsafe { libc::epoll_ctl(epfd, libc::EPOLL_CTL_DEL, touch_fd, std::ptr::null_mut()); }
                    listening = false;
                    TOUCH_LISTENING.store(false, Ordering::Relaxed); // 暂停 → UI 未监听
                }
            } else if tag == TAG_TOUCH {
                // touch event: 清空事件 (只读丢弃)
                loop {
                    let r = unsafe { libc::read(touch_fd, buf.as_mut_ptr() as *mut _, buf.len()) };
                    if r <= 0 {
                        break;
                    }
                }
                activity = true;
            } else {
                // pidfd 退出: 移除并关闭监听 fd → 通知主线程清理该 uid 身份
                let pid = tag as i32;
                if pid > 0 {
                    let fd = reg_lock().remove(&pid);
                    if let Some(fd) = fd {
                        unsafe { libc::close(fd); }
                    }
                    if exit_sock >= 0 {
                        let bytes = pid.to_ne_bytes();
                        let _ = unsafe {
                            libc::send(exit_sock, bytes.as_ptr() as *const libc::c_void, 4, libc::MSG_DONTWAIT)
                        };
                    }
                }
            }
        }
        if activity {
            // 通知主线程: 有输入活动
            if touch_sock >= 0 {
                let v: u8 = 1;
                let _ = unsafe { libc::send(touch_sock, &v as *const u8 as *const _, 1, libc::MSG_DONTWAIT) };
            }
            // 节流: 摘除触摸 fd 暂停读取 (期间事件在队列堆积, 只读丢弃); 经 epoll timeout 恢复
            if listening {
                unsafe { libc::epoll_ctl(epfd, libc::EPOLL_CTL_DEL, touch_fd, std::ptr::null_mut()); }
                listening = false;
                TOUCH_LISTENING.store(false, Ordering::Relaxed);
            }
            throttle_until = Some(now + std::time::Duration::from_millis(TOUCH_THROTTLE_MS));
        }
    }

    if touch_fd >= 0 {
        unsafe { libc::close(touch_fd); }
    }
    unsafe { libc::close(epfd); }
}

//! 刷新率控制模块
//!
//! 简单路线:
//!   主循环 (binder 回调) 把前台 pid 交给本模块 (refresh_on_fg_pid);
//!   把前台应用送给本模块; 本模块收到 (pid, 包名) 后查规则 (app_configs /
//!   默认桌面), 决定是否切换刷新率, 再按 timeout 计时切回 idle。
//! 事件只经 mpsc 从其他线程送来, 刷新率线程独占 SurfaceFlinger 切换。

use std::collections::HashMap;
use std::ffi::CString;
use std::fs;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::{mpsc, Mutex};
use std::thread;
use std::time::Instant;

const MODE_120: i32 = 0;
const MODE_60: i32 = 1;
const MODE_90: i32 = 2;

/// input 事件类型码 (与 ebpf_mode::EBPF_EVENT_INPUT 一致)
pub const EVENT_INPUT: u32 = 5;

/// 刷新率配置与 CPU 规则共用 CONFIG_FILE 指向的主配置文件。
fn config_path() -> String {
    crate::lock_ignore_poison(&crate::config::CONFIG_FILE).clone()
}

static REFRESH_FORCE_RELOAD: AtomicBool = AtomicBool::new(false);
static WAKE_FD: AtomicI32 = AtomicI32::new(-1);
static REFRESH_STATUS: Mutex<Option<RefreshStatus>> = Mutex::new(None);
static REFRESH_TX: Mutex<Option<mpsc::Sender<RefreshEvent>>> = Mutex::new(None);

/// 前台应用事件: (pid, 包名)。收到后查规则决定是否切换刷新率。
enum RefreshEvent {
    Input,
    /// full_scan 发现已存在的默认桌面后，要求刷新线程绑定全局配置。
    BindDefaultLauncher,
    /// binder 回调送来的前台 pid: 本线程自行 /proc 解析包名后查规则。
    FgPid(i32),
}

#[derive(Clone)]
pub struct RefreshStatus {
    pub current_mode: i32,
    pub is_paused: bool,
    pub timer_enabled: bool,
    pub timer_running: bool,
    pub current_package: String,
    pub timeout: i32,
    pub active_mode: i32,
    pub idle_mode: i32,
}

struct AppRefreshConfig {
    timeout: i32,
    active_mode: i32,
    idle_mode: i32,
}

struct RefreshState {
    timeout_seconds: i32,
    active_mode: i32,
    idle_mode: i32,
    app_configs: HashMap<String, AppRefreshConfig>,
    current_active: i32,
    current_idle: i32,
    current_timeout: i32,
    current_applied_mode: i32,
    is_paused: bool,
    timer_enabled: bool,
    last_reset_time: Option<Instant>,
    current_package: String,
    last_applied_pkg: String,
    last_apply_time: Option<Instant>,
    last_input_time: Option<Instant>,
    timer_fd: i32,
}

/// 从共享 CURRENT_CONFIG 读取刷新率全局配置（统一加载，避免线程内重复读文件）
fn load_global_config(state: &mut RefreshState) {
    let cfg = crate::lock_ignore_poison(&crate::config::CURRENT_CONFIG).clone();
    let Some(cfg) = cfg else { return };
    state.timeout_seconds = cfg.refresh_timeout;
    state.active_mode = cfg.refresh_active;
    state.idle_mode = cfg.refresh_idle;
    state.current_active = state.active_mode;
    state.current_idle = state.idle_mode;
    state.current_timeout = state.timeout_seconds;
    state.timer_enabled = state.current_idle != state.current_active;
}

/// 从共享 CURRENT_CONFIG 读取按应用刷新率配置（统一加载）
fn load_app_configs(state: &mut RefreshState) {
    state.app_configs.clear();
    let cfg = crate::lock_ignore_poison(&crate::config::CURRENT_CONFIG).clone();
    let Some(cfg) = cfg else { return };
    for (pkg, (timeout, active_mode, idle_mode)) in &cfg.app_refresh_configs {
        state.app_configs.insert(
            pkg.clone(),
            AppRefreshConfig {
                timeout: *timeout,
                active_mode: *active_mode,
                idle_mode: *idle_mode,
            },
        );
    }
}

fn set_refresh_rate(state: &mut RefreshState, mode: i32) {
    if mode == state.current_applied_mode {
        return;
    }
    // 只走 binder 直连 SurfaceFlinger
    crate::process_observer::set_refresh_rate_binder(mode);
    state.current_applied_mode = mode;
}

fn bind_default_launcher(state: &mut RefreshState) {
    state.current_package = crate::config::DEFAULT_REFRESH_PACKAGE.to_string();
    state.last_applied_pkg = state.current_package.clone();
    // 默认 launcher 永远使用全局 timeout/active/idle。
    apply_app_config(state, crate::config::DEFAULT_REFRESH_PACKAGE);
    set_refresh_rate(state, state.current_active);
    reset_timer(state, true);
}

fn apply_app_config(state: &mut RefreshState, pkg: &str) {
    // 默认桌面始终绑定全局刷新率配置；其余应用有专属配置用专属，否则用全局。
    if pkg != crate::config::DEFAULT_REFRESH_PACKAGE {
        if let Some(cfg) = state.app_configs.get(pkg) {
            state.current_timeout = cfg.timeout;
            state.current_active = cfg.active_mode;
            state.current_idle = cfg.idle_mode;
        } else {
            state.current_timeout = state.timeout_seconds;
            state.current_active = state.active_mode;
            state.current_idle = state.idle_mode;
        }
    } else {
        state.current_timeout = state.timeout_seconds;
        state.current_active = state.active_mode;
        state.current_idle = state.idle_mode;
    }
    state.timer_enabled = state.current_idle != state.current_active;
}

fn timerfd_set(fd: i32, seconds: i32) {
    let its = libc::itimerspec {
        it_interval: libc::timespec { tv_sec: 0, tv_nsec: 0 },
        it_value: libc::timespec { tv_sec: seconds as i64, tv_nsec: 0 },
    };
    unsafe { libc::timerfd_settime(fd, 0, &its, std::ptr::null_mut()); }
}

fn timerfd_cancel(fd: i32) {
    let its = libc::itimerspec {
        it_interval: libc::timespec { tv_sec: 0, tv_nsec: 0 },
        it_value: libc::timespec { tv_sec: 0, tv_nsec: 0 },
    };
    unsafe { libc::timerfd_settime(fd, 0, &its, std::ptr::null_mut()); }
}

fn reset_timer(state: &mut RefreshState, force: bool) {
    if !state.timer_enabled {
        timerfd_cancel(state.timer_fd);
        state.last_reset_time = None;
        return;
    }
    if state.is_paused {
        state.is_paused = false;
    }
    let now = Instant::now();
    if !force
        && state.current_applied_mode == state.current_active
        && state.current_active != state.current_idle
    {
        let debounce = std::time::Duration::from_secs((state.current_timeout - 10).max(0) as u64);
        if let Some(last) = state.last_reset_time {
            if now - last < debounce {
                return;
            }
        }
    }
    timerfd_set(state.timer_fd, state.current_timeout);
    state.last_reset_time = Some(now);
}

fn switch_to_idle(state: &mut RefreshState) {
    if !state.timer_enabled {
        return;
    }
    set_refresh_rate(state, state.current_idle);
    state.is_paused = true;
    timerfd_cancel(state.timer_fd);
    state.last_reset_time = None;
}

/// 刷新率模块收到 (pid, 包名) 后查规则, 决定是否切换刷新率。
/// 规则:
///   - com.android.launcher3 视为无配置应用;
///   - 无配置应用之间切换 (含 launcher) → 不切换刷新率;
///   - 从有配置应用切换到 launcher → 应用全局配置并切换;
///   - 涉及有配置应用的切换 → 应用对应配置并切换。
/// 刷新率模块收到 (pid, 包名) 后查规则应用。
/// 规则:
///   - com.android.launcher3 视为无配置应用;
///   - 有配置应用 → 应用其专属配置并切换;
///   - launcher / 无配置应用 → 保持全局配置 (速率不变 = "不切换"), 计时器照常运行。
fn apply_fg(state: &mut RefreshState, _pid: i32, pkg: &str) {
    if pkg.is_empty() || pkg == state.last_applied_pkg {
        return; // 已应用过
    }
    // 无配置应用 (含 com.android.launcher3) 之间切换: 什么都不做
    if !state.app_configs.contains_key(pkg) && !state.app_configs.contains_key(&state.last_applied_pkg) {
        return;
    }
    let now = Instant::now();
    state.current_package = pkg.to_string();
    state.last_applied_pkg = pkg.to_string();
    state.last_apply_time = Some(now);
    // 有配置应用 → 专属配置; 有配置 → 无配置 (含 launcher) → 全局配置。
    // 只应用配置, 不额外启动计时器 (计时器由 input/初始化路径管理)。
    apply_app_config(state, pkg);
    set_refresh_rate(state, state.current_active);
}

/// binder 回调收到前台 pid 后交给刷新率线程; 线程内自行解析包名并查规则。
pub fn refresh_on_fg_pid(pid: i32) {
    if pid <= 0 {
        return;
    }
    let guard = REFRESH_TX.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(tx) = guard.as_ref() {
        let _ = tx.send(RefreshEvent::FgPid(pid));
        wake();
    }
}

/// input 事件触发：用户活动。1 秒节流 + 计时器停止时切回活跃刷新率并重启计时器。
fn handle_input(state: &mut RefreshState) {
    let now = Instant::now();
    if let Some(last) = state.last_input_time {
        if now - last < std::time::Duration::from_secs(1) {
            return;
        }
    }
    state.last_input_time = Some(now);

    if state.last_reset_time.is_none() {
        // 计时器已停止（空闲状态）：切回活跃刷新率 + 重启计时器
        set_refresh_rate(state, state.current_active);
        state.is_paused = false;
        reset_timer(state, true);
    } else {
        // 计时器运行中：带防抖重置
        reset_timer(state, false);
    }
}

fn check_config(state: &mut RefreshState) {
    if REFRESH_FORCE_RELOAD.swap(false, Ordering::AcqRel) {
        load_global_config(state);
        load_app_configs(state);
        let current_pkg = state.current_package.clone();
        apply_app_config(state, &current_pkg);
        set_refresh_rate(state, state.current_active);
        if state.last_reset_time.is_some() {
            reset_timer(state, true);
        }
    }
}

fn update_status(state: &RefreshState) {
    let status = RefreshStatus {
        current_mode: state.current_applied_mode,
        is_paused: state.is_paused,
        timer_enabled: state.timer_enabled,
        timer_running: state.last_reset_time.is_some(),
        current_package: state.current_package.clone(),
        timeout: state.current_timeout,
        active_mode: state.current_active,
        idle_mode: state.current_idle,
    };
    *REFRESH_STATUS.lock().unwrap_or_else(|e| e.into_inner()) = Some(status);
}

fn wake() {
    let fd = WAKE_FD.load(Ordering::Acquire);
    if fd >= 0 {
        let val: u64 = 1;
        unsafe { libc::write(fd, &val as *const u64 as *const _, 8); }
    }
}

pub fn refresh_init() {
    let wake_fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
    if wake_fd < 0 {
        return;
    }
    WAKE_FD.store(wake_fd, Ordering::Release);

    // IProcessObserver 回调由主循环注册并统一分发前台 pid (refresh_on_fg_pid)。
    let timer_fd = unsafe {
        libc::timerfd_create(libc::CLOCK_MONOTONIC, libc::TFD_CLOEXEC | libc::TFD_NONBLOCK)
    };
    if timer_fd < 0 {
        unsafe { libc::close(wake_fd); }
        return;
    }

    let (tx, rx) = mpsc::channel::<RefreshEvent>();
    *REFRESH_TX.lock().unwrap_or_else(|e| e.into_inner()) = Some(tx);

    let mut state = RefreshState {
        timeout_seconds: 30,
        active_mode: MODE_120,
        idle_mode: MODE_60,
        app_configs: HashMap::new(),
        current_active: MODE_120,
        current_idle: MODE_60,
        current_timeout: 30,
        current_applied_mode: -1,
        is_paused: false,
        timer_enabled: true,
        last_reset_time: None,
        current_package: String::new(),
        last_applied_pkg: String::new(),
        last_apply_time: None,
        last_input_time: None,
        timer_fd,
    };

    load_global_config(&mut state);
    load_app_configs(&mut state);

    // 初始化时先应用一次全局 active 刷新率；launcher 的全局绑定由 full_scan 事件完成。
    let active = state.current_active;
    set_refresh_rate(&mut state, active);

    let name = CString::new("RefreshRate").unwrap();
    thread::spawn(move || {
        unsafe { libc::pthread_setname_np(libc::pthread_self(), name.as_ptr()); }

        let epfd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
        if epfd < 0 {
            return;
        }

        let mut ev: libc::epoll_event = unsafe { std::mem::zeroed() };
        ev.events = libc::EPOLLIN as u32;
        ev.u64 = 0;
        unsafe { libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, wake_fd, &mut ev); }

        ev.u64 = 1;
        unsafe { libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, timer_fd, &mut ev); }

        let mut events: [libc::epoll_event; 2] = unsafe { std::mem::zeroed() };

        loop {
            let n = unsafe { libc::epoll_wait(epfd, events.as_mut_ptr(), 2, -1) };
            if n < 0 {
                if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                break;
            }

            for i in 0..n as usize {
                match events[i].u64 {
                    0 => {
                        let mut val: u64 = 0;
                        unsafe { libc::read(wake_fd, &mut val as *mut _ as *mut _, 8); }
                        while let Ok(event) = rx.try_recv() {
                            match event {
                                RefreshEvent::Input => handle_input(&mut state),
                                RefreshEvent::BindDefaultLauncher => {
                                    bind_default_launcher(&mut state)
                                }
                                // binder 回调送来的前台 pid: 自行解析包名后查规则
                                RefreshEvent::FgPid(pid) => {
                                    if let Some(cfg) =
                                        crate::lock_ignore_poison(
                                            &crate::config::CURRENT_CONFIG,
                                        ).clone()
                                    {
                                        if let Some(pkg) =
                                            crate::ebpf_mode::resolve_pkg(pid, &cfg)
                                        {
                                            apply_fg(&mut state, pid, &pkg);
                                        }
                                    }
                                }
                            }
                        }
                        check_config(&mut state);
                    }
                    1 => {
                        let mut val: u64 = 0;
                        unsafe { libc::read(timer_fd, &mut val as *mut _ as *mut _, 8); }
                        switch_to_idle(&mut state);
                    }
                    _ => {}
                }
            }
            update_status(&state);
        }

        unsafe {
            libc::close(epfd);
            libc::close(wake_fd);
            libc::close(timer_fd);
        }
    });
}

/// full_scan 发现默认 launcher PID 后，请求刷新线程绑定全局配置。
pub fn refresh_bind_default_launcher() {
    let guard = REFRESH_TX.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(tx) = guard.as_ref() {
        let _ = tx.send(RefreshEvent::BindDefaultLauncher);
        wake();
    }
}

pub fn refresh_on_event(event_type: u32, _pid: i32) {
    let guard = REFRESH_TX.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(tx) = guard.as_ref() {
        let event = match event_type {
            EVENT_INPUT => RefreshEvent::Input,
            _ => return,
        };
        let _ = tx.send(event);
        wake();
    }
}

// ===== Web API =====

pub fn refresh_get_config() -> (i32, String, String) {
    // 从共享 CURRENT_CONFIG 读取（统一加载；未就绪时回退默认值）
    if let Some(cfg) = crate::lock_ignore_poison(&crate::config::CURRENT_CONFIG).clone() {
        return (
            cfg.refresh_timeout,
            crate::config::refresh_mode_str(cfg.refresh_active).to_string(),
            crate::config::refresh_mode_str(cfg.refresh_idle).to_string(),
        );
    }
    (30, "120".to_string(), "60".to_string())
}

pub fn refresh_set_config(timeout: i32, active: &str, idle: &str) {
    // 原地编辑主配置文件：只替换刷新率字段，保留 CPU 规则、注释、空行和应用配置。
    let path = config_path();
    let content = fs::read_to_string(&path).unwrap_or_default();
    let mut found_timeout = false;
    let mut found_active = false;
    let mut found_idle = false;

    let mut lines: Vec<String> = content.lines().map(str::to_string).collect();
    for line in lines.iter_mut() {
        let trimmed = line.trim();
        let Some((k, _v)) = trimmed.split_once('=') else { continue };
        match k.trim() {
            "refresh_timeout" => {
                *line = format!("refresh_timeout={}", timeout);
                found_timeout = true;
            }
            "refresh_active" => {
                *line = format!("refresh_active={}", active);
                found_active = true;
            }
            "refresh_idle" => {
                *line = format!("refresh_idle={}", idle);
                found_idle = true;
            }
            _ => {}
        }
    }
    if !found_timeout {
        lines.push(format!("refresh_timeout={}", timeout));
    }
    if !found_active {
        lines.push(format!("refresh_active={}", active));
    }
    if !found_idle {
        lines.push(format!("refresh_idle={}", idle));
    }

    if fs::write(&path, lines.join("\n") + "\n").is_err() {
        return;
    }
    // 同步共享配置（仅刷新率，不触发 CPU 重载）+ 独立通知 refresh 线程
    crate::config::reload_refresh_only();
    REFRESH_FORCE_RELOAD.store(true, Ordering::Release);
    wake();
}

pub fn refresh_get_apps() -> Vec<(String, i32, String, String)> {
    let Some(cfg) = crate::lock_ignore_poison(&crate::config::CURRENT_CONFIG).clone() else {
        return Vec::new();
    };
    cfg.app_refresh_configs
        .iter()
        .map(|(pkg, (t, a, i))| {
            (
                pkg.clone(),
                *t,
                crate::config::refresh_mode_str(*a).to_string(),
                crate::config::refresh_mode_str(*i).to_string(),
            )
        })
        .collect()
}

pub fn refresh_add_app(pkg: &str, timeout: i32, active: &str, idle: &str) {
    let path = config_path();
    let content = fs::read_to_string(&path).unwrap_or_default();
    let mut lines: Vec<String> = content.lines().map(String::from).collect();
    let new_line = format!("refresh_app,{},{},{},{}", pkg, timeout, active, idle);
    let mut found = false;
    for line in lines.iter_mut() {
        if line.trim().starts_with('#') || line.trim().is_empty() {
            continue;
        }
        let fields: Vec<&str> = line.split(',').map(str::trim).collect();
        if (fields.len() == 5 && fields[0] == "refresh_app" && fields[1] == pkg)
            || (fields.len() == 4 && fields[0] == pkg)
        {
            *line = new_line.clone();
            found = true;
            break;
        }
    }
    if !found {
        lines.push(new_line);
    }
    if fs::write(&path, lines.join("\n") + "\n").is_err() {
        return;
    }
    // 同步共享配置（仅刷新率）+ 独立通知 refresh 线程
    crate::config::reload_refresh_only();
    REFRESH_FORCE_RELOAD.store(true, Ordering::Release);
    wake();
}

pub fn refresh_del_app(pkg: &str) -> bool {
    let path = config_path();
    let content = match fs::read_to_string(&path) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let lines: Vec<String> = content
        .lines()
        .filter(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return true;
            }
            let fields: Vec<&str> = line.split(',').map(str::trim).collect();
            !((fields.len() == 5 && fields[0] == "refresh_app" && fields[1] == pkg)
                || (fields.len() == 4 && fields[0] == pkg))
        })
        .map(String::from)
        .collect();
    if fs::write(&path, lines.join("\n") + "\n").is_err() {
        return false;
    }
    // 同步共享配置（仅刷新率）+ 独立通知 refresh 线程
    crate::config::reload_refresh_only();
    REFRESH_FORCE_RELOAD.store(true, Ordering::Release);
    wake();
    true
}

pub fn refresh_get_status() -> Option<RefreshStatus> {
    REFRESH_STATUS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
}
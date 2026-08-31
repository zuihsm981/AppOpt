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

/// 刷新率配置与 CPU 规则共用 CONFIG_FILE 指向的主配置文件。
fn config_path() -> String {
    crate::lock_ignore_poison(&crate::config::CONFIG_FILE).clone()
}

pub const EVENT_INPUT: u32 = 5;

static REFRESH_FORCE_RELOAD: AtomicBool = AtomicBool::new(false);
static WAKE_FD: AtomicI32 = AtomicI32::new(-1);
static REFRESH_STATUS: Mutex<Option<RefreshStatus>> = Mutex::new(None);
static REFRESH_TX: Mutex<Option<mpsc::Sender<RefreshEvent>>> = Mutex::new(None);

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

enum RefreshEvent {
    Input,
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
    // 只走 binder 直连 SurfaceFlinger，不再回退到 service 子进程
    crate::process_observer::set_refresh_rate_binder(mode);
    state.current_applied_mode = mode;
}

fn apply_app_config(state: &mut RefreshState, pkg: &str) {
    if let Some(cfg) = state.app_configs.get(pkg) {
        state.current_timeout = cfg.timeout;
        state.current_active = cfg.active_mode;
        state.current_idle = cfg.idle_mode;
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

/// IProcessObserver 回调触发：收到 pid，从共享 ProcCache(PID_PKG) 查包名
/// 白名单准入（两道防线，参考 优化.md）：
///   防线一：数据可用性检查（查不到包名即丢弃）
///   防线二：白名单准入（仅 launcher 或已配置应用）
fn handle_fg_change(state: &mut RefreshState, pid: i32) {
    // 防线一：从共享 pid→pkg 索引获取包名（防御性检查）
    let Some(pkg) = crate::cache::pkg_lookup_pid(pid) else {
        return; // 极端情况：进程在回调触发时恰好退出/尚未入库
    };
    if pkg.is_empty() || pkg == state.last_applied_pkg {
        return;
    }

    // 防线二：白名单准入检查（唯一真正的过滤器）
    let is_launcher = pkg == "com.android.launcher3";
    let is_managed = state.app_configs.contains_key(&pkg);
    if !is_launcher && !is_managed {
        return; // 系统设置、状态栏、弹窗、未配置应用全部丢弃
    }

    // 判断切换前/后的应用是否已配置（决定是否应用全局活跃刷新率）
    let prev_configured = state.app_configs.contains_key(&state.last_applied_pkg);
    let cur_configured = is_launcher || is_managed;

    let now = Instant::now();
    state.current_package = pkg.clone();
    state.last_applied_pkg = pkg.clone();
    state.last_apply_time = Some(now);

    apply_app_config(state, &pkg);
    // 未配置应用之间切换时不重新应用全局活跃刷新率；
    // 仅当从已配置应用切换到未配置应用（或切到已配置应用）时才应用活跃刷新率
    if prev_configured || cur_configured {
        set_refresh_rate(state, state.current_active);
    }
    reset_timer(state, true);
}

/// input 事件触发：用户活动
/// 1 秒节流 + 计时器停止时切回活跃刷新率并重启计时器
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
    *REFRESH_STATUS.lock().unwrap() = Some(status);
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

    // IProcessObserver 回调用 socketpair(SOCK_DGRAM) 传递包名（字符串），不再传 uid
    let mut fg_sv: [libc::c_int; 2] = [0, 0];
    if unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_DGRAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
            fg_sv.as_mut_ptr(),
        )
    } != 0
    {
        unsafe { libc::close(wake_fd); }
        return;
    }
    let fg_recv_fd = fg_sv[0];
    let fg_send_fd = fg_sv[1];

    // 增大 socketpair 接收缓冲（默认可能只有几十 KB），减少 fg 事件堆积溢出
    let rcvbuf: libc::c_int = 256 * 1024;
    unsafe {
        libc::setsockopt(
            fg_recv_fd,
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            &rcvbuf as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }

    let timer_fd = unsafe {
        libc::timerfd_create(libc::CLOCK_MONOTONIC, libc::TFD_CLOEXEC | libc::TFD_NONBLOCK)
    };
    if timer_fd < 0 {
        unsafe { libc::close(wake_fd); }
        return;
    }

    let (tx, rx) = mpsc::channel::<RefreshEvent>();
    *REFRESH_TX.lock().unwrap() = Some(tx);

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

    // 初始化完成后应用一次全局配置的活跃刷新率
    // （之后的前台切换判定见 handle_fg_change：未配置→未配置不再重复应用全局活跃刷新率）
    let active = state.current_active;
    set_refresh_rate(&mut state, active);

    // 注册 IProcessObserver 回调（回调只传 pid，包名由共享 ProcCache 查询）
    let _ = crate::process_observer::init_observer(fg_send_fd);

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

        // fg socketpair 读端: IProcessObserver 回调通知 (u64=3)
        ev.events = libc::EPOLLIN as u32;
        ev.u64 = 3;
        unsafe { libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, fg_recv_fd, &mut ev); }

        let mut events: [libc::epoll_event; 3] = unsafe { std::mem::zeroed() };
        // fg socketpair 接收缓冲（4 字节 pid i32）
        let mut fg_buf = [0u8; 4];

        loop {
            // maxevents 与 events 缓冲大小一致（3 个已注册 fd，最多返回 3 个事件）
            let n = unsafe { libc::epoll_wait(epfd, events.as_mut_ptr(), 3, -1) };
            if n <= 0 {
                if n < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
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
                            }
                        }
                        check_config(&mut state);
                    }
                    1 => {
                        let mut val: u64 = 0;
                        unsafe { libc::read(timer_fd, &mut val as *mut _ as *mut _, 8); }
                        switch_to_idle(&mut state);
                    }
                    3 => {
                        // IProcessObserver 回调: 读取 pid（socketpair datagram，4 字节 i32），
                        // 包名由 handle_fg_change 从共享 ProcCache 查询
                        let n = unsafe {
                            libc::recv(
                                fg_recv_fd,
                                fg_buf.as_mut_ptr() as *mut libc::c_void,
                                fg_buf.len(),
                                0,
                            )
                        };
                        if n == 4 {
                            let pid = i32::from_ne_bytes([fg_buf[0], fg_buf[1], fg_buf[2], fg_buf[3]]);
                            handle_fg_change(&mut state, pid);
                        }
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
            libc::close(fg_recv_fd);
            libc::close(fg_send_fd);
        }
    });
}

pub fn refresh_on_event(event_type: u32, _pid: i32) {
    let guard = REFRESH_TX.lock().unwrap();
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
    // 使用 refresh_ 前缀，确保不会与 CPU 规则语法混淆。
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
    // 刷新率应用配置只从共享 CURRENT_CONFIG 返回，不再单独读取配置文件。
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
    REFRESH_STATUS.lock().unwrap().clone()
}
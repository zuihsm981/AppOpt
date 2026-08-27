use std::collections::HashMap;
use std::ffi::CString;
use std::fs;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::Mutex;
use std::sync::mpsc;
use std::thread;
use std::time::Instant;

// ── Android log (调试用) ──
unsafe extern "C" {
    fn __android_log_write(prio: std::os::raw::c_int, tag: *const std::os::raw::c_char, text: *const std::os::raw::c_char) -> std::os::raw::c_int;
}
const RLOG_TAG: &[u8] = b"AppOpt\0";
fn rlog(msg: &str) {
    let mut buf = vec![0u8; msg.len() + 1];
    buf[..msg.len()].copy_from_slice(msg.as_bytes());
    unsafe { __android_log_write(3, RLOG_TAG.as_ptr() as *const std::os::raw::c_char, buf.as_ptr() as *const std::os::raw::c_char); }
}
macro_rules! ralog { ($($a:tt)*) => { rlog(&format!($($a)*)) } }

const MODE_120: i32 = 0;
const MODE_60: i32 = 1;
const MODE_90: i32 = 2;

const CONFIG_PATH: &str = "./refresh_config.conf";

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

fn parse_mode(s: &str) -> i32 {
    match s.trim() {
        "120" => MODE_120,
        "90" => MODE_90,
        "60" => MODE_60,
        _ => MODE_60,
    }
}

fn create_default_config() {
    if !std::path::Path::new(CONFIG_PATH).exists() {
        let _ = fs::write(CONFIG_PATH, "timeout=30\nactive=120\nidle=60\n# packageName,timeout,activeMode,idleMode\n");
    }
}

fn load_global_config(state: &mut RefreshState) {
    let content = match fs::read_to_string(CONFIG_PATH) {
        Ok(s) => s,
        Err(_) => return,
    };
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            match k.trim() {
                "timeout" => {
                    if let Ok(t) = v.trim().parse::<i32>() {
                        if t > 0 {
                            state.timeout_seconds = t;
                        }
                    }
                }
                "active" => state.active_mode = parse_mode(v),
                "idle" => state.idle_mode = parse_mode(v),
                _ => {}
            }
        }
    }
    state.current_active = state.active_mode;
    state.current_idle = state.idle_mode;
    state.current_timeout = state.timeout_seconds;
    state.timer_enabled = state.current_idle != state.current_active;
}

fn load_app_configs(state: &mut RefreshState) {
    state.app_configs.clear();
    let content = match fs::read_to_string(CONFIG_PATH) {
        Ok(s) => s,
        Err(_) => return,
    };
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.split(',').collect();
        if parts.len() != 4 {
            continue;
        }
        state.app_configs.insert(
            parts[0].trim().to_string(),
            AppRefreshConfig {
                timeout: parts[1].trim().parse::<i32>().unwrap_or(30),
                active_mode: parse_mode(parts[2].trim()),
                idle_mode: parse_mode(parts[3].trim()),
            },
        );
    }
}

fn set_refresh_rate(state: &mut RefreshState, mode: i32) {
    if mode == state.current_applied_mode {
        return;
    }
    let _ = std::process::Command::new("service")
        .args(["call", "SurfaceFlinger", "1035", "i32", &mode.to_string()])
        .output();
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

/// IProcessObserver 回调触发：直接收到包名（socketpair 传递，系统过滤已在 UID 映射表完成）
fn handle_fg_change(state: &mut RefreshState, pkg: &str) {
    ralog!("handle_fg_change: pkg={}", pkg);

    if pkg.is_empty() || pkg == state.last_applied_pkg {
        ralog!("  skip: empty or same as last_applied_pkg={}", state.last_applied_pkg);
        return;
    }

    // 判断切换前/后的应用是否已配置（决定是否应用全局活跃刷新率）
    // 注意：last_applied_pkg 为空串时不可能是已配置 uid，故无需单独判断是否有上一应用
    let prev_configured = state.app_configs.contains_key(&state.last_applied_pkg);
    let cur_configured = state.app_configs.contains_key(pkg);

    let now = Instant::now();
    state.current_package = pkg.to_string();
    state.last_applied_pkg = pkg.to_string();
    state.last_apply_time = Some(now);

    apply_app_config(state, pkg);
    // 未配置 uid 之间切换时不重新应用全局活跃刷新率；
    // 仅当从已配置 uid 切换到未配置 uid（或切到已配置 uid）时才应用活跃刷新率
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
    create_default_config();

    let wake_fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
    if wake_fd < 0 {
        eprintln!("刷新率: eventfd 创建失败");
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
        eprintln!("刷新率: fg socketpair 创建失败");
        unsafe { libc::close(wake_fd); }
        return;
    }
    let fg_recv_fd = fg_sv[0];
    let fg_send_fd = fg_sv[1];

    let timer_fd = unsafe {
        libc::timerfd_create(libc::CLOCK_MONOTONIC, libc::TFD_CLOEXEC | libc::TFD_NONBLOCK)
    };
    if timer_fd < 0 {
        eprintln!("刷新率: timerfd 创建失败");
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
    set_refresh_rate(&mut state, state.current_active);

    // 加载 UID → 包名映射表
    crate::process_observer::init_uid_map();

    // 注册 IProcessObserver 回调
    let observer_ok = crate::process_observer::init_observer(fg_send_fd);
    ralog!("init_observer result={}", observer_ok);

    let name = CString::new("RefreshRate").unwrap();
    thread::spawn(move || {
        unsafe { libc::pthread_setname_np(libc::pthread_self(), name.as_ptr()); }

        let epfd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
        if epfd < 0 {
            eprintln!("刷新率: epoll_create1 失败");
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

        loop {
            let n = unsafe { libc::epoll_wait(epfd, events.as_mut_ptr(), 4, -1) };
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
                        // IProcessObserver 回调: 读取包名（socketpair datagram，无需再查表）
                        let mut buf = [0u8; 512];
                        let n = unsafe {
                            libc::recv(fg_recv_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0)
                        };
                        if n > 0 {
                            let pkg = String::from_utf8_lossy(&buf[..n as usize]).into_owned();
                            ralog!("epoll: fg pkg={}", pkg);
                            handle_fg_change(&mut state, &pkg);
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
    let content = fs::read_to_string(CONFIG_PATH).unwrap_or_default();
    let mut timeout = 30;
    let mut active = "120".to_string();
    let mut idle = "60".to_string();
    for line in content.lines() {
        let line = line.trim();
        if let Some((k, v)) = line.split_once('=') {
            match k.trim() {
                "timeout" => {
                    if let Ok(t) = v.trim().parse::<i32>() {
                        if t > 0 {
                            timeout = t;
                        }
                    }
                }
                "active" => active = v.trim().to_string(),
                "idle" => idle = v.trim().to_string(),
                _ => {}
            }
        }
    }
    (timeout, active, idle)
}

pub fn refresh_set_config(timeout: i32, active: &str, idle: &str) {
    // 原地编辑而非覆盖整个文件：只替换 timeout/active/idle 三个全局配置键的值，
    // 保留原有行顺序、注释、空行与应用配置行（不做 trim、不丢弃空行、不重排），
    // 缺失的键追加到文件末尾。
    let content = fs::read_to_string(CONFIG_PATH).unwrap_or_default();
    let mut found_timeout = false;
    let mut found_active = false;
    let mut found_idle = false;

    let mut lines: Vec<String> = content.lines().map(str::to_string).collect();
    for line in lines.iter_mut() {
        let trimmed = line.trim();
        let Some((k, _v)) = trimmed.split_once('=') else { continue };
        match k.trim() {
            "timeout" => {
                *line = format!("timeout={}", timeout);
                found_timeout = true;
            }
            "active" => {
                *line = format!("active={}", active);
                found_active = true;
            }
            "idle" => {
                *line = format!("idle={}", idle);
                found_idle = true;
            }
            _ => {}
        }
    }
    if !found_timeout {
        lines.push(format!("timeout={}", timeout));
    }
    if !found_active {
        lines.push(format!("active={}", active));
    }
    if !found_idle {
        lines.push(format!("idle={}", idle));
    }

    let _ = fs::write(CONFIG_PATH, lines.join("\n") + "\n");
    REFRESH_FORCE_RELOAD.store(true, Ordering::Release);
    wake();
}

pub fn refresh_get_apps() -> Vec<(String, i32, String, String)> {
    let content = match fs::read_to_string(CONFIG_PATH) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let mut apps = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.split(',').collect();
        if parts.len() != 4 {
            continue;
        }
        apps.push((
            parts[0].trim().to_string(),
            parts[1].trim().parse::<i32>().unwrap_or(30),
            parts[2].trim().to_string(),
            parts[3].trim().to_string(),
        ));
    }
    apps
}

pub fn refresh_add_app(pkg: &str, timeout: i32, active: &str, idle: &str) {
    let content = fs::read_to_string(CONFIG_PATH).unwrap_or_default();
    let mut lines: Vec<String> = content.lines().map(String::from).collect();
    let new_line = format!("{},{},{},{}", pkg, timeout, active, idle);
    let mut found = false;
    for line in lines.iter_mut() {
        if line.trim().starts_with('#') || line.trim().is_empty() {
            continue;
        }
        if line.split(',').next().map(|s| s.trim() == pkg).unwrap_or(false) {
            *line = new_line.clone();
            found = true;
            break;
        }
    }
    if !found {
        lines.push(new_line);
    }
    let _ = fs::write(CONFIG_PATH, lines.join("\n") + "\n");
    REFRESH_FORCE_RELOAD.store(true, Ordering::Release);
    wake();
}

pub fn refresh_del_app(pkg: &str) -> bool {
    let content = match fs::read_to_string(CONFIG_PATH) {
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
            line.split(',').next().map(|s| s.trim() != pkg).unwrap_or(true)
        })
        .map(String::from)
        .collect();
    let _ = fs::write(CONFIG_PATH, lines.join("\n") + "\n");
    REFRESH_FORCE_RELOAD.store(true, Ordering::Release);
    wake();
    true
}

pub fn refresh_get_status() -> Option<RefreshStatus> {
    REFRESH_STATUS.lock().unwrap().clone()
}
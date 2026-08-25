use std::collections::HashMap;
use std::ffi::CString;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::Mutex;
use std::sync::mpsc;
use std::thread;
use std::time::Instant;

const MODE_120: i32 = 0;
const MODE_60: i32 = 1;
const MODE_90: i32 = 2;

const CONFIG_PATH: &str = "./refresh_config.conf";
const APPS_CONFIG_PATH: &str = "./refresh_config_apps.conf";
const OOM_ADJ_DEBOUNCE_MS: u64 = 100;
const FG_ADJ_THRESHOLD: i32 = 200;

pub const EVENT_INPUT: u32 = 5;
pub const EVENT_OOM_ADJ: u32 = 7;

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
    OomAdj,
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
    last_fg_check_time: Option<Instant>,
    backlight_path: Option<String>,
    prev_backlight: bool,
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

fn find_backlight_path() -> Option<String> {
    let path = "/sys/class/leds/lcd-backlight/brightness";
    if std::path::Path::new(path).exists() {
        return Some(path.to_string());
    }
    if let Ok(entries) = fs::read_dir("/sys/class/backlight") {
        for entry in entries.flatten() {
            let brightness = entry.path().join("brightness");
            if brightness.exists() {
                return Some(brightness.to_string_lossy().into_owned());
            }
        }
    }
    None
}

fn read_backlight(path: &str) -> bool {
    fs::read_to_string(path)
        .ok()
        .and_then(|s| s.trim().parse::<i32>().ok())
        .map(|v| v > 0)
        .unwrap_or(false)
}

fn create_default_config() {
    if !std::path::Path::new(CONFIG_PATH).exists() {
        let _ = fs::write(CONFIG_PATH, "timeout=30\nactive=120\nidle=60\n");
    }
    if !std::path::Path::new(APPS_CONFIG_PATH).exists() {
        let _ = fs::write(APPS_CONFIG_PATH, "# packageName,timeout,activeMode,idleMode\n");
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
    let content = match fs::read_to_string(APPS_CONFIG_PATH) {
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
}

/// 扫描 /proc 找到前台应用：oom_score_adj 最低且 < 200 的用户应用
/// Android oom_score_adj: 前台 0-100, 可见 100-200, 后台 900+
fn find_foreground_package() -> Option<String> {
    let entries = fs::read_dir("/proc").ok()?;
    let mut best: Option<(String, i32)> = None;
    for entry in entries.flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<i32>() else { continue };

        let adj = fs::read_to_string(format!("/proc/{}/oom_score_adj", pid))
            .ok()
            .and_then(|s| s.trim().parse::<i32>().ok())
            .unwrap_or(1000);
        if adj >= FG_ADJ_THRESHOLD {
            continue;
        }

        let cmdline = match fs::read(format!("/proc/{}/cmdline", pid)) {
            Ok(data) => {
                let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
                let s = std::str::from_utf8(&data[..end]).unwrap_or("");
                let name = s.rsplit('/').next().unwrap_or(s);
                name.trim().to_string()
            }
            Err(_) => continue,
        };
        if cmdline.is_empty() {
            continue;
        }
        // 用户应用 UID >= 10000，桌面 com.android.launcher3 特殊放行
        let uid = fs::metadata(format!("/proc/{}", pid))
            .map(|m| m.uid())
            .unwrap_or(0);
        let is_user_app = uid >= 10000;
        let is_launcher = cmdline == "com.android.launcher3";
        if !is_user_app && !is_launcher {
            continue;
        }

        match &best {
            None => best = Some((cmdline, adj)),
            Some((_, b)) if adj < *b => best = Some((cmdline, adj)),
            _ => {}
        }
    }
    best.map(|(pkg, _)| pkg)
}

/// kprobe oom_score_adj_write 触发：前台应用可能变化
/// 扫描 /proc 确认实际前台应用（oom_score_adj 最低），仅在变化时切换
fn handle_oom_adj(state: &mut RefreshState) {
    let now = Instant::now();
    if let Some(last) = state.last_fg_check_time {
        if now - last < std::time::Duration::from_millis(OOM_ADJ_DEBOUNCE_MS) {
            return;
        }
    }
    state.last_fg_check_time = Some(now);

    let Some(pkg) = find_foreground_package() else { return };
    if pkg == state.last_applied_pkg {
        return;
    }

    state.current_package = pkg.clone();
    state.last_applied_pkg = pkg;
    state.last_apply_time = Some(now);

    let current_pkg = state.current_package.clone();
    apply_app_config(state, &current_pkg);
    set_refresh_rate(state, state.current_active);
    if state.prev_backlight {
        reset_timer(state, true);
    }
}

/// input_event 触发：用户活动
/// 切回活跃刷新率 + 重置定时器（仅在定时器运行时）
fn handle_input(state: &mut RefreshState) {
    if state.is_paused || state.current_applied_mode == state.current_idle {
        set_refresh_rate(state, state.current_active);
        state.is_paused = false;
    }
    if state.last_reset_time.is_some() {
        reset_timer(state, false);
    }
}

/// sysfs 背光 EPOLLPRI 触发：仅 0 边界穿越时操作
/// 0→>0 启动定时器，>0→0 关闭定时器，1~254 微调丢弃
fn handle_backlight_change(state: &mut RefreshState) {
    let Some(path) = &state.backlight_path else { return };
    let brightness = read_backlight(path);
    if brightness && !state.prev_backlight {
        // 0 → >0：启动定时器
        reset_timer(state, true);
    } else if !brightness && state.prev_backlight {
        // >0 → 0：关闭定时器
        timerfd_cancel(state.timer_fd);
        state.last_reset_time = None;
    }
    state.prev_backlight = brightness;
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

    let backlight_path = find_backlight_path();
    let backlight_fd = if let Some(path) = &backlight_path {
        let c_path = CString::new(path.as_str()).unwrap();
        let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_RDONLY | libc::O_NONBLOCK) };
        if fd < 0 {
            eprintln!("刷新率: 无法打开背光文件 {}", path);
        }
        fd
    } else {
        eprintln!("刷新率: 未找到背光路径，灭屏检测依赖 input 事件");
        -1
    };

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
        last_fg_check_time: None,
        backlight_path,
        prev_backlight: false,
        timer_fd,
    };

    load_global_config(&mut state);
    load_app_configs(&mut state);

    // 初始前台应用检测，确保 current_package 在线程启动前就绪
    if let Some(pkg) = find_foreground_package() {
        state.current_package = pkg.clone();
        state.last_applied_pkg = pkg;
        let current_pkg = state.current_package.clone();
        apply_app_config(&mut state, &current_pkg);
    }

    if let Some(path) = &state.backlight_path {
        state.prev_backlight = read_backlight(path);
        if state.prev_backlight {
            reset_timer(&mut state, true);
        }
    }

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

        if backlight_fd >= 0 {
            ev.events = (libc::EPOLLPRI | libc::EPOLLET) as u32;
            ev.u64 = 2;
            unsafe { libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, backlight_fd, &mut ev); }
        }

        let mut events: [libc::epoll_event; 3] = unsafe { std::mem::zeroed() };

        loop {
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
                                RefreshEvent::OomAdj => handle_oom_adj(&mut state),
                            }
                        }
                        check_config(&mut state);
                    }
                    1 => {
                        let mut val: u64 = 0;
                        unsafe { libc::read(timer_fd, &mut val as *mut _ as *mut _, 8); }
                        switch_to_idle(&mut state);
                    }
                    2 => {
                        handle_backlight_change(&mut state);
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
            if backlight_fd >= 0 { libc::close(backlight_fd); }
        }
    });
}

pub fn refresh_on_event(event_type: u32, _pid: i32) {
    let guard = REFRESH_TX.lock().unwrap();
    if let Some(tx) = guard.as_ref() {
        let event = match event_type {
            EVENT_INPUT => RefreshEvent::Input,
            EVENT_OOM_ADJ => RefreshEvent::OomAdj,
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
    let content = format!("timeout={}\nactive={}\nidle={}\n", timeout, active, idle);
    let _ = fs::write(CONFIG_PATH, content);
    REFRESH_FORCE_RELOAD.store(true, Ordering::Release);
    wake();
}

pub fn refresh_get_apps() -> Vec<(String, i32, String, String)> {
    let content = match fs::read_to_string(APPS_CONFIG_PATH) {
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
    let content = fs::read_to_string(APPS_CONFIG_PATH).unwrap_or_default();
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
    let _ = fs::write(APPS_CONFIG_PATH, lines.join("\n") + "\n");
    REFRESH_FORCE_RELOAD.store(true, Ordering::Release);
    wake();
}

pub fn refresh_del_app(pkg: &str) -> bool {
    let content = match fs::read_to_string(APPS_CONFIG_PATH) {
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
    let _ = fs::write(APPS_CONFIG_PATH, lines.join("\n") + "\n");
    REFRESH_FORCE_RELOAD.store(true, Ordering::Release);
    wake();
    true
}

pub fn refresh_get_status() -> Option<RefreshStatus> {
    REFRESH_STATUS.lock().unwrap().clone()
}
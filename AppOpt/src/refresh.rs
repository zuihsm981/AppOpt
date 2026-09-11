use std::collections::HashMap;
use std::process::Command;
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

/// 从设备可用档位取默认值: active=最高档, idle=最低档 (不硬编码 120/60)
fn default_rates_from_modes(available_modes: &[bool; 3]) -> (i32, i32) {
    let mut avail: Vec<i32> = Vec::new();
    if available_modes[0] { avail.push(120); }
    if available_modes[1] { avail.push(90); }
    if available_modes[2] { avail.push(60); }
    if avail.is_empty() { avail = vec![120, 90, 60]; }
    (*avail.iter().max().unwrap(), *avail.iter().min().unwrap())
}

/// 把全局默认刷新率写入指定配置文件**开头** (已存在的字段不覆盖, 尊重用户配置)。
/// 供启动初始化与 webui 新建配置文件复用。
pub(crate) fn write_global_refresh_defaults(path: &str, active: i32, idle: i32) {
    if path.is_empty() {
        return;
    }
    let content = fs::read_to_string(path).unwrap_or_default();
    let has = |k: &str| {
        content.lines().any(|l| {
            l.trim()
                .split_once('=')
                .map(|(a, _)| a.trim() == k)
                .unwrap_or(false)
        })
    };
    let mut pre: Vec<String> = Vec::new();
    if !has("refresh_active") {
        pre.push(format!("refresh_active={}", active));
    }
    if !has("refresh_idle") {
        pre.push(format!("refresh_idle={}", idle));
    }
    if !has("refresh_timeout") {
        pre.push("refresh_timeout=30".to_string());
    }
    if pre.is_empty() {
        return;
    }
    // 写入文件开头 (保留原有内容)
    let mut lines = pre;
    lines.extend(content.lines().map(str::to_string));
    if fs::write(path, lines.join("\n") + "\n").is_err() {
        return;
    }
    // 同步共享配置 (全局刷新率生效) + 通知 refresh 线程重新加载
    crate::config::reload_refresh_only();
    REFRESH_FORCE_RELOAD.store(true, Ordering::Release);
}

/// 供 webui 新建配置文件使用: 取当前设备默认档位 (active=最高, idle=最低)
pub(crate) fn refresh_device_default_rates() -> (i32, i32) {
    let mut avail = refresh_get_status().map(|s| s.available).unwrap_or_default();
    if avail.is_empty() {
        avail = vec![120, 90, 60];
    }
    (*avail.iter().max().unwrap(), *avail.iter().min().unwrap())
}

/// 启动初始化: 设备可用刷新率解析完成后, 把全局默认写入当前配置文件开头
fn ensure_global_refresh_defaults(state: &RefreshState) {
    let (active, idle) = default_rates_from_modes(&state.available_modes);
    write_global_refresh_defaults(&config_path(), active, idle);
}

pub const EVENT_INPUT: u32 = 5;

static REFRESH_FORCE_RELOAD: AtomicBool = AtomicBool::new(false);
/// input 触摸事件 kprobe 当前武装状态 (初始 false: 由 activate() 的 input_on 成功后置位)
pub(crate) static INPUT_HOOK_ON: AtomicBool = AtomicBool::new(false);
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
    /// 设备可用刷新率 (Hz), 供 web 过滤选项 (如仅 [90, 60])
    pub available: Vec<i32>,
    /// 设备全部显示模式 (格式化: "id|WxH Hz"), 供 web 展示
    pub device_modes: std::sync::Arc<Vec<String>>,
    /// 内核 input 触摸 kprobe 是否已武装
    pub input_hooked: bool,
    /// 距上次 input 事件秒数 (-1 = 无事件)
    pub last_input_secs: i64,
}

enum RefreshEvent {
    Input,
    /// 主线程判定前台 uid 命中刷新率表后, 下发包名应用刷新率
    FgPkg(String),
}

struct AppRefreshConfig {
    timeout: i32,
    active_mode: i32,
    idle_mode: i32,
}

struct RefreshState {
    /// 设备实际显示模式 id: [120Hz 模式, 90Hz 模式, 60Hz 模式]
    /// (binder 1035 的 i32 参数 = 显示模式 id; 由初始化 dumpsys 解析自动检测)
    rate_args: [i32; 3],
    /// 设备可用刷新率档位 [120, 90, 60] (web 据此隐藏不可用选项)
    available_modes: [bool; 3],
    /// 设备全部显示模式 (格式化: "id|WxH Hz")
    device_modes: std::sync::Arc<Vec<String>>,
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
    last_input_time: Option<Instant>,
    timer_fd: i32,
}

/// 从共享 CURRENT_CONFIG 读取刷新率全局配置（统一加载，避免线程内重复读文件）
fn load_global_config(state: &mut RefreshState) {
    let cfg = crate::rw_read_ignore_poison(&crate::config::CURRENT_CONFIG).clone();
    let Some(cfg) = cfg else { return };
    state.timeout_seconds = cfg.refresh_timeout;
    state.active_mode = cfg.refresh_active;
    state.idle_mode = cfg.refresh_idle;
    state.current_active = state.active_mode;
    state.current_idle = state.idle_mode;
    state.current_timeout = state.timeout_seconds;
    state.timer_enabled = state.current_idle != state.current_active;
    sync_input_hook(state);
    // 用户态触摸监听按需启停: 活跃==空闲(无需 input 切换)暂停 event5, 切换应用
    // 后按新规则恢复 (KPM 模式此开关同样生效, 避免双源)
    crate::touch_probe::set_enabled(state.timer_enabled);
}

/// 从共享 CURRENT_CONFIG 读取按应用刷新率配置（统一加载）
fn load_app_configs(state: &mut RefreshState) {
    state.app_configs.clear();
    let cfg = crate::rw_read_ignore_poison(&crate::config::CURRENT_CONFIG).clone();
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
    // 内部 mode 码 (MODE_120/60/90) → 设备实际显示模式 id (初始化检测所得)
    let arg = match mode {
        MODE_120 => state.rate_args[0],
        MODE_90 => state.rate_args[1],
        MODE_60 => state.rate_args[2],
        _ => mode,
    };
    // 解析失败/未检测到该档位 (arg<0): 不切换, 避免发送错误模式 id
    if arg < 0 {
        state.current_applied_mode = mode;
        return;
    }
    // 只走 binder 直连 SurfaceFlinger，不再回退到 service 子进程
    crate::process_observer::set_refresh_rate_binder(arg);
    state.current_applied_mode = mode;
}

fn apply_app_config(state: &mut RefreshState, pkg: &str) {
    // com.android.launcher3 是默认桌面, 始终绑定全局刷新率配置;
    // 即使配置文件中残留同名 refresh_app 行，也不能把桌面切到应用级覆盖值。
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
    sync_input_hook(state);
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

/// 刷新率活跃==空闲时无 idle→active 切换, 无需触摸事件: 卸载 input kprobe 省开销;
/// 不同时重新安装。仅状态变化时下发 ctl0 (input_on/input_off)。
fn sync_input_hook(state: &RefreshState) {
    let want = state.timer_enabled;
    if INPUT_HOOK_ON.swap(want, Ordering::AcqRel) != want {
        crate::ebpf_mode::set_input_hook(want);
    }
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

/// 刷新率应用: 仅 launcher 或已配置应用会到达此处 (主线程 rfr uid 表已过滤,
/// 不存在"无配置 → 无配置"场景)。launcher(视为无配置) → 全局配置; 已配置 → 专属配置。
fn try_apply_fg_pkg(state: &mut RefreshState, pkg: &str) -> bool {
    if pkg.is_empty() {
        return false;
    }
    state.current_package = pkg.to_string();
    apply_app_config(state, pkg);
    set_refresh_rate(state, state.current_active);
    reset_timer(state, true);
    true
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
        available: {
            let mut v = Vec::new();
            if state.available_modes[0] { v.push(120); }
            if state.available_modes[1] { v.push(90); }
            if state.available_modes[2] { v.push(60); }
            v
        },
        device_modes: std::sync::Arc::clone(&state.device_modes),
        input_hooked: INPUT_HOOK_ON.load(Ordering::Relaxed),
        last_input_secs: state
            .last_input_time
            .map(|t| t.elapsed().as_secs() as i64)
            .unwrap_or(-1),
    };
    *crate::lock_ignore_poison(&REFRESH_STATUS) = Some(status);
}

fn wake() {
    let fd = WAKE_FD.load(Ordering::Acquire);
    if fd >= 0 {
        let val: u64 = 1;
        unsafe { libc::write(fd, &val as *const u64 as *const _, 8); }
    }
}

pub fn refresh_init(display_modes: std::thread::JoinHandle<Vec<(u32, u32, u32, f32)>>) {
    let wake_fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
    if wake_fd < 0 {
        return;
    }
    WAKE_FD.store(wake_fd, Ordering::Release);

    let timer_fd = unsafe {
        libc::timerfd_create(libc::CLOCK_MONOTONIC, libc::TFD_CLOEXEC | libc::TFD_NONBLOCK)
    };
    if timer_fd < 0 {
        unsafe { libc::close(wake_fd); }
        return;
    }

    let (tx, rx) = mpsc::channel::<RefreshEvent>();
    *crate::lock_ignore_poison(&REFRESH_TX) = Some(tx);

    // 初始化一次性解析 dumpsys display 的显示模式: 已在 L1 并发线程完成, join 取结果
    let device_modes_raw = display_modes.join().unwrap_or_default();
    let mut state = RefreshState {
        timeout_seconds: 30,
        active_mode: MODE_120,
        idle_mode: MODE_60,
        app_configs: HashMap::new(),
        current_active: MODE_120,
        current_idle: MODE_60,
        current_timeout: 30,
        current_applied_mode: -1,
        rate_args: detect_rate_args(&device_modes_raw),
        available_modes: detect_available_modes(&device_modes_raw),
        device_modes: std::sync::Arc::new(fmt_device_modes(&device_modes_raw)),
        is_paused: false,
        timer_enabled: true,
        last_reset_time: None,
        current_package: String::new(),
        last_input_time: None,
        timer_fd,
    };

    // 设备可用刷新率已解析: 首次运行写入全局默认到配置文件开头 (已有字段不覆盖)
    ensure_global_refresh_defaults(&state);
    load_global_config(&mut state);
    load_app_configs(&mut state);

    let name = CString::new("RefreshRate").unwrap();
    thread::spawn(move || {
        unsafe { libc::pthread_setname_np(libc::pthread_self(), name.as_ptr()); }

        // 初始化先应用一次全局 active 刷新率 (异步: 在后台线程执行 SF binder,
        // 不阻塞主初始化; launcher 的全局绑定由 init 时 marked 标记完成)。
        let active = state.current_active;
        set_refresh_rate(&mut state, active);

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
            // 事件驱动：阻塞等待事件；无轮询、无超时兜底。
            // 前台包名由 binder 回调 pid + /proc cmdline 直接解析, 无共享缓存依赖。
            let n = unsafe { libc::epoll_wait(epfd, events.as_mut_ptr(), 3, -1) };
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
                                RefreshEvent::FgPkg(pkg) => {
                                    try_apply_fg_pkg(&mut state, &pkg);
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

/// 主线程命中刷新率 uid 表后, 下发前台包名 (三线程: 主 → 刷新率线程)。
pub fn refresh_send_fg_pkg(pkg: String) {
    let guard = crate::lock_ignore_poison(&REFRESH_TX);
    if let Some(tx) = guard.as_ref() {
        let _ = tx.send(RefreshEvent::FgPkg(pkg));
        wake();
    }
}

pub fn refresh_on_event(event_type: u32, _pid: i32) {
    let guard = crate::lock_ignore_poison(&REFRESH_TX);
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
    if let Some(cfg) = crate::rw_read_ignore_poison(&crate::config::CURRENT_CONFIG).clone() {
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
    let Some(cfg) = crate::rw_read_ignore_poison(&crate::config::CURRENT_CONFIG).clone() else {
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

/// 判断一行是否属于该包的刷新率配置 (新格式 pkg=refresh-*, 兼容旧格式
/// refresh_app,<pkg>,… / <pkg>,t,a,i)
fn is_refresh_pkg_line(line: &str, pkg: &str) -> bool {
    let t = line.trim();
    if let Some((k, v)) = t.split_once('=') {
        return k.trim() == pkg && v.starts_with("refresh-");
    }
    let fields: Vec<&str> = t.split(',').map(str::trim).collect();
    (fields.len() == 5 && fields[0] == "refresh_app" && fields[1] == pkg)
        || (fields.len() == 4 && fields[0] == pkg)
}

pub fn refresh_add_app(pkg: &str, timeout: i32, active: &str, idle: &str) {
    let path = config_path();
    let content = fs::read_to_string(&path).unwrap_or_default();
    let mut lines: Vec<String> = content.lines().map(String::from).collect();
    // 新格式: pkg=refresh-<timeout>-<active>-<idle>
    let new_line = format!("{}=refresh-{}-{}-{}", pkg, timeout, active, idle);
    let mut found = false;
    for line in lines.iter_mut() {
        if line.trim().starts_with('#') || line.trim().is_empty() {
            continue;
        }
        if is_refresh_pkg_line(line, pkg) {
            *line = new_line.clone();
            found = true;
            break;
        }
    }
    if !found {
        lines.push(new_line);
    }
    if !crate::config::save_config_lines(&path, &lines) {
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
            !is_refresh_pkg_line(line, pkg)
        })
        .map(String::from)
        .collect();
    if !crate::config::save_config_lines(&path, &lines) {
        return false;
    }
    // 同步共享配置（仅刷新率）+ 独立通知 refresh 线程
    crate::config::reload_refresh_only();
    REFRESH_FORCE_RELOAD.store(true, Ordering::Release);
    wake();
    true
}

pub fn refresh_get_status() -> Option<RefreshStatus> {
    crate::lock_ignore_poison(&REFRESH_STATUS).clone()
}

/// 解析 `dumpsys display` 支持的显示模式 (display_modes.sh v3/v2 同款文本解析):
/// 返回 (mode_id, width, height, fps)。失败/无输出返回空表。
/// 解析 `dumpsys display` 的显示模式 (模仿命令行):
///   dumpsys display | grep 'DisplayMode{id=' | awk -F'[,{}]' '{... peakRefreshRate= ...}'
/// 即: 只处理含 `DisplayMode{id=` 的行; 以 `,` `{` `}` 为分隔符切分整行;
/// 取 `id=`/`width=`/`height=`/`peakRefreshRate=` 字段, 刷新率截断小数取整数 Hz。
/// 另兼容部分 ROM 用 `refreshRate=`/`vsyncRate=`/`fps=` 字段 (优先 peakRefreshRate)。
pub(crate) fn parse_display_modes() -> Vec<(u32, u32, u32, f32)> {
    let out = match Command::new("dumpsys").arg("display").output() {
        Ok(o) if o.status.success() => o,
        _ => return Vec::new(),
    };
    let text = String::from_utf8_lossy(&out.stdout);
    let mut modes: Vec<(u32, u32, u32, f32)> = Vec::new();
    for line in text.lines() {
        // 行过滤: 仅含字面量 DisplayMode{id= (awk grep 'DisplayMode{id=')
        if !line.contains("DisplayMode{id=") {
            continue;
        }
        let (mut id, mut w, mut h): (Option<u32>, Option<u32>, Option<u32>) = (None, None, None);
        let mut fps: Option<f32> = None;
        // 以 , { } 为分隔符切分整行 (awk -F'[,{}]')
        for col in line.split(|c: char| c == ',' || c == '{' || c == '}') {
            let col = col.trim();
            if let Some(v) = col.strip_prefix("id=") {
                id = v.trim().parse().ok();
            } else if let Some(v) = col.strip_prefix("width=") {
                w = v.trim().parse().ok();
            } else if let Some(v) = col.strip_prefix("height=") {
                h = v.trim().parse().ok();
            } else if let Some(v) = col.strip_prefix("peakRefreshRate=") {
                // 截断小数 → 整数 Hz (awk sub(/\..*/,"",r))
                fps = v.split('.').next().unwrap_or(v).trim().parse().ok();
            } else if fps.is_none() {
                // 兜底字段 (部分 ROM): refreshRate / vsyncRate / fps, 同样截断小数
                let r = ["refreshRate=", "vsyncRate=", "fps="]
                    .iter()
                    .find_map(|p| col.strip_prefix(p));
                if let Some(v) = r {
                    fps = v.split('.').next().unwrap_or(v).trim().parse().ok();
                }
            }
        }
        if let (Some(id), Some(w), Some(h), Some(fps)) = (id, w, h, fps) {
            modes.push((id, w, h, fps));
        }
    }
    modes
}

/// 初始化自动检测显示模式 id (返回 [高档, 中档90, 低档]):
///   - 高档 (原 120): 最高可用刷新率的 mode id —— 只有 90/60 的设备自动落到 90
///   - 中档 (90):     最接近 90Hz 的 mode id
///   - 低档 (原 60):  最低可用刷新率的 mode id
/// 同档多个分辨率取最小 id (首分辨率档)。解析失败返回 [-1,-1,-1] (未知),
/// 调用方不切换刷新率; 不做硬编码回退。
fn detect_rate_args(modes: &[(u32, u32, u32, f32)]) -> [i32; 3] {
    if modes.is_empty() {
        return [-1, -1, -1];
    }
    let max_fps = modes.iter().map(|m| m.3).fold(0.0f32, f32::max);
    let min_fps = modes.iter().map(|m| m.3).fold(f32::MAX, f32::min);
    // 高档 = 最高可用刷新率 (同档取最小 id, 即首分辨率档)
    let high = modes
        .iter()
        .filter(|m| (m.3 - max_fps).abs() < 0.5)
        .min_by_key(|m| m.0)
        .map(|m| m.0 as i32)
        .unwrap_or(-1);
    // 低档 = 最低可用刷新率 (同档取最小 id)
    let low = modes
        .iter()
        .filter(|m| (m.3 - min_fps).abs() < 0.5)
        .min_by_key(|m| m.0)
        .map(|m| m.0 as i32)
        .unwrap_or(-1);
    // 中档 (90) = 最接近 90Hz 的 mode id (90/60 设备 → 90)
    let mid = modes
        .iter()
        .min_by(|a, b| {
            let da = (a.3 - 90.0).abs();
            let db = (b.3 - 90.0).abs();
            da.partial_cmp(&db).unwrap_or(std::cmp::Ordering::Equal)
        })
        .map(|m| m.0 as i32)
        .unwrap_or(-1);
    [high, mid, low]
}

/// 检测设备可用刷新率档位 [120, 90, 60] (web 隐藏不可用选项)。
/// 解析失败默认全可用 (不隐藏选项; 缺档由 rate_args=-1 在发送时直接不切换)。
fn detect_available_modes(modes: &[(u32, u32, u32, f32)]) -> [bool; 3] {
    if modes.is_empty() {
        return [true, true, true];
    }
    let has = |t: f32| modes.iter().any(|m| (m.3 - t).abs() < 0.5);
    [has(120.0), has(90.0), has(60.0)]
}

/// 格式化设备全部显示模式 (web "设备刷新率" 展示): "id|WxH Hz" (display_modes.sh 同款)
fn fmt_device_modes(modes: &[(u32, u32, u32, f32)]) -> Vec<String> {
    modes
        .iter()
        .map(|(id, w, h, fps)| format!("{}|{}x{} {}Hz", id, w, h, fps.trunc() as u32))
        .collect()
}

use std::collections::HashMap;
use std::process::Command;
use std::ffi::CString;
use std::fs;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::{mpsc, Mutex};
use std::thread;
use std::time::Instant;


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
    /* 文件已保存 活跃==空闲 (refresh_active == refresh_idle) → 不补写 refresh_timeout,
     * 与 refresh_set_config 同率保存删行保持一致 (避免重启把超时默认补回) */
    let val_of = |k: &str| -> Option<String> {
        content.lines().find_map(|l| {
            let t = l.trim();
            let (kk, v) = t.split_once('=')?;
            (kk.trim() == k).then(|| v.trim().to_string())
        })
    };
    let file_same = match (val_of("refresh_active"), val_of("refresh_idle")) {
        (Some(a), Some(i)) => a == i,
        _ => false,
    };
    if !has("refresh_timeout") && !file_same {
        pre.push("refresh_timeout=30".to_string());
    }
    if pre.is_empty() {
        return;
    }
    // 写入位置: 跳过开头连续注释/空行, 插在文件头注释的下面 (保留原有内容)
    let mut lines: Vec<String> = content.lines().map(str::to_string).collect();
    let mut at = 0;
    while at < lines.len() {
        let t = lines[at].trim();
        if t.starts_with('#') || t.is_empty() {
            at += 1;
        } else {
            break;
        }
    }
    for (i, l) in pre.into_iter().enumerate() {
        lines.insert(at + i, l);
    }
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
static WAKE_FD: AtomicI32 = AtomicI32::new(-1);
/// web 轮询请求刷新状态快照 (仅被请求时才 update_status, 避免每次事件都构建)
static STATUS_REQ: AtomicBool = AtomicBool::new(false);
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
    /// 用户态触摸监听是否就绪 (event_probe::TOUCH_LISTENING)
    pub input_hooked: bool,
    /// 距上次 input 事件秒数 (-1 = 无事件)
    pub last_input_secs: i64,
}

enum RefreshEvent {
    Input,
    /// 主线程判定前台 uid 命中刷新率表后, 下发 (uid, 包名) 应用刷新率
    FgPkg(i32, String),
    /// activity 级刷新率事件 (0xc): (uid, 包名, activity 完整类名);
    /// 命中恒值映射 → 该界面恒用对应刷新率 (无回落); 未命中 → 包级默认
    Act(i32, String, String),
    /// 规则应用退出: 清理该 uid 的 act 刷新率缓存
    ActCacheClear(i32),
    /// 挂机黑屏挂起/恢复: true=停止空闲回落定时器 (刷新率保持 active,
    /// 单击恢复时无刷新率切换, 避免面板切换绿屏/瞬亮); false=重启定时器
    HangSuspend(bool),
}

struct AppRefreshConfig {
    timeout: i32,
    active_mode: i32,
    idle_mode: i32,
}

/// 刷新率三参数 (active/idle/timeout); global=全局默认, effective=当前生效 (应用级覆盖)
struct RateConfig {
    active: i32,
    idle: i32,
    timeout: i32,
}

struct RefreshState {
    /// 设备实际显示模式 id: [120Hz 模式, 90Hz 模式, 60Hz 模式]
    /// (binder 1035 的 i32 参数 = 显示模式 id; 由初始化 dumpsys 解析自动检测)
    rate_args: [i32; 3],
    /// 设备可用刷新率档位 [120, 90, 60] (web 据此隐藏不可用选项)
    available_modes: [bool; 3],
    /// 设备全部显示模式 (格式化: "id|WxH Hz")
    device_modes: std::sync::Arc<Vec<String>>,
    /// 全局默认配置 (从 refresh_* 字段加载)
    global: RateConfig,
    app_configs: HashMap<String, AppRefreshConfig>,
    /// activity 级恒值映射: pkg -> (activity完整类名 -> 刷新率模式码); 命中即恒值无回落
    app_activity: HashMap<String, HashMap<String, i32>>,
    /// act 规则缓存: uid → 该 uid 上一次已应用的刷新率模式码 (无 activity 记录)。
    ///  · act 命中 → 写入; 该 uid 回落包级 → 删除; 应用退出 → 删除
    ///  · 包级事件/配置热更/回到前台: 同 uid 有缓存且包有 activity 规则 → 保持该值
    act_last: std::collections::HashMap<i32, i32>,
    /// 当前前台 uid (与 current_package 配对; 配置热更时用于恢复 activity 恒值)
    current_uid: i32,
    /// 当前生效配置 (全局默认, 或被应用级配置覆盖)
    effective: RateConfig,
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
    state.global.timeout = cfg.refresh_timeout;
    state.global.active = cfg.refresh_active;
    state.global.idle = cfg.refresh_idle;
    state.effective.active = state.global.active;
    state.effective.idle = state.global.idle;
    state.effective.timeout = state.global.timeout;
    state.timer_enabled = state.effective.idle != state.effective.active;
    // 用户态触摸监听按需启停: 活跃==空闲(无需 input 切换)暂停监听, 切换应用
    // 后按新规则恢复 (KPM 模式此开关同样生效, 避免双源)
    crate::event_probe::set_enabled(state.timer_enabled);
}

/// 从共享 CURRENT_CONFIG 读取按应用刷新率配置（统一加载）
fn load_app_configs(state: &mut RefreshState) {
    state.app_configs.clear();
    state.app_activity.clear();
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
    for (pkg, acts) in &cfg.app_refresh_activity {
        state.app_activity.insert(pkg.clone(), acts.clone());
    }
}

fn set_refresh_rate(state: &mut RefreshState, mode: i32) {
    if mode == state.current_applied_mode {
        return;
    }
    // 内部 mode 码 (MODE_120/60/90) → 设备实际显示模式 id (初始化检测所得)
    let arg = match mode {
        crate::config::REFRESH_MODE_120 => state.rate_args[0],
        crate::config::REFRESH_MODE_90 => state.rate_args[1],
        crate::config::REFRESH_MODE_60 => state.rate_args[2],
        _ => mode,
    };
    // 解析失败/未检测到该档位 (arg<0): 不切换也不改内部状态 (保持原档位,
    // 避免"假切换"——实际没切, 内部却以为切了)
    if arg < 0 {
        return;
    }
    // 只走 binder 直连 SurfaceFlinger，不再回退到 service 子进程
    let _ok = crate::process_observer::set_refresh_rate_binder(arg);
    state.current_applied_mode = mode;
}

/// 包级/全局取值 (纯计算, 不含 activity 概念)
fn apply_pkg_rates(state: &mut RefreshState, pkg: &str) {
    // com.android.launcher3 是默认桌面, 始终绑定全局刷新率配置;
    // 即使配置文件中残留同名刷新率行，也不能把桌面切到应用级覆盖值。
    if pkg != crate::config::DEFAULT_REFRESH_PACKAGE {
        if let Some(cfg) = state.app_configs.get(pkg) {
            state.effective.timeout = cfg.timeout;
            state.effective.active = cfg.active_mode;
            state.effective.idle = cfg.idle_mode;
            return;
        }
    }
    state.effective.timeout = state.global.timeout;
    state.effective.active = state.global.active;
    state.effective.idle = state.global.idle;
}

/// 落地: 按 effective 计算 timer/触摸开关并切档
fn finish_apply(state: &mut RefreshState) {
    state.timer_enabled = state.effective.idle != state.effective.active;
    // 同步触摸监听开关 (与 load_global_config 一致)
    crate::event_probe::set_enabled(state.timer_enabled);
    set_refresh_rate(state, state.effective.active);
    reset_timer(state, true);
}

/// 刷新率解析与应用 (唯一入口)
/// 优先级:
///   ① comp 命中 activity 规则        → 该 activity 恒值 (写 act_last)
///   ② 该 uid 上次 activity 同包       → 保持该恒值 (包级事件/配置热更不得覆盖)
///   ③ 包级配置 / 全局                → 回落 (明确给了 comp 且未命中 → 清该 uid 缓存)
fn resolve_apply(state: &mut RefreshState, uid: i32, pkg: &str, comp: Option<&str>) {
    if pkg.is_empty() {
        return;
    }
    state.current_uid = uid;
    state.current_package = pkg.to_string();
    let timeout_for_pkg = |st: &RefreshState| -> i32 {
        st.app_configs
            .get(pkg)
            .map(|c| c.timeout)
            .unwrap_or(st.global.timeout)
    };

    /* ① 明确的 activity 命中 → 恒值 */
    if let Some(c) = comp {
        if !c.is_empty() {
            if let Some(v) = state.app_activity.get(pkg).and_then(|m| m.get(c)).copied() {
                state.effective.timeout = timeout_for_pkg(state);
                state.effective.active = v;
                state.effective.idle = v;
                state.act_last.insert(uid, v);
                finish_apply(state);
                return;
            }
        }
    }

    /* ② 只有"没有 activity 信息"的事件 (FgPkg / 配置热更) 才用缓存保持上次刷新率;
     * 明确带着 activity 但没命中时必须走 ③ 回落包级 (否则返回无规则页面不回 90) */
    if comp.is_none() && state.app_activity.contains_key(pkg) {
        if let Some(&mode) = state.act_last.get(&uid) {
            state.effective.timeout = timeout_for_pkg(state);
            state.effective.active = mode;
            state.effective.idle = mode;
            finish_apply(state);
            return;
        }
    }

    /* ③ 回落包级/全局 */
    if let Some(c) = comp {
        if !c.is_empty() {
            state.act_last.remove(&uid);   /* activity 未命中 → 清该 uid 缓存 */
        }
    }
    apply_pkg_rates(state, pkg);
    finish_apply(state);
}

/// 前台包变化 (EV_TASK → FgPkg): 无 activity 信息, 走解析器 (可命中 uid 缓存)
fn try_apply_fg_pkg(state: &mut RefreshState, uid: i32, pkg: &str) -> bool {
    if pkg.is_empty() {
        return false;
    }
    resolve_apply(state, uid, pkg, None);
    true
}

/// activity 事件 (0xc): 带 activity 类名走解析器
fn apply_activity(state: &mut RefreshState, uid: i32, pkg: &str, comp: &str) {
    if pkg.is_empty() || comp.is_empty() {
        return;
    }
    // 无 activity 块的包: 包级刷新率已由 task event 应用, activity 事件不干预
    if !state.app_activity.contains_key(pkg) {
        return;
    }
    resolve_apply(state, uid, pkg, Some(comp));
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

/// 刷新率活跃==空闲时无 idle→active 切换, 无需触摸事件:
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
        && state.current_applied_mode == state.effective.active
        && state.effective.active != state.effective.idle
    {
        let debounce = std::time::Duration::from_secs((state.effective.timeout - 10).max(0) as u64);
        if let Some(last) = state.last_reset_time {
            if now - last < debounce {
                return;
            }
        }
    }
    timerfd_set(state.timer_fd, state.effective.timeout);
    state.last_reset_time = Some(now);
}

fn switch_to_idle(state: &mut RefreshState) {
    if !state.timer_enabled {
        return;
    }
    set_refresh_rate(state, state.effective.idle);
    state.is_paused = true;
    timerfd_cancel(state.timer_fd);
    state.last_reset_time = None;
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
        set_refresh_rate(state, state.effective.active);
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
        /* 配置热更: 用解析器按当前 (uid, 包) 重新决定 (act_last 命中则保持 activity 恒值) */
        let current_pkg = state.current_package.clone();
        let cur_uid = state.current_uid;
        resolve_apply(state, cur_uid, &current_pkg, None);
    }
}

fn update_status(state: &RefreshState) {
    let status = RefreshStatus {
        current_mode: state.current_applied_mode,
        is_paused: state.is_paused,
        timer_enabled: state.timer_enabled,
        timer_running: state.last_reset_time.is_some(),
        current_package: state.current_package.clone(),
        timeout: state.effective.timeout,
        active_mode: state.effective.active,
        idle_mode: state.effective.idle,
        available: [120, 90, 60]
            .iter()
            .zip(state.available_modes)
            .filter_map(|(r, ok)| ok.then_some(*r))
            .collect(),
        device_modes: std::sync::Arc::clone(&state.device_modes),
        input_hooked: crate::event_probe::TOUCH_LISTENING.load(Ordering::Relaxed),
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
        global: RateConfig {
            active: crate::config::REFRESH_MODE_120,
            idle: crate::config::REFRESH_MODE_60,
            timeout: 30,
        },
        app_configs: HashMap::new(),
        app_activity: HashMap::new(),
        act_last: std::collections::HashMap::new(),
        effective: RateConfig {
            active: crate::config::REFRESH_MODE_120,
            idle: crate::config::REFRESH_MODE_60,
            timeout: 30,
        },
        current_applied_mode: -1,
        rate_args: detect_rate_args(&device_modes_raw),
        available_modes: detect_available_modes(&device_modes_raw),
        device_modes: std::sync::Arc::new(fmt_device_modes(&device_modes_raw)),
        is_paused: false,
        timer_enabled: true,
        last_reset_time: None,
        current_package: String::new(),
        current_uid: -1,
        last_input_time: None,
        timer_fd,
    };

    // 设备可用刷新率已解析: 首次运行写入全局默认到配置文件开头 (已有字段不覆盖)
    ensure_global_refresh_defaults(&state);
    load_global_config(&mut state);
    load_app_configs(&mut state);

    // 初始状态快照 (web 首次轮询即可读到; 之后仅在轮询请求时更新)
    update_status(&state);

    let name = CString::new("RefreshRate").unwrap();
    thread::spawn(move || {
        unsafe { libc::pthread_setname_np(libc::pthread_self(), name.as_ptr()); }

        // 初始化先应用一次全局 active 刷新率 (异步: 在后台线程执行 SF binder,
        // 不阻塞主初始化; launcher 的全局刷新率绑定由主线程 uid 表驱动。
        let active = state.effective.active;
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
                                RefreshEvent::FgPkg(uid, pkg) => {
                                    try_apply_fg_pkg(&mut state, uid, &pkg);
                                }
                                RefreshEvent::Act(uid, pkg, comp) => {
                                    apply_activity(&mut state, uid, &pkg, &comp);
                                }
                                RefreshEvent::ActCacheClear(uid) => {
                                    state.act_last.remove(&uid);
                                }
                                RefreshEvent::HangSuspend(on) => {
                                    if on {
                                        // 黑屏: 停止空闲回落定时器 → 刷新率保持 active,
                                        // 单击时 handle_input 切回 active 无实际切换
                                        timerfd_cancel(state.timer_fd);
                                        state.last_reset_time = None;
                                    } else {
                                        // 渐亮稳定: 重启空闲回落定时器
                                        reset_timer(&mut state, true);
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
            // 仅在 web 轮询请求时更新状态快照 (避免每个事件都构建)
            if STATUS_REQ.swap(false, Ordering::AcqRel) {
                update_status(&state);
            }
        }

        unsafe {
            libc::close(epfd);
            libc::close(wake_fd);
            libc::close(timer_fd);
        }
    });
}

/// 主线程命中刷新率 uid 表后, 下发前台包名 (三线程: 主 → 刷新率线程)。
pub fn refresh_send_fg_pkg(uid: i32, pkg: String) {
    let guard = crate::lock_ignore_poison(&REFRESH_TX);
    if let Some(tx) = guard.as_ref() {
        let _ = tx.send(RefreshEvent::FgPkg(uid, pkg));
        wake();
    }
}

/// KPM activity 事件: 按完整类名精确匹配 activity 恒值映射并应用刷新率
/// (命中 → 恒值无回落; 未命中 → 包级默认)。主线程 EV_ACT 调用。
/// 规则应用退出: 清理该 uid 的 act 刷新率缓存
pub fn refresh_act_cache_clear(uid: i32) {
    let guard = crate::lock_ignore_poison(&REFRESH_TX);
    if let Some(tx) = guard.as_ref() {
        let _ = tx.send(RefreshEvent::ActCacheClear(uid));
        wake();
    }
}

pub fn refresh_send_fg_act(uid: i32, pkg: String, comp: String) {
    let guard = crate::lock_ignore_poison(&REFRESH_TX);
    if let Some(tx) = guard.as_ref() {
        let _ = tx.send(RefreshEvent::Act(uid, pkg, comp));
        wake();
    }
}


/// 挂机黑屏挂起/恢复 (由 hang_monitor 线程调用):
///   true  = 黑屏写 0 后: 停止空闲回落定时器 (刷新率保持 active,
///           单击恢复时无刷新率切换, 避免面板切换绿屏/瞬亮);
///   false = 渐亮稳定后: 重启空闲回落定时器。
pub fn refresh_hang_suspend(on: bool) {
    let guard = crate::lock_ignore_poison(&REFRESH_TX);
    if let Some(tx) = guard.as_ref() {
        let _ = tx.send(RefreshEvent::HangSuspend(on));
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
    let same = active == idle;   /* 活跃==空闲: 不再保存 refresh_timeout */

    let mut lines: Vec<String> = content.lines().map(str::to_string).collect();
    for line in lines.iter_mut() {
        let trimmed = line.trim();
        let Some((k, _v)) = trimmed.split_once('=') else { continue };
        match k.trim() {
            "refresh_timeout" => {
                found_timeout = true;
                if !same {
                    *line = format!("refresh_timeout={}", timeout);
                }
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
    if same {
        // 活跃==空闲: 移除旧 refresh_timeout 行, 且不补写
        lines.retain(|l| !l.trim().starts_with("refresh_timeout="));
        found_timeout = true;
    }
    // 缺失字段插入: 头部注释/空行之后, 紧跟已有 refresh_* 字段 (不插到配置顶部覆盖文件头)
    let missing: Vec<String> = [
        (!found_timeout).then(|| format!("refresh_timeout={}", timeout)),
        (!found_active).then(|| format!("refresh_active={}", active)),
        (!found_idle).then(|| format!("refresh_idle={}", idle)),
    ]
    .into_iter()
    .flatten()
    .collect();
    if !missing.is_empty() {
        let mut at = 0;
        let mut last_rf: Option<usize> = None;
        while at < lines.len() {
            let t = lines[at].trim();
            if t.is_empty() || t.starts_with('#') {
                at += 1;
                continue;
            }
            if t.starts_with("refresh_")
                && t.split_once('=')
                    .map(|(k, _)| {
                        matches!(
                            k.trim(),
                            "refresh_timeout" | "refresh_active" | "refresh_idle"
                        )
                    })
                    .unwrap_or(false)
            {
                last_rf = Some(at);
                at += 1;
                continue;
            }
            break;   /* 头部区 (注释/空行/刷新率字段) 结束 */
        }
        let ins = last_rf.map(|i| i + 1).unwrap_or(at);
        for (i, l) in missing.into_iter().enumerate() {
            lines.insert(ins + i, l);
        }
    }

    // 原子写: 先写临时文件再 rename, 避免中途崩溃留下半写配置
    let tmp = format!("{}.tmp", path);
    if fs::write(&tmp, lines.join("\n") + "\n").is_err() {
        return;
    }
    if fs::rename(&tmp, &path).is_err() {
        let _ = fs::remove_file(&tmp);
        return;
    }
    // 同步共享配置（仅刷新率，不触发 CPU 重载）+ 独立通知 refresh 线程
    crate::config::reload_refresh_only();
    REFRESH_FORCE_RELOAD.store(true, Ordering::Release);
    wake();
}

pub fn refresh_get_apps() -> Vec<(String, i32, String, String, Vec<(String, i32)>)> {
    // 刷新率应用配置只从共享 CURRENT_CONFIG 返回，不再单独读取配置文件。
    let Some(cfg) = crate::rw_read_ignore_poison(&crate::config::CURRENT_CONFIG).clone() else {
        return Vec::new();
    };
    cfg.app_refresh_configs
        .iter()
        .map(|(pkg, (t, a, i))| {
            // activity 块: 内部模式码 → 显示值 (60/90/120)
            let acts: Vec<(String, i32)> = cfg
                .app_refresh_activity
                .get(pkg)
                .map(|m| {
                    m.iter()
                        .map(|(c, v)| {
                            (
                                c.clone(),
                                crate::config::refresh_mode_str(*v).parse().unwrap_or(*v),
                            )
                        })
                        .collect()
                })
                .unwrap_or_default();
            (
                pkg.clone(),
                *t,
                crate::config::refresh_mode_str(*a).to_string(),
                crate::config::refresh_mode_str(*i).to_string(),
                acts,
            )
        })
        .collect()
}

/// 写该包的刷新率配置 (单行或 activity 块):
/// 先移除旧 refresh 单行/块 (块感知), 再在包末尾插入新内容。
/// acts 为空 → 单行 `pkg=refresh-<a>-<i>` / `refresh-<t>-<a>-<i>`;
/// acts 非空 → 块 `pkg=refresh-...{ comp=rate ... }`。
pub fn refresh_write_config(
    pkg: &str,
    timeout: i32,
    active: &str,
    idle: &str,
    acts: &[(String, i32)],
) -> bool {
    let path = config_path();
    let content = fs::read_to_string(&path).unwrap_or_default();
    // 1) 移除该包旧 refresh 内容 (单行 / 块入口+块内行+结束 }
    let mut out: Vec<String> = Vec::new();
    let mut in_block = false;
    for line in content.lines().map(String::from) {
        let t = line.trim();
        if in_block {
            if crate::config::close_like(t) {
                in_block = false;
            }
            continue;
        }
        if let Some((k, v)) = t.split_once('=') {
            if k.trim() == pkg && v.trim().starts_with("refresh-") {
                if v.trim().ends_with('{') {
                    in_block = true; // 块入口 → 连块内行一起跳过
                }
                continue; // 单行 → 跳过
            }
        }
        out.push(line);
    }
    // 2) 构造新内容
    let mut new_lines: Vec<String> = Vec::new();
    if acts.is_empty() {
        let l = if active == idle {
            format!("{}=refresh-{}-{}", pkg, active, idle)
        } else {
            format!("{}=refresh-{}-{}-{}", pkg, timeout, active, idle)
        };
        new_lines.push(l);
    } else {
        let head = if active == idle {
            format!("{}=refresh-{}-{}{{", pkg, active, idle)
        } else {
            format!("{}=refresh-{}-{}-{}{{", pkg, timeout, active, idle)
        };
        new_lines.push(head);
        for (comp, rate) in acts {
            new_lines.push(format!("    {comp}={rate}"));
        }
        new_lines.push("}".to_string());
    }
    // 3) 插入到该包已有规则之后
    let at = crate::config::last_pkg_end_index(&out, pkg).unwrap_or(out.len());
    for (i, l) in new_lines.into_iter().enumerate() {
        out.insert(at + i, l);
    }
    crate::config::save_config_lines(&path, &out)
}

pub fn refresh_add_app(pkg: &str, timeout: i32, active: &str, idle: &str) {
    // 统一走 refresh_write_config (无 activity 块 → 单行; 旧块会一并清除)
    if !refresh_write_config(pkg, timeout, active, idle, &[]) {
        return;
    }
    /* 完整 reload: 重建前台 uid 表 (rfr 标志)。若只 reload_refresh_only(),
     * "最后一步是刷新率操作"时 rfr 标志不更新 → 刷新率不生效
     * (先线程后刷新率 / 同时添加场景)。 */
    crate::config::config_reload_now();
    REFRESH_FORCE_RELOAD.store(true, Ordering::Release);
    wake();
}

/// 保存 activity 块配置 (包级默认 + 活动映射); 供 webui 添加/编辑活动规则调用。
/// 与 refresh_add_app 同款 reload/wake 语义。
pub fn refresh_set_activity(
    pkg: &str,
    timeout: i32,
    active: &str,
    idle: &str,
    acts: &[(String, i32)],
) -> bool {
    if !refresh_write_config(pkg, timeout, active, idle, acts) {
        return false;
    }
    crate::config::config_reload_now();
    REFRESH_FORCE_RELOAD.store(true, Ordering::Release);
    wake();
    true
}

pub fn refresh_del_app(pkg: &str) -> bool {
    let path = config_path();
    let content = match fs::read_to_string(&path) {
        Ok(s) => s,
        Err(_) => return false,
    };
    // 块感知删除: 移除该包 refresh 单行 / 块 (入口行 + 块内行 + 结束 }), 保留其他
    let mut out: Vec<String> = Vec::new();
    let mut in_block = false;
    for line in content.lines().map(String::from) {
        let t = line.trim();
        if in_block {
            if crate::config::close_like(t) {
                in_block = false;
            }
            continue;
        }
        if t.is_empty() || t.starts_with('#') {
            out.push(line);
            continue;
        }
        if let Some((k, v)) = t.split_once('=') {
            if k.trim() == pkg && v.trim().starts_with("refresh-") {
                if v.trim().ends_with('{') {
                    in_block = true;
                }
                continue;
            }
        }
        out.push(line);
    }
    if !crate::config::save_config_lines(&path, &out) {
        return false;
    }
    /* 完整 reload: 重建前台 uid 表 (rfr 标志), 与 refresh_add_app 一致 */
    crate::config::config_reload_now();
    REFRESH_FORCE_RELOAD.store(true, Ordering::Release);
    wake();
    true
}

pub fn refresh_get_status() -> Option<RefreshStatus> {
    // 请求刷新线程更新一次状态快照 (下一次轮询读到最新); 返回当前快照
    STATUS_REQ.store(true, Ordering::Release);
    wake();
    crate::lock_ignore_poison(&REFRESH_STATUS).clone()
}

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

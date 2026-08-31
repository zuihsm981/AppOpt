use std::collections::{HashMap, HashSet};
use std::ffi::CString;
use std::fs;
use std::io;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::UNIX_EPOCH;

use crate::{lock_ignore_poison, MAX_PKG_LEN, MAX_THREAD_LEN};
use crate::cpuset::{base_cpuset, create_cpuset_dir, parse_cpu_spec, CpuSet, CpuTopology};

pub static INOTIFY_SUPPORTED: AtomicBool = AtomicBool::new(false);
pub static INOTIFY_FD: AtomicI32 = AtomicI32::new(-1);
pub static INOTIFY_WD: AtomicI32 = AtomicI32::new(-1);

/// 运行时可调参数，web 端热更新
pub static CHECK_INTERVAL: AtomicU64 = AtomicU64::new(2);

/// 配置重载通知 fd (eventfd): web 端修改 cpuset/路径后写入, 唤醒主循环 epoll 处理
pub static CONFIG_WAKE_FD: AtomicI32 = AtomicI32::new(-1);

/// 请求配置热加载 (事件驱动, 不轮询文件): 写 eventfd 通知主循环
pub fn request_config_reload() {
    let fd = CONFIG_WAKE_FD.load(Ordering::Relaxed);
    if fd >= 0 {
        let val: u64 = 1;
        unsafe { libc::write(fd, &val as *const u64 as *const _, 8); }
    } else {
        // fd 尚未初始化 (启动早期): 直接重载
        config_reload_now();
    }
}
pub static CONFIG_FILE: Mutex<String> = Mutex::new(String::new());

#[derive(Clone)]
pub struct AffinityRule {
    pub pkg: String,
    pub thread: String,
    pub thread_pattern: CString,
    pub cpuset_dir: String,
    pub cpus: CpuSet,
}

#[derive(Clone)]
pub struct AppConfig {
    pub rules: Vec<AffinityRule>,
    /// CPU 亲和性规则覆盖的应用包名
    pub pkgs: HashSet<String>,
    /// 需要识别的目标包 = CPU 规则包 ∪ 刷新率配置包。
    /// 只配置了刷新率（无 CPU 规则）的应用也必须被进程识别并登记 PID_PKG，
    /// 否则刷新率前台回调查不到包名、刷新率永不生效。
    pub target_pkgs: HashSet<String>,
    pub has_thread_rules: HashSet<String>,
    pub topo: CpuTopology,
    /// 刷新率全局配置（统一加载，供 refresh 模块从共享 CURRENT_CONFIG 读取）
    pub refresh_timeout: i32,
    pub refresh_active: i32,
    pub refresh_idle: i32,
    /// 按应用刷新率配置: pkg -> (timeout, active_mode, idle_mode)
    pub app_refresh_configs: HashMap<String, (i32, i32, i32)>,
}

pub static CURRENT_CONFIG: Mutex<Option<Arc<AppConfig>>> = Mutex::new(None);

pub static PARSE_FAILS: AtomicUsize = AtomicUsize::new(0);

/// 默认参与刷新率前台识别的系统桌面。它不需要 CPU 亲和性规则，
/// 刷新率未配置专属项时直接使用全局 active/idle 配置。
pub const DEFAULT_REFRESH_PACKAGE: &str = "com.android.launcher3";
/// com.android.launcher3 在当前系统中的实际进程 comm。
pub const DEFAULT_REFRESH_COMM: &str = "droid.launcher3";

/// 校验 CPU 规格形态
pub fn spec_like(s: &str) -> bool {
    let mut any = false;
    for part in s.split(',') {
        let t = part.trim();
        if t.is_empty() {
            continue;
        }
        any = true;
        let ok = matches!(t, "e-core" | "p-core" | "hp-core" | "all-core")
            || t.bytes().all(|b| b.is_ascii_digit())
            || t.split_once('-').is_some_and(|(a, b)| {
                !a.is_empty()
                    && !b.is_empty()
                    && a.bytes().all(|b| b.is_ascii_digit())
                    && b.bytes().all(|b| b.is_ascii_digit())
            });
        if !ok {
            return false;
        }
    }
    any
}

pub fn comment_at(s: &str) -> Option<usize> {
    let mut prev_ws = false;
    for (i, c) in s.char_indices() {
        if prev_ws && (c == '#' || (c == '/' && s[i..].starts_with("//"))) {
            return Some(s[..i].trim_end().len());
        }
        prev_ws = c.is_whitespace();
    }
    None
}

pub fn strip_comment(s: &str) -> &str {
    &s[..comment_at(s).unwrap_or(s.len())]
}

pub fn split_rule_line(p: &str) -> Option<(&str, &str, bool)> {
    let p = strip_comment(p);
    fn kv(s: &str) -> Option<(&str, &str)> {
        s.rfind('=')
            .map(|eq| (s[..eq].trim(), s[eq + 1..].trim()))
            .filter(|(k, _)| !k.is_empty())
    }
    p.match_indices('}')
        .find_map(|(cb, _)| kv(&p[..cb]).map(|(k, v)| (k, v, true)))
        .or_else(|| kv(p).map(|(k, v)| (k, v, false)))
}

pub fn close_like(p: &str) -> bool {
    p.strip_prefix('}').is_some_and(|r| {
        r.is_empty() || r.starts_with(char::is_whitespace) || r.starts_with('#') || r.starts_with("//")
    })
}

pub fn split_single_line(body: &str) -> Option<(&str, &str, &str)> {
    let eq = body.rfind('=')?;
    let cpus = body[eq + 1..].trim();
    let left = body[..eq].trim_end().strip_suffix('}')?.trim_end();
    let ob = left.find('{')?;
    let (pkg, thread) = (left[..ob].trim(), left[ob + 1..].trim());
    (!pkg.is_empty() && !thread.is_empty()).then_some((pkg, thread, cpus))
}

pub enum OuterLine<'a> {
    Rule { pkg: &'a str, cpus: &'a str, open: bool },
    BareOpen { pkg: &'a str },
    Pending { pkg: &'a str },
    Single { pkg: &'a str, thread: &'a str, cpus: &'a str, open: bool },
    Junk,
}

pub fn parse_outer(p: &str) -> OuterLine<'_> {
    let p = strip_comment(p);
    let (open, body) = match p.strip_suffix('{') {
        Some(b) => (true, b.trim_end()),
        None => (false, p),
    };
    if let Some((pkg, thread, cpus)) = split_single_line(body) {
        return OuterLine::Single { pkg, thread, cpus, open };
    }
    if !open && close_like(body) {
        return OuterLine::Junk;
    }
    match body.rfind('=') {
        Some(eq) => {
            let (pkg, cpus) = (body[..eq].trim(), body[eq + 1..].trim());
            if cpus.is_empty() {
                return if open {
                    OuterLine::BareOpen { pkg }
                } else {
                    OuterLine::Pending { pkg }
                };
            }
            OuterLine::Rule { pkg, cpus, open }
        }
        None => {
            if open {
                OuterLine::BareOpen { pkg: body }
            } else {
                OuterLine::Pending { pkg: body }
            }
        }
    }
}

fn add_rule(
    rules: &mut Vec<AffinityRule>,
    topo: &CpuTopology,
    pkg: &str,
    thread: &str,
    cpus_spec: &str,
) -> bool {
    if pkg.is_empty() || pkg.len() >= MAX_PKG_LEN || thread.len() >= MAX_THREAD_LEN {
        return false;
    }
    if pkg.bytes().chain(thread.bytes()).any(|b| b < 0x20 || b == 0x7f) {
        return false;
    }
    if !spec_like(cpus_spec) {
        return false;
    }
    let set = parse_cpu_spec(cpus_spec, topo);
    if set.count() == 0 {
        return false;
    }
    let cpuset_dir = if thread.is_empty() {
        let dir_name = set.to_range_string();
        if topo.cpuset_enabled {
            let path = format!("{}/{}", base_cpuset(), dir_name);
            if create_cpuset_dir(&path, &dir_name, &topo.mems_str) { dir_name } else { Default::default() }
        } else {
            String::new()
        }
    } else {
        String::new()
    };
    rules.push(AffinityRule {
        pkg: pkg.to_string(),
        thread: thread.to_string(),
        thread_pattern: CString::new(thread).unwrap_or_default(),
        cpuset_dir,
        cpus: set,
    });
    true
}

/// 解析统一配置文件中的刷新率记录。
///
/// 刷新率记录使用 `refresh_` 前缀，避免与 CPU 规则的 `pkg=cpus` 语法冲突。
///   refresh_timeout=30
///   refresh_active=120
///   refresh_idle=60
///   refresh_app,com.example.game,30,120,60
///
/// 返回 true 表示该行是刷新率记录，调用方不应再把它当作 CPU 规则解析。
pub fn is_refresh_config_line(line: &str) -> bool {
    let line = strip_comment(line).trim();
    if let Some((key, _)) = line.split_once('=') {
        if matches!(key.trim(), "refresh_timeout" | "refresh_active" | "refresh_idle") {
            return true;
        }
    }
    let parts: Vec<&str> = line.split(',').map(str::trim).collect();
    parts.len() == 5 && parts[0] == "refresh_app"
}

fn parse_refresh_config_line(
    line: &str,
    timeout: &mut i32,
    active: &mut i32,
    idle: &mut i32,
    apps: &mut HashMap<String, (i32, i32, i32)>,
) -> bool {
    let line = strip_comment(line).trim();
    if let Some((key, value)) = line.split_once('=') {
        match key.trim() {
            "refresh_timeout" => {
                if let Ok(value) = value.trim().parse::<i32>() {
                    if value > 0 {
                        *timeout = value;
                    }
                }
                return true;
            }
            "refresh_active" => {
                *active = parse_refresh_mode(value);
                return true;
            }
            "refresh_idle" => {
                *idle = parse_refresh_mode(value);
                return true;
            }
            _ => {}
        }
    }

    let parts: Vec<&str> = line.split(',').map(str::trim).collect();
    let (pkg, timeout, active, idle) = if parts.len() == 5 && parts[0] == "refresh_app" {
        (parts[1], parts[2], parts[3], parts[4])
    } else {
        return false;
    };
    if pkg.is_empty() {
        return true;
    }
    let app_timeout = timeout.parse::<i32>().unwrap_or(30).max(1);
    apps.insert(
        pkg.to_string(),
        (app_timeout, parse_refresh_mode(active), parse_refresh_mode(idle)),
    );
    true
}

/// 只读取统一主配置文件中的刷新率字段。
/// 刷新率保存后的轻量同步使用此函数，不重新解析 CPU 规则。
pub fn load_refresh_config(config_file: &str) -> (i32, i32, i32, HashMap<String, (i32, i32, i32)>) {
    let mut timeout = 30;
    let mut active = 0;
    let mut idle = 1;
    let mut apps = HashMap::new();
    if let Ok(content) = fs::read_to_string(config_file) {
        for line in content.lines() {
            let _ = parse_refresh_config_line(
                line,
                &mut timeout,
                &mut active,
                &mut idle,
                &mut apps,
            );
        }
    }
    (timeout, active, idle, apps)
}

/// 加载统一主配置文件，返回 None 表示未变化或解析失败。
/// CPU 亲和性规则和刷新率记录均从此文件解析，并一起发布到 CURRENT_CONFIG。
pub fn load_config(
    config_file: &str,
    topo: &CpuTopology,
    last_mtime: &mut i64,
) -> Option<AppConfig> {
    let metadata = fs::metadata(config_file).ok()?;
    let mtime = metadata
        .modified()
        .ok()?
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_nanos() as i64;

    if *last_mtime == mtime && *last_mtime != -1 {
        return None;
    }

    let content = fs::read_to_string(config_file).ok()?;

    let mut rules: Vec<AffinityRule> = Vec::new();
    let mut fail_cnt: usize = 0;
    // 刷新率与 CPU 规则共用同一个配置文件；这些字段最终写入 AppConfig，
    // 由 refresh 线程从 CURRENT_CONFIG 读取。
    let (mut refresh_timeout, mut refresh_active, mut refresh_idle, mut app_refresh_configs) =
        (30, 0, 1, HashMap::new());
    let mut cur_pkg = String::new();
    let mut pending_pkg = String::new();
    let mut in_block = false;

    for line in content.lines() {
        let p = line.trim();
        if p.is_empty() || p.starts_with('#') || p.starts_with("//") {
            continue;
        }

        // 刷新率配置与 CPU 规则共用主配置文件。识别后跳过 CPU 规则解析，
        // 同时把值写入 AppConfig，避免出现“字段存在但永远是默认值”的问题。
        if parse_refresh_config_line(
            p,
            &mut refresh_timeout,
            &mut refresh_active,
            &mut refresh_idle,
            &mut app_refresh_configs,
        ) {
            continue;
        }

        if in_block {
            if close_like(p) {
                in_block = false;
                cur_pkg.clear();
                continue;
            }
            match split_rule_line(p) {
                Some((thread, cpus, closed)) => {
                    if !add_rule(&mut rules, topo, &cur_pkg, thread, cpus) {
                        fail_cnt += 1;
                    }
                    if closed {
                        in_block = false;
                        cur_pkg.clear();
                    }
                }
                None => {
                    fail_cnt += 1;
                    if p.contains('}') {
                        in_block = false;
                        cur_pkg.clear();
                    }
                }
            }
            continue;
        }

        match parse_outer(p) {
            OuterLine::Single { pkg, thread, cpus, open } => {
                if !pending_pkg.is_empty() {
                    fail_cnt += 1;
                }
                pending_pkg.clear();
                if !add_rule(&mut rules, topo, pkg, thread, cpus) {
                    fail_cnt += 1;
                }
                if open {
                    cur_pkg = pkg.to_string();
                    in_block = true;
                }
            }
            OuterLine::Rule { pkg, cpus, open } => {
                if !pending_pkg.is_empty() {
                    fail_cnt += 1;
                }
                if !add_rule(&mut rules, topo, pkg, "", cpus) {
                    fail_cnt += 1;
                }
                if open {
                    cur_pkg = pkg.to_string();
                    in_block = true;
                }
                pending_pkg.clear();
            }
            OuterLine::BareOpen { pkg } => {
                let owner = if !pkg.is_empty() {
                    if !pending_pkg.is_empty() {
                        fail_cnt += 1;
                    }
                    pkg.to_string()
                } else {
                    pending_pkg.clone()
                };
                if owner.is_empty() {
                    fail_cnt += 1;
                    continue;
                }
                cur_pkg = owner;
                pending_pkg.clear();
                in_block = true;
            }
            OuterLine::Pending { pkg } => {
                if !pending_pkg.is_empty() {
                    fail_cnt += 1;
                }
                pending_pkg = pkg.to_string();
            }
            OuterLine::Junk => {
                fail_cnt += 1;
                pending_pkg.clear();
            }
        }
    }

    if in_block || !pending_pkg.is_empty() {
        fail_cnt += 1;
    }

    *last_mtime = mtime;
    PARSE_FAILS.store(fail_cnt, Ordering::Relaxed);

    let pkgs: HashSet<String> = rules.iter().map(|r| r.pkg.clone()).collect();
    let has_thread_rules: HashSet<String> = rules
        .iter()
        .filter(|r| !r.thread.is_empty())
        .map(|r| r.pkg.clone())
        .collect();

    // 需要识别的目标包 = CPU 规则包 ∪ 刷新率配置包。
    // 只配置了刷新率（无 CPU 规则）的应用也必须被识别并登记 PID_PKG，
    // 否则刷新率前台回调查不到包名、刷新率永不生效。
    let mut target_pkgs = pkgs.clone();
    for pkg in app_refresh_configs.keys() {
        target_pkgs.insert(pkg.clone());
    }

    Some(AppConfig {
        rules,
        pkgs,
        target_pkgs,
        has_thread_rules,
        topo: topo.clone(),
        refresh_timeout,
        refresh_active,
        refresh_idle,
        app_refresh_configs,
    })
}

/// 刷新率配置由 `load_config(CONFIG_FILE, ...)` 统一解析；不再由 refresh 模块
/// 读取独立文件，避免共享配置与磁盘配置分裂。

/// 解析刷新率模式字符串 → 内部模式码 (0=120, 1=60, 2=90)
pub fn parse_refresh_mode(s: &str) -> i32 {
    match s.trim() {
        "120" => 0,
        "90" => 2,
        _ => 1, // 60 或默认
    }
}

/// 内部模式码 → 显示字符串
pub fn refresh_mode_str(mode: i32) -> &'static str {
    match mode {
        0 => "120",
        2 => "90",
        _ => "60",
    }
}

/// 主循环直接处理 inotify 事件 (阻塞版): 返回 true 表示配置已变更需应用。
/// 由主循环在 inotify fd 可读时调用; 无 inotify 时返回 false。
pub fn inotify_drain() -> bool {
    if !INOTIFY_SUPPORTED.load(Ordering::Acquire) {
        return false;
    }
    let inotify_fd = INOTIFY_FD.load(Ordering::Acquire);

    #[repr(align(8))]
    struct InotifyBuf([u8; 4096]);
    let mut buf = InotifyBuf([0u8; 4096]);
    let mut reload_needed = false;
    let mut needs_rewatch = false;
    let hdr = std::mem::size_of::<libc::inotify_event>();

    loop {
        let len = unsafe {
            libc::read(
                inotify_fd,
                buf.0.as_mut_ptr() as *mut libc::c_void,
                buf.0.len(),
            )
        };
        if len <= 0 {
            let err = io::Error::last_os_error();
            let errno = err.raw_os_error();
            if errno == Some(libc::EAGAIN)
                || errno == Some(libc::EWOULDBLOCK)
                || errno == Some(libc::EINTR)
            {
                break;
            }
            disable_inotify(inotify_fd);
            return false;
        }

        let mut offset = 0;
        while offset + hdr <= len as usize {
            let event = unsafe { &*(buf.0.as_ptr().add(offset) as *const libc::inotify_event) };
            if event.mask & (libc::IN_CLOSE_WRITE | libc::IN_DELETE_SELF | libc::IN_MOVE_SELF) != 0
            {
                reload_needed = true;
                if event.mask & (libc::IN_DELETE_SELF | libc::IN_MOVE_SELF) != 0 {
                    needs_rewatch = true;
                }
            }
            offset += hdr + event.len as usize;
        }
    }

    if needs_rewatch {
        if !inotify_rewatch(inotify_fd) {
            return false;
        }
    }

    if reload_needed {
        // 统一解析后只在 CPU 规则实际变化时通知主循环；刷新率字段的
        // CURRENT_CONFIG 更新不会触发 CPU 全量扫描，通知仍然分离。
        let mut mtime: i64 = -1;
        return config_reload(&mut mtime);
    }
    false
}

pub fn init_inotify(config_file: &str) {
    let inotify_fd = unsafe { libc::inotify_init1(libc::IN_CLOEXEC | libc::IN_NONBLOCK) };
    if inotify_fd < 0 {
        return;
    }
    let cfg_cstr = match CString::new(config_file) {
        Ok(c) => c,
        Err(_) => {
            unsafe { libc::close(inotify_fd); }
            return;
        }
    };
    let wd = unsafe {
        libc::inotify_add_watch(
            inotify_fd,
            cfg_cstr.as_ptr(),
            libc::IN_CLOSE_WRITE | libc::IN_DELETE_SELF | libc::IN_MOVE_SELF,
        )
    };
    if wd >= 0 {
        INOTIFY_SUPPORTED.store(true, Ordering::Release);
        INOTIFY_FD.store(inotify_fd, Ordering::Release);
        INOTIFY_WD.store(wd, Ordering::Release);
    } else {
        unsafe {
            libc::close(inotify_fd);
        }
    }
}

fn disable_inotify(inotify_fd: i32) {
    INOTIFY_SUPPORTED.store(false, Ordering::Release);
    unsafe {
        libc::close(inotify_fd);
    }
    INOTIFY_FD.store(-1, Ordering::Release);
    INOTIFY_WD.store(-1, Ordering::Release);
}

fn cpu_config_changed(old: &AppConfig, new: &AppConfig) -> bool {
    if old.rules.len() != new.rules.len()
        || old.pkgs != new.pkgs
        || old.has_thread_rules != new.has_thread_rules
    {
        return true;
    }
    old.rules.iter().zip(&new.rules).any(|(a, b)| {
        a.pkg != b.pkg
            || a.thread != b.thread
            || a.cpuset_dir != b.cpuset_dir
            || a.cpus != b.cpus
    })
}

fn config_reload(last_mtime: &mut i64) -> bool {
    let Some(old_cfg) = lock_ignore_poison(&CURRENT_CONFIG).clone() else {
        return false;
    };
    let file = lock_ignore_poison(&CONFIG_FILE).clone();
    let Some(new_cfg) = load_config(&file, &old_cfg.topo, last_mtime) else {
        return false;
    };
    let cpu_changed = cpu_config_changed(&old_cfg, &new_cfg);
    let mut guard = lock_ignore_poison(&CURRENT_CONFIG);
    *guard = Some(Arc::new(new_cfg));
    cpu_changed
}

pub fn config_reload_now() {
    let mut mtime: i64 = -1;
    let _ = config_reload(&mut mtime);
    // 通知主循环应用新配置 (事件驱动; fd 未初始化时跳过, 启动早期由主循环自行加载)
    let fd = CONFIG_WAKE_FD.load(Ordering::Relaxed);
    if fd >= 0 {
        let val: u64 = 1;
        unsafe { libc::write(fd, &val as *const u64 as *const _, 8); }
    }
}

/// 仅从统一主配置文件重载刷新率字段到共享 CURRENT_CONFIG。
/// 不写 CONFIG_WAKE_FD，保持“保存配置的通知分离”：CPU 规则保存走主循环，
/// 刷新率保存只更新共享刷新率字段并由 refresh 线程自行唤醒。
pub fn reload_refresh_only() {
    let file = {
        let guard = lock_ignore_poison(&CURRENT_CONFIG);
        if guard.is_none() { return; }
        lock_ignore_poison(&CONFIG_FILE).clone()
    };
    let (refresh_timeout, refresh_active, refresh_idle, app_refresh_configs) =
        load_refresh_config(&file);
    let mut guard = lock_ignore_poison(&CURRENT_CONFIG);
    if let Some(cfg) = guard.as_ref() {
        let mut new_cfg = (**cfg).clone();
        new_cfg.refresh_timeout = refresh_timeout;
        new_cfg.refresh_active = refresh_active;
        new_cfg.refresh_idle = refresh_idle;
        new_cfg.app_refresh_configs = app_refresh_configs;
        // 刷新率配置变化后重建 target_pkgs（CPU 规则包 ∪ 刷新率配置包）
        let mut target_pkgs = new_cfg.pkgs.clone();
        for pkg in new_cfg.app_refresh_configs.keys() {
            target_pkgs.insert(pkg.clone());
        }
        new_cfg.target_pkgs = target_pkgs;
        *guard = Some(Arc::new(new_cfg));
    }
}

/// 将旧默认主配置 applist.conf 迁移为统一的 appopt.conf。
/// 仅在目标不存在时执行，避免覆盖用户显式指定的配置文件。
pub fn migrate_legacy_main_config(config_file: &str) {
    let target = std::path::Path::new(config_file);
    if target.exists() || target.file_name().and_then(|n| n.to_str()) != Some("appopt.conf") {
        return;
    }
    let Some(parent) = target.parent() else { return };
    let legacy = parent.join("applist.conf");
    if !legacy.exists() { return; }
    // rename 保证后续只有一个权威配置文件；失败时复制，避免启动因迁移失败而丢配置。
    if fs::rename(&legacy, target).is_err() {
        if let Ok(content) = fs::read(&legacy) {
            let _ = fs::write(target, content);
        }
    }
}

/// 旧版本曾把刷新率写到可执行文件目录下的 refresh_config.conf。
/// 启动时只做一次兼容迁移，之后所有读写均使用 CONFIG_FILE。
pub fn migrate_legacy_refresh_config(config_file: &str) {
    let mut legacy = std::env::current_exe()
        .or_else(|_| std::env::current_dir())
        .unwrap_or_else(|_| std::path::PathBuf::from("."));
    legacy.pop();
    legacy.push("refresh_config.conf");
    if legacy == std::path::Path::new(config_file) || !legacy.exists() {
        return;
    }
    let Ok(content) = fs::read_to_string(&legacy) else { return };
    let mut additions = Vec::new();
    for line in content.lines() {
        let line = strip_comment(line).trim();
        if line.is_empty() { continue; }
        if let Some((key, value)) = line.split_once('=') {
            let key = match key.trim() {
                "timeout" | "refresh_timeout" => "refresh_timeout",
                "active" | "refresh_active" => "refresh_active",
                "idle" | "refresh_idle" => "refresh_idle",
                _ => continue,
            };
            additions.push(format!("{}={}", key, value.trim()));
        } else {
            let parts: Vec<&str> = line.split(',').map(str::trim).collect();
            if parts.len() == 5 && parts[0] == "refresh_app" {
                additions.push(parts.join(","));
            } else if parts.len() == 4 && !parts[0].is_empty() {
                additions.push(format!("refresh_app,{}", parts.join(",")));
            }
        }
    }
    if additions.is_empty() { return; }
    let mut main = fs::read_to_string(config_file).unwrap_or_default();
    if !main.ends_with('\n') { main.push('\n'); }
    main.push_str("\n# Migrated refresh-rate settings\n");
    main.push_str(&additions.join("\n"));
    main.push('\n');
    let tmp = format!("{}.tmp", config_file);
    if fs::File::create(&tmp)
        .and_then(|mut f| { use std::io::Write; f.write_all(main.as_bytes())?; f.sync_all() })
        .and_then(|_| fs::rename(&tmp, config_file))
        .is_ok()
    {
        let _ = fs::remove_file(legacy);
    }
}

fn inotify_rewatch(inotify_fd: i32) -> bool {
    let inotify_wd = INOTIFY_WD.load(Ordering::Acquire);
    unsafe {
        libc::inotify_rm_watch(inotify_fd, inotify_wd as u32);
    }
    let cfg_cstr = match CString::new(lock_ignore_poison(&CONFIG_FILE).clone()) {
        Ok(c) => c,
        Err(_) => {
            disable_inotify(inotify_fd);
            return false;
        }
    };
    let new_wd = unsafe {
        libc::inotify_add_watch(
            inotify_fd,
            cfg_cstr.as_ptr(),
            libc::IN_CLOSE_WRITE | libc::IN_DELETE_SELF | libc::IN_MOVE_SELF,
        )
    };

    if new_wd < 0 {
        disable_inotify(inotify_fd);
        return false;
    }
    INOTIFY_WD.store(new_wd, Ordering::Release);
    true
}
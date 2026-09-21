use std::collections::{HashMap, HashSet};
use std::ffi::CString;
use std::fs;
use std::io;
use std::sync::atomic::{AtomicBool, AtomicI8, AtomicI32, AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock, Mutex, RwLock};
use std::time::UNIX_EPOCH;

use crate::{lock_ignore_poison, rw_read_ignore_poison, rw_write_ignore_poison, MAX_PKG_LEN, MAX_THREAD_LEN};
use crate::cpuset::{base_cpuset, create_cpuset_dir, parse_cpu_spec, CpuSet, CpuTopology};

pub static INOTIFY_SUPPORTED: AtomicBool = AtomicBool::new(false);
pub static INOTIFY_FD: AtomicI32 = AtomicI32::new(-1);
pub static INOTIFY_WD: AtomicI32 = AtomicI32::new(-1);

/// 配置重载通知 fd (eventfd): web 端修改 cpuset/路径后写入, 唤醒主循环 epoll 处理
pub static CONFIG_WAKE_FD: AtomicI32 = AtomicI32::new(-1);

/// 当前配置快照 (Arc); 各模块共用 (cpu_affinity/web 统一走此, 消除重复实现)
pub fn current_cfg() -> Option<std::sync::Arc<AppConfig>> {
    rw_read_ignore_poison(&CURRENT_CONFIG).clone()
}

/// 写 eventfd 通知主循环应用配置 (fd 未初始化时跳过)
fn config_wake() {
    let fd = CONFIG_WAKE_FD.load(Ordering::Relaxed);
    if fd >= 0 {
        let val: u64 = 1;
        unsafe { libc::write(fd, &val as *const u64 as *const _, 8); }
    }
}

/// 请求配置热加载 (事件驱动, 不轮询文件): 写 eventfd 通知主循环
pub fn request_config_reload() {
    if CONFIG_WAKE_FD.load(Ordering::Relaxed) >= 0 {
        config_wake();
    } else {
        // fd 尚未初始化 (启动早期): 直接重载
        config_reload_now();
    }
}

/* ================= waylay (service list 拦截伪装) 配置 =================
 * 独立配置文件 waylay.conf (与 applist.conf 同目录):
 *   srv_from=lineage    拦截目标字符 (7 字符)
 *   srv_to=opluseu      替换字符 (7 字符, 等长)
 *   包名一行一个        目标应用 (前台时激活拦截)
 */
pub const WAYLAY_FILE: &str = "waylay.conf";
/// 拦截目标字符 (7 字符)
pub static WAYLAY_FROM: LazyLock<RwLock<String>> =
    LazyLock::new(|| RwLock::new("lineage".to_string()));
/// 替换字符 (7 字符)
pub static WAYLAY_TO: LazyLock<RwLock<String>> =
    LazyLock::new(|| RwLock::new("opluseu".to_string()));
/// 目标应用列表 (waylay.conf)
pub static WAYLAY_APPS: LazyLock<RwLock<Vec<String>>> = LazyLock::new(|| RwLock::new(Vec::new()));
/// 目标应用 uid 集合 (查 packages.list; 前台回调据此激活拦截)
pub static WAYLAY_UIDS: LazyLock<RwLock<HashSet<i32>>> = LazyLock::new(|| RwLock::new(HashSet::new()));
/// waylay 配置已变更 (web 保存后置位; 主循环 EV_CONFIG 分支消费并同步内核)
pub static WAYLAY_CHANGED: AtomicBool = AtomicBool::new(false);
/// KPM 武装请求 (拦截页连接/断开): 1=武装(start), -1=解除(stop), 0=无
pub static KPM_ARM_REQ: AtomicI8 = AtomicI8::new(0);

pub fn set_kpm_arm_req(arm: bool) {
    KPM_ARM_REQ.store(if arm { 1 } else { -1 }, Ordering::Release);
    request_config_reload();
}

pub fn take_kpm_arm_req() -> i8 {
    KPM_ARM_REQ.swap(0, Ordering::AcqRel)
}

/// 解析 waylay.conf (不存在时用默认 lineage→opluseu + 空应用表)
pub fn load_waylay() -> (String, String, Vec<String>) {
    let mut from = "lineage".to_string();
    let mut to = "opluseu".to_string();
    let mut apps: Vec<String> = Vec::new();
    if let Ok(content) = std::fs::read_to_string(WAYLAY_FILE) {
        for line in content.lines() {
            let t = line.trim();
            if t.is_empty() || t.starts_with('#') || t.starts_with("//") {
                continue;
            }
            if let Some(v) = t.strip_prefix("srv_from=") {
                from = v.trim().to_string();
            } else if let Some(v) = t.strip_prefix("srv_to=") {
                to = v.trim().to_string();
            } else if !t.starts_with("srv_") {
                apps.push(t.to_string());
            }
        }
    }
    (from, to, apps)
}

/// 目标应用 → uid 集合 (查 packages.list; 未安装跳过)
pub fn build_waylay_uids(apps: &[String]) -> HashSet<i32> {
    let mut uids = HashSet::new();
    if let Ok(content) = std::fs::read_to_string("/data/system/packages.list") {
        for line in content.lines() {
            let mut it = line.split_whitespace();
            let (Some(pkg), Some(uid_s)) = (it.next(), it.next()) else { continue };
            let Ok(uid) = uid_s.parse::<i32>() else { continue };
            if uid >= 100000 {
                continue;
            }
            if apps.iter().any(|a| a == pkg) {
                uids.insert(uid);
            }
        }
    }
    uids
}

/// 保存 waylay.conf (tmp+rename 原子写), 更新静态并置变更标志
pub fn save_waylay(from: &str, to: &str, apps: &[String]) -> io::Result<()> {
    let mut out = String::from("# waylay: service list 拦截伪装配置\n");
    out.push_str("# srv_from=拦截目标字符(7)  srv_to=替换字符(7, 等长)\n");
    out.push_str(&format!("srv_from={}\n", from.trim()));
    out.push_str(&format!("srv_to={}\n", to.trim()));
    out.push_str("# 目标应用 (前台时激活拦截), 包名一行一个\n");
    for a in apps {
        out.push_str(&format!("{}\n", a.trim()));
    }
    let tmp = format!("{}.tmp", WAYLAY_FILE);
    fs::write(&tmp, out.as_bytes())?;
    fs::rename(&tmp, WAYLAY_FILE)?;
    *rw_write_ignore_poison(&WAYLAY_FROM) = from.trim().to_string();
    *rw_write_ignore_poison(&WAYLAY_TO) = to.trim().to_string();
    *rw_write_ignore_poison(&WAYLAY_APPS) = apps.to_vec();
    *rw_write_ignore_poison(&WAYLAY_UIDS) = build_waylay_uids(apps);
    WAYLAY_CHANGED.store(true, Ordering::Release);
    Ok(())
}

/// 取出并复位 waylay 变更标志
pub fn take_waylay_changed() -> bool {
    WAYLAY_CHANGED.swap(false, Ordering::AcqRel)
}

/// 启动/重载时把 waylay.conf 加载进静态 (默认 lineage→opluseu + 空应用表兜底)
pub fn waylay_load_static() {
    let (f, t, a) = load_waylay();
    *rw_write_ignore_poison(&WAYLAY_FROM) = f;
    *rw_write_ignore_poison(&WAYLAY_TO) = t;
    *rw_write_ignore_poison(&WAYLAY_APPS) = a.clone();
    *rw_write_ignore_poison(&WAYLAY_UIDS) = build_waylay_uids(&a);
}
pub static CONFIG_FILE: Mutex<String> = Mutex::new(String::new());

#[derive(Clone)]
pub struct AffinityRule {
    pub pkg: String,
    pub thread: String,
    pub thread_pattern: CString,
    pub cpuset_dir: String,
    pub cpus: CpuSet,
    /// uclamp 下限 (0..=1024, -1 = 未设)
    pub util_min: i32,
    /// uclamp 上限 (0..=1024, -1 = 未设)
    pub util_max: i32,
}

#[derive(Clone)]
pub struct AppConfig {
    pub rules: Vec<AffinityRule>,
    /// CPU 亲和性规则覆盖的应用包名
    pub pkgs: HashSet<String>,
    pub has_thread_rules: HashSet<String>,
    pub topo: CpuTopology,
    /// 刷新率全局配置（统一加载，供 refresh 模块从共享 CURRENT_CONFIG 读取）
    pub refresh_timeout: i32,
    pub refresh_active: i32,
    pub refresh_idle: i32,
    /// 按应用刷新率配置: pkg -> (timeout, active_mode, idle_mode)
    pub app_refresh_configs: HashMap<String, (i32, i32, i32)>,
}

/// 共享配置: 读多写少 (各线程频繁读, 仅配置重载时写) -> RwLock
pub static CURRENT_CONFIG: RwLock<Option<Arc<AppConfig>>> = RwLock::new(None);

/// 最近一次 config_reload 是否检测到 CPU 规则变化 (供主循环 apply_config 消费;
/// 默认 true 保证首个配置事件不会漏扫)
static CPU_RULES_CHANGED: AtomicBool = AtomicBool::new(true);

/// 取出并复位“最近一次重载是否 CPU 规则变化”
pub fn take_cpu_rules_changed() -> bool {
    CPU_RULES_CHANGED.swap(false, Ordering::Relaxed)
}

pub static PARSE_FAILS: AtomicUsize = AtomicUsize::new(0);

/// 默认参与刷新率前台识别的系统桌面。它不需要 CPU 亲和性规则，
/// 刷新率未配置专属项时直接使用全局 active/idle 配置。
pub const DEFAULT_REFRESH_PACKAGE: &str = "com.android.launcher3";

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
        s.find('=')
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
    // 单行内联规则格式: pkg { thread=cpus } —— '}' 在 cpus 尾部 (等号右侧),
    // 从右侧剥离; 等号前 (left) 无 '}'。
    let eq = body.find('=')?;
    let mut cpus = body[eq + 1..].trim();
    if let Some(stripped) = cpus.strip_suffix('}') {
        cpus = stripped.trim();
    }
    let left = body[..eq].trim_end();
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
    match body.find('=') {
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

/// 从规则 CPU 规格中提取 uclamp token (util_min=/util_max=), 返回 (纯 CPU 规格, min, max)
/// 规则行格式: `0-3 util_min=256 util_max=1024` (util token 空格分隔, 可只给其一)
pub(crate) fn split_uclamp(spec: &str) -> (&str, i32, i32) {
    let mut util_min = -1;
    let mut util_max = -1;
    let mut cpus = ""; // 仅 uclamp 时保持空 (无 CPU 集合)
    for t in spec.split_whitespace() {
        if let Some(v) = t.strip_prefix("util_min=") {
            util_min = v.parse::<i32>().unwrap_or(-1);
        } else if let Some(v) = t.strip_prefix("util_max=") {
            util_max = v.parse::<i32>().unwrap_or(-1);
        } else if cpus.is_empty() {
            cpus = t; // 第一个非 util token 为 CPU 集合规格
        }
    }
    (cpus, util_min, util_max)
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
    // 先提 uclamp token; CPU 集合可空 (只有 uclamp 时不设亲和)
    let (cpus_spec, util_min, util_max) = split_uclamp(cpus_spec);
    let has_util = util_min >= 0 || util_max >= 0;
    if cpus_spec.is_empty() && !has_util {
        return false; // 无 CPU 也无 uclamp: 无意义
    }
    let mut set = CpuSet::new();
    let mut cpuset_dir = String::new();
    if !cpus_spec.is_empty() {
        if !spec_like(cpus_spec) {
            return false;
        }
        set = parse_cpu_spec(cpus_spec, topo);
        if set.count() == 0 {
            return false;
        }
        cpuset_dir = if thread.is_empty() {
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
    }
    rules.push(AffinityRule {
        pkg: pkg.to_string(),
        thread: thread.to_string(),
        thread_pattern: CString::new(thread).unwrap_or_default(),
        cpuset_dir,
        cpus: set,
        util_min,
        util_max,
    });
    true
}

/// 解析统一配置文件中的刷新率记录。
///
/// 刷新率记录使用 `refresh_` 前缀，避免与 CPU 规则的 `pkg=cpus` 语法冲突。
///   refresh_timeout=30
///   refresh_active=120
///   refresh_idle=60
///   com.example.game=refresh-30-120-60
///
/// 返回 true 表示该行是刷新率记录，调用方不应再把它当作 CPU 规则解析。
pub fn is_refresh_config_line(line: &str) -> bool {
    let line = strip_comment(line).trim();
    if let Some((key, value)) = line.split_once('=') {
        if matches!(key.trim(), "refresh_timeout" | "refresh_active" | "refresh_idle") {
            return true;
        }
        // 应用级刷新率行: pkg=refresh-<t>-<a>-<i> (与 route_pkg_val_line 一致)
        if value.trim().starts_with("refresh-") {
            return true;
        }
    }
    false
}

/// 解析全局刷新率三字段 (refresh_timeout/active/idle)。
/// 应用级刷新率 (pkg=refresh-<t>-<a>-<i>) 由 route_pkg_val_line 路由
/// (load_config 主循环与 load_refresh_config 均如此; 旧 refresh_app,逗号 格式已废弃)。
fn parse_refresh_config_line(
    line: &str,
    timeout: &mut i32,
    active: &mut i32,
    idle: &mut i32,
    _apps: &mut HashMap<String, (i32, i32, i32)>,
) -> bool {
    let line = strip_comment(line).trim();
    let Some((key, value)) = line.split_once('=') else { return false };
    match key.trim() {
        "refresh_timeout" => {
            if let Ok(value) = value.trim().parse::<i32>() {
                if value > 0 {
                    *timeout = value;
                }
            }
            true
        }
        "refresh_active" => {
            *active = parse_refresh_mode(value);
            true
        }
        "refresh_idle" => {
            *idle = parse_refresh_mode(value);
            true
        }
        _ => false,
    }
}

/// pkg=refresh-<timeout>-<active>-<idle> 前缀路由
fn route_pkg_val_line(
    pkg: &str,
    val: &str,
    apps: &mut HashMap<String, (i32, i32, i32)>,
) -> bool {
    if !pkg.is_empty() && val.starts_with("refresh-") {
        let parts: Vec<&str> = val.split('-').collect();
        if parts.len() == 4 && !parts[1].is_empty() {  // ["refresh", t, a, i]
            let t = parts[1].parse::<i32>().unwrap_or(30).max(1);
            let a = parse_refresh_mode(parts[2]);
            let i = parse_refresh_mode(parts[3]);
            apps.insert(pkg.to_string(), (t, a, i));
        }
        return true;
    }
    false
}

/// 包属性行所属包名: pkg=… / pkg,thread,cpus / 裸块 pkg {
fn pkg_of_line(t: &str) -> Option<String> {
    let t = crate::config::strip_comment(t).trim();
    if let Some((k, _)) = t.split_once('=') {
        let k = k.trim().trim_end_matches('{').trim();
        if !k.is_empty() && !k.contains(',') {
            return Some(k.to_string());
        }
    }
    let fields: Vec<&str> = t.split(',').map(str::trim).collect();
    if fields.len() >= 3 && !fields[0].is_empty() {
        return Some(fields[0].to_string());
    }
    if t.ends_with('{') {
        let k = t.trim_end_matches('{').trim();
        if !k.is_empty() {
            return Some(k.to_string());
        }
    }
    None
}

/// 包属性行中“配置属性”(刷新率/移入cpuset), 排在同包规则行之后
fn is_special_attr(line: &str) -> bool {
    let t = line.trim();
    t.contains("=refresh-")
}

/// 空行/注释行 (load_config 主循环 / organize / pkg_set 共用)
fn is_skip_line(t: &str) -> bool {
    let t = t.trim();
    t.is_empty() || t.starts_with('#') || t.starts_with("//")
}

/// 配置行分类 (organize_config_file / pkg_set_of_config 共用)
enum LineKind {
    /// 空行/注释
    Skip,
    /// 全局设置行 (refresh_*=), 置顶保留
    Global,
    /// 包属性行 (规则/刷新率行), 含包名
    Pkg(String),
    /// 块规则首行 (含 '{' 且非单行规则), 含包名
    Block(String),
    /// 无法归属的杂项行
    Other,
}

fn classify_line(t: &str) -> LineKind {
    let raw = strip_comment(t).trim();
    if raw.is_empty() {
        return LineKind::Skip;
    }
    if raw.contains('=') && !raw.contains(',') && !raw.contains('{') {
        if let Some((k, _)) = raw.split_once('=') {
            if k.trim().starts_with("refresh_") {
                return LineKind::Global;
            }
        }
    }
    if let Some(pkg) = pkg_of_line(raw) {
        if raw.contains('{') && !raw.contains(',') {
            return LineKind::Block(pkg);
        }
        return LineKind::Pkg(pkg);
    }
    LineKind::Other
}

/// 当前共享配置中的“规则应用集合” (CPU 规则包 ∪ 刷新率配置包)
fn current_config_pkg_set() -> HashSet<String> {
    let mut s = HashSet::new();
    if let Some(cfg) = rw_read_ignore_poison(&CURRENT_CONFIG).as_ref() {
        s.extend(cfg.rules.iter().map(|r| r.pkg.clone()));
        s.extend(cfg.app_refresh_configs.keys().cloned());
    }
    s
}

/// 从配置文件内容解析“规则应用集合”(跳过注释/空行/全局设置行)
fn pkg_set_of_config(content: &str) -> HashSet<String> {
    let mut s = HashSet::new();
    for raw in content.lines() {
        if let LineKind::Pkg(pkg) | LineKind::Block(pkg) = classify_line(raw.trim()) {
            s.insert(pkg);
        }
    }
    s
}

/// 原子写配置文件 (tmp+rename) + 保存后自动整理; 供 rule_edit/refresh 写接口共用
pub(crate) fn save_config_lines(path: &str, lines: &[String]) -> bool {
    let mut out = lines.join("\n");
    out.push('\n');
    let tmp = format!("{}.tmp", path);
    let ok = fs::File::create(&tmp)
        .and_then(|mut f| {
            use std::io::Write;
            f.write_all(out.as_bytes())?;
            f.sync_all()
        })
        .and_then(|_| fs::rename(&tmp, path));
    if ok.is_err() {
        return false;
    }
    organize_config_file(path);
    true
}

/// 保存配置后自动整理: 注释/空行/全局设置(refresh_*)保持原序置顶;
/// 各包属性行(规则/刷新率/移入cpuset)按包名分组, 包内规则在前、属性在后,
/// 块规则(含 '{')作为整体随包移动。
pub(crate) fn organize_config_file(path: &str) {
    use std::collections::BTreeMap;
    let Ok(content) = fs::read_to_string(path) else { return };
    // 仅“规则应用集合”相对 CURRENT_CONFIG 变化 (新增/移除应用) 时重排;
    // 只调整数值/核集不重排
    if pkg_set_of_config(&content) == current_config_pkg_set() {
        return;
    }
    let lines: Vec<String> = content.lines().map(String::from).collect();
    let mut head: Vec<String> = Vec::new();
    let mut pkgs: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut i = 0;
    while i < lines.len() {
        let raw = lines[i].clone();
        let t = raw.trim();
        match classify_line(t) {
            LineKind::Skip | LineKind::Global | LineKind::Other => {
                head.push(raw);
                i += 1;
            }
            LineKind::Block(pkg) => {
                let mut unit = vec![raw];
                i += 1;
                while i < lines.len() {
                    unit.push(lines[i].clone());
                    if lines[i].contains('}') {
                        i += 1;
                        break;
                    }
                    i += 1;
                }
                pkgs.entry(pkg).or_default().push(unit.join("\n"));
            }
            LineKind::Pkg(pkg) => {
                pkgs.entry(pkg).or_default().push(raw);
                i += 1;
            }
        }
    }
    let mut out = head;
    for (_, mut ls) in pkgs {
        let (rules, attrs): (Vec<String>, Vec<String>) =
            ls.drain(..).partition(|l| !is_special_attr(l));
        out.extend(rules);
        out.extend(attrs);
    }
    let _ = fs::write(path, out.join("\n") + "\n");
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
            if !parse_refresh_config_line(
                line,
                &mut timeout,
                &mut active,
                &mut idle,
                &mut apps,
            ) {
                // 新格式 pkg=refresh-<t>-<a>-<i>: parse_refresh_config_line 不识别,
                // 走 route_pkg_val_line 路由 (与 load_config 主循环一致)
                let line = strip_comment(line).trim();
                if let Some((k, v)) = line.split_once('=') {
                    let _ = route_pkg_val_line(k.trim(), v.trim(), &mut apps);
                }
            }
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
        if is_skip_line(p) {
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
                // 前缀路由: pkg=refresh-<t>-<a>-<i> 不是 CPU 规则
                if !route_pkg_val_line(pkg, cpus, &mut app_refresh_configs) {
                    if !add_rule(&mut rules, topo, pkg, "", cpus) {
                        fail_cnt += 1;
                    }
                    if open {
                        cur_pkg = pkg.to_string();
                        in_block = true;
                    }
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

    Some(AppConfig {
        rules,
        pkgs,
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

/// 监听 /data/system/packages.list (应用安装/卸载/替换 → 重建 uid 表)。
/// 在初始化并发线程中执行; 返回 inotify fd (失败 -1), 线程完成后自行退出。
pub(crate) fn init_pkg_inotify() -> i32 {
    let pkglist_path = match std::ffi::CString::new("/data/system/packages.list") {
        Ok(p) => p,
        Err(_) => return -1,
    };
    unsafe {
        let ifd = libc::inotify_init1(libc::IN_CLOEXEC | libc::IN_NONBLOCK);
        if ifd < 0 {
            return -1; // inotify 不可用 (如 SELinux 拦截)
        }
        let wd = libc::inotify_add_watch(
            ifd,
            pkglist_path.as_ptr(),
            libc::IN_CLOSE_WRITE | libc::IN_MOVED_TO | libc::IN_MOVE_SELF | libc::IN_DELETE_SELF,
        );
        if wd < 0 {
            libc::close(ifd);
            return -1;
        }
        ifd
    }
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
            || a.util_min != b.util_min
            || a.util_max != b.util_max
    })
}

fn config_reload(last_mtime: &mut i64) -> bool {
    let Some(old_cfg) = rw_read_ignore_poison(&CURRENT_CONFIG).clone() else {
        return false;
    };
    let file = lock_ignore_poison(&CONFIG_FILE).clone();
    let Some(new_cfg) = load_config(&file, &old_cfg.topo, last_mtime) else {
        // 解析失败: 保留旧配置, 规则未变 → 清变更标记 (防残留 true 触发误重放)
        CPU_RULES_CHANGED.store(false, Ordering::Relaxed);
        return false;
    };
    let cpu_changed = cpu_config_changed(&old_cfg, &new_cfg);
    CPU_RULES_CHANGED.store(cpu_changed, Ordering::Relaxed);
    let mut guard = rw_write_ignore_poison(&CURRENT_CONFIG);
    *guard = Some(Arc::new(new_cfg));
    cpu_changed
}

pub fn config_reload_now() {
    let mut mtime: i64 = -1;
    let _ = config_reload(&mut mtime);
    // 通知主循环应用新配置 (事件驱动; fd 未初始化时跳过, 启动早期由主循环自行加载)
    config_wake();
}

/// 仅从统一主配置文件重载刷新率字段到共享 CURRENT_CONFIG。
/// 不写 CONFIG_WAKE_FD，保持“保存配置的通知分离”：CPU 规则保存走主循环，
/// 刷新率保存只更新共享刷新率字段并由 refresh 线程自行唤醒。
pub fn reload_refresh_only() {
    let file = {
        let guard = rw_read_ignore_poison(&CURRENT_CONFIG);
        if guard.is_none() { return; }
        lock_ignore_poison(&CONFIG_FILE).clone()
    };
    let (refresh_timeout, refresh_active, refresh_idle, app_refresh_configs) =
        load_refresh_config(&file);
    let mut guard = rw_write_ignore_poison(&CURRENT_CONFIG);
    if let Some(cfg) = guard.as_ref() {
        let mut new_cfg = (**cfg).clone();
        new_cfg.refresh_timeout = refresh_timeout;
        new_cfg.refresh_active = refresh_active;
        new_cfg.refresh_idle = refresh_idle;
        new_cfg.app_refresh_configs = app_refresh_configs;
        *guard = Some(Arc::new(new_cfg));
    }
}

/// 计算该 pkg 在文件中"最后一段"的结束位置 (插入点): 同一应用的多条规则
/// (CPU 行 + refresh 行, 或块) 连续排列时, 新行应插在其后, 保持整齐。
/// 返回 Some(idx) = 应插入的下标; None = 文件中尚无该应用任何行。
pub(crate) fn last_pkg_end_index(lines: &[String], pkg: &str) -> Option<usize> {
    let eq = format!("{}=", pkg);
    let sp = format!("{} ", pkg);
    let br = format!("[{}]", pkg);
    let mut last: Option<usize> = None;
    let mut i = 0;
    while i < lines.len() {
        let t = lines[i].trim();
        if t.is_empty() || t.starts_with('#') || t.starts_with("//") {
            i += 1;
            continue;
        }
        let is_pkg = t.starts_with(&eq) || t == pkg || t.starts_with(&sp) || t == br;
        if !is_pkg {
            i += 1;
            continue;
        }
        if t.contains('{') {
            if t.contains('}') {
                last = Some(i);                        // 同行内联闭合
                i += 1;
            } else {
                // 块: 找匹配的 '}' (首个含 '}' 的行)
                let mut j = i + 1;
                while j < lines.len() {
                    if lines[j].trim().contains('}') {
                        break;
                    }
                    j += 1;
                }
                let end = j.min(lines.len().saturating_sub(1));
                last = Some(end);
                i = j + 1;
            }
        } else {
            last = Some(i);
            i += 1;
        }
    }
    last.map(|x| x + 1)
}

fn inotify_rewatch(inotify_fd: i32) -> bool {
    let inotify_wd = INOTIFY_WD.load(Ordering::Acquire);
    // Android libc 的 inotify_rm_watch 第二参为 u32; linux 为 i32 —— 按 target 适配
    #[cfg(target_os = "android")]
    unsafe { libc::inotify_rm_watch(inotify_fd, inotify_wd as u32); }
    #[cfg(not(target_os = "android"))]
    unsafe { libc::inotify_rm_watch(inotify_fd, inotify_wd); }
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


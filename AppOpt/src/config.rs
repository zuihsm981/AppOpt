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

/* ================= waylay (service list / prop 伪装) 配置 =================
 * 独立配置文件 waylay.conf (与 applist.conf 同目录):
 *   srv_set <f> <t>      service list 拦截字符/替换字符 (多组, 等长)
 *   包名一行一个         目标应用 (前台时激活拦截)
 *   [prop] 段:
 *     prop_set <f> <t>     属性名替换对: 原属性名 → 新属性名 (完整名, 等长
 *                          ASCII ≤92, 每 pair 一行)
 */
pub const WAYLAY_FILE: &str = "waylay.conf";

/* ================= waylay.conf 新格式 (目标应用独立) =================
 * 每行: <包名>=<kind>-<from>-<to>
 *   kind = src       系统服务伪装 (from 服务名 → to 服务名, 等长)
 *        | prop      系统属性伪装 (from 完整属性名 → to 属性名, 等长)
 *        | red       重定向/内容替换 (from → to, 等长)
 *        | red-path  重定向/文件重定向 (from 原路径 → to 新路径, 不限长度)
 * 前台回调节省: 仅该包名应用在前台时激活其规则; 切走恢复 (vfc off 摘 hook)。
 */
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum WaylayKind {
    Src,
    Prop,
    Red,
    RedPath,
}
impl WaylayKind {
    pub fn tag(&self) -> &'static str {
        match self {
            WaylayKind::Src => "src",
            WaylayKind::Prop => "prop",
            WaylayKind::Red => "red",
            WaylayKind::RedPath => "red-path",
        }
    }
    pub fn parse(t: &str) -> Option<WaylayKind> {
        match t {
            "src" => Some(WaylayKind::Src),
            "prop" => Some(WaylayKind::Prop),
            "red" => Some(WaylayKind::Red),
            "red-path" => Some(WaylayKind::RedPath),
            _ => None,
        }
    }
}

#[derive(Clone)]
pub struct WaylayRule {
    pub pkg: String,
    pub kind: WaylayKind,
    pub target: String,   /* 内容替换(Red)的目标文件; 其他 kind 空 */
    pub from: String,
    pub to: String,
}

pub static WAYLAY_RULES_NEW: LazyLock<RwLock<Vec<WaylayRule>>> =
    LazyLock::new(|| RwLock::new(Vec::new()));
/// uid → 包名 (waylay 规则应用缓存; 与 cpu 表共用 packages.list 构建时机, on_fg 查缓存不读文件)
pub static WAYLAY_PKG_BY_UID: LazyLock<RwLock<std::collections::HashMap<i32, String>>> =
    LazyLock::new(|| RwLock::new(std::collections::HashMap::new()));

/// 重建 uid→包名 缓存 (读 packages.list + WAYLAY_RULES_NEW 规则包过滤; 触发: 配置保存/加载/EV_PKG)
pub fn rebuild_pkg_by_uid() {
    let rules = rw_read_ignore_poison(&WAYLAY_RULES_NEW);
    let mut pkgs: std::collections::HashSet<String> = std::collections::HashSet::new();
    for r in rules.iter() {
        if r.pkg != "*" {
            pkgs.insert(r.pkg.clone());
        }
    }
    let mut m: std::collections::HashMap<i32, String> = std::collections::HashMap::new();
    if let Ok(content) = std::fs::read_to_string("/data/system/packages.list") {
        for line in content.lines() {
            let mut it = line.split_whitespace();
            let (Some(pkg), Some(uid_s)) = (it.next(), it.next()) else { continue };
            let Ok(uid) = uid_s.parse::<i32>() else { continue };
            if uid >= 100000 && pkgs.contains(pkg) {
                m.insert(uid, pkg.to_string());
            }
        }
    }
    *rw_write_ignore_poison(&WAYLAY_PKG_BY_UID) = m;
}
/// 解析 waylay.conf 新格式: <pkg>=<kind>-<from>-<to> (旧 srv_set/包名行/[prop]/[redirect] 废弃)
pub fn load_waylay_rules() -> Vec<WaylayRule> {
    let mut out: Vec<WaylayRule> = Vec::new();
    if let Ok(content) = std::fs::read_to_string(WAYLAY_FILE) {
        for line in content.lines() {
            let t = line.trim();
            if t.is_empty() || t.starts_with('#') || t.starts_with("//") {
                continue;
            }
            let Some((pkg, rest)) = t.split_once('=') else { continue };
            let pkg = pkg.trim();
            if pkg.is_empty() {
                continue;
            }
            let rest = rest.trim();   /* 容忍 '= ' 后空格 */
            let (kind_t, rr) = if let Some(r) = rest.strip_prefix("red-path-") {
                ("red-path", r)
            } else {
                rest.split_once('-').unwrap_or((rest, ""))
            };
            let Some(mut kind) = WaylayKind::parse(kind_t) else { continue };
            let mut target = String::new();
            let from: String;
            let to: String;
            if kind == WaylayKind::RedPath {
                /* red-path 仅文件重定向: red-path-<from路径>-<to路径> (split_once 取首个 '-') */
                let (f, t) = rr.split_once('-').unwrap_or(("", ""));
                let f = f.trim();
                let t = t.trim();
                if f.starts_with('/') && t.starts_with('/') {
                    from = f.to_string();
                    to = t.to_string();
                } else if f.starts_with('/') && !t.starts_with('/') && t.len() > 2 {
                    /* 兼容旧错误格式: red-path-<target>-<from>-<to> (内容带目标, 救回) */
                    if let Some((from1, to1)) = t.split_once('-') {
                        kind = WaylayKind::Red;
                        target = f.to_string();
                        from = from1.to_string();
                        to = to1.to_string();
                    } else {
                        continue;
                    }
                } else {
                    continue;   /* 非路径 → 整条丢弃 */
                }
            } else if kind == WaylayKind::Red {
                /* red 内容替换: red-<目标文件路径>-<from>-<to> (目标必为 '/' 路径, 防无差别替换) */
                let parts: Vec<&str> = rr.split('-').collect();
                let t0 = parts.first().unwrap_or(&"");
                if !t0.starts_with('/') || t0.len() > 127 {
                    continue;   /* 目标非法 → 整条丢弃 */
                }
                target = t0.to_string();
                from = parts.get(1).map(|x| x.to_string()).unwrap_or_default();
                to = parts[2..].join("-");
            } else {
                let (f, t) = rr.split_once('-').unwrap_or(("", ""));
                from = f.trim().to_string();
                to = t.trim().to_string();
            }
            if !from.is_empty() && !to.is_empty() {
                out.push(WaylayRule {
                    pkg: pkg.to_string(),
                    kind,
                    target,
                    from,
                    to,
                });
            }
        }
    }
    /* 同步静态: 启动/重载时 waylay.conf 直接生效 (web 保存同路径) */
    let old_has_vfc = rw_read_ignore_poison(&WAYLAY_RULES_NEW)
        .iter()
        .any(|r| r.kind == WaylayKind::Red || r.kind == WaylayKind::RedPath);
    *rw_write_ignore_poison(&WAYLAY_RULES_NEW) = out.clone();
    WAYLAY_VFC_CHANGED.store(old_has_vfc || out.iter().any(|r| r.kind == WaylayKind::Red || r.kind == WaylayKind::RedPath), Ordering::Release);
    WAYLAY_CHANGED.store(true, Ordering::Release);
    out
}

/// 保存 waylay.conf 新格式 (tmp+rename 原子写), 更新静态并置变更标志
static WAYLAY_SAVE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

pub fn save_waylay_rules(rules: &[WaylayRule]) -> io::Result<()> {
    let _g = WAYLAY_SAVE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut out = String::from("# waylay 新格式: <包名>=<kind>-<from>-<to>\n");
    out.push_str("# kind: src=服务伪装 prop=属性伪装 red=重定向(内容替换); from/to 等长且不含 '-'\n");
    for r in rules {
        let prefix = match r.kind {
            WaylayKind::Red => "red",
            WaylayKind::RedPath => "red-path",
            _ => r.kind.tag(),
        };
        if r.kind == WaylayKind::Red {
            /* 内容替换带目标文件: <目标>-<from>-<to> */
            out.push_str(&format!(
                "{}={}-{}-{}-{}\n",
                r.pkg.trim(),
                prefix,
                r.target.trim(),
                r.from.trim(),
                r.to.trim()
            ));
        } else {
            out.push_str(&format!(
                "{}={}-{}-{}\n",
                r.pkg.trim(),
                prefix,
                r.from.trim(),
                r.to.trim()
            ));
        }
    }
    let old_has_vfc = rw_read_ignore_poison(&WAYLAY_RULES_NEW)
        .iter()
        .any(|r| r.kind == WaylayKind::Red || r.kind == WaylayKind::RedPath);
    let new_has_vfc = rules
        .iter()
        .any(|r| r.kind == WaylayKind::Red || r.kind == WaylayKind::RedPath);
    let tmp = format!("{}.tmp", WAYLAY_FILE);
    fs::write(&tmp, out.as_bytes())?;
    fs::rename(&tmp, WAYLAY_FILE)?;
    *rw_write_ignore_poison(&WAYLAY_RULES_NEW) = rules.to_vec();
    WAYLAY_VFC_CHANGED.store(old_has_vfc || new_has_vfc, Ordering::Release);
    WAYLAY_CHANGED.store(true, Ordering::Release);
    Ok(())
}

/// property 区伪装规则列表 (新格式 prop 规则; on_fg 按包 set_prop_rules 维护)
pub static WAYLAY_PROP_RULES: LazyLock<RwLock<Vec<(String, String)>>> =
    LazyLock::new(|| RwLock::new(Vec::new()));
/// prop 规则 → selinux context 缓存 (原属性名 → context): 初始化/保存时由
/// property_contexts 解析一次, prop_apply 直接使用 (不再每次读上下文文件)
pub static WAYLAY_PROP_CTX: LazyLock<RwLock<Vec<(String, String)>>> =
    LazyLock::new(|| RwLock::new(Vec::new()));
/// waylay 配置已变更 (web 保存后置位; 主循环 EV_CONFIG 分支消费并同步内核)
pub static WAYLAY_CHANGED: AtomicBool = AtomicBool::new(false);
/// vfc (red/red-path) 规则集是否变化: 仅内容替换/文件重定向配置保存或加载时置位,
/// 驱动 sync_vfc_rules (src/prop 保存不触发 vfc 下发)
pub static WAYLAY_VFC_CHANGED: AtomicBool = AtomicBool::new(false);
/// KPM 武装请求 (拦截页连接/断开): 1=武装(start), -1=解除(stop), 0=无
pub static KPM_ARM_REQ: AtomicI8 = AtomicI8::new(0);

pub fn set_kpm_arm_req(arm: bool) {
    KPM_ARM_REQ.store(if arm { 1 } else { -1 }, Ordering::Release);
    request_config_reload();
}

pub fn take_kpm_arm_req() -> i8 {
    KPM_ARM_REQ.swap(0, Ordering::AcqRel)
}


/// 目标应用 → uid 集合 (查 packages.list; 未安装跳过)

/// 取出并复位 waylay 变更标志
pub fn take_waylay_changed() -> bool {
    WAYLAY_CHANGED.swap(false, Ordering::AcqRel)
}

pub fn take_vfc_changed() -> bool {
    WAYLAY_VFC_CHANGED.swap(false, Ordering::AcqRel)
}

/* ===== waylay 规则 (新格式 <pkg>=<kind>-<from>-<to>) =====
 * 加载/保存统一走 load_waylay_rules / save_waylay_rules (WAYLAY_RULES_NEW);
 * 内容替换 red-<目标>-<from>-<to>, 文件重定向 red-path-<from路径>-<to路径>,
 * 服务伪装 src-, 属性伪装 prop-; 规则带 pkg (全局为 "*")。 */
/// 属性名 → selinux context: 读各 property_contexts 取最长匹配前缀的 context
fn prop_context_for(name: &str) -> Option<String> {
    const FILES: &[&str] = &[
        "/system/etc/selinux/plat_property_contexts",
        "/vendor/etc/selinux/vendor_property_contexts",
        "/odm/etc/selinux/odm_property_contexts",
        "/system_ext/etc/selinux/system_ext_property_contexts",
        "/product/etc/selinux/product_property_contexts",
    ];
    let mut best: Option<(usize, String)> = None;
    for f in FILES {
        if let Ok(c) = std::fs::read_to_string(f) {
            for line in c.lines() {
                let t = line.trim();
                if t.is_empty() || t.starts_with('#') {
                    continue;
                }
                let mut it = t.split_whitespace();
                let (Some(pre), Some(ctx)) = (it.next(), it.next()) else { continue };
                if name.starts_with(pre) {
                    let l = pre.len();
                    if best.as_ref().map(|(bl, _)| l > *bl).unwrap_or(true) {
                        best = Some((l, ctx.to_string()));
                    }
                }
            }
        }
    }
    best.map(|(_, c)| c)
}

/// red-path 规则 to 文件: 同步 from 的权限 (DAC mode) 与 SELinux 上下文。
/// 目的: 重定向后读取者按"读 from 的预期"访问 to —— to 的权限/上下文应与
/// from 对齐 (同目录场景 base.apk 副本继承 apk 上下文, 读取者即可读)。
pub fn sync_redpath_perm(rules: &[WaylayRule]) {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    for r in rules.iter().filter(|r| r.kind == WaylayKind::RedPath) {
        if !std::path::Path::new(&r.to).exists() {
            continue;
        }
        if let Ok(md) = std::fs::metadata(&r.from) {
            let _ = std::fs::set_permissions(&r.to, std::fs::Permissions::from_mode(md.mode() & 0o7777));
        }
        let cf = std::ffi::CString::new(r.from.as_str()).unwrap_or_default();
        let ct = std::ffi::CString::new(r.to.as_str()).unwrap_or_default();
        let cn = std::ffi::CString::new("security.selinux").unwrap_or_default();
        let mut buf = [0u8; 256];
        let n = unsafe {
            libc::getxattr(
                cf.as_ptr(),
                cn.as_ptr(),
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
            )
        };
        if n > 0 {
            unsafe {
                libc::lsetxattr(
                    ct.as_ptr(),
                    cn.as_ptr(),
                    buf.as_ptr() as *const libc::c_void,
                    n as usize,
                    0,
                );
            }
        }
    }
}

/// 按包临时设置 prop 替换规则 (前台驱动): 更新 WAYLAY_PROP_RULES + 重建 ctx 缓存
pub fn set_prop_rules(rules: &[(String, String)]) {
    *rw_write_ignore_poison(&WAYLAY_PROP_RULES) = rules.to_vec();
    rebuild_prop_ctx_cache();
}

/// 解析并缓存 prop 规则 → context 映射 (WAYLAY_PROP_CTX): 初始化/保存配置后
/// 调用一次, prop_apply 直接消费缓存
pub fn rebuild_prop_ctx_cache() {
    let rules = rw_read_ignore_poison(&WAYLAY_PROP_RULES).clone();
    let mut out: Vec<(String, String)> = Vec::new();
    for (from, _) in &rules {
        if let Some(ctx) = prop_context_for(from) {
            out.push((from.clone(), ctx));
        }
    }
    *rw_write_ignore_poison(&WAYLAY_PROP_CTX) = out;
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

/// 规则 CPU 规格解析 (新格式): 返回 (CPU 规格, util_min, util_max)
/// `cpus[-min-max]` —— util 段成对 (单侧缺省由输出端补默认 min=0/max=1024);
/// 剩余段数 >=3 才尝试剥 util, 防纯数字区间 cpus (如 `0-3`/`0-3,6-7`) 误剥。
pub(crate) fn parse_rule_spec(spec: &str) -> (String, i32, i32) {
    let parts: Vec<&str> = spec.split('-').collect();
    if parts.len() < 3 {
        return (spec.to_string(), -1, -1);
    }
    let mut i = parts.len();
    let mut got = 0;
    let mut util_max = -1;
    if let Ok(v) = parts[i - 1].parse::<i32>() && (0..=1024).contains(&v) {
        util_max = v;
        i -= 1;
        got += 1;
    }
    let mut util_min = -1;
    if let Ok(v) = parts[i - 1].parse::<i32>() && (0..=1024).contains(&v) {
        util_min = v;
        i -= 1;
        got += 1;
    }
    if got < 2 {
        // 不成对 (如 0-3,6-7 只剩 1 个数字可剥) → 整串当 CPU 规格
        return (spec.to_string(), -1, -1);
    }
    (parts[..i].join("-"), util_min, util_max)
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
    // 解析 CPU 规格 + uclamp (连字符 `cpus-min-max`)
    let (cpus_spec, util_min, util_max) = crate::config::parse_rule_spec(cpus_spec);
    let has_util = util_min >= 0 || util_max >= 0;
    if cpus_spec.is_empty() && !has_util {
        return false; // 无 CPU 也无 uclamp: 无意义
    }
    let mut set = CpuSet::new();
    let mut cpuset_dir = String::new();
    if !cpus_spec.is_empty() {
        if !spec_like(&cpus_spec) {
            return false;
        }
        set = parse_cpu_spec(&cpus_spec, topo);
        if set.count() == 0 {
            return false;
        }
        cpuset_dir = if thread.is_empty() {
            let dir_name = set.to_range_string();
            if topo.cpuset_enabled {
                let path = format!("{}/{}", base_cpuset(), dir_name);
                if create_cpuset_dir(&path, &dir_name, &topo.mems_str) { dir_name } else { String::new() }
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
                line, &mut timeout, &mut active, &mut idle,
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
            p, &mut refresh_timeout, &mut refresh_active, &mut refresh_idle,
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
/// 刷新率模式码 (与 parse_refresh_mode / refresh_mode_str 一致): 120=0, 90=2, 60=1
pub const REFRESH_MODE_120: i32 = 0;
pub const REFRESH_MODE_90: i32 = 2;
pub const REFRESH_MODE_60: i32 = 1;

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

    let mut buf = [0u64; 512];   /* 8 字节天然对齐, 4096B */
    let mut reload_needed = false;
    let mut needs_rewatch = false;
    let hdr = std::mem::size_of::<libc::inotify_event>();

    loop {
        let len = unsafe {
            libc::read(
                inotify_fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                std::mem::size_of_val(&buf),
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
            let event = unsafe { &*(buf.as_ptr().add(offset) as *const libc::inotify_event) };
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
    {
        let mut guard = rw_write_ignore_poison(&CURRENT_CONFIG);
        *guard = Some(Arc::new(new_cfg));
    }
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


use std::cmp::Reverse;
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU8, Ordering};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::apply_affinity::{read_cmdline, task_tids};
use crate::cache::ProcCache;
use crate::config::{
    config_reload_now, spec_like,
    CHECK_INTERVAL, CONFIG_FILE, CURRENT_CONFIG, PARSE_FAILS,
};
use crate::cpuset::{base_cpuset, create_cpuset_dir, parse_cpu_spec, CpuSet, CpuTopology, DEFAULT_CPUSET_NAME};
use crate::ebpf_mode::kpm_probe;
use crate::rule_edit::{rule_delete, rule_delete_pkg, rule_rename, rule_upsert, RuleEdit};
use crate::{lock_ignore_poison, MAX_PKG_LEN, MAX_THREAD_LEN};

pub const WEB_PORT: u16 = 8889;
const INDEX_HTML: &str = include_str!("../web/index.html");

pub static MODE_FORCE: AtomicU8 = AtomicU8::new(0);
pub static WEB_ENABLED: AtomicBool = AtomicBool::new(false);

/// 模式切换通知 fd (eventfd): web 端修改 MODE_FORCE 后写入, 唤醒主循环 epoll
pub static MODE_SWITCH_FD: AtomicI32 = AtomicI32::new(-1);

/// 通知主循环模式已变更 (事件驱动, 不轮询)
pub fn notify_mode_switch() {
    let fd = MODE_SWITCH_FD.load(Ordering::Relaxed);
    if fd >= 0 {
        let val: u64 = 1;
        unsafe { libc::write(fd, &val as *const u64 as *const _, 8); }
    }
}

pub static WEB_STATS: Mutex<Option<WebStats>> = Mutex::new(None);

/// 状态页可见性: 前端状态页可见时每 3s 轮询 /api/status; 离开状态页/隐藏/关闭
/// 即停止该请求。窗口取 2 个轮询间隔, 超过即视为未查看, 跳过统计汇总。
const WEB_ACTIVE_WINDOW: Duration = Duration::from_secs(6);
static LAST_WEB_REQ: Mutex<Option<Instant>> = Mutex::new(None);

pub fn mark_web_active() {
    *LAST_WEB_REQ.lock().unwrap() = Some(Instant::now());
}

pub fn web_active() -> bool {
    LAST_WEB_REQ
        .lock()
        .unwrap()
        .is_some_and(|t| t.elapsed() < WEB_ACTIVE_WINDOW)
}

#[derive(Clone)]
pub struct WebStats {
    pub rules: usize,
    pub pkgs: usize,
    pub hit_pkgs: usize,
    /// 当前命中(被管理)的具体包名列表, 供状态页点击展示
    pub hit_list: Vec<String>,
    pub threads: usize,
    pub kpm: bool,
    pub uptime: u64,
}

/// 缓存统计: 返回 (线程数, 命中包名数, 命中包名列表)。
/// 命中包名由 ProcCache 增量维护，避免每次 Web 请求扫描全部线程。
pub fn cache_stats(cache: &ProcCache) -> (usize, usize, Vec<String>) {
    let hit_list = cache.hit_package_list();
    (cache.tasks.len(), hit_list.len(), hit_list)
}

/// 启动 web 前端
pub fn web_start() {
    let listener = match TcpListener::bind(("127.0.0.1", WEB_PORT)) {
        Ok(l) => l,
        Err(_) => {
            return;
        }
    };
    WEB_ENABLED.store(true, Ordering::Release);
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            thread::spawn(move || conn_handle(stream));
        }
    });
}

struct Request {
    method: String,
    path: String,
    host: String,
    origin: String,
    fetch_site: String,
    content_type: String,
    body: Vec<u8>,
    keep_alive: bool,
}

fn conn_handle(stream: TcpStream) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
    let _ = stream.set_nodelay(true);
    let mut writer = match stream.try_clone() {
        Ok(w) => w,
        Err(_) => return,
    };
    let mut reader = BufReader::new(stream);
    while let Some(req) = request_read(&mut reader) {
        dispatch(&mut writer, &req);
        if !req.keep_alive {
            return;
        }
    }
}

fn request_read(reader: &mut BufReader<TcpStream>) -> Option<Request> {
    let mut head = Vec::with_capacity(512);
    let mut line = Vec::with_capacity(128);
    loop {
        line.clear();
        reader.read_until(b'\n', &mut line).ok()?;
        if line.is_empty() {
            return None;
        }
        if line == b"\r\n" || line == b"\n" {
            break;
        }
        head.extend_from_slice(&line);
        if head.len() > 8192 {
            return None;
        }
    }

    let head_str = String::from_utf8_lossy(&head);
    let mut lines = head_str.lines();
    let mut parts = lines.next()?.split_whitespace();
    let method = parts.next()?.to_string();
    let path = parts.next()?.split('?').next().unwrap_or("").to_string();
    let version = parts.next().unwrap_or("HTTP/1.1").to_string();

    let (mut host, mut origin, mut site, mut ctype, mut len) =
        (String::new(), String::new(), String::new(), String::new(), 0usize);
    let mut conn = String::new();
    for h in lines {
        let Some((k, v)) = h.split_once(':') else { continue };
        let v = v.trim();
        match k.trim().to_ascii_lowercase().as_str() {
            "host" => host = v.to_ascii_lowercase(),
            "origin" => origin = v.to_ascii_lowercase(),
            "sec-fetch-site" => site = v.to_ascii_lowercase(),
            "content-type" => ctype = v.to_ascii_lowercase(),
            "content-length" => len = v.parse().unwrap_or(usize::MAX),
            "connection" => conn = v.to_ascii_lowercase(),
            "transfer-encoding" => return None, // 拒绝 chunked
            _ => {}
        }
    }
    if len > 16384 {
        return None;
    }

    let mut body = vec![0u8; len];
    if len > 0 {
        reader.read_exact(&mut body).ok()?;
    }
    let keep_alive = if version == "HTTP/1.0" {
        conn.contains("keep-alive")
    } else {
        !conn.contains("close")
    };
    Some(Request {
        method,
        path,
        host,
        origin,
        fetch_site: site,
        content_type: ctype,
        body,
        keep_alive,
    })
}

fn resp_send(out: &mut TcpStream, status: u16, ctype: &str, body: &[u8], close: bool) {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        _ => "Error",
    };
    let head = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: {}\r\n\r\n",
        status,
        reason,
        ctype,
        body.len(),
        if close { "close" } else { "keep-alive" }
    );
    let _ = out.write_all(head.as_bytes());
    let _ = out.write_all(body);
    let _ = out.flush();
}

fn dispatch(out: &mut TcpStream, req: &Request) {
    let port_str = format!(":{}", WEB_PORT);
    let host = req.host.strip_suffix(&port_str).unwrap_or(req.host.as_str());
    let origin_ok = matches!(host, "127.0.0.1" | "localhost")
        && (req.origin.is_empty()
            || req.origin == "null"
            || matches!(req.fetch_site.as_str(), "" | "none" | "same-origin"))
        && (req.method != "POST" || req.content_type.starts_with("application/json"));
    if !origin_ok {
        resp_send(out, 403, "application/json", b"{\"ok\":false,\"err\":\"forbidden\"}", true);
        return;
    }

    if req.method == "GET" && matches!(req.path.as_str(), "/" | "/index.html") {
        resp_send(out, 200, "text/html; charset=utf-8", INDEX_HTML.as_bytes(), !req.keep_alive);
        return;
    }

    let (status, body) = match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/api/status") => {
                mark_web_active();   /* 状态页轮询信号: 只有状态页可见才持续请求 */
                (200, status_json())
            },
        ("GET", "/api/rules") => (200, rules_json()),
        ("GET", "/api/config") => (200, config_json()),
        ("POST", "/api/rule") => rule_api(req),
        ("POST", "/api/rule/del") => rule_del_api(req),
        ("POST", "/api/rule/rename") => rule_rename_api(req),
        ("POST", "/api/config") => config_set_api(req),
        ("POST", "/api/suggest") => suggest_api(req),
        ("GET", "/api/refresh/status") => (200, refresh_status_json()),
        ("GET", "/api/refresh/config") => (200, refresh_config_json()),
        ("POST", "/api/refresh/config") => refresh_config_set_api(req),
        ("GET", "/api/refresh/apps") => (200, refresh_apps_json()),
        ("POST", "/api/refresh/app") => refresh_app_add_api(req),
        ("POST", "/api/refresh/app/del") => refresh_app_del_api(req),
        _ => err_json(404, "not found"),
    };
    resp_send(out, status, "application/json", body.as_bytes(), !req.keep_alive);
}

fn err_json(code: u16, msg: &str) -> (u16, String) {
    (code, json!({ "ok": false, "err": msg }).to_string())
}

fn current_cfg() -> Option<std::sync::Arc<crate::config::AppConfig>> {
    lock_ignore_poison(&CURRENT_CONFIG).clone()
}

fn sys_procs() -> u16 {
    let mut info: libc::sysinfo = unsafe { std::mem::zeroed() };
    if unsafe { libc::sysinfo(&mut info) } == 0 {
        info.procs
    } else {
        0
    }
}

/// CPU 集合转语义名
fn spec_name(cpus: &CpuSet, topo: &CpuTopology) -> String {
    if cpus.count() > 0 {
        if *cpus == topo.e_core {
            return "e-core".into();
        }
        if *cpus == topo.p_core {
            return "p-core".into();
        }
        if *cpus == topo.hp_core {
            return "hp-core".into();
        }
        if *cpus == topo.present_cpus {
            return "all-core".into();
        }
    }
    cpus.to_range_string()
}

fn status_json() -> String {
    let stats = lock_ignore_poison(&WEB_STATS).clone();
    let cfg = current_cfg();
    let topo = cfg.as_ref().map(|c| &c.topo);
    let s = stats.unwrap_or(WebStats {
        rules: 0,
        pkgs: 0,
        hit_pkgs: 0,
        hit_list: Vec::new(),
        threads: 0,
        kpm: false,
        uptime: 0,
    });
    json!({
        "version": env!("CARGO_PKG_VERSION"),
        "mode": if s.kpm { "kpm" } else { "proc" },
        "uptime": s.uptime,
        "rules": s.rules,
        "pkgs": s.pkgs,
        "parse_fail": PARSE_FAILS.load(Ordering::Relaxed),
        "hit_pkgs": s.hit_pkgs,
        "hit_list": s.hit_list,
        "threads": s.threads,
        "total_procs": sys_procs(),
        "interval": CHECK_INTERVAL.load(Ordering::Relaxed).max(1),
        "e_core": topo.map(|t| t.e_core.to_range_string()).unwrap_or_default(),
        "p_core": topo.map(|t| t.p_core.to_range_string()).unwrap_or_default(),
        "hp_core": topo.map(|t| t.hp_core.to_range_string()).unwrap_or_default(),
        "all_core": topo.map(|t| t.present_str.clone()).unwrap_or_default(),
        "cores": topo.map(|t| t.present_cpus.count()).unwrap_or(0),
        "cpuset_enabled": topo.is_some_and(|t| t.cpuset_enabled),
    })
    .to_string()
}

fn rules_json() -> String {
    let Some(cfg) = current_cfg() else {
        return json!({ "rules": [] }).to_string();
    };
    let mut groups: Vec<serde_json::Value> = Vec::new();
    let mut index: HashMap<&str, usize> = HashMap::new();
    for r in &cfg.rules {
        let gi = *index.entry(r.pkg.as_str()).or_insert_with(|| {
            groups.push(json!({ "pkg": r.pkg, "items": [] }));
            groups.len() - 1
        });
        groups[gi]["items"]
            .as_array_mut()
            .unwrap()
            .push(json!({ "thread": r.thread, "spec": spec_name(&r.cpus, &cfg.topo) }));
    }
    json!({ "rules": groups }).to_string()
}

/// 名称校验
fn token_ok(s: &str, max: usize) -> bool {
    let t = s.trim();
    !t.is_empty()
        && t.len() < max
        && !t.bytes().any(|b| b < 0x20 || b == 0x7f)
        && !t.contains('#')
        && !t.contains("//")
}

fn pkg_shape_ok(pkg: &str) -> bool {
    !(pkg.contains('{') && pkg.ends_with('}'))
}

fn rule_api(req: &Request) -> (u16, String) {
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(&req.body) else {
        return err_json(400, "请求体不是合法 JSON");
    };
    let (Some(pkg), Some(cpus)) = (
        v["pkg"].as_str().map(str::trim),
        v["cpus"].as_str().map(str::trim),
    ) else {
        return err_json(400, "缺少 pkg 或 cpus 字段");
    };
    let thread = v["thread"].as_str().map(str::trim).unwrap_or("");
    let Some(cfg) = current_cfg() else {
        return err_json(500, "配置未就绪");
    };
    if !token_ok(pkg, MAX_PKG_LEN) || (!thread.is_empty() && !token_ok(thread, MAX_THREAD_LEN)) {
        return err_json(400, "名称含有非法字符");
    }
    if thread.is_empty() && !pkg_shape_ok(pkg) {
        return err_json(400, "包名含 { 且以 } 结尾时不支持包级规则，可改用线程规则");
    }
    if cpus.is_empty() || cpus.len() >= 64 || !spec_like(cpus)
        || parse_cpu_spec(cpus, &cfg.topo).count() == 0
    {
        return err_json(400, "无效的 CPU 规格");
    }

    let file = lock_ignore_poison(&CONFIG_FILE).clone();
    match rule_upsert(&file, pkg, thread, cpus) {
        RuleEdit::Ok => {
            config_reload_now();
            (200, json!({ "ok": true }).to_string())
        }
        RuleEdit::Malformed => err_json(409, "配置文件存在未闭合块，请修复后重试"),
        _ => err_json(500, "配置文件写入失败"),
    }
}

fn rule_del_api(req: &Request) -> (u16, String) {
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(&req.body) else {
        return err_json(400, "请求体不是合法 JSON");
    };
    let Some(pkg) = v["pkg"].as_str().map(str::trim) else {
        return err_json(400, "缺少 pkg 字段");
    };
    let thread = v["thread"].as_str().map(str::trim).unwrap_or("");

    let file = lock_ignore_poison(&CONFIG_FILE).clone();
    let result = if v["all"].as_bool().unwrap_or(false) {
        rule_delete_pkg(&file, pkg)
    } else {
        rule_delete(&file, pkg, thread)
    };
    match result {
        RuleEdit::Ok => {
            config_reload_now();
            (200, json!({ "ok": true }).to_string())
        }
        RuleEdit::NotFound => err_json(404, "规则不存在"),
        RuleEdit::Conflict => err_json(409, "状态冲突"),
        RuleEdit::Malformed => err_json(409, "配置文件存在未闭合块，请修复后重试"),
        RuleEdit::IoErr => err_json(500, "配置文件写入失败"),
    }
}

fn rule_rename_api(req: &Request) -> (u16, String) {
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(&req.body) else {
        return err_json(400, "请求体不是合法 JSON");
    };
    let (Some(old), Some(new)) =
        (v["old"].as_str().map(str::trim), v["new"].as_str().map(str::trim))
    else {
        return err_json(400, "缺少 old 或 new 字段");
    };
    if !token_ok(old, MAX_PKG_LEN) || !token_ok(new, MAX_PKG_LEN) {
        return err_json(400, "名称含有非法字符");
    }
    if !pkg_shape_ok(new) {
        return err_json(400, "包名含 { 且以 } 结尾时不可作为重命名目标");
    }
    if old == new {
        return (200, json!({ "ok": true }).to_string());
    }

    let file = lock_ignore_poison(&CONFIG_FILE).clone();
    match rule_rename(&file, old, new) {
        RuleEdit::Ok => {
            config_reload_now();
            (200, json!({ "ok": true }).to_string())
        }
        RuleEdit::NotFound => err_json(404, "原包名不存在"),
        RuleEdit::Conflict => err_json(409, "目标包名已存在规则"),
        RuleEdit::Malformed => err_json(409, "配置文件存在未闭合块，请修复后重试"),
        RuleEdit::IoErr => err_json(500, "配置文件写入失败"),
    }
}

/// 输入建议
fn suggest_api(req: &Request) -> (u16, String) {
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(&req.body) else {
        return err_json(400, "请求体不是合法 JSON");
    };
    let q = v["q"].as_str().map(str::trim).unwrap_or("");
    if q.len() > 64 {
        return err_json(400, "q 过长");
    }
    let list: Vec<String> = match v["pkg"].as_str().map(str::trim).filter(|p| !p.is_empty()) {
        None => suggest_pkgs(q).into_iter().map(|(n, _)| n).collect(),
        Some(pkg) => {
            if !token_ok(pkg, MAX_PKG_LEN) {
                return err_json(400, "名称含有非法字符");
            }
            suggest_threads(pkg, q).into_iter().map(|(n, _)| n).collect()
        }
    };
    (200, json!({ "ok": true, "list": list }).to_string())
}

/// 枚举包名
fn installed_pkgs() -> Vec<String> {
    fs::read_dir("/data/data")
        .map(|dirs| {
            dirs.flatten()
                .map(|d| d.file_name().to_string_lossy().into_owned())
                .filter(|n| n.contains('.') && !n.starts_with('.'))
                .collect()
        })
        .unwrap_or_default()
}

fn for_each_pid(mut f: impl FnMut(i32)) {
    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            if let Ok(pid) = entry.file_name().to_string_lossy().parse::<i32>() {
                f(pid);
            }
        }
    }
}

/// 排序键
fn rank_top(counts: BTreeMap<String, usize>, lq: &str) -> Vec<(String, usize)> {
    let mut ranked: Vec<(u8, Reverse<usize>, String)> = counts
        .into_iter()
        .filter_map(|(n, c)| {
            let ln = n.to_ascii_lowercase();
            let r = if ln.starts_with(lq) { 0 } else if ln.contains(lq) { 1 } else { 2 };
            (r < 2).then_some((r, Reverse(c), n))
        })
        .collect();
    ranked.sort_unstable();
    ranked.truncate(20);
    ranked.into_iter().map(|(_, Reverse(c), n)| (n, c)).collect()
}

fn suggest_pkgs(q: &str) -> Vec<(String, usize)> {
    let mut counts: BTreeMap<String, usize> =
        installed_pkgs().into_iter().map(|p| (p, 0)).collect();
    for_each_pid(|pid| {
        if let Some(name) = read_cmdline(pid).filter(|n| n.contains('.')) {
            *counts.entry(name).or_insert(0) += 1;
        }
    });
    rank_top(counts, &q.to_ascii_lowercase())
}

fn thread_comm(pid: i32, tid: i32) -> Option<String> {
    let s = fs::read_to_string(format!("/proc/{}/task/{}/comm", pid, tid)).ok()?;
    let name = s.trim_end_matches(['\0', '\n']).trim();
    (!name.is_empty()).then(|| name.to_string())
}

fn suggest_threads(pkg: &str, q: &str) -> Vec<(String, usize)> {
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for_each_pid(|pid| {
        if read_cmdline(pid).as_deref() == Some(pkg) {
            for tid in task_tids(pid).unwrap_or_default() {
                if let Some(comm) = thread_comm(pid, tid) {
                    *counts.entry(comm).or_insert(0) += 1;
                }
            }
        }
    });
    rank_top(counts, &q.to_ascii_lowercase())
}

fn config_json() -> String {
    let stats = lock_ignore_poison(&WEB_STATS).clone();
    let cfg = current_cfg();
    json!({
        "mode": MODE_FORCE.load(Ordering::Relaxed),
        "mode_active": if stats.is_some_and(|s| s.kpm) { "kpm" } else { "proc" },
        "kpm_available": kpm_probe(),
        "interval": CHECK_INTERVAL.load(Ordering::Relaxed).max(1),
        "cpuset_name": base_cpuset().rsplit('/').next().unwrap_or_default(),
        "config_file": lock_ignore_poison(&CONFIG_FILE).clone(),
        "cpuset_enabled": cfg.is_some_and(|c| c.topo.cpuset_enabled),
    })
    .to_string()
}

fn config_set_api(req: &Request) -> (u16, String) {
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(&req.body) else {
        return err_json(400, "请求体不是合法 JSON");
    };
    let mode = v["mode"].as_u64();
    let interval = v["interval"].as_u64();
    let name = v["cpuset_name"].as_str();
    let path = v["config_file"].as_str();

    if mode.is_some_and(|m| m > 2) {
        return err_json(400, "无效的工作模式");
    }
    if interval.is_some_and(|n| !(1..=3600).contains(&n)) {
        return err_json(400, "间隔需在 1-3600 秒之间");
    }
    if name.is_some_and(|n| !valid_name(n)) {
        return err_json(400, "无效的 cpuset 目录名");
    }
    if path.is_some_and(|p| !valid_path(p)) {
        return err_json(400, "无效的配置文件路径");
    }

    if let Some(m) = mode {
        MODE_FORCE.store(m as u8, Ordering::Relaxed);
        notify_mode_switch();
    }
    if let Some(n) = interval {
        CHECK_INTERVAL.store(n, Ordering::Relaxed);
    }
    if let Some(n) = name {
        crate::cpuset::set_base_cpuset(n);
        if let Some(cfg) = current_cfg()
            && cfg.topo.cpuset_enabled {
                create_cpuset_dir(&base_cpuset(), &cfg.topo.present_str, &cfg.topo.mems_str);
            }
        crate::config::request_config_reload();
    }
    if let Some(p) = path {
        if std::fs::metadata(p).is_err() {
            let _ = std::fs::write(p, "# 规则编写与使用说明请参考 http://AppOpt.suto.top\n\n");
        }
        *lock_ignore_poison(&CONFIG_FILE) = p.to_string();
        crate::config::request_config_reload();
    }

    settings_save();
    (200, json!({ "ok": true }).to_string())
}

pub const SETTINGS_FILE: &str = "./AppOpt.json";

static SAVE_LOCK: Mutex<()> = Mutex::new(());

#[derive(Clone)]
pub struct Settings {
    pub web_enable: bool,
    pub mode: u8,
    pub check_interval: u64,
    pub cpuset_name: String,
    pub config_file: String,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            web_enable: false,
            mode: 0,
            check_interval: 2,
            cpuset_name: DEFAULT_CPUSET_NAME.to_string(),
            config_file: "./appopt.conf".to_string(),
        }
    }
}

fn valid_name(s: &str) -> bool {
    !s.is_empty() && s.len() < 64 && !s.contains('/') && !s.bytes().any(|b| b <= b' ')
}

fn valid_path(s: &str) -> bool {
    !s.is_empty() && s.len() < 256 && !s.bytes().any(|b| b < 0x20 || b == 0x7f)
}

impl Settings {
    fn from_json(v: &Value) -> Self {
        let d = Settings::default();
        Self {
            web_enable: v["web_enable"].as_bool().unwrap_or(d.web_enable),
            mode: v["mode"].as_u64().unwrap_or(d.mode as u64).min(2) as u8,
            check_interval: v["check_interval"]
                .as_u64()
                .unwrap_or(d.check_interval)
                .clamp(1, 3600),
            cpuset_name: v["cpuset_name"]
                .as_str()
                .filter(|s| valid_name(s))
                .unwrap_or(&d.cpuset_name)
                .to_string(),
            config_file: v["config_file"]
                .as_str()
                .filter(|s| valid_path(s))
                .unwrap_or(&d.config_file)
                .to_string(),
        }
    }

    fn to_value(&self) -> Value {
        json!({
            "web_enable": self.web_enable,
            "mode": self.mode,
            "check_interval": self.check_interval,
            "cpuset_name": self.cpuset_name,
            "config_file": self.config_file,
        })
    }

    fn save(&self, path: &str) {
        let _guard = lock_ignore_poison(&SAVE_LOCK);
        let json = serde_json::to_string_pretty(&self.to_value()).unwrap_or_default();
        let tmp = format!("{}.tmp", path);
        let res = fs::File::create(&tmp)
            .and_then(|mut f| {
                f.write_all(format!("{}\n", json).as_bytes())?;
                f.sync_all()
            })
            .and_then(|_| fs::rename(&tmp, path));
        let _ = res;
    }
}

pub fn settings_load(path: &str) -> Settings {
    match fs::read_to_string(path) {
        Ok(text) => match serde_json::from_str::<Value>(&text) {
            Ok(v) => Settings::from_json(&v),
            Err(_) => Settings::default(),
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let d = Settings::default();
            d.save(path);
            d
        }
        Err(_) => Settings::default(),
    }
}

pub fn settings_save() {
    Settings {
        web_enable: WEB_ENABLED.load(Ordering::Relaxed),
        mode: MODE_FORCE.load(Ordering::Relaxed),
        check_interval: CHECK_INTERVAL.load(Ordering::Relaxed).max(1),
        cpuset_name: base_cpuset().rsplit('/').next().unwrap_or_default().to_string(),
        config_file: lock_ignore_poison(&CONFIG_FILE).clone(),
    }
    .save(SETTINGS_FILE);
}

// ===== 刷新率 Web API =====

fn refresh_status_json() -> String {
    match crate::refresh::refresh_get_status() {
        Some(s) => json!({
            "current_mode": s.current_mode,
            "mode_str": match s.current_mode {
                0 => "120Hz", 1 => "60Hz", 2 => "90Hz", _ => "未知"
            },
            "timer_running": s.timer_running,
            "is_paused": s.is_paused,
            "timer_enabled": s.timer_enabled,
            "current_package": s.current_package,
            "timeout": s.timeout,
            "active_mode": s.active_mode,
            "active_str": match s.active_mode {
                0 => "120Hz", 1 => "60Hz", 2 => "90Hz", _ => "60Hz"
            },
            "idle_mode": s.idle_mode,
            "idle_str": match s.idle_mode {
                0 => "120Hz", 1 => "60Hz", 2 => "90Hz", _ => "60Hz"
            },
        }).to_string(),
        None => json!({"error": "refresh module not initialized"}).to_string(),
    }
}

fn refresh_config_json() -> String {
    let (timeout, active, idle) = crate::refresh::refresh_get_config();
    json!({
        "timeout": timeout,
        "active": active,
        "idle": idle,
    }).to_string()
}

fn refresh_config_set_api(req: &Request) -> (u16, String) {
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(&req.body) else {
        return err_json(400, "请求体不是合法 JSON");
    };
    let timeout = v["timeout"].as_u64().unwrap_or(30) as i32;
    let active = v["active"].as_str().unwrap_or("120");
    let idle = v["idle"].as_str().unwrap_or("60");
    if timeout < 1 || timeout > 3600 {
        return err_json(400, "超时时间需在 1-3600 秒之间");
    }
    if !matches!(active, "120" | "90" | "60") || !matches!(idle, "120" | "90" | "60") {
        return err_json(400, "刷新率仅支持 120/90/60");
    }
    crate::refresh::refresh_set_config(timeout, active, idle);
    (200, json!({"ok": true}).to_string())
}

fn refresh_apps_json() -> String {
    let apps = crate::refresh::refresh_get_apps();
    let arr: Vec<_> = apps.iter().map(|(pkg, timeout, active, idle)| {
        json!({"pkg": pkg, "timeout": timeout, "active": active, "idle": idle})
    }).collect();
    json!({"apps": arr}).to_string()
}

fn refresh_app_add_api(req: &Request) -> (u16, String) {
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(&req.body) else {
        return err_json(400, "请求体不是合法 JSON");
    };
    let Some(pkg) = v["pkg"].as_str().map(str::trim) else {
        return err_json(400, "缺少 pkg 字段");
    };
    if pkg.is_empty() || pkg.len() >= 128 || !pkg.bytes().all(|b| b >= 0x20 && b != 0x7f) {
        return err_json(400, "无效的包名");
    }
    let timeout = v["timeout"].as_u64().unwrap_or(30) as i32;
    let active = v["active"].as_str().unwrap_or("120");
    let idle = v["idle"].as_str().unwrap_or("60");
    if timeout < 1 || timeout > 3600 {
        return err_json(400, "超时时间需在 1-3600 秒之间");
    }
    if !matches!(active, "120" | "90" | "60") || !matches!(idle, "120" | "90" | "60") {
        return err_json(400, "刷新率仅支持 120/90/60");
    }
    crate::refresh::refresh_add_app(pkg, timeout, active, idle);
    (200, json!({"ok": true}).to_string())
}

fn refresh_app_del_api(req: &Request) -> (u16, String) {
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(&req.body) else {
        return err_json(400, "请求体不是合法 JSON");
    };
    let Some(pkg) = v["pkg"].as_str().map(str::trim) else {
        return err_json(400, "缺少 pkg 字段");
    };
    if pkg.is_empty() {
        return err_json(400, "包名不能为空");
    }
    if crate::refresh::refresh_del_app(pkg) {
        (200, json!({"ok": true}).to_string())
    } else {
        err_json(500, "删除失败")
    }
}

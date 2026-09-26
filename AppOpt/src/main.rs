#![cfg(any(target_os = "linux", target_os = "android"))]
#[cfg(target_pointer_width = "32")]
compile_error!("AppOpt requires 64-bit target due to cpu_set_t binary layout assumptions");

mod apply_affinity;
mod cpu_affinity;
mod config;
mod cpuset;
mod ebpf_mode;
mod process_observer;
mod refresh;
mod rule_edit;
mod rule_match;
mod event_probe;
mod web;

use std::collections::{HashMap, HashSet};
use std::env;
use std::ffi::CString;
use std::fs;
use std::process;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, RwLock};

use crate::config::{
    init_inotify, load_config, AppConfig,
    CONFIG_FILE, CONFIG_WAKE_FD, CURRENT_CONFIG,
};
use crate::cpuset::{init_cpu_topo, set_base_cpuset};
use crate::ebpf_mode::{
    ebpf_init, EbpfState,
};
use crate::web::{
    settings_load, settings_save, web_start, SETTINGS_FILE,
};

pub const MAX_PKG_LEN: usize = 128;
pub const MAX_THREAD_LEN: usize = 32;

pub(crate) fn lock_ignore_poison<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

/// 高频只读数据的读锁 (RwLock): 多线程并发读不互斥, 写方独占
pub(crate) fn rw_read_ignore_poison<T>(rw: &RwLock<T>) -> std::sync::RwLockReadGuard<'_, T> {
    rw.read().unwrap_or_else(|e| e.into_inner())
}

/// 高频只读数据的写锁 (RwLock): 独占写
pub(crate) fn rw_write_ignore_poison<T>(rw: &RwLock<T>) -> std::sync::RwLockWriteGuard<'_, T> {
    rw.write().unwrap_or_else(|e| e.into_inner())
}

/// uid 表条目: 一个 uid → 包名 + 用途标志 (CPU 规则 / 刷新率)
struct UidEntry {
    pkg: String,
    cpu: bool,
    rfr: bool,
}

/// 从 packages.list 构建 uid→条目 静态表 (主线程持有):
///   cpu = 有 CPU 规则的应用; rfr = com.android.launcher3 + 有刷新率规则的应用。
/// 一个应用可同时 CPU + 刷新率 (合表后用标志位表达)。前台回调只查本表。
fn build_uid_tables(cfg: &AppConfig) -> (HashMap<i32, UidEntry>, HashMap<String, i32>) {
    let mut cpu_pkgs: HashSet<&str> = HashSet::new();
    for r in &cfg.rules {
        cpu_pkgs.insert(r.pkg.as_str());
    }
    let mut fwd: HashMap<i32, UidEntry> = HashMap::new();
    let mut rev: HashMap<String, i32> = HashMap::new();
    if let Ok(content) = std::fs::read_to_string("/data/system/packages.list") {
        for line in content.lines() {
            let mut it = line.split_whitespace();
            let (Some(pkg), Some(uid_s)) = (it.next(), it.next()) else { continue };
            let Ok(uid) = uid_s.parse::<i32>() else { continue };
            // 只收当前用户 (Android 多用户 uid 偏移; 同一包多行时不污染)
            if uid >= 100000 {
                continue;
            }
            let cpu = cpu_pkgs.contains(pkg);
            let rfr = pkg == crate::config::DEFAULT_REFRESH_PACKAGE
                || cfg.app_refresh_configs.contains_key(pkg);
            if cpu || rfr {
                fwd.entry(uid).or_insert_with(|| UidEntry { pkg: pkg.to_string(), cpu, rfr });
                rev.entry(pkg.to_string()).or_insert(uid);
            }
        }
    }
    (fwd, rev)
}

/// 遍历 /proc 全部数字 pid (>0); 供 web 枚举应用进程 (cpu_affinity 已改 cgroup 取 pid, 不经过)
pub(crate) fn for_each_proc_pid(mut f: impl FnMut(i32)) {
    if let Ok(entries) = std::fs::read_dir("/proc") {
        for e in entries.flatten() {
            if let Ok(p) = e.file_name().to_string_lossy().parse::<i32>()
                && p > 0
            {
                f(p);
            }
        }
    }
}

/// CPU 规则包 → uid: 从 main 维护的反向表过滤 (不直接读 packages.list)
fn cpu_pkg_uids(cfg: &crate::config::AppConfig, pkg_uid: &HashMap<String, i32>) -> HashMap<String, i32> {
    cfg.pkgs
        .iter()
        .filter_map(|p| pkg_uid.get(p).map(|u| (p.clone(), *u)))
        .collect()
}

/// 按包名在 packages.list 查 uid (单个; 供增量维护在交叉提取失败时回退)
fn lookup_uid_in_packages_list(pkg: &str) -> Option<i32> {
    let content = std::fs::read_to_string("/data/system/packages.list").ok()?;
    for line in content.lines() {
        let mut it = line.split_whitespace();
        let (Some(p), Some(u)) = (it.next(), it.next()) else { continue };
        if p == pkg {
            return u.parse::<i32>().ok();
        }
    }
    None
}

/// 规则应用集合 (cpu/rfr): 主线程检测“新增/删除规则应用”, 集合未变则跳过重建
fn cfg_pkg_sets(cfg: &AppConfig) -> (HashSet<String>, HashSet<String>) {
    let cpu: HashSet<String> = cfg.rules.iter().map(|r| r.pkg.clone()).collect();
    let mut rfr: HashSet<String> = cfg.app_refresh_configs.keys().cloned().collect();
    rfr.insert(crate::config::DEFAULT_REFRESH_PACKAGE.to_string());
    (cpu, rfr)
}


fn print_help(prog_name: &str) {
    println!("Usage: {} [OPTIONS]", prog_name);
    println!("Options:");
    println!("  -c <config_file>   指定统一配置文件 (默认: ./applist.conf)");
    println!("  -b <cpuset_name>   指定 BASE_CPUSET 目录名 (默认: AppOpt)");
    println!("  -w                 启用网页前端 (仅本机 127.0.0.1:8889)");
    println!("  -v                 显示程序版本");
    println!("  -h                 显示帮助信息");
    println!();
    println!("示例:");
    println!("  {} -c /data/applist.conf", prog_name);
    println!("  {} -b MyAppOpt", prog_name);
    println!();
    println!("应用设置保存于 ./AppOpt.json，首次运行自动创建；");
    println!("命令行参数优先于设置文件，web 端修改会写回该文件。");
    println!();
    println!("规则格式:");
    println!("  # 注释以 # 或 // 开头");
    println!("  com.example=0-3           包级规则，绑定到 CPU 0-3");
    println!("  com.example=e-core        语义核心，绑定到全部小核");
    println!("  com.example=p-core        语义核心，绑定到全部中核");
    println!("  com.example=hp-core       语义核心，绑定到全部大核");
    println!();
    println!("  块语法，包级规则 + 线程规则");
    println!("  com.example {{");
    println!("    RenderThread=6-7");
    println!("    Thread-1=0-5");
    println!("  }}");
    println!("  线程 RenderThread 绑定到 CPU 6-7");
    println!("  线程 Thread-1 绑定到 CPU 0-5");
    println!();
    println!("刷新率配置（与上述规则共用此文件）:");
    println!("  refresh_timeout=30");
    println!("  refresh_active=120");
    println!("  refresh_idle=60");
    println!("  com.example.game=refresh-30-120-60");
}

// ================= 模块级辅助 (不捕获环境; 原 main 内嵌 fn 提取) =================

fn spawn_probe_pipe(sv: &mut [libc::c_int; 2]) -> bool {
    let ok = unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_DGRAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
            sv.as_mut_ptr(),
        )
    };
    ok == 0
}

fn epoll_add(epfd: i32, fd: i32, tag: u64) {
    if fd < 0 {
        return;
    }
    let mut ev: libc::epoll_event = unsafe { std::mem::zeroed() };
    ev.events = libc::EPOLLIN as u32;
    ev.u64 = tag;
    unsafe { libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, fd, &mut ev) };
}

fn read_eventfd(fd: i32) {
    if fd < 0 {
        return;
    }
    let mut buf = [0u8; 8];
    let _ = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut _, 8) };
}

/// 用户态事件探测线程 (合并触摸+退出): 单 epoll 统一监听 触摸 fd (/dev/input eventX,
/// abs 能力探测设备) + pidfd 集合 (进程退出) + 控制 fd (触摸启停); 全模式统一
/// (KPM 不再消费内核 EXIT 事件)。返回 (touch_ok, exit_ok); 触摸通道失败不拖垮退出监听。
fn spawn_event_probe(touch_sv: &mut [libc::c_int; 2], exit_sv: &mut [libc::c_int; 2]) -> (bool, bool) {
    let touch_ok = spawn_probe_pipe(touch_sv); // 触摸活动通知通道
    let exit_ok = spawn_probe_pipe(exit_sv);   // 主进程退出通知通道 (必需)
    if !exit_ok {
        crate::event_probe::set_ctrl_fd(-1);
        return (touch_ok, false);
    }
    // 触摸监听控制 socket: refresh 线程按 timer_enabled 暂停/恢复监听
    let mut ctrl: [libc::c_int; 2] = [-1, -1];
    let ctrl_ok = spawn_probe_pipe(&mut ctrl);
    crate::event_probe::set_ctrl_fd(if ctrl_ok { ctrl[1] } else { -1 }); // 写端供 set_enabled 使用
    let tw = if touch_ok { touch_sv[1] } else { -1 };
    let cr = if ctrl_ok { ctrl[0] } else { -1 };
    let ew = exit_sv[1];
    std::thread::spawn(move || crate::event_probe::spawn_event(tw, cr, ew));
    (touch_ok, true)
}

/// 亲和性重放 (配置变更共用): 按最近变更包单包 ApplyPkgByUid/ApplyThreadByUid,
/// 无变更包 → 全量。用户态与 KPM 模式一致生效。
fn kpm_full_apply(cfg: &crate::config::AppConfig, pkg_uid: &HashMap<String, i32>) {
    // 规则编辑保存路径: 只对最近变更包单包重放亲和性 (避免改一个应用 →
    // apply_all_now 全量重放所有规则应用); 启动/整体重载等无变更包 → 全量。
    // 主线程反查 uid (pkg_uid) 后消息携带 uid 下发; 未安装/未运行的包不反查到 uid
    // → 不发消息 (规则只对未来启动的应用生效)。
    match crate::web::last_rule_take() {
        Some((pkg, Some(thread))) => {
            if let Some(uid) = pkg_uid.get(&pkg) {
                if let Some(tx) = crate::cpu_affinity::cpu_fg_tx() {
                    let _ = tx.send(crate::cpu_affinity::CpuMsg::ApplyThreadByUid(
                        *uid, pkg, thread,
                    ));
                }
            }
        }
        Some((pkg, None)) => {
            if let Some(uid) = pkg_uid.get(&pkg) {
                if let Some(tx) = crate::cpu_affinity::cpu_fg_tx() {
                    let _ = tx.send(crate::cpu_affinity::CpuMsg::ApplyPkgByUid(*uid, pkg));
                }
            }
        }
        None => crate::cpu_affinity::apply_all_now(cpu_pkg_uids(cfg, pkg_uid)),
    }
}

/// 配置变更后应用: 全量扫描 + uid 表重建(规则包集合门控; 两模式统一)
fn apply_config(cpu_changed: bool, cfg: Option<&crate::config::AppConfig>, pkg_uid: &HashMap<String, i32>) {
    let Some(cfg) = cfg else { return };
    // CPU 规则未变 (仅刷新率/数值调整): 无需全量扫描, 亲和性/uid 表不需重放
    if !cpu_changed {
        return;
    }
    // 两模式统一重放 (用户态亦生效; 不再按 KPM 存在与否门控)
    kpm_full_apply(cfg, pkg_uid);
}

/// uid 表重建: 按 cpu_changed/包集合变化决定 (reload_config 共用)
fn rebuild_uid_if_needed(
    cpu_changed: bool,
    cfg: &crate::config::AppConfig,
    uid_map: &mut HashMap<i32, UidEntry>,
    pkg_uid: &mut HashMap<String, i32>,
    cpu_pkgs_set: &mut HashSet<String>,
    rfr_pkgs_set: &mut HashSet<String>,
) {
    let (nc, nr) = cfg_pkg_sets(cfg);
    let cpu_set_changed = cpu_changed && nc != *cpu_pkgs_set;
    let rfr_set_changed = nr != *rfr_pkgs_set;
    if !cpu_set_changed && !rfr_set_changed {
        return;
    }
    // 合表增量维护 (不再整表重扫 packages.list):
    // - 已有条目: 按新集合刷新 cpu/rfr 标志, 两者皆无则移除;
    // - 新增: 该包已存在 (如先有 CPU 规则后加刷新率) 时标志位自然覆盖,
    //         仅"全新包名"才按包名查 packages.list 取 uid。
    uid_map.retain(|_, e| {
        e.cpu = nc.contains(&e.pkg);
        e.rfr = nr.contains(&e.pkg);
        e.cpu || e.rfr
    });
    let known: HashSet<String> = uid_map.values().map(|e| e.pkg.clone()).collect();
    for pkg in nc.union(&nr) {
        if known.contains(pkg.as_str()) {
            continue;
        }
        if let Some(uid) = lookup_uid_in_packages_list(pkg) {
            uid_map.insert(uid, UidEntry {
                pkg: pkg.clone(),
                cpu: nc.contains(pkg),
                rfr: nr.contains(pkg),
            });
        }
    }
    // 就地更新反向表 (pkg → uid): 移除已删除包, 再按最新 uid_map 刷新
    pkg_uid.retain(|pkg, _| nc.contains(pkg) || nr.contains(pkg));
    for (&u, e) in uid_map.iter() {
        pkg_uid.insert(e.pkg.clone(), u);
    }
    *cpu_pkgs_set = nc;
    *rfr_pkgs_set = nr;
}

/// 主循环跨事件共享状态 (打包原 6 个局部 mut, 消除长参数传递)
struct AppState {
    ebpf_state: Option<EbpfState>,
    cfg: Option<Arc<AppConfig>>,
    uid_map: HashMap<i32, UidEntry>,
    pkg_uid: HashMap<String, i32>,
    cpu_pkgs_set: HashSet<String>,
    rfr_pkgs_set: HashSet<String>,
    /// 已下发给内核的 service list 伪装开关 (差量下发, 仅应用切换时调整)
    srv_active_cur: bool,
    last_fg_pkg: String,
    /* vfc 规则下发指纹缓存: (pkg, kind, target, from, to) — 对比判断新增/删除, 无变化不重发 */
    rule_cache: Vec<(String, String, String, String, String)>,
    /// 已下发给内核的 property 区伪装开关 (独立目标应用集)
    prop_active_cur: bool,
}

impl AppState {
    /// 从 CURRENT_CONFIG 构建 (初始 uid 表 + 规则包集合)
    fn new() -> Self {
        let cfg = rw_read_ignore_poison(&CURRENT_CONFIG).clone();
        let (uid_map, pkg_uid) = cfg
            .as_ref()
            .map(|c| build_uid_tables(c))
            .unwrap_or_default();
        let (cpu_pkgs_set, rfr_pkgs_set) = cfg
            .as_ref()
            .map(|c| cfg_pkg_sets(c))
            .unwrap_or_default();
        Self {
            ebpf_state: None,
            cfg,
            uid_map,
            pkg_uid,
            cpu_pkgs_set,
            rfr_pkgs_set,
            srv_active_cur: false,
            last_fg_pkg: String::new(),
            rule_cache: Vec::new(),
            prop_active_cur: false,
        }
    }

    /// 配置重载 (EV_INOTIFY / EV_CONFIG 共用): 重载配置 → 应用到当前模式 →
    /// 仅"规则应用集合"变更时重建 uid 表 (调整数值不重建)
    /// KPM 武装/解除 (拦截页连接/断开): start=武装全功能, stop=解除;
    /// 武装后立即同步 waylay 规则 (清理后的合法规则)
    fn set_kpm_arm(&mut self, arm: bool) {
        // 连接且 KPM 未就绪: 模块可能后加载 (AppOpt 先启动) —— 重试初始化
        if arm && self.ebpf_state.is_none() {
            if let Some(es) = crate::ebpf_mode::ebpf_init(String::new()) {
                self.ebpf_state = Some(es);
            }
        }
        if arm {
            /* 连接: 先下发 uid 规则表 (sync_vfc_rules 需 &mut self, 移出 es 借用块) */
            self.sync_vfc_rules();
        }
        if let Some(es) = self.ebpf_state.as_ref() {
            if arm {
                es.bpf.arm();
                // red-path 副本权限/上下文同步 (连接时校准)
                crate::config::sync_redpath_perm(&crate::rw_read_ignore_poison(
                    &crate::config::WAYLAY_RULES_NEW,
                ));
                es.bpf.vfc_apply();
            } else {
                es.bpf.disarm();
                // 断开把探针摘除 (srv_remove); 重置激活记录 → 下次前台回调重新下发
                self.srv_active_cur = false;
            }
            crate::web::KPM_ARMED.store(arm, std::sync::atomic::Ordering::Relaxed);
        }
    }

    /// 用户态配置驱动: uid 规则表下发。构建指纹 (uid, kind, target, from, to) 对比缓存,
    /// 有新增/删除才 clear + 重发 (无变化零动作); 全局(pkg="*")→uid=-1 段在前。
    fn sync_vfc_rules(&mut self) {
        let all = crate::rw_read_ignore_poison(&crate::config::WAYLAY_RULES_NEW);
        /* 包名规则表 (四功能统一包名, 无需转 uid): 指纹 (pkg, kind, target, from, to) 对比缓存 */
        let mut rows: Vec<(String, String, String, String, String)> = Vec::new();
        for r in all.iter() {
            if r.kind == crate::config::WaylayKind::Red
                || r.kind == crate::config::WaylayKind::RedPath
            {
                let (k, tg) = if r.kind == crate::config::WaylayKind::Red {
                    ("c", r.target.clone())
                } else {
                    ("p", "-".to_string())   /* 占位: 内核 sscanf 需 target 段非空 */
                };
                rows.push((r.pkg.clone(), k.to_string(), tg, r.from.clone(), r.to.clone()));
            }
        }
        rows.sort_by(|a, b| a.0.cmp(&b.0));   /* "*" 全局段在前, 同包规则连续 */
        if rows == self.rule_cache {
            return;   /* 无新增/删除 → 不重发 */
        }
        if let Some(es) = self.ebpf_state.as_ref() {
            let glob_n = rows.iter().filter(|x| x.0 == "*").count().min(512);
            es.bpf.vfc_rule_clear();
            let mut i = 0usize;
            for (pkg, kind, tg, from, to) in rows.iter() {
                if i >= 512 {
                    break;
                }
                es.bpf.vfc_rule(i, pkg, kind, tg, from, to);
                i += 1;
            }
            es.bpf.vfc_glob_count(glob_n);
            es.bpf.vfc_fg(&self.last_fg_pkg);   /* 表重建后定位当前前台包段 */
        }
        self.rule_cache = rows;
    }

    fn reload(&mut self) {
        // waylay.conf 启动/重载直接加载 (更新 WAYLAY_RULES_NEW/BY_UID/GLOBAL_RED; web 保存已走 save)
        crate::config::load_waylay_rules();
        // 拦截页连接/断开: 武装请求 (在模块加载/激活前提下执行)
        match crate::config::take_kpm_arm_req() {
            1 => self.set_kpm_arm(true),
            -1 => self.set_kpm_arm(false),
            _ => {}
        }
        // waylay 配置保存 (web /api/waylay): 同步替换字符到内核 (目标 uid 集合已由
        // save_waylay 更新静态, 下一次前台回调差量生效)
        if crate::config::take_waylay_changed() {
            // 仅 red/red-path (内容替换/文件重定向) 配置变化 → 重下发 vfc 规则
            // (src/prop 保存不触发; 连接 arm 时始终全量下发)
            if crate::config::take_vfc_changed() {
                self.sync_vfc_rules();
            }
            crate::config::sync_redpath_perm(&crate::rw_read_ignore_poison(
                &crate::config::WAYLAY_RULES_NEW,
            ));
            crate::ebpf_mode::ensure_prop_maps();
            crate::config::rebuild_pkg_by_uid();   /* 规则应用变化 → 重建 uid→包名缓存 */
            // src/prop 保存也立即下发 (当前前台包, 各自机制)
            if !self.last_fg_pkg.is_empty() {
                let my: Vec<crate::config::WaylayRule> = crate::rw_read_ignore_poison(
                    &crate::config::WAYLAY_RULES_NEW,
                )
                .iter()
                .filter(|r| r.pkg == self.last_fg_pkg)
                .cloned()
                .collect();
                let has_src = my
                    .iter()
                    .any(|r| r.kind == crate::config::WaylayKind::Src);
                let has_prop = my
                    .iter()
                    .any(|r| r.kind == crate::config::WaylayKind::Prop);
                if let Some(es) = self.ebpf_state.as_ref() {
                    es.bpf.srv_clear();
                    for (i, r) in my
                        .iter()
                        .filter(|r| r.kind == crate::config::WaylayKind::Src)
                        .enumerate()
                    {
                        es.bpf.srv_rule(i, &r.from, &r.to);
                    }
                    es.bpf.srv_active(has_src);
                    if has_prop {
                        let prop_rules: Vec<(String, String)> = my
                            .iter()
                            .filter(|r| r.kind == crate::config::WaylayKind::Prop)
                            .map(|r| (r.from.clone(), r.to.clone()))
                            .collect();
                        crate::config::set_prop_rules(&prop_rules);
                    }
                    es.bpf.prop_file_apply(has_prop);
                }
                self.srv_active_cur = has_src;
                self.prop_active_cur = has_prop;
            }
        }
        let cpu_changed = crate::config::take_cpu_rules_changed();
        self.cfg = rw_read_ignore_poison(&CURRENT_CONFIG).clone();
        // 先重建 uid 表 (新加规则包的 uid 进 pkg_uid), 再重放/全量 ——
        // 顺序反了会把新规则包从 cpu_pkg_uids 过滤掉 (apply_config 不生效)
        if let Some(cfg) = self.cfg.as_ref() {
            rebuild_uid_if_needed(
                cpu_changed,
                cfg,
                &mut self.uid_map,
                &mut self.pkg_uid,
                &mut self.cpu_pkgs_set,
                &mut self.rfr_pkgs_set,
            );
        }
        apply_config(cpu_changed, self.cfg.as_deref(), &self.pkg_uid);
    }

    /// packages.list 变化 (安装/卸载/替换) → 整表重建 cpu uid 表。
    /// waylay 四功能统一包名 (规则不依赖 packages.list; on_fg 实时查包名) → 无需重建。
    fn rebuild_uid_tables(&mut self) {
        if let Some(cfg) = self.cfg.as_ref() {
            (self.uid_map, self.pkg_uid) = build_uid_tables(cfg);
        }
        /* 与 cpu 共用 packages.list 构建时机: waylay 规则应用 uid→包名缓存 (on_fg 查缓存) */
        crate::config::rebuild_pkg_by_uid();
    }

    /// 全量重放 (初始 / KPM 重连后): 对当前规则应用整表 apply_all_now
    fn apply_all(&self) {
        if let Some(cfg) = self.cfg.as_ref() {
            crate::cpu_affinity::apply_all_now(cpu_pkg_uids(cfg, &self.pkg_uid));
        }
    }

    /// binder 前台回调 (pid+uid): 查 uid 表分发 CPU (冷启动 ApplyPkg + pidfd watch)
    /// 与刷新率 (包名) —— 原 EV_FG 分支主体
    fn on_fg(&mut self, pid: i32, uid: i32) {
        // 前台包名 (查缓存 — 初始化 reload 已构建 uid→包名映射)
        let fg_pkg = crate::rw_read_ignore_poison(&crate::config::WAYLAY_PKG_BY_UID)
            .get(&uid)
            .cloned()
            .unwrap_or_default();
        self.last_fg_pkg = fg_pkg.clone();
        let my: Vec<crate::config::WaylayRule> = crate::rw_read_ignore_poison(
            &crate::config::WAYLAY_RULES_NEW,
        )
        .iter()
        .filter(|r| r.pkg == fg_pkg)
        .cloned()
        .collect();
        let active = !my.is_empty();
        // ---- 前台包名通知内核 (vfc 规则按包段执行; 空=仅全局) ----
        if let Some(es) = self.ebpf_state.as_ref() {
            es.bpf.vfc_fg(&fg_pkg);
        }
        // ---- src (系统服务伪装): 该包 src 规则 + 开关 ----
        if active != self.srv_active_cur {
            self.srv_active_cur = active;
            if let Some(es) = self.ebpf_state.as_ref() {
                if active {
                    es.bpf.srv_clear();
                    for (i, r) in my.iter().filter(|r| r.kind == crate::config::WaylayKind::Src).enumerate() {
                        es.bpf.srv_rule(i, &r.from, &r.to);
                    }
                }
                es.bpf.srv_active(active);
            }
        }
        // prop (系统属性伪装): 该包 prop 规则前台激活, 切走恢复 (用户态 tmpfs 写替换)
        let prop_rules: Vec<(String, String)> = my
            .iter()
            .filter(|r| r.kind == crate::config::WaylayKind::Prop)
            .map(|r| (r.from.clone(), r.to.clone()))
            .collect();
        let want_prop = !prop_rules.is_empty();
        if want_prop != self.prop_active_cur {
            self.prop_active_cur = want_prop;
            if let Some(es) = self.ebpf_state.as_ref() {
                if want_prop {
                    crate::config::set_prop_rules(&prop_rules);
                }
                es.bpf.prop_file_apply(want_prop);
            }
        }
        let Some(e) = self.uid_map.get(&uid) else { return };
        // CPU 规则: 冷热判断 (cpu_known 中 uid+pid 一致=热);
        // 冷时注册 pidfd 监听 (退出清理由 EV_EXIT_PID 驱动)
        if e.cpu && !crate::cpu_affinity::cpu_known_is_hot(uid, pid) {
            crate::event_probe::watch(pid);
            if let Some(tx) = crate::cpu_affinity::cpu_fg_tx() {
                let _ = tx.send(crate::cpu_affinity::CpuMsg::ApplyPkg(
                    pid, uid, e.pkg.clone(),
                ));
            }
        }
        // 刷新率: 命中 → 发包名给刷新率线程
        if e.rfr {
            crate::refresh::refresh_send_fg_pkg(e.pkg.clone());
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let prog_name = &args[0];

    // 参数解析先行，-v/-h/错误用法在设置加载前退出，不产生文件副作用
    let (mut cli_cfg, mut cli_cpuset, mut cli_web) = (None, None, false);

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-c" => {
                i += 1;
                if i < args.len() {
                    cli_cfg = Some(args[i].clone());
                } else {
                    eprintln!("错误: -c 需要指定配置文件路径");
                    process::exit(1);
                }
            }
            "-w" => {
                cli_web = true;
            }
            "-b" => {
                i += 1;
                if i < args.len() {
                    cli_cpuset = Some(args[i].clone());
                    if args[i].is_empty() || args[i].contains('/') {
                        eprintln!("无效的 cpuset 目录名: {}", args[i]);
                        eprintln!("目录名不能为空或包含路径分隔符");
                        process::exit(1);
                    }
                } else {
                    eprintln!("错误: -b 需要指定 cpuset 目录名");
                    process::exit(1);
                }
            }
            "-v" => {
                if crate::ebpf_mode::kpm_probe() {
                    println!("AppOpt 版本 {} KPM", env!("CARGO_PKG_VERSION"));
                } else {
                    println!("AppOpt 版本 {}", env!("CARGO_PKG_VERSION"));
                }
                process::exit(0);
            }
            "-h" => {
                print_help(prog_name);
                process::exit(0);
            }
            other => {
                eprintln!("未知选项: {}", other);
                print_help(prog_name);
                process::exit(1);
            }
        }
        i += 1;
    }

    // 应用设置 (AppOpt.json) 提前读取: 驱动模式需在 L1 ebpf_init spawn 前决定
    let st = settings_load(SETTINGS_FILE);
    let drive_mode = st.mode;
    crate::web::set_drive_mode(&drive_mode);
    // uclamp 支持探测 (webui 据此隐藏/显示 uclamp 配置)
    crate::web::init_uclamp_support();

    // ================= 初始化并发: 独立无依赖项并行 =================
    // 提前创建 fd (不依赖 settings; 供各独立线程使用)
    let mut fg_sv: [libc::c_int; 2] = [0, 0];
    let socket_ok = unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_DGRAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
            fg_sv.as_mut_ptr(),
        )
    } == 0;
    if socket_ok {
        let rcvbuf: libc::c_int = 256 * 1024;
        unsafe {
            libc::setsockopt(
                fg_sv[0],
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                &rcvbuf as *const libc::c_int as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
    }

    // T2: ebpf_init (按驱动模式尝试 KPM: userspace 直退 / auto 快速回退 / kpm 等待)
    let dm = drive_mode.clone();
    let ebpf_thread = std::thread::spawn(move || ebpf_init(dm));

    // T3: process_observer (binder 回调注册; 完成后线程退出)
    let obs_fd = fg_sv[1];
    let observer_thread = std::thread::spawn(move || {
        if socket_ok {
            crate::process_observer::init_observer(obs_fd);
        }
    });

    // T4: packages.list inotify (返回 fd; 完成后线程退出)
    let pkg_inotify_thread = std::thread::spawn(crate::config::init_pkg_inotify);

    // T5: dumpsys display 显示模式解析 (供 refresh_init; 完成后线程退出)
    let display_modes_thread = std::thread::spawn(crate::refresh::parse_display_modes);

    // 命令行参数优先覆盖设置 (settings_load 已在 L1 前完成)
    let config_file = cli_cfg.unwrap_or(st.config_file);
    let cpuset_name = cli_cpuset.unwrap_or(st.cpuset_name);
    let web_enable = cli_web || st.web_enable;

    // 先设置 cpuset 路径再初始化拓扑，init_cpu_topo 会创建 BASE_CPUSET 目录
    set_base_cpuset(&cpuset_name);
    let topo = init_cpu_topo();

    if fs::metadata(&config_file).is_err() {
        // 头注释两行; refresh_* 由设备可用刷新率解析后写入这两行下面
        let initial_content = "# 规则编写与使用说明请参考 http://AppOpt.suto.top\n# 刷新率字段与 CPU 规则共用此文件\n";
        let _ = fs::write(&config_file, initial_content);
    }
    {

        let mut guard = lock_ignore_poison(&CONFIG_FILE);
        *guard = config_file.clone();
    }

    let mut tmp_mtime: i64 = -1;
    let initial_config = match load_config(&config_file, &topo, &mut tmp_mtime) {
        Some(cfg) => cfg,
        None => {
            eprintln!("初始配置加载失败");
            process::exit(1);
        }
    };

    {
        let mut guard = rw_write_ignore_poison(&CURRENT_CONFIG);
        *guard = Some(Arc::new(initial_config));
    }

    init_inotify(&config_file);

    // waylay 规则: 启动/重载由 reload() 的 load_waylay_rules 加载 (WAYLAY_RULES_NEW)
    crate::ebpf_mode::ensure_prop_maps();

    if web_enable {
        web_start();
    }
    // 落盘当前设置 (含旧默认配置名迁移后的 config_file)，重启后保持一致
    settings_save();

    // ===== join 各独立线程 (事件循环/使用点前就绪) =====
    // 主循环共享状态: uid 表 / 规则包集合 / 当前配置 (ebpf_state 稍后 join 填入)
    let mut state = AppState::new();
    // ebpf_init 线程: KPM 加载+激活已并行完成, join 拿 EbpfState
    state.ebpf_state = ebpf_thread.join().ok().flatten();
    if state.ebpf_state.is_some() {
        crate::web::KPM_ACTIVE.store(true, Ordering::Relaxed);
    }

    // 用户态事件探测线程 (模块级 spawn_event_probe): 触摸活动 → EV_TOUCH, 主进程退出 → EV_EXIT_PID
    let mut touch_sv: [libc::c_int; 2] = [-1, -1];
    let mut exit_sv: [libc::c_int; 2] = [-1, -1];
    let (touch_ok, exit_ok) = spawn_event_probe(&mut touch_sv, &mut exit_sv);
    // T4: packages.list inotify fd
    let pkg_inotify_fd = pkg_inotify_thread.join().unwrap_or(-1);
    // T3: observer 注册完成
    let _ = observer_thread.join();
    let fg_recv_fd = fg_sv[0];
    let mut fg_buf = [0u8; 8];

    crate::cpu_affinity::start();

    // 刷新率控制模块，独立线程运行 (binder 回调经主线程 uid 表 → FgPkg 消息驱动)
    refresh::refresh_init(display_modes_thread);
    let _ = crate::web::START.get_or_init(|| std::time::Instant::now());

    // ================= 纯事件驱动主循环 =================
    // 事件源: KPM 事件唤醒 eventfd / inotify / 配置重载 eventfd / binder 前台回调
    //         / packages.list inotify (全模式)
    const EV_INOTIFY: u64 = 2;
    const EV_CONFIG: u64 = 4;
    const EV_FG: u64 = 6; // binder 前台回调 (pid+uid), 主线程分发
    const EV_PKG: u64 = 7; // packages.list inotify (安装/卸载/替换)
    const EV_TOUCH: u64 = 8; // 用户态 /dev/input 触摸/输入活动 (替代 4.19 内核 input hook)
    const EV_EXIT_PID: u64 = 9; // pidfd 进程退出监听 (全模式统一退出来源)

    let epfd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
    if epfd < 0 {
        eprintln!("初始化 epoll 失败");
        process::exit(1);
    }
    // KPM 事件唤醒 eventfd: reader 收到事件后写入, 主循环 epoll 唤醒
    // 配置重载 eventfd: web 端写配置/规则后由 config_reload_now 写入
    let config_wake_fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
    CONFIG_WAKE_FD.store(config_wake_fd, Ordering::Relaxed);
    epoll_add(epfd, config_wake_fd, EV_CONFIG);
    // inotify fd: 配置文件修改
    let inotify_fd = crate::config::INOTIFY_FD.load(Ordering::Acquire);
    epoll_add(epfd, inotify_fd, EV_INOTIFY);
    if fg_recv_fd > 0 {
        epoll_add(epfd, fg_recv_fd, EV_FG);
    }
    if touch_ok {
        epoll_add(epfd, touch_sv[0], EV_TOUCH);
    }
    if exit_ok {
        epoll_add(epfd, exit_sv[0], EV_EXIT_PID);
    }

    // packages.list inotify: 应用安装/卸载/替换 → 重建 uid 表 (fd 由并发 T4 线程建立;
    // pkglist_path 保留供 EV_PKG 重挂 watch 用)
    let pkglist_path = CString::new("/data/system/packages.list").unwrap_or_default();
    epoll_add(epfd, pkg_inotify_fd, EV_PKG);

    // 初始全量应用 (两种驱动模式都执行: KPM 事件驱动 / 纯用户态)
    state.apply_all();
    // 初始加载 waylay 配置 (WAYLAY_RULES_NEW + uid→包名缓存 + src/prop 规则; on_fg 直接查缓存)
    state.reload();

    let mut events = [unsafe { std::mem::zeroed::<libc::epoll_event>() }; 8];

    loop {
        let n = unsafe { libc::epoll_wait(epfd, events.as_mut_ptr(), 8, -1) };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            break;
        }
        if n == 0 {
            continue;
        }

        for i in 0..n as usize {
            let ev = events[i];
            match ev.u64 {
                EV_PKG => {
                    // packages.list 变化 (安装/卸载/替换) → 重建 uid 表
                    if pkg_inotify_fd > 0 {
                        let mut buf = [0u8; 4096];
                        let mut need_rewatch = false;
                        loop {
                            let len = unsafe {
                                libc::read(
                                    pkg_inotify_fd,
                                    buf.as_mut_ptr() as *mut libc::c_void,
                                    buf.len(),
                                )
                            };
                            if len <= 0 {
                                break;
                            }
                            let hdr = std::mem::size_of::<libc::inotify_event>();
                            let mut off = 0usize;
                            while off + hdr <= len as usize {
                                let ev = unsafe {
                                    &*(buf.as_ptr().add(off) as *const libc::inotify_event)
                                };
                                if ev.mask & (libc::IN_MOVE_SELF | libc::IN_DELETE_SELF) != 0 {
                                    need_rewatch = true;
                                }
                                off += hdr + ev.len as usize;
                            }
                        }
                        // atomic 替换 (rename) 后 inode 变化, 需重加 watch
                        if need_rewatch {
                            let wd = unsafe {
                                libc::inotify_add_watch(
                                    pkg_inotify_fd,
                                    pkglist_path.as_ptr(),
                                    libc::IN_CLOSE_WRITE
                                        | libc::IN_MOVED_TO
                                        | libc::IN_MOVE_SELF
                                        | libc::IN_DELETE_SELF,
                                )
                            };
                            if wd < 0 {
                                /* rewatch 失败: 下次事件再尝试 */
                            }
                        }
                        state.rebuild_uid_tables();
                    }
                }
                EV_FG => {
                    // binder 前台回调 (pid+uid): 主线程查两张 uid 表分发
                    if fg_recv_fd > 0 {
                        let nrecv = unsafe {
                            libc::recv(
                                fg_recv_fd,
                                fg_buf.as_mut_ptr() as *mut libc::c_void,
                                fg_buf.len(),
                                0,
                            )
                        };
                        if nrecv == 8 {
                            let pid = i32::from_ne_bytes([fg_buf[0], fg_buf[1], fg_buf[2], fg_buf[3]]);
                            let uid = i32::from_ne_bytes([fg_buf[4], fg_buf[5], fg_buf[6], fg_buf[7]]);
                            state.on_fg(pid, uid);
                        }
                    }
                }
                EV_TOUCH => {
                    // 用户态触摸/输入活动: 读走 1 字节通知 (只关心"有活动") → 重置刷新率空闲
                    if touch_ok && touch_sv[0] > 0 {
                        // event_probe 每次活动通知 1 字节; 读走即可 (只关心"有活动")
                        let mut tb = [0u8; 1];
                        let _ = unsafe {
                            libc::recv(
                                touch_sv[0],
                                tb.as_mut_ptr() as *mut libc::c_void,
                                1,
                                0,
                            )
                        };
                    }
                    crate::refresh::refresh_on_event(crate::refresh::EVENT_INPUT, 0);
                }
                EV_EXIT_PID => {
                    // 用户态进程退出: recv pid → 清理该 uid 身份
                    if exit_ok && exit_sv[0] > 0 {
                        let mut pb = [0u8; 4];
                        let n = unsafe {
                            libc::recv(exit_sv[0], pb.as_mut_ptr() as *mut libc::c_void, 4, 0)
                        };
                        if n == 4 {
                            let pid = i32::from_ne_bytes([pb[0], pb[1], pb[2], pb[3]]);
                            // 清身份 + 通知 CPU worker 清该 uid managed → 发布统计
                            // CPU 身份清理 (EvictUid → evict_uid 移除条目)
                            if let Some(uid) = crate::cpu_affinity::cpu_known_pid_to_uid(pid) {
                                if let Some(tx) = crate::cpu_affinity::cpu_fg_tx() {
                                    let _ = tx.send(crate::cpu_affinity::CpuMsg::EvictUid(uid));
                                }
                            }
                        }
                    }
                }
                EV_INOTIFY => {
                    // 配置变更 (inotify): 与 EV_CONFIG 共用 reload_config
                    if crate::config::inotify_drain() {
                        state.reload();
                    }
                }
                EV_CONFIG => {
                    read_eventfd(config_wake_fd);
                    // 配置变更 (eventfd 主动唤醒): 与 EV_INOTIFY 共用 state.reload()
                    state.reload();
                }
                _ => {}
            }
        }
    }

    unsafe { libc::close(epfd) };
}

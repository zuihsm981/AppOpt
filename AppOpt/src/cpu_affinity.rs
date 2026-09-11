//! CPU 亲和性模块（binder 前台回调触发, 无周期扫描）
//!
//! 设计:
//!   - 触发: IProcessObserver binder 前台回调 (主线程 EV_FG 接收 pid+uid); 主线程查
//!     cpu uid 表, 命中且冷启动时发 CpuMsg::ApplyPkg(pid, uid, pkg); ApplyAll = 启动/配置全量。
//!   - 归因: 包名由主线程 cpu uid 表提供 (随 CpuMsg 消息携带); 枚举按 uid 过滤
//!     /proc (Uid: 字段) → 该应用全部进程 (主进程 + pkg: 子进程共享同一 uid)。
//!   - 应用: 该 uid 全部进程的全部线程 (/proc/<pid>/task) → thread_affinity →
//!     applied_set + affinity_set。
//!   - 清理: 每次触发顺带删除已消失 tid 的 APPLIED 条目, 防止 kprobe 误抓
//!     被回收的 tid (tid 复用 → 错误覆盖新进程亲和性)。
//!   - 内核只保留: applied 表 (ctl0) + sched_setaffinity kprobe 强制 +
//!     input kprobe (刷新率)。进程事件探针对本模块无意义。
//!
//! 为什么按 uid: pid 归因对 zygote spawn 子进程 (pkg:child, 不同 tgid) 有结构性
//! 盲区; 同一应用的主进程与所有子进程共享 uid, binder 回调直接携带 uid, 一次
//! /proc 按 uid 过滤即完整覆盖, 无 pid 家族匹配/晚起子进程问题。

use std::collections::{HashMap, HashSet};
use std::ffi::CString;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::thread;
use std::time::Duration;

use crate::config::AppConfig;
use crate::cpuset::{CpuSet, CpuTopology};
use crate::ebpf_mode::KpmHandle;

/// 前台回调后延迟枚举时长: 冷启动子进程 (pkg:child) 常在回调后 0.5~2s 内 spawn,
/// 延迟后按 uid 枚举一次覆盖冷启动窗口 (主进程回调时已在, 无影响)。
/// 延迟值由 web 设置项「线程放置延迟」控制 (默认 2000ms)。
fn enum_delay() -> Duration {
    Duration::from_millis(crate::web::AFFINITY_DELAY_MS.load(Ordering::Relaxed))
}

/// CPU worker 消息
pub enum CpuMsg {
    /// 主线程判定冷启动后, 下发 (主 pid, uid, 包名) → 延迟按 uid 枚举应用
    ApplyPkg(i32, i32, String),
    /// 规则应用主进程退出 (EXIT 事件): 按 uid 清除该应用在 managed 的全部条目
    /// → web 命中归零 (按 uid 整清, 不依赖主线程 tid 是否在 managed)
    EvictUid(i32),
    /// 全量应用 (启动 / 配置变更)
    ApplyAll,
    /// 单包重放 (整包规则编辑保存): 只对该包枚举 pid + 重设亲和, 不做全量
    ApplyPkgByName(String),
    /// 单线程重放 (单线程规则编辑保存): 只对该包中 comm==thread 的 tid 设亲和
    ApplyThread(String, String),
}

/// 全局投递通道: 主线程 (main EV_FG) 转发前台回调 → CpuMsg 消息
static CPU_FG_TX: OnceLock<Mutex<mpsc::Sender<CpuMsg>>> = OnceLock::new();

/// 冷热身份: uid → (前台主 pid, 该 uid 全部 pid 列表); 主线程判冷热, CPU 线程回写
/// 冷热身份: uid -> (前台主 pid, 该 uid 全部 pid 列表); 主线程每次 binder 前台
/// 回调都读 (高频只读) -> RwLock, 仅冷启动/EXIT 时写
pub static CPU_KNOWN: std::sync::LazyLock<RwLock<HashMap<i32, (i32, Vec<i32>)>>> =
    std::sync::LazyLock::new(|| RwLock::new(HashMap::new()));

/// proc 快照: uid → 该 uid 全部 pid 列表; 冷启动先清除再重建
pub static PROC_SNAPSHOT: std::sync::LazyLock<RwLock<HashMap<i32, Vec<i32>>>> =
    std::sync::LazyLock::new(|| RwLock::new(HashMap::new()));

/// 冷热判断: cpu_known 中该 uid 的 pid 与回调 pid 一致 → 热
pub fn cpu_known_is_hot(uid: i32, pid: i32) -> bool {
    crate::rw_read_ignore_poison(&CPU_KNOWN)
        .get(&uid)
        .is_some_and(|(p, _)| *p == pid)
}

/// 清除某 uid 的 pid 列表与 cpu_known 身份
pub fn cpu_known_evict(uid: i32) {
    crate::rw_write_ignore_poison(&PROC_SNAPSHOT).remove(&uid);
    crate::rw_write_ignore_poison(&CPU_KNOWN).remove(&uid);
}

/// 进程退出 (EXIT 事件, 仅主线程 tid==pid 时调用): 该 pid 为主进程则清除其
/// uid 的 pid 列表与 cpu_known 身份并返回该 uid; 子进程/线程退出不匹配主 pid,
/// 幂等跳过返回 None。调用方可用返回值按 uid 通知 CPU worker 清理 managed。
pub fn cpu_known_evict_by_pid(pid: i32) -> Option<i32> {
    if pid <= 0 {
        return None;
    }
    let uid = {
        let k = crate::rw_read_ignore_poison(&CPU_KNOWN);
        k.iter().find_map(|(u, (mp, _))| (*mp == pid).then_some(*u))
    };
    if let Some(u) = uid {
        cpu_known_evict(u);
        Some(u)
    } else {
        None
    }
}

/// KPM 模式 web 统计: (绑定线程数, 命中包名列表); 由 worker 在每次应用后发布
static CPU_STATS: RwLock<(usize, Vec<String>)> = RwLock::new((0, Vec::new()));

/// 读取 KPM 模式统计: (线程数, 命中包名数, 命中包名列表)
pub fn cpu_stats() -> (usize, usize, Vec<String>) {
    let g = crate::rw_read_ignore_poison(&CPU_STATS);
    (g.0, g.1.len(), g.1.clone())
}


pub fn cpu_fg_tx() -> Option<mpsc::Sender<CpuMsg>> {
    CPU_FG_TX
        .get()
        .and_then(|m| m.lock().ok())
        .map(|g| g.clone())
}

/// 请求一次全量应用 (启动 / 配置变更), 不阻塞
pub fn apply_all_now() {
    if let Some(tx) = cpu_fg_tx() {
        let _ = tx.send(CpuMsg::ApplyAll);
    }
}

/// CPU 亲和性执行器 (worker 线程独占)
pub struct CpuAffinity {
    bpf: KpmHandle,
    /// 已管理线程 tid → 包名 (用于清理已退出线程)
    managed: HashMap<i32, String>,
    /// 已应用应用的 uid → 包名 (退出时按 uid 整清 managed)
    uid_pkg: HashMap<i32, String>,
    /// 初始化时 /proc 全部 pid 快照: 其余应用枚举时跳过 (含 launcher3/systemui)
    init_pids: HashSet<i32>,
    /// 额外标记 launcher3/systemui 的 pid 目录: 其规则直接使用, 免扫描/读 cmdline
    marked: HashMap<String, Vec<i32>>,
    /// 包名 → uid 反向缓存 (重放免扫 /proc; Android uid 固定, 缓存稳定)
    pkg_uid_cache: HashMap<String, i32>,
    /// 合并 CPU 集合 bits → cpuset 目录名 缓存 (相同集合只 ensure 一次, 避免每线程重复建目录)
    cpuset_cache: HashMap<u64, String>,
}

impl CpuAffinity {
    /// init_pids: main.rs 在 AppOpt 初始化时构建的 /proc pid 快照;
    /// marked: 其中 launcher3/systemui 的 pid 标记
    pub fn new(init_pids: HashSet<i32>, marked: HashMap<String, Vec<i32>>) -> Self {
        Self {
            bpf: KpmHandle::new(),
            managed: HashMap::new(),
            uid_pkg: HashMap::new(),
            init_pids,
            marked,
            pkg_uid_cache: HashMap::new(),
            cpuset_cache: HashMap::new(),
        }
    }

    /// 发布当前 managed 统计到 CPU_STATS (web 命中应用/绑定线程在 KPM 模式显示用)
    fn publish_stats(&self) {
        let mut pkgs: Vec<String> = self.managed.values().cloned().collect();
        pkgs.sort_unstable();
        pkgs.dedup();
        *crate::rw_write_ignore_poison(&CPU_STATS) = (self.managed.len(), pkgs);
    }

    /// 按 uid 枚举该应用全部进程 (主 + pkg: 子进程同 uid) → 应用全部线程。
    /// uid 即应用身份: 精确、无 cmdline 归因竞态、多用户下不误捞其他实例。
    /// 包名 → uid (单包重放用): 先查反向缓存, 未命中再走标记/扫描并回填
    fn pkg_to_uid(&mut self, pkg: &str) -> Option<i32> {
        if let Some(&u) = self.pkg_uid_cache.get(pkg) {
            return Some(u);
        }
        if let Some(pids) = self.marked.get(pkg) {
            if let Some(&p) = pids.first() {
                if let Some(u) = proc_uid(p) {
                    self.pkg_uid_cache.insert(pkg.to_string(), u);
                    return Some(u);
                }
            }
        }
        if let Ok(entries) = std::fs::read_dir("/proc") {
            for e in entries.flatten() {
                let Ok(p) = e.file_name().to_string_lossy().parse::<i32>() else { continue };
                if p <= 0 || self.init_pids.contains(&p) {
                    continue;
                }
                if crate::apply_affinity::read_cmdline(p).as_deref() == Some(pkg) {
                    if let Some(u) = proc_uid(p) {
                        self.pkg_uid_cache.insert(pkg.to_string(), u);
                        return Some(u);
                    }
                }
            }
        }
        None
    }

    fn on_uid(&mut self, uid: i32, pkg: &str, cfg: &AppConfig) -> Vec<i32> {
        if uid <= 0 {
            return Vec::new();
        }
        // launcher3/systemui 的规则: 直接用标记目录 (免 /proc 扫描)
        if let Some(pids) = self.marked.get(pkg).cloned() {
            self.apply_tids(&pids, pkg, cfg);
            return pids;
        }
        // 跳过 init_pids (含 launcher3/systemui), 只处理初始化后新出现的 pid, 按 uid 过滤
        let mut pids: Vec<i32> = Vec::new();
        if let Ok(entries) = std::fs::read_dir("/proc") {
            for e in entries.flatten() {
                let Ok(p) = e.file_name().to_string_lossy().parse::<i32>() else { continue };
                if p <= 0 || self.init_pids.contains(&p) {
                    continue;
                }
                if proc_uid(p) == Some(uid) {
                    pids.push(p);
                }
            }
        }
        self.apply_tids(&pids, pkg, cfg);
        pids
    }

    /// 全量应用 (启动 / 配置变更), 非周期; 单遍 /proc 收集 pkg→pids 后逐包
    /// apply_tids (O(P), 避免 O(P²): 每包一次全表重扫); 不做 cleanup (触发时清理)
    pub fn apply_all(&mut self, cfg: &AppConfig) -> usize {
        let mut by_pkg: HashMap<String, Vec<i32>> = HashMap::new();
        // launcher3/systemui 标记 pid 直接按标记归属 (免 cmdline 读)
        for (pkg, pids) in &self.marked {
            if cfg.target_pkgs.contains(pkg) {
                by_pkg.entry(pkg.clone()).or_default().extend(pids.iter().copied());
            }
        }
        let marked_pid_set: HashSet<i32> = self.marked.values().flatten().copied().collect();
        // 其余 pid 全量扫描归因 (标记 pid 已在上面处理, 跳过免重复读 cmdline)
        if let Ok(entries) = std::fs::read_dir("/proc") {
            for e in entries.flatten() {
                let Ok(pid) = e.file_name().to_string_lossy().parse::<i32>() else { continue };
                if pid <= 0 || marked_pid_set.contains(&pid) {
                    continue;
                }
                if let Some(pkg) = resolve_pkg(pid, cfg) {
                    by_pkg.entry(pkg).or_default().push(pid);
                }
            }
        }
        let pkgs: Vec<String> = by_pkg.keys().cloned().collect();
        for pkg in &pkgs {
            if let Some(pids) = by_pkg.get(pkg) {
                self.apply_tids(pids, pkg, cfg);
            }
        }
        by_pkg.len()
    }

    /// 应用一个包的全部进程 (主进程 + pkg: 子进程) 的全部线程
    /// 对给定进程集合的全部线程套用规则并应用
    fn apply_tids(&mut self, pids: &[i32], pkg: &str, cfg: &AppConfig) {
        let has_thread_rules = cfg.has_thread_rules.contains(pkg);
        // 批量 applied_set: 相同 bits 的 tid 聚合, 每个 bits 一次 supercall
        let mut set: HashMap<u64, Vec<i32>> = HashMap::new();
        let mut aff: Vec<(i32, CpuSet, String)> = Vec::new();
        for p in pids {
            let Some(tids) = crate::apply_affinity::task_tids(*p) else { continue };
            for tid in tids {
                let tname = if has_thread_rules {
                    crate::apply_affinity::tid_comm(tid).unwrap_or_default()
                } else {
                    String::new()
                };
                let Some(rule) = crate::rule_match::thread_affinity(pkg, &tname, cfg) else {
                    continue;
                };
                let bits = rule.cpus.bits[0];
                set.entry(bits).or_default().push(tid);
                // cpuset 目录: 配置自带优先, 否则按合并 CPU 集合缓存 ensure
                let cpuset_dir = if rule.cpuset_dir.is_empty() {
                    self.cpuset_dir_for(&rule.cpus, &cfg.topo)
                } else {
                    rule.cpuset_dir.clone()
                };
                aff.push((tid, rule.cpus, cpuset_dir));
                self.managed.insert(tid, pkg.to_string());
            }
        }
        // 批量写内核 APPLIED 表 (每 bits 一次 supercall, 替代逐 tid ctl0)
        for (bits, tids) in &set {
            self.bpf.applied_set_many(*bits, tids);
        }
        // 逐个设置 cpuset (cpuset_enabled) + sched_setaffinity (必要的每线程 syscall)
        for (tid, cpus, cpuset_dir) in aff {
            let _ = crate::apply_affinity::affinity_set(tid, &cpus, &cpuset_dir, &cfg.topo);
        }
        self.publish_stats();
    }

    /// cpuset 目录缓存: 相同 CPU 集合 (bits) 只 ensure 一次, 其余线程直接复用
    fn cpuset_dir_for(&mut self, cpus: &CpuSet, topo: &CpuTopology) -> String {
        let bits = cpus.bits[0];
        if let Some(d) = self.cpuset_cache.get(&bits) {
            return d.clone();
        }
        let d = crate::cpuset::ensure_cpuset_dir(cpus, topo);
        self.cpuset_cache.insert(bits, d.clone());
        d
    }

    /// 常驻线程入口 (纯事件驱动, 无重试/无周期)
    pub fn run(mut self, rx: mpsc::Receiver<CpuMsg>, stop: Arc<AtomicBool>) {
        let name = CString::new("CpuAffinity").unwrap();
        unsafe {
            libc::pthread_setname_np(libc::pthread_self(), name.as_ptr());
        }
        while !stop.load(Ordering::Relaxed) {
            match rx.recv() {
                Ok(CpuMsg::ApplyAll) => {
                    let cfg = crate::rw_read_ignore_poison(&crate::config::CURRENT_CONFIG).clone();
                    if let Some(cfg) = cfg {
                        self.apply_all(&cfg);
                    }
                }
                Ok(CpuMsg::ApplyPkg(pid, uid, pkg)) => {
                    // 冷启动: 先占位 cpu_known (uid+主 pid), 延迟 2s 覆盖子进程窗口
                    crate::rw_write_ignore_poison(&CPU_KNOWN).insert(uid, (pid, Vec::new()));
                    thread::sleep(enum_delay());
                    let cfg = crate::rw_read_ignore_poison(&crate::config::CURRENT_CONFIG).clone();
                    if let Some(cfg) = cfg {
                        let pids = self.on_uid(uid, &pkg, &cfg);
                        // 设置亲和性后: 该 uid 主进程+全部子进程 pid 列表写入
                        // cpu_known 与 proc 快照 (供后续冷热判断/统计)
                        crate::rw_write_ignore_poison(&CPU_KNOWN).insert(uid, (pid, pids.clone()));
                        crate::rw_write_ignore_poison(&PROC_SNAPSHOT).insert(uid, pids);
                        // 标记内核主进程 tgid: 退出探针只对该主进程发布 EXIT
                        self.bpf.applied_set_main(pid);
                        // 记录 uid→pkg + pkg→uid (反向缓存: 重放免扫 /proc)
                        self.uid_pkg.insert(uid, pkg.clone());
                        self.pkg_uid_cache.insert(pkg.clone(), uid);
                    }
                }
                Ok(CpuMsg::ApplyPkgByName(pkg)) => {
                    // 单包重放: 找该包当前 uid → 枚举该 uid 全部 pid → 重设亲和 + 回写身份
                    let cfg = crate::rw_read_ignore_poison(&crate::config::CURRENT_CONFIG).clone();
                    if let (Some(cfg), Some(uid)) = (cfg, self.pkg_to_uid(&pkg)) {
                        let pids = self.on_uid(uid, &pkg, &cfg);
                        if let Some(&main_pid) = pids.first() {
                            crate::rw_write_ignore_poison(&CPU_KNOWN)
                                .insert(uid, (main_pid, pids.clone()));
                        }
                        crate::rw_write_ignore_poison(&PROC_SNAPSHOT).insert(uid, pids);
                        self.uid_pkg.insert(uid, pkg.clone());
                        self.pkg_uid_cache.insert(pkg.clone(), uid);
                    }
                }
                Ok(CpuMsg::ApplyThread(pkg, thread)) => {
                    // 单线程重放: 找该包 uid → 枚举该 uid 各 pid 的 task, 收集
                    // comm==thread 的 tid → 只对这些 tid 应用亲和 (apply_tids 按规则匹配)
                    let cfg = crate::rw_read_ignore_poison(&crate::config::CURRENT_CONFIG).clone();
                    if let (Some(cfg), Some(uid)) = (cfg, self.pkg_to_uid(&pkg)) {
                        let mut tids: Vec<i32> = Vec::new();
                        if let Ok(entries) = std::fs::read_dir("/proc") {
                            for e in entries.flatten() {
                                let Ok(p) = e.file_name().to_string_lossy().parse::<i32>() else { continue };
                                if p <= 0 || self.init_pids.contains(&p) {
                                    continue;
                                }
                                if proc_uid(p) != Some(uid) {
                                    continue;
                                }
                                for t in crate::apply_affinity::task_tids(p).unwrap_or_default() {
                                    if crate::apply_affinity::tid_comm(t).as_deref()
                                        == Some(thread.as_str())
                                    {
                                        tids.push(t);
                                    }
                                }
                            }
                        }
                        if !tids.is_empty() {
                            self.apply_tids(&tids, &pkg, &cfg);
                        }
                    }
                }
                Ok(CpuMsg::EvictUid(uid)) => {
                    // 主进程退出 (EXIT 事件): 按 uid 找到该应用包名, 清除 managed 中
                    // 全部线程条目 → 立即发布统计 (web 命中归零)。不依赖主线程 tid
                    // 是否在 managed (线程规则类应用主线程可能未被管理)。
                    // 内核侧已在 exit 探针逐 tid 摘 APPLIED。
                    let pkg = self.uid_pkg.remove(&uid);
                    if let Some(pkg) = pkg {
                        self.managed.retain(|_, p| p != &pkg);
                    }
                    self.publish_stats();
                }
                Err(mpsc::RecvError) => break,
            }
        }
        self.bpf.applied_clear();
    }
}

/// 启动 CPU worker 线程 (KPM 模式下调用一次); 返回 false 表示模块不可用
pub fn start(init_pids: HashSet<i32>, marked: HashMap<String, Vec<i32>>) -> bool {
    if CPU_FG_TX.get().is_some() {
        return true;
    }
    // 用户态与 KPM 模式统一启动 CPU worker: 身份记录/进程枚举/亲和性施加全部经
    // ApplyPkg 消息驱动; KPM 不可用时 bpf ctl0 调用仅失败无副作用 (用户态由
    // apply_affinity::affinity_set 真正施加 sched_setaffinity)。
    let (tx, rx) = mpsc::channel::<CpuMsg>();
    let _ = CPU_FG_TX.set(Mutex::new(tx));
    // init_pids/marked 由 main.rs 在 AppOpt 初始化时构建传入
    let cpu = CpuAffinity::new(init_pids, marked);
    thread::spawn(move || cpu.run(rx, Arc::new(AtomicBool::new(false))));
    true
}

/// 从 init_pids 快照中额外标记 launcher3/systemui 的 pid 目录:
///   - 其余应用枚举时跳过它们 (它们在 init_pids 内), 避免读其目录;
///   - launcher3/systemui 自身规则直接使用标记目录, 免扫描。
pub(crate) fn classify_marked_pids(init_pids: &HashSet<i32>) -> HashMap<String, Vec<i32>> {
    let mut m: HashMap<String, Vec<i32>> = HashMap::new();
    for &p in init_pids {
        if let Some(cmd) = crate::apply_affinity::read_cmdline(p) {
            if same_pkg(&cmd, crate::config::DEFAULT_REFRESH_PACKAGE) {
                m.entry(crate::config::DEFAULT_REFRESH_PACKAGE.to_string())
                    .or_default()
                    .push(p);
            } else if same_pkg(&cmd, "com.android.systemui") {
                m.entry("com.android.systemui".to_string()).or_default().push(p);
            }
        }
    }
    m
}

/// 缓存初始化时 /proc 下全部 pid (AppOpt 启动快照): 由 main.rs 在初始化时调用,
/// 传给 CPU worker 用于枚举跳过 (系统进程/已运行应用), 只处理之后新出现的 pid
/// 快照只记低位稳定 pid (≤6100): 应用高位 pid (6000+) 不写入快照,
/// 避免应用 pid 复用撞上快照旧号被 on_uid 误跳过 (首次冷启动失效根因)。
/// 用过滤而非 break: /proc 枚举顺序不保证升序, 过滤同样不写高位且更安全。
const INIT_PIDS_MAX_PID: i32 = 6100;

pub(crate) fn proc_pid_set() -> HashSet<i32> {
    let mut set = HashSet::new();
    if let Ok(entries) = std::fs::read_dir("/proc") {
        for e in entries.flatten() {
            if let Ok(p) = e.file_name().to_string_lossy().parse::<i32>() {
                if p > INIT_PIDS_MAX_PID {
                    continue; // 高位 (应用区) 不记入快照
                }
                if p > 0 {
                    set.insert(p);
                }
            }
        }
    }
    set
}

/// /proc/<pid>/status 的有效 uid (Uid: 首值); 按 uid 枚举用
fn proc_uid(pid: i32) -> Option<i32> {
    let status = std::fs::read_to_string(format!("/proc/{}/status", pid)).ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            return rest.split_whitespace().next()?.parse().ok();
        }
    }
    None
}

/// cmdline 归因: 目标包(精确) 或 目标包:子进程
fn resolve_pkg(pid: i32, cfg: &AppConfig) -> Option<String> {
    let cmd = crate::apply_affinity::read_cmdline(pid)?;
    cfg.target_pkgs
        .iter()
        .find(|pkg| same_pkg(&cmd, pkg))
        .cloned()
}

/// cmdline 是否属于该包 (等于 或 pkg: 子进程)
fn same_pkg(cmd: &str, pkg: &str) -> bool {
    cmd == pkg || cmd.strip_prefix(pkg).is_some_and(|r| r.starts_with(':'))
}
//! CPU 亲和性模块（binder 前台回调触发, 无周期扫描）
//!
//! 设计:
//!   - 触发: IProcessObserver binder 前台回调 (主线程 EV_FG 接收 pid+uid); 主线程查
//!     cpu uid 表, 命中且冷启动时发 CpuMsg::ApplyPkg(uid, pkg); ApplyAll = 启动/配置全量。
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
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::Duration;

use crate::config::AppConfig;
use crate::ebpf_mode::KpmHandle;

/// 前台回调后延迟枚举时长: 冷启动子进程 (pkg:child) 常在回调后 0.5~2s 内 spawn,
/// 延迟 2s 后按 uid 枚举一次覆盖冷启动窗口 (主进程回调时已在, 无影响)。
const ENUM_DELAY: Duration = Duration::from_secs(2);

/// CPU worker 消息
pub enum CpuMsg {
    /// 主线程判定命中 CPU 表且为冷启动后, 下发 (uid, 包名) → 延迟按 uid 枚举应用
    ApplyPkg(i32, String),
    /// 全量应用 (启动 / 配置变更)
    ApplyAll,
}

/// 全局投递通道: 主线程 (main EV_FG) 转发前台回调 → CpuMsg 消息
static CPU_FG_TX: OnceLock<Mutex<mpsc::Sender<CpuMsg>>> = OnceLock::new();

/// KPM 模式 web 统计: (绑定线程数, 命中包名列表); 由 worker 在每次应用后发布
static CPU_STATS: Mutex<(usize, Vec<String>)> = Mutex::new((0, Vec::new()));

/// 读取 KPM 模式统计: (线程数, 命中包名数, 命中包名列表)
pub fn cpu_stats() -> (usize, usize, Vec<String>) {
    let g = CPU_STATS.lock().unwrap();
    (g.0, g.1.len(), g.1.clone())
}

/// 发布当前 managed 统计 (worker 调用)
fn publish_stats(&self) {
    let mut pkgs: Vec<String> = self.managed.values().cloned().collect();
    pkgs.sort_unstable();
    pkgs.dedup();
    *CPU_STATS.lock().unwrap() = (self.managed.len(), pkgs);
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
    /// 初始化时 /proc 全部 pid 快照: 其余应用枚举时跳过 (含 launcher3/systemui)
    init_pids: HashSet<i32>,
    /// 额外标记 launcher3/systemui 的 pid 目录: 其规则直接使用, 免扫描/读 cmdline
    marked: HashMap<String, Vec<i32>>,
}

impl CpuAffinity {
    /// init_pids: main.rs 在 AppOpt 初始化时构建的 /proc pid 快照;
    /// marked: 其中 launcher3/systemui 的 pid 标记
    pub fn new(init_pids: HashSet<i32>, marked: HashMap<String, Vec<i32>>) -> Self {
        Self {
            bpf: KpmHandle::new(),
            managed: HashMap::new(),
            init_pids,
            marked,
        }
    }

    /// 按 uid 枚举该应用全部进程 (主 + pkg: 子进程同 uid) → 应用全部线程。
    /// uid 即应用身份: 精确、无 cmdline 归因竞态、多用户下不误捞其他实例。
    fn on_uid(&mut self, uid: i32, pkg: &str, cfg: &AppConfig) {
        if uid <= 0 {
            return;
        }
        // launcher3/systemui 的规则: 直接用标记目录 (免 /proc 扫描)
        if let Some(pids) = self.marked.get(pkg).cloned() {
            self.apply_tids(&pids, pkg, cfg);
            return;
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
                self.bpf.applied_set(tid, rule.cpus.bits[0]);
                let _ = crate::apply_affinity::affinity_set(
                    tid,
                    &rule.cpus,
                    &rule.cpuset_dir,
                    &cfg.topo,
                    rule.move_cpuset,
                );
                self.managed.insert(tid, pkg.to_string());
            }
        }
        self.publish_stats();
    }

    /// 删除已消失线程的 APPLIED 条目 (防 tid 回收后 kprobe 误抓)
    fn cleanup_dead(&mut self) {
        let dead: Vec<i32> = self
            .managed
            .keys()
            .copied()
            .filter(|t| crate::apply_affinity::tid_comm(*t).is_none())
            .collect();
        for t in dead {
            self.bpf.applied_del(t);
            self.managed.remove(&t);
        }
        self.publish_stats();
    }

    /// 常驻线程入口 (纯事件驱动, 无重试/无周期)
    pub fn run(mut self, rx: mpsc::Receiver<CpuMsg>, stop: Arc<AtomicBool>) {
        let name = CString::new("CpuAffinity").unwrap();
        unsafe {
            libc::pthread_setname_np(libc::pthread_self(), name.as_ptr());
        }
        while !stop.load(Ordering::Relaxed) {
            match rx.recv_timeout(Duration::from_millis(300)) {
                Ok(CpuMsg::ApplyAll) => {
                    let cfg = crate::lock_ignore_poison(&crate::config::CURRENT_CONFIG).clone();
                    if let Some(cfg) = cfg {
                        self.apply_all(&cfg);
                    }
                }
                Ok(CpuMsg::ApplyPkg(uid, pkg)) => {
                    // 冷启动: 延迟 2s 覆盖子进程窗口后按 uid 枚举 (主+子进程同 uid,
                    // 精确且避免 cmdline 归因竞态; 不误捞其他用户同包名实例)
                    thread::sleep(ENUM_DELAY);
                    let cfg = crate::lock_ignore_poison(&crate::config::CURRENT_CONFIG).clone();
                    if let Some(cfg) = cfg {
                        self.on_uid(uid, &pkg, &cfg);
                    }
                    // 触发枚举时清理: 删已消失 tid 的 APPLIED 条目, 防 tid 回收后 kprobe 误抓
                    self.cleanup_dead();
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
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
    // 校验 KPM 可 ping
    let probe = KpmHandle::new();
    if !probe.verify_loaded() {
        return false;
    }
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
pub(crate) fn proc_pid_set() -> HashSet<i32> {
    let mut set = HashSet::new();
    if let Ok(entries) = std::fs::read_dir("/proc") {
        for e in entries.flatten() {
            if let Ok(p) = e.file_name().to_string_lossy().parse::<i32>() {
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
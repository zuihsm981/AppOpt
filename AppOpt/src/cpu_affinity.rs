//! CPU 亲和性模块（binder 前台回调触发, 无周期扫描）
//!
//! 设计:
//!   - 触发: IProcessObserver binder 前台回调 (主线程 EV_FG 接收 pid+uid); 主线程查
//!     cpu uid 表, 命中且冷启动时发 CpuMsg::ApplyPkg(pid, uid, pkg); ApplyAll = 启动/配置全量。
//!   - 归因: 包名由主线程 cpu uid 表提供 (随 CpuMsg 消息携带); 按 uid 读
//!     /sys/fs/cgroup/apps/uid_<uid>/ 下 pid_* 目录 (Android cgroup apps 布局,
//!     精确 O(该 uid 进程数), 含主进程与全部子进程; 布局缺失视为未运行)。
//!   - 应用: 该 uid 全部进程的全部线程 (/proc/<pid>/task) → thread_affinity →
//!     applied_set + affinity_set。
//!   - 清理: APPLIED 条目由进程退出清理 (pidfd 事件 → EvictUid → 按 uid 摘除,
//!     防 tid 复用被 kprobe 误抓/错误覆盖新进程亲和性)。
//!   - 内核只保留: applied 表 (ctl0) + sched_setaffinity kprobe 强制;
//!     input 检测已统一用户态 eventX (内核 input kprobe 不再依赖)。
//!     进程事件探针对本模块无意义。
//!
//! 为什么按 uid + cgroup: zygote spawn 子进程 (pkg:child, 不同 tgid) 与主进程共享
//! uid; /sys/fs/cgroup/apps/uid_<uid>/ 目录按 uid 归属全部进程 (主+子), 直接读 pid_*
//! 即完整覆盖, 无 pid 家族匹配/晚起子进程问题。

use std::collections::{HashMap, HashSet};
use std::ffi::CString;
use std::sync::atomic::Ordering;
use std::sync::mpsc;
use std::sync::{Mutex, OnceLock, RwLock};
use std::thread;
use std::time::Duration;

use crate::config::AppConfig;
use crate::cpuset::{CpuSet, CpuTopology};
use crate::ebpf_mode::KpmHandle;

/// 前台回调后延迟枚举时长: 冷启动子进程 (pkg:child) 常在回调后 0.5~2s 内 spawn,
/// 延迟后 cgroup 取一遍该 uid 全部 pid 覆盖冷启动窗口 (主进程回调时已在, 无影响)。
/// 延迟值由 web 设置项「线程放置延迟」控制 (默认 2000ms)。
fn enum_delay() -> Duration {
    Duration::from_millis(crate::web::AFFINITY_DELAY_MS.load(Ordering::Relaxed))
}

/// CPU worker 消息
pub enum CpuMsg {
    /// 主线程判定冷启动后, 下发 (主 pid, uid, 包名) → 延迟按 uid 取该应用全部进程
    ApplyPkg(i32, i32, String),
    /// 规则应用主进程退出 (pidfd 退出事件): 按 uid 清除该应用在 managed 的全部条目
    /// → web 命中归零 (按 uid 整清, 不依赖主线程 tid 是否在 managed)
    EvictUid(i32),
    /// 全量应用 (启动 / 配置变更): 携带 规则包→uid 表 (main 由 uid 表供给, worker 不读文件)
    ApplyAll(HashMap<String, i32>),
    /// web 轮询请求刷新 CPU 统计快照 (仅在轮询时发布, 避免每次事件都构建)
    PublishStats,
    /// 整包重放 (整包规则编辑保存): 主线程反查 uid 后下发, worker 仅对已接管应用重放
    ApplyPkgByUid(i32, String),
    /// 单线程重放 (单线程规则编辑保存): 只对该包中 comm==thread 的 tid 设亲和
    ApplyThreadByUid(i32, String, String),
}

/// 全局投递通道: 主线程 (main EV_FG) 转发前台回调 → CpuMsg 消息
static CPU_FG_TX: OnceLock<Mutex<mpsc::Sender<CpuMsg>>> = OnceLock::new();

/// 冷热身份: uid -> (前台主 pid, 该 uid 全部 pid 列表); 主线程每次 binder 前台
/// 回调都读 (高频只读) -> RwLock, 仅冷启动/退出时写
pub static CPU_KNOWN: std::sync::LazyLock<RwLock<HashMap<i32, (i32, Vec<i32>)>>> =
    std::sync::LazyLock::new(|| RwLock::new(HashMap::new()));

/// 冷热判断: cpu_known 中该 uid 的 pid 与回调 pid 一致 → 热
pub fn cpu_known_is_hot(uid: i32, pid: i32) -> bool {
    crate::rw_read_ignore_poison(&CPU_KNOWN)
        .get(&uid)
        .is_some_and(|(p, _)| *p == pid)
}
/// 按主 pid 反查 uid (退出事件路径用: 反查后发 EvictUid, 身份清理统一由
/// CPU worker 的 evict_uid 完成, 避免主线程/worker 双重清理)
pub fn cpu_known_pid_to_uid(pid: i32) -> Option<i32> {
    if pid <= 0 {
        return None;
    }
    crate::rw_read_ignore_poison(&CPU_KNOWN)
        .iter()
        .find_map(|(u, (mp, _))| (*mp == pid).then_some(*u))
}

/// KPM 模式 web 统计: (绑定线程数, 命中包名列表); 由 worker 在每次应用后发布
static CPU_STATS: RwLock<(usize, Vec<String>)> = RwLock::new((0, Vec::new()));

/// 读取 KPM 模式统计: (线程数, 命中包名数, 命中包名列表)
pub fn cpu_stats() -> (usize, usize, Vec<String>) {
    // 请求 worker 发布最新统计快照 (web 轮询触发; 返回当前快照, 下一次轮询读到最新)
    if let Some(tx) = cpu_fg_tx() {
        let _ = tx.send(CpuMsg::PublishStats);
    }
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
pub fn apply_all_now(pkg_uids: HashMap<String, i32>) {
    if let Some(tx) = cpu_fg_tx() {
        let _ = tx.send(CpuMsg::ApplyAll(pkg_uids));
    }
}

/// 延迟放置任务 (冷启动 ApplyPkg 登记, 到期应用)
struct PendingTask {
    due: std::time::Instant,
    pid: i32,
    uid: i32,
    pkg: String,
}

/// CPU 亲和性执行器 (worker 线程独占)
pub struct CpuAffinity {
    bpf: KpmHandle,
    /// 已管理线程 tid → 包名 (用于清理已退出线程)
    /// 已应用包 → 绑定 tid 集合 (退出按 uid 反查 pkg 后 O(1) 整清)
    managed: HashMap<String, HashSet<i32>>,
    /// 已应用应用的 uid → 包名 (退出时按 uid 反查 pkg 清 managed)
    uid_pkg: HashMap<i32, String>,
    /// 合并 CPU 集合 bits → cpuset 目录名 缓存 (相同集合只 ensure 一次, 避免每线程重复建目录)
    cpuset_cache: HashMap<u64, String>,
    /// 延迟放置任务队列 (异步): 冷启动 ApplyPkg 登记, 到期应用;
    /// EvictUid/ApplyAll 会清理对应任务 (防止与身份/配置不同步)。
    pending: Vec<PendingTask>,
}

impl CpuAffinity {
    pub fn new() -> Self {
        Self {
            bpf: KpmHandle::new(),
            managed: HashMap::new(),
            uid_pkg: HashMap::new(),
            cpuset_cache: HashMap::new(),
            pending: Vec::new(),
        }
    }

    /// 应用退出清理: Cgroup 主 pid 目录消失 / 显式 EvictUid 消息共用
    fn evict_uid(&mut self, uid: i32) {
        crate::rw_write_ignore_poison(&CPU_KNOWN).remove(&uid);
        self.pending.retain(|t| t.uid != uid);
        let pkg = self.uid_pkg.remove(&uid);
        if let Some(pkg) = pkg {
            self.managed.remove(&pkg); // pkg→tids, O(1) 整清 (替代 retain 全表扫)
        }
    }

    /// 发布当前 managed 统计到 CPU_STATS (web 命中应用/绑定线程在 KPM 模式显示用)
    fn publish_stats(&self) {
        let mut pkgs: Vec<String> = self.managed.keys().cloned().collect();
        pkgs.sort_unstable();
        let thread_count: usize = self.managed.values().map(|s| s.len()).sum();
        *crate::rw_write_ignore_poison(&CPU_STATS) = (thread_count, pkgs);
    }

    /// 读 /sys/fs/cgroup/apps/uid_<uid>/ 下 pid_* 目录获取该 uid 全部 pid
    /// (Android cgroup apps 布局: 每个进程一个 pid_<pid> 目录, 归属精确,
    /// 含主进程与全部子进程)。失败 (布局不存在/目录缺失) 返回 None →
    /// 该 uid 视为未运行 (空)。
    fn cgroup_apps_pids(uid: i32) -> Option<Vec<i32>> {
        let dir_path = format!("/sys/fs/cgroup/apps/uid_{uid}");
        let rd = std::fs::read_dir(&dir_path).ok()?;
        let mut pids: Vec<i32> = Vec::new();
        for ent in rd.flatten() {
            let name = ent.file_name().to_string_lossy().into_owned();
            if let Some(rest) = name.strip_prefix("pid_")
                && let Ok(p) = rest.parse::<i32>()
            {
                pids.push(p);
            }
        }
        Some(pids)
    }

    /// 应用已登记的前台应用: uid 目录直接取全部 pid, 再由 /proc/<pid>/task 取全部线程;
    /// 无 /proc 全量 uid 扫描。
    fn on_uid(&mut self, uid: i32, pkg: &str, cfg: &AppConfig) -> Vec<i32> {
        // cgroup apps 精确枚举: uid_<uid> 不存在 (含 uid<=0/未运行) → None → 空, 天然短路
        let pids = Self::cgroup_apps_pids(uid).unwrap_or_default();
        self.apply_tids(&pids, pkg, cfg);
        pids
    }

    /// 全量重放规则亲和性 (启动 / 配置变更): 只设亲和性 —— cgroup 按 uid 取全部 pid,
    /// /proc/<pid>/task 取线程 → 应用规则。
    /// 不写身份 (CPU_KNOWN): 身份仅由 binder 前台回调 (ApplyPkg)
    /// 产生, 因为只有它知道"谁是前台主进程"。
    pub fn apply_all(&mut self, cfg: &AppConfig, pkg_uids: HashMap<String, i32>) -> usize {
        let mut applied = 0usize;
        for (pkg, uid) in &pkg_uids {
            let Some(pids) = Self::cgroup_apps_pids(*uid) else { continue };
            if pids.is_empty() {
                continue; // 未运行
            }
            self.apply_tids(&pids, pkg, cfg);
            // 记录 uid→pkg 清理索引 (managed 按包名索引, 退出 evict_uid 需反查;
            // 不写 CPU_KNOWN —— 前台主 pid 身份仍只由 ApplyPkg 产生)
            self.uid_pkg.insert(*uid, pkg.clone());
            applied += 1;
        }
        // 初始化 (初始全量应用) 完成后: 整树时间戳同步一次 (仅首次)
        crate::cpuset::sync_init_once();
        applied
    }


    /// 应用一个包的全部进程 (主进程 + pkg: 子进程) 的全部线程
    /// 对给定进程集合的全部线程套用规则并应用 (解析 → 亲和 → uclamp 三段)
    fn apply_tids(&mut self, pids: &[i32], pkg: &str, cfg: &AppConfig) {
        let (set, aff, uclamps) = self.resolve_threads(pids, pkg, cfg);
        self.apply_affinity_batch(&set, aff, cfg);
        self.apply_uclamp_batch(uclamps);
    }

    /// 1) 解析: 遍历 pids × tids 套用规则, 收集 (bits 聚合的 applied_set,
    ///    亲和任务, uclamp 任务), 同时登记 managed (web 命中统计)。
    fn resolve_threads(
        &mut self,
        pids: &[i32],
        pkg: &str,
        cfg: &AppConfig,
    ) -> (HashMap<u64, Vec<i32>>, Vec<(i32, CpuSet, String)>, Vec<(i32, i32, i32)>) {
        let has_thread_rules = cfg.has_thread_rules.contains(pkg);
        // 规则只有包名 (无线程规则): 包级规则一次取好, 所有线程统一应用,
        // 免去逐线程 thread_affinity / 读 comm 匹配。
        let pkg_rule = if has_thread_rules {
            None
        } else {
            crate::rule_match::thread_affinity(pkg, "", cfg)
        };
        // 批量 applied_set: 相同 bits 的 tid 聚合, 每个 bits 一次 supercall
        let mut set: HashMap<u64, Vec<i32>> = HashMap::new();
        let mut aff: Vec<(i32, CpuSet, String)> = Vec::new();
        let mut uclamps: Vec<(i32, i32, i32)> = Vec::new();
        for p in pids {
            let Some(tids) = crate::apply_affinity::task_tids(*p) else { continue };
            for tid in tids {
                let rule = if has_thread_rules {
                    crate::rule_match::thread_affinity(
                        pkg,
                        &crate::apply_affinity::tid_comm(tid).unwrap_or_default(),
                        cfg,
                    )
                } else {
                    pkg_rule.clone()
                };
                let Some(rule) = rule else {
                    continue;
                };
                let bits = rule.cpus.bits[0];
                set.entry(bits).or_default().push(tid);
                // 只有 uclamp (cpus 空): 不设亲和, 仅收集 uclamp
                if rule.cpus.count() > 0 {
                    // cpuset 目录: 配置自带优先, 否则按合并 CPU 集合缓存 ensure
                    let cpuset_dir = if rule.cpuset_dir.is_empty() {
                        self.cpuset_dir_for(&rule.cpus, &cfg.topo)
                    } else {
                        rule.cpuset_dir.clone()
                    };
                    aff.push((tid, rule.cpus, cpuset_dir));
                }
                if rule.util_min >= 0 || rule.util_max >= 0 {
                    uclamps.push((tid, rule.util_min, rule.util_max));
                }
                self.managed.entry(pkg.to_string()).or_default().insert(tid);
            }
        }
        (set, aff, uclamps)
    }

    /// 2) 应用亲和: 批量写内核 APPLIED 表 (每 bits 一次 supercall) + 按 cpuset_dir
    ///    分组设 sched_setaffinity (主要手段), 仍不正确的 tid 走 cpuset tasks 迁移兜底。
    fn apply_affinity_batch(
        &self,
        set: &HashMap<u64, Vec<i32>>,
        aff: Vec<(i32, CpuSet, String)>,
        cfg: &AppConfig,
    ) {
        for (bits, tids) in set {
            self.bpf.applied_set_many(*bits, tids);
        }
        // 按 cpuset_dir 分组: 每个目录只拼一次 tasks 路径, 再逐线程设置
        let base = crate::cpuset::base_cpuset();
        let mut by_dir: HashMap<String, Vec<(i32, CpuSet)>> = HashMap::new();
        for (tid, cpus, cpuset_dir) in aff {
            by_dir.entry(cpuset_dir).or_default().push((tid, cpus));
        }
        for (dir, items) in &by_dir {
            let tasks_path = if dir.is_empty() {
                format!("{}/tasks", base)
            } else {
                format!("{}/{}/tasks", base, dir)
            };
            // 1) 先筛出"需要改"的 tid (亲和性已正确的不动, 免重复 syscall)
            let need: Vec<(i32, &CpuSet)> = items
                .iter()
                .filter(|(tid, cpus)| CpuSet::get_affinity(*tid).map_or(true, |a| a != *cpus))
                .map(|(t, c)| (*t, c))
                .collect();
            if need.is_empty() {
                continue;
            }
            // 2) 先逐个 sched_setaffinity (主要手段, 内核原生 API)
            for (tid, cpus) in &need {
                let _ = cpus.set_affinity(*tid);
            }
            // 3) 设置后仍不正确的 tid → cpuset tasks 迁移兜底
            //    (cpuset 控制器强制调度域; 一次 open 批量写)
            if cfg.topo.cpuset_enabled {
                let mut pend: Vec<i32> = Vec::new();
                for (tid, cpus) in &need {
                    if !CpuSet::get_affinity(*tid).is_some_and(|a| a == **cpus) {
                        pend.push(*tid);
                    }
                }
                if !pend.is_empty() {
                    use std::io::Write;
                    if let Ok(mut f) =
                        std::fs::OpenOptions::new().append(true).open(&tasks_path)
                    {
                        for tid in &pend {
                            let _ = writeln!(f, "{}", tid);
                        }
                    }
                }
            }
        }
    }

    /// 3) 应用 uclamp (sched_setattr): 逐 tid 设 util_min/max (仅设了 uclamp 的 tid)
    fn apply_uclamp_batch(&self, uclamps: Vec<(i32, i32, i32)>) {
        for (tid, mn, mx) in uclamps {
            crate::apply_affinity::set_uclamp(tid, mn, mx);
        }
    }

    /// cpuset 目录缓存: 相同 CPU 集合 (bits) 只 ensure 一次, 其余线程直接复用
    fn cpuset_dir_for(&mut self, cpus: &CpuSet, topo: &CpuTopology) -> String {
        let bits = cpus.bits[0];
        if let Some(d) = self.cpuset_cache.get(&bits) {
            return d.clone();
        }
        let d = crate::cpuset::ensure_cpuset_dir(cpus, topo);
        // 新建的 CPU 组合目录: 立即同步时间戳
        crate::cpuset::sync_cpuset_dir(&d);
        self.cpuset_cache.insert(bits, d.clone());
        d
    }

    /// 常驻线程入口 (纯事件驱动, 无重试/无周期)
    pub fn run(mut self, rx: mpsc::Receiver<CpuMsg>) {
        let name = CString::new("CpuAffinity").unwrap();
        unsafe {
            libc::pthread_setname_np(libc::pthread_self(), name.as_ptr());
        }

        loop {
            let timeout = self
                .pending
                .iter()
                .map(|t| t.due.saturating_duration_since(std::time::Instant::now()))
                .min()
                .unwrap_or(std::time::Duration::from_secs(3600)); // 无 pending: 长阻塞 (消息唤醒)
            match rx.recv_timeout(timeout) {
                Ok(msg) => self.handle_msg(msg),
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(_) => break,
            }

            // 到期应用: 先取出到期任务, 再处理 (状态在 apply_pkg 前已更新)
            let now = std::time::Instant::now();
            let (due, rest): (Vec<_>, Vec<_>) = self.pending.drain(..).partition(|t| t.due <= now);
            self.pending = rest;
            for t in due {
                self.apply_pkg(t.pid, t.uid, &t.pkg);
            }
        }
        self.bpf.applied_clear();
    }

    /// 应用已登记的前台应用 (到期执行): cgroup 取 uid 全部 pid → /proc/<pid>/task
    /// 线程 → 设亲和 + 回写身份
    fn apply_pkg(&mut self, pid: i32, uid: i32, pkg: &str) {
        let Some(cfg) = crate::config::current_cfg() else {
            // 配置异常缺失: 清占位身份, 等下次前台回调重新触发
            crate::rw_write_ignore_poison(&CPU_KNOWN).remove(&uid);
            return;
        };
        let pids = self.on_uid(uid, pkg, &cfg);
        if pids.is_empty() {
            // 应用已退出 (EvictUid 已清身份) → 不重插空身份
            crate::rw_write_ignore_poison(&CPU_KNOWN).remove(&uid);
            return;
        }
        // 设置亲和性后: 该 uid 主进程+全部子进程 pid 列表写入 cpu_known
        // (供后续冷热判断/统计); pids 已消费完, 直接 move
        crate::rw_write_ignore_poison(&CPU_KNOWN).insert(uid, (pid, pids));
        // 记录 uid→pkg (退出时按 uid 整清 managed)
        self.uid_pkg.insert(uid, pkg.to_string());
    }

    /// 消息处理 (即时; 顺序保真)。ApplyPkg 登记延迟任务; ApplyAll/EvictUid 清理 pending
    fn handle_msg(&mut self, msg: CpuMsg) {
        match msg {
            CpuMsg::ApplyPkg(pid, uid, pkg) => {
                // 配置未就绪 (CURRENT_CONFIG 未写入): 不占位不登记, 下次前台回调重试
                if crate::config::current_cfg().is_none() {
                    return;
                }
                // 冷启动: 占位 (冷热判断) + 登记延迟应用; 同 uid 重复前台合并 (保留最新)
                crate::rw_write_ignore_poison(&CPU_KNOWN).insert(uid, (pid, Vec::new()));
                let due = std::time::Instant::now() + enum_delay();
                match self.pending.iter_mut().find(|t| t.uid == uid) {
                    Some(t) => {
                        t.due = due;
                        t.pid = pid;
                        t.pkg = pkg;
                    }
                    None => self.pending.push(PendingTask { due, pid, uid, pkg }),
                }
            }
            CpuMsg::ApplyAll(pkg_uids) => {
                // 全量应用覆盖所有应用: 清掉未到期任务 (防旧任务用旧 pid/身份覆盖新配置)
                self.pending.clear();
                if let Some(cfg) = crate::config::current_cfg() {
                    self.apply_all(&cfg, pkg_uids);
                }
            }
            CpuMsg::ApplyPkgByUid(uid, pkg) => {
                // 整包重放: 仅对已接管 (CPU_KNOWN 有记录) 的应用重放; 未运行则跳过
                let cached = crate::rw_read_ignore_poison(&CPU_KNOWN).get(&uid).cloned();
                let pids = match cached {
                    Some((_, pids)) if !pids.is_empty() => pids, // 复用缓存 pids
                    Some(_) => Self::cgroup_apps_pids(uid).unwrap_or_default(), // 占位中现扫
                    None => return,                              // 未运行: 跳过本条
                };
                let Some(cfg) = crate::config::current_cfg() else { return };
                self.apply_tids(&pids, &pkg, &cfg);
            }
            CpuMsg::ApplyThreadByUid(uid, pkg, thread) => {
                // 单线程重放: 同上存活判断; 收集 comm==thread 的 tid
                let cached = crate::rw_read_ignore_poison(&CPU_KNOWN).get(&uid).cloned();
                let pids = match cached {
                    Some((_, pids)) if !pids.is_empty() => pids,
                    Some(_) => Self::cgroup_apps_pids(uid).unwrap_or_default(), // 占位中现扫
                    None => return,
                };
                let Some(cfg) = crate::config::current_cfg() else { return };
                let mut tids: Vec<i32> = Vec::new();
                for p in pids {
                    for t in crate::apply_affinity::task_tids(p).unwrap_or_default() {
                        if crate::apply_affinity::tid_comm(t).as_deref() == Some(thread.as_str()) {
                            tids.push(t);
                        }
                    }
                }
                if !tids.is_empty() {
                    self.apply_tids(&tids, &pkg, &cfg);
                }
            }
            CpuMsg::EvictUid(uid) => self.evict_uid(uid),
            CpuMsg::PublishStats => self.publish_stats(),
        }
    }
}

/// 启动 CPU worker 线程 (两种驱动模式统一调用一次)
pub fn start() {
    if CPU_FG_TX.get().is_some() {
        return;
    }
    // 用户态与 KPM 模式统一启动 CPU worker: 身份记录/进程枚举/亲和性施加全部经
    // ApplyPkg 消息驱动; KPM 不可用时 bpf ctl0 调用仅失败无副作用 (用户态由
    // apply_affinity::affinity_set 真正施加 sched_setaffinity)。
    let (tx, rx) = mpsc::channel::<CpuMsg>();
    let _ = CPU_FG_TX.set(Mutex::new(tx));
    let cpu = CpuAffinity::new();
    thread::spawn(move || cpu.run(rx));
}



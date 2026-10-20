//! CPU 亲和性模块（TaskStackListener task event 触发, 无周期扫描）
//!
//! 设计:
//!   - 触发: TaskStackListener 任务前移事件 (主线程 EV_TASK 接收前移任务 effectiveUid);
//!     主线程查 cpu uid 表, 命中且冷启动 (CPU_KNOWN 无该 uid) 时发
//!     CpuMsg::ApplyPkgByUid(uid, pkg) 立即应用并登记; ApplyAll = 启动/配置全量。
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
use std::sync::mpsc;
use std::sync::{Mutex, OnceLock, RwLock};
use std::thread;

use crate::config::AppConfig;
use crate::cpuset::{CpuSet, CpuTopology};

/// CPU worker 消息
pub enum CpuMsg {
    /// 规则应用主进程退出 (pidfd 退出事件): 按 uid 清除该应用在 managed 的全部条目
    /// → web 命中归零 (按 uid 整清, 不依赖主线程 tid 是否在 managed)
    EvictUid(i32),
    /// 全量应用 (启动 / 配置变更): 携带 规则包→uid 表 (main 由 uid 表供给, worker 不读文件)
    ApplyAll(HashMap<String, i32>),
    /// web 轮询请求刷新 CPU 统计快照 (仅在轮询时发布, 避免每次事件都构建)
    PublishStats,
    /// task event 驱动 CPU 应用: 冷启动 (未登记) 现扫应用并登记; 热启动由主线程
    /// cpu_known_has 判断不发; 也是整包编辑保存后的重放入口
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

/// 冷热判断: 表里有该 uid = 已登记应用过 (热); 无 = 冷 (需应用)。uid 登记即热,
/// 与主 pid 无关; 进程退出由 pidfd 退出监听 (EvictUid) 清表。
pub fn cpu_known_has(uid: i32) -> bool {
    uid > 0 && crate::rw_read_ignore_poison(&CPU_KNOWN).contains_key(&uid)
}

/// CPU 链路调试日志 (临时; 写 /data/local/tmp/appopt_cpu_dbg.txt, ≤1MB)
pub(crate) fn cpu_dbg(msg: &str) {
    use std::io::Write;
    if let Ok(md) = std::fs::metadata("/data/local/tmp/appopt_cpu_dbg.txt") {
        if md.len() > 1024 * 1024 {
            return;
        }
    }
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open("/data/local/tmp/appopt_cpu_dbg.txt")
    {
        let _ = f.write_all(format!("t={:?} {}\n", std::time::Instant::now().elapsed(), msg).as_bytes());
    }
}

/// 按 uid 从 cgroup apps 目录取全部 pid (task event 驱动: web 命中显示/退出监听,
/// CPU worker 也复用)。失败 (布局不存在/未运行) 返回 None。
pub fn cgroup_pids(uid: i32) -> Option<Vec<i32>> {
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

/// KPM 模式 web 统计: (绑定线程数, 命中包名列表 [(pkg, 线程规则名→ok; 应用级 ok 派生)])
static CPU_STATS: RwLock<(usize, Vec<(String, HashMap<String, bool>)>)> =
    RwLock::new((0, Vec::new()));

/// 读取 KPM 模式统计: (线程数, 命中包名数, 命中包名列表 [(pkg, 线程名→ok)])
pub fn cpu_stats() -> (usize, usize, Vec<(String, HashMap<String, bool>)>) {
    // 请求 worker 发布最新统计快照 (web 轮询触发; 返回当前快照, 下一次轮询读到最新)
    if let Some(tx) = cpu_fg_tx() {
        let _ = tx.send(CpuMsg::PublishStats);
    }
    let g = crate::rw_read_ignore_poison(&CPU_STATS);
    (g.0, g.1.len(), g.1.clone())
}

/// 初始化: 清空命中应用/绑定线程统计快照 (web 线程状态页命中应用显示)
pub fn cpu_stats_clear() {
    *crate::rw_write_ignore_poison(&CPU_STATS) = (0, Vec::new());
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

/// CPU 亲和性执行器 (worker 线程独占)
pub struct CpuAffinity {
    /// 已管理线程 tid → 包名 (用于清理已退出线程)
    /// 已应用包 → 绑定 tid 集合 (退出按 uid 反查 pkg 后 O(1) 整清)
    managed: HashMap<String, HashSet<i32>>,
    /// 回读校验结果 (pkg → 线程名 → 该线程全部 tid 核对通过); 应用级 ok 由此派生
    managed_tok: HashMap<String, HashMap<String, bool>>,
    /// 已应用应用的 uid → 包名 (退出时按 uid 反查 pkg 清 managed)
    uid_pkg: HashMap<i32, String>,
    /// 合并 CPU 集合 bits → cpuset 目录名 缓存 (相同集合只 ensure 一次, 避免每线程重复建目录)
    cpuset_cache: HashMap<u64, String>,
}

impl CpuAffinity {
    pub fn new() -> Self {
        Self {
            managed: HashMap::new(),
            managed_tok: HashMap::new(),
            uid_pkg: HashMap::new(),
            cpuset_cache: HashMap::new(),
        }
    }

    /// 应用退出清理: Cgroup 主 pid 目录消失 / 显式 EvictUid 消息共用
    fn evict_uid(&mut self, uid: i32) {
        crate::rw_write_ignore_poison(&CPU_KNOWN).remove(&uid);
        let pkg = self.uid_pkg.remove(&uid);
        if let Some(pkg) = pkg {
            self.managed.remove(&pkg); // pkg→tids, O(1) 整清 (替代 retain 全表扫)
            self.managed_tok.remove(&pkg);
        }
    }

    /// 发布当前 managed 统计到 CPU_STATS (web 命中应用/绑定线程在 KPM 模式显示用;
    /// 应用级 ok = 全部线程 ok, 由调用方从 managed_tok 派生)
    fn publish_stats(&self) {
        let mut pkgs: Vec<(String, HashMap<String, bool>)> = self
            .managed
            .keys()
            .map(|p| (p.clone(), self.managed_tok.get(p).cloned().unwrap_or_default()))
            .collect();
        pkgs.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        let thread_count: usize = self.managed.values().map(|s| s.len()).sum();
        *crate::rw_write_ignore_poison(&CPU_STATS) = (thread_count, pkgs);
    }

    /// 读 /sys/fs/cgroup/apps/uid_<uid>/ 下 pid_* 目录获取该 uid 全部 pid
    /// (Android cgroup apps 布局: 每个进程一个 pid_<pid> 目录, 归属精确,
    /// 含主进程与全部子进程)。失败 (布局不存在/目录缺失) 返回 None →
    /// 该 uid 视为未运行 (空)。
    fn cgroup_apps_pids(uid: i32) -> Option<Vec<i32>> {
        crate::cpu_affinity::cgroup_pids(uid)
    }

    /// 全量重放规则亲和性 (启动 / 配置变更): cgroup 按 uid 取全部 pid,
    /// /proc/<pid>/task 取线程 → 应用规则。不写 CPU_KNOWN 身份
    /// (该表由前台驱动 ApplyPkgByUid 按任务前移时机维护)。
    pub fn apply_all(&mut self, cfg: &AppConfig, pkg_uids: HashMap<String, i32>) -> usize {
        let mut applied = 0usize;
        for (pkg, uid) in &pkg_uids {
            let Some(pids) = Self::cgroup_apps_pids(*uid) else { continue };
            if pids.is_empty() {
                continue; // 未运行
            }
            self.apply_tids(&pids, pkg, cfg);
            // 记录 uid→pkg 清理索引 (managed 按包名索引, 退出 evict_uid 需反查)
            self.uid_pkg.insert(*uid, pkg.clone());
            applied += 1;
        }
        // 初始化 (初始全量应用) 完成后: 整树时间戳同步一次 (仅首次)
        crate::cpuset::sync_init_once();
        if applied > 0 {
            self.publish_stats();
        }
        applied
    }


    /// 应用一个包的全部进程 (主进程 + pkg: 子进程) 的全部线程
    /// 对给定进程集合的全部线程套用规则并应用 (解析 → 亲和 → uclamp 三段)
    fn apply_tids(&mut self, pids: &[i32], pkg: &str, cfg: &AppConfig) {
        let (aff, uclamps) = self.resolve_threads(pids, pkg, cfg);
        self.apply_affinity_batch(aff.clone(), cfg);
        self.apply_uclamp_batch(uclamps);
        /* 应用级 + 线程规则同一遍回读校验 (tok 一次遍历得出; 应用 ok 从 tok 派生) */
        let mut tok: HashMap<String, bool> = HashMap::new();
        for (tid, cpus, _) in &aff {
            let name = crate::apply_affinity::tid_comm(*tid).unwrap_or_default();
            let ok = CpuSet::get_affinity(*tid).is_some_and(|a| a == *cpus);
            let e = tok.entry(name).or_insert(true);
            *e = *e && ok;
        }
        self.managed_tok.insert(pkg.to_string(), tok);
    }

    /// 1) 解析: 遍历 pids × tids 套用规则, 收集 (亲和任务, uclamp 任务),
    ///    同时登记 managed (web 命中统计)。
    fn resolve_threads(
        &mut self,
        pids: &[i32],
        pkg: &str,
        cfg: &AppConfig,
    ) -> (Vec<(i32, CpuSet, String)>, Vec<(i32, i32, i32)>) {
        let has_thread_rules = cfg.has_thread_rules.contains(pkg);
        // 规则只有包名 (无线程规则): 包级规则一次取好, 所有线程统一应用,
        // 免去逐线程 thread_affinity / 读 comm 匹配。
        let pkg_rule = if has_thread_rules {
            None
        } else {
            crate::rule_match::thread_affinity(pkg, "", cfg)
        };
        let mut aff: Vec<(i32, CpuSet, String)> = Vec::new();
        let mut uclamps: Vec<(i32, i32, i32)> = Vec::new();
        /* 命中 tid 先收集, 最后一次性登记 managed (pkg.to_string/entry 只做一次) */
        let mut managed_tids: Vec<i32> = Vec::new();
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
                managed_tids.push(tid);
            }
        }
        if !managed_tids.is_empty() {
            let s = self.managed.entry(pkg.to_string()).or_default();
            for t in managed_tids {
                s.insert(t);
            }
        }
        (aff, uclamps)
    }

    /// 2) 应用亲和: 按 cpuset_dir 分组设 sched_setaffinity (主要手段),
    ///    仍不正确的 tid 走 cpuset tasks 迁移兜底。
    fn apply_affinity_batch(&self, aff: Vec<(i32, CpuSet, String)>, cfg: &AppConfig) {
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

    /// 常驻线程入口 (纯事件驱动: 阻塞等消息, task event / 全量 / 退出 全部即时处理)
    pub fn run(mut self, rx: mpsc::Receiver<CpuMsg>) {
        let name = CString::new("CpuAffinity").unwrap();
        unsafe {
            libc::pthread_setname_np(libc::pthread_self(), name.as_ptr());
        }

        loop {
            match rx.recv() {
                Ok(msg) => self.handle_msg(msg),
                Err(_) => break,
            }
        }
    }

    /// 消息处理 (即时; 顺序保真): ApplyPkgByUid 一次性应用并登记;
    /// ApplyAll/EvictUid 全量/清理。
    fn handle_msg(&mut self, msg: CpuMsg) {
        match msg {
            CpuMsg::ApplyAll(pkg_uids) => {
                // 全量应用覆盖所有应用 (启动 / 配置变更)
                if let Some(cfg) = crate::config::current_cfg() {
                    self.apply_all(&cfg, pkg_uids);
                }
            }
            CpuMsg::ApplyPkgByUid(uid, pkg) => {
                // task event 驱动 CPU 应用: 冷启动现扫应用并登记; 已登记复用缓存 pids
                crate::cpu_affinity::cpu_dbg(&format!(
                    "worker recv ApplyPkgByUid uid={} pkg={}",
                    uid, pkg
                ));
                let cached = crate::rw_read_ignore_poison(&CPU_KNOWN).get(&uid).cloned();
                let had_cached = cached.is_some();
                let pids = match cached {
                    Some((_, pids)) if !pids.is_empty() => pids, // 复用缓存 pids
                    _ => Self::cgroup_apps_pids(uid).unwrap_or_default(), // 未登记: 现扫
                };
                crate::cpu_affinity::cpu_dbg(&format!(
                    "ApplyPkgByUid uid={} pkg={} cached={} scan_pids={:?}",
                    uid,
                    pkg,
                    had_cached,
                    pids.iter().take(6).collect::<Vec<_>>()
                ));
                if pids.is_empty() {
                    // 进程不在 → 清身份 (下次 task event 冷启动重新应用)
                    crate::rw_write_ignore_poison(&CPU_KNOWN).remove(&uid);
                    crate::cpu_affinity::cpu_dbg(&format!(
                        "ApplyPkgByUid uid={} pkg={} PIDS_EMPTY (cgroup 扫不到)",
                        uid, pkg
                    ));
                    return;
                }
                let Some(cfg) = crate::config::current_cfg() else {
                    crate::cpu_affinity::cpu_dbg(&format!("ApplyPkgByUid uid={} pkg={} cfg_none", uid, pkg));
                    return;
                };
                self.apply_tids(&pids, &pkg, &cfg);
                // 复检统计 (tok: 线程名→是否全部 ok; bad>0 → set_affinity 未生效)
                let tok = self.managed_tok.get(&pkg).cloned().unwrap_or_default();
                let ok_n = tok.values().filter(|v| **v).count();
                let bad_n = tok.values().filter(|v| !**v).count();
                crate::cpu_affinity::cpu_dbg(&format!(
                    "ApplyPkgByUid uid={} pkg={} pids={:?} aff_threads={} tok_ok={} tok_bad={}",
                    uid, pkg, pids, pids.len(), ok_n, bad_n
                ));
                // 登记身份: 主 pid = cgroup 下最小 pid (主进程最先 fork)
                let main = *pids.iter().min().unwrap_or(&0);
                crate::rw_write_ignore_poison(&CPU_KNOWN).insert(uid, (main, pids));
                self.uid_pkg.insert(uid, pkg.to_string());
                // 退出监听 (保留原 on_fg 功能): 主 pid 退出 → EV_EXIT_PID → EvictUid 清身份
                if main > 0 {
                    crate::event_probe::watch(main);
                }
                // 应用后立即发布命中统计 (web 轮询 PublishStats 是"发一轮读下一轮",
                // 不立即发布会晚两个轮询周期才显示)
                self.publish_stats();
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
    // ApplyPkgByUid (前台 task event 驱动) / ApplyAll 消息驱动; 亲和完全由用户态
    // apply_affinity::affinity_set 施加 (内核 KPM 只做 service list 替换, 不参与亲和)。
    let (tx, rx) = mpsc::channel::<CpuMsg>();
    let _ = CPU_FG_TX.set(Mutex::new(tx));
    let cpu = CpuAffinity::new();
    thread::spawn(move || cpu.run(rx));
}



use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};

use crate::apply_affinity::affinity_set;
use crate::config::AppConfig;
use crate::cpuset::{CpuSet, CpuTopology};
use crate::rule_match::{comm_to_pkg, thread_affinity};

/// 全局共享 pid→pkg 索引：由 ProcCache 的增删方法统一维护，
/// 供刷新率模块按 pid 查包名（替代 packages.list 文件 I/O）。
pub static PID_PKG: LazyLock<Mutex<HashMap<i32, String>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// 供刷新率模块查询 pid→pkg。这里只读共享索引，不在刷新率热路径补扫 /proc。
pub fn pkg_lookup_pid(pid: i32) -> Option<String> {
    PID_PKG.lock().unwrap().get(&pid).cloned()
}

pub fn pkg_track_pid(pid: i32, pkg: &str) {
    if pid > 0 && !pkg.is_empty() {
        PID_PKG.lock().unwrap().insert(pid, pkg.to_string());
        // 若刷新率线程正等待该 pid 的包名（冷启动竞态），事件驱动立即通知，
        // 替代轮询等待：KPM 事件链填充 PID_PKG 后刷新率即刻生效。
        crate::refresh::notify_pkg_tracked(pid);
    }
}

pub fn pkg_untrack_pid(pid: i32) {
    PID_PKG.lock().unwrap().remove(&pid);
}

pub struct TaskEntry {
    pub pid: i32,
    pub pkg: String,
    pub cpus: CpuSet,
    pub cpuset_dir: String,
    pub is_thread_rule: bool,
}

/// 双模式共用进程缓存，eBPF 事件驱动增量维护，proc 模式触发全量重建
pub struct ProcCache {
    pub tasks: HashMap<i32, TaskEntry>,
    /// 事件热路径使用的本地 pid→pkg 缓存，避免每个线程事件锁全局 PID_PKG。
    pid_pkgs: HashMap<i32, String>,
    /// 最近确认不是目标包的 pid→comm，避免内核粗过滤产生的重复事件反复读 /proc。
    negative_pids: HashMap<i32, String>,
    /// pid→缓存任务数，避免每次线程退出都扫描全部 tasks。
    pid_task_counts: HashMap<i32, usize>,
    /// tid→pkg 的计数，供 Web 统计直接取唯一包名，避免每次请求扫描全部任务。
    hit_pkgs: HashMap<String, usize>,
}

impl ProcCache {
    pub fn new() -> Self {
        Self {
            tasks: HashMap::new(),
            pid_pkgs: HashMap::new(),
            negative_pids: HashMap::new(),
            pid_task_counts: HashMap::new(),
            hit_pkgs: HashMap::new(),
        }
    }

    fn forget_pid(&mut self, pid: i32) {
        self.pid_pkgs.remove(&pid);
        self.negative_pids.remove(&pid);
        pkg_untrack_pid(pid);
    }

    fn drop_pid_ref(&mut self, pid: i32) {
        let last = match self.pid_task_counts.get_mut(&pid) {
            Some(n) => {
                *n -= 1;
                *n == 0
            }
            None => true,
        };
        if last {
            self.pid_task_counts.remove(&pid);
            self.forget_pid(pid);
        }
    }

    fn add_pid_ref(&mut self, pid: i32) {
        *self.pid_task_counts.entry(pid).or_insert(0) += 1;
    }

    fn hit_pkg_add(&mut self, pkg: &str) {
        *self.hit_pkgs.entry(pkg.to_string()).or_insert(0) += 1;
    }

    fn hit_pkg_del(&mut self, pkg: &str) {
        if let Some(n) = self.hit_pkgs.get_mut(pkg) {
            *n -= 1;
            if *n == 0 {
                self.hit_pkgs.remove(pkg);
            }
        }
    }

    /// 当前命中的唯一包名，按字典序返回；只遍历包数，不扫描全部线程。
    pub fn hit_package_list(&self) -> Vec<String> {
        let mut list: Vec<String> = self.hit_pkgs.keys().cloned().collect();
        list.sort_unstable();
        list
    }

    /// 配置热加载后清理 pid 解析缓存（正/负），任务与命中计数保留。
    /// 仅需在新白名单下重新识别进程包名，无需重建已绑定的任务。
    pub fn invalidate_pid_cache(&mut self) {
        self.pid_pkgs.clear();
        self.negative_pids.clear();
    }

    pub fn clear(&mut self) {
        self.tasks.clear();
        self.pid_pkgs.clear();
        self.negative_pids.clear();
        self.pid_task_counts.clear();
        self.hit_pkgs.clear();
        PID_PKG.lock().unwrap().clear();
    }

    /// 删除任务并做 O(1) 簿记；若该 PID 没有其它缓存任务则清掉缓存映射。
    pub fn task_del(&mut self, tid: i32) {
        let Some(entry) = self.tasks.remove(&tid) else { return };
        self.hit_pkg_del(&entry.pkg);
        self.drop_pid_ref(entry.pid);
    }

    /// 清理一个进程的缓存任务。EXEC 后必须清理旧包名，避免 PID 复用/换包导致误命中。
    pub fn pid_exec(&mut self, pid: i32) {
        let tids: Vec<i32> = self
            .tasks
            .iter()
            .filter_map(|(&tid, entry)| (entry.pid == pid).then_some(tid))
            .collect();
        for tid in tids {
            self.task_del(tid);
        }
        self.forget_pid(pid);
    }

    /// comm 匹配包名。
    ///
    /// KPM 事件路径中同一进程的多个线程会反复触发此函数；成功应用过的进程
    /// 直接复用本地 pid→pkg 缓存，避免全局 Mutex 和 /proc/<pid>/cmdline 访问。
    /// 首次识别后同时缓存正/负结果：目标 PID 命中 pid_pkgs，非目标 PID 命中
    /// negative_pids，之后同一 PID 的后续线程事件不再重复读 /proc/<pid>/cmdline。
    /// EXEC / 进程退出 / 配置变更会清除对应缓存，避免 PID 复用或换包误判。
    pub fn pkg_lookup_comm(&mut self, pid: i32, comm: &str, cfg: &AppConfig) -> Option<String> {
        // 正缓存: 已确认是目标包
        if let Some(pkg) = self.pid_pkgs.get(&pid).cloned() {
            if cfg.target_pkgs.contains(&pkg) {
                return Some(pkg);
            }
            // 配置已变化但旧映射尚未被全量扫描清理时，立即丢弃旧值。
            self.forget_pid(pid);
        }
        // 负缓存: 同一 PID + 同一 comm 之前确认非目标，直接跳过 cmdline 读取。
        if let Some(prev) = self.negative_pids.get(&pid) {
            if prev == comm {
                return None;
            }
        }
        // 解析（只对未知 PID 读一次 cmdline）
        let pkg = comm_to_pkg(pid, comm, cfg);
        if let Some(pkg) = &pkg {
            self.pid_pkgs.insert(pid, pkg.clone());
            // 立即登记共享 PID_PKG（供刷新率模块按 pid 查包名）。
            // 不能只等 task_apply 成功：只配置刷新率、没有 CPU 亲和性规则
            // 的应用 thread_affinity 会返回 None 而 task_apply 失败，
            // 若不在此登记，刷新率前台回调将永远查不到该应用的包名。
            pkg_track_pid(pid, pkg);
        } else {
            self.negative_pids.insert(pid, comm.to_string());
        }
        pkg.or_else(|| self.tasks.get(&pid).map(|e| e.pkg.clone()))
    }

    /// 计算并应用线程亲和性，保护已有线程规则绑定防止降级
    pub fn task_apply<F>(
        &mut self,
        tid: i32,
        pid: i32,
        pkg: &str,
        comm: &str,
        cfg: &AppConfig,
        apply_fn: F,
    ) -> bool
    where
        F: FnOnce(i32, &CpuSet, &str) -> bool,
    {
        // 目标包（CPU 规则 ∪ 刷新率配置）即登记共享 PID_PKG，供刷新率模块按 pid 查包名。
        // 只配置刷新率、没有 CPU 规则的应用 thread_affinity 会返回 None，若在此 return
        // 前不登记，full_scan / proc 路径将永远不登记其 PID→包名，刷新率切换永不生效。
        if cfg.target_pkgs.contains(pkg) {
            self.pid_pkgs.insert(pid, pkg.to_string());
            pkg_track_pid(pid, pkg);
        }

        let thread_name = if cfg.has_thread_rules.contains(pkg) { comm } else { "" };
        let Some(result) = thread_affinity(pkg, thread_name, cfg) else {
            return false;
        };

        if !result.is_thread_rule && self.tasks.get(&tid).is_some_and(|old| old.is_thread_rule) {
            return true;
        }

        let dead = apply_fn(tid, &result.cpus, &result.cpuset_dir);
        if dead {
            self.task_del(tid);
            return false;
        }

        // 替换已有条目时，先归还旧 PID 引用与旧包名命中计数。
        if let Some(old) = self.tasks.insert(
            tid,
            TaskEntry {
                pid,
                pkg: pkg.to_string(),
                cpus: result.cpus,
                cpuset_dir: result.cpuset_dir,
                is_thread_rule: result.is_thread_rule,
            },
        ) {
            self.hit_pkg_del(&old.pkg);
            if old.pid != pid {
                self.drop_pid_ref(old.pid);
                self.add_pid_ref(pid);
            }
        } else {
            self.add_pid_ref(pid);
        }
        self.hit_pkg_add(pkg);
        // 只有任务成功进入 cache 后才登记 PID，避免无效匹配污染快速路径。
        self.pid_pkgs.insert(pid, pkg.to_string());
        pkg_track_pid(pid, pkg);
        true
    }

    /// 遍历 tasks 重新应用亲和性，清理已退出的条目
    pub fn affinity_sync(&mut self, topo: &CpuTopology) {
        let dead_tids: Vec<i32> = self
            .tasks
            .iter()
            .filter_map(|(tid, e)| {
                if affinity_set(*tid, &e.cpus, &e.cpuset_dir, topo) {
                    Some(*tid)
                } else {
                    None
                }
            })
            .collect();
        for tid in dead_tids {
            self.task_del(tid);
        }
    }
}

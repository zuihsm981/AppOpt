use std::collections::HashMap;

use crate::apply_affinity::affinity_set;
use crate::config::AppConfig;
use crate::cpuset::{CpuSet, CpuTopology};
use crate::rule_match::thread_affinity;

pub struct TaskEntry {
    pub pid: i32,
    pub pkg: String,
    pub cpus: CpuSet,
    pub cpuset_dir: String,
    pub is_thread_rule: bool,
}

/// /proc 回退模式的进程缓存 (KPM 模式下 CPU 由 binder 驱动、刷新率由 uid 表驱动,
/// 均不使用本缓存; 仅 /proc 回退与 web 统计在用)
pub struct ProcCache {
    pub tasks: HashMap<i32, TaskEntry>,
    /// pid→缓存任务数，避免每次线程退出都扫描全部 tasks。
    pid_task_counts: HashMap<i32, usize>,
    /// tid→pkg 的计数，供 Web 统计直接取唯一包名，避免每次请求扫描全部任务。
    hit_pkgs: HashMap<String, usize>,
}

impl ProcCache {
    pub fn new() -> Self {
        Self {
            tasks: HashMap::new(),
            pid_task_counts: HashMap::new(),
            hit_pkgs: HashMap::new(),
        }
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

    pub fn clear(&mut self) {
        self.tasks.clear();
        self.pid_task_counts.clear();
        self.hit_pkgs.clear();
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
        let thread_name = if cfg.has_thread_rules.contains(pkg) { comm } else { "" };
        let Some(result) = thread_affinity(pkg, thread_name, cfg) else {
            return false;
        };

        if !result.is_thread_rule && self.tasks.get(&tid).is_some_and(|old| old.is_thread_rule) {
            return true;
        }

        let dead = apply_fn(tid, &result.cpus, &result.cpuset_dir);
        if dead {
            if let Some(e) = self.tasks.remove(&tid) {
                self.hit_pkg_del(&e.pkg);
                self.drop_pid_ref(e.pid);
            }
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
        true
    }

    /// 遍历 tasks 重新应用亲和性，清理已退出的条目
    pub fn affinity_sync(&mut self, topo: &CpuTopology) {
        let dead_tids: Vec<i32> = self
            .tasks
            .iter()
            .filter_map(|(tid, e)| {
                if affinity_set(*tid, &e.cpus, &e.cpuset_dir, topo, false) {
                    Some(*tid)
                } else {
                    None
                }
            })
            .collect();
        for tid in dead_tids {
            if let Some(e) = self.tasks.remove(&tid) {
                self.hit_pkg_del(&e.pkg);
                self.drop_pid_ref(e.pid);
            }
        }
    }
}

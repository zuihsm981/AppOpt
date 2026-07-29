use std::collections::HashMap;

use crate::apply_affinity::affinity_set;
use crate::config::AppConfig;
use crate::cpuset::{CpuSet, CpuTopology};
use crate::rule_match::{pkg_match, thread_affinity};

/// 线程条目，对应 /proc/[pid]/task/[tid]
pub struct TaskEntry {
    pub pid: i32,
    pub cpus: CpuSet,
    pub cpuset_dir: String,
    pub is_thread_rule: bool,
}

/// 双模式共用进程缓存，eBPF 事件驱动增量维护，proc 模式触发全量重建
pub struct ProcCache {
    pub pkgs: HashMap<i32, (String, bool)>,
    pub tasks: HashMap<i32, TaskEntry>,
}

impl ProcCache {
    pub fn new() -> Self {
        Self {
            pkgs: HashMap::new(),
            tasks: HashMap::new(),
        }
    }

    pub fn clear(&mut self) {
        self.pkgs.clear();
        self.tasks.clear();
    }

    /// 删除 tid，若该 pid 下无线程则清理 pkgs[pid]
    pub fn task_del(&mut self, tid: i32) {
        let pid = self.tasks.remove(&tid).map(|t| t.pid);
        if let Some(pid) = pid {
            self.pkgs_purge(pid);
        }
    }

    /// pid 无残留 task 时清理 pkgs[pid] 避免孤立缓存泄漏
    fn pkgs_purge(&mut self, pid: i32) {
        if !self.tasks.values().any(|t| t.pid == pid) {
            self.pkgs.remove(&pid);
        }
    }

    /// eBPF 专用，pkgs 缓存命中优先否则 comm_to_pkg 匹配后缓存
    pub fn pkg_lookup_comm(
        &mut self,
        pid: i32,
        comm: &str,
        cfg: &AppConfig,
    ) -> Option<(String, bool)> {
        if let Some(&(ref pkg, htr)) = self.pkgs.get(&pid) {
            return Some((pkg.clone(), htr));
        }
        let pkg = comm_to_pkg(comm, cfg)?;
        let (_, htr) = pkg_match(&pkg, cfg);
        self.pkgs.insert(pid, (pkg.clone(), htr));
        Some((pkg, htr))
    }

    /// 计算并应用线程亲和性，trust_comm=false 时忽略 comm 走 fallback（FORK 继承场景）
    /// 新结果走 fallback 时保护已有线程规则绑定，防止临时改名降级
    pub fn task_apply<F>(
        &mut self,
        tid: i32,
        pid: i32,
        pkg: &str,
        comm: &str,
        has_thread_rules: bool,
        cfg: &AppConfig,
        trust_comm: bool,
        apply_fn: F,
    ) -> bool
    where
        F: FnOnce(i32, &CpuSet, &str) -> bool,
    {
        let thread_name = if has_thread_rules && trust_comm { comm } else { "" };
        let Some(result) = thread_affinity(pkg, thread_name, cfg) else {
            return false;
        };

        if !result.is_thread_rule {
            if let Some(old) = self.tasks.get(&tid) {
                if old.is_thread_rule {
                    return true;
                }
            }
        }

        self.tasks.remove(&tid);
        let dead = apply_fn(tid, &result.cpus, &result.cpuset_dir);
        if dead {
            return false;
        }

        self.tasks.insert(
            tid,
            TaskEntry {
                pid,
                cpus: result.cpus,
                cpuset_dir: result.cpuset_dir,
                is_thread_rule: result.is_thread_rule,
            },
        );
        true
    }

    /// 遍历 tasks 应用亲和性，返回 dead_tids 供 eBPF 调用方清理 APPLIED_MAP
    pub fn affinity_sync(&mut self, topo: &CpuTopology) -> Vec<i32> {
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
        for tid in &dead_tids {
            self.task_del(*tid);
        }
        dead_tids
    }
}

/// 将内核 comm 截断于首个 NUL 并 trim 尾部空白
pub fn comm_str(comm: &[u8; 16]) -> String {
    let end = comm.iter().position(|&b| b == 0).unwrap_or(16);
    std::str::from_utf8(&comm[..end])
        .unwrap_or("")
        .trim()
        .to_string()
}

/// 通过内核 comm 匹配配置包名，精确优先其次前缀后缀，与 BPF 双键逻辑一致
pub fn comm_to_pkg(comm: &str, cfg: &AppConfig) -> Option<String> {
    if cfg.pkgs.contains(comm) {
        return Some(comm.to_string());
    }
    if comm.len() >= 15 {
        for pkg in &cfg.pkgs {
            if pkg.starts_with(comm) {
                return Some(pkg.clone());
            }
        }
        for pkg in &cfg.pkgs {
            if pkg.ends_with(comm) {
                return Some(pkg.clone());
            }
        }
    }
    None
}



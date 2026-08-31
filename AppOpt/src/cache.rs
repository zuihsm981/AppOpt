use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};

use crate::apply_affinity::affinity_set;
use crate::config::AppConfig;
use crate::cpuset::{CpuSet, CpuTopology};
use crate::rule_match::{comm_to_pkg, thread_affinity};

/// 全局共享 pid→pkg 索引：由 ProcCache 的增删方法统一维护，
/// 供刷新率模块在 Binder 回调热路径 O(1) 查包名（替代原 packages.list 文件 I/O）。
/// 触发分离：CPU 模块只写，刷新率模块只读，互不通知。
pub static PID_PKG: LazyLock<Mutex<HashMap<i32, String>>> = LazyLock::new(|| Mutex::new(HashMap::new()));

/// 供刷新率模块查询 pid→pkg（只读共享索引）
pub fn pkg_lookup_pid(pid: i32) -> Option<String> {
    PID_PKG.lock().unwrap().get(&pid).cloned()
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
}

impl ProcCache {
    pub fn new() -> Self {
        Self {
            tasks: HashMap::new(),
        }
    }

    pub fn clear(&mut self) {
        self.tasks.clear();
        PID_PKG.lock().unwrap().clear();
    }

    pub fn task_del(&mut self, tid: i32) {
        self.tasks.remove(&tid);
    }

    /// comm 匹配包名，线程名时回退主线程条目
    pub fn pkg_lookup_comm(&self, pid: i32, comm: &str, cfg: &AppConfig) -> Option<String> {
        comm_to_pkg(pid, comm, cfg).or_else(|| self.tasks.get(&pid).map(|e| e.pkg.clone()))
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
            self.tasks.remove(&tid);
            return false;
        }

        self.tasks.insert(
            tid,
            TaskEntry {
                pid,
                pkg: pkg.to_string(),
                cpus: result.cpus,
                cpuset_dir: result.cpuset_dir,
                is_thread_rule: result.is_thread_rule,
            },
        );
        // 同步维护共享 pid→pkg 索引
        PID_PKG.lock().unwrap().insert(pid, pkg.to_string());
        true
    }

    /// 遍历 tasks 重新应用亲和性，清理已退出的条目（内部处理，不返回列表）
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
use std::collections::HashSet;
use std::fs;

use crate::apply_affinity::{read_cmdline, task_tids, tid_comm};
use crate::cache::ProcCache;
use crate::config::AppConfig;
use crate::rule_match::pkg_match;

/// /proc 轮询扫描状态
pub struct ProcScanState {
    pub cache: ProcCache,
    pub last_proc_count: i32,
    pub scan_all_proc: bool,
    pub tracked_pids: HashSet<i32>,
    pub last_proc_total: i32,
    pub force_affinity: bool,
}

impl ProcScanState {
    pub fn new() -> Self {
        Self {
            cache: ProcCache::new(),
            last_proc_count: 0,
            scan_all_proc: false,
            tracked_pids: HashSet::new(),
            last_proc_total: 0,
            force_affinity: false,
        }
    }
}

/// 全量扫描 /proc 重建 ProcCache
pub fn proc_scan(cfg: &AppConfig, state: &mut ProcScanState) -> usize {
    state.cache.clear();

    let proc_dir = match fs::read_dir("/proc") {
        Ok(d) => d,
        Err(_) => return 0,
    };

    let mut count: usize = 0;
    let mut current_proc_total: i32 = 0;

    for entry in proc_dir.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        let Ok(pid) = name_str.parse::<i32>() else {
            continue;
        };
        current_proc_total += 1;

        if !state.scan_all_proc && !state.tracked_pids.contains(&pid) {
            continue;
        }

        let Some(proc_name) = read_cmdline(pid) else {
            continue;
        };

        let (interested, has_thread_rules) = pkg_match(&proc_name, cfg);
        if !interested {
            continue;
        }

        // 仅 task 插入成功才缓存 pkgs 避免 pid 复用脏缓存
        let any_inserted = proc_tasks(pid, &proc_name, has_thread_rules, cfg, &mut state.cache);
        if any_inserted {
            state.cache.pkgs.insert(pid, (proc_name, has_thread_rules));
            count += 1;
        }
    }

    state.scan_all_proc = current_proc_total > state.last_proc_total;
    state.last_proc_total = current_proc_total;

    count
}

/// sysinfo 进程数变化或 kill(pid,0) 失败时触发 proc_scan
pub fn cache_sync(state: &mut ProcScanState, cfg: &AppConfig) {
    let mut need_reload = state.scan_all_proc;

    let mut info: libc::sysinfo = unsafe { std::mem::zeroed() };
    if unsafe { libc::sysinfo(&mut info) } != 0 {
        need_reload = true;
    } else {
        let current_proc_count = info.procs as i32;
        if current_proc_count > state.last_proc_count + 11 {
            need_reload = true;
        } else if current_proc_count > state.last_proc_count {
            state.force_affinity = true;
        }
        state.last_proc_count = current_proc_count;
    }

    if !need_reload {
        for &pid in state.tracked_pids.iter() {
            if unsafe { libc::kill(pid, 0) } != 0 {
                need_reload = true;
                break;
            }
        }
    }

    if need_reload {
        let new_count = proc_scan(cfg, state);

        state.tracked_pids.clear();
        state.tracked_pids.reserve(new_count);
        state
            .tracked_pids
            .extend(state.cache.tasks.values().map(|t| t.pid));

        state.force_affinity = true;
    }
}

/// 扫描 task 下全部 tid 仅填充缓存，返回 true 表示至少一个 tid 插入成功
fn proc_tasks(
    pid: i32,
    pkg: &str,
    has_thread_rules: bool,
    cfg: &AppConfig,
    cache: &mut ProcCache,
) -> bool {
    let Some(tids) = task_tids(pid) else { return false };
    let mut any_inserted = false;
    for tid in tids {
        let thread_name = if has_thread_rules {
            tid_comm(tid).unwrap_or_default()
        } else {
            String::new()
        };

        let inserted = cache.task_apply(tid, pid, pkg, &thread_name, has_thread_rules, cfg, true, |_, _, _| false);
        any_inserted |= inserted;
    }
    any_inserted
}

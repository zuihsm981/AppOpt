use std::collections::HashSet;
use std::fs;
use std::io::Write as _;

use crate::apply_affinity::{apply_thread_affinity, read_cmdline, read_thread_name_by_tid};
use crate::config::AppConfig;
use crate::cpuset::{CpuSet, CpuTopology};
use crate::rule_match::{check_pkg, resolve_thread_affinity};

pub struct ThreadInfo {
    pub tid: i32,
    pub cpuset_dir: String,
    pub cpus: CpuSet,
}

pub struct ProcessInfo {
    pub pid: i32,
    pub pkg: String,
    pub threads: Vec<ThreadInfo>,
}

pub struct ProcCache {
    pub procs: Vec<ProcessInfo>,
    pub last_proc_count: i32,
    pub scan_all_proc: bool,
    pub tracked_pids: HashSet<i32>,
    pub last_proc_total: i32,
}

/// 扫描 /proc，重建进程缓存，返回有效进程数量
pub fn proc_collect(cfg: &AppConfig, cache: &mut ProcCache) -> usize {
    let proc_dir = match fs::read_dir("/proc") {
        Ok(d) => d,
        Err(_) => return 0,
    };

    if cache.procs.capacity() < 2048 {
        cache.procs.reserve(2048 - cache.procs.capacity());
    }

    let mut count: usize = 0;
    let mut current_proc_total: i32 = 0;

    for entry in proc_dir.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        let Ok(pid) = name_str.parse::<i32>() else {
            continue;
        };
        current_proc_total += 1;

        if !cache.scan_all_proc && !cache.tracked_pids.contains(&pid) {
            continue;
        }

        let Some(proc_name) = read_cmdline(pid) else {
            continue;
        };

        if !cfg.pkgs.contains(&proc_name) {
            continue;
        }

        if count >= cache.procs.len() {
            cache.procs.push(ProcessInfo {
                pid: 0,
                pkg: String::new(),
                threads: Vec::new(),
            });
        }

        let proc = &mut cache.procs[count];
        proc.pid = pid;
        proc.pkg = proc_name.clone();
        proc.threads.clear();

        if !collect_threads_for_process(proc, cfg) || proc.threads.is_empty() {
            continue;
        }

        count += 1;
    }

    cache.scan_all_proc = current_proc_total > cache.last_proc_total;
    cache.last_proc_total = current_proc_total;

    count
}

/// 根据系统进程数变化或存活检查决定是否需要重新扫描
pub fn update_cache(cache: &mut ProcCache, cfg: &AppConfig, affinity_counter: &mut i32) {
    let mut need_reload = false;

    let mut info: libc::sysinfo = unsafe { std::mem::zeroed() };
    if unsafe { libc::sysinfo(&mut info) } != 0 {
        need_reload = true;
    } else {
        let current_proc_count = info.procs as i32;
        if current_proc_count > cache.last_proc_count + 11 {
            need_reload = true;
        } else if current_proc_count > cache.last_proc_count {
            *affinity_counter = 0;
        }
        cache.last_proc_count = current_proc_count;
    }

    if !need_reload {
        for proc in &cache.procs {
            if unsafe { libc::kill(proc.pid, 0) } != 0 {
                need_reload = true;
                break;
            }
        }
    }

    if need_reload {
        let new_count = proc_collect(cfg, cache);

        cache.procs.truncate(new_count);
        // 容量远超需时收缩
        if cache.procs.capacity() > new_count * 4 && new_count > 0 {
            cache.procs.shrink_to(new_count * 2);
        }

        cache.tracked_pids.clear();
        cache.tracked_pids.reserve(new_count);
        cache.tracked_pids.extend(cache.procs.iter().map(|p| p.pid));

        *affinity_counter = 0;
    }
}

/// 应用亲和性
pub fn apply_affinity(cache: &mut ProcCache, topo: &CpuTopology) {
    for proc in &cache.procs {
        for ti in &proc.threads {
            if apply_thread_affinity(ti.tid, &ti.cpus, &ti.cpuset_dir, topo) {
                cache.last_proc_count = 0;
            }
        }
    }
}

/// 扫描 /proc/<pid>/task 下所有线程，通过 resolve_thread_affinity 统一匹配并填充 ThreadInfo
fn collect_threads_for_process(proc: &mut ProcessInfo, cfg: &AppConfig) -> bool {
    let mut path_buf = [0u8; 32];
    let mut cur = std::io::Cursor::new(&mut path_buf[..]);
    write!(cur, "/proc/{}/task", proc.pid).ok();
    let path_len = cur.position() as usize;
    let task_path = std::str::from_utf8(&path_buf[..path_len]).unwrap();
    let task_dir = match fs::read_dir(task_path) {
        Ok(d) => d,
        Err(_) => return false,
    };

    const INITIAL_THREAD_CAP: usize = 512;
    if proc.threads.capacity() < INITIAL_THREAD_CAP {
        proc.threads
            .reserve(INITIAL_THREAD_CAP - proc.threads.capacity());
    }

    let (_, has_thread_rules) = check_pkg(&proc.pkg, cfg);

    for tent in task_dir.flatten() {
        let tname_str = tent.file_name();
        let tname_str = tname_str.to_string_lossy();
        let Ok(tid) = tname_str.parse::<i32>() else {
            continue;
        };

        let tname = if has_thread_rules {
            let Some(n) = read_thread_name_by_tid(tid) else {
                continue;
            };
            n
        } else {
            String::new()
        };

        if let Some((cpus, cpuset_dir)) = resolve_thread_affinity(&proc.pkg, &tname, cfg) {
            proc.threads.push(ThreadInfo {
                tid,
                cpuset_dir,
                cpus,
            });
        }
    }

    true
}

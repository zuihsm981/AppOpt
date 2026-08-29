use std::ffi::CString;

use crate::apply_affinity::read_cmdline;
use crate::MAX_THREAD_LEN;
use crate::config::AppConfig;
use crate::cpuset::{ensure_cpuset_dir, CpuSet};

/// 线程亲和性计算结果
pub struct AffinityResult {
    pub cpus: CpuSet,
    pub cpuset_dir: String,
    pub is_thread_rule: bool,
}

/// 线程规则 CPU 累加，无线程匹配走包级 fallback，仍无则返回 None
pub fn thread_affinity(
    pkg: &str,
    thread: &str,
    cfg: &AppConfig,
) -> Option<AffinityResult> {
    let mut cpus = CpuSet::new();
    let mut cpuset_dir = String::new();
    let mut matched = false;

    if !thread.is_empty() {
        for rule in &cfg.rules {
            if rule.pkg != pkg || rule.thread.is_empty() {
                continue;
            }
            if fnmatch_c(&rule.thread_pattern, thread) {
                cpus.or(&rule.cpus);
                matched = true;
            }
        }
        // 按合并后的 CPU 集合重算 cpuset 目录，确保与亲和性一致
        if matched {
            cpuset_dir = ensure_cpuset_dir(&cpus, &cfg.topo);
        }
    }

    if !matched {
        let mut fallback_seen = false;
        for rule in &cfg.rules {
            if rule.pkg != pkg || !rule.thread.is_empty() {
                continue;
            }
            cpus.or(&rule.cpus);
            if !fallback_seen {
                cpuset_dir = rule.cpuset_dir.clone();
                fallback_seen = true;
            } else {
                cpuset_dir.clear();
            }
        }
    }

    if cpus.count() == 0 {
        if cfg.has_thread_rules.contains(pkg) {
            return Some(AffinityResult {
                cpus: cfg.topo.present_cpus,
                cpuset_dir: String::new(),
                is_thread_rule: false,
            });
        }
        None
    } else {
        Some(AffinityResult {
            cpus,
            cpuset_dir,
            is_thread_rule: matched,
        })
    }
}

/// POSIX fnmatch 封装，需预转换为 CString
fn fnmatch_c(pattern: &CString, string: &str) -> bool {
    if string.len() >= MAX_THREAD_LEN {
        return false;
    }
    let mut buf = [0u8; MAX_THREAD_LEN];
    buf[..string.len()].copy_from_slice(string.as_bytes());
    unsafe { libc::fnmatch(pattern.as_ptr(), buf.as_ptr() as *const _, libc::FNM_NOESCAPE) == 0 }
}

/// 通过内核 comm 匹配配置包名。长 comm(≥15字节, 可能被 16 字节上限截断)时,
/// 通过 /proc/<pid>/cmdline 读取完整命令匹配白名单, 避免前缀/后缀误杀。
pub fn comm_to_pkg(pid: i32, comm: &str, cfg: &AppConfig) -> Option<String> {
    if cfg.pkgs.contains(comm) {
        return Some(comm.to_string());
    }
    if comm.len() >= 15 {
        // 优先用 cmdline 完整命令匹配 (comm 截断后前缀/后缀可能匹配到错误包)
        // 支持子进程: com.bilibili.app.in:download → com.bilibili.app.in
        if let Some(cmd) = read_cmdline(pid) {
            for pkg in &cfg.pkgs {
                if cmd == pkg.as_str() || cmd.starts_with(&format!("{}:", pkg)) {
                    return Some(pkg.clone());
                }
            }
        }
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
    // 8 字节键滑动匹配 (与内核 KPM whitelist_matched 一致):
    // 包名前 8 / 末 8 字节, 在 comm 上做 8 字节窗口滑动。
    // 覆盖子进程 comm 截断片段, 如 comm="bilibili.app.in:ijk" 含 "i.app.in" (包名末 8 字节)。
    if comm.len() >= 8 {
        let cb = comm.as_bytes();
        let max_pos = cb.len() - 8;
        for pkg in &cfg.pkgs {
            let pb = pkg.as_bytes();
            let prefix8 = pb.get(..8).unwrap_or(pb);
            let suffix8 = if pb.len() > 8 { pb.get(pb.len() - 8..).unwrap_or(pb) } else { prefix8 };
            for pos in 0..=max_pos {
                if &cb[pos..pos + 8] == prefix8 || &cb[pos..pos + 8] == suffix8 {
                    return Some(pkg.clone());
                }
            }
        }
    }
    // comm 含 ':' 是子进程特征 (如 "bilibili.app.in:ijk"): 取 ':' 前部分,
    // 若它是某个包名的子串则匹配 (覆盖 comm 截断导致 8 字节键不命中的情况)。
    if let Some(idx) = comm.find(':') {
        let base = &comm[..idx];
        if base.len() >= 3 {
            for pkg in &cfg.pkgs {
                if pkg.contains(base) {
                    return Some(pkg.clone());
                }
            }
        }
    }
    None
}
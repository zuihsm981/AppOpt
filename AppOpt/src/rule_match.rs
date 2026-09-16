use std::ffi::CString;

use crate::MAX_THREAD_LEN;
use crate::config::AppConfig;
use crate::cpuset::CpuSet;

/// 线程亲和性计算结果
#[derive(Clone)]
pub struct AffinityResult {
    pub cpus: CpuSet,
    pub cpuset_dir: String,
    /// uclamp 下限聚合 (0..=1024, -1 = 未设; 多规则取 max)
    pub util_min: i32,
    /// uclamp 上限聚合 (0..=1024, -1 = 未设; 多规则取 min)
    pub util_max: i32,
}

/// 聚合 uclamp: min 取最大, max 取最小 (保守区间)
fn fold_util(min: &mut i32, max: &mut i32, rmin: i32, rmax: i32) {
    if rmin >= 0 {
        *min = (*min).max(rmin);
    }
    if rmax >= 0 {
        *max = if *max < 0 { rmax } else { (*max).min(rmax) };
    }
}

/// 线程规则 CPU 累加，无线程匹配走包级 fallback，仍无则返回 None
pub fn thread_affinity(
    pkg: &str,
    thread: &str,
    cfg: &AppConfig,
) -> Option<AffinityResult> {
    let mut cpus = CpuSet::new();
    let mut cpuset_dir = String::new();
    let mut util_min = -1i32;
    let mut util_max = -1i32;
    let mut matched = false;

    if !thread.is_empty() {
        for rule in &cfg.rules {
            if rule.pkg != pkg || rule.thread.is_empty() {
                continue;
            }
            if fnmatch_c(&rule.thread_pattern, thread) {
                cpus.or(&rule.cpus);
                fold_util(&mut util_min, &mut util_max, rule.util_min, rule.util_max);
                matched = true;
            }
        }
        // cpuset 目录由调用方 (CpuAffinity) 按合并 CPU 集合缓存 ensure, 避免每线程重复建目录
    }

    if !matched {
        let mut fallback_seen = false;
        for rule in &cfg.rules {
            if rule.pkg != pkg || !rule.thread.is_empty() {
                continue;
            }
            cpus.or(&rule.cpus);
            fold_util(&mut util_min, &mut util_max, rule.util_min, rule.util_max);
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
                util_min: -1,
                util_max: -1,
            });
        }
        None
    } else {
        Some(AffinityResult { cpus, cpuset_dir, util_min, util_max })
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


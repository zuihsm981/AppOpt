use crate::common::fnmatch_c;
use crate::config::AppConfig;
use crate::cpuset::CpuSet;

/// 返回 (包名是否匹配, 是否存在线程规则)
pub fn check_pkg(pkg: &str, cfg: &AppConfig) -> (bool, bool) {
    let interested = cfg.pkgs.contains(pkg);
    (interested, interested && cfg.has_thread_rules.contains(pkg))
}

/// 累加匹配的线程规则 CPU，无线程规则匹配则累加包级别 fallback
pub fn resolve_thread_affinity(
    pkg: &str,
    thread: &str,
    cfg: &AppConfig,
) -> Option<(CpuSet, String)> {
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
                cpuset_dir = rule.cpuset_dir.clone();
                matched = true;
            }
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
        None
    } else {
        Some((cpus, cpuset_dir))
    }
}

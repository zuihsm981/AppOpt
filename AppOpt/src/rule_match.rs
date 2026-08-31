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

/// CPU 规则扫描仍按原有 cfg.pkgs 匹配；默认 launcher 的 PID 映射只在
/// `ebpf_mode::full_scan` 中额外建立，不在此处扩大 CPU 规则匹配范围。

/// 低成本 comm 匹配。
/// 返回 None 时不代表一定不是目标包，调用方仍可按需查询 cmdline。
pub(crate) fn comm_fast_to_pkg(comm: &str, cfg: &AppConfig) -> Option<String> {
    // 未截断的完整包名。
    if cfg.pkgs.contains(comm) {
        return Some(comm.to_string());
    }

    // 完整包名子进程，例如 pkg:remote；只按冒号前的完整包名匹配。
    if let Some(idx) = comm.find(':') {
        let base = &comm[..idx];
        if cfg.pkgs.contains(base) {
            return Some(base.to_string());
        }
    }
    None
}

/// 仅用于 cmdline 不可读时的安全截断回退。
/// 必须只有一个包名拥有该明确前缀，避免同一截断 comm 对应多个包。
fn comm_prefix_fallback(comm: &str, cfg: &AppConfig) -> Option<String> {
    if comm.len() < 15 {
        return None;
    }
    let mut found: Option<&String> = None;
    for pkg in &cfg.pkgs {
        if !pkg.starts_with(comm) {
            continue;
        }
        if found.is_some() {
            return None; // 前缀歧义，不猜测
        }
        found = Some(pkg);
    }
    found.cloned()
}

/// 通过 comm 识别配置包名。
///
/// 每个未知 PID 最多执行一次 cmdline 读取（由 ProcCache 缓存结果）；
/// cmdline 可读时以完整包名为唯一权威，comm 只在 cmdline 不可读时按
/// 明确的 15 字节截断前缀回退。不再使用 8 字节滑动键，避免
/// air.tv.douyu.android 的 ".android" 键误命中 com.android.* 进程。
pub fn comm_to_pkg(pid: i32, comm: &str, cfg: &AppConfig) -> Option<String> {
    let fast = comm_fast_to_pkg(comm, cfg);

    // 即使 comm 看起来像包名，也优先用进程 cmdline 校验，防止伪造/误命名。
    if let Some(cmd) = read_cmdline(pid) {
        for pkg in &cfg.pkgs {
            if cmd == pkg.as_str()
                || cmd.strip_prefix(pkg.as_str()).is_some_and(|rest| rest.starts_with(':'))
            {
                return Some(pkg.clone());
            }
        }
        return None;
    }

    // 进程已退出或 cmdline 不可读时，仅保留安全的完整 comm/截断前缀回退。
    fast.or_else(|| comm_prefix_fallback(comm, cfg))
}
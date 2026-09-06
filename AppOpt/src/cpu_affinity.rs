//! CPU 亲和性模块（binder 前台回调触发, 无周期扫描）
//!
//! 设计:
//!   - 触发: IProcessObserver binder 前台回调 (与刷新率同源)。refresh 线程收到
//!     fg pid+uid 后把 uid 转发本模块 (CPU_FG_TX); 0 表示启动/配置变更 → 全量应用一次。
//!   - 归因: 按 uid 枚举 /proc (Uid: 字段) → 该应用全部进程 (主进程 + pkg: 子进程
//!     共享同一 uid), 取 cmdline 归因目标包 (精确 / 目标包:子进程)。
//!   - 应用: 该 uid 全部进程的全部线程 (/proc/<pid>/task) → thread_affinity →
//!     applied_set + affinity_set。
//!   - 清理: 每次触发顺带删除已消失 tid 的 APPLIED 条目, 防止 kprobe 误抓
//!     被回收的 tid (tid 复用 → 错误覆盖新进程亲和性)。
//!   - 内核只保留: applied 表 (ctl0) + sched_setaffinity kprobe 强制 +
//!     input kprobe (刷新率)。进程事件探针对本模块无意义。
//!
//! 为什么按 uid: pid 归因对 zygote spawn 子进程 (pkg:child, 不同 tgid) 有结构性
//! 盲区; 同一应用的主进程与所有子进程共享 uid, binder 回调直接携带 uid, 一次
//! /proc 按 uid 过滤即完整覆盖, 无 pid 家族匹配/晚起子进程问题。

use std::collections::HashMap;
use std::ffi::CString;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::Duration;

use crate::config::AppConfig;
use crate::ebpf_mode::KpmHandle;

/// 前台回调后延迟枚举时长: 冷启动子进程 (pkg:child) 常在回调后 0.5~2s 内 spawn,
/// 延迟 2s 后按 uid 枚举一次覆盖冷启动窗口 (主进程回调时已在, 无影响)。
const ENUM_DELAY: Duration = Duration::from_secs(2);

/// CPU worker 消息
pub enum CpuMsg {
    /// 主线程判定命中 CPU 表且为冷启动后, 下发包名 → 延迟应用亲和性
    ApplyPkg(String),
    /// 全量应用 (启动 / 配置变更)
    ApplyAll,
}

/// 全局投递通道: refresh 线程转发 fg uid + 冷/热标志
static CPU_FG_TX: OnceLock<Mutex<mpsc::Sender<CpuMsg>>> = OnceLock::new();

pub fn cpu_fg_tx() -> Option<mpsc::Sender<CpuMsg>> {
    CPU_FG_TX
        .get()
        .and_then(|m| m.lock().ok())
        .map(|g| g.clone())
}

/// 请求一次全量应用 (启动 / 配置变更), 不阻塞
pub fn apply_all_now() {
    if let Some(tx) = cpu_fg_tx() {
        let _ = tx.send(CpuMsg::ApplyAll);
    }
}

/// CPU 亲和性执行器 (worker 线程独占)
pub struct CpuAffinity {
    bpf: KpmHandle,
    /// 已管理线程 tid → 包名 (用于清理已退出线程)
    managed: HashMap<i32, String>,
}

impl CpuAffinity {
    pub fn new() -> Self {
        Self { bpf: KpmHandle::new(), managed: HashMap::new() }
    }

    /// 全量应用 (启动 / 配置变更), 非周期; 不做 cleanup (清理只在触发枚举时进行)
    pub fn apply_all(&mut self, cfg: &AppConfig) -> usize {
        let mut seen: HashMap<String, i32> = HashMap::new(); // pkg -> 任一 pid
        if let Ok(entries) = std::fs::read_dir("/proc") {
            for e in entries.flatten() {
                let Ok(pid) = e.file_name().to_string_lossy().parse::<i32>() else { continue };
                if pid <= 0 {
                    continue;
                }
                if let Some(pkg) = resolve_pkg(pid, cfg) {
                    seen.entry(pkg).or_insert(pid);
                }
            }
        }
        let keys: Vec<String> = seen.keys().cloned().collect();
        for pkg in keys {
            self.apply_pkg(&pkg, cfg);
        }
        seen.len()
    }

    /// 应用一个包的全部进程 (主进程 + pkg: 子进程) 的全部线程
    fn apply_pkg(&mut self, pkg: &str, cfg: &AppConfig) {
        let mut pids: Vec<i32> = Vec::new();
        if let Ok(entries) = std::fs::read_dir("/proc") {
            for e in entries.flatten() {
                let Ok(p) = e.file_name().to_string_lossy().parse::<i32>() else { continue };
                if p <= 0 {
                    continue;
                }
                if crate::apply_affinity::read_cmdline(p).is_some_and(|c| same_pkg(&c, pkg)) {
                    pids.push(p);
                }
            }
        }
        self.apply_tids(&pids, pkg, cfg);
    }

    /// 对给定进程集合的全部线程套用规则并应用
    fn apply_tids(&mut self, pids: &[i32], pkg: &str, cfg: &AppConfig) {
        let has_thread_rules = cfg.has_thread_rules.contains(pkg);
        for p in pids {
            let Some(tids) = crate::apply_affinity::task_tids(*p) else { continue };
            for tid in tids {
                let tname = if has_thread_rules {
                    crate::apply_affinity::tid_comm(tid).unwrap_or_default()
                } else {
                    String::new()
                };
                let Some(rule) = crate::rule_match::thread_affinity(pkg, &tname, cfg) else {
                    continue;
                };
                self.bpf.applied_set(tid, rule.cpus.bits[0]);
                let _ = crate::apply_affinity::affinity_set(tid, &rule.cpus, &rule.cpuset_dir, &cfg.topo);
                self.managed.insert(tid, pkg.to_string());
            }
        }
    }

    /// 删除已消失线程的 APPLIED 条目 (防 tid 回收后 kprobe 误抓)
    fn cleanup_dead(&mut self) {
        let dead: Vec<i32> = self
            .managed
            .keys()
            .copied()
            .filter(|t| crate::apply_affinity::tid_comm(*t).is_none())
            .collect();
        for t in dead {
            self.bpf.applied_del(t);
            self.managed.remove(&t);
        }
    }

    /// 常驻线程入口 (纯事件驱动, 无重试/无周期)
    pub fn run(mut self, rx: mpsc::Receiver<CpuMsg>, stop: Arc<AtomicBool>) {
        let name = CString::new("CpuAffinity").unwrap();
        unsafe {
            libc::pthread_setname_np(libc::pthread_self(), name.as_ptr());
        }
        while !stop.load(Ordering::Relaxed) {
            match rx.recv_timeout(Duration::from_millis(300)) {
                Ok(CpuMsg::ApplyAll) => {
                    let cfg = crate::lock_ignore_poison(&crate::config::CURRENT_CONFIG).clone();
                    if let Some(cfg) = cfg {
                        self.apply_all(&cfg);
                    }
                }
                Ok(CpuMsg::ApplyPkg(pkg)) => {
                    // 冷启动包名: 延迟 2s 覆盖冷启动子进程窗口后按包应用
                    thread::sleep(ENUM_DELAY);
                    let cfg = crate::lock_ignore_poison(&crate::config::CURRENT_CONFIG).clone();
                    if let Some(cfg) = cfg {
                        self.apply_pkg(&pkg, &cfg);
                    }
                    // 触发枚举时清理: 删已消失 tid 的 APPLIED 条目, 防 tid 回收后 kprobe 误抓
                    self.cleanup_dead();
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
        self.bpf.applied_clear();
    }
}

/// 启动 CPU worker 线程 (KPM 模式下调用一次); 返回 false 表示模块不可用
pub fn start() -> bool {
    if CPU_FG_TX.get().is_some() {
        return true;
    }
    // 校验 KPM 可 ping
    let probe = KpmHandle::new();
    if !probe.verify_loaded() {
        return false;
    }
    let (tx, rx) = mpsc::channel::<CpuMsg>();
    let _ = CPU_FG_TX.set(Mutex::new(tx));
    let cpu = CpuAffinity::new();
    thread::spawn(move || cpu.run(rx, Arc::new(AtomicBool::new(false))));
    true
}

/// cmdline 归因: 目标包(精确) 或 目标包:子进程
fn resolve_pkg(pid: i32, cfg: &AppConfig) -> Option<String> {
    let cmd = crate::apply_affinity::read_cmdline(pid)?;
    cfg.target_pkgs
        .iter()
        .find(|pkg| same_pkg(&cmd, pkg))
        .cloned()
}

/// cmdline 是否属于该包 (等于 或 pkg: 子进程)
fn same_pkg(cmd: &str, pkg: &str) -> bool {
    cmd == pkg || cmd.strip_prefix(pkg).is_some_and(|r| r.starts_with(':'))
}
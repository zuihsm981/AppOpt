//! CPU 亲和性模块（binder 前台回调触发, 无周期扫描）
//!
//! 设计:
//!   - 触发: IProcessObserver binder 前台回调 (与刷新率同源)。refresh 线程收到
//!     fg pid 后转发本模块 (CPU_FG_TX); pid=0 表示启动/配置变更 → 全量应用一次。
//!   - 归因: /proc/<pid>/cmdline → 目标包(精确) 或 目标包:子进程。
//!   - 应用: 该包"家族"全部进程 (fg pid + /proc 中同包名进程) 的全部线程
//!     (/proc/<pid>/task) → thread_affinity → applied_set + affinity_set。
//!   - 清理: 每次触发顺带删除已消失 tid 的 APPLIED 条目, 防止 kprobe 误抓
//!     被回收的 tid (tid 复用 → 错误覆盖新进程亲和性)。
//!   - 内核只保留: applied 表 (ctl0) + sched_setaffinity kprobe 强制 +
//!     input kprobe (刷新率)。进程事件探针对本模块无意义。
//!
//! 为什么不再用进程事件链: zygote 继承线程(HeapTaskDaemon 等)与 zygote spawn
//! 子进程(pkg:child)在事件归因上有结构性盲区(pid=zygote / comm 截断 / 事件
//! 竞态), 补丁无法收敛; binder 前台回调 + /proc 枚举是唯一可靠闭环。

use std::collections::HashMap;
use std::ffi::CString;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::Duration;

use crate::config::AppConfig;
use crate::ebpf_mode::KpmHandle;

/// 全局投递通道: refresh 线程转发 fg pid (pid=0 → 全量应用一次)
static CPU_FG_TX: OnceLock<Mutex<mpsc::Sender<i32>>> = OnceLock::new();

pub fn cpu_fg_tx() -> Option<mpsc::Sender<i32>> {
    CPU_FG_TX
        .get()
        .and_then(|m| m.lock().ok())
        .map(|g| g.clone())
}

/// 请求一次全量应用 (启动 / 配置变更), 不阻塞
pub fn apply_all_now() {
    if let Some(tx) = cpu_fg_tx() {
        let _ = tx.send(0);
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

    /// binder 前台回调处理: pid 归因 → 应用该包家族全部线程
    pub fn on_fg(&mut self, pid: i32, cfg: &AppConfig) -> bool {
        let Some(pkg) = resolve_pkg(pid, cfg) else { return false };
        self.apply_family(&pkg, pid, cfg);
        self.cleanup_dead();
        true
    }

    /// 全量应用 (启动 / 配置变更), 非周期
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
            let pid = seen[&pkg];
            self.apply_family(&pkg, pid, cfg);
        }
        self.cleanup_dead();
        seen.len()
    }

    /// 应用一个包的全部进程 (fg pid + /proc 中同包名进程, 含 pkg: 子进程)
    fn apply_family(&mut self, pkg: &str, fg_pid: i32, cfg: &AppConfig) {
        let mut pids: Vec<i32> = vec![fg_pid];
        if let Ok(entries) = std::fs::read_dir("/proc") {
            for e in entries.flatten() {
                let Ok(p) = e.file_name().to_string_lossy().parse::<i32>() else { continue };
                if p <= 0 || p == fg_pid {
                    continue;
                }
                if crate::apply_affinity::read_cmdline(p).is_some_and(|c| same_pkg(&c, pkg)) {
                    pids.push(p);
                }
            }
        }
        let has_thread_rules = cfg.has_thread_rules.contains(pkg);
        for p in pids {
            let Some(tids) = crate::apply_affinity::task_tids(p) else { continue };
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

    /// 常驻线程入口
    pub fn run(mut self, rx: mpsc::Receiver<i32>, stop: Arc<AtomicBool>) {
        let name = CString::new("CpuAffinity").unwrap();
        unsafe {
            libc::pthread_setname_np(libc::pthread_self(), name.as_ptr());
        }
        // 未归因 pid 的有界重试: 首次打开应用时 binder 回调可能早于 cmdline 就绪
        // (冷启动竞态), on_fg 归因失败则挂起重试, 150ms × 20 ≈ 3s 后放弃。
        let mut pending: Option<(i32, u32)> = None;
        while !stop.load(Ordering::Relaxed) {
            let timeout = if pending.is_some() {
                Duration::from_millis(150)
            } else {
                Duration::from_millis(300)
            };
            match rx.recv_timeout(timeout) {
                Ok(0) => {
                    pending = None;
                    let cfg = crate::lock_ignore_poison(&crate::config::CURRENT_CONFIG).clone();
                    if let Some(cfg) = cfg {
                        self.apply_all(&cfg);
                    }
                }
                Ok(pid) if pid > 0 => {
                    let cfg = crate::lock_ignore_poison(&crate::config::CURRENT_CONFIG).clone();
                    if let Some(cfg) = cfg {
                        if !self.on_fg(pid, &cfg) {
                            pending = Some((pid, 0));
                        } else {
                            pending = None;
                        }
                    }
                }
                Ok(_) => {}
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    if let Some((pid, tries)) = pending.take() {
                        if tries < 20 {
                            let cfg =
                                crate::lock_ignore_poison(&crate::config::CURRENT_CONFIG).clone();
                            if let Some(cfg) = cfg {
                                if !self.on_fg(pid, &cfg) {
                                    pending = Some((pid, tries + 1));
                                }
                            }
                        }
                    }
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
        // 退出: 清空 APPLIED 表
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
    let (tx, rx) = mpsc::channel::<i32>();
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
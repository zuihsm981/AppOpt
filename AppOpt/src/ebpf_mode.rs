use std::collections::{HashMap, HashSet};
use std::ffi::CString;
use std::fs;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use aya::{programs::TracePoint as AyaTracePoint, Ebpf, EbpfLoader};

use crate::apply_affinity::{
    apply_thread_affinity, read_cmdline, read_thread_name_by_tid, refresh_process_rules,
    ThreadNameCache,
};
use crate::common::{current_time_secs, lock_ignore_poison, EBPF_EVENT_EXEC};
use crate::config::{AppConfig, CURRENT_CONFIG};
use crate::rule_match::{check_pkg, resolve_thread_affinity};

/// eBPF 进程事件（布局需与 appopt-ebpf 内核态 `ProcEvent` 一致）
#[repr(C)]
#[derive(Clone, Copy)]
pub struct EbpfProcEvent {
    pub pid: i32,        // FORK: child_pid；EXEC: tgid
    pub tid: i32,        // FORK: child_pid；EXEC: pid
    pub child_pid: i32,  // FORK: 子进程PID；EXEC: 0
    pub comm: [u8; 16],  // FORK: child_comm；EXEC: bpf_get_current_comm()
    pub event_type: u32,
}

pub struct ProcessScanState {
    pub initial_scan_done: bool,
    pub last_scan_time: i64,
    pub tid_cache: ThreadNameCache,
}

impl ProcessScanState {
    fn new(now: i64) -> Self {
        ProcessScanState {
            initial_scan_done: false,
            last_scan_time: now,
            tid_cache: ThreadNameCache::new(now),
        }
    }
}

pub struct EbpfRuntime {
    pub process_cache: HashMap<i32, ProcessScanState>,
    pub last_dead_cleanup_time: i64,
}

pub struct EbpfState {
    pub event_rx: mpsc::Receiver<EbpfProcEvent>,
    pub _reader_thread: thread::JoinHandle<()>,
    pub bpf: Ebpf,
    pub runtime: EbpfRuntime,
}

/// 检测 eBPF 支持
pub fn check_ebpf_support() -> bool {
    if fs::metadata("/sys/kernel/btf/vmlinux").is_err() {
        return false;
    }
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.join("AppOpt-ebpf")))
        .is_some_and(|path| path.exists())
}

fn attach_tracepoint(bpf: &mut Ebpf, category: &str, name: &str) -> bool {
    let Some(prog) = bpf.program_mut(name) else {
        eprintln!("eBPF: 未找到 {} 程序", name);
        return false;
    };
    let Ok(tp): Result<&mut AyaTracePoint, _> = prog.try_into() else {
        eprintln!("eBPF: {} 类型转换失败", name);
        return false;
    };
    if let Err(e) = tp.load() {
        eprintln!("eBPF: {} 加载失败 ({})", name, e);
        return false;
    }
    if let Err(e) = tp.attach(category, name) {
        eprintln!("eBPF: {} 附加失败 ({})", name, e);
        return false;
    }
    true
}

/// 构建白名单条目：每个包名生成前 8 字节前缀键和末 8 字节后缀键
fn build_target_entries<'a, I: IntoIterator<Item = &'a String>>(pkgs: I) -> Vec<[u8; 8]> {
    let mut entries: Vec<[u8; 8]> = Vec::new();
    for pkg in pkgs {
        let bytes = pkg.as_bytes();
        if bytes.is_empty() {
            continue;
        }

        let mut prefix_key = [0u8; 8];
        let prefix_len = bytes.len().min(8);
        prefix_key[..prefix_len].copy_from_slice(&bytes[..prefix_len]);
        entries.push(prefix_key);

        if bytes.len() > 8 {
            let mut suffix_key = [0u8; 8];
            let start = bytes.len() - 8;
            suffix_key.copy_from_slice(&bytes[start..]);
            entries.push(suffix_key);
        }
    }
    entries.sort();
    entries.dedup();
    entries
}

/// 配置 FORK 白名单：写入 `TARGET_COMM_MAP`，配置更新时先清理旧条目
pub fn setup_target_map(bpf: &mut Ebpf, pkgs: &HashSet<String>) {
    let Some(map) = bpf.map_mut("TARGET_COMM_MAP") else {
        eprintln!("eBPF: 未找到 TARGET_COMM_MAP");
        return;
    };
    let mut target_map = match aya::maps::HashMap::<_, [u8; 8], u32>::try_from(map) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("eBPF: TARGET_COMM_MAP 类型转换失败 ({})", e);
            return;
        }
    };

    // 用 keys() + remove() 清理旧条目
    let old_keys: Vec<[u8; 8]> = target_map.keys().filter_map(|r| r.ok()).collect();
    for key in &old_keys {
        let _ = target_map.remove(key);
    }

    let entries = build_target_entries(pkgs.iter());

    let mut count = 0;
    for key in &entries {
        match target_map.insert(key, 1, 0) {
            Ok(_) => count += 1,
            Err(e) => eprintln!("eBPF: 白名单条目插入失败 ({})，map 可能已满", e),
        }
    }

    println!(
        "eBPF: FORK/EXEC 白名单已配置，{} 个包名 > {} 条匹配规则",
        pkgs.len(),
        count
    );
}

/// 初始化 eBPF，成功返回 `EbpfState`，失败返回 None（供调用方回退到 /proc 轮询）
pub fn try_init_ebpf() -> Option<EbpfState> {
    if !check_ebpf_support() {
        eprintln!("eBPF: 内核不支持（缺少 BTF），回退到 /proc 轮询");
        return None;
    }

    let ebpf_path = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.join("AppOpt-ebpf")))?;

    if !ebpf_path.exists() {
        eprintln!("eBPF: 未找到 {}，回退到 /proc 轮询", ebpf_path.display());
        return None;
    }

    let ebpf_data = match fs::read(&ebpf_path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!(
                "eBPF: 读取 {} 失败 ({})，回退到 /proc 轮询",
                ebpf_path.display(),
                e
            );
            return None;
        }
    };

    if ebpf_data.is_empty() {
        eprintln!("eBPF: {} 文件为空，回退到 /proc 轮询", ebpf_path.display());
        return None;
    }

    println!(
        "eBPF: 从 {} 加载程序 ({} bytes)",
        ebpf_path.display(),
        ebpf_data.len()
    );

    // 按配置包名数量动态倍增设置 TARGET_COMM_MAP 容量
    let pkgs = lock_ignore_poison(&CURRENT_CONFIG)
        .as_ref()
        .map(|cfg| cfg.pkgs.clone())
        .unwrap_or_default();
    let capacity = build_target_entries(pkgs.iter())
        .len()
        .max(16)
        .next_power_of_two() as u32;

    let mut loader = EbpfLoader::new();
    loader.set_max_entries("TARGET_COMM_MAP", capacity);
    let mut bpf = match loader.load(&ebpf_data) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("eBPF: 加载失败 ({})，回退到 /proc 轮询", e);
            return None;
        }
    };

    if !attach_tracepoint(&mut bpf, "sched", "sched_process_fork") {
        eprintln!("eBPF: sched_process_fork 是必需的，回退到 /proc 轮询");
        return None;
    }
    if !attach_tracepoint(&mut bpf, "sched", "sched_process_exec") {
        eprintln!("eBPF: sched_process_exec 是必需的，回退到 /proc 轮询");
        return None;
    }

    let ring_buf = match bpf.take_map("EVENTS") {
        Some(map) => match aya::maps::RingBuf::try_from(map) {
            Ok(rb) => rb,
            Err(e) => {
                eprintln!("eBPF: EVENTS map 类型转换失败 ({})，回退到 /proc 轮询", e);
                return None;
            }
        },
        None => {
            eprintln!("eBPF: 未找到 EVENTS map，回退到 /proc 轮询");
            return None;
        }
    };

    let (tx, rx) = mpsc::channel::<EbpfProcEvent>();
    let reader_thread = thread::spawn(move || {
        ebpf_reader_thread(ring_buf, tx);
    });

    println!("eBPF: 初始化成功，使用事件驱动模式");

    let now = current_time_secs();
    Some(EbpfState {
        event_rx: rx,
        _reader_thread: reader_thread,
        bpf,
        runtime: EbpfRuntime {
            process_cache: HashMap::new(),
            last_dead_cleanup_time: now,
        },
    })
}

/// RingBuf 读取线程：阻塞读取事件并通过 mpsc 通道发送给主循环
fn ebpf_reader_thread(
    mut ring_buf: aya::maps::RingBuf<aya::maps::MapData>,
    tx: mpsc::Sender<EbpfProcEvent>,
) {
    let name = CString::new("EbpfReader").unwrap_or_else(|_| CString::new("ebpf").unwrap());
    unsafe {
        libc::pthread_setname_np(libc::pthread_self(), name.as_ptr());
    }

    loop {
        match ring_buf.next() {
            Some(item) => {
                let bytes: &[u8] = &item;
                if bytes.len() >= std::mem::size_of::<EbpfProcEvent>() {
                    let event: EbpfProcEvent =
                        unsafe { std::ptr::read_unaligned(bytes.as_ptr() as *const EbpfProcEvent) };
                    if tx.send(event).is_err() {
                        break;
                    }
                }
            }
            None => {
                thread::sleep(Duration::from_millis(50));
            }
        }
    }
}

/// 处理 eBPF 事件
pub fn handle_ebpf_event(
    event: &EbpfProcEvent,
    cfg: &AppConfig,
    runtime: &mut EbpfRuntime,
    sleep_interval: u64,
) {
    let ev_type = event.event_type;
    let pid = event.pid;
    let tid = event.tid;
    let now = current_time_secs();

    let Some(pkg) = read_cmdline(pid).or_else(|| read_thread_name_by_tid(pid)) else {
        return;
    };

    let (interested, has_thread_rules) = check_pkg(&pkg, cfg);
    if !interested {
        return;
    }

    let t_name = if has_thread_rules {
        read_thread_name_by_tid(tid).unwrap_or_default()
    } else {
        String::new()
    };

    let proc = runtime
        .process_cache
        .entry(pid)
        .or_insert_with(|| ProcessScanState::new(now));

    // EXEC：重置扫描状态并清空 tid 名缓存（exec 替换进程映像，线程名随之变化）
    if ev_type == EBPF_EVENT_EXEC {
        proc.initial_scan_done = false;
        proc.tid_cache.clear();
    }

    if !proc.initial_scan_done || now - proc.last_scan_time >= sleep_interval as i64 {
        let tid_cache = &mut proc.tid_cache;
        refresh_process_rules(pid, &pkg, cfg, has_thread_rules, tid_cache, now);
        proc.initial_scan_done = true;
        proc.last_scan_time = now;
    }

    // 始终对当前 TID 应用亲和性
    if let Some((cpus, cpuset_dir)) = resolve_thread_affinity(&pkg, &t_name, cfg) {
        apply_thread_affinity(tid, &cpus, &cpuset_dir, &cfg.topo);
    }
}

/// 周期性全量扫描 proc，配置更新时调用以发现新加入白名单的运行中进程
pub fn periodic_full_scan(cfg: &AppConfig, runtime: &mut EbpfRuntime) {
    let now = current_time_secs();

    // 配置更新，清空所有进程的扫描状态与 tid 名缓存
    for proc in runtime.process_cache.values_mut() {
        proc.initial_scan_done = false;
        proc.last_scan_time = 0;
        proc.tid_cache.clear();
    }

    let proc_dir = match fs::read_dir("/proc") {
        Ok(d) => d,
        Err(_) => return,
    };

    for entry in proc_dir.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        let Ok(pid) = name_str.parse::<i32>() else {
            continue;
        };

        let Some(pkg) = read_cmdline(pid).or_else(|| read_thread_name_by_tid(pid)) else {
            continue;
        };

        let (interested, has_thread_rules) = check_pkg(&pkg, cfg);
        if !interested {
            continue;
        }

        let proc = runtime
            .process_cache
            .entry(pid)
            .or_insert_with(|| ProcessScanState::new(now));

        let tid_cache = &mut proc.tid_cache;
        refresh_process_rules(pid, &pkg, cfg, has_thread_rules, tid_cache, now);
        proc.initial_scan_done = true;
        proc.last_scan_time = now;
    }
}

/// 刷新已缓存进程，清理已退出或不匹配的进程并重应用亲和性
///
/// 新进程由 eBPF 事件驱动发现，配置更新走 periodic_full_scan 路径。
/// 同时承担死进程清理职责（更新 last_dead_cleanup_time），避免与独立清理路径重复扫描
pub fn refresh_cached_processes(cfg: &AppConfig, runtime: &mut EbpfRuntime) {
    let now = current_time_secs();
    let pids: Vec<i32> = runtime.process_cache.keys().copied().collect();
    let mut stale: Vec<i32> = Vec::new();

    for &pid in &pids {
        if unsafe { libc::kill(pid, 0) } != 0 {
            stale.push(pid);
            continue;
        }
        let Some(pkg) = read_cmdline(pid).or_else(|| read_thread_name_by_tid(pid)) else {
            stale.push(pid);
            continue;
        };
        let (interested, has_thread_rules) = check_pkg(&pkg, cfg);
        if !interested {
            stale.push(pid);
            continue;
        }
        if let Some(proc) = runtime.process_cache.get_mut(&pid) {
            let tid_cache = &mut proc.tid_cache;
            refresh_process_rules(pid, &pkg, cfg, has_thread_rules, tid_cache, now);
        }
    }

    for pid in stale {
        runtime.process_cache.remove(&pid);
    }

    runtime.last_dead_cleanup_time = now;
}

use std::collections::{HashMap, HashSet};
use std::ffi::CString;
use std::fs;
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::mpsc;
use std::thread;

use aya::maps::{Array as AyaArray, HashMap as AyaHashMap};
use aya::{programs::TracePoint as AyaTracePoint, Ebpf, EbpfLoader, Pod};

use crate::apply_affinity::{affinity_set, read_cmdline, task_tids, tid_comm};
use crate::cache::{comm_str, ProcCache};
use crate::config::{AppConfig, CURRENT_CONFIG};
use crate::cpuset::CpuSet;
use crate::rule_match::pkg_match;

/// eBPF 进程事件，布局需与内核态 ProcEvent 一致
#[repr(C)]
#[derive(Clone, Copy)]
pub struct EbpfProcEvent {
    pub pid: i32,
    pub tid: i32,
    pub comm: [u8; 16],
    pub event_type: u32,
}

pub const EBPF_EVENT_FORK: u32 = 1;
pub const EBPF_EVENT_EXEC: u32 = 2;
pub const EBPF_EVENT_RENAME: u32 = 3;
pub const EBPF_EVENT_EXIT: u32 = 4;

/// 用户态注入内核的 tracepoint 字段偏移，布局需与内核态 TracepointOffsets 一致
#[repr(C)]
#[derive(Clone, Copy)]
struct EbpfOffsets {
    fork_child_pid: u32,
    fork_child_comm: u32,
    rename_newcomm: u32,
}

unsafe impl Pod for EbpfOffsets {}

pub struct EbpfState {
    pub event_rx: mpsc::Receiver<EbpfProcEvent>,
    pub reader_thread: Option<thread::JoinHandle<()>>,
    pub bpf: Ebpf,
    pub cache: ProcCache,
    pub wakeup_fd: RawFd,
    pub comm_capacity: u32,
}

impl Drop for EbpfState {
    fn drop(&mut self) {
        // 写 eventfd 唤醒 reader 线程的 epoll_wait 后 join 等待退出
        if self.wakeup_fd >= 0 {
            let val: u64 = 1;
            unsafe {
                libc::write(self.wakeup_fd, &val as *const u64 as *const _, 8);
            }
        }
        if let Some(handle) = self.reader_thread.take() {
            let _ = handle.join();
        }
        if self.wakeup_fd >= 0 {
            unsafe { libc::close(self.wakeup_fd); }
        }
    }
}

/// 检测 eBPF 支持，BTF 与 AppOpt-ebpf 二进制均存在才返回 true
pub fn ebpf_probe() -> bool {
    if fs::metadata("/sys/kernel/btf/vmlinux").is_err() {
        return false;
    }
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.join("AppOpt-ebpf")))
        .is_some_and(|path| path.exists())
}

fn attach_tracepoint(bpf: &mut Ebpf, category: &str, name: &str, required: bool) -> bool {
    let Some(prog) = bpf.program_mut(name) else {
        if required {
            eprintln!("eBPF: 未找到 {} 程序", name);
        }
        return false;
    };
    let Ok(tp): Result<&mut AyaTracePoint, _> = prog.try_into() else {
        if required {
            eprintln!("eBPF: {} 类型转换失败", name);
        }
        return false;
    };
    if let Err(e) = tp.load() {
        if required {
            eprintln!("eBPF: {} 加载失败 ({})", name, e);
        }
        return false;
    }
    if let Err(e) = tp.attach(category, name) {
        if required {
            eprintln!("eBPF: {} 附加失败 ({})", name, e);
        }
        return false;
    }
    true
}

/// 构建白名单键，每个包名生成前 8 字节与末 8 字节键
fn comm_keys_build<'a, I: IntoIterator<Item = &'a String>>(pkgs: I) -> Vec<[u8; 8]> {
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

/// 初始化 TARGET_COMM_MAP，返回 true 表示容量不足需重载内核端
pub fn comm_map_init(bpf: &mut Ebpf, pkgs: &HashSet<String>, comm_capacity: &mut u32) -> bool {
    let entries = comm_keys_build(pkgs.iter());

    if entries.len() > *comm_capacity as usize {
        eprintln!(
            "eBPF: 白名单容量不足（需 {} > 现 {}），触发内核端重载",
            entries.len(),
            comm_capacity
        );
        return true;
    }

    let Some(map) = bpf.map_mut("TARGET_COMM_MAP") else {
        eprintln!("eBPF: 未找到 TARGET_COMM_MAP");
        return false;
    };
    let mut target_map = match AyaHashMap::<_, [u8; 8], u32>::try_from(map) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("eBPF: TARGET_COMM_MAP 类型转换失败 ({})", e);
            return false;
        }
    };

    let old_keys: Vec<[u8; 8]> = target_map.keys().filter_map(|r| r.ok()).collect();
    for key in &old_keys {
        let _ = target_map.remove(key);
    }

    let mut count = 0;
    for key in &entries {
        if target_map.insert(key, 1, 0).is_ok() {
            count += 1;
        }
    }

    println!(
        "eBPF: FORK/EXEC 白名单已配置，{} 个包名 > {} 条匹配规则",
        pkgs.len(),
        count
    );
    false
}

/// 检测 tracefs 根路径，现代内核优先 tracing 旧内核回退 debug/tracing
fn tracefs_root() -> Option<&'static str> {
    if fs::metadata("/sys/kernel/tracing").is_ok() {
        return Some("/sys/kernel/tracing");
    }
    if fs::metadata("/sys/kernel/debug/tracing").is_ok() {
        return Some("/sys/kernel/debug/tracing");
    }
    None
}

/// 解析 tracepoint format 文件提取字段名到偏移映射，字段名剥离数组下标
fn tracepoint_parse(root: &str, category: &str, name: &str) -> Option<HashMap<String, u32>> {
    let path = format!("{}/events/{}/{}/format", root, category, name);
    let content = fs::read_to_string(&path).ok()?;
    let mut offsets = HashMap::new();
    for line in content.lines() {
        let Some(rest) = line.trim().strip_prefix("field:") else {
            continue;
        };
        let parts: Vec<&str> = rest.split(';').map(|s| s.trim()).collect();
        if parts.len() < 2 {
            continue;
        }
        let field_name = parts[0]
            .split_whitespace()
            .last()
            .unwrap_or("")
            .split('[')
            .next()
            .unwrap_or("");
        if field_name.is_empty() {
            continue;
        }
        for part in &parts[1..] {
            if let Some(off_str) = part.strip_prefix("offset:") {
                if let Ok(off) = off_str.trim().parse::<u32>() {
                    offsets.insert(field_name.to_string(), off);
                    break;
                }
            }
        }
    }
    Some(offsets)
}

/// 解析本机 format 文件并注入 OFFSETS_MAP 索引 0，失败返回 false 由调用方回退 /proc
fn offsets_inject(bpf: &mut Ebpf) -> bool {
    let Some(root) = tracefs_root() else {
        eprintln!("eBPF: tracefs 不可用，回退到 /proc 轮询");
        return false;
    };

    let offsets = (|| {
        let fork_fields = tracepoint_parse(root, "sched", "sched_process_fork")?;
        let rename_fields = tracepoint_parse(root, "task", "task_rename")?;
        Some(EbpfOffsets {
            fork_child_pid: *fork_fields.get("child_pid")?,
            fork_child_comm: *fork_fields.get("child_comm")?,
            rename_newcomm: *rename_fields.get("newcomm")?,
        })
    })();
    let Some(offsets) = offsets else {
        eprintln!(
            "eBPF: tracepoint format 解析失败 [{}]，回退到 /proc 轮询",
            root
        );
        return false;
    };

    let Some(map) = bpf.map_mut("OFFSETS_MAP") else {
        eprintln!("eBPF: 未找到 OFFSETS_MAP，回退到 /proc 轮询");
        return false;
    };
    let Ok(mut offsets_map) = AyaArray::<_, EbpfOffsets>::try_from(map) else {
        eprintln!("eBPF: OFFSETS_MAP 类型转换失败，回退到 /proc 轮询");
        return false;
    };
    if offsets_map.set(0, &offsets, 0).is_err() {
        eprintln!("eBPF: OFFSETS_MAP 注入失败，回退到 /proc 轮询");
        return false;
    }

    println!(
        "eBPF: tracepoint 偏移注入 [{}] fork[child_pid={}, child_comm={}] rename[newcomm={}]",
        root, offsets.fork_child_pid, offsets.fork_child_comm, offsets.rename_newcomm
    );
    true
}

/// 初始化 eBPF，加载程序 attach tracepoint 创建 RingBuf 线程，失败回退 /proc
pub fn ebpf_init() -> Option<EbpfState> {
    if !ebpf_probe() {
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

    // 按包名数动态设置容量，最小 512 覆盖常见场景，不足时重载自然倍增
    let pkgs = crate::common::lock_ignore_poison(&CURRENT_CONFIG)
        .as_ref()
        .map(|cfg| cfg.pkgs.clone())
        .unwrap_or_default();
    let capacity = comm_keys_build(pkgs.iter())
        .len()
        .max(512)
        .next_power_of_two() as u32;

    let mut loader = EbpfLoader::new();
    loader.map_max_entries("TARGET_COMM_MAP", capacity);
    let mut bpf = match loader.load(&ebpf_data) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("eBPF: 加载失败 ({})，回退到 /proc 轮询", e);
            return None;
        }
    };

    // attach 前注入偏移避免首批事件读到空 map
    if !offsets_inject(&mut bpf) {
        return None;
    }

    if !attach_tracepoint(&mut bpf, "sched", "sched_process_fork", true) {
        return None;
    }
    if !attach_tracepoint(&mut bpf, "sched", "sched_process_exec", true) {
        return None;
    }
    if !attach_tracepoint(&mut bpf, "sched", "sched_process_exit", true) {
        return None;
    }

    attach_tracepoint(&mut bpf, "task", "task_rename", false);

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
    let wakeup_fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
    if wakeup_fd < 0 {
        eprintln!("eBPF: eventfd 创建失败，回退到 /proc 轮询");
        return None;
    }
    let reader_thread = thread::spawn(move || {
        ebpf_reader(ring_buf, tx, wakeup_fd);
    });

    println!("eBPF: 初始化成功，使用纯事件驱动模式（启动后零 /proc 读）");

    Some(EbpfState {
        event_rx: rx,
        reader_thread: Some(reader_thread),
        bpf,
        cache: ProcCache::new(),
        wakeup_fd,
        comm_capacity: capacity,
    })
}

/// RingBuf 读取线程，epoll 阻塞等待事件 wakeup_fd 用于 Drop 唤醒退出
fn ebpf_reader(
    mut ring_buf: aya::maps::RingBuf<aya::maps::MapData>,
    tx: mpsc::Sender<EbpfProcEvent>,
    wakeup_fd: RawFd,
) {
    let name = CString::new("EbpfReader").unwrap();
    unsafe {
        libc::pthread_setname_np(libc::pthread_self(), name.as_ptr());
    }

    let epfd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
    if epfd < 0 {
        eprintln!("eBPF: epoll_create1 失败");
        return;
    }

    let ring_fd = ring_buf.as_raw_fd();
    let mut ring_ev: libc::epoll_event = unsafe { std::mem::zeroed() };
    ring_ev.events = libc::EPOLLIN as u32;
    ring_ev.u64 = 0;
    if unsafe { libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, ring_fd, &mut ring_ev) } < 0 {
        eprintln!("eBPF: epoll_ctl ADD ring_fd 失败");
        unsafe { libc::close(epfd) };
        return;
    }

    let mut wake_ev: libc::epoll_event = unsafe { std::mem::zeroed() };
    wake_ev.events = libc::EPOLLIN as u32;
    wake_ev.u64 = 1;
    if unsafe { libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, wakeup_fd, &mut wake_ev) } < 0 {
        eprintln!("eBPF: epoll_ctl ADD wakeup_fd 失败");
        unsafe { libc::close(epfd) };
        return;
    }

    let mut events: [libc::epoll_event; 2] = unsafe { std::mem::zeroed() };
    loop {
        let n = unsafe { libc::epoll_wait(epfd, events.as_mut_ptr(), 2, -1) };
        if n <= 0 {
            if n < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            break;
        }

        // wakeup 事件优先退出
        let mut wakeup = false;
        for i in 0..n as usize {
            if events[i].u64 == 1 {
                wakeup = true;
                break;
            }
        }
        if wakeup {
            break;
        }

        while let Some(item) = ring_buf.next() {
            let bytes: &[u8] = &item;
            if bytes.len() >= std::mem::size_of::<EbpfProcEvent>() {
                let event: EbpfProcEvent =
                    unsafe { std::ptr::read_unaligned(bytes.as_ptr() as *const EbpfProcEvent) };
                if tx.send(event).is_err() {
                    unsafe { libc::close(epfd) };
                    return;
                }
            }
        }
    }
    unsafe { libc::close(epfd) };
}

/// 写入 APPLIED_MAP tid 到 CPU mask
fn applied_set(bpf: &mut Ebpf, tid: i32, cpus: &CpuSet) {
    let Some(map) = bpf.map_mut("APPLIED_MAP") else {
        return;
    };
    let Ok(mut applied) = AyaHashMap::<_, u32, u64>::try_from(map) else {
        return;
    };
    if let Err(e) = applied.insert(&(tid as u32), cpus.bits[0], 0) {
        eprintln!("eBPF: APPLIED_MAP 插入失败 tid={} ({})，map 可能已满", tid, e);
    }
}

/// 从 APPLIED_MAP 删除 tid
fn applied_del(bpf: &mut Ebpf, tid: i32) {
    let Some(map) = bpf.map_mut("APPLIED_MAP") else {
        return;
    };
    let Ok(mut applied) = AyaHashMap::<_, u32, u64>::try_from(map) else {
        return;
    };
    let _ = applied.remove(&(tid as u32));
}

/// 清空 APPLIED_MAP 所有条目
fn applied_clear(bpf: &mut Ebpf) {
    let Some(map) = bpf.map_mut("APPLIED_MAP") else {
        return;
    };
    let Ok(mut m) = AyaHashMap::<_, u32, u64>::try_from(map) else {
        return;
    };
    let keys: Vec<u32> = m.keys().filter_map(|r| r.ok()).collect();
    for k in &keys {
        let _ = m.remove(k);
    }
}

/// 应用亲和性并写 APPLIED_MAP，返回 true 表示 tid 已退出
fn affinity_apply(
    tid: i32,
    cpus: &CpuSet,
    cpuset_dir: &str,
    cfg: &AppConfig,
    bpf: &mut Ebpf,
) -> bool {
    let dead = affinity_set(tid, cpus, cpuset_dir, &cfg.topo);
    if !dead {
        applied_set(bpf, tid, cpus);
    }
    dead
}

/// 事件派发，按 event_type 增量处理 FORK/RENAME/EXEC/EXIT
pub fn event_dispatch(event: &EbpfProcEvent, cfg: &AppConfig, state: &mut EbpfState) {
    let tid = event.tid;
    let pid = event.pid;
    let comm = comm_str(&event.comm);

    match event.event_type {
        EBPF_EVENT_EXIT => {
            if tid == pid {
                state.cache.pkgs.remove(&pid);
            }
            state.cache.task_del(tid);
            applied_del(&mut state.bpf, tid);
        }

        EBPF_EVENT_EXEC => {
            state.cache.pkgs.remove(&pid);
            if !event_apply(&mut state.cache, &mut state.bpf, tid, pid, &comm, cfg, true) {
                state.cache.task_del(tid);
                applied_del(&mut state.bpf, tid);
            }
        }

        EBPF_EVENT_FORK => {
            // FORK 子线程继承父 comm 不可信，主线程 tid==pid comm 为自身
            event_apply(&mut state.cache, &mut state.bpf, tid, pid, &comm, cfg, tid == pid);
        }

        EBPF_EVENT_RENAME => {
            event_apply(&mut state.cache, &mut state.bpf, tid, pid, &comm, cfg, true);
        }

        _ => {}
    }
}

/// 统一事件处理 pkg_lookup_comm 到 task_apply
fn event_apply(
    cache: &mut ProcCache,
    bpf: &mut Ebpf,
    tid: i32,
    pid: i32,
    comm: &str,
    cfg: &AppConfig,
    trust_comm: bool,
) -> bool {
    let Some((pkg, has_thread_rules)) = cache.pkg_lookup_comm(pid, comm, cfg) else {
        return false;
    };

    let _applied = cache.task_apply(tid, pid, &pkg, comm, has_thread_rules, cfg, trust_comm, |t, c, d| {
        affinity_apply(t, c, d, cfg, bpf)
    });

    true
}

/// 定期纠正 affinity_sync 清死亡 tid
pub fn affinity_check(state: &mut EbpfState, cfg: &AppConfig) {
    let dead_tids = state.cache.affinity_sync(&cfg.topo);
    for tid in dead_tids {
        applied_del(&mut state.bpf, tid);
    }
}

/// 全量扫描 /proc 仅启动或配置更新时调用，日常零 /proc 读
pub fn full_scan(cfg: &AppConfig, state: &mut EbpfState) {
    state.cache.clear();
    applied_clear(&mut state.bpf);

    let proc_dir = match fs::read_dir("/proc") {
        Ok(d) => d,
        Err(_) => return,
    };

    let targets: Vec<(i32, String, bool)> = proc_dir
        .flatten()
        .filter_map(|entry| {
            let pid = entry.file_name().to_string_lossy().parse::<i32>().ok()?;
            let pkg = read_cmdline(pid).or_else(|| tid_comm(pid))?;
            let (interested, has_thread_rules) = pkg_match(&pkg, cfg);
            if !interested {
                return None;
            }
            Some((pid, pkg, has_thread_rules))
        })
        .collect();

    for (pid, pkg, has_thread_rules) in targets {
        let Some(tids) = task_tids(pid) else {
            continue;
        };
        for tid in tids {
            let t_name = if has_thread_rules {
                tid_comm(tid).unwrap_or_default()
            } else {
                String::new()
            };
            state.cache.task_apply(
                tid,
                pid,
                &pkg,
                &t_name,
                has_thread_rules,
                cfg,
                true,
                |tid, cpus, cpuset_dir| {
                    affinity_apply(tid, cpus, cpuset_dir, cfg, &mut state.bpf)
                },
            );
        }
        // 缓存 pkg 信息
        state.cache.pkgs.insert(pid, (pkg, has_thread_rules));
    }
}

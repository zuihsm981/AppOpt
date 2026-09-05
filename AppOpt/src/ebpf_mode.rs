//! eBPF 事件驱动模式 → KPM(Kernel Patch Module)事件驱动模式
//!
//! 原实现用 aya 加载 eBPF 程序并读 RingBuf; 现改为通过 KernelPatch SuperCall
//! (syscall 45 = __NR_truncate) 与 appopt-kpm KPM 内核模块通信。
//!
//! 事件传输 (主路径): mmap 共享内存 + eventfd 通知 + 1MB Ring (零拷贝)
//!   - 用户态 mmap(MAP_ANONYMOUS|MAP_SHARED) 一块 1MB+4KB 内存并初始化头部,
//!     经 ctl0 "ring_map <ptr> <size> <efd>" 传入内核; 内核在 workqueue 用
//!     pin_user_pages_remote 钉住用户页 + vmap 得内核连续视图, 之后探针直接
//!     写入该共享内存并 eventfd_signal; reader 线程 epoll 唤醒后直接读 mmap
//!     内存, 不再 supercall drain。
//!   - 失败处理: 共享环建立失败 (mmap/eventfd 失败 或 内核 pin+vmap 超时) 时
//!     不回退 drain 轮询, 而是清理后让 ebpf_init 返回 None -> 调用方回退
//!     /proc 模式 (完全不同的机制, 非 drain 轮询)。
//!
//! 内核侧等价逻辑在 AppOpt-kpm/appopt_kpm.c; 事件结构 EbpfProcEvent 与内核
//! appopt_proc_event_t 布局完全一致 (28B), event_dispatch/affinity 逻辑不变。

use std::collections::HashSet;
use std::ffi::CString;
use std::fs;
use std::os::raw::{c_char, c_int, c_void};
use std::sync::mpsc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::thread;

use crate::apply_affinity::{proc_walk, task_tids, tid_comm};
use crate::cache::ProcCache;
use crate::config::{AppConfig, CURRENT_CONFIG};
use crate::cpuset::CpuSet;

/// eBPF 进程事件, 布局需与内核态 appopt_proc_event_t 完全一致 (28B)
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
pub const EBPF_EVENT_INPUT: u32 = 5;

/* ================= 共享环形缓冲 ABI (与 appopt_kpm.h 一致) ================= */
/// 共享环数据区大小 (1MB, 2 的幂)
const RING_DATA_SIZE: usize = 1 * 1024 * 1024;
/// 头部页大小 (数据区起始偏移)
const RING_HDR_SIZE: usize = 4096;
/// 共享环总大小 (头部页 + 数据区)
const RING_TOTAL: usize = RING_HDR_SIZE + RING_DATA_SIZE;
const RING_MAGIC: u32 = 0x41504F54; // "APOT"

/// 共享环形缓冲头部 (布局与内核 appopt_ring_header_t 完全一致: 8 * u32 = 32B)。
/// SPSC: 内核为唯一生产者(写 tail+数据), 用户态为唯一消费者(写 head)。
/// head/tail 为绝对计数 (u32 自然回绕), 用 & (DATA_SIZE-1) 索引字节。
/// 跨核读写用 AtomicU32 acquire/release (与内核 __atomic 等价)。
#[repr(C)]
struct RingHeader {
    magic: u32,
    version: u32,
    data_size: u32,
    event_size: u32,
    head: AtomicU32,       // 消费者游标 (本进程写, 内核 acquire 读)
    tail: AtomicU32,       // 生产者游标 (内核 release 写, 本进程 acquire 读)
    dropped: u32,
    kernel_ready: AtomicU32, // 内核 vmap 成功后置 1, 拆除前置 0
}

/* ================= KernelPatch SuperCall 传输 ================= */

/// SuperCall 复用 syscall 45 (__NR_truncate)
const NR_SUPERCALL: i64 = 45;
const SUPERCALL_HELLO: i64 = 0x1000;
const SUPERCALL_KPM_CONTROL: i64 = 0x1022;
const SUPERCALL_HELLO_MAGIC: i64 = 0x11581158;

/// KPM 模块名 (与 appopt_kpm.c KPM_NAME 一致)
const KPM_MODULE: &[u8] = b"appopt-kpm\0";

/// KernelPatch superkey (可由环境变量 APPOPT_KPM_KEY 覆盖; 空则用 "su" 探测)
fn kpm_key() -> CString {
    if let Ok(k) = std::env::var("APPOPT_KPM_KEY") {
        if !k.is_empty() {
            return CString::new(k).unwrap_or_default();
        }
    }
    CString::new("su").unwrap_or_default()
}

/// 构造 SuperCall 命令参数: [31:16]=0x1158 magic, [15:0]=cmd, [63:32]=版本(可留 0)
#[inline]
fn ver_and_cmd(cmd: i64) -> i64 {
    (0x1158i64 << 16) | (cmd & 0xffff)
}

/// 裸 SuperCall, 返回内核返回值 (负数=错误)
unsafe fn supercall(
    key: *const c_char,
    cmd: i64,
    a1: *const c_char,
    a2: *const c_char,
    a3: *mut u8,
    a4: usize,
) -> i64 {
    // Rust 2024: unsafe_op_in_unsafe_fn, 体内 unsafe 调用需显式 unsafe 块
    unsafe { libc::syscall(NR_SUPERCALL, key, ver_and_cmd(cmd), a1, a2, a3, a4) as i64 }
}

/// 向 KPM 模块发送 ctl0 命令; out 为可选输出缓冲
fn kpm_ctl0(key: &CString, args: &CString, out: &mut [u8]) -> i64 {
    // out 为空时用本地缓冲 (必须存活到 supercall 返回)
    let mut tmp = [0u8; 64];
    let (ptr, len) = if out.is_empty() {
        (tmp.as_mut_ptr(), tmp.len())
    } else {
        (out.as_mut_ptr(), out.len())
    };
    unsafe {
        supercall(
            key.as_ptr(),
            SUPERCALL_KPM_CONTROL,
            KPM_MODULE.as_ptr() as *const c_char,
            args.as_ptr(),
            ptr,
            len,
        )
    }
}

/// KernelPatch 是否就绪
fn kp_ready(key: &CString) -> bool {
    unsafe { supercall(key.as_ptr(), SUPERCALL_HELLO, std::ptr::null(), std::ptr::null(), std::ptr::null_mut(), 0) == SUPERCALL_HELLO_MAGIC }
}

/// KPM 传输句柄 (占用原 EbpfState.bpf 字段, 保持 main.rs 接口不变)
pub struct KpmHandle {
    key: CString,
}

impl KpmHandle {
    pub fn new() -> Self {
        Self { key: kpm_key() }
    }

    /// 确认模块已加载: ping 成功即视为已加载
    fn ping(&self) -> bool {
        let args = CString::new("ping").unwrap_or_default();
        let mut out = [0u8; 16];
        kpm_ctl0(&self.key, &args, &mut out) >= 0 && out[0] == b'p'
    }

    /// 确认模块已加载 (由 APatch 管理器加载; AppOpt 不自动部署/加载)
    fn verify_loaded(&self) -> bool {
        self.ping()
    }

    /// ctl0 命令封装
    fn cmd(&self, args: &str) -> i64 {
        let c = CString::new(args).unwrap_or_default();
        kpm_ctl0(&self.key, &c, &mut [])
    }

    fn applied_set(&self, tid: i32, bits: u64) {
        let s = format!("applied_set {} {:x}", tid, bits);
        self.cmd(&s);
    }

    /// AppOpt 初始化完成后激活 KPM: 注册 tracepoint(start) + 武装 input kprobe(input_on)
    pub fn activate(&self) {
        self.cmd("start");
        self.cmd("input_on");
    }

    fn applied_del(&self, tid: i32) {
        let s = format!("applied_del {}", tid);
        self.cmd(&s);
    }

    fn applied_clear(&self) {
        self.cmd("clear_applied");
    }

    /// 设置白名单 (包名集合), 返回 true 表示失败需要回退
    fn set_whitelist(&self, pkgs: &HashSet<String>) -> bool {
        let mut s = String::from("set_whitelist ");
        for (i, p) in pkgs.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            s.push_str(p);
        }
        let c = CString::new(s).unwrap_or_default();
        let mut out = [0u8; 16];
        kpm_ctl0(&self.key, &c, &mut out) >= 0
    }
}

/// 将内核 comm 截断于首个 NUL 并 trim 尾部空白
fn comm_str(comm: &[u8; 16]) -> &str {
    let end = comm.iter().position(|&b| b == 0).unwrap_or(16);
    std::str::from_utf8(&comm[..end]).unwrap_or("").trim()
}

pub struct EbpfState {
    pub event_rx: mpsc::Receiver<EbpfProcEvent>,
    pub reader_thread: Option<thread::JoinHandle<()>>,
    /// 原 aya Ebpf 替换为 KPM 传输句柄; 字段名保持 bpf 以兼容 main.rs
    pub bpf: KpmHandle,
    pub cache: ProcCache,
    pub wakeup_fd: c_int,
    /// 事件到达通知 fd (eventfd): reader 收到事件后写入, 唤醒主循环 epoll
    pub kpm_wake_fd: c_int,
    pub comm_capacity: u32,
    /// 共享环形缓冲指针 (mmap MAP_ANONYMOUS|MAP_SHARED); 0 = 未建立/回退 drain
    pub ring_ptr: usize,
    /// 共享环 eventfd (内核写, 本进程 epoll 读); -1 = 未建立
    pub ring_efd: c_int,
}

impl Drop for EbpfState {
    fn drop(&mut self) {
        // 1. 写 wakeup_fd 唤醒 reader 线程退出, 再 join (确保不再读共享环)
        if self.wakeup_fd >= 0 {
            let val: u64 = 1;
            unsafe {
                libc::write(self.wakeup_fd, &val as *const u64 as *const _, 8);
            }
        }
        if let Some(handle) = self.reader_thread.take() {
            let _ = handle.join();
        }
        // 2. 通知内核拆除共享环映射 (停止探针写入后 pin/vmap 释放)
        if self.ring_ptr != 0 {
            self.bpf.cmd("ring_unmap");
        }
        // 3. 关闭 fd / munmap (reader 已 join, 无并发访问)
        if self.wakeup_fd >= 0 {
            unsafe { libc::close(self.wakeup_fd); }
        }
        if self.ring_efd >= 0 {
            unsafe { libc::close(self.ring_efd); }
        }
        if self.ring_ptr != 0 {
            unsafe { libc::munmap(self.ring_ptr as *mut c_void, RING_TOTAL); }
        }
        // kpm_wake_fd 由主循环创建并管理生命周期, Drop 不关闭
        self.kpm_wake_fd = -1;
    }
}

/// KPM 探测: KernelPatch 就绪 且 模块可通信 (ping)
pub fn kpm_probe() -> bool {
    let key = kpm_key();
    if !kp_ready(&key) {
        return false;
    }
    let handle = KpmHandle::new();
    handle.ping()
}

/// 查找 Zygote 相关进程的所有线程 tid
/// (cmdline 匹配 zygote/app_process/usap 前缀, 覆盖 zygote/zygote64/app_process32/app_process64/usap)
fn find_zygote_tids() -> Vec<i32> {
    let mut tids = Vec::new();
    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let Ok(pid) = entry.file_name().to_string_lossy().parse::<i32>() else { continue };
            let Ok(cmdline) = fs::read(format!("/proc/{}/cmdline", pid)) else { continue };
            let s = String::from_utf8_lossy(&cmdline);
            if !(s.starts_with("zygote") || s.starts_with("app_process") || s.starts_with("usap")) {
                continue;
            }
            if let Ok(task_dir) = fs::read_dir(format!("/proc/{}/task", pid)) {
                for t in task_dir.flatten() {
                    if let Ok(tid) = t.file_name().to_string_lossy().parse::<i32>() {
                        tids.push(tid);
                    }
                }
            }
        }
    }
    tids
}

/// 建立共享环形缓冲 (mmap + eventfd), 返回 (ring_ptr, ring_efd)。
/// 失败时 ring_ptr=0; ebpf_init 检测到后不回退轮询, 直接放弃 KPM 模式。
fn ring_setup(handle: &KpmHandle) -> (usize, c_int) {
    let ring_efd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
    if ring_efd < 0 {
        return (0, -1);
    }
    let p = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            RING_TOTAL,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if p == libc::MAP_FAILED {
        unsafe { libc::close(ring_efd); }
        return (0, -1);
    }
    // 初始化头部 (用户态侧); 内核 vmap 后会回填 version/event_size/tail/kernel_ready
    let hdr = p as *mut RingHeader;
    unsafe {
        // 先触页驻留 (memset), 避免 pin_user_pages_remote 时缺页延迟
        let bytes = std::slice::from_raw_parts_mut(p as *mut u8, RING_TOTAL);
        for b in bytes.iter_mut() {
            *b = 0;
        }
        (*hdr).magic = RING_MAGIC;
        (*hdr).data_size = RING_DATA_SIZE as u32;
        (*hdr).event_size = std::mem::size_of::<EbpfProcEvent>() as u32;
        (*hdr).head = AtomicU32::new(0);
        (*hdr).tail = AtomicU32::new(0);
        (*hdr).dropped = 0;
        (*hdr).kernel_ready = AtomicU32::new(0);
    }
    // 通知内核建立映射 (异步: workqueue pin+vmap); 内核就绪后置 kernel_ready=1
    let s = format!("ring_map {:x} {} {}", p as usize, RING_TOTAL, ring_efd);
    handle.cmd(&s);
    (p as usize, ring_efd)
}

/// 初始化 KPM 事件驱动: 确保模块加载, 建立共享环, 启动 reader 线程
/// 失败返回 None, 由调用方回退 /proc 轮询。
/// kpm_wake_fd 由主循环创建并注册 epoll, reader 收到事件后写入以唤醒主循环。
pub fn ebpf_init(kpm_wake_fd: c_int) -> Option<EbpfState> {
    let key = kpm_key();
    if !kp_ready(&key) {
        return None;
    }

    let handle = KpmHandle { key };
    if !handle.verify_loaded() {
        return None;
    }

    // 配置 input 节流 (与 eBPF 默认 1s 一致)
    handle.cmd("input_ms 1000");

    let pkgs_len = crate::lock_ignore_poison(&CURRENT_CONFIG)
        .as_ref()
        .map(|cfg| cfg.pkgs.len())
        .unwrap_or(0);
    let capacity = (pkgs_len * 2).max(512).next_power_of_two() as u32;

    let (tx, rx) = mpsc::channel::<EbpfProcEvent>();
    let wakeup_fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
    if wakeup_fd < 0 {
        return None;
    }

    // 建立共享环形缓冲 (mmap + eventfd); 失败不回退轮询, 直接放弃 KPM 模式
    let (ring_ptr, ring_efd) = ring_setup(&handle);

    // 等待内核建立共享环映射 (读 mmap 头部 kernel_ready, 非 supercall 轮询)。
    // 内核 workqueue 的 pin+vmap 应在毫秒级完成; 超时则视为失败, 清理后返回
    // None -> 调用方回退 /proc 模式 (不回退 drain 轮询)。
    if ring_ptr == 0 {
        // ring_setup 失败 (mmap/eventfd 失败): 放弃 KPM 模式
        unsafe { libc::close(wakeup_fd); }
        return None;
    }
    {
        let hdr = ring_ptr as *const RingHeader;
        let mut ready = false;
        for _ in 0..200u32 {  // 最多 ~1s (200 * 5ms)
            if unsafe { (*hdr).kernel_ready.load(Ordering::Acquire) } != 0 {
                ready = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        if !ready {
            // 共享环建立失败: 通知内核拆除 + 释放本地资源, 放弃 KPM 模式
            handle.cmd("ring_unmap");
            unsafe {
                libc::close(ring_efd);
                libc::munmap(ring_ptr as *mut c_void, RING_TOTAL);
                libc::close(wakeup_fd);
            }
            return None;
        }
    }

    // reader 线程: epoll 唤醒 (eventfd) 后直接读 mmap 共享内存 (零拷贝, 无 drain)
    let reader_thread = thread::spawn(move || {
        kpm_reader(tx, wakeup_fd, kpm_wake_fd, ring_ptr, ring_efd);
    });

    /* 先设置白名单再激活: start 注册 tracepoint 后立即开始过滤事件,
     * 若白名单为空则所有新进程事件被丢弃, 导致直接打开应用不设置亲和性 */
    let mut pkgs = crate::lock_ignore_poison(&CURRENT_CONFIG)
        .as_ref()
        .map(|cfg| cfg.target_pkgs.clone())
        .unwrap_or_default();
    // 桌面是刷新率模块的默认白名单成员，不依赖 CPU 规则存在与否。
    pkgs.insert(crate::config::DEFAULT_REFRESH_PACKAGE.to_string());
    pkgs.insert(crate::config::DEFAULT_REFRESH_COMM.to_string());
    handle.set_whitelist(&pkgs);
    handle.activate();

    /* 把 Zygote 加入 APPLIED 表 (bits=0): Zygote fork 出的子进程
     * (如 com.bilibili.app.in:ijkservice) 会在 FORK 探针中被占位,
     * RENAME 时 tracked=true 直接通过, 无需依赖 whitelist_matched。
     * bits=0 不影响 Zygote 自身 (sched_setaffinity kprobe 见 bits=0 不干预)。 */
    for tid in find_zygote_tids() {
        handle.applied_set(tid, 0);
    }


    Some(EbpfState {
        event_rx: rx,
        reader_thread: Some(reader_thread),
        bpf: handle,
        cache: ProcCache::new(),
        wakeup_fd,
        kpm_wake_fd,
        comm_capacity: capacity,
        ring_ptr,
        ring_efd,
    })
}

/// reader 线程: epoll 监听 ring_efd (事件到达) + wakeup_fd (退出)。
/// 共享环就绪 (kernel_ready==1, 由 ebpf_init 已确认) 时直接读 mmap 内存 (零拷贝)。
/// 不回退 drain 轮询: 运行期若 kernel_ready 变 0 (内核拆除映射), 仅跳过消费,
/// 等待下一次 epoll (通常伴随 Drop 的 wakeup 退出)。
fn kpm_reader(
    tx: mpsc::Sender<EbpfProcEvent>,
    wakeup_fd: c_int,
    kpm_wake_fd: c_int,
    ring_ptr: usize,
    ring_efd: c_int,
) {
    let name = CString::new("KpmReader").unwrap();
    unsafe {
        libc::pthread_setname_np(libc::pthread_self(), name.as_ptr());
    }

    let epfd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
    if epfd < 0 {
        return;
    }
    // 注册 wakeup_fd (退出信号, tag=1) 与 ring_efd (事件通知, tag=2)
    let mut add_ev = |fd: c_int, tag: u64| {
        if fd < 0 {
            return;
        }
        let mut ev: libc::epoll_event = unsafe { std::mem::zeroed() };
        ev.events = libc::EPOLLIN as u32;
        ev.u64 = tag;
        unsafe { libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, fd, &mut ev); }
    };
    add_ev(wakeup_fd, 1);
    add_ev(ring_efd, 2);

    let mut events: [libc::epoll_event; 4] = unsafe { std::mem::zeroed() };
    let ev_sz = std::mem::size_of::<EbpfProcEvent>();
    let mask = RING_DATA_SIZE - 1;
    let data_off = RING_HDR_SIZE;

    loop {
        // 100ms 超时: eventfd 驱动低延迟; 超时为安全网 (kernel_ready 状态轮询)
        let n = unsafe { libc::epoll_wait(epfd, events.as_mut_ptr(), events.len() as i32, 100) };
        if n < 0 {
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            break;
        }

        let mut do_exit = false;
        for i in 0..n as usize {
            let e = &events[i];
            match e.u64 {
                1 => do_exit = true, // wakeup: 退出
                2 => {
                    // 清 eventfd 计数 (8 字节)
                    let mut buf = [0u8; 8];
                    let _ = unsafe { libc::read(ring_efd, buf.as_mut_ptr() as *mut _, 8) };
                }
                _ => {}
            }
        }
        if do_exit {
            break;
        }

        // 共享环路径: ring_ptr 有效且内核已就绪 (kernel_ready==1)
        let use_ring = ring_ptr != 0
            && unsafe {
                (*(ring_ptr as *const RingHeader)).kernel_ready.load(Ordering::Acquire) != 0
            };

        if use_ring {
            // 消费共享环直到空 (SPSC: 读 tail, 处理 [head, tail), 推进 head)
            let hdr = ring_ptr as *const RingHeader;
            let data = (ring_ptr + data_off) as *const u8;
            loop {
                let tail = unsafe { (*hdr).tail.load(Ordering::Acquire) };
                let head = unsafe { (*hdr).head.load(Ordering::Relaxed) };
                let avail = tail.wrapping_sub(head);
                if avail == 0 {
                    break;
                }
                let mut off = 0usize;
                while off + ev_sz <= avail as usize {
                    let base = (head as usize + off) & mask;
                    // 事件可能跨越数据区末尾回绕到起始: 不回绕则连续读, 否则逐字节
                    let ev: EbpfProcEvent = if base + ev_sz <= RING_DATA_SIZE {
                        unsafe {
                            std::ptr::read_unaligned(data.add(base) as *const EbpfProcEvent)
                        }
                    } else {
                        let mut evbuf = [0u8; 32];
                        for k in 0..ev_sz {
                            evbuf[k] = unsafe { *data.add((base + k) & mask) };
                        }
                        unsafe { std::ptr::read_unaligned(evbuf.as_ptr() as *const EbpfProcEvent) }
                    };
                    if tx.send(ev).is_err() {
                        unsafe { libc::close(epfd) };
                        return;
                    }
                    // 唤醒主循环处理该事件
                    let val: u64 = 1;
                    let _ = unsafe { libc::write(kpm_wake_fd, &val as *const u64 as *const _, 8) };
                    off += ev_sz;
                }
                // release 推进 head, 让内核看到可写空间
                unsafe {
                    (*hdr).head.store(head.wrapping_add(off as u32), Ordering::Release);
                }
                if off == 0 {
                    break; // 不足一个完整事件
                }
            }
        }
        // 共享环未就绪时不回退 drain: 直接等待下一次 epoll
    }
    unsafe { libc::close(epfd) };
}

/// 配置白名单; 返回 true 表示需重载 (KPM 白名单容量固定 16384, 不会触发)
pub fn comm_map_init(bpf: &mut KpmHandle, pkgs: &HashSet<String>, _comm_capacity: u32) -> bool {
    let mut refresh_pkgs = pkgs.clone();
    refresh_pkgs.insert(crate::config::DEFAULT_REFRESH_PACKAGE.to_string());
    refresh_pkgs.insert(crate::config::DEFAULT_REFRESH_COMM.to_string());
    if !bpf.set_whitelist(&refresh_pkgs) {
        return true;
    }
    false
}

fn applied_set(bpf: &KpmHandle, tid: i32, cpus: &CpuSet) {
    bpf.applied_set(tid, cpus.bits[0]);
}

fn applied_del(bpf: &KpmHandle, tid: i32) {
    bpf.applied_del(tid);
}

fn applied_clear(bpf: &KpmHandle) {
    bpf.applied_clear();
}

/// 事件驱动路径: 只更新 APPLIED 表 (供 sched_setaffinity kprobe 拦截),
/// 不立即设置亲和性/放置 cpuset。实际设置由主循环定期 affinity_sync
/// 在应用完全启动、任务稳定后统一执行 (先 cpuset 后亲和性)。
fn affinity_apply(
    tid: i32,
    cpus: &CpuSet,
    _cpuset_dir: &str,
    _cfg: &AppConfig,
    bpf: &KpmHandle,
) -> bool {
    applied_set(bpf, tid, cpus);
    false
}

/// 事件派发, 按 event_type 增量处理 FORK/RENAME/EXEC/EXIT (与 aya 版一致)
pub fn event_dispatch(event: &EbpfProcEvent, cfg: &AppConfig, state: &mut EbpfState) {
    let tid = event.tid;
    let pid = event.pid;
    let comm = comm_str(&event.comm);

    match event.event_type {
        EBPF_EVENT_EXIT => {
            // task_del 会在该 PID 的最后一个线程退出后再移除共享索引；
            // 不能在单个线程退出时无条件删除 PID→包名映射。
            state.cache.task_del(tid);
            applied_del(&state.bpf, tid);
        }

        EBPF_EVENT_EXEC => {
            // EXEC 可能复用同一个 pid，先清掉旧进程的任务和 PID_PKG 映射，
            // 再用新的 cmdline/comm 重新识别，避免沿用旧包名。
            state.cache.pid_exec(pid);
            if !event_apply(&mut state.cache, &state.bpf, tid, pid, comm, cfg) {
                applied_del(&state.bpf, tid);
            }
        }

        EBPF_EVENT_FORK => {
            // 子线程继承父线程亲和性与 cpuset
            // 内核态已插入 APPLIED 表占位, RENAME 时触发完整处理
        }

        EBPF_EVENT_RENAME => {
            event_apply(&mut state.cache, &state.bpf, tid, pid, comm, cfg);
        }

        EBPF_EVENT_INPUT => {
            crate::refresh::refresh_on_event(EBPF_EVENT_INPUT, 0);
        }

        _ => {}
    }
}

/// 统一事件处理 pkg_lookup_comm 到 task_apply
fn event_apply(
    cache: &mut ProcCache,
    bpf: &KpmHandle,
    tid: i32,
    pid: i32,
    comm: &str,
    cfg: &AppConfig,
) -> bool {
    let pkg_result = cache.pkg_lookup_comm(pid, comm, cfg);
    let Some(pkg) = pkg_result else {
        return false;
    };

    cache.task_apply(tid, pid, &pkg, comm, cfg, |t, c, d| {
        affinity_apply(t, c, d, cfg, bpf)
    })
}

/// 周期重钉已由内核 sched_setaffinity 拦截接管 (KPM 模式); /proc 回退模式仍用 affinity_sync

/// 启动或配置更新时全量扫描 /proc
pub fn full_scan(cfg: &AppConfig, state: &mut EbpfState) {
    state.cache.clear();

    // full_scan 时额外扫描当前已经存在的默认桌面进程。
    // 当前系统中该进程的 comm 为 droid.launcher3；它不需要 CPU 规则，
    // 但必须进入共享 PID_PKG，并绑定全局刷新率配置。
    let mut launcher_found = false;
    if let Ok(entries) = std::fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let Ok(pid) = entry.file_name().to_string_lossy().parse::<i32>() else { continue };
            if tid_comm(pid).as_deref() == Some(crate::config::DEFAULT_REFRESH_COMM) {
                crate::cache::pkg_track_pid(pid, crate::config::DEFAULT_REFRESH_PACKAGE);
                launcher_found = true;
            }
        }
    }
    if launcher_found {
        crate::refresh::refresh_bind_default_launcher();
    }

    applied_clear(&state.bpf);
    /* full_scan 清空了 APPLIED 表, Zygote 的 tid 也随之丢失。
     * 必须重新把 Zygote 加入 APPLIED (bits=0), 否则之后 Zygote fork 的
     * 子进程无法被 FORK 探针占位, RENAME 事件被过滤, 子进程匹配不到。 */
    for tid in find_zygote_tids() {
        state.bpf.applied_set(tid, 0);
    }

    proc_walk(cfg, |_| true, |pid, pkg, has_thread_rules| {
        let Some(tids) = task_tids(pid) else { return };
        for tid in tids {
            let t_name = if has_thread_rules {
                tid_comm(tid).unwrap_or_default()
            } else {
                String::new()
            };
            state.cache.task_apply(tid, pid, pkg, &t_name, cfg, |tid, cpus, cpuset_dir| {
                affinity_apply(tid, cpus, cpuset_dir, cfg, &state.bpf)
            });
        }
    });

    /* full_scan 本身包含实际应用: 立即对 cache 内全部任务执行
     * affinity_sync (仅设置 CPU 亲和性, 不做 cpuset 放置)。
     * 依赖此点: 配置更新后无论是否有后续进程事件, 亲和性都会立即生效,
     * 不依赖事件驱动定时; 调用方无需在 full_scan 后再调一次 affinity_sync。 */
    state.cache.affinity_sync(&cfg.topo);
}
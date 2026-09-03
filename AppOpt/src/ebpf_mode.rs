//! eBPF 事件驱动模式 → KPM(Kernel Patch Module)事件驱动模式
//!
//! 原实现用 aya 加载 eBPF 程序并读 RingBuf; 现改为通过 KernelPatch SuperCall
//! (syscall 45 = __NR_truncate) 与 appopt-kpm KPM 内核模块通信。
//!
//! 内核侧等价逻辑在 AppOpt-kpm/appopt_kpm.c:
//!   - tracepoint sched_process_fork/exec/exit + task_rename
//!   - 内联挂钩 input_handle_event (1s 节流)
//!   - 白名单(包名前/末 8 字节键, comm 8 字节滑动匹配)、APPLIED tid 表、256KB 事件环形缓冲
//! 用户态通过 ctl0 命令配置/读取, 事件结构 EbpfProcEvent 与内核 appopt_proc_event_t
//! 布局完全一致 (28B), event_dispatch/affinity 逻辑与原先保持一致。

use std::collections::HashSet;
use std::ffi::CString;
use std::fs;
use std::os::raw::{c_char, c_int};
use std::sync::mpsc;
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

/* ================= mmap 共享 event ring ABI (与 appopt_kpm.h 一致) =================
 * 共享区布局: [4KB header | 1MiB ring]
 *   head: 用户态已处理游标 (用户 release 写, 内核 acquire 读)
 *   tail: 内核已写入游标 (内核 release 写, 用户 acquire 读)
 * 事件写入共享内存即对用户可见, 不再依赖 ctl0 drain / 信号完备性。 */
pub const SHM_HEADER_SIZE: usize = 4096;
pub const SHM_RING_SIZE: usize = 1024 * 1024;
pub const SHM_TOTAL_SIZE: usize = SHM_HEADER_SIZE + SHM_RING_SIZE;
pub const SHM_RING_MASK: u32 = (SHM_RING_SIZE - 1) as u32;
pub const SHM_EVENT_SIZE: u32 = std::mem::size_of::<EbpfProcEvent>() as u32; // 28
pub const SHM_MAGIC: u32 = 0x41505000;

/// 共享 header (与内核 appopt_shm_header_t 布局一致)
#[repr(C)]
pub struct ShmHeader {
    pub head: u32,
    pub tail: u32,
    pub magic: u32,
    pub flags: u32,
    pub reserved: [u32; 1020],
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

    /// 获取共享 event ring fd (内核 anon_inode file 已装到当前进程 fd 表)。
    /// 用户态拿到后 mmap(fd) 即获得共享 ring 直读 (head/tail/事件)。
    pub fn create_shm(&self) -> Option<c_int> {
        let c = CString::new("create_shm").unwrap_or_default();
        let mut out = [0u8; 4];
        let rc = kpm_ctl0(&self.key, &c, &mut out);
        if rc < 4 {
            return None;
        }
        let fd = i32::from_ne_bytes([out[0], out[1], out[2], out[3]]);
        if fd < 0 {
            return None;
        }
        Some(fd)
    }

    fn applied_set(&self, tid: i32, bits: u64) {
        let s = format!("applied_set {} {:x}", tid, bits);
        self.cmd(&s);
    }

    /// 激活 KPM: 注册 tracepoint(start) + 按配置决定 input kprobe 挂载与发射。
    /// active != idle → input_on + 发射开; active == idle → input_off (卸载 kprobe)。
    /// 依赖 CURRENT_CONFIG 已就绪 (main 中 load_config 先于 ebpf_init)。
    pub fn activate(&self) {
        self.cmd("start");
        let need_input = crate::lock_ignore_poison(&crate::config::CURRENT_CONFIG)
            .as_ref()
            .map(|c| c.refresh_active != c.refresh_idle)
            .unwrap_or(true);
        let _ = self.set_input_kprobe(need_input);
        let _ = self.set_input_events(need_input);
    }

    fn applied_del(&self, tid: i32) {
        let s = format!("applied_del {}", tid);
        self.cmd(&s);
    }

    fn applied_clear(&self) {
        self.cmd("clear_applied");
    }

    /// 注册/更新事件通知 eventfd 到内核 (fd=-1 解除)。
    /// 内核在事件写入环形缓冲后（空→非空边界）eventfd_signal 唤醒 reader，
    /// reader 收到通知才启动 drain（通知驱动，无空转轮询）。
    pub fn set_eventfd(&self, fd: i32) -> bool {
        let s = format!("set_eventfd {}", fd);
        self.cmd(&s) >= 0
    }

    /// 设置内核 INPUT 事件发射开关 (不改变 kprobe 挂载状态)。
    /// enabled=true → 发 INPUT 事件; false → 内核 input_kprobe_pre 直接跳过
    /// (active==idle 时刷新率无需切换, 关掉可省事件)。同步 ctl0, 无异步。
    pub fn set_input_events(&self, enabled: bool) -> bool {
        let s = if enabled {
            "set_input_events 1".to_string()
        } else {
            "set_input_events 0".to_string()
        };
        self.cmd(&s) >= 0
    }

    /// 挂载/卸载 input kprobe (input_on/input_off)。
    /// INPUT 事件为低优先级 (event_emit_locked 可丢弃), 卸载 kprobe 不会影响
    /// 亲和性事件流; active==idle 时卸载以省 kprobe 开销。
    pub fn set_input_kprobe(&self, on: bool) -> bool {
        self.cmd(if on { "input_on" } else { "input_off" }) >= 0
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

/// 按"刷新率是否需要切换"(active != idle) 联动内核 INPUT:
/// - active != idle: 挂载 input kprobe + 发射开 (触摸唤醒)
/// - active == idle: 卸载 input kprobe + 发射关 (省 kprobe 开销与事件)
/// 仅由 refresh 模块在配置加载/变化时调用 (低频), 不在 fg 切换热路径调用。
/// INPUT 为低优先级事件 (内核 event_emit_locked 可丢弃), 卸载/挂载 kprobe
/// 不会影响亲和性事件流 (FORK/EXEC/RENAME), 不丢线程。
pub fn sync_input_events(enabled: bool) {
    let handle = KpmHandle::new();
    let _ = handle.set_input_kprobe(enabled);
    let _ = handle.set_input_events(enabled);
}

pub struct EbpfState {
    pub event_rx: mpsc::Receiver<EbpfProcEvent>,
    pub reader_thread: Option<thread::JoinHandle<()>>,
    /// 原 aya Ebpf 替换为 KPM 传输句柄; 字段名保持 bpf 以兼容 main.rs
    pub bpf: KpmHandle,
    pub cache: ProcCache,
    pub wakeup_fd: c_int,
    /// 事件到达通知 fd (eventfd): 内核写入事件后 signal, 唤醒 reader 启动 drain
    pub notify_fd: c_int,
    /// 事件到达通知 fd (eventfd): reader 收到事件后写入, 唤醒主循环 epoll
    pub kpm_wake_fd: c_int,
    /// mmap 共享 event ring (reader 直读, Drop 时 munmap)
    pub shm_ptr: *mut u8,
    pub shm_fd: c_int,
    pub comm_capacity: u32,
}

impl Drop for EbpfState {
    fn drop(&mut self) {
        // 解除内核 notify_ctx 引用 (KPM 模块持有我们 eventfd 的 ctx)
        self.bpf.set_eventfd(-1);
        // 写 eventfd 唤醒 reader 线程后 join
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
        if self.notify_fd >= 0 {
            unsafe { libc::close(self.notify_fd); }
        }
        // 释放 mmap 共享 ring + close shm fd
        if !self.shm_ptr.is_null() {
            unsafe {
                libc::munmap(self.shm_ptr as *mut _, SHM_TOTAL_SIZE);
            }
            self.shm_ptr = std::ptr::null_mut();
        }
        if self.shm_fd >= 0 {
            unsafe { libc::close(self.shm_fd); }
            self.shm_fd = -1;
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

/// 初始化 KPM 事件驱动: 确保模块加载, 启动 reader 线程
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
    // 事件通知 eventfd: 内核写入事件后 signal, 唤醒 reader 启动 drain
    let notify_fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
    if notify_fd < 0 {
        unsafe { libc::close(wakeup_fd); }
        return None;
    }
    // 注册通知通道 (事件写入共享 ring 后由内核 signal 唤醒 reader, 仅加速)
    if !handle.set_eventfd(notify_fd) {
        unsafe {
            libc::close(wakeup_fd);
            libc::close(notify_fd);
        }
        return None;
    }

    /* 获取共享 event ring fd + mmap 直读 (核心可靠性: 事件写入共享内存即可见,
     * 不依赖 ctl0 drain/信号完备性; notify 只做低延迟加速唤醒)。 */
    let shm_fd = handle.create_shm()?;
    let shm_ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            SHM_TOTAL_SIZE,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            shm_fd,
            0,
        )
    };
    if shm_ptr == libc::MAP_FAILED {
        unsafe {
            libc::close(shm_fd);
            libc::close(wakeup_fd);
            libc::close(notify_fd);
        }
        return None;
    }
    // 校验共享区 magic (内核 vmalloc_user + anon_inode 映射成功)
    let hdr = shm_ptr as *const ShmHeader;
    let magic = unsafe { (*hdr).magic };
    if magic != SHM_MAGIC {
        unsafe {
            libc::munmap(shm_ptr, SHM_TOTAL_SIZE);
            libc::close(shm_fd);
            libc::close(wakeup_fd);
            libc::close(notify_fd);
        }
        return None;
    }

    // reader 线程: 直读共享内存取事件, 处理完自动停止回阻塞。
    // 原始指针非 Send, 跨线程传 usize 地址, 线程内还原。
    let shm_addr = shm_ptr as usize;
    let reader_thread = thread::spawn(move || {
        kpm_reader(tx, wakeup_fd, notify_fd, kpm_wake_fd, shm_addr as *mut u8);
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
        notify_fd,
        kpm_wake_fd,
        shm_ptr: shm_ptr as *mut u8,
        shm_fd,
        comm_capacity: capacity,
    })
}

/* mmap 共享 ring 直读: 事件写入共享内存即对用户可见 (head/tail acquire/release),
 * 不依赖 ctl0 drain / 信号完备性。通知仅加速唤醒, 100ms 心跳兜底读共享区。 */
fn kpm_reader(
    tx: mpsc::Sender<EbpfProcEvent>,
    wakeup_fd: c_int,
    notify_fd: c_int,
    kpm_wake_fd: c_int,
    shm: *mut u8,
) {
    let name = CString::new("KpmReader").unwrap();
    unsafe {
        libc::pthread_setname_np(libc::pthread_self(), name.as_ptr());
    }

    // epoll: 监听 wakeup_fd (退出信号, u64=1) + notify_fd (内核事件通知, u64=2)
    let epfd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
    if epfd < 0 {
        return;
    }
    let mut ev: libc::epoll_event = unsafe { std::mem::zeroed() };
    ev.events = libc::EPOLLIN as u32;
    ev.u64 = 1;
    if unsafe { libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, wakeup_fd, &mut ev) } < 0 {
        unsafe { libc::close(epfd) };
        return;
    }
    ev.u64 = 2;
    if unsafe { libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, notify_fd, &mut ev) } < 0 {
        unsafe { libc::close(epfd) };
        return;
    }

    let mut events: [libc::epoll_event; 2] = unsafe { std::mem::zeroed() };
    // 事件环形数据区 (共享 header 之后)
    let ring = unsafe { shm.add(SHM_HEADER_SIZE) };
    // head@0 / tail@4: 用 AtomicU32 (Acquire/Release) 与内核 stlr/ldar 严格配对
    let head_atomic = shm as *const std::sync::atomic::AtomicU32;
    let tail_atomic = unsafe { (shm as *const std::sync::atomic::AtomicU32).add(1) };

    loop {
        /* 事件驱动主路径: notify (内核每事件 signal) 立即醒来 → 直读共享内存;
         * 心跳兜底 100ms: 即使通知遗漏, 也主动读共享 tail 消费, 事件不滞留。
         * 共享内存可见性即可靠性本身 (写入即可见), 心跳只是防止"漏唤醒后
         * 永久阻塞"的最终保险, 与轮询 drain 的开销不同: 无 syscall/无 copy。 */
        let n = unsafe { libc::epoll_wait(epfd, events.as_mut_ptr(), 2, 100) };
        if n < 0 {
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            break;
        }
        // n==0 表示 100ms 心跳超时: 兜底读共享区
        let mut need_read = n == 0;
        for i in 0..n as usize {
            match events[i].u64 {
                1 => {
                    // wakeup: 退出
                    unsafe { libc::close(epfd) };
                    return;
                }
                2 => {
                    // 内核事件通知: 清 eventfd 计数后直读共享区
                    let mut val: u64 = 0;
                    unsafe { libc::read(notify_fd, &mut val as *mut _ as *mut _, 8); }
                    need_read = true;
                }
                _ => {}
            }
        }
        if !need_read {
            continue;
        }

        // 直读共享 ring: acquire 读 tail, 消费 [head, tail) 全部事件, release 推进 head。
        // 循环直到共享区真空 (tail==head), 不遗漏任何事件。
        loop {
            use std::sync::atomic::Ordering;
            let tail = unsafe { &*tail_atomic }.load(Ordering::Acquire);
            let head = unsafe { &*head_atomic }.load(Ordering::Relaxed);
            if head == tail {
                break;
            }
            let ev_sz = SHM_EVENT_SIZE;
            let mut head = head;
            while head != tail {
                // 读取一个事件 (28B); 环形可能回绕, 分段拷贝到栈上
                let mut raw = [0u8; 32];
                let dst = raw.as_mut_ptr();
                for i in 0..ev_sz {
                    let idx = (head.wrapping_add(i)) & SHM_RING_MASK;
                    unsafe { *dst.add(i as usize) = *ring.add(idx as usize); }
                }
                let event: EbpfProcEvent =
                    unsafe { core::ptr::read_unaligned(dst as *const EbpfProcEvent) };
                if tx.send(event).is_err() {
                    unsafe { libc::close(epfd) };
                    return;
                }
                // 唤醒主循环处理该事件
                let val: u64 = 1;
                let _ = unsafe { libc::write(kpm_wake_fd, &val as *const u64 as *const _, 8) };
                head = head.wrapping_add(ev_sz) & SHM_RING_MASK;
            }
            // release 推进 head (通知内核空间已释放; 与内核 smp_load_acquire 配对)
            unsafe { &*head_atomic }.store(head, Ordering::Release);
        }
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

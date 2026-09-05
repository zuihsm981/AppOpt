//! eBPF 事件驱动模式 → KPM(Kernel Patch Module)事件驱动模式
//!
//! 原实现用 aya 加载 eBPF 程序并读 RingBuf; 现改为通过 KernelPatch SuperCall
//! (syscall 45 = __NR_truncate) 与 appopt-kpm KPM 内核模块通信。
//!
//! 事件传输 (2025 改版): 不再让 reader 线程周期 supercall `drain` 轮询, 而是:
//!   - ctl0 `shm_open <eventfd>` 让内核把 256KB 事件环 remap 为共享内存 fd,
//!     并把 AppOpt 的 eventfd 注册为通知端;
//!   - reader 线程 mmap 该 fd, 阻塞在 eventfd 上, 被内核探针 eventfd_signal
//!     唤醒后直接从共享环消费事件 (SPSC, acquire/release 同步), 零轮询。
//! 控制面 (白名单 / APPLIED 表 / start-stop) 仍走 ctl0 supercall。
//!
//! 内核侧等价逻辑在 AppOpt-kpm/appopt_kpm.c:
//!   - tracepoint sched_process_fork/exec/exit + task_rename
//!   - 内联挂钩 input_handle_event (1s 节流)
//!   - 白名单(包名前 15 字节前缀匹配)、APPLIED tid 表、mmap 共享 256KB 事件环
//! 事件结构 EbpfProcEvent 与内核 appopt_proc_event_t 布局完全一致 (28B),
//! event_dispatch/affinity 逻辑与原先保持一致。

use std::collections::HashSet;
use std::ffi::CString;
use std::fs;
use std::os::raw::{c_char, c_int};
use std::sync::atomic::{AtomicU32, Ordering};
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

/* ================= mmap 共享内存事件环 (与内核 appopt_shm_t 布局一致) =================
 * 见 AppOpt-kpm/appopt_kpm.h。head/tail 是 32 位字节游标, 按 ring_size(2 的幂)回绕:
 *   内核 = 唯一生产者: 写 data[] 后以 release 发布 tail, 再写 eventfd 通知;
 *   AppOpt = 唯一消费者: 以 acquire 读 tail, 直接消费 data[head..tail),
 *           以 release 推进 head; 阻塞在 eventfd 上, 不再周期 supercall drain。
 * Rust 侧只写 head/读 tail; magic/version/event_size/ring_size 仅启动时校验。
 * 字段顺序与 C 端一致, 不能增删 (data[] 起始 = size_of::<ShmRing>() = 48)。 */
#[repr(C)]
pub struct ShmRing {
    pub magic: u32,
    pub version: u32,
    pub event_size: u32,
    pub ring_size: u32,
    pub head: AtomicU32,
    pub tail: AtomicU32,
    pub seq: u64,
    pub _reserved: [u8; 16],
}

pub const APPOPT_SHM_MAGIC: u32 = 0x4150_5054; // "APPT"
pub const APPOPT_SHM_VERSION: u32 = 1;
pub const APPOPT_SHM_HDR_SIZE: usize = 48; // size_of::<ShmRing>(), data[] 偏移
pub const APPOPT_EVENT_RING_SIZE: u32 = 256 * 1024;
pub const APPOPT_RING_MASK: u32 = APPOPT_EVENT_RING_SIZE - 1;
pub const APPOPT_EVENT_SZ: u32 = 28; // size_of::<EbpfProcEvent>()

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

    /// 建立 mmap 共享环 + eventfd 通知 (ctl0 `shm_open <eventfd_fd>`)。
    /// 成功返回内核在当前进程 fd 表安装的可 mmap anon inode fd (正数);
    /// 失败返回负错误码。须在 activate()/start 之前调用, 以免漏事件。
    fn shm_open(&self, evt_fd: c_int) -> i64 {
        let s = format!("shm_open {}", evt_fd);
        let c = CString::new(s).unwrap_or_default();
        kpm_ctl0(&self.key, &c, &mut [])
    }

    /// 解除内核侧 eventfd 通知绑定 (AppOpt 退出 / 降级 /proc 模式时调用)
    fn shm_close(&self) {
        let c = CString::new("shm_close").unwrap_or_default();
        kpm_ctl0(&self.key, &c, &mut []);
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
    /// 内核共享环事件通知 fd: AppOpt 创建的 eventfd, ctl0 shm_open 注册给内核;
    /// 内核探针写入事件后 signal 之, reader 阻塞在此 fd 上 (替代 drain 轮询)
    pub evt_fd: c_int,
    /// ctl0 shm_open 返回的可 mmap 共享环 fd (内核 anon inode)
    pub shm_fd: c_int,
    pub comm_capacity: u32,
}

impl Drop for EbpfState {
    fn drop(&mut self) {
        // 通知内核解除 eventfd 绑定 (best-effort; 模块可能已被卸载)
        self.bpf.shm_close();
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
        // evt_fd/shm_fd 为本模块创建; reader 已退出 (mmap 已由 reader 解除)
        if self.evt_fd >= 0 {
            unsafe { libc::close(self.evt_fd); }
        }
        if self.shm_fd >= 0 {
            unsafe { libc::close(self.shm_fd); }
        }
        // kpm_wake_fd 由主循环创建并管理生命周期, Drop 不关闭
        self.kpm_wake_fd = -1;
        self.evt_fd = -1;
        self.shm_fd = -1;
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

    // ---- 建立事件传输通道: mmap 共享环 + eventfd 通知 (替代 drain 轮询) ----
    // evt_fd: AppOpt 创建的 eventfd, 经 ctl0 shm_open 注册给内核; 内核探针
    // 发布事件后 signal 之, reader 线程阻塞等待 (零周期轮询)。
    let evt_fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
    if evt_fd < 0 {
        return None;
    }
    // ctl0 shm_open: 绑定 evt_fd(通知端) + 在当前进程安装可 mmap 的 anon fd
    let shm_fd = handle.shm_open(evt_fd);
    if shm_fd < 0 || shm_fd > i64::from(i32::MAX) {
        unsafe { libc::close(evt_fd); }
        return None;
    }
    let shm_fd = shm_fd as c_int;

    // 立即 mmap 并校验共享环头; 校验失败视为模块/客户端不匹配, 干净失败
    // 让调用方回退 /proc (reader 线程不再负责映射, 避免启动后静默失联)。
    let map_len = APPOPT_SHM_HDR_SIZE + APPOPT_EVENT_RING_SIZE as usize;
    let shm_base = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            map_len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            shm_fd,
            0,
        )
    };
    if shm_base == libc::MAP_FAILED {
        unsafe { libc::close(evt_fd); }
        unsafe { libc::close(shm_fd); }
        return None;
    }
    {
        let hdr = shm_base as *const ShmRing;
        let ok = unsafe {
            (*hdr).magic == APPOPT_SHM_MAGIC
                && (*hdr).version == APPOPT_SHM_VERSION
                && (*hdr).event_size == APPOPT_EVENT_SZ
                && (*hdr).ring_size == APPOPT_EVENT_RING_SIZE
        };
        if !ok {
            unsafe { libc::munmap(shm_base, map_len); }
            unsafe { libc::close(evt_fd); }
            unsafe { libc::close(shm_fd); }
            handle.shm_close(); // 释放内核侧 eventfd 绑定
            return None;
        }
    }

    let (tx, rx) = mpsc::channel::<EbpfProcEvent>();
    let wakeup_fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
    if wakeup_fd < 0 {
        unsafe { libc::munmap(shm_base, map_len); }
        unsafe { libc::close(evt_fd); }
        unsafe { libc::close(shm_fd); }
        handle.shm_close(); // 释放内核侧 eventfd 绑定
        return None;
    }

    // reader 线程: 阻塞在 evt_fd(内核 eventfd 通知) + wakeup_fd(退出信号),
    // 直接消费 mmap 共享环, 收到后写 kpm_wake_fd 唤醒主循环。
    // 注意: 共享环指针以 usize 传入 move 闭包 (裸指针非 Send)。
    let shm_ptr = shm_base as usize;
    let reader_thread = thread::spawn(move || {
        kpm_shm_reader(shm_ptr, map_len, evt_fd, tx, wakeup_fd, kpm_wake_fd);
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
        evt_fd,
        shm_fd,
        comm_capacity: capacity,
    })
}

/// mmap 共享环消费者线程 (替代原 supercall drain 轮询):
/// 阻塞在 evt_fd(内核 eventfd 通知) 上; 唤醒后直接从共享环消费事件,
/// 以 release 推进 head 让内核回收空间, 再写 kpm_wake_fd 唤醒主循环。
/// shm_base 由 ebpf_init 提前 mmap+校验, 线程结束时 munmap。
fn kpm_shm_reader(
    shm_base: usize,
    map_len: usize,
    evt_fd: c_int,
    tx: mpsc::Sender<EbpfProcEvent>,
    wakeup_fd: c_int,
    kpm_wake_fd: c_int,
) {
    let name = CString::new("KpmShmReader").unwrap();
    unsafe {
        libc::pthread_setname_np(libc::pthread_self(), name.as_ptr());
    }
    let base = shm_base as *mut libc::c_void;

    let hdr = base as *mut ShmRing;
    let data = unsafe { (base as *mut u8).add(APPOPT_SHM_HDR_SIZE) };
    let ev_sz = APPOPT_EVENT_SZ as usize;
    let ring_mask = (APPOPT_EVENT_RING_SIZE as usize) - 1;

    // ---- epoll: evt_fd(内核事件通知) + wakeup_fd(退出信号) ----
    let epfd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
    if epfd < 0 {
        unsafe { libc::munmap(base, map_len); }
        return;
    }
    let mut ev: libc::epoll_event = unsafe { std::mem::zeroed() };
    ev.events = libc::EPOLLIN as u32;
    ev.u64 = 1; // evt_fd
    if unsafe { libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, evt_fd, &mut ev) } < 0 {
        unsafe { libc::close(epfd); }
        unsafe { libc::munmap(base, map_len); }
        return;
    }
    ev.u64 = 2; // wakeup_fd (退出)
    if unsafe { libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, wakeup_fd, &mut ev) } < 0 {
        unsafe { libc::close(epfd); }
        unsafe { libc::munmap(base, map_len); }
        return;
    }
    let mut events: [libc::epoll_event; 2] = unsafe { std::mem::zeroed() };

    // head 仅由本消费者线程写; shm_open 已清零环, 取当前 head 即可
    let mut head: u32 = unsafe { (*hdr).head.load(Ordering::Acquire) };

    loop {
        // 阻塞等待: 新事件(evt_fd) / 退出(wakeup_fd)。无事件时线程沉睡, 零轮询。
        let n = unsafe { libc::epoll_wait(epfd, events.as_mut_ptr(), 2, -1) };
        if n < 0 {
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            break;
        }
        let mut exit = false;
        for i in 0..n as usize {
            if events[i].u64 == 2 {
                exit = true; // wakeup: 退出
            }
        }
        if exit {
            break;
        }

        // 复位+消费循环: 直到“环已空 且 eventfd 计数已清零”才回 epoll 阻塞。
        // 关键: 清零 eventfd 后必须复查环, 防止清零瞬间新事件发布(其 signal
        // 已被读出)造成漏唤醒。
        loop {
            // 1) 消费当前全部已发布事件 (可能有新事件边读边来)
            let mut sent = 0usize;
            loop {
                let tail = unsafe { (*hdr).tail.load(Ordering::Acquire) };
                let used = tail.wrapping_sub(head) & APPOPT_RING_MASK;
                if used < APPOPT_EVENT_SZ {
                    break;
                }
                let n_ev = used / APPOPT_EVENT_SZ;
                for _ in 0..n_ev {
                    let mut event: EbpfProcEvent = unsafe { std::mem::zeroed() };
                    // 逐字节拷贝一个 28B 事件 (允许跨环尾回绕)
                    for k in 0..ev_sz {
                        let idx = (head as usize + k) & ring_mask;
                        unsafe {
                            *((&mut event as *mut EbpfProcEvent as *mut u8).add(k)) = *data.add(idx);
                        }
                    }
                    head = head.wrapping_add(APPOPT_EVENT_SZ) & APPOPT_RING_MASK;
                    if tx.send(event).is_err() {
                        exit = true;
                        break;
                    }
                    sent += 1;
                }
                // release 推进 head: 让内核回收已消费空间
                unsafe { (*hdr).head.store(head, Ordering::Release); }
                if exit {
                    break;
                }
            }
            if exit {
                break;
            }
            // 2) 通知主循环 (每批一次; 主循环会排空 mpsc 再睡)
            if sent > 0 {
                let val: u64 = 1;
                let _ = unsafe { libc::write(kpm_wake_fd, &val as *const u64 as *const _, 8) };
            }
            // 3) 清零 eventfd 计数器 (非阻塞; 之后新的 signal 会产生新的 epoll 事件)
            let mut cnt: u64 = 0;
            let _ = unsafe { libc::read(evt_fd, &mut cnt as *mut u64 as *mut _, 8) };
            // 4) 若清零期间又有新事件发布(其 signal 已被上面的 read 清零), 继续消费
            if unsafe { (*hdr).tail.load(Ordering::Relaxed) } == head {
                break; // 环空且计数器已复位 -> 回到 epoll_wait 阻塞
            }
        }
        if exit {
            break;
        }
    }
    unsafe { libc::close(epfd); }
    unsafe { libc::munmap(base, map_len); }
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

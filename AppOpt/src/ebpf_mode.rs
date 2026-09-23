//! KPM 事件环模式 (KernelPatch KPM 内核模块, syscall 45 通信)
//!
//! 事件环 (input 事件通道): ctl0 `shm_open <eventfd>` 让内核把 256KB 事件环
//! remap 为共享内存 fd 并把 AppOpt 的 eventfd 注册为通知端; reader 线程 mmap
//! 该 fd, 阻塞在 eventfd 上, 唤醒后直接从共享环消费 (SPSC, acquire/release
//! 同步), 零轮询。input 检测已统一用户态 eventX (内核 input kprobe 不再武装,
//! 本事件环保留备用); 退出清理走 pidfd, 不经事件环。
//!
//! CPU 亲和性/刷新率不再由进程事件驱动: binder 前台回调 (pid+uid) 由主线程
//! 经 uid 静态表分发到 cpuset(按 uid 取应用) 与刷新率线程 (见 main.rs EV_FG,
//! cpu_affinity.rs, refresh.rs)。
//!
//! 控制面 (APPLIED 表 / start-stop / shm_open) 走 ctl0 supercall。
//!
//! 内核侧 (AppOpt-kpm/appopt_kpm.c):
//!   - kprobe input_handle_event (1s 节流)
//!   - kprobe sched_setaffinity (按 APPLIED bits 强制)
//!   - APPLIED tid 表、mmap 共享 256KB 事件环
//! 事件结构 EbpfProcEvent 与内核 appopt_proc_event_t 布局完全一致 (28B),
//! event_dispatch/affinity 逻辑与原先保持一致。

use std::ffi::CString;
use std::os::raw::{c_char, c_int};
// use std::sync::atomic::{AtomicU32, Ordering};  // 事件环停用, 临时注释
use std::sync::mpsc;
use std::thread;

use crate::config::AppConfig;

/// 安全构造 CString (输入受控/常量; 无 NUL 时保底空串, 避免 panic)
fn cstr(s: &str) -> CString {
    CString::new(s).unwrap_or_default()
}

/// eBPF 进程事件, 布局需与内核态 appopt_proc_event_t 完全一致 (28B)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct EbpfProcEvent {
    pub pid: i32,
    pub tid: i32,
    pub comm: [u8; 16],
    pub event_type: u32,
}

/* 事件环当前只流动 INPUT (内核事件已停用, 临时注释)
pub const EBPF_EVENT_INPUT: u32 = 5;*/

/* ================= mmap 共享内存事件环 (临时注释: 内核事件停用) =================
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
pub const APPOPT_SHM_HDR_SIZE: usize = 48;
pub const APPOPT_EVENT_RING_SIZE: u32 = 256 * 1024;
pub const APPOPT_RING_MASK: u32 = APPOPT_EVENT_RING_SIZE - 1;
pub const APPOPT_EVENT_SZ: u32 = 28;*/

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
            return cstr(&k);
        }
    }
    cstr("su")
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
        let args = cstr("ping");
        let mut out = [0u8; 16];
        kpm_ctl0(&self.key, &args, &mut out) >= 0 && out[0] == b'p'
    }

    /// 确认模块已加载 (由 APatch 管理器加载; AppOpt 不自动部署/加载)
    pub(crate) fn verify_loaded(&self) -> bool {
        self.ping()
    }

    /// ctl0 命令封装
    fn cmd(&self, args: &str) -> i64 {
        let c = cstr(args);
        kpm_ctl0(&self.key, &c, &mut [])
    }

    /// service list 伪装开关 (前台回调驱动): on=true 激活(无差别替换 listServices)
    pub(crate) fn srv_active(&self, on: bool) {
        let args = format!("srv_active {}", if on { 1 } else { 0 });
        self.cmd(&args);
    }

    /// 清空全部替换规则 (waylay.conf 重载前)
    pub(crate) fn srv_clear(&self) {
        self.cmd("srv_clear");
    }

    /// 设置第 idx 组等长替换规则 (from→to, 字符数一致)
    pub(crate) fn srv_rule(&self, idx: usize, from: &str, to: &str) {
        let args = format!("srv_rule {} {} {}", idx, from, to);
        self.cmd(&args);
    }

    /// 武装 KPM (start: affinity 拦截 + 清理探针 + service list 伪装)
    pub(crate) fn arm(&self) {
        self.cmd("start");
    }

    /// 解除武装 (stop: 摘除全部业务探针)
    pub(crate) fn disarm(&self) {
        self.cmd("stop");
    }

    /// 清空内核 property 替换规则表 (waylay.conf [prop] 段重载前调用)
    pub(crate) fn prop_clear(&self) {
        self.cmd("prop_clear");
    }

    /// 设置第 i 组 property 替换规则 (from→to, 等长 ASCII ≤32)
    pub(crate) fn prop_rule(&self, i: usize, from: &str, to: &str) {
        let s = format!("prop_rule {} {} {}", i, from, to);
        self.cmd(&s);
    }

    /// 内核态 property 区等长替换 (lineage<->hyperos): 解析本进程 maps 中
    /// /dev/__properties__/ 共享 vma 地址, 交内核 access_process_vm 写穿
    /// (共享物理页 → 全部进程生效)。on=true 替换 lineage→hyperos, false 恢复。
    pub(crate) fn prop_apply(&self, on: bool) {
        use std::fmt::Write as _;
        let mut s = String::from(if on { "prop_apply 1" } else { "prop_apply 0" });
        if let Ok(maps) = std::fs::read_to_string("/proc/self/maps") {
            for line in maps.lines() {
                if !line.contains("__properties__") {
                    continue;
                }
                let mut it = line.split_whitespace();
                let (Some(rng), Some(_perm)) = (it.next(), it.next()) else { continue };
                let Some((st, en)) = rng.split_once('-') else { continue };
                if let (Ok(a), Ok(b)) = (
                    u64::from_str_radix(st, 16),
                    u64::from_str_radix(en, 16),
                ) {
                    if b > a {
                        let _ = write!(s, " {:x} {:x}", a, b - a);
                    }
                }
            }
        }
        self.cmd(&s);
    }

    /* ---- 事件环通道 (shm_open/shm_close): 临时注释 —— 内核已无事件生产者,
     * 不再建立/解除事件通道 (见 kpm_shm_reader 注释) ----
    fn shm_open(&self, evt_fd: c_int) -> i64 {
        let s = format!("shm_open {}", evt_fd);
        let c = cstr(&s);
        kpm_ctl0(&self.key, &c, &mut [])
    }

    fn shm_close(&self) {
        let c = cstr("shm_close");
        kpm_ctl0(&self.key, &c, &mut []);
    }
    */

}

/// 将内核 comm 截断于首个 NUL 并 trim 尾部空白
pub struct EbpfState {
    pub event_rx: mpsc::Receiver<EbpfProcEvent>,
    pub reader_thread: Option<thread::JoinHandle<()>>,
    /// KPM 传输句柄 (ctl0 supercall 通道); 字段名 bpf 沿用历史
    pub bpf: KpmHandle,
    pub wakeup_fd: c_int,
    /// 事件到达通知 fd (eventfd): reader 收到事件后写入, 唤醒主循环 epoll
    pub kpm_wake_fd: c_int,
    /// 内核共享环事件通知 fd: AppOpt 创建的 eventfd, ctl0 shm_open 注册给内核;
    /// 内核探针写入事件后 signal 之, reader 阻塞在此 fd 上 (替代 drain 轮询)
    pub evt_fd: c_int,
    /// ctl0 shm_open 返回的可 mmap 共享环 fd (内核 anon inode)
    pub shm_fd: c_int,
}

impl Drop for EbpfState {
    fn drop(&mut self) {
        // 通知内核解除 eventfd 绑定 (best-effort; 模块可能已被卸载)
        // 临时注释: 事件通道已停用 (shm_open/shm_close 注释)
        // self.bpf.shm_close();
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

/// 初始化 KPM 事件驱动: 确保模块加载, 启动 reader 线程
/// 失败返回 None, 由调用方回退纯用户态事件驱动 (binder+pidfd+触摸, 无 /proc 轮询)。
/// kpm_wake_fd 由主循环创建并注册 epoll, reader 收到事件后写入以唤醒主循环。
/// 初始化 KPM 事件驱动。drive_mode: "userspace" 直接纯用户态(不依赖 KPM);
/// "auto" ping 失败快速回退纯用户态; "kpm" 等待模块长时间重试。
pub fn ebpf_init(kpm_wake_fd: c_int, drive_mode: String) -> Option<EbpfState> {
    // 设置项工作模式 UI 已移除: 不再因 userspace 直退 —— 只要模块加载 (ping 成功)
    // 即可用 KPM (连接由拦截页控制); drive_mode 仅保留签名兼容。
    let _ = drive_mode;

    // 不重试: 连接不上 KPM 就直接回退用户态模式 (4.19 常无 KPM/或 KP hook 不可用)
    let key = kpm_key();
    if !kp_ready(&key) {
        return None;
    }

    let handle = KpmHandle { key };
    if !handle.verify_loaded() {
        return None;
    }

    // 配置 input 节流 (与 eBPF 默认 1s 一致)
    // 临时注释: 内核无 input_ms 命令 (input 已用户态 eventX)
    // handle.cmd("input_ms 1000");

    /* ---- 事件传输通道 (mmap 共享环 + eventfd + reader 线程): 临时注释 ----
     * 内核已无事件生产者 (input/exit 事件已移除, SRV 替换纯内核不发事件),
     * 不再建立事件环通道。主循环 EV_KPM 因 kpm_wake_fd 无写者而空转;
     * kpm_died 断开检测随之停用 (临时取舍)。
     * ---- 取消注释即恢复事件环 ----
    let evt_fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
    if evt_fd < 0 {
        return None;
    }
    let shm_fd = handle.shm_open(evt_fd);
    if shm_fd < 0 || shm_fd > i64::from(i32::MAX) {
        unsafe { libc::close(evt_fd); }
        return None;
    }
    let shm_fd = shm_fd as c_int;
    let map_len = APPOPT_SHM_HDR_SIZE + APPOPT_EVENT_RING_SIZE as usize;
    let shm_base = unsafe {
        libc::mmap(std::ptr::null_mut(), map_len, libc::PROT_READ | libc::PROT_WRITE,
                   libc::MAP_SHARED, shm_fd, 0)
    };
    if shm_base == libc::MAP_FAILED {
        unsafe { libc::close(evt_fd); }
        unsafe { libc::close(shm_fd); }
        return None;
    }
    {
        let hdr = shm_base as *const ShmRing;
        let ok = unsafe {
            (*hdr).magic == APPOPT_SHM_MAGIC && (*hdr).version == APPOPT_SHM_VERSION
                && (*hdr).event_size == APPOPT_EVENT_SZ
                && (*hdr).ring_size == APPOPT_EVENT_RING_SIZE
        };
        if !ok {
            unsafe { libc::munmap(shm_base, map_len); }
            unsafe { libc::close(evt_fd); }
            unsafe { libc::close(shm_fd); }
            handle.shm_close();
            return None;
        }
    }
    let (tx, rx) = mpsc::channel::<EbpfProcEvent>();
    let wakeup_fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
    if wakeup_fd < 0 {
        unsafe { libc::munmap(shm_base, map_len); }
        unsafe { libc::close(evt_fd); }
        unsafe { libc::close(shm_fd); }
        handle.shm_close();
        return None;
    }
    let shm_ptr = shm_base as usize;
    let reader_thread = thread::spawn(move || {
        kpm_shm_reader(shm_ptr, map_len, evt_fd, tx, wakeup_fd, kpm_wake_fd);
    });
    */

    // 事件环停用: 仅保留空事件接收端 (主循环 EV_KPM try_recv 恒 Empty, 空转)
    let (_tx, rx) = mpsc::channel::<EbpfProcEvent>();

    // 不自动武装 (start): 初始化只加载/握手; 武装由 webui 拦截页「连接」触发
    // (KpmHandle::arm → start; affinity 拦截 + 清理探针 + service list 伪装随武装启用)

    Some(EbpfState {
        event_rx: rx,
        reader_thread: None,
        bpf: handle,
        wakeup_fd: -1,
        kpm_wake_fd,
        evt_fd: -1,
        shm_fd: -1,
    })
}

/* ===== 事件环消费者线程: 临时注释 (内核无事件生产者) =====
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
    let name = cstr("KpmShmReader");
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
*/

/// 事件派发 (input: 刷新率活动检测; 退出清理统一由用户态 pidfd 负责,
/// 内核 EXIT 事件不再消费; CPU/刷新率主体由 binder 三线程驱动)
pub fn event_dispatch(event: &EbpfProcEvent, _cfg: &AppConfig, _state: &mut EbpfState)  {
    /* 临时注释: 事件环已停用, 内核不发事件 (input 用户态, SRV 纯内核) */
    let _ = event;
}



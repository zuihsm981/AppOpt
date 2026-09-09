//! KPM 事件环模式 (KernelPatch KPM 内核模块, syscall 45 通信)
//!
//! 事件环仅承载 input 事件 (刷新率活动检测): ctl0 `shm_open <eventfd>` 让内核
//! 把 256KB 事件环 remap 为共享内存 fd 并把 AppOpt 的 eventfd 注册为通知端;
//! reader 线程 mmap 该 fd, 阻塞在 eventfd 上, 被内核 input kprobe eventfd_signal
//! 唤醒后直接从共享环消费 (SPSC, acquire/release 同步), 零轮询。
//!
//! CPU 亲和性/刷新率不再由进程事件驱动: binder 前台回调 (pid+uid) 由主线程
//! 经 uid 静态表分发到 cpuset(按 uid 枚举应用) 与刷新率线程 (见 main.rs EV_FG,
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
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc;
use std::thread;

use crate::apply_affinity::tid_comm;
use crate::config::AppConfig;

/// 连接诊断日志 (临时): /data/local/tmp/appopt_conn.log + stderr
fn conn_log(msg: &str) {
    use std::io::Write;
    eprintln!("[appopt_conn] {}", msg);
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true).append(true)
        .open("/data/local/tmp/appopt_conn.log")
    {
        let _ = writeln!(f, "[{:?}] {}", std::time::SystemTime::now(), msg);
    }
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

/// 事件环当前只流动 INPUT (CPU/刷新率由 binder 三线程驱动, 无进程事件)
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
    pub(crate) fn verify_loaded(&self) -> bool {
        self.ping()
    }

    /// ctl0 命令封装
    fn cmd(&self, args: &str) -> i64 {
        let c = CString::new(args).unwrap_or_default();
        kpm_ctl0(&self.key, &c, &mut [])
    }

    pub(crate) fn applied_set(&self, tid: i32, bits: u64) {
        let s = format!("applied_set {} {:x}", tid, bits);
        self.cmd(&s);
    }

    /// AppOpt 初始化完成后激活 KPM: start 武装 sched_setaffinity kprobe + input_on 武装 input kprobe
    pub fn activate(&self) {
        self.cmd("start");
        self.cmd("input_on");
    }

    /// 标记规则应用主进程 tgid (内核退出探针只对主进程发布 EXIT 事件;
    /// 子进程/线程退出被内核过滤)
    pub(crate) fn applied_set_main(&self, pid: i32) {
        let s = format!("applied_set_main {}", pid);
        self.cmd(&s);
    }

    pub(crate) fn applied_clear(&self) {
        self.cmd("clear_applied");
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

    /// drain: 内核充当消费者, 把共享环可用事件拷到 out (hook 路径/4.19 传输)。
    /// 返回实际拷贝字节数 (28 的倍数), 负=错误; 零=环空。
    fn drain(&self, out: &mut [u8]) -> i64 {
        let c = CString::new("drain").unwrap_or_default();
        kpm_ctl0(&self.key, &c, out)
    }

    /// 查询模块事件通道模式: "hook"(KP hook 路径/4.19) / "kprobe"(6.6)
    fn mode(&self) -> Option<String> {
        let mut out = [0u8; 16];
        let c = CString::new("mode").unwrap_or_default();
        let rc = kpm_ctl0(&self.key, &c, &mut out);
        if rc < 0 {
            return None;
        }
        let s = String::from_utf8_lossy(&out);
        let s = s.trim_end_matches('\0').trim().to_string();
        if s.is_empty() { None } else { Some(s) }
    }

    /// 仅绑定 evt_fd 为内核事件通知端 (hook/drain 通道, 不创建 anon fd)
    fn shm_bind(&self, evt_fd: c_int) -> i64 {
        let s = format!("shm_bind {}", evt_fd);
        let c = CString::new(s).unwrap_or_default();
        kpm_ctl0(&self.key, &c, &mut [])
    }
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

/// 初始化 KPM 事件驱动: 确保模块加载, 启动 reader 线程
/// 失败返回 None, 由调用方回退 /proc 轮询。
/// kpm_wake_fd 由主循环创建并注册 epoll, reader 收到事件后写入以唤醒主循环。
pub fn ebpf_init(kpm_wake_fd: c_int) -> Option<EbpfState> {
    let key = kpm_key();
    if !kp_ready(&key) {
        conn_log("ebpf_init: kp_ready=false (KP/superkey 不可用)");
        return None;
    }

    let handle = KpmHandle { key };
    if !handle.verify_loaded() {
        conn_log("ebpf_init: verify_loaded=false (ping 失败, 模块未加载?)");
        return None;
    }
    conn_log("ebpf_init: ping OK");

    // 配置 input 节流 (与 eBPF 默认 1s 一致)
    handle.cmd("input_ms 1000");

    // ---- 建立事件传输通道: mmap 共享环 + eventfd 通知 (仅此一种, 无 drain 回退) ----
    let evt_fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
    if evt_fd < 0 {
        conn_log(&format!("ebpf_init: eventfd 创建失败 errno={}", std::io::Error::last_os_error()));
        return None;
    }
    conn_log(&format!("ebpf_init: evt_fd={}", evt_fd));

    // ---- 按模块模式选事件通道: hook(4.19, fops 布局未知)直接 ctl0 drain,
    //     不创建 anon fd / 不 mmap; kprobe(6.6) 走 mmap 共享环。 ----
    let is_hook = handle.mode().map(|m| m == "hook").unwrap_or(false);
    if is_hook {
        conn_log("ebpf_init: hook 模式 -> 直接 ctl0 drain 事件通道");
        if handle.shm_bind(evt_fd) < 0 {
            conn_log("ebpf_init: shm_bind 失败 (绑定 evt_fd 为通知端)");
            unsafe { libc::close(evt_fd); }
            return None;
        }
        let (tx, rx) = mpsc::channel::<EbpfProcEvent>();
        let wakeup_fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
        if wakeup_fd < 0 {
            conn_log("ebpf_init: wakeup eventfd 创建失败");
            unsafe { libc::close(evt_fd); }
            return None;
        }
        let reader_thread = thread::spawn(move || {
            kpm_drain_reader(evt_fd, tx, wakeup_fd, kpm_wake_fd);
        });
        // 4.19 hook 模式【测试2】: 只武装 input 钩子 (1s 节流 → drain ≤1次/s),
        // 不 start (不装 do_exit/setaffinity → 无线程退出风暴)。
        // 若稳定 → 坐实 exit 事件风暴是元凶; 若仍崩 → input 钩子/drain 低频也触发。
        handle.cmd("input_on");
        // handle.cmd("start");   // 暂不装 exit/setaffinity
        conn_log("ebpf_init: OK (drain 事件通道建立, reader 已启动; 仅 input 武装)");
        return Some(EbpfState {
            event_rx: rx,
            reader_thread: Some(reader_thread),
            bpf: handle,
            wakeup_fd,
            kpm_wake_fd,
            evt_fd,
            shm_fd: -1,
        });
    }

    conn_log("ebpf_init: kprobe 模式 -> mmap 事件通道");
    // ctl0 shm_open: 绑定 evt_fd(通知端) + 在当前进程安装可 mmap 的 anon fd
    let shm_fd = handle.shm_open(evt_fd);
    conn_log(&format!("ebpf_init: shm_open -> {}", shm_fd));
    if shm_fd < 0 || shm_fd > i64::from(i32::MAX) {
        unsafe { libc::close(evt_fd); }
        return None;
    }
    let shm_fd = shm_fd as c_int;

    // 立即 mmap 并校验共享环头; 校验失败视为模块/客户端不匹配
    // (kprobe 路径 mmap 必然成功; 失败直接放弃, 不兜底)
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
        conn_log(&format!("ebpf_init: mmap 失败 errno={}", std::io::Error::last_os_error()));
        unsafe { libc::close(evt_fd); }
        unsafe { libc::close(shm_fd); }
        return None;
    }
    conn_log("ebpf_init: mmap OK");
    {
        let hdr = shm_base as *const ShmRing;
        let ok = unsafe {
            (*hdr).magic == APPOPT_SHM_MAGIC
                && (*hdr).version == APPOPT_SHM_VERSION
                && (*hdr).event_size == APPOPT_EVENT_SZ
                && (*hdr).ring_size == APPOPT_EVENT_RING_SIZE
        };
        if !ok {
            unsafe {
                conn_log(&format!(
                    "ebpf_init: 共享环头校验失败 magic={:08x}(需{:08x}) ver={}(需{}) esz={}(需{}) rsz={}(需{})",
                    (*hdr).magic, APPOPT_SHM_MAGIC, (*hdr).version, APPOPT_SHM_VERSION,
                    (*hdr).event_size, APPOPT_EVENT_SZ, (*hdr).ring_size, APPOPT_EVENT_RING_SIZE,
                ));
            }
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
        conn_log("ebpf_init: wakeup eventfd 创建失败");
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

    handle.activate();
    conn_log("ebpf_init: OK (reader 已启动, 事件通道建立)");

    Some(EbpfState {
        event_rx: rx,
        reader_thread: Some(reader_thread),
        bpf: handle,
        wakeup_fd,
        kpm_wake_fd,
        evt_fd,
        shm_fd,
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

/// drain 传输 reader (hook 路径/4.19): 阻塞在 evt_fd (内核 eventfd 通知) 上,
/// 唤醒后调一次 ctl0 drain 取整批事件, 零轮询; wakeup_fd 用于退出。
fn kpm_drain_reader(
    evt_fd: c_int,
    tx: mpsc::Sender<EbpfProcEvent>,
    wakeup_fd: c_int,
    kpm_wake_fd: c_int,
) {
    let name = CString::new("KpmDrainReader").unwrap();
    unsafe {
        libc::pthread_setname_np(libc::pthread_self(), name.as_ptr());
    }
    let handle = KpmHandle::new();
    let ev_sz = APPOPT_EVENT_SZ as usize;

    // epoll: evt_fd(内核事件通知) + wakeup_fd(退出信号)
    let epfd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
    if epfd < 0 {
        return;
    }
    let mut ev: libc::epoll_event = unsafe { std::mem::zeroed() };
    ev.events = libc::EPOLLIN as u32;
    ev.u64 = 1; // evt_fd
    if unsafe { libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, evt_fd, &mut ev) } < 0 {
        unsafe { libc::close(epfd); }
        return;
    }
    ev.u64 = 2; // wakeup_fd
    if unsafe { libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, wakeup_fd, &mut ev) } < 0 {
        unsafe { libc::close(epfd); }
        return;
    }
    let mut events: [libc::epoll_event; 2] = unsafe { std::mem::zeroed() };
    let mut buf = [0u8; 4096];

    loop {
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
                exit = true;
            }
        }
        if exit {
            break;
        }

        // 消费循环: 清零 eventfd 计数 → drain 取批 → 直到环空才回 epoll 阻塞。
        // 清零后若新事件到达其 signal 使计数器非零, epoll 会再次触发, 不漏。
        loop {
            // 1) 清零 eventfd 计数器 (非阻塞)
            let mut cnt: u64 = 0;
            let _ = unsafe { libc::read(evt_fd, &mut cnt as *mut u64 as *mut _, 8) };
            // 2) 调一次 ctl0 drain 取整批
            let nb = handle.drain(&mut buf);
            if nb <= 0 {
                break; // 环空
            }
            let nb = nb as usize;
            let n_ev = nb / ev_sz;
            for e in 0..n_ev {
                let off = e * ev_sz;
                let mut event: EbpfProcEvent = unsafe { std::mem::zeroed() };
                for k in 0..ev_sz {
                    unsafe {
                        *((&mut event as *mut EbpfProcEvent as *mut u8).add(k)) = buf[off + k];
                    }
                }
                if tx.send(event).is_err() {
                    exit = true;
                    break;
                }
            }
            if exit {
                break;
            }
            // 3) 通知主循环 (每批一次; 主循环会排空 mpsc 再睡)
            let val: u64 = 1;
            let _ = unsafe { libc::write(kpm_wake_fd, &val as *const u64 as *const _, 8) };
            // 4) 若本批把缓冲填满, 可能还有事件, 继续 drain
            if nb < buf.len() {
                break;
            }
        }
        if exit {
            break;
        }
    }
    unsafe { libc::close(epfd); }
}

/// 按需武装/卸载 input 触摸事件 kprobe (ctl0 input_on/input_off):
/// 刷新率活跃==空闲时无 idle→active 切换, 卸载触摸钩子省开销; 不同时重新安装。
pub fn set_input_hook(on: bool) {
    let h = KpmHandle::new();
    if on {
        h.cmd("input_on");
    } else {
        h.cmd("input_off");
    }
}

/// 事件派发 (input: 刷新率活动检测; EXIT: 规则应用主进程退出 → 清身份;
/// CPU/刷新率主体由 binder 三线程驱动)
pub const EBPF_EVENT_EXIT: u32 = 4;
pub fn event_dispatch(event: &EbpfProcEvent, _cfg: &AppConfig, _state: &mut EbpfState) {
    // CPU 亲和性已由 binder 触发的 CpuAffinity 模块负责 (cpu_affinity.rs):
    // 进程事件不驱动 CPU 逻辑; input 仅用于刷新率活动检测。
    if event.event_type == EBPF_EVENT_INPUT {
        crate::refresh::refresh_on_event(EBPF_EVENT_INPUT, 0);
    } else if event.event_type == EBPF_EVENT_EXIT && event.tid == event.pid {
        // 规则应用主进程退出 (内核已按 APPLIED+主进程标记过滤非规则应用/非主进程):
        // 清除该 uid 的 pid 列表与 cpu_known 身份, 并按 uid 通知 CPU worker 清除该
        // 应用 managed 条目 → web 命中应用/绑定线程立即归零 (事件驱动, 不等周期清理)。
        if let Some(uid) = crate::cpu_affinity::cpu_known_evict_by_pid(event.pid) {
            if let Some(tx) = crate::cpu_affinity::cpu_fg_tx() {
                let _ = tx.send(crate::cpu_affinity::CpuMsg::EvictUid(uid));
            }
        }
    }
}

/// 启动或配置更新时全量扫描 /proc
pub fn full_scan(_cfg: &AppConfig, _state: &mut EbpfState) {
    // CPU 亲和性已由 binder 触发的 CpuAffinity 模块负责 (cpu_affinity.rs),
    // 此处仅保留默认桌面进程绑定 (刷新率全局配置入口)。
    let mut launcher_found = false;
    if let Ok(entries) = std::fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let Ok(pid) = entry.file_name().to_string_lossy().parse::<i32>() else { continue };
            if tid_comm(pid).as_deref() == Some(crate::config::DEFAULT_REFRESH_COMM) {
                launcher_found = true;
            }
        }
    }
    if launcher_found {
        crate::refresh::refresh_bind_default_launcher();
    }
}

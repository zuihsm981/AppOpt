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

/// 调试日志: 追加到 /data/local/tmp/appopt_debug.log (可靠, 不受启动方式影响)
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
    pub comm_capacity: u32,
}

impl Drop for EbpfState {
    fn drop(&mut self) {
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

/// 调试日志: 同时输出到 stderr 和 /data/local/tmp/appopt_debug.log
/// (文件方式可靠, 不受 AppOpt 启动方式影响; stderr 仅前台终端可见)
macro_rules! kpm_log {
    ($($arg:tt)*) => {{
        let msg = format!($($arg)*);
        eprintln!("{}", msg);
        use std::io::Write;
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open("/data/local/tmp/appopt_debug.log")
        {
            let _ = writeln!(f, "{}", msg);
        }
    }};
}

/// 初始化 KPM 事件驱动: 确保模块加载, 启动 reader 线程
/// 失败返回 None, 由调用方回退 /proc 轮询
pub fn ebpf_init() -> Option<EbpfState> {
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

    // reader 线程通过 supercall drain 轮询事件
    let reader_key = kpm_key();
    let reader_thread = thread::spawn(move || {
        kpm_reader(reader_key, tx, wakeup_fd);
    });

    /* 先设置白名单再激活: start 注册 tracepoint 后立即开始过滤事件,
     * 若白名单为空则所有新进程事件被丢弃, 导致直接打开应用不设置亲和性 */
    let pkgs = crate::lock_ignore_poison(&CURRENT_CONFIG)
        .as_ref()
        .map(|cfg| cfg.pkgs.clone())
        .unwrap_or_default();
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
        comm_capacity: capacity,
    })
}

/// reader 线程: 轮询 drain, 解析事件送入 mpsc; wakeup_fd 用于 Drop 唤醒退出
fn kpm_reader(key: CString, tx: mpsc::Sender<EbpfProcEvent>, wakeup_fd: c_int) {
    let name = CString::new("KpmReader").unwrap();
    unsafe {
        libc::pthread_setname_np(libc::pthread_self(), name.as_ptr());
    }

    // epoll: 仅监听 wakeup_fd, 用 50ms 超时轮询 drain
    let epfd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
    if epfd < 0 {
        return;
    }
    let mut wake_ev: libc::epoll_event = unsafe { std::mem::zeroed() };
    wake_ev.events = libc::EPOLLIN as u32;
    wake_ev.u64 = 1;
    if unsafe { libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, wakeup_fd, &mut wake_ev) } < 0 {
        unsafe { libc::close(epfd) };
        return;
    }

    let mut events: [libc::epoll_event; 1] = unsafe { std::mem::zeroed() };
    // 单次 drain 缓冲: 8KB, 约 292 个事件
    let mut buf = vec![0u8; 8192];

    loop {
        let n = unsafe { libc::epoll_wait(epfd, events.as_mut_ptr(), 1, 50) };
        if n < 0 {
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            break;
        }
        // wakeup 事件优先退出
        if n > 0 && events[0].u64 == 1 {
            break;
        }

        // 轮询 drain, 直到暂时无事件
        loop {
            let args = CString::new("drain").unwrap_or_default();
            let got = unsafe {
                let (ptr, len) = (buf.as_mut_ptr(), buf.len());
                supercall(key.as_ptr(), SUPERCALL_KPM_CONTROL,
                          KPM_MODULE.as_ptr() as *const c_char,
                          args.as_ptr(), ptr, len)
            };
            if got <= 0 {
                break;
            }
            let bytes = got as usize;
            let ev_sz = std::mem::size_of::<EbpfProcEvent>();
            let mut off = 0;
            while off + ev_sz <= bytes {
                let event: EbpfProcEvent =
                    unsafe { std::ptr::read_unaligned(buf.as_ptr().add(off) as *const EbpfProcEvent) };
                if tx.send(event).is_err() {
                    unsafe { libc::close(epfd) };
                    return;
                }
                off += ev_sz;
            }
            // 若一次就取满, 可能还有更多, 继续; 否则退出内层循环
            if bytes < buf.len() {
                break;
            }
        }
    }
    unsafe { libc::close(epfd) };
}

/// 配置白名单; 返回 true 表示需重载 (KPM 白名单容量固定 16384, 不会触发)
pub fn comm_map_init(bpf: &mut KpmHandle, pkgs: &HashSet<String>, _comm_capacity: u32) -> bool {
    if !bpf.set_whitelist(pkgs) {
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
    cpuset_dir: &str,
    cfg: &AppConfig,
    bpf: &KpmHandle,
) -> bool {
    kpm_log!("affinity_apply: tid={} cpus={} (delayed, APPLIED only)", tid, cpus.to_range_string());
    applied_set(bpf, tid, cpus);
    kpm_log!("affinity_apply: tid={} APPLIED bits={:#x}", tid, cpus.bits[0]);
    false
}

/// 事件派发, 按 event_type 增量处理 FORK/RENAME/EXEC/EXIT (与 aya 版一致)
pub fn event_dispatch(event: &EbpfProcEvent, cfg: &AppConfig, state: &mut EbpfState) {
    let tid = event.tid;
    let pid = event.pid;
    let comm = comm_str(&event.comm);
    eprintln!("KPM event: type={} tid={} pid={} comm='{}'", event.event_type, tid, pid, comm);
    kpm_log!("KPM event: type={} tid={} pid={} comm='{}'", event.event_type, tid, pid, comm);

    match event.event_type {
        EBPF_EVENT_EXIT => {
            state.cache.task_del(tid);
            applied_del(&state.bpf, tid);
        }

        EBPF_EVENT_EXEC
            if !event_apply(&mut state.cache, &state.bpf, tid, pid, comm, cfg) => {
                state.cache.task_del(tid);
                applied_del(&state.bpf, tid);
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
    eprintln!("KPM event_apply: tid={} pid={} comm='{}' pkg={:?}", tid, pid, comm, pkg_result);
    kpm_log!("KPM event_apply: tid={} pid={} comm='{}' pkg={:?}", tid, pid, comm, pkg_result);
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
}
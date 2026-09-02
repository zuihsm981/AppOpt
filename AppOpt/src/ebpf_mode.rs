//! eBPF 事件驱动模式 → KPM(Kernel Patch Module)事件驱动模式
//!
//! 原实现用 aya 加载 eBPF 程序并读 RingBuf; 现改为通过 KernelPatch SuperCall
//! (syscall 45 = __NR_truncate) 与 appopt-kpm KPM 内核模块通信。
//!
//! 内核侧等价逻辑在 AppOpt-kpm/appopt_kpm.c:
//!   - tracepoint sched_process_fork/exec/exit + task_rename
//!   - 内联挂钩 input_handle_event (1s 节流)
//!   - 白名单(包名前/末 8 字节键, comm 8 字节滑动匹配)、APPLIED tid 表、256KB 事件环形缓冲
//!   - 事件写入环形缓冲后在"空→非空"边界 eventfd_signal() 通知用户态 (事件驱动)
//! 用户态通过 ctl0 命令配置/读取, 事件结构 EbpfProcEvent 与内核 appopt_proc_event_t
//! 布局完全一致 (28B), event_dispatch/affinity 逻辑与原先保持一致。
//!
//! 事件传输路径 (纯事件驱动, 无轮询):
//!   内核探针写入 ring → 空→非空 边界 eventfd_signal(notify_fd)
//!     → 主循环 epoll 唤醒 (EV_KPM) → read_eventfd 清零 → consume_events()
//!       消费共享环形缓冲 → event_dispatch 逐条处理 → 回到 epoll_wait 阻塞
//! 不再有 reader 线程 / 100ms epoll 轮询 / ctl0 数据拷贝；通知信号本身即唤醒源。

use std::collections::HashSet;
use std::ffi::CString;
use std::fs;
use std::os::raw::{c_char, c_int};
use std::sync::atomic::{AtomicU32, Ordering};

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

/* ================= KernelPatch SuperCall 传输 ================= */

/// SuperCall 复用 syscall 45 (__NR_truncate)
const NR_SUPERCALL: i64 = 45;
const SUPERCALL_HELLO: i64 = 0x1000;
const SUPERCALL_KPM_CONTROL: i64 = 0x1022;
const SUPERCALL_HELLO_MAGIC: i64 = 0x11581158;

/// KPM 模块名 (与 appopt_kpm.c KPM_NAME 一致)
const KPM_MODULE: &[u8] = b"appopt-kpm\0";
const EVENT_MAP_SIZE: usize = 266_240; // round_up(16 + 256 KiB, 4096)
const EVENT_HEADER_SIZE: usize = 16;
const EVENT_RING_SIZE: usize = 256 * 1024;
const EVENT_SIZE: usize = std::mem::size_of::<EbpfProcEvent>();

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

    /// 确认模块已加载；ping 只返回状态码，不读取 ctl0 输出缓冲。
    fn ping(&self) -> bool {
        let args = CString::new("ping").unwrap_or_default();
        kpm_ctl0(&self.key, &args, &mut []) >= 0
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

    /// 注册/更新事件通知 eventfd 到内核 (fd=-1 解除)。
    /// 内核在事件写入 mmap 环形缓冲后 eventfd_signal 唤醒主循环 epoll。
    pub fn set_eventfd(&self, fd: i32) -> bool {
        let s = format!("set_eventfd {}", fd);
        self.cmd(&s) >= 0
    }

    /// 清空共享事件环形缓冲。事件数据不再通过 ctl0 返回。
    fn clear_events(&self) -> bool {
        self.cmd("clear_events") >= 0
    }

    /// 请求内核创建匿名事件文件并返回其 fd 号。
    /// 内核在 init 阶段用 anon_inode_getfile 建好 file，ctl0 的 create_shm
    /// 只做非睡眠的 fd_install（RCU 临界区安全），把 fd 装入本进程 fd 表。
    fn create_shm(&self) -> Option<c_int> {
        let rc = self.cmd("create_shm");
        (rc > 0).then_some(rc as c_int)
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

#[repr(C)]
struct EventMap {
    head: AtomicU32,
    tail: AtomicU32,
    generation: u32,
    reserved: u32,
    events: [u8; EVENT_RING_SIZE],
}

pub struct EbpfState {
    /// 原 aya Ebpf 替换为 KPM 传输句柄; 字段名保持 bpf 以兼容 main.rs
    pub bpf: KpmHandle,
    pub cache: ProcCache,
    /// 内核 eventfd 通知 fd，由主循环创建并注册 epoll
    pub notify_fd: c_int,
    pub comm_capacity: u32,
    /// 匿名事件文件 fd（内核经 ctl0 create_shm 装入本进程 fd 表）；映射生命周期与状态绑定
    event_device_fd: c_int,
    /// mmap 共享事件区；事件数据直接从这里读取，不经过 ctl0
    event_map: *mut EventMap,
}

impl Drop for EbpfState {
    fn drop(&mut self) {
        // 先解除 eventfd，再取消映射并关闭设备 fd；ctl0 不再传输事件数据。
        let _ = self.bpf.set_eventfd(-1);
        if !self.event_map.is_null() {
            unsafe { libc::munmap(self.event_map as *mut libc::c_void, EVENT_MAP_SIZE); }
            self.event_map = std::ptr::null_mut();
        }
        if self.event_device_fd >= 0 {
            unsafe { libc::close(self.event_device_fd); }
            self.event_device_fd = -1;
        }
        self.notify_fd = -1;
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

/// 初始化 KPM 事件驱动: 确保模块加载, 注册事件通知 fd 到内核
/// 失败返回 None, 由调用方回退 /proc 轮询。
/// notify_fd 由主循环创建并注册 epoll: 内核写入事件后 eventfd_signal 唤醒
/// 主循环, 主循环随后 consume_events() 消费共享环形缓冲 (纯事件驱动, 无轮询、
/// 无 reader 线程、无 ctl0 用户态拷贝)。
pub fn ebpf_init(notify_fd: c_int) -> Option<EbpfState> {
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

    /* 请求内核创建匿名事件文件并 mmap 共享事件区。mmap 在用户态普通进程
     * 上下文执行；ctl0 只做 fd 安装，不再传输事件数据或 copy_to_user。 */
    let event_device_fd = handle.create_shm()?;
    let mapped = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            EVENT_MAP_SIZE,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            event_device_fd,
            0,
        )
    };
    if mapped == libc::MAP_FAILED {
        unsafe { libc::close(event_device_fd); }
        return None;
    }
    let event_map = mapped as *mut EventMap;

    /* 先注册通知 fd，再清空模块常驻/重启后的存量事件。这样即使旧会话
     * 在清空期间产生事件，也会留下 eventfd 唤醒；清空后新事件可正常走
     * 空→非空通知边界。 */
    if !handle.set_eventfd(notify_fd) || !handle.clear_events() {
        let _ = handle.set_eventfd(-1);
        unsafe {
            libc::munmap(mapped, EVENT_MAP_SIZE);
            libc::close(event_device_fd);
        }
        return None;
    }

    let pkgs_len = crate::lock_ignore_poison(&CURRENT_CONFIG)
        .as_ref()
        .map(|cfg| cfg.pkgs.len())
        .unwrap_or(0);
    let capacity = (pkgs_len * 2).max(512).next_power_of_two() as u32;

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
        bpf: handle,
        cache: ProcCache::new(),
        notify_fd,
        comm_capacity: capacity,
        event_device_fd,
        event_map,
    })
}

impl EbpfState {
    /// 事件驱动消费 mmap 共享环形缓冲。内核只负责发布 tail 和 eventfd 通知，
    /// 用户态读取稳定的 tail，处理所有已发布事件，最后 release-store head。
    /// ctl0 不再参与事件数据传输，因此不会在 RCU 临界区触发用户页缺页。
    pub fn consume_events(&mut self, cfg: &AppConfig) -> Option<bool> {
        if self.event_map.is_null() {
            return None;
        }
        let map_ptr = self.event_map;
        let mut head = unsafe { (*map_ptr).head.load(Ordering::Acquire) };
        let mut need_sync = false;

        loop {
            /* 读取本轮已发布的 tail；生产者可能在消费期间继续追加事件，
             * 因此发布 head 后必须重新读取 tail，避免“非空期间不重复 signal”
             * 导致追加事件永远没有下一次唤醒。 */
            let tail = unsafe { (*map_ptr).tail.load(Ordering::Acquire) };
            while head != tail {
                let pos = head as usize;
                let first = EVENT_SIZE.min(EVENT_RING_SIZE - pos);
                let mut raw = [0u8; EVENT_SIZE];
                unsafe {
                    /* 事件可能跨越环尾，分两段读取；这是 mmap 直接消费，
                     * 不经过 ctl0，也不会触发 ctl0 的用户页缺页路径。 */
                    std::ptr::copy_nonoverlapping(
                        (map_ptr as *const u8).add(EVENT_HEADER_SIZE + pos),
                        raw.as_mut_ptr(),
                        first,
                    );
                    if first < EVENT_SIZE {
                        std::ptr::copy_nonoverlapping(
                            (map_ptr as *const u8).add(EVENT_HEADER_SIZE),
                            raw.as_mut_ptr().add(first),
                            EVENT_SIZE - first,
                        );
                    }
                }
                let event: EbpfProcEvent = unsafe {
                    std::ptr::read_unaligned(raw.as_ptr() as *const EbpfProcEvent)
                };
                if event.event_type == EBPF_EVENT_FORK
                    || event.event_type == EBPF_EVENT_EXEC
                    || event.event_type == EBPF_EVENT_RENAME
                {
                    need_sync = true;
                }
                event_dispatch(&event, cfg, self);
                head = (head + EVENT_SIZE as u32) & (EVENT_RING_SIZE as u32 - 1);
            }

            /* release-store head 后，生产者才可以回收这段 ring 空间。
             * 若 tail 在本轮快照后前进，继续处理；若此时再次为空，
             * 后续生产者从空状态写入时会产生新的 eventfd 通知。 */
            unsafe { (*map_ptr).head.store(head, Ordering::Release); }
            if unsafe { (*map_ptr).tail.load(Ordering::Acquire) } == head {
                break;
            }
        }
        Some(need_sync)
    }
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
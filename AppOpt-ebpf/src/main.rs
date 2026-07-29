#![no_std]
#![no_main]
#![allow(linker_messages)]
#![allow(dead_code)]

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid},
    macros::{map, tracepoint},
    maps::{Array, HashMap, LruHashMap, RingBuf},
    programs::TracePointContext,
};

const EVENT_FORK: u32 = 1;
const EVENT_EXEC: u32 = 2;
const EVENT_RENAME: u32 = 3;
const EVENT_EXIT: u32 = 4;

/// 4 类 tracepoint 字段布局：fork 读 child_pid/child_comm，exec/exit 用 bpf_get_current_pid_tgid，rename 读 newcomm

/// 用户态解析 format 文件注入的字段偏移，因内核版本设备而异禁止硬编码
#[repr(C)]
#[derive(Clone, Copy)]
struct TracepointOffsets {
    fork_child_pid: u32,
    fork_child_comm: u32,
    rename_newcomm: u32,
}

/// 进程事件，布局需与用户态 EbpfProcEvent 一致
#[repr(C)]
struct ProcEvent {
    pid: i32,
    tid: i32,
    comm: [u8; 16],
    event_type: u32,
}

const MAP_CAPACITY: u32 = 16 << 5;
const APPLIED_CAPACITY: u32 = 8192;

/// 白名单键为包名前 8 字节或末 8 字节
#[map]
static TARGET_COMM_MAP: HashMap<[u8; 8], u32> = HashMap::with_max_entries(MAP_CAPACITY, 0);

/// 已应用亲和性表 tid 到 CPU mask，LruHashMap 配合 ESRCH 兜底
#[map]
static APPLIED_MAP: LruHashMap<u32, u64> = LruHashMap::with_max_entries(APPLIED_CAPACITY, 0);

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// 用户态注入的 tracepoint 字段偏移单条 Array 索引 0
#[map]
static OFFSETS_MAP: Array<TracepointOffsets> = Array::with_max_entries(1, 0);

/// 读取偏移，fork_child_pid 为 0 视为未注入返回 None
#[inline(always)]
fn offsets_load() -> Option<TracepointOffsets> {
    OFFSETS_MAP.get(0).and_then(|o| {
        if o.fork_child_pid != 0 {
            Some(*o)
        } else {
            None
        }
    })
}

/// 事件元信息
struct EventMeta {
    pid: i32,
    tid: i32,
    comm: [u8; 16],
    parent_tid: u32,
    parent_tgid: u32,
}

#[inline(always)]
fn applied_lookup(key: u32) -> bool {
    unsafe { APPLIED_MAP.get(&key) }.is_some()
}

/// 在 comm 16 字节上以 8 字节窗口滑动匹配白名单
#[inline(always)]
fn whitelist_matched(comm: &[u8; 16]) -> bool {
    for pos in 0..=8usize {
        let key: [u8; 8] = comm[pos..pos + 8].try_into().unwrap_or([0u8; 8]);
        if unsafe { TARGET_COMM_MAP.get(&key) }.is_some() {
            return true;
        }
    }
    false
}

#[inline(always)]
fn submit_event(event: ProcEvent) {
    if let Some(mut entry) = EVENTS.reserve(0) {
        entry.write(event);
        entry.submit(0);
    }
}

/// 解析 fork 字段，统一用 parent_tgid 作为 pid 确保 clone 共享 TGID，tid 为 child_pid
#[inline(always)]
fn fork_parse(ctx: &TracePointContext, offsets: &TracepointOffsets) -> EventMeta {
    let pid_tgid = bpf_get_current_pid_tgid();
    let parent_tid = (pid_tgid & 0xFFFFFFFF) as u32;
    let parent_tgid = (pid_tgid >> 32) as u32;
    let child_pid = unsafe { ctx.read_at::<i32>(offsets.fork_child_pid as usize).unwrap_or(0) };
    let child_comm =
        unsafe { ctx.read_at::<[u8; 16]>(offsets.fork_child_comm as usize).unwrap_or([0u8; 16]) };
    EventMeta {
        pid: parent_tgid as i32,
        tid: child_pid,
        comm: child_comm,
        parent_tid,
        parent_tgid,
    }
}

#[inline(always)]
fn exec_parse() -> EventMeta {
    let pid_tgid = bpf_get_current_pid_tgid();
    EventMeta {
        pid: (pid_tgid >> 32) as i32,
        tid: pid_tgid as i32,
        comm: bpf_get_current_comm().unwrap_or_default(),
        parent_tid: 0,
        parent_tgid: 0,
    }
}

/// FORK 检查已管理线程的父线程，EXEC 检查自身，均以白名单兜底
/// FORK 通过时立即占位 APPLIED_MAP[child_tid]=0，防 RENAME 竞态过滤
#[inline(always)]
fn report_named_event(ctx: &TracePointContext, event_type: u32) -> u32 {
    let meta = if event_type == EVENT_FORK {
        let Some(offsets) = offsets_load() else {
            return 0;
        };
        fork_parse(ctx, &offsets)
    } else {
        exec_parse()
    };

    let is_tracked = if event_type == EVENT_FORK {
        applied_lookup(meta.parent_tid)
    } else {
        applied_lookup(meta.tid as u32)
    };

    if !is_tracked && !whitelist_matched(&meta.comm) {
        return 0;
    }

    if event_type == EVENT_FORK && is_tracked {
        let _ = APPLIED_MAP.insert(&(meta.tid as u32), &0, 0);
    }

    submit_event(ProcEvent {
        pid: meta.pid,
        tid: meta.tid,
        comm: meta.comm,
        event_type,
    });
    0
}

#[tracepoint(name = "sched_process_fork", category = "sched")]
fn sched_process_fork(ctx: TracePointContext) -> u32 {
    report_named_event(&ctx, EVENT_FORK)
}

#[tracepoint(name = "sched_process_exec", category = "sched")]
fn sched_process_exec(ctx: TracePointContext) -> u32 {
    report_named_event(&ctx, EVENT_EXEC)
}

/// 捕获线程改名，已管理线程直接放行否则白名单匹配
#[tracepoint(name = "task_rename", category = "task")]
fn task_rename(ctx: TracePointContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let tid = (pid_tgid & 0xFFFFFFFF) as u32;
    if tid == 0 {
        return 0;
    }
    let tgid = (pid_tgid >> 32) as u32;

    let tracked = applied_lookup(tid);

    let Some(offsets) = offsets_load() else {
        return 0;
    };
    let new_comm =
        unsafe { ctx.read_at::<[u8; 16]>(offsets.rename_newcomm as usize).unwrap_or([0u8; 16]) };

    if !tracked && !whitelist_matched(&new_comm) {
        return 0;
    }

    submit_event(ProcEvent {
        pid: tgid as i32,
        tid: tid as i32,
        comm: new_comm,
        event_type: EVENT_RENAME,
    });
    0
}

/// 捕获线程退出，已管理线程清理 APPLIED_MAP
#[tracepoint(name = "sched_process_exit", category = "sched")]
fn sched_process_exit(_ctx: TracePointContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let tid = (pid_tgid & 0xFFFFFFFF) as u32;
    let tgid = (pid_tgid >> 32) as u32;

    if !applied_lookup(tid) {
        return 0;
    }

    let _ = APPLIED_MAP.remove(&tid);

    submit_event(ProcEvent {
        pid: tgid as i32,
        tid: tid as i32,
        comm: [0u8; 16],
        event_type: EVENT_EXIT,
    });
    0
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

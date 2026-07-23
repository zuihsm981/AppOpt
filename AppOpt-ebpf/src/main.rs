#![no_std]
#![no_main]
#![allow(linker_messages)]

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_ktime_get_ns},
    macros::{map, tracepoint},
    maps::{HashMap, LruHashMap, RingBuf},
    programs::TracePointContext,
};

const EVENT_FORK: u32 = 1;
const EVENT_EXEC: u32 = 2;

/// 进程事件（布局需与用户态 EbpfProcEvent 一致）
#[repr(C)]
struct ProcEvent {
    pid: i32,
    tid: i32,
    child_pid: i32,
    comm: [u8; 16],
    event_type: u32,
}

#[repr(C)]
struct DedupEntry {
    last_ns: u64,
    count: u32,
}

/// 白名单默认容量（用户态通过 EbpfLoader::set_max_entries 动态覆盖）
const MAP_CAPACITY: u32 = 16 << 5;
const DEDUP_CAPACITY: u32 = 4096;
/// 防抖时间窗口：0.1 秒（纳秒）
const DEDUP_WINDOW_NS: u64 = 100_000_000;
/// 窗口内最大事件数，超过则丢弃
const DEDUP_MAX_COUNT: u32 = 2;

/// FORK/EXEC 共用白名单：键为 8 字节匹配串（包名前 8 字节或末 8 字节）
#[map]
static TARGET_COMM_MAP: HashMap<[u8; 8], u32> = HashMap::with_max_entries(MAP_CAPACITY, 0);

#[map]
static DEDUP_MAP: LruHashMap<u32, DedupEntry> = LruHashMap::with_max_entries(DEDUP_CAPACITY, 0);

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[inline(always)]
fn should_dedup(pid: u32, now_ns: u64) -> bool {
    let prev = unsafe { DEDUP_MAP.get(&pid) };
    let (last_ns, count) = match prev {
        Some(e) => (e.last_ns, e.count),
        None => (0, 0),
    };

    if now_ns - last_ns < DEDUP_WINDOW_NS {
        let new_count = count + 1;
        if new_count > DEDUP_MAX_COUNT {
            return true;
        }
        let _ = DEDUP_MAP.insert(
            &pid,
            &DedupEntry {
                last_ns,
                count: new_count,
            },
            0,
        );
    } else {
        let _ = DEDUP_MAP.insert(
            &pid,
            &DedupEntry {
                last_ns: now_ns,
                count: 1,
            },
            0,
        );
    }
    false
}

#[inline(always)]
fn report_event(ctx: &TracePointContext, event_type: u32) -> u32 {
    // sched_process_fork 格式：offset 8=parent_comm[16], 24=parent_pid, 28=child_comm[16], 44=child_pid
    let (pid_for_dedup, child_pid) = if event_type == EVENT_FORK {
        let pid = unsafe { ctx.read_at::<i32>(44).unwrap_or(0) };
        (pid as u32, pid)
    } else {
        let pid_tgid = bpf_get_current_pid_tgid();
        ((pid_tgid >> 32) as u32, 0)
    };

    // 防抖先于白名单匹配，避免高频非目标进程事件冲击用户态
    let now_ns = unsafe { bpf_ktime_get_ns() };
    if should_dedup(pid_for_dedup, now_ns) {
        return 0;
    }

    let comm = if event_type == EVENT_FORK {
        unsafe { ctx.read_at::<[u8; 16]>(28).unwrap_or([0u8; 16]) }
    } else {
        bpf_get_current_comm().unwrap_or_default()
    };

    let mut matched = false;
    let mut pos: usize = 0;
    while pos <= 8 {
        let key: [u8; 8] = [
            comm[pos],
            comm[pos + 1],
            comm[pos + 2],
            comm[pos + 3],
            comm[pos + 4],
            comm[pos + 5],
            comm[pos + 6],
            comm[pos + 7],
        ];
        if unsafe { TARGET_COMM_MAP.get(&key) }.is_some() {
            matched = true;
            break;
        }
        pos += 1;
    }
    if !matched {
        return 0;
    }

    let event = if event_type == EVENT_FORK {
        ProcEvent {
            pid: child_pid,
            tid: child_pid,
            child_pid,
            comm,
            event_type,
        }
    } else {
        let pid_tgid = bpf_get_current_pid_tgid();
        ProcEvent {
            pid: (pid_tgid >> 32) as i32,
            tid: pid_tgid as i32,
            child_pid: 0,
            comm,
            event_type,
        }
    };

    if let Some(mut entry) = EVENTS.reserve(0) {
        entry.write(event);
        entry.submit(0);
    }
    0
}

/// 捕获进程 fork / 线程 clone 事件
#[tracepoint(name = "sched_process_fork", category = "sched")]
fn sched_process_fork(ctx: TracePointContext) -> u32 {
    report_event(&ctx, EVENT_FORK)
}

/// 捕获进程执行新程序
#[tracepoint(name = "sched_process_exec", category = "sched")]
fn sched_process_exec(ctx: TracePointContext) -> u32 {
    report_event(&ctx, EVENT_EXEC)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

use std::fmt::Write as _;
use std::fs;
use std::io::Write as _;
use std::os::unix::fs::FileExt;

use crate::common::{BASE_CPUSET, MAX_PKG_LEN, MAX_THREAD_LEN};
use crate::config::AppConfig;
use crate::cpuset::{CpuSet, CpuTopology};
use crate::rule_match::resolve_thread_affinity;

/// 栈上构建路径，调用方负责截断（\0/\n）与后处理
fn read_proc_file<'a>(pid: i32, suffix: &str, buf: &'a mut [u8]) -> Option<&'a [u8]> {
    let mut path = [0u8; 32];
    let mut cur = std::io::Cursor::new(&mut path[..]);
    write!(cur, "/proc/{}/{}", pid, suffix).ok()?;
    let len = cur.position() as usize;
    let path_str = std::str::from_utf8(&path[..len]).ok()?;
    let file = fs::File::open(path_str).ok()?;
    let n = file.read_at(buf, 0).ok()?;
    (n > 0).then_some(&buf[..n])
}

pub(crate) fn read_cmdline(pid: i32) -> Option<String> {
    let mut buf = [0u8; MAX_PKG_LEN];
    let bytes = read_proc_file(pid, "cmdline", &mut buf)?;
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    let cmdline = std::str::from_utf8(&bytes[..end]).ok()?;
    let name = cmdline.rsplit('/').next().unwrap_or(cmdline);
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(trimmed.to_string())
}

pub(crate) fn read_thread_name_by_tid(tid: i32) -> Option<String> {
    let mut buf = [0u8; MAX_THREAD_LEN];
    let bytes = read_proc_file(tid, "comm", &mut buf)?;
    let end = bytes
        .iter()
        .position(|&b| b == 0 || b == b'\n')
        .unwrap_or(bytes.len());
    let name = std::str::from_utf8(&bytes[..end]).ok()?;
    Some(name.trim().to_string())
}

/// 线程名缓存
pub(crate) struct ThreadNameCache {
    names: std::collections::HashMap<i32, String>,
    last_full_refresh: i64,
}

const THREAD_NAME_CACHE_TTL_SECS: i64 = 60;

impl ThreadNameCache {
    pub fn new(now: i64) -> Self {
        Self {
            names: std::collections::HashMap::new(),
            last_full_refresh: now,
        }
    }

    pub fn get_or_read(&mut self, tid: i32, now: i64) -> &str {
        if now - self.last_full_refresh >= THREAD_NAME_CACHE_TTL_SECS {
            self.names.clear();
            self.last_full_refresh = now;
        }
        self.names
            .entry(tid)
            .or_insert_with(|| read_thread_name_by_tid(tid).unwrap_or_default())
    }

    pub fn retain(&mut self, current_tids: &std::collections::HashSet<i32>) {
        self.names.retain(|&tid, _| current_tids.contains(&tid));
    }

    pub fn clear(&mut self) {
        self.names.clear();
        self.last_full_refresh = 0;
    }
}

/// 对单个线程应用亲和性
/// 返回 true 表示 set_affinity 因 ESRCH 失败（线程已退出），调用方触发重扫
pub fn apply_thread_affinity(
    tid: i32,
    cpus: &CpuSet,
    cpuset_dir: &str,
    topo: &CpuTopology,
) -> bool {
    // sched_getaffinity 短路：已符合目标则零开销返回
    if let Some(curr) = CpuSet::get_affinity(tid) {
        if curr.bits == cpus.bits {
            return false;
        }
    }

    if topo.cpuset_enabled && topo.base_cpuset_fd != -1 {
        let mut tid_str = String::new();
        let _ = writeln!(tid_str, "{}", tid);
        let tasks_path = if cpuset_dir.is_empty() {
            format!("{}/tasks", BASE_CPUSET)
        } else {
            format!("{}/{}/tasks", BASE_CPUSET, cpuset_dir)
        };
        let _ = fs::OpenOptions::new()
            .append(true)
            .open(&tasks_path)
            .and_then(|mut f| f.write_all(tid_str.as_bytes()));
    }

    if let Err(e) = cpus.set_affinity(tid) {
        return e.raw_os_error() == Some(libc::ESRCH);
    }

    false
}

pub fn refresh_process_rules(
    pid: i32,
    pkg: &str,
    cfg: &AppConfig,
    has_thread_rules: bool,
    tid_cache: &mut ThreadNameCache,
    now: i64,
) {
    let mut task_path_buf = [0u8; 32];
    let mut cur = std::io::Cursor::new(&mut task_path_buf[..]);
    write!(cur, "/proc/{}/task", pid).ok();
    let len = cur.position() as usize;
    let task_path = std::str::from_utf8(&task_path_buf[..len]).unwrap();
    let task_dir = match fs::read_dir(task_path) {
        Ok(d) => d,
        Err(_) => return,
    };

    let mut current_tids: std::collections::HashSet<i32> = std::collections::HashSet::new();

    for tent in task_dir.flatten() {
        let tname_str = tent.file_name();
        let tname_str = tname_str.to_string_lossy();
        let Ok(tid) = tname_str.parse::<i32>() else {
            continue;
        };
        current_tids.insert(tid);
        let t_name = if has_thread_rules {
            tid_cache.get_or_read(tid, now)
        } else {
            ""
        };

        if let Some((cpus, cpuset_dir)) = resolve_thread_affinity(pkg, t_name, cfg) {
            apply_thread_affinity(tid, &cpus, &cpuset_dir, &cfg.topo);
        }
    }
    tid_cache.retain(&current_tids);
}

use std::ffi::CString;
use std::fmt::Write as _;
use std::fs;
use std::io;

use std::sync::RwLock;

pub const CPU_SETSIZE: usize = 1024;
pub const CPU_WORD_BITS: usize = 64;
pub const CPU_WORDS: usize = CPU_SETSIZE / CPU_WORD_BITS;

/// BASE_CPUSET 运行时路径，web 端可热更新，未设置时默认 /dev/cpuset/AppOpt
static BASE_CPUSET_PATH: RwLock<Option<String>> = RwLock::new(None);

pub const DEFAULT_CPUSET_NAME: &str = "AppOpt";

/// 设置 BASE_CPUSET 目录名，name 为空或含 / 时忽略
pub fn set_base_cpuset(name: &str) {
    if name.is_empty() || name.contains('/') {
        return;
    }
    *crate::rw_write_ignore_poison(&BASE_CPUSET_PATH) = Some(format!("/dev/cpuset/{}", name));
}

pub fn base_cpuset() -> String {
    crate::rw_read_ignore_poison(&BASE_CPUSET_PATH)
        .clone()
        .unwrap_or_else(|| "/dev/cpuset/AppOpt".to_string())
}

const _: () = assert!(std::mem::size_of::<CpuSet>() == std::mem::size_of::<libc::cpu_set_t>());

#[repr(C)]
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct CpuSet {
    pub bits: [u64; CPU_WORDS],
}

impl std::fmt::Debug for CpuSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CpuSet({})", self.to_range_string())
    }
}

impl CpuSet {
    pub fn new() -> Self {
        CpuSet::default()
    }

    pub fn set(&mut self, cpu: usize) {
        if cpu < CPU_SETSIZE {
            self.bits[cpu / CPU_WORD_BITS] |= 1u64 << (cpu % CPU_WORD_BITS);
        }
    }

    pub fn is_set(&self, cpu: usize) -> bool {
        cpu < CPU_SETSIZE && self.bits[cpu / CPU_WORD_BITS] & (1u64 << (cpu % CPU_WORD_BITS)) != 0
    }

    pub fn count(&self) -> usize {
        self.bits.iter().map(|&b| b.count_ones() as usize).sum()
    }

    pub fn or(&mut self, other: &CpuSet) {
        for (d, &s) in self.bits.iter_mut().zip(other.bits.iter()) {
            *d |= s;
        }
    }

    pub fn to_range_string(self) -> String {
        let mut result = String::new();
        let mut start: Option<usize> = None;
        let mut end: Option<usize> = None;
        let mut first = true;

        for (word_idx, &word) in self.bits.iter().enumerate() {
            if word == 0 {
                if start.is_some() {
                    push_range(&mut result, start, end, &mut first);
                    start = None;
                    end = None;
                }
                continue;
            }
            let base = word_idx * CPU_WORD_BITS;
            for bit in 0..CPU_WORD_BITS {
                if word & (1u64 << bit) != 0 {
                    let cpu = base + bit;
                    if start.is_none() {
                        start = Some(cpu);
                        end = Some(cpu);
                    } else if end.is_some_and(|e| cpu == e + 1) {
                        end = Some(cpu);
                    } else {
                        push_range(&mut result, start, end, &mut first);
                        start = Some(cpu);
                        end = Some(cpu);
                    }
                }
            }
        }
        push_range(&mut result, start, end, &mut first);
        result
    }

    pub fn get_affinity(tid: i32) -> Option<CpuSet> {
        let mut curr = CpuSet::new();
        let ret = unsafe {
            libc::sched_getaffinity(
                tid,
                std::mem::size_of::<CpuSet>(),
                &mut curr as *mut CpuSet as *mut libc::cpu_set_t,
            )
        };
        if ret == -1 {
            None
        } else {
            Some(curr)
        }
    }

    pub fn set_affinity(&self, tid: i32) -> io::Result<()> {
        let ret = unsafe {
            libc::sched_setaffinity(
                tid,
                std::mem::size_of::<CpuSet>(),
                self as *const CpuSet as *const libc::cpu_set_t,
            )
        };
        if ret == -1 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

fn push_range(s: &mut String, start: Option<usize>, end: Option<usize>, first: &mut bool) {
    if let (Some(lo), Some(hi)) = (start, end) {
        if !*first {
            s.push(',');
        }
        if lo == hi {
            let _ = write!(s, "{}", lo);
        } else {
            let _ = write!(s, "{}-{}", lo, hi);
        }
        *first = false;
    }
}

pub fn parse_cpu_ranges(spec: &str, present: Option<&CpuSet>) -> CpuSet {
    let mut set = CpuSet::new();
    if spec.is_empty() {
        return set;
    }
    for part in spec.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (lo, hi) = if let Some(pos) = part.find('-') {
            let a: usize = part[..pos].parse().ok().unwrap_or(usize::MAX);
            let b: usize = part[pos + 1..].parse().ok().unwrap_or(a);
            if a == usize::MAX {
                continue;
            }
            if a > b {
                (b, a)
            } else {
                (a, b)
            }
        } else {
            let a: usize = part.parse().ok().unwrap_or(usize::MAX);
            if a == usize::MAX {
                continue;
            }
            (a, a)
        };
        for i in lo..=hi.min(CPU_SETSIZE - 1) {
            if let Some(present) = present
                && !present.is_set(i) {
                    continue;
                }
            set.set(i);
        }
    }
    set
}

/// 解析 CPU 规格，支持语义核心名(e-core/p-core/hp-core)与数字范围混合
pub fn parse_cpu_spec(spec: &str, topo: &CpuTopology) -> CpuSet {
    let mut set = CpuSet::new();
    if spec.is_empty() {
        return set;
    }
    for part in spec.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        // 语义名展开为对应核心层，其余按数字范围解析
        let seg = match part {
            "e-core" => &topo.e_core,
            "p-core" => &topo.p_core,
            "hp-core" => &topo.hp_core,
            "all-core" => &topo.present_cpus,
            _ => {
                set.or(&parse_cpu_ranges(part, Some(&topo.present_cpus)));
                continue;
            }
        };
        set.or(seg);
    }
    set
}

/// foreground 时间基准缓存: 首次 stat 后复用
static FG_TIMES: std::sync::OnceLock<[libc::timespec; 2]> = std::sync::OnceLock::new();

/// 取 /dev/cpuset/foreground 的 atime/mtime (伪装时间基准, 已缓存)
fn foreground_times() -> Option<[libc::timespec; 2]> {
    if let Some(t) = FG_TIMES.get() {
        return Some(*t);
    }
    let p = CString::new("/dev/cpuset/foreground").ok()?;
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::stat(p.as_ptr(), &mut st) } != 0 {
        return None;
    }
    let ts = [
        libc::timespec { tv_sec: st.st_atime, tv_nsec: st.st_atime_nsec },
        libc::timespec { tv_sec: st.st_mtime, tv_nsec: st.st_mtime_nsec },
    ];
    let _ = FG_TIMES.set(ts);
    Some(ts)
}

/// 把目录及目录内所有条目的 atime/mtime 统一为 /dev/cpuset/foreground 的时间。
/// 顺序: 先设子项, **最后**设目录自身 (read_dir 会刷新目录 atime)。
fn set_times_like_foreground(path: &str) {
    let Some(ts) = foreground_times() else { return };
    if let Ok(rd) = fs::read_dir(path) {
        for e in rd.flatten() {
            let Some(name) = e.file_name().to_str().map(String::from) else { continue };
            if let Ok(c2) = CString::new(format!("{}/{}", path, name)) {
                unsafe {
                    libc::utimensat(libc::AT_FDCWD, c2.as_ptr(), ts.as_ptr(), 0);
                }
            }
        }
    }
    let c = CString::new(path).unwrap_or_default();
    if c.is_empty() {
        return;
    }
    unsafe {
        libc::utimensat(libc::AT_FDCWD, c.as_ptr(), ts.as_ptr(), 0);
    }
}

pub(crate) fn create_cpuset_dir(path: &str, cpus: &str, mems: &str) -> bool {
    let c_path = CString::new(path).expect("cpuset path 受控输入，无 NUL");
    let ret = unsafe { libc::mkdir(c_path.as_ptr(), 0o755) };
    if ret != 0 {
        let err = io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EEXIST) {
            return false;
        }
        // 目录已存在且 cpus/mems 内容一致 → 无需重复 chmod/chown/写文件
        // (配置重载时避免对每个包级规则重复写)
        let cpus_ok = fs::read_to_string(format!("{}/cpus", path))
            .map(|cur| cur.trim() == cpus.trim())
            .unwrap_or(false);
        let mems_ok = fs::read_to_string(format!("{}/mems", path))
            .map(|cur| cur.trim() == mems.trim())
            .unwrap_or(false);
        if cpus_ok && mems_ok {
            return true;
        }
    }
    if unsafe { libc::chmod(c_path.as_ptr(), 0o755) } != 0 {
        return false;
    }
    if unsafe { libc::chown(c_path.as_ptr(), 0, 0) } != 0 {
        return false;
    }
    let cpus_path = format!("{}/cpus", path);
    if fs::write(&cpus_path, cpus).is_err() {
        return false;
    }
    let mems_path = format!("{}/mems", path);
    if fs::write(&mems_path, mems).is_err() {
        return false;
    }
    true
}

/// 递归同步目录子树时间戳 (深→浅, 每层先子项后目录自身)
fn sync_tree(path: &str) {
    if let Ok(rd) = fs::read_dir(path) {
        for e in rd.flatten() {
            let Ok(ft) = e.file_type() else { continue };
            if ft.is_dir()
                && let Some(s) = e.path().to_str()
            {
                sync_tree(s);
            }
        }
    }
    set_times_like_foreground(path);
}

/// 同步 BASE_CPUSET 整棵目录树的时间戳为 /dev/cpuset/foreground 的时间。
pub(crate) fn sync_cpuset_timestamps() {
    sync_tree(&base_cpuset());
}

/// 同步单个 cpuset 子目录 (dir 为空 → base 目录)。创建新 CPU 组合目录后调用。
pub(crate) fn sync_cpuset_dir(dir: &str) {
    let path = if dir.is_empty() {
        base_cpuset()
    } else {
        format!("{}/{}", base_cpuset(), dir)
    };
    sync_tree(&path);
}

/// 初始化 (初始全量应用) 完成后调用, 仅首次生效一次。
static INIT_SYNCED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
pub(crate) fn sync_init_once() {
    if !INIT_SYNCED.swap(true, std::sync::atomic::Ordering::Relaxed) {
        sync_cpuset_timestamps();
    }
}

/// 按合并后的 CPU 集合确保 cpuset 子目录存在，返回目录名（cpuset 未启用或创建失败返回空串）
pub fn ensure_cpuset_dir(cpus: &CpuSet, topo: &CpuTopology) -> String {
    if !topo.cpuset_enabled {
        return String::new();
    }
    let dir_name = cpus.to_range_string();
    let path = format!("{}/{}", base_cpuset(), dir_name);
    // create_cpuset_dir 已处理 EEXIST，重复调用幂等
    if create_cpuset_dir(&path, &dir_name, &topo.mems_str) {
        dir_name
    } else {
        String::new()
    }
}

#[derive(Clone)]
pub struct CpuTopology {
    pub present_cpus: CpuSet,
    pub present_str: String,
    pub mems_str: String,
    pub cpuset_enabled: bool,
    pub e_core: CpuSet,
    pub p_core: CpuSet,
    pub hp_core: CpuSet,
}

/// 按 cpufreq 策略检测核心分层，按最高频率升序分组：首组为 e-core，末组为 hp-core，中间为 p-core
fn detect_core_types() -> (CpuSet, CpuSet, CpuSet) {
    let mut groups: Vec<(u64, Vec<usize>)> = Vec::new();
    // 读取每个 policy 的 related_cpus 与 cpuinfo_max_freq，按频率合并同组
    if let Ok(entries) = fs::read_dir("/sys/devices/system/cpu/cpufreq") {
        for entry in entries.flatten() {
            let path = entry.path();
            if !path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("policy"))
            {
                continue;
            }
            let freq: u64 = fs::read_to_string(path.join("cpuinfo_max_freq"))
                .ok()
                .and_then(|s| s.trim().parse().ok())
                .unwrap_or(0);
            if freq == 0 {
                continue;
            }
            let cpus: Vec<usize> = fs::read_to_string(path.join("related_cpus"))
                .ok()
                .map(|s| s.split_whitespace().filter_map(|c| c.parse().ok()).collect())
                .unwrap_or_default();
            if cpus.is_empty() {
                continue;
            }
            if let Some(g) = groups.iter_mut().find(|(f, _)| *f == freq) {
                g.1.extend(cpus);
            } else {
                groups.push((freq, cpus));
            }
        }
    }
    groups.sort_by_key(|(f, _)| *f);
    let mut e = CpuSet::new();
    let mut p = CpuSet::new();
    let mut h = CpuSet::new();
    let n = groups.len();
    for (i, (_, cpus)) in groups.iter().enumerate() {
        let target = if i == 0 {
            &mut e
        } else if i == n - 1 {
            &mut h
        } else {
            &mut p
        };
        for &cpu in cpus {
            target.set(cpu);
        }
    }
    (e, p, h)
}

/// 初始化 CPU 拓扑，检测 cpuset 可用性并创建 BASE_CPUSET 目录
pub fn init_cpu_topo() -> CpuTopology {
    let mut topo = CpuTopology {
        present_cpus: CpuSet::new(),
        present_str: String::new(),
        mems_str: String::new(),
        cpuset_enabled: false,
        e_core: CpuSet::new(),
        p_core: CpuSet::new(),
        hp_core: CpuSet::new(),
    };

    if let Ok(content) = fs::read_to_string("/sys/devices/system/cpu/present") {
        topo.present_str = content.trim().to_string();
    }
    topo.present_cpus = parse_cpu_ranges(&topo.present_str, None);
    let (e, p, h) = detect_core_types();
    topo.e_core = e;
    topo.p_core = p;
    topo.hp_core = h;

    let cpuset_path = CString::new("/dev/cpuset").expect("常量字符串无 NUL");
    if unsafe { libc::access(cpuset_path.as_ptr(), libc::F_OK) } != 0 {
        return topo;
    }

    let mems = fs::read_to_string("/dev/cpuset/mems")
        .ok()
        .and_then(|s| {
            let t = s.trim().to_string();
            if t.is_empty() { None } else { Some(t) }
        })
        .unwrap_or_else(|| "0".to_string());
    topo.mems_str = mems;

    if create_cpuset_dir(&base_cpuset(), &topo.present_str, &topo.mems_str) {
        topo.cpuset_enabled = true;
    }

    topo
}

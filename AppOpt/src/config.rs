use std::collections::HashSet;
use std::ffi::CString;
use std::fs;
use std::io;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, UNIX_EPOCH};

use crate::common::{
    base_cpuset, lock_ignore_poison, CONFIG_UPDATED, INOTIFY_FD, INOTIFY_SUPPORTED, INOTIFY_WD,
    MAX_PKG_LEN, MAX_THREAD_LEN,
};
use crate::cpuset::{create_cpuset_dir, parse_cpu_spec, CpuSet, CpuTopology};

pub struct AffinityRule {
    pub pkg: String,
    pub thread: String,
    pub thread_pattern: CString,
    pub cpuset_dir: String,
    pub cpus: CpuSet,
}

pub struct AppConfig {
    pub rules: Vec<AffinityRule>,
    pub pkgs: HashSet<String>,
    pub has_thread_rules: HashSet<String>,
    pub topo: CpuTopology,
    pub config_file: String,
}

/// 当前生效配置，主循环与配置加载线程共享
pub static CURRENT_CONFIG: Mutex<Option<Arc<AppConfig>>> = Mutex::new(None);

/// 添加规则，包级规则创建 cpuset 子目录，线程规则目录由匹配时按合并集合创建
fn add_rule(
    rules: &mut Vec<AffinityRule>,
    topo: &CpuTopology,
    pkg: &str,
    thread: &str,
    cpus_spec: &str,
) -> bool {
    if pkg.len() >= MAX_PKG_LEN || thread.len() >= MAX_THREAD_LEN {
        return false;
    }
    let set = parse_cpu_spec(cpus_spec, topo);
    if set.count() == 0 {
        return false;
    }
    // 线程规则目录延迟到 thread_affinity 合并后创建，避免冗余空目录
    let cpuset_dir = if thread.is_empty() {
        let dir_name = set.to_range_string();
        if topo.cpuset_enabled {
            let path = format!("{}/{}", base_cpuset(), dir_name);
            create_cpuset_dir(&path, &dir_name, &topo.mems_str)
                .then_some(dir_name)
                .unwrap_or_default()
        } else {
            String::new()
        }
    } else {
        String::new()
    };
    rules.push(AffinityRule {
        pkg: pkg.to_string(),
        thread: thread.to_string(),
        thread_pattern: CString::new(thread).unwrap_or_default(),
        cpuset_dir,
        cpus: set,
    });
    true
}

/// 加载配置文件，返回 None 表示未变化或解析失败
pub fn load_config(
    config_file: &str,
    topo: &CpuTopology,
    last_mtime: &mut i64,
) -> Option<AppConfig> {
    let metadata = fs::metadata(config_file).ok()?;
    let mtime = metadata
        .modified()
        .ok()?
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_nanos() as i64;

    if *last_mtime == mtime && *last_mtime != -1 {
        return None;
    }

    let content = fs::read_to_string(config_file).ok()?;

    let mut rules: Vec<AffinityRule> = Vec::new();
    let mut fail_cnt: usize = 0;
    let mut cur_pkg = String::new();
    let mut pending_pkg = String::new();
    let mut in_block = false;

    for line in content.lines() {
        let p = line.trim();
        if p.is_empty() || p.starts_with('#') || p.starts_with("//") {
            continue;
        }

        if in_block {
            let mut block_end = false;
            let content_part = if let Some(close_br) = p.find('}') {
                block_end = true;
                p[..close_br].trim()
            } else {
                p
            };

            if !content_part.is_empty() {
                if let Some(eq) = content_part.find('=') {
                    let thread = content_part[..eq].trim();
                    let cpus = content_part[eq + 1..].trim();
                    if !add_rule(&mut rules, topo, &cur_pkg, thread, cpus) {
                        fail_cnt += 1;
                    }
                } else {
                    fail_cnt += 1;
                }
            }

            if block_end {
                in_block = false;
                cur_pkg.clear();
            }
            continue;
        }

        let sep_pos = match p.find(['=', '{']) {
            Some(pos) => pos,
            None => {
                if !pending_pkg.is_empty() {
                    fail_cnt += 1;
                }
                pending_pkg.clear();
                continue;
            }
        };

        let sep_char = p.as_bytes()[sep_pos] as char;
        let before = p[..sep_pos].trim();
        let after = p[sep_pos + 1..].trim();

        if sep_char == '{' {
            let pkg = before;
            if let Some(eb) = after.find('}') {
                if !pending_pkg.is_empty() {
                    fail_cnt += 1;
                    pending_pkg.clear();
                }
                let thread = after[..eb].trim();
                let rest = after[eb + 1..].trim();
                if let Some(eq) = rest.find('=') {
                    let cpus = rest[eq + 1..].trim();
                    let tail_br = cpus.find('{');
                    if let Some(tb) = tail_br {
                        let cpus_only = cpus[..tb].trim();
                        if !cpus_only.is_empty()
                            && !add_rule(&mut rules, topo, pkg, thread, cpus_only)
                        {
                            fail_cnt += 1;
                        }
                        cur_pkg = pkg.to_string();
                        in_block = true;
                        continue;
                    }
                    if !add_rule(&mut rules, topo, pkg, thread, cpus) {
                        fail_cnt += 1;
                    }
                } else {
                    fail_cnt += 1;
                }
                continue;
            }

            let blk_pkg = if !pkg.is_empty() {
                if !pending_pkg.is_empty() {
                    fail_cnt += 1;
                }
                pkg
            } else {
                &pending_pkg
            };
            if blk_pkg.is_empty() {
                fail_cnt += 1;
                continue;
            }
            cur_pkg = blk_pkg.to_string();
            pending_pkg.clear();
            in_block = true;
            continue;
        }

        if !pending_pkg.is_empty() {
            fail_cnt += 1;
        }

        let pkg = before;
        if let Some(br) = after.find('{') {
            let cpus = after[..br].trim();
            cur_pkg = pkg.to_string();
            in_block = true;
            if !cpus.is_empty() && !add_rule(&mut rules, topo, pkg, "", cpus) {
                fail_cnt += 1;
            }
            pending_pkg.clear();
            continue;
        }

        let cpus = after.trim();
        if cpus.is_empty() {
            pending_pkg = pkg.to_string();
            continue;
        }
        if !add_rule(&mut rules, topo, pkg, "", cpus) {
            fail_cnt += 1;
        }
        pending_pkg.clear();
    }

    if in_block || !pending_pkg.is_empty() {
        fail_cnt += 1;
    }

    if fail_cnt == 0 {
        *last_mtime = mtime;
    }

    let pkgs: HashSet<String> = rules.iter().map(|r| r.pkg.clone()).collect();
    let has_thread_rules: HashSet<String> = rules
        .iter()
        .filter(|r| !r.thread.is_empty())
        .map(|r| r.pkg.clone())
        .collect();
    let num_rules = rules.len();

    println!("配置文件解析完成，共加载 {} 条规则", num_rules);
    if fail_cnt > 0 {
        eprintln!("警告: {} 条规则因格式无效被跳过", fail_cnt);
    }

    Some(AppConfig {
        rules,
        pkgs,
        has_thread_rules,
        topo: topo.clone(),
        config_file: config_file.to_string(),
    })
}

/// 配置加载线程，优先 inotify 失败降级为定时轮询
pub fn config_loader(interval: u64) {
    let name = CString::new("ConfigLoader").unwrap();
    unsafe {
        libc::pthread_setname_np(libc::pthread_self(), name.as_ptr());
    }

    let mut last_mtime: i64 = -1;

    loop {
        if INOTIFY_SUPPORTED.load(Ordering::Acquire) {
            inotify_handle(interval, &mut last_mtime);
        } else {
            config_reload(&mut last_mtime);
            thread::sleep(Duration::from_secs(interval));
        }
    }
}

/// 关闭 inotify 并降级为轮询模式
fn disable_inotify(inotify_fd: i32) {
    INOTIFY_SUPPORTED.store(false, Ordering::Release);
    unsafe {
        libc::close(inotify_fd);
    }
    INOTIFY_FD.store(-1, Ordering::Release);
    INOTIFY_WD.store(-1, Ordering::Release);
}

/// 重新加载配置，成功则更新 CURRENT_CONFIG 并置位 CONFIG_UPDATED
fn config_reload(last_mtime: &mut i64) {
    let Some(cfg) = lock_ignore_poison(&CURRENT_CONFIG).clone() else {
        return;
    };
    let Some(new_cfg) = load_config(&cfg.config_file, &cfg.topo, last_mtime) else {
        return;
    };
    {
        let mut guard = lock_ignore_poison(&CURRENT_CONFIG);
        *guard = Some(Arc::new(new_cfg));
    }
    CONFIG_UPDATED.store(true, Ordering::Release);
}

/// 处理 inotify 事件，循环 read 直到 EAGAIN 避免事件丢失
fn inotify_handle(interval: u64, last_mtime: &mut i64) {
    let inotify_fd = INOTIFY_FD.load(Ordering::Acquire);

    let mut pfd = libc::pollfd {
        fd: inotify_fd,
        events: libc::POLLIN,
        revents: 0,
    };

    let ret = unsafe { libc::poll(&mut pfd, 1, (interval as libc::c_int) * 1000) };

    if ret < 0 {
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EINTR) {
            return;
        }
        disable_inotify(inotify_fd);
        return;
    } else if ret == 0 {
        return;
    }

    #[repr(align(8))]
    struct InotifyBuf([u8; 4096]);
    let mut buf = InotifyBuf([0u8; 4096]);
    let mut reload_needed = false;
    let mut needs_rewatch = false;
    let hdr = std::mem::size_of::<libc::inotify_event>();

    loop {
        let len = unsafe {
            libc::read(
                inotify_fd,
                buf.0.as_mut_ptr() as *mut libc::c_void,
                buf.0.len(),
            )
        };
        if len <= 0 {
            let err = io::Error::last_os_error();
            let errno = err.raw_os_error();
            // EAGAIN 或 EINTR 退出循环
            if errno == Some(libc::EAGAIN)
                || errno == Some(libc::EWOULDBLOCK)
                || errno == Some(libc::EINTR)
            {
                break;
            }
            disable_inotify(inotify_fd);
            return;
        }

        let mut offset = 0;
        while offset + hdr <= len as usize {
            let event = unsafe { &*(buf.0.as_ptr().add(offset) as *const libc::inotify_event) };
            if event.mask & (libc::IN_CLOSE_WRITE | libc::IN_DELETE_SELF | libc::IN_MOVE_SELF) != 0
            {
                reload_needed = true;
                *last_mtime = -1;
                if event.mask & (libc::IN_DELETE_SELF | libc::IN_MOVE_SELF) != 0 {
                    needs_rewatch = true;
                }
            }
            offset += hdr + event.len as usize;
        }
    }

    // rewatch 在 read 循环结束后统一处理避免中途 sleep 丢事件
    if needs_rewatch {
        thread::sleep(Duration::from_secs(interval));
        if !inotify_rewatch(inotify_fd) {
            return;
        }
    }

    if reload_needed {
        config_reload(last_mtime);
    }
}

/// 重装 inotify 监听，失败则降级为轮询
fn inotify_rewatch(inotify_fd: i32) -> bool {
    let Some(cfg) = lock_ignore_poison(&CURRENT_CONFIG).clone() else {
        return false;
    };
    let inotify_wd = INOTIFY_WD.load(Ordering::Acquire);
    unsafe {
        libc::inotify_rm_watch(inotify_fd, inotify_wd as u32);
    }
    let cfg_cstr = match CString::new(cfg.config_file.as_str()) {
        Ok(c) => c,
        Err(_) => {
            eprintln!("错误: 配置文件路径包含非法字符，降级为轮询模式");
            disable_inotify(inotify_fd);
            return false;
        }
    };
    let new_wd = unsafe {
        libc::inotify_add_watch(
            inotify_fd,
            cfg_cstr.as_ptr(),
            libc::IN_CLOSE_WRITE | libc::IN_DELETE_SELF | libc::IN_MOVE_SELF,
        )
    };

    if new_wd < 0 {
        disable_inotify(inotify_fd);
        return false;
    }
    INOTIFY_WD.store(new_wd, Ordering::Release);
    true
}

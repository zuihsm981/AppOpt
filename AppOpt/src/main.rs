#![cfg(any(target_os = "linux", target_os = "android"))]
#[cfg(target_pointer_width = "32")]
compile_error!("AppOpt requires 64-bit target due to cpu_set_t binary layout assumptions");

mod apply_affinity;
mod common;
mod config;
mod cpuset;
mod ebpf_mode;
mod proc_mode;
mod rule_match;

use std::collections::HashSet;
use std::env;
use std::ffi::CString;
use std::fs;
use std::process;
use std::sync::atomic::Ordering;
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::Duration;

use crate::common::{
    current_time_secs, lock_ignore_poison, CONFIG_UPDATED, DEAD_CLEANUP_INTERVAL, INOTIFY_FD,
    INOTIFY_SUPPORTED, INOTIFY_WD,
};
use crate::config::{config_loader_thread, load_config, CURRENT_CONFIG};
use crate::cpuset::init_cpu_topo;
use crate::ebpf_mode::{
    handle_ebpf_event, periodic_full_scan, refresh_cached_processes, setup_target_map,
    try_init_ebpf, EbpfState,
};
use crate::proc_mode::{apply_affinity as proc_apply_affinity, update_cache, ProcCache};

fn print_help(prog_name: &str) {
    println!("Usage: {} [OPTIONS]", prog_name);
    println!("Options:");
    println!("  -c <config_file>   指定配置文件 (默认: ./applist.conf)");
    println!("  -s <interval>      设置检查间隔(秒) (必须>=1, 默认: 2)");
    println!("  -v                 显示程序版本");
    println!("  -h                 显示帮助信息");
    println!();
    println!("示例:");
    println!("  {} -c /data/applist.conf -s 3", prog_name);
}

fn init_inotify(config_file: &str) {
    let inotify_fd = unsafe { libc::inotify_init1(libc::IN_CLOEXEC | libc::IN_NONBLOCK) };
    if inotify_fd < 0 {
        println!("inotify初始化失败，使用轮询模式");
        return;
    }
    // 路径含 NUL 字节时无法构造 CString，直接降级到轮询模式
    let cfg_cstr = match CString::new(config_file) {
        Ok(c) => c,
        Err(_) => {
            eprintln!("错误: 配置文件路径包含非法字符，使用轮询模式");
            unsafe { libc::close(inotify_fd); }
            return;
        }
    };
    let wd = unsafe {
        libc::inotify_add_watch(
            inotify_fd,
            cfg_cstr.as_ptr(),
            libc::IN_CLOSE_WRITE | libc::IN_DELETE_SELF | libc::IN_MOVE_SELF,
        )
    };
    if wd >= 0 {
        INOTIFY_SUPPORTED.store(true, Ordering::Release);
        INOTIFY_FD.store(inotify_fd, Ordering::Release);
        INOTIFY_WD.store(wd, Ordering::Release);
        println!("启用inotify监控配置文件变更");
    } else {
        unsafe {
            libc::close(inotify_fd);
        }
        println!("inotify初始化失败，使用轮询模式");
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let prog_name = &args[0];

    let topo = init_cpu_topo();
    let mut config_file = String::from("./applist.conf");
    let mut sleep_interval: u64 = 2;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-c" => {
                i += 1;
                if i < args.len() {
                    config_file = args[i].clone();
                    println!("配置文件: {}", config_file);
                } else {
                    eprintln!("错误: -c 需要指定配置文件路径");
                    process::exit(1);
                }
            }
            "-s" => {
                i += 1;
                if i < args.len() {
                    let val: u64 = match args[i].parse() {
                        Ok(v) if v >= 1 => v,
                        _ => {
                            eprintln!("无效的时间间隔: {}", args[i]);
                            eprintln!("间隔必须是 >=1 的整数");
                            process::exit(1);
                        }
                    };
                    sleep_interval = val;
                    println!("检查间隔: {} 秒", sleep_interval);
                } else {
                    eprintln!("错误: -s 需要指定时间间隔");
                    process::exit(1);
                }
            }
            "-v" => {
                if crate::ebpf_mode::check_ebpf_support() {
                    println!("AppOpt 版本 {} eBPF", env!("CARGO_PKG_VERSION"));
                } else {
                    println!("AppOpt 版本 {}", env!("CARGO_PKG_VERSION"));
                }
                process::exit(0);
            }
            "-h" => {
                print_help(prog_name);
                process::exit(0);
            }
            other => {
                eprintln!("未知选项: {}", other);
                print_help(prog_name);
                process::exit(1);
            }
        }
        i += 1;
    }

    if fs::metadata(&config_file).is_err() {
        let initial_content = "# 规则编写与使用说明请参考 http://AppOpt.suto.top\n\n";
        if fs::write(&config_file, initial_content).is_ok() {
            println!("配置文件不存在，重建一个空的配置文件: {}", config_file);
        }
    }

    let mut tmp_mtime: i64 = -1;
    let initial_config = match load_config(&config_file, &topo, &mut tmp_mtime) {
        Some(cfg) => cfg,
        None => {
            eprintln!("初始配置加载失败");
            process::exit(1);
        }
    };

    {
        let mut guard = lock_ignore_poison(&CURRENT_CONFIG);
        *guard = Some(Arc::new(initial_config));
    }
    CONFIG_UPDATED.store(true, Ordering::Release);

    init_inotify(&config_file);

    thread::spawn(move || {
        config_loader_thread(sleep_interval);
    });

    let mut cache = ProcCache {
        procs: Vec::new(),
        last_proc_count: 0,
        scan_all_proc: false,
        tracked_pids: HashSet::new(),
        last_proc_total: 0,
    };
    let mut affinity_counter: i32 = 0;

    println!("启动AppOpt服务 v{}", env!("CARGO_PKG_VERSION"));

    let mut ebpf_state: Option<EbpfState> = try_init_ebpf();

    let mut last_cfg_ptr: *const u8 = std::ptr::null();

    loop {
        let config_updated = CONFIG_UPDATED.swap(false, Ordering::AcqRel);
        let Some(cfg) = lock_ignore_poison(&CURRENT_CONFIG).clone() else {
            thread::sleep(Duration::from_millis(100));
            continue;
        };
        let cfg_ptr = Arc::as_ptr(&cfg) as *const u8;
        let config_changed = config_updated || cfg_ptr != last_cfg_ptr;
        last_cfg_ptr = cfg_ptr;

        let mut ebpf_dead = false;
        match &mut ebpf_state {
            Some(ref mut es) => {
                if config_changed {
                    setup_target_map(&mut es.bpf, &cfg.pkgs);
                    periodic_full_scan(&cfg, &mut es.runtime);
                }

                match es.event_rx.recv_timeout(Duration::from_millis(100)) {
                    Ok(event) => {
                        handle_ebpf_event(&event, &cfg, &mut es.runtime, sleep_interval);
                        while let Ok(event) = es.event_rx.try_recv() {
                            handle_ebpf_event(&event, &cfg, &mut es.runtime, sleep_interval);
                        }
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => {}
                    Err(mpsc::RecvTimeoutError::Disconnected) => {
                        ebpf_dead = true;
                    }
                }

                // 周期性清理死进程、重应用亲和性
                if !ebpf_dead {
                    let now = current_time_secs();
                    if now - es.runtime.last_dead_cleanup_time >= DEAD_CLEANUP_INTERVAL {
                        refresh_cached_processes(&cfg, &mut es.runtime);
                    }
                }
            }
            None => {
                if config_changed {
                    cache.scan_all_proc = true;
                    cache.last_proc_count = 0;
                }

                update_cache(&mut cache, &cfg, &mut affinity_counter);
                affinity_counter -= 1;
                if affinity_counter < 1 {
                    proc_apply_affinity(&mut cache, &cfg.topo);
                    affinity_counter = 5;
                }

                thread::sleep(Duration::from_secs(sleep_interval));
            }
        }

        if ebpf_dead {
            eprintln!("eBPF: 事件通道断开，回退到 /proc 轮询");
            ebpf_state = None;
            // 下轮 /proc 轮询立即全量扫描，避免空窗
            cache.scan_all_proc = true;
            cache.last_proc_count = 0;
            affinity_counter = 0;
        }
    }
}

#![cfg(any(target_os = "linux", target_os = "android"))]
#[cfg(target_pointer_width = "32")]
compile_error!("AppOpt requires 64-bit target due to cpu_set_t binary layout assumptions");

mod apply_affinity;
mod cache;
mod common;
mod config;
mod cpuset;
mod ebpf_mode;
mod proc_mode;
mod rule_match;

use std::env;
use std::ffi::CString;
use std::fs;
use std::process;
use std::sync::atomic::Ordering;
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::{Duration, Instant};

use crate::common::{
    lock_ignore_poison, set_base_cpuset, DEFAULT_CPUSET_NAME, CONFIG_UPDATED, INOTIFY_FD,
    INOTIFY_SUPPORTED, INOTIFY_WD,
};
use crate::config::{config_loader, load_config, CURRENT_CONFIG};
use crate::cpuset::init_cpu_topo;
use crate::ebpf_mode::{
    affinity_check, full_scan, event_dispatch, comm_map_init,
    ebpf_init, EbpfState,
};
use crate::proc_mode::{cache_sync, ProcScanState};

fn print_help(prog_name: &str) {
    println!("Usage: {} [OPTIONS]", prog_name);
    println!("Options:");
    println!("  -c <config_file>   指定配置文件 (默认: ./applist.conf)");
    println!("  -s <interval>      设置检查间隔(秒) (必须>=1, 默认: 2)");
    println!("  -b <cpuset_name>   指定 BASE_CPUSET 目录名 (默认: AppOpt)");
    println!("  -v                 显示程序版本");
    println!("  -h                 显示帮助信息");
    println!();
    println!("示例:");
    println!("  {} -c /data/applist.conf -s 3", prog_name);
    println!("  {} -b MyAppOpt", prog_name);
    println!();
    println!("规则格式:");
    println!("  # 注释以 # 或 // 开头");
    println!("  com.example=0-3           包级规则，绑定到 CPU 0-3");
    println!("  com.example=e-core        语义核心，绑定到全部小核");
    println!("  com.example=p-core        语义核心，绑定到全部中核");
    println!("  com.example=hp-core       语义核心，绑定到全部大核");
    println!();
    println!("  块语法，包级规则 + 线程规则");
    println!("  com.example {{");
    println!("    RenderThread=6-7");
    println!("    Thread-1=0-5");
    println!("  }}");
    println!("  线程 RenderThread 绑定到 CPU 6-7");
    println!("  线程 Thread-1 绑定到 CPU 0-5");
}

fn init_inotify(config_file: &str) {
    let inotify_fd = unsafe { libc::inotify_init1(libc::IN_CLOEXEC | libc::IN_NONBLOCK) };
    if inotify_fd < 0 {
        println!("inotify初始化失败，使用轮询模式");
        return;
    }
    // 路径含 NUL 时无法构造 CString，降级到轮询模式
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

    let mut config_file = String::from("./applist.conf");
    let mut sleep_interval: u64 = 2;
    let mut cpuset_name = String::from(DEFAULT_CPUSET_NAME);

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
            "-b" => {
                i += 1;
                if i < args.len() {
                    cpuset_name = args[i].clone();
                    if cpuset_name.is_empty() || cpuset_name.contains('/') {
                        eprintln!("无效的 cpuset 目录名: {}", args[i]);
                        eprintln!("目录名不能为空或包含路径分隔符");
                        process::exit(1);
                    }
                    println!("cpuset 目录名: {}", cpuset_name);
                } else {
                    eprintln!("错误: -b 需要指定 cpuset 目录名");
                    process::exit(1);
                }
            }
            "-v" => {
                if crate::ebpf_mode::ebpf_probe() {
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

    // 先设置 cpuset 路径再初始化拓扑，init_cpu_topo 会创建 BASE_CPUSET 目录
    set_base_cpuset(&cpuset_name);
    let topo = init_cpu_topo();

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

    // 守护进程模式，配置加载线程无 JoinHandle 进程退出时强制终止
    thread::spawn(move || {
        config_loader(sleep_interval);
    });

    let mut cache = ProcScanState::new();
    let mut affinity_deadline = Instant::now();

    println!("启动AppOpt服务 v{}", env!("CARGO_PKG_VERSION"));

    let mut ebpf_state: Option<EbpfState> = ebpf_init();

    loop {
        // 先 swap CONFIG_UPDATED 再获取 cfg 防止漏更新
        let config_changed = CONFIG_UPDATED.swap(false, Ordering::AcqRel);
        let Some(cfg) = lock_ignore_poison(&CURRENT_CONFIG).clone() else {
            thread::sleep(Duration::from_millis(100));
            continue;
        };

        let mut ebpf_dead = false;
        let mut need_ebpf_reload = false;
        match &mut ebpf_state {
            Some(es) => {
                if config_changed {
                    need_ebpf_reload = comm_map_init(&mut es.bpf, &cfg.pkgs, &mut es.comm_capacity);
                    if !need_ebpf_reload {
                        full_scan(&cfg, es);
                    }
                }

                if !need_ebpf_reload {
                    match es.event_rx.recv_timeout(Duration::from_secs(1)) {
                        Ok(event) => {
                            event_dispatch(&event, &cfg, es);
                            while let Ok(event) = es.event_rx.try_recv() {
                                event_dispatch(&event, &cfg, es);
                            }
                        }
                        Err(mpsc::RecvTimeoutError::Timeout) => {}
                        Err(mpsc::RecvTimeoutError::Disconnected) => {
                            ebpf_dead = true;
                        }
                    }

                    // 每 3*sleep_interval 秒定期纠正，纯事件驱动零 /proc 读
                    if affinity_deadline.elapsed() >= Duration::from_secs(3 * sleep_interval) {
                        affinity_check(es, &cfg);
                        affinity_deadline = Instant::now();
                    }
                }
            }
            None => {
                if config_changed {
                    cache.scan_all_proc = true;
                    cache.last_proc_count = 0;
                }

                cache_sync(&mut cache, &cfg);
                if affinity_deadline.elapsed() >= Duration::from_secs(5 * sleep_interval) || cache.force_affinity {
                    cache.cache.affinity_sync(&cfg.topo);
                    affinity_deadline = Instant::now();
                    cache.force_affinity = false;
                }

                thread::sleep(Duration::from_secs(sleep_interval));
            }
        }

        if ebpf_dead {
            eprintln!("eBPF: 事件通道断开，回退到 /proc 轮询");
            ebpf_state = None;
            cache.scan_all_proc = true;
            cache.last_proc_count = 0;
            cache.force_affinity = true;
            affinity_deadline = Instant::now();
        }

        // 容量不足先释放旧 BPF 程序再重载，置位 CONFIG_UPDATED 触发重建
        if need_ebpf_reload {
            ebpf_state.take();
            ebpf_state = ebpf_init();
            CONFIG_UPDATED.store(true, Ordering::Release);
            affinity_deadline = Instant::now();
        }
    }
}

#![cfg(any(target_os = "linux", target_os = "android"))]
#[cfg(target_pointer_width = "32")]
compile_error!("AppOpt requires 64-bit target due to cpu_set_t binary layout assumptions");

mod apply_affinity;
mod cache;
mod config;
mod cpuset;
mod ebpf_mode;
mod proc_mode;
mod rule_edit;
mod rule_match;
mod web;

use std::env;
use std::fs;
use std::process;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::config::{config_loader, init_inotify, load_config, CHECK_INTERVAL, CONFIG_FILE, CURRENT_CONFIG};
use crate::cpuset::{init_cpu_topo, set_base_cpuset};
use crate::ebpf_mode::{
    affinity_check, full_scan, event_dispatch, comm_map_init,
    ebpf_init, EbpfState,
};
use crate::proc_mode::{cache_sync, ProcScanState};
use crate::web::{
    cache_stats, settings_load, settings_save, web_start, WebStats,
    WEB_ENABLED, WEB_STATS, MODE_FORCE, SETTINGS_FILE,
};

pub const MAX_PKG_LEN: usize = 128;
pub const MAX_THREAD_LEN: usize = 32;

pub static CONFIG_UPDATED: AtomicBool = AtomicBool::new(false);

/// 自动模式下 eBPF 初始化失败后的放弃标记，用户强制切换时清除
pub static EBPF_GAVE_UP: AtomicBool = AtomicBool::new(false);

pub(crate) fn lock_ignore_poison<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| {
        eprintln!("警告: 互斥锁中毒，尝试恢复...");
        e.into_inner()
    })
}

fn print_help(prog_name: &str) {
    println!("Usage: {} [OPTIONS]", prog_name);
    println!("Options:");
    println!("  -c <config_file>   指定配置文件 (默认: ./applist.conf)");
    println!("  -s <interval>      设置检查间隔(秒) (必须>=1, 默认: 2)");
    println!("  -b <cpuset_name>   指定 BASE_CPUSET 目录名 (默认: AppOpt)");
    println!("  -w                 启用网页前端 (仅本机 127.0.0.1:8889)");
    println!("  -v                 显示程序版本");
    println!("  -h                 显示帮助信息");
    println!();
    println!("示例:");
    println!("  {} -c /data/applist.conf -s 3", prog_name);
    println!("  {} -b MyAppOpt", prog_name);
    println!();
    println!("应用设置保存于 ./AppOpt.json，首次运行自动创建；");
    println!("命令行参数优先于设置文件，web 端修改会写回该文件。");
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

fn main() {
    let args: Vec<String> = env::args().collect();
    let prog_name = &args[0];

    // 参数解析先行，-v/-h/错误用法在设置加载前退出，不产生文件副作用
    let (mut cli_cfg, mut cli_interval, mut cli_cpuset, mut cli_web) =
        (None, None, None, false);

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-c" => {
                i += 1;
                if i < args.len() {
                    cli_cfg = Some(args[i].clone());
                    println!("配置文件: {}", args[i]);
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
                    cli_interval = Some(val);
                    println!("检查间隔: {} 秒", val);
                } else {
                    eprintln!("错误: -s 需要指定时间间隔");
                    process::exit(1);
                }
            }
            "-w" => {
                cli_web = true;
            }
            "-b" => {
                i += 1;
                if i < args.len() {
                    cli_cpuset = Some(args[i].clone());
                    if args[i].is_empty() || args[i].contains('/') {
                        eprintln!("无效的 cpuset 目录名: {}", args[i]);
                        eprintln!("目录名不能为空或包含路径分隔符");
                        process::exit(1);
                    }
                    println!("cpuset 目录名: {}", args[i]);
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

    // 应用设置持久化于 AppOpt.json，命令行参数优先覆盖
    let st = settings_load(SETTINGS_FILE);
    let config_file = cli_cfg.unwrap_or(st.config_file);
    let sleep_interval = cli_interval.unwrap_or(st.check_interval);
    let cpuset_name = cli_cpuset.unwrap_or(st.cpuset_name);
    let web_enable = cli_web || st.web_enable;

    // 先设置 cpuset 路径再初始化拓扑，init_cpu_topo 会创建 BASE_CPUSET 目录
    set_base_cpuset(&cpuset_name);
    let topo = init_cpu_topo();

    if fs::metadata(&config_file).is_err() {
        let initial_content = "# 规则编写与使用说明请参考 http://AppOpt.suto.top\n\n";
        if fs::write(&config_file, initial_content).is_ok() {
            println!("配置文件不存在，重建一个空的配置文件: {}", config_file);
        }
    }

    {
        let mut guard = lock_ignore_poison(&CONFIG_FILE);
        *guard = config_file.clone();
    }
    CHECK_INTERVAL.store(sleep_interval, Ordering::Release);
    MODE_FORCE.store(st.mode, Ordering::Release);

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

    if web_enable {
        web_start();
        // -w 或设置恢复启用后落盘，重启保持开启
        settings_save();
    }

    // 守护进程模式，保存 JoinHandle 用于 panic 恢复检测
    let mut config_handle = thread::spawn(config_loader);

    let mut proc_state: Option<ProcScanState> = None;
    let mut affinity_deadline = Instant::now();
    let prog_start = Instant::now();
    let mut web_stats_deadline = Instant::now();
    // 预支 60 秒使首次重试立即到期
    let mut ebpf_retry_at = Instant::now()
        .checked_sub(Duration::from_secs(60))
        .unwrap_or_else(Instant::now);

    println!("启动AppOpt服务 v{}", env!("CARGO_PKG_VERSION"));

    // 恢复的强制 proc 模式无需 eBPF 初始化
    let mut ebpf_state: Option<EbpfState> =
        if MODE_FORCE.load(Ordering::Relaxed) == 2 { None } else { ebpf_init() };
    // 仅自动模式失败一次即放弃；强制 eBPF 需持续重试，强制 proc 无需 eBPF
    if ebpf_state.is_none() && MODE_FORCE.load(Ordering::Relaxed) == 0 {
        EBPF_GAVE_UP.store(true, Ordering::Relaxed);
    }

    loop {
        // 先 swap CONFIG_UPDATED 再获取 cfg 防止漏更新
        let config_changed = CONFIG_UPDATED.swap(false, Ordering::AcqRel);
        let Some(cfg) = lock_ignore_poison(&CURRENT_CONFIG).clone() else {
            thread::sleep(Duration::from_millis(100));
            continue;
        };
        let interval = CHECK_INTERVAL.load(Ordering::Relaxed).max(1);
        let mode = MODE_FORCE.load(Ordering::Relaxed);

        // 配置加载线程 panic 恢复
        if config_handle.is_finished() {
            eprintln!("警告: 配置加载线程异常退出，尝试重启...");
            config_handle = thread::spawn(config_loader);
        }

        // 强制 /proc 时卸载 eBPF 并触发全量扫描
        if mode == 2 && ebpf_state.is_some() {
            println!("工作模式切换: /proc 轮询");
            ebpf_state = None;
            let cache = proc_state.get_or_insert_with(ProcScanState::new);
            cache.scan_all_proc = true;
            cache.last_proc_count = 0;
            cache.force_affinity = true;
            affinity_deadline = Instant::now();
        }

        // eBPF 缺失时周期重试，自动模式失败一次后放弃，强制模式持续重试
        if mode != 2
            && ebpf_state.is_none()
            && (mode == 1 || !EBPF_GAVE_UP.load(Ordering::Relaxed))
            && ebpf_retry_at.elapsed() >= Duration::from_secs(30)
        {
            ebpf_retry_at = Instant::now();
            if let Some(mut new_es) = ebpf_init() {
                if comm_map_init(&mut new_es.bpf, &cfg.pkgs, new_es.comm_capacity) {
                    eprintln!("eBPF: 白名单容量不足，保持 /proc 轮询");
                    if mode == 0 {
                        EBPF_GAVE_UP.store(true, Ordering::Relaxed);
                    }
                } else {
                    println!("工作模式切换: eBPF 事件驱动");
                    full_scan(&cfg, &mut new_es);
                    ebpf_state = Some(new_es);
                    affinity_deadline = Instant::now();
                }
            } else if mode == 0 {
                EBPF_GAVE_UP.store(true, Ordering::Relaxed);
            }
        }

        let mut ebpf_dead = false;

        let need_reload = if let Some(es) = ebpf_state.as_mut() {
            if config_changed {
                let r = comm_map_init(&mut es.bpf, &cfg.pkgs, es.comm_capacity);
                if !r {
                    full_scan(&cfg, es);
                }
                r
            } else {
                false
            }
        } else {
            false
        };

        if need_reload {
            ebpf_state = None;
            if let Some(mut new_es) = ebpf_init() {
                if comm_map_init(&mut new_es.bpf, &cfg.pkgs, new_es.comm_capacity) {
                    eprintln!("eBPF: 重载后白名单容量仍不足，回退到 /proc 轮询");
                    continue;
                }
                full_scan(&cfg, &mut new_es);
                ebpf_state = Some(new_es);
            }
            continue;
        }

        if let Some(es) = ebpf_state.as_mut() {
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

            if affinity_deadline.elapsed() >= Duration::from_secs(3 * interval) {
                affinity_check(es, &cfg);
                affinity_deadline = Instant::now();
            }
        } else {
            let cache = proc_state.get_or_insert_with(ProcScanState::new);
            if config_changed {
                cache.scan_all_proc = true;
                cache.last_proc_count = 0;
            }
            cache_sync(cache, &cfg);
            if affinity_deadline.elapsed() >= Duration::from_secs(5 * interval) || cache.force_affinity {
                cache.cache.affinity_sync(&cfg.topo);
                affinity_deadline = Instant::now();
                cache.force_affinity = false;
            }
            thread::sleep(Duration::from_secs(interval));
        }

        if ebpf_dead {
            eprintln!("eBPF: 事件通道断开，回退到 /proc 轮询");
            ebpf_state = None;
            let cache = proc_state.get_or_insert_with(ProcScanState::new);
            cache.scan_all_proc = true;
            cache.last_proc_count = 0;
            cache.force_affinity = true;
            affinity_deadline = Instant::now();
        }

        // web 状态统计，低频更新避免高频事件循环下的额外开销
        if WEB_ENABLED.load(Ordering::Relaxed)
            && web_stats_deadline.elapsed() >= Duration::from_secs(2)
        {
            web_stats_deadline = Instant::now();
            let (threads, hit_pkgs) = match (&ebpf_state, &proc_state) {
                (Some(es), _) => cache_stats(&es.cache),
                (None, Some(ps)) => cache_stats(&ps.cache),
                _ => (0, 0),
            };
            *lock_ignore_poison(&WEB_STATS) = Some(WebStats {
                rules: cfg.rules.len(),
                pkgs: cfg.pkgs.len(),
                hit_pkgs,
                threads,
                ebpf: ebpf_state.is_some(),
                uptime: prog_start.elapsed().as_secs(),
            });
        }
    }
}

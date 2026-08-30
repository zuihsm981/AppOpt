#![cfg(any(target_os = "linux", target_os = "android"))]
#[cfg(target_pointer_width = "32")]
compile_error!("AppOpt requires 64-bit target due to cpu_set_t binary layout assumptions");

mod apply_affinity;
mod cache;
mod config;
mod cpuset;
mod ebpf_mode;
mod proc_mode;
mod process_observer;
mod refresh;
mod rule_edit;
mod rule_match;
mod web;

use std::env;
use std::fs;
use std::process;
use std::sync::atomic::Ordering;
use std::sync::{mpsc, Arc, Mutex};
use std::time::Instant;

use crate::config::{
    init_inotify, load_config,
    CHECK_INTERVAL, CONFIG_FILE, CONFIG_WAKE_FD, CURRENT_CONFIG,
};
use crate::cpuset::{init_cpu_topo, set_base_cpuset};
use crate::ebpf_mode::{
    full_scan, event_dispatch, comm_map_init, EBPF_EVENT_FORK, EBPF_EVENT_EXEC,
    EBPF_EVENT_RENAME, ebpf_init, EbpfState,
};
use crate::proc_mode::{cache_sync, ProcScanState};
use crate::web::{
    cache_stats, settings_load, settings_save, web_start, WebStats,
    WEB_ENABLED, WEB_STATS, MODE_FORCE, MODE_SWITCH_FD, SETTINGS_FILE,
};

pub const MAX_PKG_LEN: usize = 128;
pub const MAX_THREAD_LEN: usize = 32;

pub(crate) fn lock_ignore_poison<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
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
                } else {
                    eprintln!("错误: -b 需要指定 cpuset 目录名");
                    process::exit(1);
                }
            }
            "-v" => {
                if crate::ebpf_mode::kpm_probe() {
                    println!("AppOpt 版本 {} KPM", env!("CARGO_PKG_VERSION"));
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
        let _ = fs::write(&config_file, initial_content);
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

    init_inotify(&config_file);

    if web_enable {
        web_start();
        // -w 或设置恢复启用后落盘，重启保持开启
        settings_save();
    }

    // 刷新率控制模块，独立线程运行，通过 eBPF 事件驱动
    refresh::refresh_init();

    let prog_start = Instant::now();
    let mut proc_state: Option<ProcScanState> = None;
    let mut ebpf_state: Option<EbpfState> = None;

    // ================= 纯事件驱动主循环 =================
    // 事件源: KPM 事件唤醒 eventfd / inotify / 模式切换 eventfd / 配置重载 eventfd
    //          /proc 回退模式的周期 timerfd (仅 KPM 不可用时启用)
    const EV_KPM: u64 = 1;
    const EV_INOTIFY: u64 = 2;
    const EV_MODE: u64 = 3;
    const EV_CONFIG: u64 = 4;
    const EV_PROC: u64 = 5;

    let epfd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
    if epfd < 0 {
        eprintln!("初始化 epoll 失败");
        process::exit(1);
    }
    fn epoll_add(epfd: i32, fd: i32, tag: u64) {
        if fd < 0 {
            return;
        }
        let mut ev: libc::epoll_event = unsafe { std::mem::zeroed() };
        ev.events = libc::EPOLLIN as u32;
        ev.u64 = tag;
        unsafe { libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, fd, &mut ev) };
    }
    fn read_eventfd(fd: i32) {
        if fd < 0 {
            return;
        }
        let mut buf = [0u8; 8];
        let _ = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut _, 8) };
    }
    fn arm_periodic(tfd: i32, secs: i64) {
        let ts = libc::timespec { tv_sec: secs, tv_nsec: 0 };
        let it = libc::itimerspec { it_interval: ts, it_value: ts };
        unsafe { libc::timerfd_settime(tfd, 0, &it, std::ptr::null_mut()) };
    }
    fn disarm_timerfd(tfd: i32) {
        let zero = libc::timespec { tv_sec: 0, tv_nsec: 0 };
        let it = libc::itimerspec { it_interval: zero, it_value: zero };
        unsafe { libc::timerfd_settime(tfd, 0, &it, std::ptr::null_mut()) };
    }
    // 配置变更后应用到当前模式: KPM 重载白名单 + 全量扫描; /proc 标记全量重扫
    fn apply_config(
        ebpf_state: &mut Option<EbpfState>,
        proc_state: &mut Option<ProcScanState>,
        cfg: Option<&crate::config::AppConfig>,
    ) {
        let Some(cfg) = cfg else { return };
        if let Some(es) = ebpf_state.as_mut() {
            let r = comm_map_init(&mut es.bpf, &cfg.pkgs, es.comm_capacity);
            if !r {
                full_scan(cfg, es);
            }
        } else {
            let ps = proc_state.get_or_insert_with(ProcScanState::new);
            ps.scan_all_proc = true;
            ps.last_proc_count = 0;
            ps.force_affinity = true;
        }
    }

    // KPM 事件唤醒 eventfd: reader 收到事件后写入, 主循环 epoll 唤醒
    let kpm_wake_fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
    epoll_add(epfd, kpm_wake_fd, EV_KPM);
    // 模式切换 eventfd: web 端修改 MODE_FORCE 后写入
    let mode_switch_fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
    MODE_SWITCH_FD.store(mode_switch_fd, Ordering::Relaxed);
    epoll_add(epfd, mode_switch_fd, EV_MODE);
    // 配置重载 eventfd: web 端写配置/规则后由 config_reload_now 写入
    let config_wake_fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
    CONFIG_WAKE_FD.store(config_wake_fd, Ordering::Relaxed);
    epoll_add(epfd, config_wake_fd, EV_CONFIG);
    // inotify fd: 配置文件修改
    let inotify_fd = crate::config::INOTIFY_FD.load(Ordering::Acquire);
    epoll_add(epfd, inotify_fd, EV_INOTIFY);
    // /proc 回退模式周期 timerfd
    let proc_timer_fd = unsafe {
        libc::timerfd_create(libc::CLOCK_MONOTONIC, libc::TFD_CLOEXEC | libc::TFD_NONBLOCK)
    };
    epoll_add(epfd, proc_timer_fd, EV_PROC);

    // 初始 eBPF 初始化 (强制 /proc 模式不尝试)
    if MODE_FORCE.load(Ordering::Relaxed) != 2 {
        if let Some(mut es) = ebpf_init(kpm_wake_fd) {
            let cfg = lock_ignore_poison(&CURRENT_CONFIG).clone();
            if let Some(cfg) = cfg {
                if !comm_map_init(&mut es.bpf, &cfg.pkgs, es.comm_capacity) {
                    full_scan(&cfg, &mut es);
                }
            }
            ebpf_state = Some(es);
        }
    }
    // /proc 模式: 周期 timerfd 立即启动; KPM 模式: 保持 disarm
    if ebpf_state.is_none() {
        let interval = CHECK_INTERVAL.load(Ordering::Relaxed).max(1);
        arm_periodic(proc_timer_fd, interval as i64);
    }

    let mut events = [unsafe { std::mem::zeroed::<libc::epoll_event>() }; 8];

    loop {
        let n = unsafe { libc::epoll_wait(epfd, events.as_mut_ptr(), 8, -1) };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            break;
        }
        if n == 0 {
            continue;
        }

        let mut cfg = lock_ignore_poison(&CURRENT_CONFIG).clone();
        let mut kpm_died = false;

        for i in 0..n as usize {
            let ev = events[i];
            match ev.u64 {
                EV_KPM => {
                    read_eventfd(kpm_wake_fd);
                    if let Some(es) = ebpf_state.as_mut() {
                        // 本批事件中是否含 FORK/EXEC/RENAME (需要立即同步亲和性)
                        let mut need_sync = false;
                        loop {
                            match es.event_rx.try_recv() {
                                Ok(event) => {
                                    if event.event_type == EBPF_EVENT_FORK
                                        || event.event_type == EBPF_EVENT_EXEC
                                        || event.event_type == EBPF_EVENT_RENAME
                                    {
                                        need_sync = true;
                                    }
                                    let Some(cfg) =
                                        lock_ignore_poison(&CURRENT_CONFIG).clone()
                                    else {
                                        continue;
                                    };
                                    event_dispatch(&event, &cfg, es);
                                }
                                Err(mpsc::TryRecvError::Empty) => break,
                                Err(mpsc::TryRecvError::Disconnected) => {
                                    kpm_died = true;
                                    break;
                                }
                            }
                        }
                        // 收到 FORK/EXEC/RENAME: 立即执行 affinity_sync (仅设置 CPU 亲和性),
                        // 不依赖定时器/IDLE; 无此类事件时仅增量更新 cache
                        if need_sync {
                            let Some(cfg) = lock_ignore_poison(&CURRENT_CONFIG).clone() else {
                                continue;
                            };
                            es.cache.affinity_sync(&cfg.topo);
                        }
                    }
                }
                EV_INOTIFY => {
                    if crate::config::inotify_drain() {
                        // 配置已重载: 应用到当前模式
                        cfg = lock_ignore_poison(&CURRENT_CONFIG).clone();
                        apply_config(&mut ebpf_state, &mut proc_state, cfg.as_deref());
                    }
                }
                EV_MODE => {
                    read_eventfd(mode_switch_fd);
                    let mode = MODE_FORCE.load(Ordering::Relaxed);
                    if mode == 2 {
                        // 强制 /proc: 卸载 eBPF
                        if ebpf_state.take().is_some() {
                            let ps = proc_state.get_or_insert_with(ProcScanState::new);
                            ps.scan_all_proc = true;
                            ps.last_proc_count = 0;
                            ps.force_affinity = true;
                        }
                    } else if ebpf_state.is_none() {
                        // 自动/强制 KPM: 尝试初始化
                        if let Some(mut es) = ebpf_init(kpm_wake_fd) {
                            if let Some(cfg) = cfg.as_ref() {
                                if !comm_map_init(&mut es.bpf, &cfg.pkgs, es.comm_capacity) {
                                    full_scan(cfg, &mut es);
                                }
                            }
                            ebpf_state = Some(es);
                        }
                    } else {
                        // 已在 KPM 模式: 重新应用配置 (白名单可能变化)
                        apply_config(&mut ebpf_state, &mut proc_state, cfg.as_deref());
                    }
                }
                EV_CONFIG => {
                    read_eventfd(config_wake_fd);
                    cfg = lock_ignore_poison(&CURRENT_CONFIG).clone();
                    apply_config(&mut ebpf_state, &mut proc_state, cfg.as_deref());
                }
                EV_PROC => {
                    read_eventfd(proc_timer_fd);
                    // /proc 回退模式周期同步
                    if ebpf_state.is_none() {
                        let Some(cfg) = cfg.as_ref() else { continue };
                        let ps = proc_state.get_or_insert_with(ProcScanState::new);
                        cache_sync(ps, cfg);
                        if ps.force_affinity {
                            ps.cache.affinity_sync(&cfg.topo);
                            ps.force_affinity = false;
                        }
                    }
                }
                _ => {}
            }
        }

        // KPM 通道断开: 回退 /proc 并启动周期 timerfd
        if kpm_died {
            ebpf_state = None;
            let ps = proc_state.get_or_insert_with(ProcScanState::new);
            ps.scan_all_proc = true;
            ps.last_proc_count = 0;
            ps.force_affinity = true;
        }

        // 周期 timerfd 与模式联动: /proc 模式启动, KPM 模式停止
        let interval = CHECK_INTERVAL.load(Ordering::Relaxed).max(1);
        if ebpf_state.is_none() {
            arm_periodic(proc_timer_fd, interval as i64);
        } else {
            disarm_timerfd(proc_timer_fd);
        }

        // web 状态统计: 事件驱动更新 (收到事件时刷新, 不再定时轮询)
        if WEB_ENABLED.load(Ordering::Relaxed) && crate::web::web_active() {
            let (threads, hit_pkgs) = match (&ebpf_state, &proc_state) {
                (Some(es), _) => cache_stats(&es.cache),
                (None, Some(ps)) => cache_stats(&ps.cache),
                _ => (0, 0),
            };
            if let Some(cfg) = cfg.as_ref() {
                *lock_ignore_poison(&WEB_STATS) = Some(WebStats {
                    rules: cfg.rules.len(),
                    pkgs: cfg.pkgs.len(),
                    hit_pkgs,
                    threads,
                    kpm: ebpf_state.is_some(),
                    uptime: prog_start.elapsed().as_secs(),
                });
            }
        }
    }

    unsafe { libc::close(epfd) };
}
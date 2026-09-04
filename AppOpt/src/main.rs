#![cfg(any(target_os = "linux", target_os = "android"))]
#[cfg(target_pointer_width = "32")]
compile_error!("AppOpt requires 64-bit target due to cpu_set_t binary layout assumptions");

mod apply_affinity;
mod cache;
mod config;
mod cpuset;
mod debug_log;
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
    full_scan, event_dispatch, comm_map_init, ebpf_init, EbpfState,
};
use crate::proc_mode::{cache_sync, ProcScanState};
use crate::rule_match::PkgMatch;
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
    println!("  -c <config_file>   指定统一配置文件 (默认: ./appopt.conf)");
    println!("  -s <interval>      设置检查间隔(秒) (必须>=1, 默认: 2)");
    println!("  -b <cpuset_name>   指定 BASE_CPUSET 目录名 (默认: AppOpt)");
    println!("  -w                 启用网页前端 (仅本机 127.0.0.1:8889)");
    println!("  -v                 显示程序版本");
    println!("  -h                 显示帮助信息");
    println!();
    println!("示例:");
    println!("  {} -c /data/appopt.conf -s 3", prog_name);
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
    println!();
    println!("刷新率配置（与上述规则共用此文件）:");
    println!("  refresh_timeout=30");
    println!("  refresh_active=120");
    println!("  refresh_idle=60");
    println!("  refresh_app,com.example.game,30,120,60");
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let prog_name = &args[0];

    // 调试日志初始化 (追加 /data/local/tmp/appopt_debug.log, 线程安全)
    crate::debug_log::init_debug_log();
    crate::debug_log::debug_log("=== AppOpt start ===");

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
    let config_file = match cli_cfg {
        Some(path) => path,
        None if st.config_file == "./applist.conf" => "./appopt.conf".to_string(),
        None => st.config_file,
    };
    // 默认配置升级：applist.conf -> appopt.conf；-c 显式指定的路径不受影响。
    crate::config::migrate_legacy_main_config(&config_file);
    let sleep_interval = cli_interval.unwrap_or(st.check_interval);
    let cpuset_name = cli_cpuset.unwrap_or(st.cpuset_name);
    let web_enable = cli_web || st.web_enable;

    // 先设置 cpuset 路径再初始化拓扑，init_cpu_topo 会创建 BASE_CPUSET 目录
    set_base_cpuset(&cpuset_name);
    let topo = init_cpu_topo();

    if fs::metadata(&config_file).is_err() {
        let initial_content = "# 规则编写与使用说明请参考 http://AppOpt.suto.top\n# 刷新率字段与 CPU 规则共用此文件\nrefresh_timeout=30\nrefresh_active=120\nrefresh_idle=60\n\n";
        let _ = fs::write(&config_file, initial_content);
    }
    // 兼容旧版本：将 refresh_config.conf 内容一次性并入当前主配置文件。
    // 迁移完成后刷新率模块不再依赖该独立文件。
    crate::config::migrate_legacy_refresh_config(&config_file);

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
    fn arm_periodic_ms(tfd: i32, ms: i64) {
        let ts = libc::timespec {
            tv_sec: ms / 1000,
            tv_nsec: (ms % 1000) * 1_000_000,
        };
        let it = libc::itimerspec { it_interval: ts, it_value: ts };
        unsafe { libc::timerfd_settime(tfd, 0, &it, std::ptr::null_mut()) };
    }
    #[allow(dead_code)]
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
            let r = comm_map_init(&mut es.bpf, cfg, es.comm_capacity);
            if !r {
                full_scan(cfg, es);
            } else {
                // 白名单已更新，丢弃旧的 pid→pkg 解析缓存，让后续事件重新识别；
                // 已绑定的任务和命中计数保留，避免重复全量扫描的开销。
                es.cache.invalidate_pid_cache();
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
                if !comm_map_init(&mut es.bpf, &cfg, es.comm_capacity) {
                    full_scan(&cfg, &mut es);
                }
            }
            ebpf_state = Some(es);
        }
    }
    // /proc 模式: 周期 timerfd 立即启动; KPM 模式: 短周期 pending 重放 (200ms)
    if ebpf_state.is_none() {
        let interval = CHECK_INTERVAL.load(Ordering::Relaxed).max(1);
        arm_periodic(proc_timer_fd, interval as i64);
    } else {
        arm_periodic_ms(proc_timer_fd, 200);
    }

    // KPM 模式 EV_PROC tick 计数: 200ms × 10 = 2s 周期 affinity_sync 兜底
    let mut kpm_tick: u32 = 0;
    // 模式跟踪: 仅模式切换时重置 proc_timer_fd (每轮重置会饿死 EV_PROC)
    let mut prev_kpm_mode = false;

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
                        // 事件驱动亲和性: FORK 全量跟踪 + RENAME 关联包名 + EXIT 清理
                        // (EXEC 已移除: Android 应用由 Zygote fork 产生, 从不 execve)。
                        // 用户态收到事件后 comm_to_pkg (cmdline 权威) 识别包名,
                        // task_apply → affinity_apply 立即设置亲和性; INPUT 唤醒刷新率。
                        loop {
                            match es.event_rx.try_recv() {
                                Ok(event) => {
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
                                if !comm_map_init(&mut es.bpf, cfg, es.comm_capacity) {
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
                    } else if let Some(es) = ebpf_state.as_mut() {
                        // KPM 模式: 200ms 定时器双职责。
                        //  1. pending_rename 重查 (FORK 时线程名/cmdline 未就绪):
                        //     pthread_setname_np 走 prctl 不触发 task_rename;
                        //     Zygote fork 主线程时 cmdline 仍是 zygote64。
                        //  2. 每 10 tick (2s) 轻量 affinity_sync 兜底: EXIT 探针
                        //     恢复 APPLIED 过滤后, "线程在 applied_set 前退出"
                        //     的漏报残留由 sync 的 ESRCH 清理 (get_affinity
                        //     失败 → task_del), 不依赖 EXIT 事件。
                        let has_pending = !es.cache.pending_rename.is_empty();
                        kpm_tick += 1;
                        let do_sync = kpm_tick >= 10;
                        if !has_pending && !do_sync {
                            continue;
                        }
                        let Some(cfg) = cfg.as_ref() else { continue };
                        if has_pending {
                            let pending: Vec<(i32, (i32, String))> =
                                es.cache.pending_rename.drain().collect();
                            for (tid, (pid, pkg)) in pending {
                                let Some(comm) = crate::apply_affinity::tid_comm(tid) else {
                                    // 线程已退出: sync 兜底清理, 此处跳过
                                    continue;
                                };
                                if pkg.is_empty() {
                                    // cmdline 未就绪场景: 重新识别包名
                                    if let PkgMatch::Hit(pkg) =
                                        crate::rule_match::comm_to_pkg(pid, &comm, cfg)
                                    {
                                        es.cache.task_apply(tid, pid, &pkg, &comm, cfg, |tid, cpus, cpuset_dir| {
                                            crate::ebpf_mode::event_affinity_apply(tid, cpus, cpuset_dir, cfg, &es.bpf)
                                        });
                                    }
                                } else {
                                    // 线程名未确定场景: 重读线程名匹配线程规则
                                    es.cache.task_apply(tid, pid, &pkg, &comm, cfg, |tid, cpus, cpuset_dir| {
                                        crate::ebpf_mode::event_affinity_apply(tid, cpus, cpuset_dir, cfg, &es.bpf)
                                    });
                                }
                            }
                        }
                        if do_sync {
                            kpm_tick = 0;
                            es.cache.affinity_sync(&cfg.topo);
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

        // 周期 timerfd 与模式联动: 仅在模式切换时重置, 不每轮重置!
        // timerfd_settime 会重置倒计时 — 若每轮 epoll 唤醒后都重设 200ms,
        // 事件间隔 < 200ms 时 (INPUT/FORK/EXIT 随时到来) EV_PROC 永不触发,
        // pending_rename 重查失效 → Zygote fork 主线程 (cmdline 未就绪,
        // Miss 登记 pending) 永不识别 → 主进程亲和性永不设置。
        // 用 prev_kpm_mode 检测模式变化, 稳态下不再触碰 timerfd。
        let interval = CHECK_INTERVAL.load(Ordering::Relaxed).max(1);
        let kpm_mode_now = ebpf_state.is_some();
        if kpm_mode_now != prev_kpm_mode {
            prev_kpm_mode = kpm_mode_now;
            if kpm_mode_now {
                arm_periodic_ms(proc_timer_fd, 200);
            } else {
                arm_periodic(proc_timer_fd, interval as i64);
            }
        }

        // web 状态统计: 事件驱动更新 (收到事件时刷新, 不再定时轮询)
        if WEB_ENABLED.load(Ordering::Relaxed) && crate::web::web_active() {
            let (threads, hit_pkgs, hit_list) = match (&ebpf_state, &proc_state) {
                (Some(es), _) => cache_stats(&es.cache),
                (None, Some(ps)) => cache_stats(&ps.cache),
                _ => (0, 0, Vec::new()),
            };
            if let Some(cfg) = cfg.as_ref() {
                *lock_ignore_poison(&WEB_STATS) = Some(WebStats {
                    rules: cfg.rules.len(),
                    pkgs: cfg.pkgs.len(),
                    hit_pkgs,
                    hit_list,
                    threads,
                    kpm: ebpf_state.is_some(),
                    uptime: prog_start.elapsed().as_secs(),
                });
            }
        }
    }

    unsafe { libc::close(epfd) };
}

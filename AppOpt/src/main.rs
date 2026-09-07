#![cfg(any(target_os = "linux", target_os = "android"))]
#[cfg(target_pointer_width = "32")]
compile_error!("AppOpt requires 64-bit target due to cpu_set_t binary layout assumptions");

mod apply_affinity;
mod cache;
mod cpu_affinity;
mod config;
mod cpuset;
mod ebpf_mode;
mod proc_mode;
mod process_observer;
mod refresh;
mod rule_edit;
mod rule_match;
mod web;

use std::collections::{HashMap, HashSet};
use std::env;
use std::ffi::CString;
use std::fs;
use std::process;
use std::sync::atomic::Ordering;
use std::sync::{mpsc, Arc, Mutex};
use std::time::Instant;

use crate::config::{
    init_inotify, load_config, AppConfig,
    CHECK_INTERVAL, CONFIG_FILE, CONFIG_WAKE_FD, CURRENT_CONFIG,
};
use crate::cpuset::{init_cpu_topo, set_base_cpuset};
use crate::ebpf_mode::{
    full_scan, event_dispatch, ebpf_init, EbpfState,
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

/// 从 packages.list 构建两张 uid→包名 静态表 (主线程持有):
///   cpu: 有 CPU 规则的应用; rfr: com.android.launcher3 + 有刷新率规则的应用。
/// 前台回调只查这两张表, 不查 cmdline、不管 pid。
fn build_uid_tables(cfg: &AppConfig) -> (HashMap<i32, String>, HashMap<i32, String>) {
    let mut cpu_pkgs: HashSet<&str> = HashSet::new();
    for r in &cfg.rules {
        cpu_pkgs.insert(r.pkg.as_str());
    }
    let mut cpu: HashMap<i32, String> = HashMap::new();
    let mut rfr: HashMap<i32, String> = HashMap::new();
    if let Ok(content) = std::fs::read_to_string("/data/system/packages.list") {
        for line in content.lines() {
            let mut it = line.split_whitespace();
            let (Some(pkg), Some(uid_s)) = (it.next(), it.next()) else { continue };
            let Ok(uid) = uid_s.parse::<i32>() else { continue };
            if cpu_pkgs.contains(pkg) {
                cpu.entry(uid).or_insert_with(|| pkg.to_string());
            }
            if pkg == crate::config::DEFAULT_REFRESH_PACKAGE
                || cfg.app_refresh_configs.contains_key(pkg)
            {
                rfr.entry(uid).or_insert_with(|| pkg.to_string());
            }
        }
    }
    (cpu, rfr)
}

/// 规则应用集合 (cpu/rfr): 主线程检测“新增/删除规则应用”, 集合未变则跳过重建
fn cfg_pkg_sets(cfg: &AppConfig) -> (HashSet<String>, HashSet<String>) {
    let cpu: HashSet<String> = cfg.rules.iter().map(|r| r.pkg.clone()).collect();
    let mut rfr: HashSet<String> = cfg.app_refresh_configs.keys().cloned().collect();
    rfr.insert(crate::config::DEFAULT_REFRESH_PACKAGE.to_string());
    (cpu, rfr)
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

    // CPU 亲和性投递通道必须先于刷新率 observer 建立, 否则注册瞬间(或首个)
    // 前台回调会被丢弃, 导致首次打开应用不生效。
    // AppOpt 初始化时缓存 /proc pid 快照: CPU 枚举跳过系统进程/已运行应用,
    // 只处理之后新出现的 pid (冷启动应用)。早于 worker 线程调度, 不漏启动瞬间进程。
    let init_pids = crate::cpu_affinity::proc_pid_set();
    // 快照保留全部 pid (含 launcher3/systemui): 非其规则时枚举跳过, 避免读取其目录;
    // 额外标记 launcher3/systemui 的 pid, 其规则直接使用标记目录
    let marked = crate::cpu_affinity::classify_marked_pids(&init_pids);
    let cpu_ready = crate::cpu_affinity::start(init_pids, marked);

    // 刷新率控制模块，独立线程运行 (binder 回调经主线程 uid 表 → FgPkg 消息驱动)
    refresh::refresh_init();

    // ===== 三线程: 主线程持有 IProcessObserver 回调 socket, 分发 cpuset/刷新率线程 =====
    let mut fg_sv: [libc::c_int; 2] = [0, 0];
    if unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_DGRAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
            fg_sv.as_mut_ptr(),
        )
    } == 0
    {
        let rcvbuf: libc::c_int = 256 * 1024;
        unsafe {
            libc::setsockopt(
                fg_sv[0],
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                &rcvbuf as *const libc::c_int as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
        crate::process_observer::init_observer(fg_sv[1]);
    }
    let fg_recv_fd = fg_sv[0];
    let mut fg_buf = [0u8; 8];
    // uid 静态表 (主线程): CPU 表 = 有 CPU 规则应用; 刷新率表 = launcher + 规则应用
    let mut cpu_uid: HashMap<i32, String> = HashMap::new();
    let mut rfr_uid: HashMap<i32, String> = HashMap::new();
    let mut cpu_known: HashMap<i32, i32> = HashMap::new(); // uid → pid (CPU 冷热)
    // 规则应用集合 (主线程对比用): 仅集合变化才重建 uid 表 (数值调整不重建)
    let mut cpu_pkgs_set: HashSet<String> = HashSet::new();
    let mut rfr_pkgs_set: HashSet<String> = HashSet::new();
    if let Some(cfg) = lock_ignore_poison(&CURRENT_CONFIG).clone() {
        (cpu_uid, rfr_uid) = build_uid_tables(&cfg);
        (cpu_pkgs_set, rfr_pkgs_set) = cfg_pkg_sets(&cfg);
    }

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
    const EV_FG: u64 = 6; // binder 前台回调 (pid+uid), 主线程分发
    const EV_PKG: u64 = 7; // packages.list inotify (安装/卸载/替换)

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
    // 配置变更后应用到当前模式: KPM 全量扫描 + uid 表重建(规则包集合门控); /proc 标记全量重扫
    fn apply_config(
        cpu_changed: bool,
        ebpf_state: &mut Option<EbpfState>,
        proc_state: &mut Option<ProcScanState>,
        cfg: Option<&crate::config::AppConfig>,
    ) {
        let Some(cfg) = cfg else { return };
        // CPU 规则未变 (仅刷新率/数值调整): 无需全量扫描, 亲和性/uid 表不需重放
        if !cpu_changed {
            return;
        }
        if let Some(es) = ebpf_state.as_mut() {
            kpm_full_apply(cfg, es);
        } else {
            force_proc_rescan(proc_state);
        }
    }

    /// KPM 全量归因扫描 + 亲和性全量应用 (配置变更/模式切换共用)
    fn kpm_full_apply(cfg: &crate::config::AppConfig, es: &mut EbpfState) {
        full_scan(cfg, es);
        crate::cpu_affinity::apply_all_now();
    }

    /// /proc 模式强制重扫 + 亲和性全量应用 (配置变更/切 /proc 共用)
    fn force_proc_rescan(proc_state: &mut Option<ProcScanState>) {
        let ps = proc_state.get_or_insert_with(ProcScanState::new);
        ps.scan_all_proc = true;
        ps.last_proc_count = 0;
        ps.force_affinity = true;
        crate::cpu_affinity::apply_all_now();
    }

    /// uid 表重建: 按 cpu_changed/包集合变化决定 (reload_config 与 EV_MODE 共用)
    fn rebuild_uid_if_needed(
        cpu_changed: bool,
        cfg: &crate::config::AppConfig,
        cpu_uid: &mut HashMap<i32, String>,
        rfr_uid: &mut HashMap<i32, String>,
        cpu_pkgs_set: &mut HashSet<String>,
        rfr_pkgs_set: &mut HashSet<String>,
    ) {
        let (nc, nr) = cfg_pkg_sets(cfg);
        if (cpu_changed && nc != *cpu_pkgs_set) || nr != *rfr_pkgs_set {
            (*cpu_uid, *rfr_uid) = build_uid_tables(cfg);
            *cpu_pkgs_set = nc;
            *rfr_pkgs_set = nr;
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
    if fg_recv_fd > 0 {
        epoll_add(epfd, fg_recv_fd, EV_FG);
    }

    // 监听 /data/system/packages.list: 应用安装/卸载/替换 → 重建 uid 表
    // 用 inotify 而非 mtime (用户要求); 日志确认监听是否成功 (SELinux/权限可见)
    let mut pkg_inotify_fd: i32 = -1;
    let pkglist_path = CString::new("/data/system/packages.list").unwrap_or_default();
    unsafe {
        let ifd = libc::inotify_init1(libc::IN_CLOEXEC | libc::IN_NONBLOCK);
        if ifd < 0 {
            // inotify 不可用 (如 SELinux 拦截), 放弃监听 packages.list
        } else {
            let wd = libc::inotify_add_watch(
                ifd,
                pkglist_path.as_ptr(),
                libc::IN_CLOSE_WRITE
                    | libc::IN_MOVED_TO
                    | libc::IN_MOVE_SELF
                    | libc::IN_DELETE_SELF,
            );
            if wd < 0 {
                libc::close(ifd);
            } else {
                epoll_add(epfd, ifd, EV_PKG);
                pkg_inotify_fd = ifd;
            }
        }
    }

    // 初始 eBPF 初始化 (强制 /proc 模式不尝试)
    if MODE_FORCE.load(Ordering::Relaxed) != 2 {
        if let Some(mut es) = ebpf_init(kpm_wake_fd) {
            let cfg = lock_ignore_poison(&CURRENT_CONFIG).clone();
            if let Some(cfg) = cfg {
                full_scan(&cfg, &mut es);
            }
            ebpf_state = Some(es);
            // CPU 亲和性: binder 前台回调驱动 (cpu_affinity.rs), 启动即全量应用一次
            if cpu_ready {
                crate::cpu_affinity::apply_all_now();
            }
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

    // 配置事件 (EV_INOTIFY / EV_CONFIG) 公共处理: 重载配置 → 应用到当前模式 →
    // 仅“规则应用集合”变更时重建 uid 表 (调整数值不重建)
    let reload_config = |ebpf_state: &mut Option<EbpfState>,
                         proc_state: &mut Option<ProcScanState>,
                         cfg: &mut Option<Arc<AppConfig>>,
                         cpu_uid: &mut HashMap<i32, String>,
                         rfr_uid: &mut HashMap<i32, String>,
                         cpu_pkgs_set: &mut HashSet<String>,
                         rfr_pkgs_set: &mut HashSet<String>| {
        let cpu_changed = crate::config::take_cpu_rules_changed();
        *cfg = lock_ignore_poison(&CURRENT_CONFIG).clone();
        apply_config(cpu_changed, ebpf_state, proc_state, cfg.as_deref());
        if let Some(cfg) = cfg.as_ref() {
            rebuild_uid_if_needed(cpu_changed, cfg, cpu_uid, rfr_uid, cpu_pkgs_set, rfr_pkgs_set);
        }
    };

        for i in 0..n as usize {
            let ev = events[i];
            match ev.u64 {
                EV_KPM => {
                    read_eventfd(kpm_wake_fd);
                    if let Some(es) = ebpf_state.as_mut() {
                        // CPU 亲和性已由 binder 触发的 CpuAffinity 模块负责;
                        // 事件流仅消费 input (刷新率活动检测)。
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
                EV_PKG => {
                    // packages.list 变化 (安装/卸载/替换) → 重建 uid 表
                    if pkg_inotify_fd > 0 {
                        let mut buf = [0u8; 4096];
                        let mut need_rewatch = false;
                        loop {
                            let len = unsafe {
                                libc::read(
                                    pkg_inotify_fd,
                                    buf.as_mut_ptr() as *mut libc::c_void,
                                    buf.len(),
                                )
                            };
                            if len <= 0 {
                                break;
                            }
                            let hdr = std::mem::size_of::<libc::inotify_event>();
                            let mut off = 0usize;
                            while off + hdr <= len as usize {
                                let ev = unsafe {
                                    &*(buf.as_ptr().add(off) as *const libc::inotify_event)
                                };
                                if ev.mask & (libc::IN_MOVE_SELF | libc::IN_DELETE_SELF) != 0 {
                                    need_rewatch = true;
                                }
                                off += hdr + ev.len as usize;
                            }
                        }
                        // atomic 替换 (rename) 后 inode 变化, 需重加 watch
                        if need_rewatch {
                            let wd = unsafe {
                                libc::inotify_add_watch(
                                    pkg_inotify_fd,
                                    pkglist_path.as_ptr(),
                                    libc::IN_CLOSE_WRITE
                                        | libc::IN_MOVED_TO
                                        | libc::IN_MOVE_SELF
                                        | libc::IN_DELETE_SELF,
                                )
                            };
                            if wd < 0 {
                                /* rewatch 失败: 下次事件再尝试 */
                            }
                        }
                        if let Some(cfg) = cfg.as_ref() {
                            (cpu_uid, rfr_uid) = build_uid_tables(cfg);
                        }
                    }
                }
                EV_FG => {
                    // binder 前台回调 (pid+uid): 主线程查两张 uid 表分发
                    if fg_recv_fd > 0 {
                        let nrecv = unsafe {
                            libc::recv(
                                fg_recv_fd,
                                fg_buf.as_mut_ptr() as *mut libc::c_void,
                                fg_buf.len(),
                                0,
                            )
                        };
                        if nrecv == 8 {
                            let pid = i32::from_ne_bytes([fg_buf[0], fg_buf[1], fg_buf[2], fg_buf[3]]);
                            let uid = i32::from_ne_bytes([fg_buf[4], fg_buf[5], fg_buf[6], fg_buf[7]]);
                            // CPU: 表命中 且 冷(新 pid) → 发包名给 cpuset 线程; 热跳过
                            if let Some(pkg) = cpu_uid.get(&uid) {
                                let cold = cpu_known.get(&uid).map_or(true, |&p| p != pid);
                                cpu_known.insert(uid, pid);
                                if cold {
                                    if let Some(tx) = crate::cpu_affinity::cpu_fg_tx() {
                                        let _ = tx.send(crate::cpu_affinity::CpuMsg::ApplyPkg(
                                            uid,
                                            pkg.clone(),
                                        ));
                                    }
                                }
                            } else {
                            }
                            // 刷新率: 表命中 → 发包名给刷新率线程
                            if let Some(pkg) = rfr_uid.get(&uid) {
                                crate::refresh::refresh_send_fg_pkg(pkg.clone());
                            }
                        }
                    }
                }
                EV_INOTIFY => {
                    // 配置变更 (inotify): 与 EV_CONFIG 共用 reload_config
                    if crate::config::inotify_drain() {
                        reload_config(
                            &mut ebpf_state,
                            &mut proc_state,
                            &mut cfg,
                            &mut cpu_uid,
                            &mut rfr_uid,
                            &mut cpu_pkgs_set,
                            &mut rfr_pkgs_set,
                        );
                    }
                }
                EV_MODE => {
                    read_eventfd(mode_switch_fd);
                    let mode = MODE_FORCE.load(Ordering::Relaxed);
                    if mode == 2 {
                        // 强制 /proc: 卸载 eBPF
                        if ebpf_state.take().is_some() {
                            force_proc_rescan(&mut proc_state);
                        }
                    } else if ebpf_state.is_none() {
                        // 自动/强制 KPM: 尝试初始化
                        if let Some(mut es) = ebpf_init(kpm_wake_fd) {
                            if let Some(cfg) = cfg.as_ref() {
                                full_scan(cfg, &mut es);
                            }
                            ebpf_state = Some(es);
                            if cpu_ready {
                                crate::cpu_affinity::apply_all_now();
                            }
                        }
                    } else {
                        // 已在 KPM 模式: 重新应用配置 (规则应用集合可能变化)
                        apply_config(true, &mut ebpf_state, &mut proc_state, cfg.as_deref());
                        if let Some(cfg) = cfg.as_ref() {
                            rebuild_uid_if_needed(true, cfg, &mut cpu_uid, &mut rfr_uid, &mut cpu_pkgs_set, &mut rfr_pkgs_set);
                        }
                    }
                }
                EV_CONFIG => {
                    read_eventfd(config_wake_fd);
                    // 配置变更 (eventfd 主动唤醒): 与 EV_INOTIFY 共用 reload_config
                    reload_config(
                        &mut ebpf_state,
                        &mut proc_state,
                        &mut cfg,
                        &mut cpu_uid,
                        &mut rfr_uid,
                        &mut cpu_pkgs_set,
                        &mut rfr_pkgs_set,
                    );
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
            let (threads, hit_pkgs, hit_list) = match (&ebpf_state, &proc_state) {
                (Some(_), _) => crate::cpu_affinity::cpu_stats(),
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

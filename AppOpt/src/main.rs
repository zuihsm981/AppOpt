#![cfg(any(target_os = "linux", target_os = "android"))]
#[cfg(target_pointer_width = "32")]
compile_error!("AppOpt requires 64-bit target due to cpu_set_t binary layout assumptions");

mod apply_affinity;
mod cpu_affinity;
mod config;
mod cpuset;
mod ebpf_mode;
mod process_observer;
mod refresh;
mod rule_edit;
mod rule_match;
mod touch_probe;
mod exit_probe;
mod web;

use std::collections::{HashMap, HashSet};
use std::env;
use std::ffi::CString;
use std::fs;
use std::process;
use std::sync::atomic::Ordering;
use std::sync::{mpsc, Arc, Mutex, RwLock};

use crate::config::{
    init_inotify, load_config, AppConfig,
    CONFIG_FILE, CONFIG_WAKE_FD, CURRENT_CONFIG,
};
use crate::cpuset::{init_cpu_topo, set_base_cpuset};
use crate::ebpf_mode::{
    event_dispatch, ebpf_init, EbpfState,
};
use crate::web::{
    settings_load, settings_save, web_start, SETTINGS_FILE,
};

pub const MAX_PKG_LEN: usize = 128;
pub const MAX_THREAD_LEN: usize = 32;

pub(crate) fn lock_ignore_poison<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

/// 高频只读数据的读锁 (RwLock): 多线程并发读不互斥, 写方独占
pub(crate) fn rw_read_ignore_poison<T>(rw: &RwLock<T>) -> std::sync::RwLockReadGuard<'_, T> {
    rw.read().unwrap_or_else(|e| e.into_inner())
}

/// 高频只读数据的写锁 (RwLock): 独占写
pub(crate) fn rw_write_ignore_poison<T>(rw: &RwLock<T>) -> std::sync::RwLockWriteGuard<'_, T> {
    rw.write().unwrap_or_else(|e| e.into_inner())
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
    println!("  -c <config_file>   指定统一配置文件 (默认: ./applist.conf)");
    println!("  -b <cpuset_name>   指定 BASE_CPUSET 目录名 (默认: AppOpt)");
    println!("  -w                 启用网页前端 (仅本机 127.0.0.1:8889)");
    println!("  -v                 显示程序版本");
    println!("  -h                 显示帮助信息");
    println!();
    println!("示例:");
    println!("  {} -c /data/applist.conf", prog_name);
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
    let (mut cli_cfg, mut cli_cpuset, mut cli_web) = (None, None, false);

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

    // 应用设置 (AppOpt.json) 提前读取: 驱动模式需在 L1 ebpf_init spawn 前决定
    let st = settings_load(SETTINGS_FILE);
    let drive_mode = st.mode.clone();
    crate::web::set_drive_mode(&drive_mode);

    // ================= 初始化并发: 独立无依赖项并行 =================
    // T1: /proc pid 快照线程 (最早抓取启动瞬间 pid; 完成后线程退出)
    let snapshot_thread = std::thread::spawn(|| crate::cpu_affinity::proc_pid_set());

    // 提前创建 fd (不依赖 settings; 供各独立线程使用)
    let kpm_wake_fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
    // T6: 用户态触摸/输入活动探测线程 (root 读 /dev/input/event*, 事件驱动通知;
    //      4.19 上替代不可用的内核 input hook; 6.6 亦可作兜底)
    let mut touch_sv: [libc::c_int; 2] = [0, 0];
    let touch_ok = unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_DGRAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
            touch_sv.as_mut_ptr(),
        )
    } == 0;
    // 触摸监听控制 socket: refresh 线程按 timer_enabled 暂停/恢复 event5 监听
    let mut touch_ctrl: [libc::c_int; 2] = [0, 0];
    let touch_ctrl_ok = unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_DGRAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
            touch_ctrl.as_mut_ptr(),
        )
    } == 0;
    if touch_ok && touch_ctrl_ok {
        let tw = touch_sv[1];
        let cw = touch_ctrl[1];
        crate::touch_probe::set_ctrl_fd(cw);   // 写端供 set_enabled 使用
        let cr = touch_ctrl[0];
        std::thread::spawn(move || crate::touch_probe::spawn_touch(tw, cr));
    }
    // T7: 用户态进程退出监听 (4.19 用户态模式, 替代内核 EXIT; 仅主 pid 注册)
    let mut exit_sv: [libc::c_int; 2] = [0, 0];
    let exit_ok = unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_DGRAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
            exit_sv.as_mut_ptr(),
        )
    } == 0;
    if exit_ok {
        let ew = exit_sv[1];
        std::thread::spawn(move || crate::exit_probe::spawn_exit(ew));
    }
    let mut fg_sv: [libc::c_int; 2] = [0, 0];
    let socket_ok = unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_DGRAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
            fg_sv.as_mut_ptr(),
        )
    } == 0;
    if socket_ok {
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
    }

    // T2: ebpf_init (按驱动模式尝试 KPM: userspace 直退 / auto 快速回退 / kpm 等待)
    let wk = kpm_wake_fd;
    let dm = drive_mode.clone();
    let ebpf_thread = std::thread::spawn(move || ebpf_init(wk, dm));

    // T3: process_observer (binder 回调注册; 完成后线程退出)
    let obs_fd = fg_sv[1];
    let observer_thread = std::thread::spawn(move || {
        if socket_ok {
            crate::process_observer::init_observer(obs_fd);
        }
    });

    // T4: packages.list inotify (返回 fd; 完成后线程退出)
    let pkg_inotify_thread = std::thread::spawn(crate::config::init_pkg_inotify);

    // T5: dumpsys display 显示模式解析 (供 refresh_init; 完成后线程退出)
    let display_modes_thread = std::thread::spawn(crate::refresh::parse_display_modes);

    // 命令行参数优先覆盖设置 (settings_load 已在 L1 前完成)
    let config_file = cli_cfg.unwrap_or(st.config_file);
    let cpuset_name = cli_cpuset.unwrap_or(st.cpuset_name);
    let web_enable = cli_web || st.web_enable;

    // 先设置 cpuset 路径再初始化拓扑，init_cpu_topo 会创建 BASE_CPUSET 目录
    set_base_cpuset(&cpuset_name);
    let topo = init_cpu_topo();

    if fs::metadata(&config_file).is_err() {
        // 头注释两行; refresh_* 由设备可用刷新率解析后写入这两行下面
        let initial_content = "# 规则编写与使用说明请参考 http://AppOpt.suto.top\n# 刷新率字段与 CPU 规则共用此文件\n";
        let _ = fs::write(&config_file, initial_content);
    }
    // 兼容旧版本：将 refresh_config.conf 内容一次性并入当前主配置文件。
    // 迁移完成后刷新率模块不再依赖该独立文件。
    crate::config::migrate_legacy_refresh_config(&config_file);

    {
        let mut guard = lock_ignore_poison(&CONFIG_FILE);
        *guard = config_file.clone();
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
        let mut guard = rw_write_ignore_poison(&CURRENT_CONFIG);
        *guard = Some(Arc::new(initial_config));
    }

    init_inotify(&config_file);

    if web_enable {
        web_start();
    }
    // 落盘当前设置 (含旧默认配置名迁移后的 config_file)，重启后保持一致
    settings_save();

    // ===== join 各独立线程 (事件循环/使用点前就绪) =====
    let init_pids = snapshot_thread.join().unwrap_or_default();
    let marked = crate::cpu_affinity::classify_marked_pids(&init_pids);
    // ebpf_init 线程: KPM 加载+激活已并行完成, join 拿 EbpfState
    let mut ebpf_state: Option<EbpfState> = ebpf_thread.join().ok().flatten();
    if ebpf_state.is_some() {
        crate::web::KPM_ACTIVE.store(true, Ordering::Relaxed);
    }
    // T4: packages.list inotify fd
    let pkg_inotify_fd = pkg_inotify_thread.join().unwrap_or(-1);
    // T3: observer 注册完成
    let _ = observer_thread.join();
    let fg_recv_fd = fg_sv[0];
    let mut fg_buf = [0u8; 8];

    let cpu_ready = crate::cpu_affinity::start(init_pids, marked);

    // 刷新率控制模块，独立线程运行 (binder 回调经主线程 uid 表 → FgPkg 消息驱动)
    refresh::refresh_init(display_modes_thread);
    // uid 静态表 (主线程): CPU 表 = 有 CPU 规则应用; 刷新率表 = launcher + 规则应用
    let mut cpu_uid: HashMap<i32, String> = HashMap::new();
    let mut rfr_uid: HashMap<i32, String> = HashMap::new();
    // 规则应用集合 (主线程对比用): 仅集合变化才重建 uid 表 (数值调整不重建)
    let mut cpu_pkgs_set: HashSet<String> = HashSet::new();
    let mut rfr_pkgs_set: HashSet<String> = HashSet::new();
    if let Some(cfg) = rw_read_ignore_poison(&CURRENT_CONFIG).clone() {
        (cpu_uid, rfr_uid) = build_uid_tables(&cfg);
        (cpu_pkgs_set, rfr_pkgs_set) = cfg_pkg_sets(&cfg);
    }

    let _ = crate::web::START.get_or_init(|| std::time::Instant::now());

    // ================= 纯事件驱动主循环 =================
    // 事件源: KPM 事件唤醒 eventfd / inotify / 配置重载 eventfd / binder 前台回调
    //         / packages.list inotify (仅 KPM 模式)
    const EV_KPM: u64 = 1;
    const EV_INOTIFY: u64 = 2;
    const EV_CONFIG: u64 = 4;
    const EV_FG: u64 = 6; // binder 前台回调 (pid+uid), 主线程分发
    const EV_PKG: u64 = 7; // packages.list inotify (安装/卸载/替换)
    const EV_TOUCH: u64 = 8; // 用户态 /dev/input 触摸/输入活动 (替代 4.19 内核 input hook)
    const EV_EXIT_PID: u64 = 9; // 用户态 pidfd//proc 进程退出监听 (4.19 替代内核 EXIT)

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
    // 配置变更后应用到当前模式 (仅 KPM): 全量扫描 + uid 表重建(规则包集合门控)
    fn apply_config(
        cpu_changed: bool,
        ebpf_state: &mut Option<EbpfState>,
        cfg: Option<&crate::config::AppConfig>,
    ) {
        let Some(cfg) = cfg else { return };
        // CPU 规则未变 (仅刷新率/数值调整): 无需全量扫描, 亲和性/uid 表不需重放
        if !cpu_changed {
            return;
        }
        if let Some(es) = ebpf_state.as_mut() {
            kpm_full_apply(cfg, es);
        }
    }

    /// KPM 全量归因扫描 + 亲和性全量应用 (配置变更/重连共用)
    fn kpm_full_apply(_cfg: &crate::config::AppConfig, _es: &mut EbpfState) {
        // 规则编辑保存路径: 只对最近变更包单包重放亲和性 (避免改一个应用 →
        // apply_all_now 全量重放所有规则应用); 启动/整体重载等无变更包 → 全量。
        // 按编辑粒度重放: 单线程编辑 → 只重放该线程; 整包编辑 → 只重放该包;
        // 无记录 (启动/整体重载) → 全量
        match crate::web::last_rule_take() {
            Some((pkg, Some(thread))) => {
                if let Some(tx) = crate::cpu_affinity::cpu_fg_tx() {
                    let _ = tx.send(crate::cpu_affinity::CpuMsg::ApplyThread(pkg, thread));
                }
            }
            Some((pkg, None)) => {
                if let Some(tx) = crate::cpu_affinity::cpu_fg_tx() {
                    let _ = tx.send(crate::cpu_affinity::CpuMsg::ApplyPkgByName(pkg));
                }
            }
            None => crate::cpu_affinity::apply_all_now(),
        }
    }

    /// uid 表重建: 按 cpu_changed/包集合变化决定 (reload_config 共用)
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
    // (kpm_wake_fd 已在初始化并发段创建)
    epoll_add(epfd, kpm_wake_fd, EV_KPM);
    // 配置重载 eventfd: web 端写配置/规则后由 config_reload_now 写入
    let config_wake_fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
    CONFIG_WAKE_FD.store(config_wake_fd, Ordering::Relaxed);
    epoll_add(epfd, config_wake_fd, EV_CONFIG);
    // inotify fd: 配置文件修改
    let inotify_fd = crate::config::INOTIFY_FD.load(Ordering::Acquire);
    epoll_add(epfd, inotify_fd, EV_INOTIFY);
    if fg_recv_fd > 0 {
        epoll_add(epfd, fg_recv_fd, EV_FG);
    }
    if touch_ok {
        epoll_add(epfd, touch_sv[0], EV_TOUCH);
    }
    if exit_ok {
        epoll_add(epfd, exit_sv[0], EV_EXIT_PID);
    }


    // packages.list inotify: 应用安装/卸载/替换 → 重建 uid 表 (fd 由并发 T4 线程建立;
    // pkglist_path 保留供 EV_PKG 重挂 watch 用)
    let pkglist_path = CString::new("/data/system/packages.list").unwrap_or_default();
    epoll_add(epfd, pkg_inotify_fd, EV_PKG);

    // 初始全量应用 (两种驱动模式都执行: KPM 事件驱动 / 纯用户态)
    // 刷新率全局初始 active 已由 refresh_init 应用; launcher 前台由 FgPkg 包名驱动。
    if cpu_ready {
        crate::cpu_affinity::apply_all_now();
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

        let mut cfg = rw_read_ignore_poison(&CURRENT_CONFIG).clone();
        let mut kpm_died = false;

    // 配置事件 (EV_INOTIFY / EV_CONFIG) 公共处理: 重载配置 → 应用到当前模式 →
    // 仅“规则应用集合”变更时重建 uid 表 (调整数值不重建)
    let reload_config = |ebpf_state: &mut Option<EbpfState>,
                         cfg: &mut Option<Arc<AppConfig>>,
                         cpu_uid: &mut HashMap<i32, String>,
                         rfr_uid: &mut HashMap<i32, String>,
                         cpu_pkgs_set: &mut HashSet<String>,
                         rfr_pkgs_set: &mut HashSet<String>| {
        let cpu_changed = crate::config::take_cpu_rules_changed();
        *cfg = rw_read_ignore_poison(&CURRENT_CONFIG).clone();
        apply_config(cpu_changed, ebpf_state, cfg.as_deref());
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
                                        rw_read_ignore_poison(&CURRENT_CONFIG).clone()
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
                            // CPU: 表命中 → 冷热判断 (cpu_known 中 uid+pid 一致=热);
                            // 冷 → 只发 (pid+uid+包名); 身份清除由 EXIT 事件驱动
                            if let Some(pkg) = cpu_uid.get(&uid) {
                                // 冷启动不再清除 pid 列表/cpu_known —— 身份清除改由
                                // EXIT 事件驱动 (ebpf_mode::event_dispatch); 冷时仅重发
                                // ApplyPkg, CPU 线程枚举后覆盖写回新身份
                                if !crate::cpu_affinity::cpu_known_is_hot(uid, pid) {
                                    // 身份记录/枚举/亲和性统一经 ApplyPkg → CPU worker 回写
                                    // CPU_KNOWN(uid,(主pid,全部pids))。用户态退出监听仅 4.19
                                    // (KPM 模式由内核 EXIT 驱动)。
                                    if !crate::web::KPM_ACTIVE.load(std::sync::atomic::Ordering::Relaxed) {
                                        crate::exit_probe::watch(pid);
                                    }
                                    if let Some(tx) = crate::cpu_affinity::cpu_fg_tx() {
                                        let _ = tx.send(crate::cpu_affinity::CpuMsg::ApplyPkg(
                                            pid,
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
                EV_TOUCH => {
                    // 用户态触摸/输入活动: recv 触发设备索引 → 日志 → 重置刷新率空闲
                    if touch_ok && touch_sv[0] > 0 {
                        let mut tb = [0u8; 4];
                        let n = unsafe {
                            libc::recv(
                                touch_sv[0],
                                tb.as_mut_ptr() as *mut libc::c_void,
                                4,
                                0,
                            )
                        };
                        if n == 4 {
                            let _idx = i32::from_ne_bytes([tb[0], tb[1], tb[2], tb[3]]);
                        }
                    }
                    crate::refresh::refresh_on_event(crate::refresh::EVENT_INPUT, 0);
                }
                EV_EXIT_PID => {
                    // 用户态进程退出 (4.19): recv pid → 清理该 uid 身份
                    if exit_ok && exit_sv[0] > 0 {
                        let mut pb = [0u8; 4];
                        let n = unsafe {
                            libc::recv(exit_sv[0], pb.as_mut_ptr() as *mut libc::c_void, 4, 0)
                        };
                        if n == 4 {
                            let pid = i32::from_ne_bytes([pb[0], pb[1], pb[2], pb[3]]);
                            // 清身份 + 通知 CPU worker 清该 uid managed → 发布统计
                            // (webui 命中应用/绑定线程归零, 与 KPM EXIT 同效果)
                            if let Some(uid) = crate::cpu_affinity::cpu_known_evict_by_pid(pid) {
                                if let Some(tx) = crate::cpu_affinity::cpu_fg_tx() {
                                    let _ = tx.send(crate::cpu_affinity::CpuMsg::EvictUid(uid));
                                }
                            }
                        }
                    }
                }
                EV_INOTIFY => {
                    // 配置变更 (inotify): 与 EV_CONFIG 共用 reload_config
                    if crate::config::inotify_drain() {
                        reload_config(
                            &mut ebpf_state,
                            &mut cfg,
                            &mut cpu_uid,
                            &mut rfr_uid,
                            &mut cpu_pkgs_set,
                            &mut rfr_pkgs_set,
                        );
                    }
                }
                EV_CONFIG => {
                    read_eventfd(config_wake_fd);
                    // 配置变更 (eventfd 主动唤醒): 与 EV_INOTIFY 共用 reload_config
                    reload_config(
                        &mut ebpf_state,
                        &mut cfg,
                        &mut cpu_uid,
                        &mut rfr_uid,
                        &mut cpu_pkgs_set,
                        &mut rfr_pkgs_set,
                    );
                }
                _ => {}
            }
        }

        // KPM 通道断开: 标记断开并尝试重新初始化 (仅 KPM 模式, 无 /proc 回退)
        if kpm_died {
            ebpf_state = None;
            crate::web::KPM_ACTIVE.store(false, Ordering::Relaxed);
            if let Some(es) = ebpf_init(kpm_wake_fd, drive_mode.clone()) {
                crate::web::KPM_ACTIVE.store(true, Ordering::Relaxed);
                ebpf_state = Some(es);
                if cpu_ready {
                    crate::cpu_affinity::apply_all_now();
                }
            }
        }

    }

    unsafe { libc::close(epfd) };
}

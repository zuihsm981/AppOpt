//! IProcessObserver binder 回调实现（dlopen 运行时加载 libbinder_ndk.so）
//!
//! 触发分离/数据共享（参考 优化.md）：
//! Binder 回调提取 pid+uid, 经 socketpair(SOCK_DGRAM) 发送 8 字节 (pid+uid);
//! 主线程据此查 uid 静态表并分发 CPU(按 uid 取该应用全部进程)/刷新率(按包)线程。

use std::ffi::c_void;
use std::sync::{OnceLock};
use std::sync::atomic::{AtomicI32, Ordering};
use libc::{c_char, c_int, dlopen, dlsym, RTLD_LAZY};

// ── 硬编码事务码 ──
const TX_REGISTER_PROCESS_OBSERVER: u32 = 0x0d;
const TX_ON_PROCESS_STARTED: u32 = 0x01;
const TX_ON_FG_ACTIVITIES_CHANGED: u32 = 0x02;
const TX_ON_FG_SERVICES_CHANGED: u32 = 0x03;

// ── FFI 函数指针类型 ──
type FnGetService = unsafe extern "C" fn(*const c_char) -> *mut c_void;
type FnClassDefine = unsafe extern "C" fn(
    *const c_char,
    Option<extern "C" fn(*mut c_void) -> *mut c_void>,
    Option<extern "C" fn(*mut c_void)>,
    Option<extern "C" fn(*mut c_void, u32, *mut c_void, *mut c_void) -> c_int>,
) -> *mut c_void;
type FnBinderNew = unsafe extern "C" fn(*mut c_void, *mut c_void) -> *mut c_void;
type FnPrepareTx = unsafe extern "C" fn(*mut c_void, *mut *mut c_void) -> c_int;
type FnTransact = unsafe extern "C" fn(
    *mut c_void,       // binder
    u32,               // code
    *mut *mut c_void,  // in parcel (AParcel** — transact 会消费并置 null)
    *mut *mut c_void,  // out parcel (AParcel**)
    u32,               // flags
) -> c_int;
type FnParcelDelete = unsafe extern "C" fn(*mut c_void);
type FnWriteBinder = unsafe extern "C" fn(*mut c_void, *mut c_void) -> c_int;
type FnReadI32 = unsafe extern "C" fn(*mut c_void, *mut i32) -> bool;
type FnWriteI32 = unsafe extern "C" fn(*mut c_void, i32) -> c_int;
type FnReadByte = unsafe extern "C" fn(*mut c_void, *mut i8) -> bool;
type FnGetDataSize = unsafe extern "C" fn(*mut c_void) -> usize;
type FnJoinThreadPool = unsafe extern "C" fn();
type FnStartThreadPool = unsafe extern "C" fn();
type FnAssociateClass = unsafe extern "C" fn(*mut c_void, *const c_void) -> bool;

struct BinderNdk {
    get_service: FnGetService,
    class_define: FnClassDefine,
    binder_new: FnBinderNew,
    prepare_tx: FnPrepareTx,
    transact: FnTransact,
    parcel_delete: FnParcelDelete,
    write_binder: FnWriteBinder,
    write_int32: FnWriteI32,
    read_i32: FnReadI32,
    read_byte: FnReadByte,
    get_data_size: FnGetDataSize,
    join_thread_pool: FnJoinThreadPool,
    start_thread_pool: FnStartThreadPool,
    associate_class: FnAssociateClass,
}

static BINDER_NDK: OnceLock<Option<BinderNdk>> = OnceLock::new();

fn ndk() -> Option<&'static BinderNdk> {
    BINDER_NDK.get_or_init(|| unsafe {
        // RTLD_LOCAL: 避免 libbinder_ndk 符号污染进程全局符号空间 (标准做法)
        let lib = dlopen(b"libbinder_ndk.so\0".as_ptr() as *const c_char, RTLD_LAZY | libc::RTLD_LOCAL);
        if lib.is_null() { return None; }

        let sym = |name: &str| -> *mut c_void {
            let c = std::ffi::CString::new(name).unwrap();
            dlsym(lib, c.as_ptr())
        };

        let p_get_service = sym("AServiceManager_getService");
        let p_class_define = sym("AIBinder_Class_define");
        let p_binder_new = sym("AIBinder_new");
        let p_prepare_tx = sym("AIBinder_prepareTransaction");
        let p_transact = sym("AIBinder_transact");
        let p_parcel_delete = sym("AParcel_delete");
        let p_write_binder = sym("AParcel_writeStrongBinder");
        let p_write_i32 = sym("AParcel_writeInt32");
        let p_read_i32 = sym("AParcel_readInt32");
        let p_read_byte = sym("AParcel_readByte");
        let p_get_data_size = sym("AParcel_getDataSize");
        let p_join = sym("ABinderProcess_joinThreadPool");
        let p_start = sym("ABinderProcess_startThreadPool");
        let p_associate = sym("AIBinder_associateClass");
        if p_get_service.is_null() || p_class_define.is_null() || p_binder_new.is_null()
            || p_prepare_tx.is_null() || p_transact.is_null() || p_parcel_delete.is_null()
            || p_write_binder.is_null() || p_write_i32.is_null()
            || p_read_i32.is_null() || p_read_byte.is_null() || p_get_data_size.is_null()
            || p_join.is_null() || p_start.is_null() || p_associate.is_null()
        { return None; }
        
        Some(BinderNdk {
            get_service: std::mem::transmute(p_get_service),
            class_define: std::mem::transmute(p_class_define),
            binder_new: std::mem::transmute(p_binder_new),
            prepare_tx: std::mem::transmute(p_prepare_tx),
            transact: std::mem::transmute(p_transact),
            parcel_delete: std::mem::transmute(p_parcel_delete),
            write_binder: std::mem::transmute(p_write_binder),
            write_int32: std::mem::transmute(p_write_i32),
            read_i32: std::mem::transmute(p_read_i32),
            read_byte: std::mem::transmute(p_read_byte),
            get_data_size: std::mem::transmute(p_get_data_size),
            join_thread_pool: std::mem::transmute(p_join),
            start_thread_pool: std::mem::transmute(p_start),
            associate_class: std::mem::transmute(p_associate),
        })
    }).as_ref()
}

const STATUS_OK: c_int = 0;
const STATUS_UNKNOWN_TRANSACTION: c_int = -29;

// fg 事件经 socketpair(SOCK_DGRAM) 传递 pid+uid (8 字节); 主线程 EV_FG 分发
static FG_SEND_FD: AtomicI32 = AtomicI32::new(-1);

struct SendClass(*mut c_void);
unsafe impl Send for SendClass {}
unsafe impl Sync for SendClass {}
static OBSERVER_CLASS: OnceLock<SendClass> = OnceLock::new();
static AM_CLASS: OnceLock<SendClass> = OnceLock::new();
static ATM_CLASS: OnceLock<SendClass> = OnceLock::new();
// SurfaceFlinger 的 ISurfaceComposer 描述符：
// ISurfaceComposer.h 中 DECLARE_META_INTERFACE(SurfaceComposer) →
// IMPLEMENT_META_INTERFACE(SurfaceComposer, "android.ui.ISurfaceComposer")，
// 即旧版 C++ binder 接口注册的就是 android.ui.ISurfaceComposer
static SF_CLASS: OnceLock<SendClass> = OnceLock::new();

extern "C" fn on_create(_args: *mut c_void) -> *mut c_void { std::ptr::null_mut() }
extern "C" fn on_destroy(_user_data: *mut c_void) {}
extern "C" fn am_dummy_on_transact(_b: *mut c_void, _c: u32, _i: *mut c_void, _o: *mut c_void) -> c_int { STATUS_UNKNOWN_TRANSACTION }

/// onTransact 回调
extern "C" fn on_transact(
    _binder: *mut c_void,
    code: u32,
    in_parcel: *mut c_void,
    _out: *mut c_void,
) -> c_int {
    let Some(ndk) = ndk() else { return STATUS_UNKNOWN_TRANSACTION };

    // NDK 的 AIBinder_onTransact 内部已通过 checkInterface() 读取了 Interface Token
    // (strict_mode i32 + UTF-16 descriptor)，且不重置 parcel 位置
    // 因此这里直接从事务数据开始读取，不再重复读 token

    match code {
        TX_ON_PROCESS_STARTED => {
            // 本事务不携带有效负载; 即使协议变体带参数, 每次 onTransact 也是独立
            // parcel (无跨事务位置状态), oneway 无 reply —— 漏读不影响后续
            STATUS_OK
        }
        TX_ON_FG_ACTIVITIES_CHANGED => {
            let mut pid = 0i32;
            let mut uid = 0i32;
            let mut fg_val = 0i32;

            let _ = unsafe { (ndk.read_i32)(in_parcel, &mut pid) };
            let _ = unsafe { (ndk.read_i32)(in_parcel, &mut uid) };
            let _ = unsafe { (ndk.read_i32)(in_parcel, &mut fg_val) };

            // 临时诊断: 记录所有前台回调 (含 started=false) 到文件,
            // 验证"按最近键→返回原应用"时是否产生回调 / 哪些回调
            if pid > 0 {
                let line = format!("pid={} uid={} fg={}\n", pid, uid, fg_val != 0);
                if let Ok(mut f) = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open("/data/local/tmp/appopt_fg_cb.txt")
                {
                    use std::io::Write;
                    let _ = f.write_all(line.as_bytes());
                }
            }

            let fg = fg_val != 0;

            if fg && pid > 0 {
                // 触发分离：Binder 回调携带 pid + uid（8 字节）。
                // 刷新率按 pid 解析包名; CPU 亲和性按 uid 取该应用全部进程
                let fd = FG_SEND_FD.load(Ordering::Acquire);
                if fd >= 0 {
                    let pkt = [pid, uid];
                    let _ = unsafe {
                        libc::send(fd, pkt.as_ptr() as *const libc::c_void, 8, 0)
                    };
                }
            }
            STATUS_OK
        }
        TX_ON_FG_SERVICES_CHANGED => {
            let mut _pid = 0i32; let mut _uid = 0i32; let mut _st = 0i32;
            let _ = unsafe { (ndk.read_i32)(in_parcel, &mut _pid) };
            let _ = unsafe { (ndk.read_i32)(in_parcel, &mut _uid) };
            let _ = unsafe { (ndk.read_i32)(in_parcel, &mut _st) };
            STATUS_OK
        }
        _ => { STATUS_UNKNOWN_TRANSACTION }
    }
}

fn get_observer_class() -> *mut c_void {
    let Some(ndk) = ndk() else { return std::ptr::null_mut() };
    OBSERVER_CLASS.get_or_init(|| {
        let class = unsafe {
            (ndk.class_define)(
                b"android.app.IProcessObserver\0".as_ptr() as *const c_char,
                Some(on_create), Some(on_destroy), Some(on_transact),
            )
        };
        SendClass(class)
    }).0
}

fn get_am_class() -> *mut c_void {
    let Some(ndk) = ndk() else { return std::ptr::null_mut() };
    AM_CLASS.get_or_init(|| {
        let class = unsafe {
            (ndk.class_define)(
                b"android.app.IActivityManager\0".as_ptr() as *const c_char,
                Some(on_create), Some(on_destroy), Some(am_dummy_on_transact),
            )
        };
        SendClass(class)
    }).0
}

/// IActivityTaskManager 本地 class (供 probe 直连 activity_task 时 associateClass)
fn get_atm_class() -> *mut c_void {
    let Some(ndk) = ndk() else { return std::ptr::null_mut() };
    ATM_CLASS.get_or_init(|| {
        let class = unsafe {
            (ndk.class_define)(
                b"android.app.IActivityTaskManager\0".as_ptr() as *const c_char,
                Some(on_create), Some(on_destroy), Some(am_dummy_on_transact),
            )
        };
        SendClass(class)
    }).0
}

/// SurfaceFlinger 的 ISurfaceComposer class（用于 binder 直连设置刷新率）
fn get_sf_class() -> *mut c_void {
    let Some(ndk) = ndk() else { return std::ptr::null_mut() };
    SF_CLASS.get_or_init(|| {
        let class = unsafe {
            (ndk.class_define)(
                b"android.ui.ISurfaceComposer\0".as_ptr() as *const c_char,
                Some(on_create), Some(on_destroy), Some(am_dummy_on_transact),
            )
        };
        SendClass(class)
    }).0
}

pub fn init_observer(send_fd: i32) -> bool {
    FG_SEND_FD.store(send_fd, Ordering::Release);

    let Some(ndk) = ndk() else { return false };
    let class = get_observer_class();
    if class.is_null() { return false; }

    let observer = unsafe { (ndk.binder_new)(class, std::ptr::null_mut()) };
    if observer.is_null() { return false; }

    let am = unsafe { (ndk.get_service)(b"activity\0".as_ptr() as *const c_char) };
    if am.is_null() { return false; }

    let am_class = get_am_class();
    if am_class.is_null() { return false; }
    if !unsafe { (ndk.associate_class)(am, am_class as *const c_void) } {
        return false;
    }

    let mut in_parcel: *mut c_void = std::ptr::null_mut();
    let prep_status = unsafe { (ndk.prepare_tx)(am, &mut in_parcel) };
    if prep_status != STATUS_OK || in_parcel.is_null() {
        return false;
    }

    let _ = unsafe { (ndk.write_binder)(in_parcel, observer) };

    let mut out_parcel: *mut c_void = std::ptr::null_mut();
    let status = unsafe { (ndk.transact)(am, TX_REGISTER_PROCESS_OBSERVER, &mut in_parcel, &mut out_parcel, 0) };

    // 读取 reply 异常码以排空 parcel（不再输出日志）
    if status == STATUS_OK && !out_parcel.is_null() {
        let mut _exception_code = 0i32;
        let _ = unsafe { (ndk.read_i32)(out_parcel, &mut _exception_code) };
    }

    unsafe { (ndk.parcel_delete)(in_parcel) };
    if !out_parcel.is_null() { unsafe { (ndk.parcel_delete)(out_parcel) }; }

    if status == STATUS_OK {
        let start_fn = ndk.start_thread_pool;
        let join_fn = ndk.join_thread_pool;
        std::thread::spawn(move || {
            unsafe { start_fn(); }
            unsafe { join_fn(); }
        });
        true
    } else {
        false
    }
}

/// binder 直连 SurfaceFlinger 设置刷新率：事务码 1035，一个 int32 参数
/// （替代 `service call SurfaceFlinger 1035 i32 <mode>` 的 fork/exec 子进程方式）
/// 使用 ISurfaceComposer.h 确认的描述符 android.ui.ISurfaceComposer；
/// 失败返回 false，调用方可回退到 service 命令。
pub fn set_refresh_rate_binder(mode: i32) -> bool {
    let Some(ndk) = ndk() else { return false };

    let sf = unsafe { (ndk.get_service)(b"SurfaceFlinger\0".as_ptr() as *const c_char) };
    if sf.is_null() {
        return false;
    }

    let sf_class = get_sf_class();
    if sf_class.is_null() {
        return false;
    }
    if !unsafe { (ndk.associate_class)(sf, sf_class as *const c_void) } {
        return false;
    }

    let mut in_parcel: *mut c_void = std::ptr::null_mut();
    let prep_status = unsafe { (ndk.prepare_tx)(sf, &mut in_parcel) };
    if prep_status != STATUS_OK || in_parcel.is_null() {
        return false;
    }

    // 写入 int32 参数（刷新率模式：0=120Hz, 1=60Hz, 2=90Hz）
    let _ = unsafe { (ndk.write_int32)(in_parcel, mode) };

    let mut out_parcel: *mut c_void = std::ptr::null_mut();
    const TX_SET_REFRESH_RATE: u32 = 1035;
    let status =
        unsafe { (ndk.transact)(sf, TX_SET_REFRESH_RATE, &mut in_parcel, &mut out_parcel, 0) };

    // 检查 reply 异常码：服务端 enforceInterface/参数校验失败时视为失败
    let mut ok = status == STATUS_OK;
    if ok && !out_parcel.is_null() {
        let mut exception_code = 0i32;
        let _ = unsafe { (ndk.read_i32)(out_parcel, &mut exception_code) };
        if exception_code != 0 {
            ok = false;
        }
    }

    unsafe { (ndk.parcel_delete)(in_parcel) };
    if !out_parcel.is_null() {
        unsafe { (ndk.parcel_delete)(out_parcel) };
    }

    ok
}

/// 跳过 parcel 里的一个字符串: 读 int32 长度 (char16 数), null(-1) 无数据,
/// 否则逐字节消费 2×len 字节 (最底层 readByte, 不依赖 readString 的转换/缓冲,
/// 避免 readCharArray 在特定数据下失败导致位置错位)
fn skip_string(ndk: &BinderNdk, p: *mut c_void) -> bool {
    // 长度 (int32) 用 readByte 逐字节读 (小端)。忽略 NDK 返回值
    // (实测读取本身成功, 仅返回值判断不可靠), 靠 len 合理性兜底。
    let mut buf = [0u8; 4];
    let mut b: i8 = 0;
    for i in 0..4 {
        let _ = unsafe { (ndk.read_byte)(p, &mut b) };
        buf[i] = b as u8;
    }
    let len = i32::from_le_bytes(buf);
    if len < 0 {
        return true;   // null 字符串
    }
    if len > 4096 {
        crate::main_dbg(&format!("skip abnormal_len={}", len));
        return false;  // 异常长度 (防死循环)
    }
    let total = (len as usize) * 2;
    let mut i = 0usize;
    while i < total {
        let _ = unsafe { (ndk.read_byte)(p, &mut b) };
        i += 1;
    }
    true
}

/// 临时诊断: dump getFocusedRootTaskInfo 回复 parcel 前 28 个 int32 (定位解析偏移)
pub fn dump_root_task_ints() {
    let Some(ndk) = ndk() else { return };
    let svc = unsafe { (ndk.get_service)(b"activity_task\0".as_ptr() as *const c_char) };
    if svc.is_null() { return; }
    let atm_class = get_atm_class();
    if atm_class.is_null() { return; }
    if !unsafe { (ndk.associate_class)(svc, atm_class as *const c_void) } { return; }
    let mut in_parcel: *mut c_void = std::ptr::null_mut();
    if unsafe { (ndk.prepare_tx)(svc, &mut in_parcel) } != STATUS_OK || in_parcel.is_null() { return; }
    let mut out_parcel: *mut c_void = std::ptr::null_mut();
    let status = unsafe { (ndk.transact)(svc, 32, &mut in_parcel, &mut out_parcel, 0) };
    unsafe { (ndk.parcel_delete)(in_parcel); }
    if status != STATUS_OK || out_parcel.is_null() {
        if !out_parcel.is_null() { unsafe { (ndk.parcel_delete)(out_parcel); } }
        return;
    }
    let p = out_parcel;
    let mut exc = 0i32;
    let _ = unsafe { (ndk.read_i32)(p, &mut exc) };
    let mut obj = 0i32;
    let _ = unsafe { (ndk.read_i32)(p, &mut obj) };
    let mut s = format!("dump exc={} obj={}", exc, obj);
    for i in 0..28 {
        let mut v = 0i32;
        let ok = unsafe { (ndk.read_i32)(p, &mut v) };
        s.push_str(&format!(" [{}]={}ok{}", i, v, ok as i32));
    }
    unsafe { (ndk.parcel_delete)(p); }
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open("/data/local/tmp/appopt_dbg.txt")
    {
        use std::io::Write;
        let _ = f.write_all(s.as_bytes());
        let _ = f.write_all(b"\n");
    }
}

/// 用 readByte 读 4 字节组合成 int32 (小端)。注意: 忽略 NDK 返回值
/// (transmute 后 bool 判断不可靠, 实测读取本身成功), 靠数据合理性兜底。
fn rb_i32(ndk: &BinderNdk, p: *mut c_void) -> i32 {
    let mut buf = [0u8; 4];
    let mut b: i8 = 0;
    for i in 0..4 {
        let _ = unsafe { (ndk.read_byte)(p, &mut b) };
        buf[i] = b as u8;
    }
    i32::from_le_bytes(buf)
}

/// binder 查询: getFocusedRootTaskInfo (事务 0x20=32) 只读 effectiveUid (第 3 字段),
/// 用于"桌面回调时确认聚焦" — 不读 baseIntent/ComponentName, 无崩溃风险。
/// Ok(effectiveUid) = 聚焦任务的有效 uid; Err = 无聚焦/失败。
pub fn query_focused_effective_uid() -> Result<i32, String> {
    let ndk = ndk().ok_or("ndk init failed")?;
    let svc = unsafe { (ndk.get_service)(b"activity_task\0".as_ptr() as *const c_char) };
    if svc.is_null() {
        return Err("get_service(activity_task) returned null".into());
    }
    let atm_class = get_atm_class();
    if atm_class.is_null() {
        return Err("atm class define failed".into());
    }
    if !unsafe { (ndk.associate_class)(svc, atm_class as *const c_void) } {
        return Err("associate_class failed (descriptor mismatch?)".into());
    }
    let mut in_parcel: *mut c_void = std::ptr::null_mut();
    let prep = unsafe { (ndk.prepare_tx)(svc, &mut in_parcel) };
    if prep != STATUS_OK || in_parcel.is_null() {
        return Err(format!("prepare_tx status={}", prep));
    }
    let mut out_parcel: *mut c_void = std::ptr::null_mut();
    let status = unsafe { (ndk.transact)(svc, 32, &mut in_parcel, &mut out_parcel, 0) };
    unsafe { (ndk.parcel_delete)(in_parcel); }
    if status != STATUS_OK || out_parcel.is_null() {
        let null_out = out_parcel.is_null();
        if !out_parcel.is_null() {
            unsafe { (ndk.parcel_delete)(out_parcel); }
        }
        return Err(format!("transact status={} out_null={}", status, null_out));
    }
    let p = out_parcel;
    let mut log = String::from("q");
    let dsz = unsafe { (ndk.get_data_size)(p) };
    log.push_str(&format!(" dsz={}", dsz));
    let exc = rb_i32(&ndk, p);
    log.push_str(&format!(" exc={}", exc));
    if exc != 0 {
        unsafe { (ndk.parcel_delete)(p); }
        crate::main_dbg(&log);
        return Err(format!("reply exception={}", exc));
    }
    let obj_flag = rb_i32(&ndk, p);
    log.push_str(&format!(" obj={}", obj_flag));
    if obj_flag == 0 {
        unsafe { (ndk.parcel_delete)(p); }
        crate::main_dbg(&log);
        return Err("no focused root task".into());
    }
    let b0 = rb_i32(&ndk, p);
    log.push_str(&format!(" b0={}", b0));
    if b0 != 0 {
        for _ in 0..4 {
            let v = rb_i32(&ndk, p);
            log.push_str(&format!(" r={}", v));
        }
    }
    let ids_len = rb_i32(&ndk, p);
    log.push_str(&format!(" ids={}", ids_len));
    for _ in 0..ids_len.max(0).min(128) {
        let v = rb_i32(&ndk, p);
        log.push_str(&format!(" ids0={}", v));
    }
    let names_len = rb_i32(&ndk, p);
    log.push_str(&format!(" names={}", names_len));
    let mut str_fail = 0i32;
    for _ in 0..names_len.max(0).min(128) {
        if !skip_string(&ndk, p) {
            str_fail += 1;
        }
    }
    let barr_len = rb_i32(&ndk, p);
    log.push_str(&format!(" barr={}", barr_len));
    for _ in 0..barr_len.max(0).min(128) {
        let v = rb_i32(&ndk, p);
        log.push_str(&format!(" b0={}", v));
        for _ in 0..4 {
            let v = rb_i32(&ndk, p);
            log.push_str(&format!(" br={}", v));
        }
    }
    let uids_len = rb_i32(&ndk, p);
    log.push_str(&format!(" uids={}", uids_len));
    for _ in 0..uids_len.max(0).min(128) {
        let v = rb_i32(&ndk, p);
        log.push_str(&format!(" uid0={}", v));
    }
    let vis = rb_i32(&ndk, p);
    log.push_str(&format!(" vis={}", vis));
    let pos = rb_i32(&ndk, p);
    log.push_str(&format!(" pos={}", pos));
    let user_id = rb_i32(&ndk, p);
    log.push_str(&format!(" uidf={}", user_id));
    let task_id = rb_i32(&ndk, p);
    log.push_str(&format!(" tid={}", task_id));
    let eff_uid = rb_i32(&ndk, p);
    log.push_str(&format!(" eff={}", eff_uid));
    unsafe { (ndk.parcel_delete)(p); }
    // 临时诊断: 完整读取序列 + 解析结果
    crate::main_dbg(&format!(
        "{} | ids={} names={} barr={} uids={} sf={} | u={} t={} e={}",
        log, ids_len, names_len, barr_len, uids_len, str_fail, user_id, task_id, eff_uid
    ));
    Ok(eff_uid)
}

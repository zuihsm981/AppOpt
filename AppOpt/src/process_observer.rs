//! ITaskStackListener binder 回调实现（dlopen 运行时加载 libbinder_ndk.so）
//!
//! 触发分离/数据共享（参考 优化.md）：
//! Binder 回调 onTaskMovedToFront 解析 RunningTaskInfo 的 effectiveUid,
//! 经 socketpair(SOCK_DGRAM) 发送 4 字节 uid; 主线程 EV_TASK 统一驱动
//! CPU / 刷新率 / vfc / srv / prop (IProcessObserver on_fg 驱动已移除)。

use std::ffi::c_void;
use std::sync::{OnceLock};
use std::sync::atomic::{AtomicI32, Ordering};
use libc::{c_char, c_int, dlopen, dlsym, RTLD_LAZY};

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
type FnReadI32 = unsafe extern "C" fn(*mut c_void, *mut i32) -> c_int;
type FnWriteI32 = unsafe extern "C" fn(*mut c_void, i32) -> c_int;
type FnGetDataPos = unsafe extern "C" fn(*mut c_void) -> i32;
type FnSetDataPos = unsafe extern "C" fn(*mut c_void, i32) -> c_int;
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
    /* 手动 parcel 解析的游标辅助 (可选; 失败仅影响 0xc/TSL 事件解析,
     * 绝不拖垮 ndk() 核心 —— SF_BINDER 不依赖这两个符号) */
    data_position: Option<FnGetDataPos>,
    set_data_position: Option<FnSetDataPos>,
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
        let p_get_data_pos = sym("AParcel_getDataPosition");
        let p_set_data_pos = sym("AParcel_setDataPosition");
        let p_join = sym("ABinderProcess_joinThreadPool");
        let p_start = sym("ABinderProcess_startThreadPool");
        let p_associate = sym("AIBinder_associateClass");
        if p_get_service.is_null() || p_class_define.is_null() || p_binder_new.is_null()
            || p_prepare_tx.is_null() || p_transact.is_null() || p_parcel_delete.is_null()
            || p_write_binder.is_null() || p_write_i32.is_null()
            || p_read_i32.is_null()
            || p_join.is_null() || p_start.is_null() || p_associate.is_null()
        { return None; }
        /* 游标辅助为可选: dlsym 失败 → getTasks 解析不可用, 不影响核心 binder 功能 */
        let data_position = if p_get_data_pos.is_null() {
            None
        } else {
            Some(std::mem::transmute::<*mut c_void, FnGetDataPos>(p_get_data_pos))
        };
        let set_data_position = if p_set_data_pos.is_null() {
            None
        } else {
            Some(std::mem::transmute::<*mut c_void, FnSetDataPos>(p_set_data_pos))
        };

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
            data_position,
            set_data_position,
            join_thread_pool: std::mem::transmute(p_join),
            start_thread_pool: std::mem::transmute(p_start),
            associate_class: std::mem::transmute(p_associate),
        })
    }).as_ref()
}

const STATUS_OK: c_int = 0;
const STATUS_UNKNOWN_TRANSACTION: c_int = -29;

struct SendClass(*mut c_void);
unsafe impl Send for SendClass {}
unsafe impl Sync for SendClass {}
static ATM_CLASS: OnceLock<SendClass> = OnceLock::new();
// SurfaceFlinger 的 ISurfaceComposer 描述符：
// ISurfaceComposer.h 中 DECLARE_META_INTERFACE(SurfaceComposer) →
// IMPLEMENT_META_INTERFACE(SurfaceComposer, "android.ui.ISurfaceComposer")，
// 即旧版 C++ binder 接口注册的就是 android.ui.ISurfaceComposer
static SF_CLASS: OnceLock<SendClass> = OnceLock::new();
/// SurfaceFlinger binder 句柄缓存: 只 get_service + associate 一次, 之后直接
/// transact (AIBinder_transact 线程安全; 顺带消除每帧 get_service 的引用泄漏)。
/// 失败不缓存 null → 下次调用重试。refresh 线程串行调用, 无并发争用。
static SF_BINDER: std::sync::LazyLock<std::sync::Mutex<Option<SendClass>>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(None));
// ITaskStackListener 本地 class (任务栈变化事件接收)
static TSL_CLASS: OnceLock<SendClass> = OnceLock::new();
/// TaskStackListener 事件通道写端: 解析出的 effectiveUid → 主线程 EV_TASK
static TASK_SEND_FD: AtomicI32 = AtomicI32::new(-1);
/// onTaskDescriptionChanged(0xc) 事件通道写端 (uid+pkg+comp → 主线程)
static ACTL_SEND_FD: AtomicI32 = AtomicI32::new(-1);
/// 有 activity 规则的应用 uid 集合: 0xc 回调早期过滤 (先于 Intent/Component 解析与投递),
/// 由 main 在 reload/连接时同步; 空集合 = 无规则应用 → 0xc 全忽略
static ACT_RULE_UIDS: std::sync::LazyLock<std::sync::Mutex<std::collections::HashSet<i32>>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashSet::new()));

/// 同步"有 activity 规则的应用 uid"集合 (0xc 早期过滤用)
pub fn sync_act_rule_uids(uids: std::collections::HashSet<i32>) {
    *ACT_RULE_UIDS.lock().unwrap() = uids;
}

/// 设置 0xc 事件通道写端 (main 创建 socketpair 后注入)
pub fn set_actl_fd(fd: i32) {
    ACTL_SEND_FD.store(fd, Ordering::Release);
}

extern "C" fn on_create(_args: *mut c_void) -> *mut c_void { std::ptr::null_mut() }
extern "C" fn on_destroy(_user_data: *mut c_void) {}
extern "C" fn am_dummy_on_transact(_b: *mut c_void, _c: u32, _i: *mut c_void, _o: *mut c_void) -> c_int { STATUS_UNKNOWN_TRANSACTION }

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

/// ITaskStackListener 本地 class (任务栈变化事件接收)
fn get_tsl_class() -> *mut c_void {
    let Some(ndk) = ndk() else { return std::ptr::null_mut() };
    TSL_CLASS.get_or_init(|| {
        let class = unsafe {
            (ndk.class_define)(
                b"android.app.ITaskStackListener\0".as_ptr() as *const c_char,
                Some(on_create), Some(on_destroy), Some(tsl_on_transact),
            )
        };
        SendClass(class)
    }).0
}

/// 读 parcel int32
#[inline]
fn p_i32(ndk: &BinderNdk, p: *mut c_void) -> Option<i32> {
    let mut v = 0i32;
    unsafe { (ndk.read_i32)(p, &mut v) == 0 }.then_some(v)
}

/// 读 parcel 字符串 (utf8=false → string16; utf8=true → string8)。
/// Android 16: Intent 的 action/type/identifier/package/categories 用 writeString8 (字节数)，
/// ComponentName 仍用 writeString (UTF-16 单元数)。int32 长度 + 数据 + 补齐到 4 字节, -1=null。
fn p_strx(ndk: &BinderNdk, p: *mut c_void, utf8: bool) -> Option<String> {
    let start = unsafe { (ndk.data_position?)(p) };
    if start < 0 {
        return None;
    }
    let n = p_i32(ndk, p)?;
    if n < 0 {
        return Some(String::new());
    }
    let n = n as usize;
    let width = if utf8 { n + 1 } else { 2 * n + 2 };
    if width > 65536 {
        return None;
    }
    let words = (width + 3) / 4;
    let mut raw: Vec<u8> = Vec::with_capacity(words * 4);
    for _ in 0..words {
        raw.extend_from_slice(&(p_i32(ndk, p)? as u32).to_le_bytes());
    }
    let s = if utf8 {
        String::from_utf8_lossy(&raw[..n]).into_owned()
    } else {
        let units: Vec<u16> = (0..n)
            .map(|i| u16::from_le_bytes([raw[i * 2], raw[i * 2 + 1]]))
            .collect();
        String::from_utf16_lossy(&units)
    };
    let end = start + 4 + (((width as i32) + 3) & !3);
    if let Some(sp) = ndk.set_data_position {
        unsafe {
            let _ = sp(p, end);
        }
    }
    Some(s)
}

#[inline]
fn p_str8(ndk: &BinderNdk, p: *mut c_void) -> Option<String> {
    p_strx(ndk, p, true)
}

#[inline]
fn p_str16(ndk: &BinderNdk, p: *mut c_void) -> Option<String> {
    p_strx(ndk, p, false)
}

/// ComponentName.writeToParcel: null → 单个 int32 -1; 否则两个 string16 (pkg, cls)
fn p_component(ndk: &BinderNdk, p: *mut c_void) -> Option<(String, String)> {
    let start = unsafe { (ndk.data_position?)(p) };
    if start < 0 || p_i32(ndk, p)? < 0 {
        return None;
    }
    if let Some(sp) = ndk.set_data_position {
        unsafe {
            let _ = sp(p, start);
        }
    }
    let pkg = p_str16(ndk, p)?;
    let cls = p_str16(ndk, p)?;
    if pkg.is_empty() || cls.is_empty() {
        return None;
    }
    Some((pkg, cls))
}

/// 宽容跳过 Intent (lineage-23.2 Intent.writeToParcel 字段序; 读错无害 — 只影响本次结果)
fn p_skip_intent(ndk: &BinderNdk, p: *mut c_void) {
    let _ = p_str8(ndk, p);            // mAction
    if let Some(t) = p_i32(ndk, p) {   // mData: Uri (0=null, 其余 TYPE_ID + string8)
        if t != 0 {
            let _ = p_str8(ndk, p);
        }
    }
    let _ = p_str8(ndk, p);            // mType
    let _ = p_str8(ndk, p);            // mIdentifier
    let _ = p_i32(ndk, p);             // mFlags
    let _ = p_i32(ndk, p);             // mExtendedFlags
    let _ = p_str8(ndk, p);            // mPackage
    let _ = p_component(ndk, p);       // mComponent
    if p_i32(ndk, p) == Some(1) {      // mSourceBounds (Rect: 4 个 int32)
        for _ in 0..4 {
            let _ = p_i32(ndk, p);
        }
    }
    if let Some(n) = p_i32(ndk, p) {   // mCategories
        for _ in 0..n.max(0) {
            let _ = p_str8(ndk, p);
        }
    }
    let _ = p_i32(ndk, p);             // mSelector (null)
    let _ = p_i32(ndk, p);             // mClipData (null)
    let _ = p_i32(ndk, p);             // mContentUserHint
    let pos = ndk.data_position.map(|dp| unsafe { dp(p) });
    if let Some(l) = p_i32(ndk, p) {   // mExtras (writeBundle: <=0 → 只占 4 字节)
        if l > 0 {
            if let (Some(sp), Some(pos)) = (ndk.set_data_position, pos) {
                unsafe {
                    let _ = sp(p, pos + 12 + l);
                }
            }
        }
    }
    let _ = p_i32(ndk, p);             // mOriginalIntent
    if p_i32(ndk, p) == Some(1) {      // mCreatorTokenInfo
        let _ = p_i32(ndk, p);         // strong binder
        if let Some(n) = p_i32(ndk, p) {
            for _ in 0..n.max(0) {
                let _ = p_i32(ndk, p);
                let _ = p_str8(ndk, p);
                let _ = p_i32(ndk, p);
            }
        }
    }
}

/// ITaskStackListener 回调 onTransact: onTaskMovedToFront=0xb 参数 RunningTaskInfo
/// (readTypedObject → null 标志 + RunningTaskInfo.id + TaskInfo: userId/taskId/effectiveUid,
/// effectiveUid = null 标志后第 4 个 int),
/// 直接取 effectiveUid 发送到主线程 EV_TASK。
extern "C" fn tsl_on_transact(
    _binder: *mut c_void,
    code: u32,
    in_parcel: *mut c_void,
    _out: *mut c_void,
) -> c_int {
    let Some(ndk) = ndk() else { return STATUS_UNKNOWN_TRANSACTION };
    match code {
        0x0c => {
            /* onTaskDescriptionChanged(RunningTaskInfo): 直接解析 topActivity
             * (事件发生在 resume 后 → 无延迟, 无 getTasks)。
             * 早期过滤: 先只取 effectiveUid (跳读 offset 16, 一次定位),
             * 非规则应用直接返回, 不解析 Intent/组件/投递 */
            let start = ndk.data_position.map(|dp| unsafe { dp(in_parcel) });
            let euid = match (start, ndk.set_data_position) {
                (Some(s), Some(sp)) => {
                    unsafe {
                        let _ = sp(in_parcel, s + 16);
                    }
                    p_i32(&ndk, in_parcel)
                }
                _ => {
                    /* 无游标辅助: 顺序读到 effectiveUid */
                    if p_i32(&ndk, in_parcel) != Some(1) {
                        None
                    } else {
                        let _id = p_i32(&ndk, in_parcel);
                        let _user = p_i32(&ndk, in_parcel);
                        let _task = p_i32(&ndk, in_parcel);
                        p_i32(&ndk, in_parcel)
                    }
                }
            };
            let Some(euid) = euid else { return STATUS_OK };
            if euid <= 0 || !ACT_RULE_UIDS.lock().unwrap().contains(&euid) {
                return STATUS_OK;   /* 非规则应用: 零解析零投递 */
            }
            /* 命中规则应用: 复位从头完整解析 (flag/id/userId/taskId 已在跳读时跳过) */
            if let (Some(sp), Some(s)) = (ndk.set_data_position, start) {
                unsafe {
                    let _ = sp(in_parcel, s);
                }
            }
            if p_i32(&ndk, in_parcel) != Some(1) {
                return STATUS_OK;
            }
            let _id = p_i32(&ndk, in_parcel);
            let _user = p_i32(&ndk, in_parcel);
            let _task = p_i32(&ndk, in_parcel);
            let _disp = p_i32(&ndk, in_parcel);
            let _run = p_i32(&ndk, in_parcel);
            if p_i32(&ndk, in_parcel) == Some(1) {
                p_skip_intent(&ndk, in_parcel);
            }
            let _ba = p_component(&ndk, in_parcel);
            let actl = p_component(&ndk, in_parcel);
            let _oa = p_component(&ndk, in_parcel);
            let _ra = p_component(&ndk, in_parcel);
            if let Some((pkg, comp)) = actl {
                if !pkg.is_empty() && !comp.is_empty() {
                    /* uid(i32 LE) + pkg\0 + comp\0 (SOCK_DGRAM 原子) */
                    let mut msg = Vec::with_capacity(8 + pkg.len() + comp.len());
                    msg.extend_from_slice(&euid.to_le_bytes());
                    msg.extend_from_slice(pkg.as_bytes());
                    msg.push(0);
                    msg.extend_from_slice(comp.as_bytes());
                    msg.push(0);
                    let fd = ACTL_SEND_FD.load(Ordering::Acquire);
                    if fd >= 0 {
                        let _ = unsafe {
                            libc::send(fd, msg.as_ptr() as *const libc::c_void, msg.len(), libc::MSG_DONTWAIT)
                        };
                    }
                }
            }
            STATUS_OK
        }
        0x0b => {
            // onTaskMovedToFront(RunningTaskInfo):
            // [null 标志][RunningTaskInfo.id][TaskInfo.userId][taskId][effectiveUid]...
            // effectiveUid = null 标志后第 4 个 int
            let mut flag = 0i32;
            let _ = unsafe { (ndk.read_i32)(in_parcel, &mut flag) };
            if flag != 0 {
                let mut _id = 0i32;
                let _ = unsafe { (ndk.read_i32)(in_parcel, &mut _id) };
                let mut _user_id = 0i32;
                let _ = unsafe { (ndk.read_i32)(in_parcel, &mut _user_id) };
                let mut _task_id = 0i32;
                let _ = unsafe { (ndk.read_i32)(in_parcel, &mut _task_id) };
                let mut uid = -1i32;
                let _ = unsafe { (ndk.read_i32)(in_parcel, &mut uid) };
                let fd = TASK_SEND_FD.load(Ordering::Acquire);
                if fd >= 0 && uid > 0 {
                    let _ = unsafe {
                        libc::send(fd, &uid as *const i32 as *const libc::c_void, 4, libc::MSG_DONTWAIT)
                    };
                }
            }
            STATUS_OK
        }
        _ => {
            // onTaskStackChanged/onTaskFocusChanged 等: 无有效 uid 负载, 忽略
            STATUS_OK
        }
    }
}

/// 注册 ITaskStackListener (事务 0x2f): 任务前移 → effectiveUid → 主线程 EV_TASK
pub fn init_task_stack_listener(send_fd: i32) -> bool {
    TASK_SEND_FD.store(send_fd, Ordering::Release);
    let Some(ndk) = ndk() else { return false };
    let class = get_tsl_class();
    if class.is_null() {
        return false;
    }
    let listener = unsafe { (ndk.binder_new)(class, std::ptr::null_mut()) };
    if listener.is_null() {
        return false;
    }
    let am = unsafe { (ndk.get_service)(b"activity_task\0".as_ptr() as *const c_char) };
    if am.is_null() {
        return false;
    }
    let atm_class = get_atm_class();
    if atm_class.is_null() {
        return false;
    }
    if !unsafe { (ndk.associate_class)(am, atm_class as *const c_void) } {
        return false;
    }
    let mut in_parcel: *mut c_void = std::ptr::null_mut();
    if unsafe { (ndk.prepare_tx)(am, &mut in_parcel) } != STATUS_OK || in_parcel.is_null() {
        return false;
    }
    // writeStrongInterface(listener)
    let _ = unsafe { (ndk.write_binder)(in_parcel, listener) };
    let mut out_parcel: *mut c_void = std::ptr::null_mut();
    let status = unsafe { (ndk.transact)(am, 0x2f, &mut in_parcel, &mut out_parcel, 0) };
    unsafe { (ndk.parcel_delete)(in_parcel); }
    if status == STATUS_OK && !out_parcel.is_null() {
        let mut exc = 0i32;
        let _ = unsafe { (ndk.read_i32)(out_parcel, &mut exc) };
        unsafe { (ndk.parcel_delete)(out_parcel); }
        if exc == 0 {
            // binder 线程池: 原由 IProcessObserver 注册启动; on_fg 驱动移除后,
            // TaskStackListener 回调依赖此线程池 → 注册成功后在此启动
            let start_fn = ndk.start_thread_pool;
            let join_fn = ndk.join_thread_pool;
            std::thread::spawn(move || {
                unsafe { start_fn(); }
                unsafe { join_fn(); }
            });
            return true;
        }
        return false;
    }
    if !out_parcel.is_null() {
        unsafe { (ndk.parcel_delete)(out_parcel); }
    }
    false
}

/// binder 直连 SurfaceFlinger 设置刷新率：事务码 1035，一个 int32 参数
/// （替代 `service call SurfaceFlinger 1035 i32 <mode>` 的 fork/exec 子进程方式）
/// 使用 ISurfaceComposer.h 确认的描述符 android.ui.ISurfaceComposer；
/// 失败返回 false，调用方可回退到 service 命令。
pub fn set_refresh_rate_binder(mode: i32) -> bool {
    let Some(ndk) = ndk() else { return false };

    // SurfaceFlinger binder 句柄缓存: 首次 get_service + associate 后复用
    // (不缓存 null: 失败下次调用重试; 缓存成功即免每帧服务解析/引用泄漏)
    let sf = {
        let mut slot = crate::lock_ignore_poison(&SF_BINDER);
        match slot.as_ref() {
            Some(c) => c.0,
            None => {
                let sf =
                    unsafe { (ndk.get_service)(b"SurfaceFlinger\0".as_ptr() as *const c_char) };
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
                *slot = Some(SendClass(sf));
                sf
            }
        }
    };

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

/* ================= activity 查询: binder 直连 getTasks(0x19) 拿 topActivity =================
 * 内核 token 命中 START_ACTIVITY → eventfd 信号 → 本函数查权威 topActivity (完整类名)。
 * 用户态解析: 读错/失败只返回 None (不应用), 无崩溃风险 (与内核 copy 崩区分)。
 */



//! KPM 事件环模式 (KernelPatch KPM 内核模块, syscall 45 通信)
//!
//! 事件环 (input 事件通道): ctl0 `shm_open <eventfd>` 让内核把 256KB 事件环
//! remap 为共享内存 fd 并把 AppOpt 的 eventfd 注册为通知端; reader 线程 mmap
//! 该 fd, 阻塞在 eventfd 上, 唤醒后直接从共享环消费 (SPSC, acquire/release
//! 同步), 零轮询。input 检测已统一用户态 eventX (内核 input kprobe 不再武装,
//! 本事件环保留备用); 退出清理走 pidfd, 不经事件环。
//!
//! CPU 亲和性/刷新率不再由进程事件驱动: binder 前台回调 (pid+uid) 由主线程
//! 经 uid 静态表分发到 cpuset(按 uid 取应用) 与刷新率线程 (见 main.rs EV_FG,
//! cpu_affinity.rs, refresh.rs)。
//!
//! 控制面 (APPLIED 表 / start-stop / shm_open) 走 ctl0 supercall。
//!
//! 内核侧 (AppOpt-kpm/appopt_kpm.c):
//!   - kprobe input_handle_event (1s 节流)
//!   - kprobe sched_setaffinity (按 APPLIED bits 强制)
//!   - APPLIED tid 表、mmap 共享 256KB 事件环
//! 事件结构 EbpfProcEvent 与内核 appopt_proc_event_t 布局完全一致 (28B),
//! event_dispatch/affinity 逻辑与原先保持一致。

use std::ffi::CString;
use std::os::raw::c_char;
// use std::sync::atomic::{AtomicU32, Ordering};  // 事件环停用, 临时注释


/// 安全构造 CString (输入受控/常量; 无 NUL 时保底空串, 避免 panic)
/// KPM 模块可用性探测 (状态页 kpm_available 用): KP 就绪 + 握手
pub(crate) fn kpm_probe() -> bool {
    kp_ready(&kpm_key())
}

fn cstr(s: &str) -> CString {
    CString::new(s).unwrap_or_default()
}

/* ================= L1: 规则下发前用户态校验 =================
 * 内核 ctl0 解析为空格分隔文本: 字段含空白/控制字符会解析错位;
 * vfc_rule 的 sscanf %127s/%255s 与 srv_rule 的定长循环会静默截断超长输入。
 * 下发前在此拒绝, 把"静默错误"变成"显式报错"。 */

/// 与内核 appopt_kpm.c 对齐的容量/长度上限
pub(crate) const SRV_MAX_RULES: usize = 16;    /* srv_rules 表容量 */
pub(crate) const SRV_MAX_CHARS: usize = 64;    /* srv_rule from/to 单字段上限 (字符) */
pub(crate) const VFC_RULE_MAX: usize = 512;    /* vfc_rules 表容量 */
pub(crate) const VFC_TARGET_MAX: usize = 127;  /* vfc_rule target (内核 sscanf %127s) */
pub(crate) const VFC_FROM_MAX: usize = 127;    /* vfc_rule from  (%127s) */
pub(crate) const VFC_TO_MAX: usize = 255;      /* vfc_rule to    (%255s) */

fn field_ok(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| !c.is_whitespace() && !c.is_control())
}

/// 校验 srv_rule: 等长 + ASCII(内核按单字节转 utf16) + 无空白/控制字符 + 长度上限
pub(crate) fn validate_srv_rule(idx: usize, from: &str, to: &str) -> Result<(), String> {
    if idx >= SRV_MAX_RULES {
        return Err(format!("srv_rule 索引 {idx} 超出表容量 {SRV_MAX_RULES}"));
    }
    if !field_ok(from) || !field_ok(to) {
        return Err(format!("srv_rule from/to 为空或含空白/控制字符: '{from}' -> '{to}'"));
    }
    if !from.is_ascii() || !to.is_ascii() {
        return Err(format!("srv_rule 仅支持 ASCII (内核按字节转 utf16): '{from}' -> '{to}'"));
    }
    if from.len() > SRV_MAX_CHARS || to.len() > SRV_MAX_CHARS {
        return Err(format!("srv_rule 字段超限 (>{SRV_MAX_CHARS}): '{from}' -> '{to}'"));
    }
    if from.len() != to.len() {
        return Err(format!(
            "srv_rule 必须等长 (等长替换): {} vs {} 字节: '{from}' -> '{to}'",
            from.len(),
            to.len()
        ));
    }
    Ok(())
}

/// 校验 vfc_rule: 长度上限(防内核 sscanf 静默截断) + 无空白/控制字符 + kind/路径语义
pub(crate) fn validate_vfc_rule(
    idx: usize,
    uid: i32,
    kind: &str,
    target: &str,
    from: &str,
    to: &str,
) -> Result<(), String> {
    if idx >= VFC_RULE_MAX {
        return Err(format!("vfc_rule 索引 {idx} 超出表容量 {VFC_RULE_MAX}"));
    }
    if kind != "c" && kind != "p" {
        return Err(format!("vfc_rule kind 非法: '{kind}' (仅 c/p)"));
    }
    if !field_ok(target) {
        return Err(format!("vfc_rule target 为空或含空白/控制字符: '{target}'"));
    }
    if !field_ok(from) || !field_ok(to) {
        return Err(format!("vfc_rule from/to 为空或含空白/控制字符: '{from}' -> '{to}'"));
    }
    if target.len() > VFC_TARGET_MAX {
        return Err(format!(
            "vfc_rule target 超限 (>{VFC_TARGET_MAX}, 内核 sscanf 会静默截断): '{target}'"
        ));
    }
    if from.len() > VFC_FROM_MAX {
        return Err(format!("vfc_rule from 超限 (>{VFC_FROM_MAX}): '{from}'"));
    }
    if to.len() > VFC_TO_MAX {
        return Err(format!("vfc_rule to 超限 (>{VFC_TO_MAX}): '{to}'"));
    }
    if kind == "c" && from.len() != to.len() {
        return Err(format!(
            "vfc_rule kind=c 内容替换必须等长: {} vs {} 字节: '{from}' -> '{to}'",
            from.len(),
            to.len()
        ));
    }
    if kind == "p" && !from.starts_with('/') {
        return Err(format!("vfc_rule kind=p 路径规则 from 必须以 '/' 开头: '{from}'"));
    }
    let _ = uid;   /* uid 仅透传 (含 -1 全局), 无需校验 */
    Ok(())
}

/// 聚合校验一组已映射的规则 (vfc rows + srv list, 索引即内核下发 idx)。
/// WebUI 保存前与主循环下发前共用; 返回全部错误, 非空则整组不下发。
pub(crate) fn validate_rule_set(
    vrows: &[(i32, String, String, String, String)],
    srows: &[(i32, String, String)],
) -> Vec<String> {
    let mut errs = Vec::new();
    for (i, (uid, kind, tg, from, to)) in vrows.iter().enumerate() {
        if let Err(e) = validate_vfc_rule(i, *uid, kind, tg, from, to) {
            errs.push(format!("vfc #{i}: {e}"));
        }
    }
    for (i, (_u, from, to)) in srows.iter().enumerate() {
        if let Err(e) = validate_srv_rule(i, from, to) {
            errs.push(format!("srv #{i}: {e}"));
        }
    }
    errs
}

// 事件环当前只流动 INPUT (内核事件已停用, 临时注释)
// pub const EBPF_EVENT_INPUT: u32 = 5;


/* ================= KernelPatch SuperCall 传输 ================= */

/// SuperCall 复用 syscall 45 (__NR_truncate)
const NR_SUPERCALL: i64 = 45;
const SUPERCALL_HELLO: i64 = 0x1000;
const SUPERCALL_KPM_CONTROL: i64 = 0x1022;
const SUPERCALL_HELLO_MAGIC: i64 = 0x11581158;

/// KPM 模块名 (与 appopt_kpm.c KPM_NAME 一致)
const KPM_MODULE: &[u8] = b"appopt-kpm\0";

/// KernelPatch superkey (可由环境变量 APPOPT_KPM_KEY 覆盖; 空则用 "su" 探测)
fn kpm_key() -> CString {
    if let Ok(k) = std::env::var("APPOPT_KPM_KEY") {
        if !k.is_empty() {
            return cstr(&k);
        }
    }
    cstr("su")
}

/// 构造 SuperCall 命令参数: [31:16]=0x1158 magic, [15:0]=cmd, [63:32]=版本(可留 0)
#[inline]
fn ver_and_cmd(cmd: i64) -> i64 {
    (0x1158i64 << 16) | (cmd & 0xffff)
}

/// 裸 SuperCall, 返回内核返回值 (负数=错误)
unsafe fn supercall(
    key: *const c_char,
    cmd: i64,
    a1: *const c_char,
    a2: *const c_char,
    a3: *mut u8,
    a4: usize,
) -> i64 {
    // Rust 2024: unsafe_op_in_unsafe_fn, 体内 unsafe 调用需显式 unsafe 块
    unsafe { libc::syscall(NR_SUPERCALL, key, ver_and_cmd(cmd), a1, a2, a3, a4) as i64 }
}

/// 向 KPM 模块发送 ctl0 命令; out 为可选输出缓冲
fn kpm_ctl0(key: &CString, args: &CString, out: &mut [u8]) -> i64 {
    // out 为空时用本地缓冲 (必须存活到 supercall 返回)
    let mut tmp = [0u8; 64];
    let (ptr, len) = if out.is_empty() {
        (tmp.as_mut_ptr(), tmp.len())
    } else {
        (out.as_mut_ptr(), out.len())
    };
    unsafe {
        supercall(
            key.as_ptr(),
            SUPERCALL_KPM_CONTROL,
            KPM_MODULE.as_ptr() as *const c_char,
            args.as_ptr(),
            ptr,
            len,
        )
    }
}

/// KernelPatch 是否就绪
fn kp_ready(key: &CString) -> bool {
    unsafe { supercall(key.as_ptr(), SUPERCALL_HELLO, std::ptr::null(), std::ptr::null(), std::ptr::null_mut(), 0) == SUPERCALL_HELLO_MAGIC }
}

/// KPM 传输句柄 (占用原 EbpfState.bpf 字段, 保持 main.rs 接口不变)
/// 屏幕挂机黑屏: 读当前亮度 (brightness 文件)
pub fn scr_read_brightness() -> Option<i32> {
    std::fs::read_to_string("/sys/class/backlight/panel0-backlight/brightness")
        .ok()
        .and_then(|s| s.trim().parse::<i32>().ok())
}

/// 屏幕挂机黑屏: 写亮度
pub fn scr_set_brightness(v: i32) {
    let _ = std::fs::write(
        "/sys/class/backlight/panel0-backlight/brightness",
        format!("{}\n", v),
    );
}

/// 保存关屏前亮度 (长按黑屏前记录; 记录成功才允许写 0)
pub fn scr_store_saved(v: i32) {
    *SCR_BRIGHTNESS.lock().unwrap() = Some(v);
}

/// 取出关屏前亮度 (单击渐亮恢复用)
pub fn scr_take_saved() -> Option<i32> {
    SCR_BRIGHTNESS.lock().unwrap().take()
}

/// 渐亮: 从 0 分 20 步 (每步 50ms) 恢复到 target, 模拟亮度慢慢提高
pub fn scr_fade_in(target: i32) {
    if target <= 0 {
        return;
    }
    let step = (target / 20).max(1);
    let mut cur = 0;
    while cur < target {
        cur += step;
        if cur > target {
            cur = target;
        }
        scr_set_brightness(cur);
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

/// 关屏前亮度 (长按黑屏时记录; 读取失败则不写 0, 避免永久黑屏)
static SCR_BRIGHTNESS: std::sync::Mutex<Option<i32>> = std::sync::Mutex::new(None);

pub struct KpmHandle {
    key: CString,
}

impl KpmHandle {
    /// 确认模块已加载: ping 成功即视为已加载
    fn ping(&self) -> bool {
        let args = cstr("ping");
        let mut out = [0u8; 16];
        kpm_ctl0(&self.key, &args, &mut out) >= 0 && out[0] == b'p'
    }

    /// 确认模块已加载 (由 APatch 管理器加载; AppOpt 不自动部署/加载)
    pub(crate) fn verify_loaded(&self) -> bool {
        self.ping()
    }

    /// ctl0 命令封装
    fn cmd(&self, args: &str) -> i64 {
        let c = cstr(args);
        kpm_ctl0(&self.key, &c, &mut [])
    }

    /// service list 伪装开关 (前台回调驱动): on=true 激活(无差别替换 listServices)
    pub(crate) fn srv_active(&self, on: bool) {
        let args = format!("srv_active {}", if on { 1 } else { 0 });
        self.cmd(&args);
    }

    /// 清空全部替换规则 (waylay.conf 重载前)
    pub(crate) fn srv_clear(&self) {
        self.cmd("srv_clear");
    }

    /// 设置第 idx 组等长替换规则 (from→to, 字符数一致); L1 校验后下发
    pub(crate) fn srv_rule(&self, idx: usize, from: &str, to: &str) -> Result<(), String> {
        validate_srv_rule(idx, from, to)?;
        let args = format!("srv_rule {} {} {}", idx, from, to);
        let r = self.cmd(&args);
        if r < 0 {
            return Err(format!("内核拒绝 srv_rule #{}: 返回 {}", idx, r));
        }
        Ok(())
    }

    /// 武装 KPM (start: affinity 拦截 + 清理探针 + service list 伪装)
    pub(crate) fn arm(&self) {
        self.cmd("start");
        /* 启动早期 bootconfig 替换 (init 导入) 已完成 → 通知内核移除钩子 */
        self.cmd("bc_on");
        ensure_prop_maps();   // 连接时提前 mmap 目标 tmpfs 文件并保持
        // vfc: 规则由用户态配置事件下发 (vfc_sync), 连接后激活; 这里不触碰
    }

    /// 解除武装 (stop: 摘除全部业务探针 + 恢复 vendor_file_contexts 读取)
    pub(crate) fn disarm(&self) {
        self.cmd("stop");
        self.vfc_disable();        // vfc off: 重定向/内容替换失效 (hook 常驻, 回调跳过)
        self.prop_file_apply(false);   // prop 恢复原属性 (tmpfs 反向替换)
    }

    /// 激活 vfc (enabled=1 + 首次常驻挂载); 规则已由 vfc_sync 下发
    pub(crate) fn vfc_apply(&self) {
        self.cmd("vfc off");   // 清 file* 表与应用侧残留
        self.cmd("vfc on");
    }

    /// 禁用 vendor_file_contexts 重定向 (摘除内核 hook, 恢复原文件读取)
    pub(crate) fn vfc_disable(&self) {
        self.cmd("vfc off");
    }

    /// 前台 uid (前台回调下发; <0=无 vfc 规则 → 仅全局)
    pub(crate) fn vfc_fg(&self, uid: i32) {
        self.cmd(&format!("vfc_fg {}", uid));
    }

    /// 清空全部 vfc 规则 (配置重下发前)
    pub(crate) fn vfc_rule_clear(&self) {
        self.cmd("vfc_rule_clear");
    }

    /// 统一 vfc 规则: uid(应用) + kind "c"=内容替换(需 target) / "p"=文件重定向; L1 校验后下发
    pub(crate) fn vfc_rule(
        &self,
        idx: usize,
        uid: i32,
        kind: &str,
        target: &str,
        from: &str,
        to: &str,
    ) -> Result<(), String> {
        validate_vfc_rule(idx, uid, kind, target, from, to)?;
        let args = format!("vfc_rule {} {} {} {} {} {}", idx, uid, kind, target, from, to);
        let r = self.cmd(&args);
        if r < 0 {
            return Err(format!("内核拒绝 vfc_rule #{}: 返回 {}", idx, r));
        }
        Ok(())
    }

    /// property 区用户态文件写替换 (root 读写 /dev/__properties__/<ctx> 文件,
    /// 等长替换 → tmpfs page cache 更新 → 全进程共享映射见新名)。
    /// on=true from→to, false 反向恢复。完全用户态, 无内核内存操作。
    pub(crate) fn prop_file_apply(&self, on: bool) {
        ensure_prop_maps();   // 懒补充 (保存后新增 context 时补映射)
        let rules =
            crate::rw_read_ignore_poison(&crate::config::WAYLAY_PROP_RULES).clone();
        let maps = crate::lock_ignore_poison(&PROP_MAPS);
        for (_, ptr, len) in maps.iter() {
            let len = *len;
            unsafe {
                let base = *ptr as *mut u8;
                for (from, to) in &rules {
                    if from.is_empty() || to.is_empty() {
                        continue;
                    }
                    /* 值替换: from/to 为 "属性名=原值" / "新属性名=新值",
                     * 子串 <name>\0<val>\0 → <newname>\0<val2>, 其它属性同值不受影响 */
                    let fv = from.find('=');
                    let tv = to.find('=');
                    let (mut pat, mut rep): (Vec<u8>, Vec<u8>) = if fv.is_some() && tv.is_some() {
                        let (n1, v1) = from.split_at(fv.unwrap());
                        let v1 = v1[1..].to_string();
                        let (n2, v2) = to.split_at(tv.unwrap());
                        let v2 = v2[1..].to_string();
                        if n1.is_empty() || v1.is_empty() || n2.is_empty() || v2.is_empty() {
                            continue;
                        }
                        (Vec::new(), Vec::new())   /* 值替换走下方"精确按名(名-92)"块, 不需 pat/rep */
                    } else {
                        (from.as_bytes().to_vec(), to.as_bytes().to_vec())
                    };
                    if !(fv.is_some() && tv.is_some())
                        && (pat.is_empty() || pat.len() != rep.len())
                    {
                        continue;
                    }
                    if !on {
                        std::mem::swap(&mut pat, &mut rep);
                    }
                    if pat.len() > len {
                        continue;
                    }
                    if fv.is_some() && tv.is_some() {
                        /* 精确按名替换: 条目 = [值区(定长92, 值文本在前)][属性名];
                         * 值文本起点 = 名起点 - 92; 验证值==原值后等长写回 (只改该属性) */
                        let _ = (on, pat, rep);
                        let (n1, v1) = from.split_at(fv.unwrap());
                        let v1 = &v1[1..];
                        let (_n2, v2) = to.split_at(tv.unwrap());
                        let v2 = &v2[1..];
                        let (ov, nw) = if on { (v1, v2) } else { (v2, v1) };
                        let nb: Vec<u8> = n1.as_bytes().to_vec();
                        if ov.len() == nw.len() {
                            let mut i = 0usize;
                            while i + nb.len() <= len {
                                if std::slice::from_raw_parts(base.add(i), nb.len()) == &nb[..] {
                                    let vt = i.saturating_sub(92);
                                    if std::slice::from_raw_parts(base.add(vt), ov.len()) == ov.as_bytes() {
                                        std::ptr::copy_nonoverlapping(nw.as_ptr(), base.add(vt), ov.len());
                                    }
                                    i += nb.len();
                                } else {
                                    i += 1;
                                }
                            }
                        } else if nw.len() < 92 {
                            /* 不等长: 写新值+NUL → release → 更新 serial 低 16 位 (高 16 位保留);
                             * libc 按 serial&0xffff 拷贝且 serial 校验重读 → 一致无撕裂 */
                            let mut i = 0usize;
                            while i + nb.len() <= len {
                                if std::slice::from_raw_parts(base.add(i), nb.len()) == &nb[..] {
                                    let vt = i.saturating_sub(92);
                                    if vt >= 8
                                        && std::slice::from_raw_parts(base.add(vt), ov.len())
                                            == ov.as_bytes()
                                    {
                                        std::ptr::copy_nonoverlapping(nw.as_ptr(), base.add(vt), nw.len());
                                        *base.add(vt + nw.len()) = 0u8;   /* NUL 结束 */
                                        std::sync::atomic::fence(std::sync::atomic::Ordering::Release);
                                        let s = (base.add(vt - 4) as *const u32).read_volatile();
                                        let ns = (s & 0xffff_0000u32) | (nw.len() as u32 & 0xffff);
                                        (base.add(vt - 4) as *mut u32).write_volatile(ns);
                                    }
                                    i += nb.len();
                                } else {
                                    i += 1;
                                }
                            }
                        }
                    } else {
                        let mut i = 0usize;
                        while i + pat.len() <= len {
                            if std::slice::from_raw_parts(base.add(i), pat.len()) == &pat[..] {
                                std::ptr::copy_nonoverlapping(rep.as_ptr(), base.add(i), pat.len());
                                i += pat.len();
                            } else {
                                i += 1;
                            }
                        }
                    }
                }
                // tmpfs: MAP_SHARED 写入即进 page cache, 其他进程映射同页立即可见
            }
        }
    }



}

/// KPM 初始化状态 (由 ebpf_init 创建; 事件环/共享内存通道已全部移除)
pub struct EbpfState {
    /// KPM 传输句柄 (ctl0 supercall 通道); 字段名 bpf 沿用历史
    pub bpf: KpmHandle,
}

/// 初始化 KPM: 握手 + 校验; 事件环通道已移除 (内核无事件生产者);
/// 武装由 webui 拦截页「连接」触发。
pub fn ebpf_init(drive_mode: String) -> Option<EbpfState> {
    // 设置项工作模式 UI 已移除: 只要模块加载 (ping 成功) 即可用 KPM
    let _ = drive_mode;
    let key = kpm_key();
    if !kp_ready(&key) {
        return None;
    }
    let handle = KpmHandle { key };
    if !handle.verify_loaded() {
        return None;
    }
    Some(EbpfState { bpf: handle })
}


/// 事件派发 (input: 刷新率活动检测; 退出清理统一由用户态 pidfd 负责,
/// 内核 EXIT 事件不再消费; CPU/刷新率主体由 binder 三线程驱动)


/// 提前 mmap 并保持目标 property tmpfs 文件映射 (连接/首次使用时建立,
/// 前台切换只做内存替换)。MAP_SHARED 改动即写回 page cache → 全进程共享映射可见。
static PROP_MAPS: std::sync::Mutex<Vec<(String, usize, usize)>> =
    std::sync::Mutex::new(Vec::new());
/// 释放全部 property tmpfs 映射 (配置无 prop 替换规则或目标应用时调用,
/// 避免无规则时仍保持映射占用 /dev/__properties__ 句柄与共享页)
fn release_prop_maps() {
    let mut maps = crate::lock_ignore_poison(&PROP_MAPS);
    for (_, ptr, len) in maps.drain(..) {
        unsafe {
            libc::munmap(ptr as *mut libc::c_void, len);
        }
    }
}

pub(crate) fn ensure_prop_maps() {
    // 门控: 新格式 prop 规则 (WAYLAY_PROP_RULES, on_fg 按包维护) 存在才映射属性区; 清空时释放
    let has_rules = !crate::rw_read_ignore_poison(&crate::config::WAYLAY_PROP_RULES).is_empty();
    if !has_rules {
        release_prop_maps();
        return;
    }
    let ctxs = crate::rw_read_ignore_poison(&crate::config::WAYLAY_PROP_CTX).clone();
    let mut maps = crate::lock_ignore_poison(&PROP_MAPS);
    for (_, ctx) in &ctxs {
        if maps.iter().any(|(b, _, _)| *b == *ctx) {
            continue;
        }
        use std::os::unix::io::AsRawFd;
        let path = format!("/dev/__properties__/{}", ctx);
        let Ok(f) = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
        else {
            continue;
        };
        let Ok(md) = f.metadata() else { continue };
        let len = md.len() as usize;
        if len == 0 {
            continue;
        }
        let map = unsafe {
            libc::mmap(std::ptr::null_mut(), len,
                       libc::PROT_READ | libc::PROT_WRITE,
                       libc::MAP_SHARED, f.as_raw_fd(), 0)
        };
        if map != libc::MAP_FAILED {
            maps.push((ctx.clone(), map as usize, len));
        }
    }
}

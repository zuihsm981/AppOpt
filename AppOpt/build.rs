use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let target = env::var("TARGET").unwrap_or_else(|_| "aarch64-linux-android".to_string());

    // 生成 stub C 文件——所有函数返回 0/null，仅用于链接期满足符号
    // 运行时由系统 libbinder_ndk.so 覆盖
    let stub_c = out_dir.join("binder_ndk_stub.c");
    std::fs::write(&stub_c, r#"
        void* AServiceManager_getService() { return 0; }
        void* AIBinder_Class_new() { return 0; }
        void* AIBinder_new() { return 0; }
        int ABinder_prepareTransaction() { return 0; }
        int ABinder_transact() { return 0; }
        void AParcel_delete() {}
        int AParcel_writeInterfaceToken() { return 0; }
        int AParcel_writeStrongBinder() { return 0; }
        int AParcel_readInt32() { return 0; }
        int AParcel_readBool() { return 0; }
        int AParcel_readString() { return 0; }
        int ABinder_joinThreadPool() { return 0; }
    "#).unwrap();

    // 查找 NDK clang：依次尝试环境变量、ANDROID_NDK_HOME 路径、PATH
    let cc = find_ndk_clang();
    alog_cc(&cc);

    let so_path = out_dir.join("libbinder_ndk.so");
    let target_arg = format!("--target={}29", target);

    let status = Command::new(&cc)
        .args([&target_arg, "-nostdlib", "-shared", "-o", so_path.to_str().unwrap(), stub_c.to_str().unwrap()])
        .status();

    match status {
        Ok(s) if s.success() => {
            println!("cargo:rustc-link-search=native={}", out_dir.display());
        }
        Ok(s) => {
            println!("cargo:warning=binder_ndk stub 编译失败: {:?}", s);
        }
        Err(e) => {
            println!("cargo:warning=NDK clang 执行失败 ({}): {}", cc, e);
        }
    }

    println!("cargo:rerun-if-changed=build.rs");
}

fn find_ndk_clang() -> String {
    // 1. CC_aarch64_linux_android
    if let Ok(cc) = env::var("CC_aarch64_linux_android") {
        if !cc.is_empty() {
            return cc;
        }
    }
    // 2. CC
    if let Ok(cc) = env::var("CC") {
        if !cc.is_empty() {
            return cc;
        }
    }
    // 3. ANDROID_NDK_HOME / ANDROID_NDK_ROOT + 已知路径
    for var in &["ANDROID_NDK_HOME", "ANDROID_NDK_ROOT"] {
        if let Ok(ndk) = env::var(var) {
            let clang = PathBuf::from(&ndk)
                .join("toolchains/llvm/prebuilt/linux-x86_64/bin/clang");
            if clang.exists() {
                return clang.to_string_lossy().into_owned();
            }
            // 也可能是 darwin 或 windows host
            for os in &["linux-x86_64", "darwin-x86_64", "windows-x86_64"] {
                let clang = PathBuf::from(&ndk)
                    .join(format!("toolchains/llvm/prebuilt/{}/bin/clang", os));
                if clang.exists() {
                    return clang.to_string_lossy().into_owned();
                }
            }
        }
    }
    // 4. PATH 中的 clang
    "clang".to_string()
}

fn alog_cc(cc: &str) {
    println!("cargo:warning=build.rs 使用 clang: {}", cc);
}
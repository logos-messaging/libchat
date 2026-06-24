fn main() {
    println!("cargo::rustc-check-cfg=cfg(logos_delivery)");

    let Some(lib_dir) = std::env::var("DEP_LOGOSDELIVERY_LIB_DIR").ok() else {
        return;
    };

    println!("cargo:rustc-cfg=logos_delivery");

    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    match target_os.as_str() {
        "macos" | "linux" => println!("cargo:rustc-link-arg=-Wl,-rpath,{lib_dir}"),
        _ => {}
    }
}

fn main() {
    println!("cargo::rustc-check-cfg=cfg(logos_delivery)");
    println!("cargo:rerun-if-env-changed=LOGOS_DELIVERY_LIB_DIR");

    let Ok(lib_dir) = std::env::var("LOGOS_DELIVERY_LIB_DIR") else {
        return;
    };

    println!("cargo:rustc-cfg=logos_delivery");
    println!("cargo:rustc-link-search=native={lib_dir}");
    println!("cargo:rustc-link-lib=dylib=logosdelivery");

    // Set rpath so the binary finds the shared library at runtime.
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    match target_os.as_str() {
        "macos" => println!("cargo:rustc-link-arg=-Wl,-rpath,{lib_dir}"),
        "linux" => println!("cargo:rustc-link-arg=-Wl,-rpath,{lib_dir}"),
        other => panic!("unsupported OS for logos-delivery transport: {other}"),
    }
}

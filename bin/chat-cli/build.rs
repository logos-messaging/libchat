fn main() {
    println!("cargo:rerun-if-env-changed=LOGOS_DELIVERY_LIB_DIR");

    let lib_dir = std::env::var("LOGOS_DELIVERY_LIB_DIR").expect(
        "LOGOS_DELIVERY_LIB_DIR must be set; build liblogosdelivery via \
         `nix build .#logos-delivery` and point this var at the result/lib directory",
    );

    println!("cargo:rustc-link-search=native={lib_dir}");
    println!("cargo:rustc-link-lib=dylib=logosdelivery");

    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    match target_os.as_str() {
        "macos" | "linux" => println!("cargo:rustc-link-arg=-Wl,-rpath,{lib_dir}"),
        other => panic!("unsupported OS for logos-delivery transport: {other}"),
    }
}

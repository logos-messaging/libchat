fn main() {
    println!("cargo:rerun-if-env-changed=LOGOS_DELIVERY_LIB_DIR");
    println!("cargo::rustc-check-cfg=cfg(logos_delivery)");

    let feature_enabled = std::env::var("CARGO_FEATURE_EMBEDDED_P2P_DELIVERY").is_ok();
    if !feature_enabled {
        return;
    }

    let lib_dir = std::env::var("LOGOS_DELIVERY_LIB_DIR")
        .ok()
        .or_else(nix_build_logos_delivery);

    let Some(lib_dir) = lib_dir else {
        // Feature is on but no library path — enable compilation, skip linking.
        println!("cargo:rustc-cfg=logos_delivery");
        return;
    };

    println!("cargo:rustc-cfg=logos_delivery");
    println!("cargo:rustc-link-search=native={lib_dir}");
    println!("cargo:rustc-link-lib=dylib=logosdelivery");
    println!("cargo:LIB_DIR={lib_dir}");

    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    match target_os.as_str() {
        "macos" | "linux" => println!("cargo:rustc-link-arg=-Wl,-rpath,{lib_dir}"),
        other => panic!("unsupported OS for logos-delivery transport: {other}"),
    }
}

fn nix_build_logos_delivery() -> Option<String> {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").ok()?;
    let flake_root = find_flake_root(&manifest_dir)?;

    println!("cargo:rerun-if-changed={flake_root}/flake.lock");

    let output = std::process::Command::new("nix")
        .args(["build", ".#logos-delivery", "--no-link", "--print-out-paths"])
        .current_dir(&flake_root)
        .output()
        .ok()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        println!("cargo:warning=nix build .#logos-delivery failed: {stderr}");
        return None;
    }

    let store_path = String::from_utf8(output.stdout).ok()?;
    let lib_dir = format!("{}/lib", store_path.trim());

    if std::path::Path::new(&lib_dir).exists() {
        Some(lib_dir)
    } else {
        None
    }
}

fn find_flake_root(start: &str) -> Option<String> {
    let mut path = std::path::PathBuf::from(start);
    loop {
        if path.join("flake.nix").exists() {
            return Some(path.to_string_lossy().into_owned());
        }
        if !path.pop() {
            return None;
        }
    }
}

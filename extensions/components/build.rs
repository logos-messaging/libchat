use std::fs;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=LOGOS_DELIVERY_LIB_DIR");
    println!("cargo::rustc-check-cfg=cfg(logos_delivery)");

    if std::env::var_os("CARGO_FEATURE_EMBEDDED_P2P_DELIVERY").is_none() {
        return;
    }

    // Locate the native library: explicit override first, then build via nix.
    let Some(lib_dir) = std::env::var("LOGOS_DELIVERY_LIB_DIR")
        .ok()
        .or_else(nix_build_logos_delivery)
    else {
        // Feature is on but the native library is unavailable (e.g. `cargo
        // check` on a machine without nix). Skip the cfg so the FFI module is
        // not compiled — this keeps `cargo check` working without producing
        // unresolved symbols at link time. `EmbeddedP2pDeliveryService` is
        // simply absent until the library can be found.
        return;
    };

    println!("cargo:rustc-cfg=logos_delivery");

    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR not set");
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();

    // The shipped library carries a relocatable install name (@rpath on macOS,
    // $ORIGIN soname on Linux), which would force every downstream BINARY to
    // inject its own RPATH. Cargo propagates `rustc-link-search` and
    // `rustc-link-lib` across crates, but NOT `rustc-link-arg` (the rpath) — so
    // that relocatable name is exactly what makes consumers need their own
    // build.rs. Instead, stamp a private copy with an ABSOLUTE install name;
    // the propagating search + lib directives are then sufficient and consumers
    // need zero build-script glue.
    match target_os.as_str() {
        "macos" => stamp_absolute_macos(&lib_dir, &out_dir),
        "linux" => stamp_absolute_linux(&lib_dir, &out_dir),
        other => panic!("unsupported OS for logos-delivery transport: {other}"),
    }

    println!("cargo:rustc-link-search=native={out_dir}");
    println!("cargo:rustc-link-lib=dylib=logosdelivery");
}

/// Copy `liblogosdelivery.dylib` into `OUT_DIR` and rewrite its install name to
/// the absolute store path. The consumer records that absolute path, so dyld
/// loads the original file directly — whose own `@loader_path` RPATH resolves
/// `librln.dylib` beside it — with no RPATH needed on the consumer.
fn stamp_absolute_macos(lib_dir: &str, out_dir: &str) {
    let src = format!("{lib_dir}/liblogosdelivery.dylib");
    let dst = format!("{out_dir}/liblogosdelivery.dylib");
    copy_writable(&src, &dst);
    run("install_name_tool", &["-id", &src, &dst]);
    println!("cargo:rerun-if-changed={src}");
}

/// Linux equivalent: an absolute `DT_SONAME` is recorded verbatim in the
/// consumer's `DT_NEEDED`, so `ld.so` loads it by path with no RPATH. Requires
/// `patchelf` at build time (provided by the nix devshell).
fn stamp_absolute_linux(lib_dir: &str, out_dir: &str) {
    let src = format!("{lib_dir}/liblogosdelivery.so");
    let dst = format!("{out_dir}/liblogosdelivery.so");
    copy_writable(&src, &dst);
    run("patchelf", &["--set-soname", &src, &dst]);
    println!("cargo:rerun-if-changed={src}");
}

fn copy_writable(src: &str, dst: &str) {
    use std::os::unix::fs::PermissionsExt;

    fs::copy(src, dst).unwrap_or_else(|e| panic!("copy {src} -> {dst}: {e}"));
    // Store-sourced files are read-only; restore owner write so the install
    // name / soname can be rewritten.
    fs::set_permissions(dst, fs::Permissions::from_mode(0o644)).unwrap();
}

fn run(cmd: &str, args: &[&str]) {
    let status = Command::new(cmd)
        .args(args)
        .status()
        .unwrap_or_else(|e| panic!("failed to run `{cmd}`: {e}"));
    assert!(status.success(), "`{cmd} {args:?}` failed with {status}");
}

fn nix_build_logos_delivery() -> Option<String> {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").ok()?;
    let flake_root = find_flake_root(&manifest_dir)?;

    println!("cargo:rerun-if-changed={flake_root}/flake.lock");

    let output = Command::new("nix")
        .args([
            "build",
            ".#logos-delivery",
            "--no-link",
            "--print-out-paths",
        ])
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

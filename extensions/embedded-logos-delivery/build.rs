use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=LOGOS_DELIVERY_LIB_DIR");

    let Some(lib_dir) = locate_lib_dir() else {
        println!(
            "cargo:warning=liblogosdelivery could not be located; `cargo check`/\
             `clippy` will pass, but building or testing will fail at link. Enter \
             the dev shell with `nix develop` or set LOGOS_DELIVERY_LIB_DIR to \
             the directory containing the library."
        );
        return;
    };

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

/// Locate the native library directory as an ABSOLUTE, canonical path. Prefers
/// `LOGOS_DELIVERY_LIB_DIR`, then falls back to building it via nix. Returns
/// `None` when neither is available (e.g. `cargo check` without nix).
fn locate_lib_dir() -> Option<PathBuf> {
    if let Ok(dir) = std::env::var("LOGOS_DELIVERY_LIB_DIR") {
        if let Some(resolved) = resolve_lib_dir(&dir) {
            return Some(resolved);
        }
        println!(
            "cargo:warning=LOGOS_DELIVERY_LIB_DIR='{dir}' could not be resolved; \
             falling back to `nix build`"
        );
    }
    resolve_lib_dir(&nix_build_logos_delivery()?)
}

/// Resolve a lib dir to an absolute, canonical path. Cargo runs build scripts
/// with the cwd set to the crate dir, but a relative value (e.g. CI's
/// `./result/lib`) is anchored at the flake/workspace root where `nix build`
/// drops `result`. Canonicalizing also follows the `result` symlink to the
/// immutable store path, so the stamped install name / soname stays stable.
fn resolve_lib_dir(dir: &str) -> Option<PathBuf> {
    let path = Path::new(dir);
    let anchored = if path.is_absolute() {
        path.to_path_buf()
    } else {
        let manifest = std::env::var("CARGO_MANIFEST_DIR").ok()?;
        Path::new(&find_flake_root(&manifest)?).join(path)
    };
    anchored.canonicalize().ok()
}

/// Copy `liblogosdelivery.dylib` into `OUT_DIR` and rewrite its install name to
/// the absolute store path. The consumer records that absolute path, so dyld
/// loads the original file directly — whose own `@loader_path` RPATH resolves
/// `librln.dylib` beside it — with no RPATH needed on the consumer.
fn stamp_absolute_macos(lib_dir: &Path, out_dir: &str) {
    let src = lib_dir.join("liblogosdelivery.dylib");
    let dst = format!("{out_dir}/liblogosdelivery.dylib");
    copy_writable(&src, Path::new(&dst));
    run("install_name_tool", &["-id", path_str(&src), &dst]);
    println!("cargo:rerun-if-changed={}", src.display());
}

/// Linux equivalent: an absolute `DT_SONAME` is recorded verbatim in the
/// consumer's `DT_NEEDED`, so `ld.so` loads it by path with no RPATH. Requires
/// `patchelf` at build time (provided by the nix devshell).
fn stamp_absolute_linux(lib_dir: &Path, out_dir: &str) {
    let src = lib_dir.join("liblogosdelivery.so");
    let dst = format!("{out_dir}/liblogosdelivery.so");
    copy_writable(&src, Path::new(&dst));
    run("patchelf", &["--set-soname", path_str(&src), &dst]);
    println!("cargo:rerun-if-changed={}", src.display());
}

fn path_str(p: &Path) -> &str {
    p.to_str()
        .unwrap_or_else(|| panic!("non-UTF-8 path: {}", p.display()))
}

fn copy_writable(src: &Path, dst: &Path) {
    use std::os::unix::fs::PermissionsExt;

    fs::copy(src, dst)
        .unwrap_or_else(|e| panic!("copy {} -> {}: {e}", src.display(), dst.display()));
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

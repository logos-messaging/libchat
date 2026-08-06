//! Links the macOS frameworks `waku-bindings` needs.
//!
//! Upstream declares them via `rustflags` in its own `.cargo/config.toml`,
//! which cargo ignores for a dependency, so the link fails on
//! `_SecRandomCopyBytes` from Nim's `std/sysrand` without this.
//!
//! `rustc-link-lib` rather than `rustc-link-arg`: rustc records it in crate
//! metadata, so dependents link the frameworks with no build script of their
//! own.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        println!("cargo:rustc-link-lib=framework=Security");
        println!("cargo:rustc-link-lib=framework=CoreFoundation");
    }
}

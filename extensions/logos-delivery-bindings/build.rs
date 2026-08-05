//! Supplies the macOS frameworks that `waku-bindings` cannot supply itself.
//!
//! Upstream carries `waku-bindings/.cargo/config.toml` with
//! `-framework CoreFoundation -framework Security`, but cargo only reads the
//! config of the workspace being built, never a dependency's. Consuming the
//! crate therefore drops those flags and the link fails on
//! `_SecRandomCopyBytes`, pulled in by Nim's `std/sysrand`.
//!
//! `rustc-link-lib` — rather than `rustc-link-arg`, or `rustflags` in a
//! `.cargo/config.toml` — is what makes this work for *dependents*: rustc
//! records the native library in this crate's metadata, so anything linking
//! `logos-delivery-bindings` (chat-cli via logos-chat, say) picks the
//! frameworks up transitively with no build script of its own. `rustflags`
//! would instead apply globally and force every crate in the workspace to
//! recompile.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        println!("cargo:rustc-link-lib=framework=Security");
        println!("cargo:rustc-link-lib=framework=CoreFoundation");
    }
}

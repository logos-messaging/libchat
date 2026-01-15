pub mod doubleratchet;
pub mod key;
pub mod utils;

#[cfg(feature = "headers")]
pub fn generate_headers() -> std::io::Result<()> {
    safer_ffi::headers::builder()
        .to_file("double_ratchet.h")?
        .generate()
}

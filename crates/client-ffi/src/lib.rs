mod api;
mod delivery;

#[cfg(feature = "headers")]
pub fn generate_headers(path: &str) -> std::io::Result<()> {
    safer_ffi::headers::builder().to_file(path)?.generate()
}

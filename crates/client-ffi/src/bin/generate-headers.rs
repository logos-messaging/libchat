fn main() -> std::io::Result<()> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "client_ffi.h".into());
    client_ffi::generate_headers(&path)
}

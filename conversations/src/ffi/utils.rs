use safer_ffi::prelude::*;

#[derive_ReprC]
#[repr(C)]
pub struct CResult<T: ReprC, Err: ReprC> {
    pub ok: Option<T>,
    pub err: Option<Err>,
}

#[ffi_export]
pub fn destroy_string(s: repr_c::String) {
    drop(s);
}

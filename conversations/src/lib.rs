mod api;
mod context;
mod conversation;
mod crypto;
mod errors;
mod identity;
mod inbox;
mod proto;
mod types;
mod utils;

pub use api::*;

#[cfg(test)]
mod tests {

    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_ffi() {}

    #[test]
    fn test_invite_convo() {
        let mut ctx = create_context();
        let mut bundle = vec![0u8; 200];

        let bundle_len = create_intro_bundle(&mut ctx, (&mut bundle[..]).into());
        unsafe {
            bundle.set_len(bundle_len as usize);
        }

        assert!(bundle_len > 0, "bundle failed: {}", bundle_len);
        let content = String::from_str("Hello").unwrap();
        let result = create_new_private_convo(
            &mut ctx,
            bundle.as_slice().into(),
            content.as_bytes().into(),
        );

        assert!(result.error_code == 0, "Error: {}", result.error_code);

        println!(" ID:{:?}   Payloads:{:?}", result.convo_id, result.payloads);

        destroy_context(ctx);
    }
}

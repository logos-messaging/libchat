mod api;
mod context;
mod conversation;
mod crypto;
mod errors;
mod identity;
mod inbox;
mod proto;
mod storage;
mod types;
mod utils;

pub use api::*;
pub use context::{Context, Introduction};
pub use errors::ChatError;

#[cfg(feature = "headers")]
pub fn generate_headers() -> std::io::Result<()> {
    safer_ffi::headers::builder()
        .to_file("libchat.h")?
        .generate()
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_ffi() {}

    #[test]
    fn test_message_roundtrip() {
        let mut saro = create_context(b"saro".as_slice().into());
        let mut raya = create_context(b"raya".as_slice().into());

        // Raya Creates Bundle and Sends to Saro
        let mut intro_result = CreateIntroResult {
            error_code: -99,
            intro_bytes: safer_ffi::Vec::EMPTY,
        };
        create_intro_bundle(&mut raya, &mut intro_result);
        assert!(is_ok(intro_result.error_code));

        let raya_bundle = intro_result.intro_bytes.as_ref();

        // Saro creates a new conversation with Raya
        let content: &[u8] = "hello".as_bytes();

        let mut convo_result = NewConvoResult {
            error_code: -99,
            convo_id: "".into(),
            payloads: safer_ffi::Vec::EMPTY,
        };
        create_new_private_convo(&mut saro, raya_bundle, content.into(), &mut convo_result);
        assert!(is_ok(convo_result.error_code));

        // Raya recieves initial message
        let payload = convo_result.payloads.first().unwrap();

        let mut handle_result: HandlePayloadResult = HandlePayloadResult {
            error_code: -99,
            convo_id: "".into(),
            content: safer_ffi::Vec::EMPTY,
            is_new_convo: false,
        };
        handle_payload(&mut raya, payload.data.as_ref(), &mut handle_result);
        assert!(is_ok(handle_result.error_code));

        // Check that the Content sent was the content received
        assert!(handle_result.content.as_ref().as_slice() == content);

        destroy_context(saro);
        destroy_context(raya);
    }
}

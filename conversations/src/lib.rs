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

    #[test]
    fn test_ffi() {}

    #[test]
    fn test_message_roundtrip() {
        let mut saro = create_context("saro".into());
        let mut raya = create_context("raya".into());

        // Raya Creates Bundle and Sends to Saro
        let intro_result = create_intro_bundle(&mut raya);
        assert!(is_ok(intro_result.error_code));

        let raya_bundle = intro_result.intro_bytes.as_ref();

        // Saro creates a new conversation with Raya
        let content: &[u8] = "hello".as_bytes();

        let convo_result = create_new_private_convo(&mut saro, raya_bundle, content.into());
        assert!(is_ok(convo_result.error_code));

        // Raya recieves initial message
        let payload = convo_result.payloads.first().unwrap();

        let handle_result = handle_payload(&mut raya, payload.data.as_ref());
        assert!(is_ok(handle_result.error_code));

        // Check that the Content sent was the content received
        assert!(handle_result.content.as_ref().as_slice() == content);

        destroy_context(saro);
        destroy_context(raya);
    }
}

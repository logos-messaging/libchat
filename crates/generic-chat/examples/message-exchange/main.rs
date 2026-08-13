use components::EphemeralRegistry;
use logos_account::TestLogosAccount;
use logos_generic_chat::{
    ChatClientBuilder, DelegateSigner, Event, InProcessDelivery, LogosAuthVerifier, MessageBus,
};
use std::time::Duration;

fn main() {
    let bus = MessageBus::default();
    let reg = EphemeralRegistry::new();

    // Mint two accounts, each endorsing a delegate signer, so a peer can resolve
    // an account address to its device.
    let mut saro_account = TestLogosAccount::new(reg.clone());
    let saro_delegate = DelegateSigner::random();
    saro_account
        .endorse_ed25519_signer(saro_delegate.public_key())
        .unwrap();

    let mut raya_account = TestLogosAccount::new(reg.clone());
    let raya_delegate = DelegateSigner::random();
    raya_account
        .endorse_ed25519_signer(raya_delegate.public_key())
        .unwrap();

    let (mut saro, saro_events) = ChatClientBuilder::new(saro_account.address().to_bytes())
        .auth(LogosAuthVerifier::new())
        .ident(saro_delegate)
        .transport(InProcessDelivery::new(bus.clone()))
        .registration(reg.clone())
        .build()
        .unwrap();

    let (mut raya, raya_events) = ChatClientBuilder::new(raya_account.address().to_bytes())
        .auth(LogosAuthVerifier::new())
        .ident(raya_delegate)
        .transport(InProcessDelivery::new(bus))
        .registration(reg)
        .build()
        .unwrap();

    // Saro opens a direct conversation with Raya by her account address.
    let saro_convo_id = saro.create_direct_conversation(raya.addr()).unwrap();

    // Wait for Raya to process the Welcome and subscribe before Saro sends, since
    // InProcessDelivery only fans out to current subscribers.
    let raya_convo_id = match raya_events.recv_timeout(Duration::from_secs(5)).unwrap() {
        Event::ConversationStarted { convo_id, .. } => convo_id,
        other => panic!("expected ConversationStarted, got {other:?}"),
    };

    saro.send_message(&saro_convo_id, b"hello raya").unwrap();
    if let Event::MessageReceived { content, .. } =
        raya_events.recv_timeout(Duration::from_secs(5)).unwrap()
    {
        println!(
            "Raya received: {:?}",
            std::str::from_utf8(&content).unwrap()
        );
    }

    raya.send_message(&raya_convo_id, b"hi saro").unwrap();
    if let Event::MessageReceived { content, .. } =
        saro_events.recv_timeout(Duration::from_secs(5)).unwrap()
    {
        println!(
            "Saro received: {:?}",
            std::str::from_utf8(&content).unwrap()
        );
    }

    println!("Message exchange complete.");
}

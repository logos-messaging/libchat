# message-exchange

An example Rust application built on top of [`crates/client`](../../).

It demonstrates that creating a working chat client in pure Rust is trivial: depend on
`crates/client`, pick a `DeliveryService` implementation (here the in-memory
`InProcessDelivery` shipped with the crate), and wire up `ChatClient`. No boilerplate, no FFI.

## Running

```
cargo run --example message-exchange
```

The binary performs a message exchange entirely in-process and prints
the exchanged messages to stdout.

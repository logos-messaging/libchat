# libchat
Supporting library for Logos-chat

## Example app

[`bin/chat-cli`](bin/chat-cli/) is an end-to-end encrypted CLI chat app
built on this library.  It uses [logos-delivery](https://github.com/logos-messaging/logos-delivery)
(Waku-based) as the transport so two users anywhere in the world can chat by
sharing an intro bundle.

```sh
# Build logos-delivery with Nix
nix build .#logos-delivery
# Build chat-cli with Cargo
LOGOS_DELIVERY_LIB_DIR=./result/lib cargo build --release -p chat-cli
# Run binary
./target/release/chat-cli --name alice
```

See [`bin/chat-cli/README.md`](bin/chat-cli/README.md) for full build,
run, and test instructions.

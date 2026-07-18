# libchat
Supporting library for Logos-chat

## Example app

[`bin/chat-cli`](bin/chat-cli/) is an end-to-end encrypted CLI chat app
built on this library. With `--transport logos-delivery` it rides
[logos-delivery](https://github.com/logos-messaging/logos-delivery) (Waku-based),
so two users anywhere in the world can chat by sharing an intro bundle. A local
file transport is bundled in and is the default; pick at runtime with
`--transport <logos-delivery|file>`.

```sh
# Fetch the logos-delivery bindings and their Nim sources
git submodule update --init --recursive
# Build (the first build compiles the Nim tree and is slow)
nix develop -c cargo build --release -p chat-cli
# Run
./target/release/chat-cli --name alice --transport logos-delivery
```

[`bin/channel-chat`](bin/channel-chat/) is a smaller example: a room chat built
directly on logos-delivery's reliable channels API, with no encryption or
libchat stack in the way.

See [`bin/chat-cli/README.md`](bin/chat-cli/README.md) for full build,
run, and test instructions.

## logos-delivery

The native node is reached through
[`waku-bindings`](vendor/logos-delivery-rust-bindings), pinned as a submodule.
Its build script compiles `liblogosdelivery` from the Nim sources in its own
`vendor/` submodule, so a recursive checkout and the `nix develop` toolchain are
what a build needs — there is no prebuilt library to point at.

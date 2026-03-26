# message-exchange

An example C application built on top of [`crates/client-ffi`](../../).

It demonstrates that the C ABI exposed by `crates/client-ffi` is straightforward to
consume from plain C — or from any language that can call into a C ABI. No Rust code,
no Cargo project: just a C source file linked against the pre-built static library.

## Building and running

```sh
make        # builds client-ffi with Cargo, then compiles src/main.c
make run    # build + execute
make clean  # remove the compiled binary
```

For a release build:

```sh
make CARGO_PROFILE=release
```

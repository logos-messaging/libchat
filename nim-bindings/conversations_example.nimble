# Package

version       = "0.1.0"
author        = "libchat"
description   = "Nim Bindings for LibChat"
license       = "MIT"
srcDir        = "src"
bin           = @["libchat"]


# Dependencies

requires "nim >= 2.2.4"
requires "results"

# Build Rust library before compiling Nim
before build:
  exec "cargo build --release --manifest-path ../Cargo.toml"

task pingpong, "Run pingpong example":
  exec "nim c -r --path:src examples/pingpong.nim"
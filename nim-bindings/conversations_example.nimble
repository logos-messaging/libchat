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

proc buildRust() =
  exec "cargo build --release --manifest-path ../Cargo.toml"


# Build Rust library before compiling Nim
before build:
  buildRust()

task pingpong, "Run pingpong example":
  buildRust()
  exec "nim c -r --path:src --passL:../target/release/liblibchat.a examples/pingpong.nim"

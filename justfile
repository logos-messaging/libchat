# The first receipt is the default task, run with `just`
build:
  cargo build

test:
  cargo test

# Run all examples
run-examples:
  cargo run --example double_ratchet_basic
  cargo run --example serialization_demo
  cargo run --example storage_demo
  cargo run --example out_of_order_demo

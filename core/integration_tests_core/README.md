This crate is dedicated to backend integration tests.

Tests can be built using any supplied service implementation.
Various implementations are available in the `Extensions/components` crate.

## Running Tests

Integration tests are executed when running `cargo test` from the workspace folder.

Alternatively they can be executed from any crate, using 

`cargo test --package integration_tests_core`

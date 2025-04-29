# Fuzz Testing for MMS

1. Install the nightly compiler: `rustup install nightly`
2. Install `cargo-fuzz`: `cargo install cargo-fuzz`
3. Start testing: `cargo fuzz run <test>`. Available tests are located in the `fuzz_targets` directory. E.g. `cargo fuzz run protocol-decode`.

Note that this is a standalone Rust crate and is not built as part of the mono-repo workspace. Fuzz testing requires a nightly compiler and should be run for hours; the longer the better.

See [Rust Fuzz Book](https://rust-fuzz.github.io/book/cargo-fuzz.html) for more info.

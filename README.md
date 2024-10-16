[![codecov](https://codecov.io/gh/spacemeshos/post-rs/branch/main/graph/badge.svg?token=iwM4ELLV7a)](https://codecov.io/gh/spacemeshos/post-rs)

# Rust implementation of PoST protocol

👉 Refer to <https://github.com/spacemeshos/protocol/blob/master/post.md> for more information on Proof of Space-Time
protocol.

Includes:

- initializing data:
  - on CPU with [scrypt-jane](https://github.com/floodyberry/scrypt-jane)
  - on GPU with OpenCL
- generating PoST
- verifying PoST

## Build dependencies

### Bindgen

[Bindgen](https://rust-lang.github.io/rust-bindgen/introduction.html) is required to generate bindings to C for calling
the scrypt-jane C library (indirect dependency from [scrypt-jane-rs](https://github.com/spacemeshos/scrypt-jane-rs)). It
depends on **clang**. Follow [these
instructions](https://rust-lang.github.io/rust-bindgen/requirements.html#installing-clang) to install it.

### Randomx-rs

[RandomX](https://github.com/tevador/randomx), that [randomx-rs](https://github.com/spacemeshos/randomx-rs) depends on,
requires **cmake**. Follow [these instructions](https://github.com/spacemeshos/randomx-rs#build-dependencies) to install
it.

## Post Service

Please refer to [service README](service/README.md) for instructions.

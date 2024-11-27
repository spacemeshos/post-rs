FROM rust:1 AS chef

RUN cargo install cargo-chef
RUN apt-get update && apt-get install -y\
    llvm-dev \
    libclang-dev \
    clang \
    cmake \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /certifier

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /certifier/recipe.json recipe.json
RUN cargo chef cook --release -p certifier --recipe-path recipe.json

COPY . .
RUN cargo build --release -p certifier --bin certifier

FROM debian:bookworm-slim AS runtime
WORKDIR /certifier
COPY --from=builder /certifier/target/release/certifier /usr/local/bin
RUN set -ex \
    && apt-get update --fix-missing \
    && apt-get install -qy --no-install-recommends \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*
ENTRYPOINT ["/usr/local/bin/certifier"]

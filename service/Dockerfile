FROM rust:1 AS chef

RUN cargo install cargo-chef
RUN apt-get update && apt-get install -y\
    llvm-dev \
    libclang-dev \
    clang \
    cmake \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /service

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /service/recipe.json recipe.json
RUN cargo chef cook --release -p service --recipe-path recipe.json

COPY . .
RUN cargo build --release -p service --bin post-service

FROM debian:bookworm-slim AS runtime
WORKDIR /service
COPY --from=builder /service/target/release/post-service /usr/local/bin
RUN apt-get update && apt-get install -y\
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*
ENTRYPOINT ["/usr/local/bin/post-service"]

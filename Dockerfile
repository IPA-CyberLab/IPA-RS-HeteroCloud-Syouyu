# syntax=docker/dockerfile:1.7
FROM rust:1.96.1-bookworm AS builder

WORKDIR /source
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates
COPY migrations ./migrations
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/source/target \
    cargo build --locked --release --bin syouyu-api && \
    install -D -m 0755 target/release/syouyu-api /output/syouyu-api

FROM debian:bookworm-slim AS runtime
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates curl jq && \
    rm -rf /var/lib/apt/lists/* && \
    useradd --system --uid 65532 --home-dir /nonexistent --shell /usr/sbin/nologin syouyu
COPY --from=builder /output/syouyu-api /usr/local/bin/syouyu-api
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/syouyu-api"]

FROM rust:1-bookworm AS builder

WORKDIR /app
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY src ./src

RUN cargo build --release

FROM debian:bookworm-slim

RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /app/target/release/stealth-gate /usr/local/bin/stealth-gate
COPY configs ./configs
COPY web ./web

EXPOSE 443

ENTRYPOINT ["stealth-gate"]
CMD ["--config", "/app/configs/config.toml"]

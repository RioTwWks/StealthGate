FROM rust:1-bookworm AS builder

WORKDIR /app
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY src ./src

RUN cargo build --release --bins

FROM debian:bookworm-slim

RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /app/target/release/stealth-gate /usr/local/bin/stealth-gate
COPY --from=builder /app/target/release/stealth-gate-mcp /usr/local/bin/stealth-gate-mcp
COPY configs ./configs
COPY web ./web
RUN mkdir -p /app/data /app/certs

EXPOSE 443 8088 9091

ENTRYPOINT ["stealth-gate"]
CMD ["--config", "/app/configs/config.toml"]

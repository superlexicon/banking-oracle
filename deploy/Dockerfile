FROM rust:1.82-bookworm AS builder
WORKDIR /build
COPY Cargo.toml ./
COPY src ./src
RUN cargo build --release --bin banking-oracle

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
RUN useradd -r -s /usr/sbin/nologin banking-oracle && mkdir -p /var/lib/banking-oracle /etc/banking-oracle && chown -R banking-oracle:banking-oracle /var/lib/banking-oracle
COPY --from=builder /build/target/release/banking-oracle /usr/local/bin/banking-oracle
USER banking-oracle
EXPOSE 9088
ENTRYPOINT ["/usr/local/bin/banking-oracle"]
CMD ["--config=/etc/banking-oracle/config.json"]

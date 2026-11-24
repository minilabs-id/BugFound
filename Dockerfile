# syntax=docker/dockerfile:1

# ---------- builder ----------
FROM rust:1.90-slim AS builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        pkg-config \
        libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy manifests first so Cargo can cache dependency compilation.
# Cargo.lock is committed: --locked keeps builds reproducible.
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

RUN cargo build --release --locked -p bugfound-cli

# ---------- runtime ----------
FROM debian:bookworm-slim AS runtime

# ca-certificates is required for HTTPS calls to the OpenAI-compatible LLM API.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system bugfound \
    && useradd --system --gid bugfound --home-dir /home/bugfound --create-home bugfound \
    && mkdir -p /work \
    && chown bugfound:bugfound /work

COPY --from=builder /build/target/release/bugfound /usr/local/bin/bugfound

# No credentials are baked into the image: the API key is read from the
# environment at runtime (llm.api_key = "env:OPENAI_API_KEY" in bugfound.toml).
ENV RUST_LOG=info
WORKDIR /work
USER bugfound

ENTRYPOINT ["bugfound"]

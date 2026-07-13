# syntax=docker/dockerfile:1
#
# Linux container image for facet.
#
# Two stages: build against the full toolchain, ship a ~10 MB runtime image with
# nothing in it but the binary and a CA bundle. The web UI is compiled *into*
# the binary by rust-embed, so there are no static assets to COPY.

# --- build -----------------------------------------------------------------
FROM rust:1-slim-bookworm AS build

# `ring` (rustls) compiles a little assembly, so it needs a C toolchain. That is
# the only system dependency: no OpenSSL, no CMake, no NASM anywhere in the tree.
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Cache dependencies separately from source. Without this, touching one .rs file
# rebuilds every crate in the tree.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs \
    && cargo build --release --locked \
    && rm -rf src

COPY src ./src
COPY assets ./assets

# `touch` defeats the cargo cache above, which still thinks main.rs is the stub.
RUN touch src/main.rs && cargo build --release --locked

# --- runtime ---------------------------------------------------------------
FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --shell /bin/bash facet

COPY --from=build /build/target/release/facet /usr/local/bin/facet

# Run as a normal user. This matters more here than in most images: facet spawns
# a shell, and that shell inherits this identity. As root, a login would hand out
# a root shell in the container.
# The working directory *is* the volume. This matters: `facet setup` writes the
# certificate to a path relative to the cwd (`certs/cert.pem`), so with a cwd
# outside the volume the cert would be written into the container's ephemeral
# layer and lost on the next restart.
RUN mkdir -p /home/facet/data && chown -R facet:facet /home/facet

USER facet
WORKDIR /home/facet/data

# Config, certificate and audit log all live here. Mount a volume to keep them.
VOLUME ["/home/facet/data"]
ENV FACET_LOG=facet=info,audit=info

EXPOSE 7443

# In a container the port must be reachable from outside it, so bind 0.0.0.0,
# and then only publish it somewhere you trust. See "Exposing it safely" in the
# README: -p 127.0.0.1:7443:7443 keeps it on the host's loopback.
ENTRYPOINT ["facet", "--config", "/home/facet/data/facet.toml"]
CMD ["run"]

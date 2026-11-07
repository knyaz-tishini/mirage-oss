# syntax=docker/dockerfile:1
#
# The server image. Build context is this repository: the libraries and
# m1r4g3-server live in one tree.
#
#   docker build -t m1r4g3-server:1 .
#
# scripts/build-image.ps1 does that and can save the tar the client ships.
# The perimeter and the node run as ONE container: they talk over unix
# sockets under /run/mirage, which needs one mount namespace, and the
# perimeter owns the host's ports (network_mode: host).

# ── builder ────────────────────────────────────────────────────────────────
FROM rust:1.99.1-bookworm AS builder

# cmake is not optional: rustls pulls aws-lc-sys, and its build script drives
# a C/C++ library through cmake. The rust image ships gcc and make, not cmake.
RUN apt-get update \
 && apt-get install -y --no-install-recommends cmake \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . /src

ENV CARGO_TERM_COLOR=never
# The target dir is pinned so the binary lands in one known place.
ENV CARGO_TARGET_DIR=/src/target
# How many rustc processes may run at once. Left empty, cargo uses every
# core — right for a build machine, wrong for a small VPS or a busy host,
# where the linker runs out of memory. Set it with
#   --build-arg CARGO_BUILD_JOBS=2
ARG CARGO_BUILD_JOBS
ENV CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS}
# The box has no database of its own, so no sqlcipher and no openssl: the
# plain bundled sqlite is enough and the image stays buildable without perl.
RUN cargo build --release -p mirage-standalone --bin m1r4g3-server \
 && strip /src/target/release/m1r4g3-server

# ── runtime ────────────────────────────────────────────────────────────────
FROM debian:bookworm-slim

# ca-certificates: the box may resolve through DoH over TLS.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*

COPY --from=builder /src/target/release/m1r4g3-server /usr/local/bin/m1r4g3-server
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
# A CRLF shebang makes the kernel look for an interpreter that does not exist
# ("no such file or directory") — so the endings are normalised here, whatever
# the build context did to the file.
RUN sed -i 's/\r$//' /usr/local/bin/entrypoint.sh \
 && chmod +x /usr/local/bin/entrypoint.sh

# The only mutable place: the box's own keys and the one artefact line.
VOLUME ["/data"]
# The perimeter and the node talk over unix sockets here.
RUN mkdir -p /run/mirage

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["run"]

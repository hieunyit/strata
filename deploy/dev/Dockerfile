# Strata dev/CI image: Rust toolchain, cbindgen, Hyperscan, NGINX build deps, Test::Nginx.
# Used both locally (deploy/dev/run.sh) and in GitHub Actions.
FROM ubuntu:24.04

ARG RUST_VERSION=1.98.0
ARG CBINDGEN_VERSION=0.29.4

ENV DEBIAN_FRONTEND=noninteractive \
    RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH \
    HOME=/tmp

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential ca-certificates curl git pkg-config \
        libpcre2-dev zlib1g-dev libssl-dev \
        libhyperscan-dev valgrind wrk strace procps \
        perl cpanminus libwww-perl libtext-diff-perl libtest-longstring-perl \
        liblist-moreutils-perl libipc-run-perl libtest-base-perl \
    && rm -rf /var/lib/apt/lists/*

RUN cpanm --notest Test::Nginx && rm -rf /root/.cpanm

RUN curl -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path \
        --profile minimal --default-toolchain ${RUST_VERSION} \
        --component clippy --component rustfmt \
    && cargo install --locked cbindgen --version ${CBINDGEN_VERSION} \
    && rm -rf ${CARGO_HOME}/registry ${CARGO_HOME}/git \
    && chmod -R a+rwX ${CARGO_HOME} ${RUSTUP_HOME}

WORKDIR /src

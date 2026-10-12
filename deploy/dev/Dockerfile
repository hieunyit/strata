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
        libhyperscan-dev valgrind wrk strace procps clang-tidy \
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

# Go for strata-agent, control-plane and tests/e2e, plus the proto and lint
# tools. GOPATH and the build cache live under /tmp (HOME), so they are
# writable for any uid; deploy/dev/run.sh points them at build/go.
ARG GO_VERSION=1.25.14
ARG GO_SHA256=a21ae5633a269bcd7e90cf767e48225633795e99d831742cbf3397064fee7712
ARG BUF_VERSION=1.34.0
ARG PROTOC_GEN_GO_VERSION=1.34.2
ARG PROTOC_GEN_GO_GRPC_VERSION=1.5.1
ARG GRPC_GATEWAY_VERSION=2.22.0
ARG GOLANGCI_LINT_VERSION=2.5.0
ENV PATH=/usr/local/go/bin:/usr/local/gotools/bin:$PATH
RUN curl -fsSL -o /tmp/go.tgz https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz \
    && echo "${GO_SHA256}  /tmp/go.tgz" | sha256sum -c - \
    && tar -C /usr/local -xzf /tmp/go.tgz && rm /tmp/go.tgz \
    && GOBIN=/usr/local/gotools/bin GOPATH=/tmp/gopath GOCACHE=/tmp/gocache GOTOOLCHAIN=local sh -c '\
        go install github.com/bufbuild/buf/cmd/buf@v${BUF_VERSION} \
        && go install google.golang.org/protobuf/cmd/protoc-gen-go@v${PROTOC_GEN_GO_VERSION} \
        && go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v${PROTOC_GEN_GO_GRPC_VERSION} \
        && go install github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-grpc-gateway@v${GRPC_GATEWAY_VERSION} \
        && go install github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-openapiv2@v${GRPC_GATEWAY_VERSION} \
        && go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v${GOLANGCI_LINT_VERSION}' \
    && rm -rf /tmp/gopath /tmp/gocache
ENV GOTOOLCHAIN=local

WORKDIR /src

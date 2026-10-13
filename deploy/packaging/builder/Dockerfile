# Builder of the packaged module (W10-N-01). The module links libstrata and
# Hyperscan statically but libc dynamically, so it runs on every system
# with a glibc at least as old as the one it was built on: Rocky Linux 9
# (glibc 2.34, supported until 2032) covers RHEL/Rocky 9, Ubuntu 22.04 and
# 24.04, Debian 12. The dev image (Ubuntu 24.04) would need glibc 2.39.
#
# Hyperscan must be the very build the bundle compiler uses: a bundle
# records hs_version() ("5.4.2 2024-04-19", build date included) and the
# module refuses one made by another build ("bundle built for another
# Hyperscan version"). The compiler runs in the dev image with Ubuntu's
# libhyperscan-dev 5.4.2-2, so the static libraries come from that package;
# they need glibc 2.34 at most. deploy/packaging/build.sh checks both the
# glibc floor and that the version string matches the dev image's.
FROM ubuntu:24.04 AS hs
ARG HS_DEB_VERSION=5.4.2-2
RUN apt-get update -qq \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
        "libhyperscan-dev=${HS_DEB_VERSION}" >/dev/null \
    && rm -rf /var/lib/apt/lists/*

FROM rockylinux:9
ARG RUST_VERSION=1.98.0
ENV RUSTUP_HOME=/usr/local/rustup CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH HOME=/tmp
RUN dnf install -y -q gcc gcc-c++ make pkgconf-pkg-config pcre2-devel zlib-devel openssl-devel binutils perl \
    && dnf clean all
COPY --from=hs /usr/lib/x86_64-linux-gnu/libhs.a /usr/lib/x86_64-linux-gnu/libhs_runtime.a /usr/local/lib/
COPY --from=hs /usr/include/hs /usr/local/include/hs
RUN curl -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path --profile minimal --default-toolchain ${RUST_VERSION} \
    && chmod -R a+rwX ${CARGO_HOME} ${RUSTUP_HOME}
# engine/ffi/hyperscan/build.rs links from here
ENV HS_LIB_DIR=/usr/local/lib
WORKDIR /src

# Builder of the packaged module (W10-N-01). The module links libstrata and
# Hyperscan statically but libc dynamically, so it runs on every system
# with a glibc at least as old as the one it was built on: Rocky Linux 9
# (glibc 2.34, supported until 2032) covers RHEL/Rocky 9, Ubuntu 22.04 and
# 24.04, Debian 12. The dev image (Ubuntu 24.04) would need glibc 2.39.
# Hyperscan is the very version the bundle compiler uses (the dev image's
# libhyperscan-dev 5.4.2): a serialized database only loads into the same
# version. Built like the Debian package: static, fat runtime (code for each
# x86 level, picked at run time).
FROM rockylinux:9
ARG RUST_VERSION=1.98.0
ARG HS_VERSION=5.4.2
ARG HS_SHA256=32b0f24b3113bbc46b6bfaa05cf7cf45840b6b59333d078cc1f624e4c40b2b99
ENV RUSTUP_HOME=/usr/local/rustup CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH HOME=/tmp
RUN dnf install -y -q epel-release dnf-plugins-core && dnf config-manager --set-enabled crb \
    && dnf install -y -q gcc gcc-c++ make cmake ragel boost-devel python3 pkgconf-pkg-config \
        pcre2-devel zlib-devel openssl-devel binutils perl \
    && dnf clean all
RUN curl -fsSL -o /tmp/hs.tgz https://github.com/intel/hyperscan/archive/refs/tags/v${HS_VERSION}.tar.gz \
    && echo "${HS_SHA256}  /tmp/hs.tgz" | sha256sum -c - \
    && mkdir /tmp/hs && tar -xzf /tmp/hs.tgz -C /tmp/hs --strip-components=1 \
    && cmake -S /tmp/hs -B /tmp/hs/build -DCMAKE_BUILD_TYPE=Release -DFAT_RUNTIME=ON \
        -DBUILD_STATIC_LIBS=ON -DCMAKE_INSTALL_PREFIX=/usr/local -DCMAKE_POSITION_INDEPENDENT_CODE=ON >/dev/null \
    && make -C /tmp/hs/build -j"$(nproc)" hs hs_runtime >/dev/null \
    && install -d /usr/local/include/hs /usr/local/lib/pkgconfig \
    && install -m 0644 /tmp/hs/build/lib/libhs.a /tmp/hs/build/lib/libhs_runtime.a /usr/local/lib/ \
    && install -m 0644 /tmp/hs/src/hs.h /tmp/hs/src/hs_common.h /tmp/hs/src/hs_compile.h /tmp/hs/src/hs_runtime.h /usr/local/include/hs/ \
    && install -m 0644 /tmp/hs/build/libhs.pc /usr/local/lib/pkgconfig/ \
    && rm -rf /tmp/hs /tmp/hs.tgz
RUN curl -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path --profile minimal --default-toolchain ${RUST_VERSION} \
    && chmod -R a+rwX ${CARGO_HOME} ${RUSTUP_HOME}
WORKDIR /src

# Strata developer entry points. Run inside the dev image:
#   deploy/dev/run.sh make <target>

NGINX_STABLE   ?= 1.30.5
NGINX_MAINLINE ?= 1.31.6
NGINX_VERSION  ?= $(NGINX_STABLE)
BUILD          ?= build
CARGO_FEATURES ?= --features test-hooks

HEADER     := engine/ffi/strata.h
NGX_HEADER := connectors/nginx/include/strata.h
LIBSTRATA  := target/release/libstrata.a
NGX_OBJS   := $(BUILD)/nginx-$(NGINX_VERSION)/objs
RUST_LIBS  := -lpthread -ldl -lm

.PHONY: all lib header check-header rust-check abi-test nginx test-nginx test poc clean

all: lib nginx

lib:
	cargo build --release -p libstrata $(CARGO_FEATURES)

header:
	cbindgen --quiet --config engine/ffi/cbindgen.toml --crate libstrata --output $(HEADER) engine/ffi
	cp $(HEADER) $(NGX_HEADER)

# Fails when the committed headers differ from what the Rust sources produce.
check-header:
	cbindgen --quiet --config engine/ffi/cbindgen.toml --crate libstrata --output $(BUILD)/strata.h engine/ffi
	diff -u $(HEADER) $(BUILD)/strata.h
	diff -u $(HEADER) $(NGX_HEADER)

rust-check:
	cargo fmt --all --check
	cargo clippy --workspace --all-targets --all-features -- -D warnings
	cargo test -p libstrata --all-features

abi-test: lib
	@mkdir -p $(BUILD)
	$(CC) -std=c11 -Wall -Wextra -Werror -DSTRATA_TEST_HOOKS -Iengine/ffi \
		engine/ffi/tests/c/abi_test.c $(LIBSTRATA) $(RUST_LIBS) -o $(BUILD)/abi_test
	$(BUILD)/abi_test

nginx: lib
	connectors/nginx/scripts/build.sh $(NGINX_VERSION) $(BUILD)

test-nginx:
	PATH="$(CURDIR)/$(NGX_OBJS):$$PATH" \
	TEST_NGINX_STRATA_MODULE="$(CURDIR)/$(NGX_OBJS)/ngx_http_strata_module.so" \
		prove -r connectors/nginx/t/

test: rust-check check-header abi-test nginx test-nginx

poc:
	$(MAKE) -C engine/poc/hs_mmap run

clean:
	cargo clean
	rm -rf $(BUILD)

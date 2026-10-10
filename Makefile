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
RUST_LIBS  := -lstdc++ -lpthread -ldl -lm

NGX_ASAN_OBJS := $(BUILD)/nginx-$(NGINX_VERSION)-asan/objs
ASAN_LOGS     := $(CURDIR)/$(BUILD)/asan

MKBUNDLE := target/release/mkbundle
COMPILE  := target/release/strata-compile
FIXTURES := connectors/nginx/t/fixtures

.PHONY: FORCE fixtures check-fixtures all lib header check-header rust-check abi-test nginx test-nginx test poc clean \
	nginx-asan test-nginx-asan test-nginx-valgrind bench-reload check-strace bench-pss \
	proto check-proto test-agent

all: lib nginx

lib:
	cargo build --release -p libstrata-ffi $(CARGO_FEATURES)

# Always ask cargo: it rebuilds only when the sources changed.
$(MKBUNDLE) $(COMPILE): FORCE
	cargo build --release -p mkbundle -p strata-compiler

FORCE:

fixtures: $(MKBUNDLE) $(COMPILE)
	$(FIXTURES)/make.sh $(CURDIR)/target/release

# Fixtures are deterministic: regenerating must not change committed files.
check-fixtures: fixtures
	git diff --exit-code -- $(FIXTURES)

header:
	cbindgen --quiet --config engine/ffi/cbindgen.toml --crate libstrata-ffi --output $(HEADER) engine/ffi
	cp $(HEADER) $(NGX_HEADER)

# Fails when the committed headers differ from what the Rust sources produce.
check-header:
	cbindgen --quiet --config engine/ffi/cbindgen.toml --crate libstrata-ffi --output $(BUILD)/strata.h engine/ffi
	diff -u $(HEADER) $(BUILD)/strata.h
	diff -u $(HEADER) $(NGX_HEADER)

rust-check:
	cargo fmt --all --check
	cargo clippy --workspace --all-targets --all-features -- -D warnings
	cargo test --workspace --all-features
	# slow tests, optimized build (10 million Block IDs, ...)
	cargo test --release -p libstrata -- --ignored

abi-test: lib
	@mkdir -p $(BUILD)
	$(CC) -std=c11 -Wall -Wextra -Werror -DSTRATA_TEST_HOOKS -Iengine/ffi \
		engine/ffi/tests/c/abi_test.c $(LIBSTRATA) $(RUST_LIBS) -o $(BUILD)/abi_test
	$(BUILD)/abi_test $(FIXTURES)/bundle/bundle-1.sbn $(FIXTURES)/bundle.pub

nginx: lib
	connectors/nginx/scripts/build.sh $(NGINX_VERSION) $(BUILD)

test-nginx: $(MKBUNDLE) $(COMPILE)
	TEST_NGINX_STRATA_MKBUNDLE="$(CURDIR)/$(MKBUNDLE)" TEST_NGINX_STRATA_COMPILE="$(CURDIR)/$(COMPILE)" \
	PATH="$(CURDIR)/$(NGX_OBJS):$$PATH" \
	TEST_NGINX_LOAD_MODULES="$(CURDIR)/$(NGX_OBJS)/ngx_http_strata_module.so" \
		sh -c "cd connectors/nginx && prove -r t/"

test: rust-check check-header check-fixtures abi-test nginx test-nginx

nginx-asan: lib
	STRATA_SANITIZE=1 connectors/nginx/scripts/build.sh $(NGINX_VERSION) $(BUILD)

# Sanitizer reports go to $(ASAN_LOGS)/{asan,ubsan}*; any report fails the run.
# detect_odr_violation=0: NGINX defines ngx_module_names in the binary and in
# every dynamic module by design. Leaks are checked with Valgrind instead.
test-nginx-asan: $(MKBUNDLE) $(COMPILE)
	rm -rf $(ASAN_LOGS) && mkdir -p $(ASAN_LOGS)
	TEST_NGINX_STRATA_MKBUNDLE="$(CURDIR)/$(MKBUNDLE)" TEST_NGINX_STRATA_COMPILE="$(CURDIR)/$(COMPILE)" \
	PATH="$(CURDIR)/$(NGX_ASAN_OBJS):$$PATH" \
	TEST_NGINX_LOAD_MODULES="$(CURDIR)/$(NGX_ASAN_OBJS)/ngx_http_strata_module.so" \
	ASAN_OPTIONS="detect_leaks=0,detect_odr_violation=0,abort_on_error=0,log_path=$(ASAN_LOGS)/asan" \
	UBSAN_OPTIONS="print_stacktrace=1:log_path=$(ASAN_LOGS)/ubsan" \
		sh -c "cd connectors/nginx && prove -r t/"
	@if ls $(ASAN_LOGS)/* >/dev/null 2>&1; then \
		cat $(ASAN_LOGS)/*; echo "sanitizer reports found"; exit 1; fi
	@echo "no sanitizer reports"

# master_process off + Valgrind memcheck (leak-check=full). Test::Nginx only
# prints reports, so any "Memcheck:" entry not in valgrind.suppress fails here.
# Valgrind makes nginx start slowly: wait longer, and never hang (timeout).
test-nginx-valgrind: $(MKBUNDLE) $(COMPILE)
	rm -f connectors/nginx/vgcore.*
	TEST_NGINX_STRATA_MKBUNDLE="$(CURDIR)/$(MKBUNDLE)" TEST_NGINX_STRATA_COMPILE="$(CURDIR)/$(COMPILE)" \
	PATH="$(CURDIR)/$(NGX_OBJS):$$PATH" \
	TEST_NGINX_LOAD_MODULES="$(CURDIR)/$(NGX_OBJS)/ngx_http_strata_module.so" \
	TEST_NGINX_USE_VALGRIND=1 TEST_NGINX_SLEEP=1 TEST_NGINX_TIMEOUT=10 \
		timeout 2400 sh -c "cd connectors/nginx && prove -r t/" > $(BUILD)/valgrind.log 2>&1 || \
		{ tail -20 $(BUILD)/valgrind.log; exit 1; }
	@if grep -q "Memcheck:" $(BUILD)/valgrind.log; then \
		grep -B3 -A30 "Memcheck:" $(BUILD)/valgrind.log | head -120; \
		echo "valgrind reported errors (see $(BUILD)/valgrind.log)"; exit 1; fi
	@if ls connectors/nginx/vgcore.* >/dev/null 2>&1; then \
		ls -l connectors/nginx/vgcore.*; \
		echo "nginx died on a signal under valgrind (vgcore written)"; exit 1; fi
	@echo "no valgrind reports"

# W05-N-01 measurements (see docs/reports/w05-hot-reload.md)
bench-reload: $(MKBUNDLE) $(COMPILE)
	connectors/nginx/scripts/reload-under-load.sh $(NGINX_VERSION) 8 100

check-strace: $(MKBUNDLE) $(COMPILE)
	connectors/nginx/scripts/strace-idle.sh $(NGINX_VERSION) 5

# W05-R-01 measurement (see docs/reports/w05-pss-32-workers.md)
bench-pss: $(MKBUNDLE) $(COMPILE)
	connectors/nginx/scripts/measure-pss.sh $(NGINX_VERSION) 32 6000

# proto/ -> agent/gen (buf, protoc-gen-go, protoc-gen-go-grpc on PATH)
proto:
	buf lint
	buf generate

check-proto: proto
	git diff --exit-code -- agent/gen

test-agent:
	cd agent && go vet ./... && go test -race ./... && golangci-lint run ./...

poc:
	$(MAKE) -C engine/poc/hs_mmap run

clean:
	cargo clean
	rm -rf $(BUILD)

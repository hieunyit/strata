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
	nginx-asan test-nginx-asan test-nginx-valgrind bench-reload bench-reload-latency check-strace bench-pss libinjection-diff \
	proto check-proto test-agent e2e e2e-go e2e-lab lint-rules crs-fetch crs-inventory crs-ftw crs-import test-crs-ftw rules-tools test-rules signatures-import test-signatures clang-tidy check-c-lines

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
	cargo test --release -p libstrata -- --ignored -- --test-threads=1

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

# Size budget of the C connector (CLAUDE.md)
C_LINES_MAX ?= 3000
check-c-lines:
	connectors/nginx/scripts/count-lines.sh $(C_LINES_MAX)

# clang-tidy on the module (W07-Q-01; checks in .clang-tidy), with the exact
# compile commands of the NGINX build of `make nginx`.
clang-tidy: nginx
	connectors/nginx/scripts/compile-commands.sh $(BUILD)/nginx-$(NGINX_VERSION) > $(BUILD)/compile_commands.json
	clang-tidy -p $(BUILD) --quiet connectors/nginx/src/*.c

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

# W05-Q-01: latency percentiles while bundles are swapped (docs/reports/w05-q01-reload-latency.md)
bench-reload-latency: $(MKBUNDLE) $(COMPILE)
	connectors/nginx/scripts/latency-during-reload.sh $(NGINX_VERSION) 4 30 300

check-strace: $(MKBUNDLE) $(COMPILE)
	connectors/nginx/scripts/strace-idle.sh $(NGINX_VERSION) 5

# W05-R-01 measurement (see docs/reports/w05-pss-32-workers.md)
bench-pss: $(MKBUNDLE) $(COMPILE)
	connectors/nginx/scripts/measure-pss.sh $(NGINX_VERSION) 32 6000

# proto/ -> agent/gen (buf, protoc-gen-go, protoc-gen-go-grpc on PATH)
proto:
	buf lint
	buf generate
	buf generate --template buf.gen.admin.yaml

check-proto: proto
	git diff --exit-code -- agent/gen control-plane/gen docs/spec/admin.swagger.json
	test -z "$$(git status --porcelain -- agent/gen control-plane/gen docs/spec/admin.swagger.json)"

test-agent:
	cd agent && go vet ./... && go test -race ./... && golangci-lint run ./...

# Go modules other than agent/. tests/e2e is only vetted, linted and
# compiled here: its tests start ClickHouse with docker, so they run on the
# host with `make e2e`.
test-go: test-agent
	cd control-plane && go vet ./... && go test -race ./... && golangci-lint run ./...
	cd tests/e2e && go vet ./... && golangci-lint run ./... && go test -count=1 -run '^$$' ./...
	cd tools/strata-rules && go vet ./... && go test -race ./... && golangci-lint run ./...
	$(MAKE) lint-rules
	tools/strata-import-crs/fetch-crs.sh >/dev/null
	cd tools/strata-import-crs && go vet ./... && go test -race ./... && golangci-lint run ./...
	cd tools/strata-import-signatures && go vet ./... && go test -race ./... && golangci-lint run ./...

# Rule tests and the corpus report through libstrata (W04-S-01).
rules-tools:
	cargo build --release -p strata-compiler -p strata-eval

test-rules: rules-tools
	cd tools/strata-rules && STRATA_RULES_REQUIRE_TOOLS=1 go test -count=1 ./... && go run . test --repo ../..
	cd tools/strata-rules && go run . report --repo ../..
	# the protocol pack (W05-S-01) matches no benign request
	cd tools/strata-rules && go run . report --repo ../.. --rules ../../rules/protocol --max-fp 0 > /dev/null
	# the imported signature packs (W07-S-01) match no benign request either
	cd tools/strata-rules && for p in sigma et-open bots; do go run . report --repo ../.. --rules ../../rules/$$p --max-fp 0 > /dev/null || exit 1; done
	$(MAKE) test-signatures

# Sigma rules/web, ET Open (SIDs 2000000-2099999), crawler-user-agents,
# pinned in tools/strata-import-signatures/sources.lock (W07-S-01).
SIG       := tools/strata-import-signatures
SIG_LOCK   = sed -n 's/^$(1)_version=//p' $(SIG)/sources.lock
signatures-import:
	cd $(SIG) && go build -o ../../build/strata-import-signatures .
	build/strata-import-signatures sigma --src "$$($(SIG)/fetch.sh sigma)" --version "$$($(call SIG_LOCK,sigma))"
	build/strata-import-signatures et --src "$$($(SIG)/fetch.sh et)" --version "$$($(call SIG_LOCK,et))"
	build/strata-import-signatures bots --src "$$($(SIG)/fetch.sh bots)" --version "$$($(call SIG_LOCK,bots))"

# their test requests through libstrata, each rule alone: all must pass
test-signatures: rules-tools
	cd tools/strata-rules && for p in sigma et-open bots; do \
		go run . ftw --repo ../.. --tests ../../rules/$$p/tests --rules ../../rules/$$p --min 100 > ../../build/ftw-$$p.md || \
		{ cat ../../build/ftw-$$p.md; exit 1; }; done

# go-ftw tests of the pinned CRS, converted (W04-S-01).
crs-ftw:
	cd tools/strata-import-crs && go run . ftw --crs "$$(./fetch-crs.sh)" --out ../../corpus/crs-ftw --report ../../docs/crs-ftw-unconverted.md

# rules/crs/ and docs/crs-import-report.md (W05-S-01, W06-S-01); CI checks that they are current.
crs-import: rules-tools
	cd tools/strata-import-crs && go run . import --crs "$$(./fetch-crs.sh)" --out ../../rules/crs --report ../../docs/crs-import-report.md --compile ../../target/release/strata-compile

# go-ftw tests of the injection groups through libstrata (W06-S-01): at
# least 90% per group; the result is docs/crs-ftw-report.md.
CRS_FTW_GROUPS ?= 930,931,932,933,941,942,944
test-crs-ftw: rules-tools
	cd tools/strata-rules && go run . ftw --repo ../.. --group $(CRS_FTW_GROUPS) --min 90 > ../../docs/crs-ftw-report.md

# CRS release pinned in tools/strata-import-crs/crs.lock, into build/crs/.
crs-fetch:
	tools/strata-import-crs/fetch-crs.sh

# docs/crs-inventory.csv (W03-S-02); CI checks that it is current.
crs-inventory:
	cd tools/strata-import-crs && go run . inventory --crs "$$(./fetch-crs.sh)" --out ../../docs/crs-inventory.csv

# Rule files under rules/ (W03-S-01): schema, ids, RE2 regexes, licenses.
lint-rules:
	cd tools/strata-rules && go run . lint --repo ../..

# Lab (deploy/lab, W03-Q-01). Run on the host: these targets use docker and
# run the build inside the dev image themselves.
LAB         := deploy/lab
LAB_COMPOSE := docker compose -f $(LAB)/compose.yaml --env-file $(LAB)/.state/env

lab-build:
	docker build -q -t strata-dev:latest deploy/dev
	deploy/dev/run.sh $(LAB)/build.sh

lab-up: lab-build
	$(LAB)/init-env.sh
	$(LAB_COMPOSE) build
	$(LAB_COMPOSE) up -d --wait --wait-timeout 900

lab-down:
	$(LAB_COMPOSE) down

lab-clean:
	-$(LAB_COMPOSE) down -v
	rm -rf $(LAB)/.state

lab-status:
	$(LAB_COMPOSE) ps

lab-smoke:
	$(LAB)/smoke.sh

# End to end (W04-Q-01). e2e-go needs docker only (PostgreSQL, MinIO,
# ClickHouse in containers); e2e-lab needs a running lab; e2e does both,
# starting the lab first.
e2e-go:
	cd tests/e2e && go test -count=1 -timeout 25m ./...

e2e-lab:
	tests/e2e/lab-chain.sh

e2e: e2e-go lab-up e2e-lab

# Rust port of libinjection vs the original C library (W06-R-01)
libinjection-diff:
	engine/tools/libinjection/diff.sh $(CURDIR)/build

poc:
	$(MAKE) -C engine/poc/hs_mmap run

clean:
	cargo clean
	rm -rf $(BUILD)

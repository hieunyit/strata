# Strata WAF

Strata là WAF mã nguồn mở: lõi detection viết bằng Rust (`libstrata`, C ABI), cắm vào proxy có sẵn qua connector (NGINX trước, sau đó Apache, HAProxy, Envoy, Kong), quản trị qua control plane (Go) + Web UI.

## Tài liệu thiết kế (đọc trước khi code)

- `docs/design/nginx-module.md` — **nguồn chính** cho giai đoạn hiện tại: module NGINX, FFI, bundle, agent, control plane, API, lộ trình.
- `docs/design/strata-overview.md` — bối cảnh tổng thể: ma trận vấn đề, mô hình policy & rule, danh mục tính năng.
- `docs/design/control-file.md` — layout byte của control file và bundle v1, quy tắc nạp bundle trong worker (bổ sung cho mục "Bundle & hot reload").

Khi tài liệu và code mâu thuẫn, tài liệu NGINX module thắng; nếu thấy tài liệu sai hoặc thiếu, dừng lại và hỏi, không tự đổi thiết kế. Sơ đồ trong tài liệu không có trong bản Markdown; phần chữ đủ để code.

## Phạm vi hiện tại: khối A3 (tuần 8–10), mọi luồng

Kế hoạch tổng: `docs/plan/plan.md` (đọc mục "Cách dùng file này với Claude Code" và các dòng "Đọc" của nhiệm vụ trước khi code). Phiên này làm **mọi luồng**: N (module NGINX, C), R (libstrata, Rust), S (rule, importer), G1 (agent, Fleet), G2 (auth/compiler/control plane), F (Web UI), Q (lab, CI, e2e). Khối A3 khóa lại ở **Gate A** cuối tuần 10 (shadow).

**Đã xong** (tuần 1–7 và các follow-up):

- Tuần 1–2: skeleton monorepo; ABI `strata.h` 1.0 + test ABI hai phía; libstrata stub; khung module (directive, context, redirect, subrequest, đọc body đồng bộ/bất đồng bộ, trang chặn, biến); CI; PoC Hyperscan + mmap.
- Tuần 3–5 (khối A1): tách `libstrata` / `libstrata-ffi`; Block ID + JSON Schema IR; protocol v1; test PREACCESS và ép đọc body; bundle v1 ký Ed25519 + hot reload qua control file; 136 rule CRS 4.25.2 PL1 (`rules/crs`), 40 rule protocol (`rules/protocol`, 0 FP trên corpus benign), `make test-crs-ftw`.
- Tuần 6 (khối A2): đường đi response, tokenizer response layer, trang Sự kiện nối API.
- Tuần 7 (khối A2): fail mode open/closed, event sink Unix socket, metrics shared memory, RST_STREAM; CPU budget hợp tác + cô lập lỗi (`catch_unwind`); operator đợt 2; mã hóa sự kiện protobuf trong libstrata; nhập Sigma/ET Open/bot + virtual patch 700001–700010; độ bền agent (reconnect, gia hạn chứng chỉ, `ForceShadow`); signer KMS (Vault transit) + cost unit + điều khiển rollout; trang Fleet; clang-tidy + CodeQL cho C.
- Follow-up #11–#14 (2026-10-12, PO giao tự quyết): giới hạn C nâng lên 3.000 dòng thực; `POST /v1/nodes:clearForceShadow`; quy trình xoay khóa ký bundle (node tin tối đa 2 khóa, phân phối ngoài băng, `tests/e2e/lab-key-rotation.sh`); bộ virtual patch khởi đầu; gate 0 FP benign.

- Tuần 8 (khối A3): `action_mode` (`block_alone | score`); Test::Nginx đầy đủ kể cả HTTP/3; fuzz libFuzzer FFI + differential `go-net-http`/`spring`; go-ftw toàn bộ CRS ≥ 95% + `strata-rules release`/`verify`; test tải Fleet 1.000 agent; toxiproxy; RBAC + CSV trên UI; conformance corpus v1 qua engine và NGINX. Review lại: `docs/reports/w08-review.md`.

- Tuần 9 (khối A3, PR #26–#40): benchmark p50/p99/throughput + event socket, quyết định giữ datagram socket (`docs/decisions/ring-buffer.md`); prefilter + `lower_loose` (gói đầy đủ ×23 nhanh hơn, ticket #27 throughput, #28 body lớn); soak 24 giờ + staging chỉ deploy từ tag (`deploy/staging/deploy.sh`); ClickHouse TTL + tra Block ID < 1 s; decision trace tô field + tác giả Sigma; `strata-mutate` hằng đêm (#34); gói signature 0.0.1 (9.054 rule, FP 0,60%, recall ≥ 70%, #36 cost unit); di chuyển sang server mới (`deploy/migrate`), deploy outlives REST timeout. **Còn mở**: verdict soak 24 giờ, staging 7 ngày của gói 0.0.1, review tuần 9 (phiên khác, nhánh `w09-review`).

**Đang làm** (tuần 10 · Đóng gói và shadow · Gate A), theo thứ tự trong `docs/plan/w10-plan.md`, mỗi nhiệm vụ một nhánh tên theo mã, trong worktree `~/strata-w10`:

1. **W10-Q-01** Giám sát: dashboard Grafana + cảnh báo VictoriaMetrics (vmalert) cho module, agent, control plane.
2. **W10-N-01** Gói deb/rpm `nginx-module-strata` theo bản NGINX + `strata-agent`, cài 1 lệnh; image container; runbook (tắt module, ép shadow, rollback bundle) diễn tập trên staging; #29 (sysctl, socket đã `connect()`).
3. **W10-G1-01** Control plane trên staging (+ `prod-sim`), node của 2 route thí điểm (giả lập nếu PO chưa có dữ liệu) enroll.
4. **W10-G2-01** Policy shadow cho 2 route thí điểm; sự kiện có Event ID về ClickHouse.
5. **W10-S-01** Bảng FP theo Rule ID cập nhật hằng ngày.
6. **W10-F-01** Trang Tổng quan v0 (bị chặn theo giờ, top rule, top route).
7. Báo cáo Gate A, rồi review tuần 10 (theo `docs/reports/w08-review.md`).

Ràng buộc phiên này: build/test chỉ trên nhân 6–10 (`STRATA_DEV_DOCKER_ARGS="--cpuset-cpus=6-10"`), không chạy benchmark; không đụng staging, soak, tag `v0.9.0-rc.*` cho tới khi memory `w09-review.md` ghi "staging handed over to W10" (trước đó dùng lab); sau đó staging chỉ deploy tag `v0.10.0-rc.*` kèm `--signatures build/signatures/v0.0.1`, ghi mỗi lần deploy vào `docs/reports/w09-s-01.md`.

**Chưa làm** trong khối này: circuit breaker và canary (B1, tuần 11+).

## Quy tắc code

### C (connector NGINX)
- Không parse input trong C; chỉ lấy con trỏ + độ dài từ cấu trúc NGINX rồi chuyển cho libstrata.
- Kiểm tra độ dài trước mọi copy; không `strcpy`/`sprintf`; dùng API cấp phát của NGINX (`ngx_palloc`, `ngx_pcalloc`).
- Không I/O, không khóa, không cấp phát lớn trên đường đi của request.
- Build với `-Wall -Wextra -Werror -fstack-protector-strong -D_FORTIFY_SOURCE=2`.
- Phần C tối đa 3.000 dòng code thực (`connectors/nginx/src/*.c`, `*.h`, không tính dòng trống và comment); `make check-c-lines` kiểm trong CI. Nâng từ 2.500 ngày 12/10/2026 (PO duyệt) khi đã dùng 2.499: chỗ cho xoay khóa bundle và các tuần sau. Logic mới vẫn ưu tiên đặt trong libstrata.

### Rust (libstrata)
- Không `unsafe` ngoài `engine/ffi/`.
- Dữ liệu từ FFI chỉ mượn dạng `&[u8]` trong thời gian gọi; không chuyển sang `String`/`Vec<u8>` trừ khi cần giữ (xem quy tắc lifetime).
- Chỉ dùng regex thời gian tuyến tính (crate `regex`, Hyperscan); không backtracking.
- Parser viết dạng vòng lặp, có giới hạn độ sâu.

### Chung
- Tên ví dụ, policy, host trong code và test dùng giá trị trung tính (`example-api`, `api.example.test`), không dùng tên hệ thống thật.
- Mỗi thay đổi đi kèm test; không merge khi test hoặc CI đỏ.
- Commit nhỏ, message tiếng Anh, dạng `area: what changed` (ví dụ `nginx: add preaccess body read`).

## Lệnh thường dùng

```bash
# Rust (trong image dev: deploy/dev/run.sh <lệnh>)
cargo build --release -p libstrata-ffi   # -> target/release/libstrata.a
cargo test -p libstrata                  # logic engine
cargo clippy --workspace --all-targets --all-features -- -D warnings

# NGINX module (trong thư mục mã nguồn NGINX tương ứng)
./configure --with-compat --with-threads --with-http_v2_module \
  --add-dynamic-module=/path/to/strata/connectors/nginx
make modules

# Test tích hợp (build nginx + module rồi chạy Test::Nginx)
make nginx test-nginx NGINX_VERSION=1.30.5
make test        # toàn bộ: Rust, header, fixture, ABI, nginx
```

## Hoàn thành khối A1 khi

- Mọi nhiệm vụ N/R của tuần 3–5 trong plan đạt dòng "Xong khi", trên cả 2 bản NGINX, CI xanh (kể cả ASan).
- Tài liệu thiết kế được cập nhật ở chỗ code thật khác thiết kế.

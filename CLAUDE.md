# Strata WAF

Strata là WAF mã nguồn mở: lõi detection viết bằng Rust (`libstrata`, C ABI), cắm vào proxy có sẵn qua connector (NGINX trước, sau đó Apache, HAProxy, Envoy, Kong), quản trị qua control plane (Go) + Web UI.

## Tài liệu thiết kế (đọc trước khi code)

- `docs/design/nginx-module.md` — **nguồn chính** cho giai đoạn hiện tại: module NGINX, FFI, bundle, agent, control plane, API, lộ trình.
- `docs/design/strata-overview.md` — bối cảnh tổng thể: ma trận vấn đề, mô hình policy & rule, danh mục tính năng.
- `docs/design/control-file.md` — layout byte của control file và bundle v1, quy tắc nạp bundle trong worker (bổ sung cho mục "Bundle & hot reload").

Khi tài liệu và code mâu thuẫn, tài liệu NGINX module thắng; nếu thấy tài liệu sai hoặc thiếu, dừng lại và hỏi, không tự đổi thiết kế. Sơ đồ trong tài liệu không có trong bản Markdown; phần chữ đủ để code.

## Phạm vi hiện tại: kế hoạch Compact (ưu tiên, PO 19/10/2026), mọi luồng

Kế hoạch tổng: `docs/plan/plan.md` (đọc mục "Cách dùng file này với Claude Code" và các dòng "Đọc" của nhiệm vụ trước khi code). Phiên này làm **mọi luồng**: N (module NGINX, C), R (libstrata, Rust), S (rule, importer), G1 (agent, Fleet), G2 (auth/compiler/control plane), F (Web UI), Q (lab, CI, e2e). Từ 19/10/2026 PO ưu tiên **kế hoạch Compact** (`docs/plan/compact-ops-plan.md`) trước giai đoạn B gốc; Gate A vẫn mở (`docs/reports/gate-a.md`).

**Đã xong** (tuần 1–7 và các follow-up):

- Tuần 1–2: skeleton monorepo; ABI `strata.h` 1.0 + test ABI hai phía; libstrata stub; khung module (directive, context, redirect, subrequest, đọc body đồng bộ/bất đồng bộ, trang chặn, biến); CI; PoC Hyperscan + mmap.
- Tuần 3–5 (khối A1): tách `libstrata` / `libstrata-ffi`; Block ID + JSON Schema IR; protocol v1; test PREACCESS và ép đọc body; bundle v1 ký Ed25519 + hot reload qua control file; 136 rule CRS 4.25.2 PL1 (`rules/crs`), 40 rule protocol (`rules/protocol`, 0 FP trên corpus benign), `make test-crs-ftw`.
- Tuần 6 (khối A2): đường đi response, tokenizer response layer, trang Sự kiện nối API.
- Tuần 7 (khối A2): fail mode open/closed, event sink Unix socket, metrics shared memory, RST_STREAM; CPU budget hợp tác + cô lập lỗi (`catch_unwind`); operator đợt 2; mã hóa sự kiện protobuf trong libstrata; nhập Sigma/ET Open/bot + virtual patch 700001–700010; độ bền agent (reconnect, gia hạn chứng chỉ, `ForceShadow`); signer KMS (Vault transit) + cost unit + điều khiển rollout; trang Fleet; clang-tidy + CodeQL cho C.
- Follow-up #11–#14 (2026-10-12, PO giao tự quyết): giới hạn C nâng lên 3.000 dòng thực; `POST /v1/nodes:clearForceShadow`; quy trình xoay khóa ký bundle (node tin tối đa 2 khóa, phân phối ngoài băng, `tests/e2e/lab-key-rotation.sh`); bộ virtual patch khởi đầu; gate 0 FP benign.

- Tuần 8 (khối A3): `action_mode` (`block_alone | score`); Test::Nginx đầy đủ kể cả HTTP/3; fuzz libFuzzer FFI + differential `go-net-http`/`spring`; go-ftw toàn bộ CRS ≥ 95% + `strata-rules release`/`verify`; test tải Fleet 1.000 agent; toxiproxy; RBAC + CSV trên UI; conformance corpus v1 qua engine và NGINX. Review lại: `docs/reports/w08-review.md`.

- Tuần 9 (khối A3, PR #26–#40): benchmark p50/p99/throughput + event socket, quyết định giữ datagram socket (`docs/decisions/ring-buffer.md`); prefilter + `lower_loose` (gói đầy đủ ×23 nhanh hơn, ticket #27 throughput, #28 body lớn); soak 24 giờ + staging chỉ deploy từ tag (`deploy/staging/deploy.sh`); ClickHouse TTL + tra Block ID < 1 s; decision trace tô field + tác giả Sigma; `strata-mutate` hằng đêm (#34); gói signature 0.0.1 (9.054 rule, FP 0,60%, recall ≥ 70%, #36 cost unit); di chuyển sang server mới (`deploy/migrate`), deploy outlives REST timeout. **Còn mở**: verdict soak 24 giờ, staging 7 ngày của gói 0.0.1, review tuần 9 (phiên khác, nhánh `w09-review`).

- Tuần 10–13 và sau đó: Gate A (chưa đạt hiệu năng A1/A2), shadow trên staging, replay service, duyệt bốn mắt (cần replay DONE), hàng chờ duyệt; chuỗi remediation (`docs/reports/remediation-tracker.md`, `branch-consolidation.md`) và các tuần 14–21 (`docs/reports/w17-w21-integration.md`) đã vào main. Con trỏ tuần trong `AGENTS.md` không phản ánh trạng thái; dùng các tracker này.

**Đang làm**: kế hoạch Compact, nhiệm vụ `CP-*`, thứ tự và nghiệm thu trong `docs/plan/compact-ops-plan.md` §3 (bảng trạng thái ở `AGENTS.md` §0). Quyết định PO 19/10: giữ PostgreSQL; local auth mặc định, Keycloak/OIDC, MinIO/S3, Vault, Grafana là tùy chọn; artifact trên filesystem và file signer mặc định; UI nhúng trong control plane; một control plane hoạt động; B03 (quản lý cấu hình NGINX) làm sau. Việc đầu tiên: **CP-SEC-01** (namespace subject OIDC), **CP-SEC-02** (tên policy và khóa artifact). Phiên strata-b9 làm CRS PL2 (W17–W21), tránh sửa chồng `control-plane/policy/spec.go`, `compiler.go`, proto admin, policy editor mà không báo trước.

Ràng buộc phiên này:

- Build/test chỉ trên nhân 6–10 (`STRATA_DEV_DOCKER_ARGS="--cpuset-cpus=6-10"`), không chạy benchmark.
- **Không có CI GitHub** (PO 19/10 quyết không bật): mỗi PR qua cổng kiểm cục bộ ở `compact-ops-plan.md` §8a, kiểm mã thoát của lệnh, không chỉ lọc dòng `ok`.
- Merge theo quyền PO giao: cho từng PR ("merge #N"), hoặc quyền merge PO đã giao cho cả luồng việc (ví dụ luồng tích hợp W17–W21).
- Staging và prod-sim: không deploy khi PO chưa cho phép; `deploy/staging/deploy.sh` và `pilot.sh` không có `--env` là staging. Lab dùng chung: hỏi các phiên đang chạy trước, xong thì dựng lại từ worktree detached ở `origin/main`.

## Compact integration · 22/10/2026

C03/C01/C02/C04/C05 và cẩm nang đã merge toàn bộ PR #321–#395 vào main
(`84160a3ee6ec296ff10d57082512c9820cb99b16`). Trạng thái mới nhất và bằng chứng:
`docs/reports/compact-main-merge.md`. B03 vẫn loại khỏi phạm vi; discovery mặc định
tắt chờ pháp chế thực tế, chưa enforce OpenAPI runtime. Không deploy staging/production.

## Quy tắc code

### C (connector NGINX)
- Không parse input trong C; chỉ lấy con trỏ + độ dài từ cấu trúc NGINX rồi chuyển cho libstrata.
- Kiểm tra độ dài trước mọi copy; không `strcpy`/`sprintf`; dùng API cấp phát của NGINX (`ngx_palloc`, `ngx_pcalloc`).
- Không I/O, không khóa, không cấp phát lớn trên đường đi của request.
- Build với `-Wall -Wextra -Werror -fstack-protector-strong -D_FORTIFY_SOURCE=2`.
- Phần C tối đa 4.000 dòng code thực (`connectors/nginx/src/*.c`, `*.h`, không tính dòng trống và comment); `make check-c-lines` kiểm trong CI. Nâng từ 2.500 lên 3.000 ngày 12/10/2026, rồi lên 4.000 ngày 15/10/2026 khi đã dùng 2.999 (PO duyệt cả hai lần). Logic mới vẫn ưu tiên đặt trong libstrata; C chỉ cho phần buộc phải nằm trong NGINX.

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

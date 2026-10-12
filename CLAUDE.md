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

**Đang làm** (tuần 9 · Benchmark, soak, staging), theo thứ tự trong `docs/plan/w09-plan.md`, mỗi nhiệm vụ một nhánh tên theo mã:

1. **W09-Q-01** Benchmark: p50/p99 và throughput (nhỏ, 64 KB, 1 MB, HTTP/2) so với NGINX không module; event socket ~50.000 sự kiện/giây; `docs/decisions/ring-buffer.md`.
2. **W09-R-01** Xử lý điểm nóng: p99 < 1 ms, throughput giảm ≤ 10%, hoặc ticket cho phần còn thiếu.
3. **W09-Q-02** Soak 24 giờ + 1.000 lần đổi bundle (bộ nhớ, fd không tăng); staging chỉ deploy từ tag.
4. **W09-G2-01** ClickHouse: TTL, tra Block ID < 1 s, tìm kiếm 24 giờ < 2 s.
5. **W09-F-01** Decision trace: tô field vi phạm, hiện tác giả rule Sigma.
6. **W09-S-02** Bộ sinh biến thể payload (`tools/strata-mutate/`), báo cáo lách theo loại tấn công, chạy hằng đêm.
7. **W09-S-01** Gói signature v0: CRS PL1 + nguồn nhập + rule riêng, staging 7 ngày, review 2 người (người thứ hai là PO/SecOps), đạt Gate A.

Mỗi nhiệm vụ chỉ xong khi đạt đúng dòng "Xong khi" trong plan. Đổi interface chung (`strata.h`, `proto/`, OpenAPI, định dạng bundle, định dạng rule/IR) chỉ khi dòng "Làm" của nhiệm vụ ghi rõ (W08-R-02 được phép đổi định dạng rule + JSON Schema); ngoài ra dừng lại và đề xuất.

**Chưa làm** trong khối này (tuần 10, hoặc tuần sau): đóng gói + shadow + Gate A (tuần 10); circuit breaker và canary (B1, tuần 11+).

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

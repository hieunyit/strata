# Strata WAF

Strata là WAF mã nguồn mở: lõi detection viết bằng Rust (`libstrata`, C ABI), cắm vào proxy có sẵn qua connector (NGINX trước, sau đó Apache, HAProxy, Envoy, Kong), quản trị qua control plane (Go) + Web UI.

## Tài liệu thiết kế (đọc trước khi code)

- `docs/design/nginx-module.md` — **nguồn chính** cho giai đoạn hiện tại: module NGINX, FFI, bundle, agent, control plane, API, lộ trình.
- `docs/design/strata-overview.md` — bối cảnh tổng thể: ma trận vấn đề, mô hình policy & rule, danh mục tính năng.

Khi tài liệu và code mâu thuẫn, tài liệu NGINX module thắng; nếu thấy tài liệu sai hoặc thiếu, dừng lại và hỏi, không tự đổi thiết kế. Sơ đồ trong tài liệu không có trong bản Markdown; phần chữ đủ để code.

## Phạm vi hiện tại: tuần 1–2 (giai đoạn A)

Chỉ làm những việc sau, theo thứ tự:

1. **Monorepo skeleton** đúng cấu trúc trong mục "Tech stack & cấu trúc repo" (`engine/`, `connectors/nginx/`, `control-plane/`, `cli/`, `deploy/`, `docs/`). Các thư mục chưa dùng chỉ cần `README.md` một dòng.
2. **Chốt ABI** `engine/ffi/strata.h` (sinh bằng cbindgen) theo mục "Ranh giới FFI": `strata_str_t`, `strata_str_pair_t`, `strata_engine_map`, `strata_tx_*`, `strata_verdict_t`, `strata_abi_version`. Tuân thủ đúng quy tắc lifetime và `strata_tx_free` idempotent.
3. **libstrata stub**: cài đặt đủ ABI nhưng logic đơn giản (ví dụ chặn khi URI hoặc body chứa chuỗi `STRATA-TEST-BLOCK`), sinh Block ID đúng định dạng `STR-XXXX-XXXX-XXXX-XXXX`. Mọi hàm `extern "C"` bọc `catch_unwind`; build `panic = "unwind"`, xuất `.a` tĩnh.
4. **Khung `ngx_http_strata_module`** trong `connectors/nginx/`:
   - File `config`, directive trong bảng "Directive & biến" (chưa cần `strata_breaker*`), merge cấu hình.
   - Context request, pool cleanup, tìm lại context sau internal redirect, bỏ qua subrequest (`r != r->main`).
   - PREACCESS handler + đọc body theo đúng mẫu đồng bộ/bất đồng bộ trong mục "Vòng đời request" (cân bằng `r->main->count`).
   - Response chặn HTML/JSON với header `X-Strata-Block-Id`, biến `$strata_block_id`, `$strata_action`.
5. **Test** `connectors/nginx/t/` bằng Test::Nginx, tối thiểu 7 case bắt buộc trong mục "Vòng đời request" + case chặn/cho qua cơ bản.
6. **CI**: build module cho 2 phiên bản NGINX OSS (stable + mainline), chạy test; build Rust với clippy và test.
7. **PoC mmap + Hyperscan** trong `engine/poc/`: xác nhận database Hyperscan dùng được từ vùng `mmap(PROT_READ, MAP_SHARED)` ở địa chỉ khác nhau giữa các process. Ghi kết quả vào `docs/poc/hyperscan-mmap.md`.

**Chưa làm** ở giai đoạn này: control plane, agent, UI, hot reload bundle, response body filter, gRPC, circuit breaker, các connector khác.

## Quy tắc code

### C (connector NGINX)
- Không parse input trong C; chỉ lấy con trỏ + độ dài từ cấu trúc NGINX rồi chuyển cho libstrata.
- Kiểm tra độ dài trước mọi copy; không `strcpy`/`sprintf`; dùng API cấp phát của NGINX (`ngx_palloc`, `ngx_pcalloc`).
- Không I/O, không khóa, không cấp phát lớn trên đường đi của request.
- Build với `-Wall -Wextra -Werror -fstack-protector-strong -D_FORTIFY_SOURCE=2`.
- Mục tiêu phần C dưới 2.000 dòng.

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
# Rust
cargo build --release -p libstrata
cargo test -p libstrata
cargo clippy -- -D warnings

# NGINX module (trong thư mục mã nguồn NGINX tương ứng)
./configure --with-compat --with-threads --with-http_v2_module \
  --add-dynamic-module=/path/to/strata/connectors/nginx
make modules

# Test tích hợp
prove -r connectors/nginx/t/
```

## Hoàn thành tuần 1–2 khi

- `strata.h` đã chốt, có test ABI ở cả hai phía.
- NGINX nạp module, chặn được request chứa chuỗi test, trả Block ID đúng định dạng.
- 7 test bắt buộc về đọc body pass trên cả 2 phiên bản NGINX.
- Có kết quả PoC Hyperscan + mmap (được hay không, và số liệu RAM đo được).

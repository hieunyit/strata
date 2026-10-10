# Strata WAF

Strata là WAF mã nguồn mở: lõi detection viết bằng Rust (`libstrata`, C ABI), cắm vào proxy có sẵn qua connector (NGINX trước, sau đó Apache, HAProxy, Envoy, Kong), quản trị qua control plane (Go) + Web UI.

## Tài liệu thiết kế (đọc trước khi code)

- `docs/design/nginx-module.md` — **nguồn chính** cho giai đoạn hiện tại: module NGINX, FFI, bundle, agent, control plane, API, lộ trình.
- `docs/design/strata-overview.md` — bối cảnh tổng thể: ma trận vấn đề, mô hình policy & rule, danh mục tính năng.
- `docs/design/control-file.md` — layout byte của control file và bundle v1, quy tắc nạp bundle trong worker (bổ sung cho mục "Bundle & hot reload").

Khi tài liệu và code mâu thuẫn, tài liệu NGINX module thắng; nếu thấy tài liệu sai hoặc thiếu, dừng lại và hỏi, không tự đổi thiết kế. Sơ đồ trong tài liệu không có trong bản Markdown; phần chữ đủ để code.

## Phạm vi hiện tại: khối A1 (tuần 3–5), luồng N và R

Kế hoạch tổng: `docs/plan/plan.md` (đọc mục "Cách dùng file này với Claude Code" và các dòng "Đọc" của nhiệm vụ trước khi code). Phiên này chỉ làm luồng **N** (module NGINX, C) và **R** (libstrata, Rust); luồng Go/UI làm ở phiên khác.

**Đã xong** (tuần 1–2 và làm trước plan): skeleton monorepo; ABI `strata.h` 1.0 + test ABI hai phía; libstrata stub; khung module (directive, context, redirect, subrequest, đọc body đồng bộ/bất đồng bộ, trang chặn, biến); 7 test đọc body trên 1.30.5 và 1.31.6; CI; PoC Hyperscan + mmap; bundle v1 có chữ ký Ed25519 và hot reload qua control file (phần lớn W05-N-01, một phần W04-R-01, W04-N-02).

**Đang làm**, theo thứ tự, mỗi nhiệm vụ một nhánh tên theo mã:

1. Tách `engine/` thành crate `libstrata` (code an toàn) và `engine/ffi/` thành crate `libstrata-ffi` (C ABI, xuất `libstrata.a`); ABI không đổi.
2. **W03-R-02** Block ID bản cuối + JSON Schema IR (`docs/spec/ir.schema.json`, cần luồng S duyệt).
3. **W03-R-01** Lớp protocol v1 (`engine/src/detectors/protocol/`, Rule ID dải 100000).
4. **W03-N-01** Test PREACCESS `t/010-preaccess.t`.
5. **W03-N-02** Ép đọc body ở enforce, `t/020-body-enforce.t`; kiểm tra `stream` + policy enforce khi `nginx -t`.

Mỗi nhiệm vụ chỉ xong khi đạt đúng dòng "Xong khi" trong plan. Đổi interface chung (`strata.h`, định dạng bundle, định dạng rule/IR) chỉ khi nhiệm vụ ghi rõ hoặc đã được duyệt; ngoài ra dừng lại và đề xuất.

**Chưa làm** trong khối này: control plane, agent, UI (luồng khác); response filter (W06); event sink, CPU budget, metrics (W07); circuit breaker (W11); việc của tuần sau.

## Quy tắc code

### C (connector NGINX)
- Không parse input trong C; chỉ lấy con trỏ + độ dài từ cấu trúc NGINX rồi chuyển cho libstrata.
- Kiểm tra độ dài trước mọi copy; không `strcpy`/`sprintf`; dùng API cấp phát của NGINX (`ngx_palloc`, `ngx_pcalloc`).
- Không I/O, không khóa, không cấp phát lớn trên đường đi của request.
- Build với `-Wall -Wextra -Werror -fstack-protector-strong -D_FORTIFY_SOURCE=2`.
- Mục tiêu phần C dưới 2.500 dòng code thực (`connectors/nginx/src/*.c`, `*.h`, không tính dòng trống và comment).

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

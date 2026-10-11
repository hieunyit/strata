# W06-R-01 · Lớp response và tokenizer SQLi/XSS

10/10/2026 · Claude Code (ngoại lệ trong dispatch: nhiệm vụ đã làm dở thì làm nốt) · Review: L3

Chạy lại:

- `cargo test -p libstrata` (gồm `tests/response.rs` và `tests/libinjection.rs`)
- `make libinjection-diff` (so với thư viện C gốc)
- `engine/fuzz/run.sh 3600` (trong dev image)
- `make rust-check check-header check-fixtures abi-test`, `make nginx test-nginx` (1.30.5, 1.31.6), `make test-nginx-asan`, `make test-nginx-valgrind`

## Kết luận theo dòng "Xong khi"

| Tiêu chí | Kết quả |
| --- | --- |
| 15 case response pass | **Đạt**: 15/15 trong `engine/tests/response.rs`, thêm 2 case (shadow chỉ ghi nhận; flush); 7 case NGINX trong `t/051-response-layer.t` |
| Tokenizer khớp tối thiểu 99% bộ test gốc của libinjection | **Đạt, 100%**: 480/480 file test gốc v3.10.0 (tokens 249, folding 118, sqli 50, html5 63), chạy đúng cách `testdriver.c` chạy. Thêm: kết quả **giống hệt** thư viện C gốc trên 168.511 input mẫu (16.678 SQLi, 2.031 XSS theo C) |
| Fuzz 1 giờ không panic | **Đạt**: 4 target chạy song song 3.601 giây, 0 crash: `sqli` 6,16 triệu lần, `xss` 20,05 triệu, `guard_chunks` 0,72 triệu, `response_tx` 1,27 triệu; RSS đỉnh 28–32 MB |

Bộ kiểm chứng chung: Rust (fmt, clippy `-D warnings`, test), header, fixtures tái lập được, ABI C, Test::Nginx 383/383 trên 1.30.5 và 1.31.6, ASan + UBSan sạch. Valgrind: xem mục cuối.

## Đã làm

**Lớp response** (`engine/src/detectors/response/`, Rule ID dải 600000):

- 600001 status ngoài allowed codes (danh sách cố định v0: mọi 1xx–3xx, 400, 401, 403, 404, 405, 409, 422, 429, 503).
- 600101–600107 thông báo lỗi DB theo họ (MySQL, PostgreSQL, MSSQL, Oracle `ORA-` + 5 số, SQLite, DB2, chung). So khớp không phân biệt hoa thường, không cấp phát, không trạng thái toàn cục.
- 600201 CCCD: đúng 12 chữ số, không nằm trong dãy số dài hơn, mã tỉnh hợp lệ (63 mã), chữ số thế kỷ 0–3. Bị che.
- 600202 JWT: `eyJ…` `.` `eyJ…` `.` chữ ký; chỉ giữ lại tối đa ~517 byte để xác nhận, phần còn lại của token che liên tục qua các chunk (token dài bao nhiêu cũng được). Bị che.
- Phát hiện ở response chỉ **ghi nhận** (rule ID + Event ID), không đổi quyết định đã đưa ra lúc request.
- Bật theo policy: byte `response` trong policy entry của bundle (bit 0 allowed codes, bit 1 lỗi DB, bit 2 CCCD, bit 3 JWT), khối `response` trong `policies.schema.json`; bundle cũ = tắt hết. Data guard chỉ che khi policy enforce; shadow chỉ ghi nhận.
- `guard.rs`: matcher có ngữ cảnh cửa sổ (byte đứng trước, cuối luồng) và có thể giữ trạng thái giữa các chunk; chế độ chỉ phát hiện không viết lại chunk. Dùng chung `strata_tx_response_body_flush` (ABI 1.1) đã có trên main.
- NGINX: biến `$strata_rules`, `$strata_block_id` cập nhật sau response (thấy được trong access log).

**Tokenizer** (`engine/src/detectors/injection/`): port libinjection v3.10.0 (BSD-3-Clause, ghi trong `engine/NOTICE`).

- `sqli.rs` (tokenizer, folding, fingerprint, whitelist), `sqli_data.rs` sinh từ `libinjection_sqli_data.h` (9.352 mục, gồm 8.368 fingerprint), `html5.rs`, `xss.rs`. Không `unsafe`.
- Giữ nguyên các hành vi đặc thù của C để kết quả khớp: byte NUL thuộc mọi tập ký tự (`strchr`), `char` có dấu, giá trị token cắt 31 byte. Chỗ C đọc quá cuối input thì port đọc byte NUL (như chuỗi C kết thúc bằng NUL). Comment `/*` không đóng: C có hành vi không xác định (độ dài tính từ con trỏ NULL); port theo kết quả thực tế của C.
- HTML5 tokenizer viết dạng vòng lặp trạng thái; bản C đệ quy theo từng byte với input như `<a ////…` (test 1 triệu byte).
- Operator `detect_sqli` / `detect_xss` nối vào đánh giá rule (stage `request_headers`), có test qua bundle biên dịch thật.

## Ngoài thư mục `engine/detectors/`

`engine/src/{bundle,tx,guard,eval}.rs`, `engine/compiler`, `engine/ffi/tests/c/abi_test.c`, `connectors/nginx/` (biến, `t/051`, fixtures), `docs/spec/policies.schema.json`, `docs/design/control-file.md` (byte `response`), `Makefile` (`libinjection-diff`), `engine/fuzz/`, `engine/tools/libinjection/`. Thay đổi interface (bundle, schema policy) đã được duyệt trong kế hoạch.

## Rủi ro và việc còn mở

- Allowed codes cố định trong v0; danh sách theo policy cần thay đổi bundle tiếp theo.
- Che JWT không nên bật cho route cấp token (ghi trong schema).
- Đánh giá rule mới chạy stage `request_headers`; `detect_sqli`/`detect_xss` trên body chờ stage `request_body` của engine.
- Nhánh được merge vào main lúc 22:51 bởi phiên khác, trước khi fuzz 1 giờ và Valgrind xong; code trên main giống hệt nhánh đã kiểm chứng ở đây.

## Valgrind

(điền sau khi chạy xong)

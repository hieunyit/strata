Nhiệm vụ: M2 · kiểm chứng runtime exception
Nhánh: codex/m2-exception-validation; base: codex/m2-exception-runtime.

Đã làm: thêm 4 test engine integration (scope, field thứ hai, alias decoder/literal, thiếu flag/section, Rule ID không tồn tại và expiry trên engine đang nạp). Một test xuất fixture bundle ký thật khi đặt STRATA_EXCEPTION_FIXTURE_DIR; tests/security/exception_probe.py chạy NGINX ASan/UBSan với fixture đó và backend SQLite trong bộ nhớ. Không nối API/compiler trong PR kiểm chứng này.

Xong khi và output thật (bản rút gọn/raw JSON trong m2-exception-validation/):
- cargo test --offline --workspace: 382 passed, 0 failed, 9 ignored. Các test ignored không được tính là đã kiểm.
- cargo clippy --offline --workspace --all-targets --all-features -- -D warnings; cargo fmt --all --check: sạch.
- make nginx-asan NGINX_VERSION=1.30.5 rồi make test-nginx-asan NGINX_VERSION=1.30.5: All tests successful. Files=20, Tests=595, Result: PASS. Không có báo cáo ASan/UBSan. HTTP/3 binary riêng bị skip theo bộ hiện có; không tuyên bố đã kiểm HTTP/3.
- STRATA_EXCEPTION_FIXTURE_DIR=/src/build/m2-runtime-http-fixture cargo test --offline -p libstrata --test policy_exceptions: 4 passed, 0 failed. cargo test --offline -p libstrata-ffi --test policy_exceptions: 1 passed, 0 failed (8 transaction C ABI).
- python3 tests/security/exception_probe.py: 3 cặp/6 HTTP attempts; 200=2, 403=1. Header được miễn trừ đi tới SQLite và trả marker, thêm payload ở query vẫn bị rule 700011 chặn; benign 200. exception HTTP assertions PASS; no sanitizer reports. Metadata chứa hash binary/module/bundle/script, output phân biệt oracle và signature.
- Engine cũ build/memo-perf/baseline-bench với bundle này: exit 101, bundle: 5 bad policy entry (từ chối bit bắt buộc). Panic ở công cụ bench cũ dùng unwrap, không phải crash NGINX/engine mới; không tính là đường xử lý vận hành tốt.

Tự review: đường lỗi bundle fail closed; codec/evaluator có giới hạn và budget; không đổi mặc định CPU/body/fail mode/oversize/max_args; không thêm dependency, không sửa test để bỏ kiểm tra; chỉ engine/test/tài liệu. Request path/Host/field trong evidence đều là dữ liệu lab. Chưa có API draft/replay/approve/deploy exception toàn luồng; cần nâng mọi engine trước khi dùng artifact mới. Không merge/deploy, không chờ hosted CI.

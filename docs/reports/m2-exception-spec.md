Nhiệm vụ: M2 · lưu và truyền exception trong policy
Nhánh: codex/m2-exception-spec; base: codex/m2-generated-draft-idempotency.

Thêm policy.Exception và validation tương ứng codec Rust: exact method/Host/path/field, giới hạn byte/count, ID unique, expiry bắt buộc, reason và nguồn Block ID. Hết hạn không tự xóa lịch sử cấu hình; runtime ngừng áp dụng. Compiler Go chuyển nguyên entries vào JSON compiler. Proto PolicySpec.exceptions field 9 và PolicyException có mapping hai chiều, OpenAPI/admin Go và TS client sinh lại. Không cần migration mới vì spec nằm trong phiên bản JSON PostgreSQL.

Kiểm chứng: go test -race ./policy ./admin PASS; golangci-lint run ./policy/... ./admin/...: 0 issues; buf lint và generate admin sạch. Tests kiểm roundtrip, nil/invalid field, metadata, expiry, 129 entries, duplicate ID và compiler không bỏ entries. npm run generate:api, npm run lint, npm test (bộ UI), npm run build PASS; output rút gọn ở m2-exception-spec-checks.txt. Lần test UI đầu lỗi EROFS khi cache Vitest ghi vào node_modules mount read-only; chạy lại với riêng .vite là tmpfs writable, không đổi hoặc tắt test.

Tự review: model/validation có bounds và UTF-8 checks; không I/O mới/unsafe/dependency; chỉ policy/admin/proto/generated/test/docs. Không đổi mặc định body/CPU/fail mode/oversize/max_args. API exception từ Block ID và atomic draft+replay chưa có ở PR này; compiler/runtime nằm stack riêng (#145–#147), cần tích hợp trước test toàn luồng. Không deploy/merge và không chờ hosted CI.

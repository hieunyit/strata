# M9 — Audit reader tùy chọn khi không có PostgreSQL

Ngày 2026-10-17. Nhánh `codex/m9-optional-audit-store`, base `160f802`. Phát hiện bổ sung khi tích hợp main `e93dc0b`/PR #141; mức trung bình về chức năng ở chế độ không có DB, không phải process crash.

`main` truyền `pg` là `*store.Store(nil)` vào `api.AuditStore`. Interface vẫn khác nil nên API đăng ký `/v1/audit`; gọi `AuditEntries` gây nil dereference, middleware recover trả **500**. Thêm `auditReader` chuyển store không có thành interface nil thật; route tùy chọn không đăng ký, trả **404**. Store đã cấu hình được giữ nguyên. Không đổi quyền hoặc query audit.

Test handler HTTP với principal admin fixture và mock event store, không DB/mạng ngoài. Trước guard, phép chuyển interface như main cũ trả 500 (FAIL, yêu cầu 404). Sau guard:

```text
go test -race -count=1 -v ./cmd/server
--- PASS: TestAuditWithoutPostgresDoesNotRegisterNilReader (0.00s)
--- PASS: TestConfiguredAuditReaderIsKept (0.00s)
ok .../cmd/server 1.171s
go test -race -count=1 -v -run '^TestAuditEndpoint_RBAC$' ./api
--- PASS: TestAuditEndpoint_RBAC (0.00s)
ok .../api 1.101s
golangci-lint run
0 issues.
```

Log [evidence](evidence/m9-optional-audit-store/). Không thay test hiện có, thêm dependency hay đổi API contract; không deploy/merge main, không chờ hosted CI. Test cấu hình không nil kiểm identity reader; không gọi DB của một `Store{}` rỗng. Kiểm quyền/JSON của endpoint audit có test API riêng giữ nguyên.

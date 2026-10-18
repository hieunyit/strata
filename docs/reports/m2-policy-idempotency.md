Nhiệm vụ: M2 · chuẩn bị transaction tạo policy draft có request_id bền vững

Migration 0018 thêm policy_edit_requests. Store.UpdatePolicyOnce ràng buộc actor subject/request_id với SHA-256 toàn bộ command (policy ID, etag, spec, audit action/resource). Retry đồng thời hoặc sau edit khác trả phản hồi đầu tiên, không tạo thêm version/audit. Command khác dùng cùng request_id bị từ chối. UpdatePolicy và phương thức mới dùng chung updatePolicyTx, giữ etag, immutable version DRAFT, created_subject và audit cùng transaction. Chuẩn hóa thời gian UTC để kết quả lần đầu/đọc lại nhất quán. Không lưu secret hay payload sự kiện trong ledger.

Test PostgreSQL thật, database riêng trong container remediation:
```
TestPolicyEditRequestInPostgres PASS (0.61s)
TestPolicyEditRequestRejectsInvalidInputBeforeIO PASS (0.01s)
go test -v -race ./store -run TestPolicyEditRequest -count=1: ok 1.718s
go test -race ./...: PASS toàn control plane (PG tests khác không được bật trong lượt unit này)
golangci-lint run: 0 issues
```

Bao gồm 12 writer retry chỉ một draft/audit, restart Store, delayed retry sau version mới, conflict khác command, stale etag, rollback cả draft/ledger khi audit thất bại, input sai/thiếu/quá giới hạn trước I/O. Lượt PG ban đầu phát hiện khác time.Location giữa phản hồi trực tiếp và JSON đọc lại; sửa chuẩn hóa UTC, giữ nguyên assertion. Test âm không dùng database giả.

Đây là nền cho endpoint tạo exception từ Block ID vào policy version, không phải exception runtime đã hoạt động. Chưa thêm endpoint/quyền, scope route+field+rule, TTL, compiler/bundle/runtime và UI. M2 còn phải nối các phần đó với replay/four-eyes M5; không nhập prototype RAM và không tuyên bố hoàn tất. Không đổi OpenAPI/proto/bundle hay thêm dependency trong PR này; chưa merge/deploy, không chờ hosted CI.

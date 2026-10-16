Nhiệm vụ: M2 · idempotency cho draft có ID/expiry sinh ở server

Bổ sung Store.EditPolicyOnce: bind request_id với command gốc, khóa request rồi khóa policy, chỉ chạy callback tạo spec trong lần ghi đầu. Callback đọc đúng bản có etag đã kiểm và không làm external I/O. Draft/audit/phản hồi vẫn commit cùng transaction. Retry sau lần edit khác không sinh lại ID/expiry. UpdatePolicyOnce giữ API và fingerprint cũ, dùng cùng cơ chế; spec từ caller được copy trước khi dùng. Không thay schema hay thêm dependency.

Kiểm chứng PostgreSQL thật, database riêng:
```
TestDerivedPolicyDraftRunsOnceInPostgres PASS (0.66s)
TestPolicyEditRequestInPostgres PASS (0.59s)
TestPolicyEditRequestRejectsInvalidInputBeforeIO PASS (0.01s)
go test -v -race ./store -run 'TestDerivedPolicyDraft|TestPolicyEditRequest' -count=1: ok 2.340s
golangci-lint run ./store/...: 0 issues
```

12 retry đồng thời chạy callback đúng một lần và trả cùng policy; delayed retry không gọi callback lại; đổi command bị từ chối; subject khác không đọc được cached response; callback lỗi không ghi policy/tiêu thụ request_id. Giữ nguyên các test etag/audit rollback đã có. Output ở m2-generated-draft/checks.log.

Đây là phần transaction để endpoint exception có thể tạo ID/expiry một lần, chưa thêm endpoint hoặc kích hoạt runtime. Callback không phải quyền sửa policy: API vẫn phải kiểm RBAC, scope/TTL và validate spec. M2 chưa xong toàn luồng replay/duyệt/deploy; không merge hoặc vận hành staging/production, không chờ hosted CI.

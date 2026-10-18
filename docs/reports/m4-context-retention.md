# M4 — Worker retention cho snapshot FP

Ngày 2026-10-17. Nhánh `codex/m4-rule-context-retention`, base `67dcaa6` (PR #171).

Đã nối `rulehealth.ContextRetention` vào startup control plane khi có PostgreSQL. Worker sweep ngay lần đầu rồi mỗi phút, dùng context I/O tối đa 5 giây, xóa tối đa 1.000 snapshot/lượt. SQL của PR #170 dùng SKIP LOCKED để nhiều replica dọn các lô riêng. Lỗi được log và thử lại ở lượt sau, không giữ callback hoặc event list trong RAM. Hủy context dừng timer và I/O đang chạy.

Mặc định giữ context tối đa 90 ngày, theo MaxEventAge; nếu `-events-ttl-days` dương và ngắn hơn thì dùng hạn đó. Giá trị 0 giữ context ở mức 90 ngày (không suy ra TTL đang có của bảng). Không đổi TTL sự kiện hay thời gian giữ annotation/audit/request_id. Backlog được dọn dần; đây không phải giới hạn dung lượng đĩa tuyệt đối hoặc cam kết mọi row hết hạn biến mất ngay lập tức.

Kiểm chứng trong dev image, CPU 6–10, PostgreSQL 17.11 riêng:

```text
go test -race -count=1 -v ./rulehealth ./cmd/server
--- PASS: TestContextRetentionRunsAgainstPostgres (0.53s)
--- PASS: TestContextRetentionUsesBoundedBatchAndRetries (0.00s)
--- PASS: TestContextRetentionHonorsShorterAgeAndCapsLongerAge (0.00s)
--- PASS: TestContextRetentionCancellationInterruptsStoreCall (0.00s)
--- PASS: TestContextRetentionAlreadyCancelledDoesNotCallStore (0.00s)
ok .../rulehealth 1.619s
ok .../cmd/server 1.177s
golangci-lint run
0 issues.
```

Test PostgreSQL chạy worker thật, tạo context 91 ngày và context mới: chỉ context cũ bị xóa, cả hai annotation vẫn còn. Các test còn lại kiểm batch/deadline/cutoff, retry lỗi DB, hạn 7 ngày, cap hạn 180 xuống 90 ngày, cancel giữa I/O và cancel trước startup. Warning fixture DB trong output là lỗi được chủ động tiêm để kiểm retry. Log ở [evidence](evidence/m4-context-retention/).

Không đổi schema/API/proto/dependency; không tắt test hoặc nới deadline cũ. Không chạy staging/production hoặc chờ hosted CI. Đây là vòng đời dữ liệu M4; endpoint health/evaluator/outbox và quarantine có tác dụng thật ở engine vẫn còn việc, không coi worker này là đã xử lý toàn M4.

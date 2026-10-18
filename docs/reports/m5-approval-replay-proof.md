Nhiệm vụ: M5 · approval lưu operation replay đã được duyệt (phần 3)

Admin truyền operation DONE của đúng policy/version vào transaction quyết định. PostgreSQL lưu `approved_replay_id`; operation PENDING, sai policy/version hoặc thiếu bị từ chối. Một replay chạy sau đó không tự thay operation đã bind. Audit của quyết định chứa reference này. Migration 0017 cũng thêm input_digest của bundle để phần deploy kế tiếp lưu provenance. Lỗi replay precondition có kiểu riêng cho API trả FailedPrecondition.

Bằng chứng local:
- `TestApprovedReplayIsDurableInPostgres`, `go test -race ./store`, PostgreSQL lab riêng: PASS; test PENDING bị từ chối, DONE được chấp nhận, Store mới đọc lại đúng operation, operation mới không đổi approval.
- `go test -race ./admin` PASS; test API kiểm audit truyền đúng `op-1` khi approve.
- Migrations lên/xuống được chạy trong `TestFourEyesInPostgres`: PASS; quy tắc subject của 4 mắt giữ nguyên.
- `golangci-lint run`: 0 issues trong đợt kiểm cùng thay đổi.

Giới hạn: approval cũ không tự được gán proof. Khi bật gate deploy của PR kế tiếp, bản chưa bind cần tạo phiên bản mới, replay và duyệt lại. Không dùng một replay mới để tự hợp thức hóa approval cũ; không chờ hosted CI.

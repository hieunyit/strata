Nhiệm vụ: H3 · quyền đánh dấu false positive

Đã làm:
- `:markFalsePositive` yêu cầu `exceptions.write` trước khi gọi handler.
- Ma trận viewer/approver → 403 và không ghi; operator/admin → 200.
- Dùng principal có subject trong test; chuẩn hóa gofmt file handler của prototype.

Bằng chứng cục bộ:
- Trước sửa: `TestMarkFalsePositivePermissionMatrix` FAIL, viewer và approver nhận 200 (`build/h3-red.log`).
- `go test -race ./api` → PASS (`build/h3-checks.log`).
- Kiểm tra lint đang được chạy cùng đợt sửa.

Giới hạn: sửa quyền trên prototype W14-G2-01; lưu annotation bền vững và audit được xử lý ở M1 trước khi coi luồng này sẵn sàng sử dụng. Không chờ hosted CI theo yêu cầu PO.

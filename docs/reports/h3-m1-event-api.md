Nhiệm vụ: H3 + M1 · endpoint false positive có quyền và lưu bền vững

Hành vi:
- `POST /v1/events/{block_id}:markFalsePositive` cần `exceptions:write`; viewer và approver nhận 403 trước mọi ghi. Operator/admin được ghi.
- Annotation/audit đi PostgreSQL (PR #122), tuyệt đối không INSERT bản sao vào ClickHouse. Thiếu PostgreSQL hoặc lưu lỗi trả 503, không báo thành công.
- GET và search overlay từ một query cho cả trang; bỏ qua annotation do agent gửi. Người xem vẫn bị che IP/snippet như cũ.
- JSON chỉ nhận một object, chặn unknown fields/trailing JSON, reason rỗng hoặc >500 byte, request_id >128 byte, body >4 KiB. Cập nhật cần etag (409 khi cũ); request_id hỗ trợ retry.
- OpenAPI và TypeScript được sinh lại. Phân loại FP chưa tự thay đổi enforcement.

Bằng chứng local:
```
# PostgreSQL 17.11 lab riêng, go test -race ./api -run TestEventAnnotationAPIInPostgres -v
--- PASS: TestEventAnnotationAPIInPostgres (0.67s)
PASS
ok github.com/strata/strata/control-plane/api 1.780s
# go test -race ./api ./ingest ./cmd/server
ok github.com/strata/strata/control-plane/api 2.577s
ok github.com/strata/strata/control-plane/ingest 5.142s
# golangci-lint run
0 issues.
# npm run generate:api && npm run lint (Node 24.21)
> tsc --noEmit
```
Integration test chứng minh: ma trận quyền và không ghi khi bị từ chối; server/store mới đọc lại annotation; overlay search; viewer masking; retry; etag conflict/edit; số raw event vẫn 3; body xấu; event thiếu; sai method; thiếu durable store. Lỗi quyền đã tái hiện trên prototype trước sửa: viewer/approver trả 200 (`build/h3-red.log` trong worktree này).

Tự review: context cho I/O, deadline 5 giây; audit cùng transaction trong store; không giữ token/secret; chỉ thêm API tương ứng phạm vi review đã duyệt; không dependency mới. Chạy local, không chờ hosted CI theo yêu cầu PO.

Giới hạn: chưa nhập exception API từ prototype vì còn lỗi vòng đời/compiler; chưa có UI nút phân loại ở main. Việc lọc FP theo rule để quarantine thuộc M4, không suy ra tỉ lệ FP từ số block.

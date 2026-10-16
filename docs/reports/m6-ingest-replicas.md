Nhiệm vụ: M6 · ingest qua nhiều replica

Thay đổi:
- Khi PostgreSQL được cấu hình, mỗi batch giữ khóa dòng theo node; số thứ tự chỉ commit sau khi ClickHouse lưu thành công. ACK đợi cả commit PostgreSQL. Lỗi/timeout không ACK thành công. Khóa có deadline 10 giây.
- Migration 0015 giữ watermark tới khi node bị xóa. Node chưa enroll và sequence 0 hoặc vượt bigint bị từ chối.
- Search, point lookup và Overview dùng FINAL để loại bản trùng vật lý ngay, kể cả trước background merge.

Kiểm chứng cục bộ:
```
# go test -race ./ingest ./store ./cmd/server
ok github.com/strata/strata/control-plane/ingest 5.228s
ok github.com/strata/strata/control-plane/store 1.091s
# golangci-lint run
0 issues.
# PostgreSQL 17.11 độc lập, TestIngestAcrossReplicasInPostgres
--- PASS: TestIngestAcrossReplicasInPostgres (0.72s)
# ClickHouse 25.8.33 độc lập, -race
--- PASS: TestContext_ClickHouseOldTableAndLookup (0.40s)
--- PASS: TestOverview_ClickHouseMatchesMock (1.88s)
```
Test mới: 20 lời gọi từ hai store chỉ ghi một lần; retry sau lỗi; store mới/restart; sequence sai; node lạ; timeout khi chờ khóa; hai IngestService dùng chung gate. ClickHouse cố ý STOP MERGES và lưu hai lần: search/total/series/top vẫn khớp 400 sự kiện. Với code cũ cùng test FAIL: Total 800 (`build/m6-red.log`).

Tự review: lỗi được trả lên; context có deadline; không đổi proto/bundle; không ghi secret/PII; không thêm dependency. Không đợi hosted CI theo yêu cầu PO.

Giới hạn:
- Đây là at-least-once giữa hai database. Crash sau ClickHouse trước PostgreSQL có thể tạo bản trùng vật lý; FINAL bảo đảm kết quả logic theo khóa `(block_id,timestamp)` hiện có. Bản có timestamp khác vẫn là hai khóa.
- Watermark mới bắt đầu từ 0 khi nâng cấp: batch cũ có thể được ghi lại nhưng không bị mất; FINAL xử lý cùng khóa. Chưa benchmark FINAL trên dữ liệu sản xuất; cần đo lại SLO tìm kiếm 10 triệu dòng trước phát hành.
- Chế độ không PostgreSQL giữ dedup một tiến trình; không dùng cho triển khai nhiều replica.

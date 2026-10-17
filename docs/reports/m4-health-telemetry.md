# M4 — Đọc telemetry durable có giới hạn

Ngày 2026-10-17. Nhánh `codex/m4-health-telemetry`, base `10d9723` (PR #172). Chưa thêm route HTTP hoặc thay enforcement.

`ClickHouseStore.RuleTelemetry` đếm sự kiện chứa Rule ID bằng `FINAL`, cửa sổ nửa mở tối đa 24 giờ và policy tùy chọn. Cost gồm cả lần đánh giá không khớp trong top-eight đã nhận. Tổng samples/nanoseconds dùng UInt128, trả decimal string để không tràn UInt64 hoặc mất chính xác ở client JavaScript. Mean là Float64 xấp xỉ, chỉ trên mẫu sự kiện đó. Query có giới hạn 5 giây/256 MiB, tham số được bind.

`rulehealth.Service.Read` ghép dữ liệu này với số sự kiện FP đã có snapshot PostgreSQL. Mỗi replica tối đa 4 query đồng thời, vượt tải trả ErrBusy ngay; hai nguồn dùng chung một context 5 giây. Không gọi callback hoặc ghi trạng thái/audit khi đọc. Trạng thái chỉ mô tả dữ liệu: observing, insufficient_telemetry hoặc inconsistent_snapshot (FP snapshot nhiều hơn match hiện đọc); trường hợp thiếu/mâu thuẫn không dựng tỷ lệ giả hoặc clamp số liệu. Không trả healthy/quarantined.

Kiểm chứng cục bộ, `-race`:

```text
TestRuleCosts_ClickHouseMigrationAndRetry (ClickHouse 25.8.33 thật)
--- PASS ... (0.75s)
ok .../ingest 1.828s
go test -race -count=1 -v ./rulehealth (PostgreSQL 17.11 riêng)
ok .../rulehealth 1.658s
go test -race -count=1 ./ingest
ok .../ingest 5.557s
golangci-lint run ./rulehealth ./ingest
0 issues.
```

Live test giữ các assertion migration/retry trước, thêm match ID lặp vẫn count 1; cost của event không match vẫn được cộng; khác policy và biên thời gian bị loại; hai counter UInt64 max cộng thành **36893488147419103230**, mean 1 ns. Ba test service mới kiểm trạng thái/NULL, tỷ lệ báo cáo 0,2, timeout dùng chung, lỗi cả hai nguồn, input sai/thiếu store, 4 query đang chạy chặn query thứ 5 và cancel dừng I/O. Retention PostgreSQL cũng chạy lại; các opt-in ClickHouse khác trong lượt unit không env thì skip, không tính thành live. Log [evidence](evidence/m4-health-telemetry/).

Không đổi schema/proto/bundle/dependency; không sửa/tắt assertion cũ. Không gọi staging/production hoặc chờ CI. Chưa benchmark reader này ở 20 triệu row/tải đồng thời; giới hạn trả lỗi khi không đủ tài nguyên, không biến lỗi thành số 0. Đây là phép đọc hai database ở các snapshot độc lập.

Số FP là sự kiện được gán nhãn có chứa rule, cost là top-eight sampled security events; chưa có coverage đầy đủ của traffic hay attribution riêng từng rule. Endpoint, contract/client và kiểm chứng API với cả hai DB là bước tiếp theo. Auto quarantine/evaluator/outbox/runtime còn cần xử lý; câu hỏi đang chờ người dùng về opt-in tự hạ mức chặn so với tạo draft qua replay/4 mắt. Trong lúc chờ chỉ hoàn thiện phần đọc, không tự cấp quyền bypass gate.

# M4 — Giữ telemetry chi phí rule từ sự kiện

Ngày 2026-10-17. Nhánh `codex/m4-event-rule-costs`, base `9810ad5`. Đây là phần nền dữ liệu của M4, chưa phải health/quarantine hoàn chỉnh.

## Đã sửa

- `fleet.toIngest` trước đây bỏ hoàn toàn `Event.rule_costs` dù engine/agent đã gửi. Nay copy tối đa **8** mục đúng giới hạn proto, kiểm giới hạn trước vòng lặp/cấp phát.
- Ingest giữ mẫu nội bộ, kiểm số mẫu, max/total/average và ID trùng bằng phép toán không overflow. Telemetry tùy chọn sai bị loại, sự kiện bảo mật vẫn được giữ. Rule ID 0 là prefilter dùng chung, không gán cho rule cụ thể.
- ClickHouse lưu bốn mảng Nested `rule_id`, `samples`, `total_ns`, `max_ns` trong cùng row sự kiện. `EnsureColumns` migrate bảng cũ, chạy lại được; row cũ mặc định mảng rỗng. Dùng cùng ReplacingMergeTree/FINAL của sự kiện để đọc bản mới nhất và aggregate không đếm đôi retry chưa merge.
- GetEvent đọc lại telemetry cho nội bộ. `json:"-"` giữ nguyên API JSON công khai; không đổi proto/OpenAPI/bundle hoặc thêm dependency. Không mở API health từ prototype RAM.

## Bằng chứng và kiểm chứng

Test gRPC thật/mTLS với store in-memory, trước khi nối converter (hàm `toIngest` vẫn như base):

```text
TestPushEventsPreservesSampledRuleCosts
sampled costs lost ... RuleCosts:[]
--- FAIL ... (0.07s)
```

Sau sửa: test gửi cùng batch hai lần qua gRPC, đúng node từ certificate, cost giữ nguyên và chỉ một batch được chấp nhận; thêm ca đủ 8, quá 8 và phần tử nil. PASS **1,228 s** cả package chọn test.

ClickHouse 25.8.33 thật, database tạm riêng, context 30 giây và cleanup:

```text
--- PASS: TestContext_ClickHouseOldTableAndLookup (0.55s)
--- PASS: TestLookup_ClickHouseSkewAndUnmergedRetry (0.42s)
--- PASS: TestRuleCosts_ClickHouseMigrationAndRetry (0.58s)
ok .../ingest 2.667s
```

Ca mới bỏ cột cost để mô phỏng bảng cũ, ghi row cũ, migrate hai lần, xác nhận row cũ vẫn tra được; dừng merge, ghi lại sự kiện hai lần, đọc đủ cost và aggregate rule 942100 vẫn **2 mẫu / 700 ns**. Prefilter được giữ riêng. Đây là hai boundary test (gRPC→mock và store→ClickHouse), chưa phải một chain duy nhất từ NGINX tới ClickHouse.

Toàn control plane: `go test -race -count=1 ./...` với PostgreSQL 17.11 riêng, CPU 6–13: **mọi package PASS**, Fleet **28,629 s**, store **8,458 s**. Tiếp theo `golangci-lint run`: **0 issues**. Không dùng `-short`, không bỏ load test 1.000 agent. Test âm phủ sample=0, max>total, average không thể xảy ra, max=0/total>0, ID trùng/quá giới hạn; test UInt64 extrema và JSON không lộ trường nội bộ. Test ClickHouse opt-in trong lượt full không có env thì skip, bằng chứng live ở lượt riêng trên.

Log: [evidence](evidence/m4-event-rule-costs/); mã test được commit để tái lập. Lượt live đầu dùng sai user fixture bị từ chối xác thực; lượt PASS dùng đúng cấu hình container riêng, không tắt/bỏ qua xác thực. Không chạy CI trả phí, staging hay production.

## Giới hạn và việc còn lại

`Event.rule_costs` chỉ là **top 8 rule tốn nhất của sự kiện được lấy mẫu**, không phải mọi request hay mọi lần đánh giá rule. Không được dùng mẫu này làm average không lệch của toàn traffic hoặc lấy thiếu telemetry thành chi phí 0. Các cumulative counter của worker vẫn mới tới Prometheus agent (50 label + other), chưa chuyển thành durable per-rule health tại control plane.

M4 vẫn cần aggregation FP/match durable có retention và scope, GET chỉ đọc, evaluator/outbox/audit ngoài request path và hành vi chỉ ghi log thật ở engine. Không dùng ngưỡng tự quarantine của prototype làm mặc định production. Benchmark M6 #167 ghim mã trước phần thêm cột này; chưa đo lại SLO 20 triệu row có cost telemetry hoặc tải đồng thời. Không đổi hai lựa chọn “chỉ đo” về body/rate-limit.

Tự review: không có vòng lặp cost không giới hạn, không đưa telemetry agent thành quyết định enforcement, không thêm callback/lock/I/O vào request NGINX, giữ lỗi DB được trả về, không bỏ FINAL/test hiện có, không đưa credential/PII thật vào source hoặc báo cáo.

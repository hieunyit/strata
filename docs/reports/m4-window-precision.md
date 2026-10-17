# M4 — Cùng ý nghĩa cửa sổ thời gian ở hai database

Ngày 2026-10-17. Nhánh `codex/m4-window-precision`, base `9f3dd0e` (PR #173). Phát hiện qua test biên khi nối API health.

`RuleTelemetry` dùng time.Time positional mặc định của clickhouse-go 2.49.0, được bind ở độ chính xác giây. Cận dưới yêu cầu sau event 1 ns vẫn đếm event trước cận. `RuleFalsePositiveEvents` truyền timestamp tới pgx ở độ chính xác microsecond: cận dưới sau event 1 ns bị cắt về chính timestamp event và cũng đếm sai. Hai nguồn có thể trả tập sự kiện khác cửa sổ được yêu cầu.

Đổi truy vấn health ClickHouse sang named parameter, `DateNamed(..., NanoSeconds)`/UTC; không ghép timestamp người dùng vào SQL. Với PostgreSQL, làm tròn từng cận **lên** microsecond trước bind để `>= from` và `< to` giữ đúng tập row trên lưới timestamp của DB. Giữ FINAL, scope policy, giới hạn thời gian/bộ nhớ, và logic dữ liệu thiếu/mâu thuẫn.

Test thật trước sửa:

```text
ClickHouse: fractional lower bound broadened: MatchedEvents:1 ... (want 0)
FAIL .../ingest 0.869s
PostgreSQL: FP count=1 want=0
FAIL .../store 0.711s
```

Sau sửa, cùng assertion cận dưới và bổ sung cận trên trước/sau event 1 ns:

```text
go test -race -count=1 -v -run '^TestRuleCosts_ClickHouseMigrationAndRetry$' ./ingest
--- PASS ... (0.73s)
ok .../ingest 1.815s
go test -race -count=1 -v -run '^TestRuleAnnotationsInPostgres$' ./store
--- PASS ... (0.65s)
ok .../store 1.741s
golangci-lint run ./store ./ingest
0 issues.
```

ClickHouse 25.8.33/PostgreSQL 17.11 riêng; fixture CH cố định phần millisecond tại .250 để assertion không phụ thuộc may rủi thời điểm chạy. Các assertion migration, retry, policy, UInt128, rollback/retention trước đó giữ nguyên. Log [evidence](evidence/m4-window-precision/).

Không đổi API/schema/bundle/dependency hoặc các query tìm sự kiện/Overview cũ trong bản sửa này; chưa khẳng định mọi query cũ đều giữ độ chính xác dưới giây. Chưa merge/deploy; không chờ hosted CI và không đổi enforcement.

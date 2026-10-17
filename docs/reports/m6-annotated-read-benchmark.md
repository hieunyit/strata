# M6 — Đo lại đường đọc có annotation PostgreSQL và cost telemetry

Ngày 2026-10-17. Nhánh `codex/m6-annotated-read-benchmark`, base `1945402` (PR #176), mã harness `95b48ee`. Production read path giữ nguyên từ stack M4.

Benchmark trước (#167) không bật annotation overlay và chưa có cột cost. Bản này thêm `TestClickHouseAPIAnnotatedPerf`, giữ test API cũ riêng; handler/RBAC/JSON thật + ClickHouse 25.8.33 + PostgreSQL 17.11 thật. Principal operator là fixture, không phải IdP/process server/Fleet/NGINX.

Fixture mới đúng **20.000.000 row**, 10 triệu tạo trong 24 giờ gần nhất + 10 triệu ở 29 ngày trước; OPTIMIZE FINAL trước đo. **200.922** row có ba cost entry tổng hợp, lấy mẫu độc lập với action để tránh toàn bộ cost rơi vào một nhóm. Timings trong row là dữ liệu kiểm hình dạng, không dùng làm cost calibration. Action dùng block/shadow đúng enum ingest. Active disk **814,17 MiB**, nạp **216 s**.

Tạo annotation qua store transaction cho **20/195 ID** được lấy mẫu; GET kiểm đúng flag FP, không chỉ đo handler cấu hình thiếu overlay. Các ID được đánh dấu đã được tra trước để lấy snapshot nguồn; không gọi đây là cold-cache test. Query tuần tự, host dùng chung; SQL/Go benchmark cpuset 6–10.

| Phép đo | API có PostgreSQL overlay | Store trực tiếp |
|---|---:|---:|
| Tra ID p50 | 61,225 ms (195 ID) | 59,454 ms (200 ID) |
| Tra ID p99 | **96,071 ms** | **91,360 ms** |
| Tra ID max | 124,591 ms | 91,670 ms |
| ID không có | 296,243 ms / 404 | 398,867 ms |
| Tìm tất cả 24 giờ | 1,131 s | 1,157 s |
| Policy | 1,213 s | 1,141 s |
| Block | 1,177 s | 1,256 s |
| Rule 942100 | 1,590 s | 1,665 s |
| Client IP | 1,649 s | 1,670 s |
| Node + method | 1,332 s | 1,341 s |
| Policy + rule + action | **1,893 s** | 1,864 s |
| Trang 41 | 1,291 s | 1,461 s |

Các hàng tìm kiếm là count + trang 50 event, 10 lần/ca; “p99” của 10 mẫu chính là max mẫu, không phải ước lượng tail production đáng tin cậy. Giữ nguyên assertion 1 giây/2 giây. Không bỏ FINAL hoặc fallback lệch giờ.

```text
--- PASS: TestClickHouseAPIAnnotatedPerf (113.23s)
ok .../api 113.289s
--- PASS: TestClickHousePerf (114.05s)
--- PASS: TestClickHouseTTL (0.31s)
ok .../ingest 114.393s
golangci-lint run ./api
0 issues.
bash -n tests/perf/clickhouse.sh → exit 0
```

Perf không dùng `-race`; đúng chức năng có các test race/live trong #169–#176. Hai container riêng dùng port ngẫu nhiên chỉ bind loopback, không dùng shared DB; sau `keep` đã xóa đúng hai fixture cùng anonymous volumes. Harness create/start riêng, giữ exit code và cleanup theo ID, không xóa theo tên chung. Không chờ hosted CI hoặc deploy staging/production.

Log, hash source và thông số ở [evidence](evidence/m6-annotated-read-benchmark/). Image CH `sha256:0152dd511befe6a2c2ef53e930726179669b08116da78500b37c51c96ff5ee77`, PG `sha256:2d2b8998d31037bf721cfdf764d76ba74171b4fab3431b7f72c27c56ddbdf9e3`.

Không suy ra throughput đa client, multi-replica ingest, query health aggregate hay SLO mọi tải từ lượt này. Chỉ có 20 annotation trong PG; chưa đánh giá kho annotation lớn/DB quá tải. Corpus/Block IDs thay đổi theo thời điểm sinh fixture, không phải cùng dataset byte-for-byte của #167. Không đổi body/rate-limit policy hoặc thêm dependency.

# M6 — Tra Block ID và tìm kiếm trên 20 triệu sự kiện

Ngày: 2026-10-17. Nhánh `codex/m6-query-performance-harness`, base `eb809c0` (`codex/h6-network-evidence`), mã sửa `dd40b70`. Đây là kiểm chứng local của stack remediation, chưa merge/deploy main.

## Lỗi và bản sửa

Lượt baseline thật không đạt mục tiêu Block ID <1 giây: API p99 **1,543 giây** trên 200 ID. Tra cứu cũ mở khoảng ±24 giờ quanh timestamp trong ID ngay từ đầu. `GetEvent` nay thử ±1 giây trước, sau đó vẫn thử ±24 giờ và toàn bộ partition nếu chưa thấy. Giữ `FINAL` để retry chưa merge vẫn trả bản mới nhất; lỗi truy vấn thật được trả về, không chuyển thành miss. Không tăng ngưỡng SLO hoặc đổi schema/index trong bản sửa này.

Harness `tests/perf/clickhouse.sh` dùng container riêng tên duy nhất, port ngẫu nhiên chỉ bind loopback, cleanup theo ID của container vừa tạo cùng anonymous volumes. Không xóa container trùng tên của người khác. Kiểm tra readiness, lỗi OPTIMIZE và đúng số row; không bỏ qua lỗi chuẩn bị fixture.

## Môi trường và cách chạy

- VM x86_64, Xeon E5-2696 v4 @2.20GHz; 16 vCPU, RAM 31,3 GiB. ClickHouse và Go benchmark cùng cpuset **6–10**. Máy dùng chung, không phải host hiệu năng chuyên dụng.
- ClickHouse `25.8.33`, image digest `sha256:0152dd511befe6a2c2ef53e930726179669b08116da78500b37c51c96ff5ee77`; dev image Go 1.25.
- 10.000.000 row rải trong 24 giờ gần nhất và 10.000.000 row trong 29 ngày trước đó; OPTIMIZE FINAL trước đo. Candidate: đúng **20.000.000 row**, 812,82 MiB active disk, tạo trong 223 giây.
- Dữ liệu tổng hợp có phân bố lệch policy, IP, rule, action, 8 node. Không dùng traffic/PII thật. Các lượt baseline/candidate tạo fixture ở thời điểm khác nhau; không phải cùng một dataset byte-for-byte hay phép đo cold-cache.

```sh
PERF_CPUS=6-10 STRATA_DEV_DOCKER_ARGS='-v /home/hellc/strata/build/go:/src/build/go' tests/perf/clickhouse.sh keep
```

`keep` giữ đúng fixture riêng để điều tra; sau đo xóa container riêng cùng volumes. Chạy không có `keep` tự cleanup. Không dùng staging/production.

API test dùng `httptest.NewServer`, handler/JSON/RBAC thật và ClickHouse thật, principal operator từ fixture `tokenRoles`; không phải kiểm chứng IdP, process server/Fleet hay reverse proxy. Store test gọi trực tiếp ClickHouseStore.

## Kết quả thật

| Phép đo | Baseline API | Candidate API | Candidate store |
|---|---:|---:|---:|
| 200 ID, p50 | 138,773 ms | 54,218 ms | 54,802 ms |
| 200 ID, p99 | **1.543,404 ms (FAIL)** | **97,673 ms** | **95,677 ms** |
| 200 ID, max | 1.606,903 ms | 98,297 ms | 97,493 ms |
| ID không tồn tại | 254,262 ms / 404 | 396,561 ms / 404 | 315,361 ms |

Tìm kiếm 24 giờ gồm count và trang 50 sự kiện, 10 lần mỗi trường hợp. Với 10 mẫu, thống kê được gọi p99 trong harness chính là max mẫu; chưa đủ mẫu để ước lượng tail production.

| Bộ lọc | Candidate API p99 | Candidate store p99 |
|---|---:|---:|
| Tất cả | 1,243 s | 1,121 s |
| Policy | 1,265 s | 1,264 s |
| Block | 1,455 s | 1,339 s |
| Rule 942100 | 1,566 s | 1,534 s |
| Client IP | 1,927 s | 1,642 s |
| Node + method | 1,354 s | 1,359 s |
| Policy + rule + action | 1,824 s | 1,654 s |
| Tất cả, trang 41 | 1,330 s | 1,368 s |

```text
--- PASS: TestClickHouseAPIPerf (111.95s)
ok .../control-plane/api 112.016s
--- PASS: TestClickHousePerf (112.13s)
--- PASS: TestClickHouseTTL (0.24s)
ok .../control-plane/ingest 112.396s
```

Baseline API FAIL nên shell dừng trước store/TTL; không ghi hai test đó đã chạy ở baseline. Log trước/sau và SHA-256 source nằm trong [evidence](evidence/m6-query-performance/).

## Đúng chức năng, lint và giới hạn

Test mới `TestLookup_ClickHouseSkewAndUnmergedRetry` chạy thật với ClickHouse, database riêng, `SYSTEM STOP MERGES`: timestamp trùng ID, lệch 2 phút, lệch 48 giờ, mỗi ca có hai bản chưa merge; luôn đọc `/latest`. ID không có trả NotFound. Test này kiểm đúng fallback/FINAL, không dùng timing assertion trên fixture nhỏ.

```text
go test -race ... -run '^TestLookup_ClickHouseSkewAndUnmergedRetry$' ./ingest
--- PASS: TestLookup_ClickHouseSkewAndUnmergedRetry (0.39s)
ok .../ingest 1.486s
go test -race -count=1 ./ingest → ok .../ingest 5.148s
golangci-lint run → 0 issues.
gofmt -d (hai file Go thay đổi) → không có diff
bash -n tests/perf/clickhouse.sh → exit 0
```

Các test ClickHouse opt-in khác trong lượt unit không có env nên skip; không tính skip là bằng chứng live. Phép đo perf không chạy `-race`; test đúng chức năng riêng có `-race`. Ngưỡng 2 giây của truy vấn IP chỉ còn khoảng 73 ms dư trong lượt này: cần quan sát tải đồng thời, số part chưa merge và quy mô triển khai, không suy ra SLO mọi tải từ một lượt local. Chưa kiểm chứng multi-replica ingest end-to-end chỉ bằng benchmark đọc này; watermark PostgreSQL có bằng chứng riêng PR #121.

Tự review: không bỏ FINAL, không nuốt lỗi, probe hữu hạn, database test có cleanup/context deadline, không đổi API/proto/dependency, không log credential; chỉ sửa ingest, perf harness và tài liệu liên quan. Không chờ hosted CI theo yêu cầu.

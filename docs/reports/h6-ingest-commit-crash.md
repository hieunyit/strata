H6 · Crash giữa CH commit và watermark PostgreSQL, panic qua spool · 18/10/2026 (UTC+7)
Nhánh `codex/h6-ingest-commit-crash`, base `codex/l3-activation-load-measurement` (`b0fc4c7`).

Mở rộng fixture process-restart hiện có, không thêm hook/dependency hay đổi code production. PostgreSQL/ClickHouse/CA/node/ports đều thuộc test mới. Control plane và agent là executable thật build `-race`; NGINX hai worker dùng C module ASan/UBSan, signed preinstalled một rule SQLi. Không giả lập event/ACK. Đường replay/deploy riêng đã có bằng chứng M2/M4, không suy ra từ fixture preinstalled này.

Database test cài BEFORE UPDATE trigger ở `ingest_sequences`, đợi advisory lock do connection test giữ. Server thật chạy `WithIngestBatch`: lấy per-node lock → ghi CH thành công → bị chặn trước cập nhật/commit watermark. Test quan sát `pg_blocking_pids`, thấy **40 event đã có trong CH** nhưng watermark/agent ACK vẫn **1**, spool còn unacked. SIGKILL process CP ở đúng trạng thái này, thả barrier/xóa trigger, gửi thêm 80 SQLi và một request kích hoạt **test-only engine panic** khi CP còn tắt. Panic được FFI bắt: HTTP 200/action error/EVT ID, được agent spool; không gọi HTTP 200 đó là inspection thành công. Khởi động process CP mới cùng địa chỉ/config/DB, agent tự reconnect/resend; gửi thêm 20 SQLi.

| Kiểm chứng | NGINX 1.30.5 | NGINX 1.31.6 |
|---|---:|---:|
| Native IDs trong CH qua GetEvent | 141/141 | 141/141 |
| Thành phần | 140 block rule700011 + 1 error EVT | 140 block rule700011 + 1 error EVT |
| Watermark bền | 1 → 5 | 1 → 5 |
| Outage quan sát | 2,619 s | 2,715 s |
| Raw rows tại lúc đo | 141 | 141 |
| Test duration | 39,12 s | 40,48 s |

Từng ID được tra và kiểm node/policy version/action/rule, không chỉ count tổng; tất cả native ID duy nhất. Spool trở về 0 unacked, ACK không tăng lúc CP chết, invalid/truncated/drop bằng 0. Control file/bundle SHA và chữ ký last-known-good giữ nguyên. Không có ASan/UBSan report cả sau cleanup; LSan tắt như runbook, không claim leak test. Raw row 141 là quan sát ở thời điểm kiểm: CH có thể dedup/merge; **không biến hai commit thành atomic transaction hoặc cam kết exactly-once physical**. Đọc FINAL/idempotent retry vẫn cần thiết.

Regression process-restart cũ chạy lại nguyên luồng 20/80/20 và các assertion: **120/120 PASS**, 38,07 s. Tổng command stable 2 test PASS, Go -race 78,580 s; mainline 1 test PASS, Go -race 41,775 s. `golangci-lint run ./...` trong tests/e2e → **0 issues**. Trước mỗi phiên native đã `make nginx-asan NGINX_VERSION=<V>` bằng private target; không test module cũ sau đổi source. Lượt sơ bộ chưa thêm panic cũng 140/140 PASS, không dùng thay acceptance cuối.

Lệnh tái chạy: dev image network host, Docker socket/CLI + group988, private Go cache/Rust target, `STRATA_TEST_COMPILER=/src/target/release/strata-compile`, `STRATA_TEST_NGINX`/`STRATA_TEST_NGINX_MODULE` trỏ bản ASan tương ứng. `STRATA_CP_COMMIT_EVIDENCE_DIR=/src/build/NEW` rồi `go -C tests/e2e test -race -count=1 -timeout 6m -v -run '^TestControlPlaneCrashBetweenIngestCommits$' .`. Regression cũ dùng **biến riêng** `STRATA_CP_RESTART_EVIDENCE_DIR`, tránh hai test đụng output. [Result từng node, đủ IDs, log/build/source hashes](evidence/h6-ingest-commit-crash/).

Tự review: đúng window được chứng minh bằng CH + PG lock/ACK, lỗi không nuốt và barrier/connection/process có cleanup; request/batch/timeouts bounded; chỉ fixture/DB lab, không token/key thật; chỉ tests/e2e/report, không schema migration/interface; lint sạch. Đây là crash-window và panic-event chain đã kiểm local. Corrupted artifact qua toàn chain, tải/đa node/diễn tập vận hành vẫn riêng, chưa gọi full game day hoàn tất; không merge/deploy/chờ hosted CI.

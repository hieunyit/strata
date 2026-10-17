# L4 — Đối chiếu main và kiểm tích hợp remediation ngày 17/10

Nhánh tài liệu `codex/l4-stage3-status`, base kỹ thuật `codex/remediation-stage3` tại `54bc37e`. Không merge main và không deploy.

Main được xác minh bằng `git ls-remote origin refs/heads/main`: `e93dc0b4da55ec93ccf3c0a9421cdf8ed0f51719`. Main mới hơn baseline review `991c4bb` ở PR #141 (UI ergonomics/audit), không chứa các remediation chỉ vì chúng đã có trong worktree khác.

Base stage3 kết hợp chuỗi remediation trước đó, L3 cache preparation/evidence (#159–#165), H6 network drills (#158), main mới, H8 shell safety (#166) và M6 query (#167). Nhánh này phục vụ kiểm tích hợp; PR thành phần giữ base riêng để review. Một conflict trong `control-plane/store/store.go` đã được giải bằng cách giữ cả `ReplayOperation json:"-"` của remediation và trường `At`/JSON tags audit của main; không bỏ binding replay hoặc dữ liệu audit.

## Kiểm chứng

- UI trên `689eda7` (base main mới + stack + H8): lint exit 0; **15 file / 91 test PASS**; build Vite **16,13 s**. Không sửa UI sau lượt này; merge M6 chỉ đổi ingest/perf/docs. Xem [H8](h8-curl-shell-safety.md).
- Control plane trên cùng `689eda7`: `go test -race -count=1 ./...`, PostgreSQL 17.11 riêng qua `STRATA_TEST_POSTGRES_DSN`, CPU 6–13; **mọi package PASS**, tiếp theo `golangci-lint run` **0 issues**. Fleet package **29,906 s**, store **8,527 s**, API **8,035 s**. Đây là toàn bộ package, không dùng `-short` hoặc bỏ load test.
- Lượt Go đầu tiên dùng CPU 12–13, chạy đồng thời một lint riêng: `TestFleetLoad1000Agents` hết 30 giây chờ kết nối; **toàn lượt đó FAIL**. Rerun tám CPU khi benchmark đã kết thúc pass với cùng source/test/deadline/số agent; không nới timeout hoặc sửa assertion. Kết quả không khẳng định triển khai hai CPU chắc chắn đáp ứng load này.
- Sau merge M6 tại `54bc37e`: `go test -race -count=1 ./ingest` **PASS 5,148 s**. Các test ClickHouse opt-in không có env trong lượt này skip; live correctness và perf 20 triệu row có log/source hash riêng ở [M6](m6-query-performance.md).
- L3 compiler/FFI/NGINX không bị thay đổi bởi các merge UI/Go này; dùng bằng chứng 386 Rust test và 595 sanitizer test trên mỗi bản NGINX đúng SHA trong [báo cáo L3](l3-worker-cache-preparation.md), không tuyên bố đã build lại chúng ở SHA tích hợp này.

Output Go rerun và test ingest ghép nằm trong [evidence](evidence/l4-stage3-integration/). Cập nhật tracker sửa các trạng thái đã lỗi thời về cold worker, rate measurement, ClickHouse; thêm H8 thành phát hiện thứ 25, không gộp chìm vào review cũ. Không sửa con trỏ tuần PO, không đóng issue hoặc xác nhận Gate dựa trên kiểm chứng local.

Các mục vẫn còn việc thực: M4 health/quarantine durable/runtime, full game day và campaign redteam, cost calibration, large-body #28, hai ca XSS header và review rule, ET archive nguyên bản. Hai quyết định “chỉ đo” về body policy và rate saturation được giữ nguyên. Chưa có bằng chứng rollout staging/production mới; không chờ CI trả phí theo yêu cầu.

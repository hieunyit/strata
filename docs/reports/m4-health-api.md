# M4/H4 — API health chỉ đọc, route đúng và contract

Ngày 2026-10-17. Nhánh `codex/m4-health-api`, base `cc00e34` (PR #174). Chưa bật auto quarantine.

`GET /v1/rules/{rule_id}/health` dùng reader durable của PR #173/#174. Main chỉ cấu hình khi có cả PostgreSQL và event store hỗ trợ telemetry (ClickHouse). Thiếu nguồn thì không quảng bá route tùy chọn. `events:read` cho viewer/operator/approver/admin; không trả IP/snippet. Đọc có Cache-Control no-store; lỗi nguồn/capacity là 503, busy có Retry-After 1; không lộ chi tiết lỗi DB.

Dispatch kiểm đúng segment `/health`, các đường rule khác được chuyển tới admin gateway để tiếp tục route/RBAC hiện có. Không nhập health monitor RAM của prototype. Handler chỉ cho GET, ID UInt32 dương, query tối đa 2048 byte, policy ID theo NamePattern, cửa sổ nửa mở dương tối đa 24 giờ; mặc định 5 phút. Từ chối tham số lặp/lạ, timestamp sai và URL encoding hỏng để không âm thầm bỏ scope.

OpenAPI mô tả đúng ba trạng thái dữ liệu, phạm vi cost top-eight, FP event không phải attribution riêng, trường NULL khi thiếu/mâu thuẫn, counter UInt128 dạng chuỗi. Đã sinh lại client types; không thêm giao diện/nút tự quarantine.

Kiểm chứng:

- Hai test API mới: 401 không gọi reader; bốn role đọc được; chuỗi counter lớn giữ nguyên; emergencyDisable/path phụ được forward, không bị health intercept; input âm bị chặn trước I/O; POST 405; error detail không lộ; busy/no-store; thiếu nguồn 404. Lượt chọn test PASS, API **1,129 s**, cmd/server **1,168 s**.
- Mã cuối: `go test -race -count=1 ./...` với PostgreSQL 17.11 riêng, CPU 6–13: **mọi package PASS**, API **8,611 s**, store **9,127 s**, Fleet **31,128 s**, rulehealth **1,468 s**. `golangci-lint run`: **0 issues**. Không `-short`, không đổi deadline/load test.
- Node 24.21.0: `npm run generate:api` (openapi-typescript 6.7.6), `npm run lint`: exit 0; `npm run build`: **15,05 s**. Chỉ thay schema type, không sửa UI runtime. Admin generated types không phát sinh diff.

Log [evidence](evidence/m4-health-api/). Lượt full không có env ClickHouse nên các test CH opt-in skip; live query/biên thời gian ở PR #173/#174 có bằng chứng riêng. Chưa có test API với **cả hai DB trong cùng chain** trong PR này; đó là kiểm chứng kế tiếp. Admin gateway trong test forward là stub, không dùng 204 của stub làm bằng chứng RBAC mutation thật.

Không thay enforcement, body policy, rate saturation, proto/bundle/dependency. GET không đánh giá hoặc gán trạng thái quarantine. Cơ chế tự giảm mức chặn so với replay/4 mắt đang chờ lựa chọn của người dùng; phần chỉ đọc được hoàn thiện độc lập. Chưa merge/deploy, không chờ hosted CI và không đóng M4/Gate chỉ từ các test trên.

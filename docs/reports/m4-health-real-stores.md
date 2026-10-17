# M4 — HTTP health với cả hai SQL store thật

Ngày 2026-10-17. Nhánh `codex/m4-health-real-stores`, base `d5fcc29` (PR #175).

Đã thêm `TestRuleHealthDurableSources` và harness `tests/e2e/rule-health.sh`: PostgreSQL 17.11 + ClickHouse 25.8.33 trên network riêng, tên duy nhất, credential ngẫu nhiên của fixture, không publish port hay dùng shared volume. Docker create/start được tách để cleanup luôn có đúng ID sở hữu. Readiness có timeout; trap giữ exit code lỗi và dọn mọi container/anonymous volume/network của lượt chạy.

Chạy local:

```sh
TEST_CPUS=6-10 STRATA_DEV_DOCKER_ARGS='-v /home/hellc/strata/build/go:/src/build/go' tests/e2e/rule-health.sh
```

```text
=== RUN TestRuleHealthDurableSources
--- PASS: TestRuleHealthDurableSources (0.97s)
PASS
ok .../control-plane/api 2.127s
golangci-lint run ./api
0 issues.
bash -n tests/e2e/rule-health.sh → exit 0
```

Test đi qua handler HTTP/RBAC với principal fixture, ClickHouse và PostgreSQL thật:

- Ghi hai bản cùng event khi dừng merge; health đếm **1** match, **2** mẫu/mean **350 ns**, FP 0.
- Operator đánh dấu FP qua API; viewer đọc FP **1**. Tạo lại API/reader/PG store object vẫn thấy FP 1; không phải test restart process/DB server.
- Cửa sổ bắt đầu sau event 1 ns: cả hai nguồn trả 0, share NULL. Kiểm biên chính xác của PR #174 được thực thi qua API.
- Bốn lần GET không thêm audit (chỉ **1** audit của mark FP), không sửa hai row gốc; status vẫn observing, không giả quarantine.

Chủ động làm dev-run thất bại bằng một Docker flag không tồn tại: script giữ **exit 125**, cleanup PASS. Kiểm lại cả lượt PASS và lượt lỗi đều còn **0 container / 0 network** của chính fixture. Log/test output và kiểm cleanup ở [evidence](evidence/m4-health-real-stores/).

Event được seed trực tiếp trong ClickHouse; auth principal là fixture, HTTP gọi qua handler/httptest. Không dùng kết quả này làm chứng cứ NGINX→agent/Fleet→ingest, IdP, TLS deployment, database crash durability hoặc SLO trên 20 triệu row. Các test real-store opt-in khác không nằm trong lệnh chọn test này. Không thêm dependency, không bỏ qua xác thực/kiểm chữ ký hiện có; không chạm staging/production, không chờ hosted CI.

M4 đã có dữ liệu FP/cost durable, retention và API chỉ đọc; auto evaluator/outbox và tác dụng quarantine thật chưa hoàn tất, đang chờ lựa chọn về cơ chế tự giảm mức chặn so với replay/4 mắt.

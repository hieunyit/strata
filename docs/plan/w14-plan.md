# Kế hoạch chi tiết tuần 14 · Exception từ Block ID, Sức khỏe rule, Game Day

Nguồn: `docs/plan/plan.md` (mục "Tuần 14"), `docs/plan/dispatch.md` (mục "Tuần 14"), `AGENTS.md`.  
Khối: **B2** · Tuần 14. Lập ngày 16/10/2026.

Mục tiêu demo tuần 14: **Helpdesk xử lý một ca chặn nhầm từ Block ID tới khi exception được duyệt và có hiệu lực trong dưới 15 phút.**

---

## 1. Danh sách nhiệm vụ và thứ tự thực hiện

| Thứ tự | Mã nhiệm vụ | Thành phần | Nội dung | Tiêu chí hoàn thành (Xong khi) |
| --- | --- | --- | --- | --- |
| 1 | **W14-G2-01** | `control-plane/` | Exception từ Block ID & Đánh dấu FP (`POST /v1/exceptions:fromBlockId`, `:markFalsePositive`) | Exception sinh từ Block ID có phạm vi hẹp nhất (`route + field + Rule ID`), bắt buộc TTL hợp lệ; kiểm tra RBAC, audit log, 4-Eyes. |
| 2 | **W14-F-01** | `ui/` | 3 nút thao tác trên chi tiết sự kiện | Nút "Đánh dấu FP", "Tạo exception (tự điền)", "Chặn IP/Identity" hoạt động; kết nối API thật, chặn tự duyệt 4-Eyes. |
| 3 | **W14-R-01** | `engine/`, `control-plane/` | Rule Compiler: Exception trước Override, Cost Unit | Biên dịch đúng thứ tự ưu tiên (Exception trước Override); policy vượt cost budget bị từ chối; lọc exception hết hạn. |
| 4 | **W14-G2-02** | `control-plane/` | Sức khỏe rule & Tự cách ly (`GET /v1/rules/{rule_id}/health`) | Rule có FP tăng đột biến tự quay về staging (log-only) trong < 5 phút; cảnh báo người duyệt; chống flapping; audit log. |
| 5 | **RV-R-03** | `connectors/nginx/`, `engine/` | NGINX Rate Limiting tầng 1 theo node (P-01 §3) | Shared Memory counter theo IP/Identity/Route; bảo vệ route đăng nhập; không khóa, không I/O; benchmark giảm $\le$ 2%. |
| 6 | **W14-S-01** | `docs/runbook/`, `tools/` | Quy trình diễn tập Virtual Patch | Runbook `docs/runbook/virtual-patch.md`; diễn tập từ CVE tới staging trong < 24 giờ. |
| 7 | **W14-Q-01** | `docs/runbook/`, `tests/` | Kịch bản Game Day Chaos Testing | Runbook `docs/runbook/game-day.md` và script test 5 tình huống: tắt CP, tắt Agent, hỏng SHM bundle, panic, ngắt mạng. |
| 8 | **Canary 25%** | `docs/runbook/` | Kế hoạch quan sát Canary 25% (72 giờ) | Runbook `docs/runbook/canary-25.md`, dashboard metrics, ngưỡng cảnh báo và quy trình tự rollback. |

---

## 2. Chi tiết kỹ thuật từng nhiệm vụ

### Nhiệm vụ 1: W14-G2-01 · Exception từ Block ID và :markFalsePositive
- **Endpoint 1**: `POST /v1/events/{block_id}:markFalsePositive`
  - Quyền yêu cầu: `events:write` hoặc `events:read` (operator, approver, admin).
  - Kiểm tra format Block ID hợp lệ, tra cứu trong event store.
  - Cập nhật cờ `false_positive = true`, ghi nhận `reason` và `actor`.
  - Ghi bản ghi audit: `events/{block_id}:markFalsePositive`.
- **Endpoint 2**: `POST /v1/exceptions:fromBlockId`
  - Body: `{"block_id": "STR-...", "ttl_seconds": 604800, "reason": "Chặn nhầm tham số tìm kiếm"}`
  - Tự động trích xuất phạm vi hẹp nhất:
    - `policy_id` từ sự kiện.
    - `rule_id` từ matched rules hoặc violations (chọn rule chính vi phạm).
    - `field` từ violation target (`body.param`, `query.q`, ...).
  - Bắt buộc TTL hợp lệ: `ttl_seconds > 0` và $\le$ 30 ngày (mặc định 14 ngày nếu không chỉ định).
  - Lưu exception vào cơ sở dữ liệu với trạng thái `PENDING_REVIEW` hoặc `DRAFT`.
  - Cơ chế 4-Eyes: `created_by` được lưu lại; người tạo không thể gọi `:approve` cho chính exception này.
- **Endpoint 3**: `GET /v1/exceptions`, `DELETE /v1/exceptions/{id}`, `POST /v1/exceptions/{id}:approve`.

### Nhiệm vụ 2: W14-F-01 · Nút xử lý trên Chi tiết sự kiện
- Giao diện `ui/src/pages/EventDetailPage.tsx`:
  - 3 nút hành động chính:
    1. **Đánh dấu False Positive**: Mở hộp thoại xác nhận lý do $\rightarrow$ gọi `:markFalsePositive` $\rightarrow$ hiển thị badge "False Positive".
    2. **Tạo Exception (điền sẵn)**: Mở modal điền sẵn Policy, Rule ID, Field từ Event Trace $\rightarrow$ cho phép chọn thời hạn (7 ngày, 14 ngày, 30 ngày) $\rightarrow$ gọi `POST /v1/exceptions:fromBlockId`.
    3. **Chặn IP/Identity**: Mở modal xác nhận $\rightarrow$ gửi lệnh Emergency Disable / IP Block tới connector group.
  - Xử lý 4-Eyes: Kiểm tra caller username/subject vs exception `created_by`; vô hiệu hóa nút duyệt đối với người tạo.
  - Cập nhật i18n (`vi.json`, `en.json`) đầy đủ.

### Nhiệm vụ 3: W14-R-01 · Rule Compiler: Exception trước Override
- Thứ tự ưu tiên trong Engine & Compiler:
  1. **Exceptions (Hẹp, có hạn)**: Ưu tiên cao nhất. Nếu request khớp exception (đúng route, rule_id, field và còn hạn dùng), rule đó lập tức bị bỏ qua (`skip`).
  2. **Overrides (Có điều kiện)**: Ưu tiên thứ hai. Đổi cấu hình/tắt signature theo điều kiện (ví dụ `/upload` với multipart).
  3. **Score & Decision**: So sánh điểm tích lũy với ngưỡng policy.
- Kiểm tra ngân sách Cost Unit (`CostBudget`):
  - Tính toán tổng cost unit của bundle.
  - Nếu tổng cost vượt quá `CostBudget`, từ chối deploy với `CostError`.
- Lọc bỏ Exception hết hạn: Compiler tự động bỏ qua các exception có `expires_at < now`.

### Nhiệm vụ 4: W14-G2-02 · Sức khỏe rule & Tự cách ly
- **Endpoint**: `GET /v1/rules/{rule_id}/health`
  - Thống kê: `matches_count`, `fp_count`, `fp_rate`, `avg_cost_us`, `status` (`healthy`, `quarantined_staging`, `disabled`).
- **Cơ chế tự cách ly (Auto-Quarantine)**:
  - Nếu tỷ lệ FP tăng đột biến (ví dụ FP rate > 0.05% trong cửa sổ hoặc > 5 FPs được báo trong 5 phút), hệ thống kích hoạt tự cách ly.
  - Rule được tự động chuyển về chế độ `staging` (log-only, non-blocking) trong vòng dưới 5 phút.
  - Gửi thông báo / audit log cảnh báo tới người duyệt (approver).
  - Chống flapping: Thời gian cooldown tối thiểu 15 phút trước khi cho phép phục hồi.

### Nhiệm vụ 5: RV-R-03 · NGINX Rate Limiting tầng 1 theo node
- Thiết kế theo P-01 §3 tầng 1:
  - Vùng nhớ chia sẻ (Shared Memory zone) quản lý bộ đếm request theo `(IP, Identity, Route)`.
  - Bộ đếm không khóa, dùng phép cộng nguyên tử `ngx_atomic_fetch_add` hoặc tumbling window.
  - Bảo vệ route đăng nhập (`/api/v1/auth/login`, `/login`) chống brute-force và credential stuffing.
  - Ngưỡng cấu hình linh hoạt trong policy (ví dụ 10 req/min cho login).
  - Mức suy giảm hiệu năng $\le$ 2% khi benchmark.

### Nhiệm vụ 6: W14-S-01 · Quy trình Virtual Patch
- Runbook `docs/runbook/virtual-patch.md`:
  - 10 bước chuẩn hóa từ tiếp nhận CVE đến triển khai staging trong < 24 giờ.
  - Mẫu rule signature, kiểm thử exploit/benign, tính toán cost unit, review 4 mắt và rollback.

### Nhiệm vụ 7: W14-Q-01 · Diễn tập sự cố Game Day
- Runbook `docs/runbook/game-day.md` và script kiểm thử `tests/chaos/game_day_test.sh`:
  - Kịch bản 1: Tắt Control Plane $\rightarrow$ WAF Data plane hoạt động bình thường với bundle shm.
  - Kịch bản 2: Tắt Agent $\rightarrow$ Sự kiện đọng lại trong socket queue, NGINX không treo.
  - Kịch bản 3: Hỏng bundle SHM $\rightarrow$ Fail-open an toàn hoặc fallback bundle cũ, không crash worker.
  - Kịch bản 4: Panic trong libstrata $\rightarrow$ Catch unwind cách ly lỗi, trả về 500/fail-open theo cấu hình.
  - Kịch bản 5: Ngắt mạng $\rightarrow$ Node tiếp tục thực thi độc lập, tự kết nối lại khi có mạng.

### Nhiệm vụ 8: Kế hoạch Canary 25% (72 giờ)
- Runbook `docs/runbook/canary-25.md`:
  - Điều kiện tiên quyết: Gate A và Canary 1% / 5% đã hoàn tất.
  - Phân bổ 25% theo hash `(client_ip / identity, policy)`.
  - Ngưỡng ngắt khẩn cấp: Tỷ lệ 5xx > 1% hoặc số lần chặn tăng đột biến > 3 lần baseline.

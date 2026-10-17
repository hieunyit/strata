# Kế hoạch chi tiết tuần 19 · Drill-down và Rule Geo/ASN · Chế độ Lite Standalone

**Nguồn nhiệm vụ**: `docs/plan/plan.md`, mục "Tuần 19".
**Vai trò lập kế hoạch**: Principal System Architect & Lead Business Analyst (BA).
**Khối**: C1 (Tuần 17–19 · GeoIP, Bản đồ & Tự động hóa phòng thủ).

---

## 1. Phân tích Nghiệp vụ & Chân dung Người dùng (BA Perspective)

### 1.1. Chân dung người dùng (User Personas)
1. **SOC Analyst / Incident Responder (Người trực ca giám sát)**:
   - *Nỗi đau (Pain point)*: Thấy một quốc gia hoặc dải ASN lạ đang tấn công ồ ạt trên bản đồ nhưng phải mở nhiều tab, gõ lại IP hoặc tìm thủ công trong hàng triệu sự kiện; tốn 15–30 phút để xác định nguyên nhân.
   - *Kỳ vọng (Expectation)*: Nhấp vào quốc gia/ASN trên bản đồ -> toàn bộ màn hình tự động gom tiêu điểm vào đối tượng đó -> nhấp vào 1 dòng sự kiện xem ngay Decision Trace với payload vi phạm được tô màu -> nhấp 1 nút hành động để chặn hoặc challenge.
2. **Security Architect / Policy Approver (Người phê duyệt chính sách)**:
   - *Nỗi đau*: Hành động chặn nóng (emergency block) trên sản xuất dễ gây lỗi False Positive (chặn nhầm đối tác, bot tìm kiếm hoặc văn phòng chi nhánh).
   - *Kỳ vọng*: Hành động nhanh tạo ra một bản nháp (Draft Policy) tự động kích hoạt Replay Service kiểm thử trên dữ liệu 7 ngày gần nhất để tính toán số request hợp lệ bị ảnh hưởng trước khi trình duyệt 4 mắt (4-eyes workflow).
3. **Platform Engineer / Edge Deployer (Kỹ sư hạ tầng cụm nhỏ)**:
   - *Nỗi đau*: Triển khai WAF cho một văn phòng chi nhánh hoặc cụm gateway nhỏ không có tài nguyên chạy cả cụm PostgreSQL, ClickHouse, Control Plane, UI.
   - *Kỳ vọng*: Chỉ cần một lệnh cài đặt package NGINX module + `strata-agent --standalone` đọc bundle cục bộ, ghi log SIEM ra file JSON Lines/Syslog, chặn tấn công ngay trong 5 phút.

### 1.2. Mục tiêu Nghiệp vụ (Business Objectives & OKRs)
* **Demo tuần 19**: Từ việc nhìn thấy đợt bùng phát trên bản đồ đến khi rule chặn ASN được tự động sinh bản nháp, chạy replay kiểm tra FP, được duyệt 4 mắt và deploy ra node trong **dưới 10 phút**.
* **Độ trễ điều tra**: Giảm số lượt click từ lúc thấy bất thường trên bản đồ tới màn hình xem trace sự kiện vi phạm xuống **≤ 2 clicks**.
* **Độ chính xác phòng vệ**: Cung cấp chế độ Challenge (JS Challenge / Captcha) thay vì chỉ Block thẳng tay đối với các quốc gia có tỉ lệ truy cập hỗn hợp.

---

## 2. Phân công Nhiệm vụ Tuần 19 (`AGENTS.md` §3)

| Mã | Tên nhiệm vụ | Phân công | Thư mục chính |
| :--- | :--- | :---: | :--- |
| **W19-F-01** | Drill-down và Hành động nhanh (Quick Action) | **Antigravity** | `ui/src/pages/`, `ui/src/components/geo/`, `ui/src/components/events/` |
| **W19-G2-01** | Rule Geo/ASN trong Policy & API Quản trị | **Antigravity** | `control-plane/admin/`, `control-plane/api/`, `docs/spec/` |
| **W19-R-01** | Tra cứu Geo/ASN trong Engine & Đóng gói Bundle | **Claude Code** | `engine/`, `engine/compiler/` |
| **RV-G1-01** | Chế độ Lite Standalone cho cụm nhỏ | **Claude Code** | `agent/`, `deploy/packaging/`, `docs/design/` |

---

## 3. Kiến trúc Hệ thống & Luồng Dữ liệu (System Architecture)

```
[ GIAO DIỆN NGƯỜI DÙNG - UI ]
┌────────────────────────────────────────────────────────────────────────┐
│ 1. GeoMap / Timeline Chart (Click Quốc gia VN/US hoặc ASN 7552)       │
│    └─► Cập nhật URL Query Params (?country_iso=...&asn=...)            │
│ 2. Deep-Linked SOC Dashboard (Đồng bộ Map, Bảng sự kiện, Timeline)     │
│    └─► Click 1 Sự kiện ──► Popover Decision Trace (Payload highlight)   │
│ 3. Quick Action Button: [ ⚡ Chặn Geo/ASN ]                           │
│    └─► Modal xác nhận phạm vi: Block / Challenge / Monitor             │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │ POST /v1/policies/{id}/quick-rule
                                   ▼
[ CONTROL PLANE API & ADMIN ]
┌────────────────────────────────────────────────────────────────────────┐
│ 1. Policy Schema Expansion: Hỗ trợ khối `geo_restrictions`             │
│    { "block_countries": [...], "block_asns": [...], "default": "pass"} │
│ 2. Draft Policy Generator: Tạo phiên bản nháp tự động kế thừa         │
│ 3. Tự động kích hoạt Replay Service (W13-G2-01) đo lường FP            │
│ 4. Chuyển vào hàng đợi Four-Eyes Approval Workflow (W13-G2-02)         │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │ Compile & Sign
                                   ▼
[ ENGINE & AGENT - CLAUDE CODE ]
┌────────────────────────────────────────────────────────────────────────┐
│ 1. Compiler đóng `.mmdb` (GeoLite2-Country/ASN) vào Bundle nhị phân   │
│ 2. Libstrata Rust FFI tra cứu IP client tại node (0 microsecond latency)│
│ 3. Standalone Agent (RV-G1-01): Chạy chế độ --standalone không cần CP  │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Chi tiết Thực thi Kỹ thuật Từng Nhiệm vụ

### 4.1. W19-F-01 · Drill-down và Hành động Nhanh trên UI (Antigravity)
* **Thư mục**: `ui/src/components/geo/`, `ui/src/pages/OverviewPage.tsx`, `ui/src/components/events/`, `ui/src/components/policy/`
* **Các thành phần cụ thể**:
  1. **URL State Synchronization (Deep-linking)**:
     - Toàn bộ trạng thái bộ lọc của trang Tổng quan (`country_iso`, `asn`, `range`, `action`) được đồng bộ 2 chiều với URL Search Parameters (`useSearchParams` hoặc router query).
     - Cho phép kỹ sư SOC copy link chia sẻ trực tiếp qua Slack/Teams/Jira cho đồng nghiệp mở ra đúng tiêu điểm đang điều tra.
  2. **Inter-Component Interaction (Tương tác liên thành phần)**:
     - Nhấp vào 1 quốc gia trên bản đồ hoặc hàng trong bảng Top Quốc gia:
       - Bản đồ zoom vào quốc gia đó.
       - Filter Chip xuất hiện thẻ `Quốc gia: [Cờ] {Tên}` kèm nút `x`.
       - Bảng sự kiện phía dưới lọc tức thì danh sách sự kiện từ quốc gia đó.
       - Biểu đồ Timeline tự động vẽ lại chuỗi thời gian chỉ riêng của quốc gia đó.
     - Nhấp vào một sự kiện trên bảng: Mở modal **Decision Trace** hiển thị chi tiết các rule vi phạm, trường vi phạm và đoạn snippet nguy hiểm.
  3. **Quick Action Panel (Hành động nhanh)**:
     - Tại tooltip/popover của quốc gia hoặc ASN trên bản đồ, bổ sung menu hành động nhanh:
       * `⚡ Tạo Rule Chặn Quốc Gia (Block)`
       * `🛡️ Tạo Rule Thách Thức (Challenge/Captcha)`
       * `👁️ Tạo Rule Giám Sát (Monitor/Shadow)`
     - Bấm vào mở modal xác nhận cấu hình: chọn Policy áp dụng, mức hành động, ghi chú lý do.
     - Sau khi bấm "Tạo bản nháp", hệ thống gọi API `POST /v1/policies/{id}/quick-rule`, tạo bản nháp mới và chuyển hướng sang Policy Editor hoặc luồng duyệt 4 mắt.

### 4.2. W19-G2-01 · Rule Geo/ASN trong Policy & API (Antigravity)
* **Thư mục**: `control-plane/admin/`, `control-plane/api/`, `docs/spec/policies.schema.json`
* **Thiết kế chi tiết**:
  1. **Mở rộng Policy Spec Schema** (`docs/spec/policies.schema.json`):
     ```json
     {
       "geo_restrictions": {
         "type": "object",
         "properties": {
           "enabled": { "type": "boolean" },
           "default_action": { "type": "string", "enum": ["pass", "monitor"] },
           "blocked_countries": { "type": "array", "items": { "type": "string", "pattern": "^[A-Z]{2}$" } },
           "challenged_countries": { "type": "array", "items": { "type": "string", "pattern": "^[A-Z]{2}$" } },
           "blocked_asns": { "type": "array", "items": { "type": "integer", "minimum": 1 } },
           "challenged_asns": { "type": "array", "items": { "type": "integer", "minimum": 1 } },
           "exempt_ips": { "type": "array", "items": { "type": "string" } }
         }
       }
     }
     ```
  2. **API Endpoint Mới**:
     - `POST /v1/policies/{id}:quick-rule`:
       - Payload: `{ "type": "geo_block" | "asn_block", "target": "KP" | "12345", "action": "block" | "challenge", "reason": "DDoS surge" }`
       - Logic: Lấy bản draft hiện tại (hoặc tạo draft mới từ bản active), cập nhật mảng `blocked_countries` hoặc `blocked_asns`, lưu lại kèm lý do vào Audit Log.
     - Tích hợp kiểm định Replay (W13-G2-01) để tự động báo cáo số lượng request bị ảnh hưởng.

### 4.3. W19-R-01 · Tra cứu Geo/ASN trong Engine (Claude Code)
* **Thư mục**: `engine/`, `engine/compiler/`
* **Công việc**:
  - Compiler WAF nhúng dữ liệu GeoIP/ASN `.mmdb` vào bundle nhị phân đã ký hoặc đóng gói tham chiếu.
  - Libstrata Rust FFI thực hiện tra cứu IP tại node proxy với độ trễ < 1µs.
  - Kiểm tra các mẫu test case rule chặn theo Country và ASN.

### 4.4. RV-G1-01 · Chế độ Lite Standalone cho Cụm Nhỏ (Claude Code)
* **Thư mục**: `agent/`, `deploy/packaging/`, `docs/design/`
* **Công việc**:
  - Cập nhật `docs/design/nginx-module.md` mô tả kiến trúc Standalone Lite.
  - Phát triển cờ `--standalone` cho `strata-agent`: Tải bundle từ thư mục hoặc URL cục bộ, đọc metrics và xuất sự kiện ra file JSON Lines / Syslog (SIEM integration) mà không cần backend Postgres/ClickHouse.
  - Đóng gói cài đặt 1 lệnh (Single-command installation) cho VM sạch.

---

## 5. Kế hoạch Kiểm thử & Tiêu chuẩn Nghiệm thu (Acceptance Criteria)

### 5.1. Tiêu chí Hoàn thành (Definition of Done)
1. **W19-F-01**:
   - [ ] Bấm quốc gia trên bản đồ: URL thay đổi, bảng sự kiện lọc đúng quốc gia đó, timeline cập nhật tương ứng.
   - [ ] Bấm vào dòng sự kiện mở popover Decision Trace với các trường vi phạm được highlight.
   - [ ] Nút "Tạo rule chặn geo/ASN" tạo thành công bản draft policy trong dưới 3 giây.
   - [ ] Đạt 100% test suites Vitest (`npm test`).
2. **W19-G2-01**:
   - [ ] Schema `policies.schema.json` kiểm tra hợp lệ khối `geo_restrictions`.
   - [ ] API `POST /v1/policies/{id}:quick-rule` tạo bản nháp hợp lệ, không xung đột etag.
   - [ ] Ghi nhận đầy đủ nhật ký Audit Trail cho mọi thao tác Quick Action.
   - [ ] Đạt 100% Go unit tests (`go test -v ./...`).
3. **Kịch bản Demo Tích hợp**:
   - Kỹ sư SOC mở giao diện bản đồ -> Click vào quốc gia bất thường -> Click nút "Tạo rule chặn" -> Hệ thống tự sinh bản draft policy và đưa vào hàng chờ duyệt 4 mắt trong dưới 10 phút.

---

## 6. Lộ trình Triển khai Chi tiết Từng Ngày (Daily Schedule)

| Ngày | Kỹ sư phụ trách | Hạng mục công việc |
| :--- | :---: | :--- |
| **Thứ 2** | Antigravity | Bổ sung schema `geo_restrictions` trong `policies.schema.json` và xử lý logic backend `POST /v1/policies/{id}:quick-rule`. |
| **Thứ 3** | Antigravity | Viết unit tests cho `quick-rule` API, tích hợp ghi log Audit Trail và kiểm tra quyền RBAC `policies:write`. |
| **Thứ 4** | Antigravity | Xây dựng cơ chế đồng bộ URL State (Deep-linking) trên UI cho trang Overview (Map, Chips, Events, Timeline). |
| **Thứ 5** | Antigravity | Phát triển Quick Action Modal trên Popover bản đồ và liên kết trực tiếp với API tạo bản nháp policy. |
| **Thứ 6** | Antigravity & Claude Code | Tích hợp end-to-end: Từ Click bản đồ -> Tạo rule nháp -> Replay -> Luồng duyệt 4 mắt. Diễn tập kịch bản Demo tuần 19. |

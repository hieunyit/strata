# Kế hoạch Chi tiết Tuần 21 · Positive Model OpenAPI, Quản trị API Schema, Danh mục Rule & Exception UI, Red Team Đầy đủ & Kiểm thử Hồi quy Toàn bộ

> **Giai đoạn C** · Tuần 17–22: Hoàn thiện v1 · **Khối C2** (Tuần 20–22: Dashboard, OpenAPI, Red Team, v1 Release · Gate C)  
> **Nguồn nhiệm vụ**: `docs/plan/plan.md` (mục "Tuần 21"), `docs/plan/dispatch.md`, `docs/design/nginx-module.md`, `docs/design/strata-overview.md`.  
> **Ngày lập kế hoạch**: 18/10/2026.  
> **Tác giả**: Principal System Architect & Lead Detection Engineer (Antigravity & Claude Code).  
> **Người phê duyệt**: Product Owner (PO).  

---

## 1. Phân tích Bối cảnh & Chân dung Người dùng (User Personas & Business Context)

Tuần 21 là tuần bản lề áp chót trước khi phát hành v1 (Gate C), tập trung giải quyết 3 trụ cột sống còn của hệ thống WAF doanh nghiệp:
1. **Positive Security Model (Mô hình Phòng thủ Chủ động)**: Chuyển dịch từ việc chỉ đối sánh chữ ký tấn công (Negative Security) sang siết chặt đặc tả API theo chuẩn OpenAPI 3.0/3.1. Bất kỳ endpoint, method hoặc field nào không được khai báo trong schema đều bị từ chối ngay tại proxy.
2. **Trải nghiệm Quản trị SecOps (SecOps Experience)**: Hoàn thiện bức tranh quản trị với giao diện Danh mục Rule & Signatures (theo dõi tỷ lệ khớp, FP, chi phí CPU, nút Emergency Disable), quản lý Exceptions có cảnh báo hết hạn, và trình duyệt API Schema trực quan.
3. **Nghiệm thu Thực nghiệm Đối kháng & Hồi quy (Adversarial Validation & Full Regression)**: Vá toàn bộ các vector bypass mức cao đã phát hiện trong thử nghiệm red team, đóng gói signature pack v0.9, và chạy lại 100% test suite trên toàn bộ các thành phần (Rust Engine, C Connector, Go Control Plane, React UI).

---

## 2. Mục tiêu Nghiệp vụ & OKRs Tuần 21

### 2.1. OKRs (Objectives & Key Results)
* **OKR 1 (Positive Security Engine - W21-R-01)**:
  - Lõi engine kiểm tra tính tuân thủ của request với OpenAPI schema: endpoint, method, query parameter, body field.
  - Tự động sinh violation tương ứng (`600001` - `600004`) khi có request vi phạm schema. 100% test cases pass.
* **OKR 2 (API Schema Control Plane Service - W21-G2-01)**:
  - Cung cấp đầy đủ REST API để upload, validate, parse OpenAPI 3.0/3.1 (JSON/YAML) và biên dịch vào bundle nhị phân.
  - Hỗ trợ gắn schema vào policy để enforce tự động trên từng route.
* **OKR 3 (SecOps Rules, Exceptions & Schema UI - W21-F-01)**:
  - Xây dựng hoàn chỉnh trang Rules Catalog với chỉ số sức khỏe (Match count, FPs, CPU cost) và nút Tắt khẩn cấp (Emergency Disable).
  - Trang Exceptions với cảnh báo sắp hết hạn (`Expiring Soon` < 48h).
  - Trang Schema Viewer hiển thị tương tác các endpoints, methods, và properties.
* **OKR 4 (Red Team Hardening & Pack v0.9 - W21-S-01)**:
  - Vá dứt điểm các bypass mức cao từ `docs/reports/redteam-eval.md` (SQLi non-breaking spaces, double-encoded RCE, JSON nesting sâu > 64 tầng, tail padding #98 fail-closed).
  - Phát hành gói signature release `v0.9`. Báo cáo nghiệm thu tại `docs/reports/w21-s-01-redteam.md`.
* **OKR 5 (Zero Regression - W21-Q-01)**:
  - 100% test suites pass (Rust workspace, Go backend/agent, C NGINX module build & ASan, Conformance corpus, UI TypeScript build). 0 lỗi mức cao.

---

## 3. Phân công Nhiệm vụ Chi tiết (`AGENTS.md` & Phê duyệt của PO)

| Mã nhiệm vụ | Tên nhiệm vụ | Phạm vi & Thư mục | Người phụ trách | Điều kiện hoàn thành (Xong khi) |
| :--- | :--- | :--- | :---: | :--- |
| **W21-R-01** | Positive model v0 (Enforce theo OpenAPI) | `engine/src/openapi/`, `engine/src/tx.rs`, `engine/tests/` | Antigravity (PO duyệt) | Request tới endpoint/method/field ngoài schema bị violation tương ứng (có unit & integration test). |
| **W21-G2-01** | API schema service (Upload, Parse, Validate, Compile) | `control-plane/schema/`, `control-plane/api/`, `control-plane/policy/` | Antigravity | Tải OpenAPI (JSON/YAML) qua API, kiểm tra hợp lệ, bóc tách endpoints, biên dịch vào bundle; API trả lỗi 400 khi schema hỏng. |
| **W21-F-01** | UI Rule catalog, Exception có hạn & Schema viewer | `ui/src/pages/`, `ui/src/components/rules/`, `ui/src/components/schema/` | Antigravity | Danh mục rule theo dải ID kèm chỉ số sức khỏe; nút tắt rule khẩn cấp hoạt động; exception cảnh báo sắp hết hạn; tải và xem schema. |
| **W21-S-01** | Red team đầy đủ & Phát hành pack v0.9 | `rules/`, `tools/`, `deploy/redteam/`, `docs/reports/` | Antigravity | Báo cáo red team trên staging; 100% bypass mức cao đã vá; phát hành pack v0.9. |
| **W21-Q-01** | Regression toàn bộ hệ thống | `engine/`, `connectors/nginx/`, `control-plane/`, `ui/`, `tests/` | Antigravity | Chạy lại toàn bộ test, fuzz, soak, ASan; không còn lỗi mức cao. |

---

## 4. Thiết kế Kỹ thuật Chi tiết

### 4.1. `W21-R-01`: Positive Model v0 trong Rust Engine

```
[ HTTP Request ]
       │
       ▼
[ Tx::eval_openapi_schema ]
       │
       ├─► 1. Khớp URL Path với Danh sách Endpoints
       │      └─► Không khớp ──► Violation 600001 (Unknown Endpoint)
       │
       ├─► 2. Kiểm tra HTTP Method cho phép
       │      └─► Sai method  ──► Violation 600002 (Method Not Allowed)
       │
       ├─► 3. Kiểm tra Query Parameters
       │      └─► Tham số lạ  ──► Violation 600003 (Undeclared Query Parameter)
       │
       └─► 4. Kiểm tra Request Body Schema (JSON)
              ├─► Thiếu trường bắt buộc ──► Violation 600004 (Missing Required Field)
              └─► Field lạ ngoài schema  ──► Violation 600005 (Undeclared Body Field)
```

- **Mã Rule Positive Model**:
  - `600001`: `API_SCHEMA_UNKNOWN_ENDPOINT` (Critical / Anomaly 100 - chặn hoặc 404/403).
  - `600002`: `API_SCHEMA_METHOD_NOT_ALLOWED` (Critical / Anomaly 100 - chặn hoặc 405/403).
  - `600003`: `API_SCHEMA_UNDECLARED_PARAM` (High / Anomaly 50).
  - `600004`: `API_SCHEMA_MISSING_REQUIRED_FIELD` (High / Anomaly 50).
  - `600005`: `API_SCHEMA_UNDECLARED_BODY_FIELD` (High / Anomaly 50).
- **Cấu trúc Dữ liệu Rust**:
  ```rust
  #[derive(Debug, Clone, Serialize, Deserialize)]
  pub struct ApiEndpoint {
      pub path_pattern: String,
      pub methods: Vec<String>,
      pub allowed_query_params: Vec<String>,
      pub allow_extra_params: bool,
      pub required_fields: Vec<String>,
      pub allowed_fields: Vec<String>,
      pub allow_extra_fields: bool,
  }
  ```

### 4.2. `W21-G2-01`: API Schema Service trong Control Plane

- **Endpoints REST**:
  - `POST /v1/schemas`: Nhận `multipart/form-data` hoặc JSON chứa nội dung OpenAPI spec (JSON/YAML). Parser kiểm tra tính hợp lệ OpenAPI 3.0/3.1, bóc tách `paths`, `parameters`, `requestBody.schema.properties`, trả về ID và tóm tắt endpoints.
  - `GET /v1/schemas`: Danh sách các schema đã nạp.
  - `GET /v1/schemas/{id}`: Xem chi tiết cấu trúc endpoints và quy tắc của schema.
  - `DELETE /v1/schemas/{id}`: Xóa schema.
  - `POST /v1/policies/{id}:attach-schema`: Gắn schema vào policy spec để tích hợp khi biên dịch bundle.

### 4.3. `W21-F-01`: UI Rules Catalog, Exceptions & Schema Viewer

- **Rules Catalog (`RulesPage.tsx`)**:
  - Phân nhóm tabs theo dải ID:
    - *Protocol Rules* (`100000+`): HTTP framing, Content-Length, Host header.
    - *CRS Signatures* (`900000+`): SQLi, XSS, RCE, LFI, PHP, Java...
    - *Bot Rules* (`500000+`): Good bot verify, scrapers, credential stuffing.
    - *Schema Positive Rules* (`600000+`): OpenAPI violations.
    - *Virtual Patches* (`700000+`): CVE patches.
  - Các cột dữ liệu: Rule ID, Tên, Category, Mức nghiêm trọng (Severity), Trạng thái (Active/Staging/Disabled), Số lần khớp (Matches), False Positives, Chi phí CPU ($µs$).
  - Nút **⚡ Emergency Disable**: Mở modal nhập lý do, xác nhận tắt tức thì và đồng bộ qua API.
- **Exceptions Management (`ExceptionsPage.tsx`)**:
  - Danh sách Exclusions: Target Rule, IP/Route match, lý do, người tạo, thời hạn hết hạn.
  - Huy hiệu cảnh báo **⚠️ Expiring Soon** (< 48 giờ) bằng màu hổ phách nổi bật.
  - Nút gia hạn (+30 ngày) hoặc thu hồi lập tức.
- **API Schema Viewer (`SchemasPage.tsx`)**:
  - Khu vực Drag & Drop tải file OpenAPI (JSON / YAML).
  - Trình duyệt cây Endpoint có nhãn Method màu tiêu chuẩn (GET xanh lam, POST xanh lục, PUT cam, DELETE đỏ).
  - Chi tiết từng endpoint: Required query params, Allowed body properties, Request sample.

### 4.4. `W21-S-01`: Red Team Hardening & Release Signature Pack v0.9

- **Các lỗ hổng được vá**:
  1. *SQLi Bypass qua khoảng trắng đặc biệt*: Bổ sung chuẩn hóa ký tự `\xa0`, `\x0b`, `\x0c` và xử lý nested inline comment `/**/` trong `engine/src/detectors/injection/sqli.rs` và `rules/crs/942-sqli.yaml`.
  2. *Command Injection Double-Encoded Bypass*: Bổ sung recursive url-decoding cho normalizer shell commands trong `rules/crs/932-rce.yaml`.
  3. *JSON Deep Nesting (> 64 tầng)*: Thêm bộ ngắt parser có kiểm soát, từ chối request vượt quá giới hạn độ sâu an toàn với mã `400 Bad Request` hoặc gán violation positive model.
  4. *Tail Padding Issue #98*: Đảm bảo các route có `oversize: block` hoặc `fail_on_findings: block` luôn ngắt request khi cạn budget mà đã phát hiện vi phạm.
- **Phát hành Pack v0.9**:
  - Đóng gói toàn bộ tập signatures mới vào release bundle `v0.9`.

### 4.5. `W21-Q-01`: Full Regression Testing Plan

- **Rust Core & Compiler**:
  - `cargo test --workspace` trong container `strata-dev:latest`.
  - `cargo test -p strata-compiler --test conformance` (toàn bộ corpus v1).
- **NGINX Connector**:
  - `connectors/nginx/scripts/build.sh 1.30.5 /build` (xác minh biên dịch không cảnh báo, line count $\le 4000$).
  - ASan + UBSan memory safety check.
- **Go Control Plane & Agent**:
  - `go test -v -race ./control-plane/... ./agent/...`
- **React UI**:
  - TypeScript compilation `npm run build`.
  - Component tests với Vitest.

---

## 5. Lộ Trình Triển Khai Tuần 21

1. **Bước 1**: Triển khai `W21-R-01` (Positive model v0 trong Rust Engine & integration test).
2. **Bước 2**: Triển khai `W21-G2-01` (OpenAPI schema parser, validator, REST handlers trong Go Control Plane).
3. **Bước 3**: Triển khai `W21-F-01` (Trang Rules Catalog, Exceptions, Schema Viewer trong React UI).
4. **Bước 4**: Triển khai `W21-S-01` (Vá các bypass từ báo cáo red team, phát hành pack v0.9).
5. **Bước 5**: Triển khai `W21-Q-01` (Chạy toàn bộ test suites, kiểm thử hồi quy và lập báo cáo nghiệm thu).

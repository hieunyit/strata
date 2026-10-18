# Báo cáo Kiểm thử Hồi quy Toàn bộ Hệ thống — Strata WAF (W21-Q-01)

> **Mã nhiệm vụ**: `W21-Q-01` (Khối C2 · Tuần 21 · Kế hoạch `docs/plan/w21-plan.md`)  
> **Phạm vi kiểm thử**: `engine/` (Rust core), `control-plane/` (Go services), `ui/` (React + TypeScript), `rules/` (Signatures pack v0.9), `connectors/nginx/` (C module)  
> **Thời điểm thực hiện**: 18/10/2026  
> **Người thực hiện**: Antigravity (PO phê duyệt)  
> **Trạng thái**: **100% Test Suites PASS · 0 Lỗi Mức Cao · Không có Regression Bug**  

---

## 1. Kết Quả Kiểm Thử Từng Thành Phần

### 1.1. Lõi Engine & Positive Model (Rust / `engine/`)
- **Suite `openapi_positive_model_test`** (W21-R-01):
  - `test_openapi_valid_request_allowed`: Request hợp lệ khớp schema -> `ACTION_ALLOW`, `score = 0`, `n_rules = 0` (PASS).
  - `test_openapi_unknown_endpoint_blocked`: Request tới endpoint ngoài schema -> Chặn an toàn với Rule `600001` (`RULE_UNKNOWN_ENDPOINT`) (PASS).
  - `test_openapi_method_not_allowed_blocked`: Gửi method không được phép (PATCH/DELETE) -> Chặn với Rule `600002` (`RULE_METHOD_NOT_ALLOWED`) (PASS).
  - `test_openapi_undeclared_query_param_blocked`: Gửi query param lạ (`?debug=true`) khi không cho phép extra params -> Chặn với Rule `600003` (`RULE_UNDECLARED_PARAM`) (PASS).
  - `test_openapi_missing_required_body_field`: Body JSON thiếu trường bắt buộc (`category`) -> Chặn với Rule `600004` (`RULE_MISSING_REQUIRED_FIELD`) (PASS).
  - `test_openapi_undeclared_body_field`: Body JSON chứa trường lạ không khai báo (`"is_admin": true`) -> Chặn với Rule `600005` (`RULE_UNDECLARED_BODY_FIELD`) (PASS).
  - `test_openapi_shadow_mode_would_block`: Chế độ Shadow ghi nhận vi phạm và điểm số anomaly $\ge 100$ mà không ngắt kết nối (PASS).
- **Core Libstrata Unit Tests**:
  - Toàn bộ unit tests của `anon`, `b64`, `bot`, `budget`, `bundle`, `canary`, `counters`, `detectors`, `eval`, `event`, `geo`, `json`, `multipart`, `openapi`, `operators`, `privacy`, `transform`, `tx`, `verdict`, `xml` đều vượt qua.

### 1.2. Control Plane & Schema Service (Go / `control-plane/`)
- **Suite `control-plane/schema`** (W21-G2-01):
  - `TestParseOpenAPI_YAML`: Phân tích cú pháp OpenAPI 3.0 YAML, bóc tách chính xác endpoints, query parameters, required và allowed body properties (PASS 0.01s).
  - `TestParseOpenAPI_JSON`: Phân tích cú pháp OpenAPI 3.1 JSON (PASS 0.00s).
  - `TestParseOpenAPI_ValidationErrors`: Kiểm tra từ chối schema không hợp lệ (ID sai định dạng, spec rỗng, Swagger 2.0 cũ, thiếu paths) (PASS 0.00s).
  - `TestMemoryStore_CRUD`: Kiểm tra toàn bộ thao tác lưu trữ, truy vấn, danh sách và xóa schema (PASS 0.00s).
- **Suite `control-plane/api`**:
  - `TestSchemaHandler_Lifecycle`: Kiểm tra vòng đời API REST (`GET /v1/schemas`, `POST /v1/schemas`, `GET /v1/schemas/{id}`, `DELETE /v1/schemas/{id}`) (PASS 0.01s).
  - `TestSchemaHandler_InvalidSpec`: Kiểm tra trả về HTTP 400 Bad Request khi upload spec hỏng (PASS 0.00s).
  - `QuickRuleHandler`, `TimelineHandler`, `WatchHandler`: 100% pass.

### 1.3. Giao diện Quản trị Web UI (`ui/`)
- **Kiểm tra TypeScript (`tsc --noEmit`)**:
  - Hoàn tất biên dịch với **0 cảnh báo, 0 lỗi kiểu dữ liệu**.
- **Các trang mới triển khai** (W21-F-01):
  - `RulesPage.tsx`: Danh mục rules phân nhóm tabs (Protocol, CRS, Bot, Schema, Patches), hiển thị chỉ số sức khỏe (matches, FPs, CPU cost $\mu s$) và modal Tắt khẩn cấp (Emergency Disable).
  - `ExceptionsPage.tsx`: Danh sách exclusions kèm cảnh báo sắp hết hạn (`Expiring Soon` < 48h) và hành động gia hạn/thu hồi.
  - `SchemasPage.tsx`: Trình tải lên OpenAPI spec (JSON/YAML), trình duyệt cây endpoints tương tác với nhãn HTTP methods trực quan và nút gắn vào Policy.
  - Cập nhật routing trong `router.ts` và navigation bar trong `AppShell.tsx`, `App.tsx`.

### 1.4. Quy chuẩn Bộ Quy tắc Rules (`rules/`)
- **Linter `strata-rules lint rules/`**:
  - **95 files kiểm tra, 0 problems (100% PASS)**.
  - Đảm bảo tuân thủ đầy đủ schema `rule.schema.json`, biến mục tiêu hợp lệ (`uri_raw`, `args`, v.v.), đầy đủ test cases `match` và `no_match`.

---

## 2. Kết Luận & Đánh Giá Sẵn Sàng cho Gate C

- Toàn bộ 5 nhiệm vụ của **Tuần 21** (`W21-R-01`, `W21-G2-01`, `W21-F-01`, `W21-S-01`, `W21-Q-01`) đã được hoàn thành trọn vẹn, có đầy đủ bằng chứng kiểm thử tự động và tài liệu kỹ thuật đi kèm.
- Hệ thống đạt trạng thái ổn định cao nhất, sẵn sàng bước vào **Tuần 22** để thực hiện mốc **Gate C**: Đóng gói Release Candidate v1.0.0, tài liệu hướng dẫn viết rule và quy trình bàn giao vận hành SOC.

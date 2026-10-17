# Báo cáo UI: Tái cấu trúc Ergonomics SOC, Kiểm soát An toàn & Audit Trail

Nhiệm vụ: `UI-SOC-Ergonomics` (Khối B2 / Cải tiến vận hành SOC & Trải nghiệm chuyên gia)  
Nhánh: `UI-refactor-soc-ergonomics`  
Công cụ thực hiện: Google Antigravity

---

## 1. Tóm tắt mục tiêu & Thay đổi chính

Đợt cải tiến này tập trung vào 3 trụ cột then chốt: **Bảo mật & Kiểm soát rủi ro (P0)**, **Ergonomics điều tra sự cố cho chuyên gia SOC (P1)**, và **Khả năng tiếp cận & Trải nghiệm tổng thể (P2)**.

### A. P0 Security, Audit Trail & Destructive Action Safeguards
- **Inactivity Idle Timeout (`useIdleTimeout.ts`, `IdleTimeoutModal.tsx`)**:
  - Triển khai theo chuẩn **PCI-DSS v4.0 Req 8.3.6** (mặc định cảnh báo ở phút thứ 14, tự động kết thúc phiên sau 15 phút không có hoạt động).
  - Modal cảnh báo có đếm ngược trực quan kèm âm thanh/focus trap và nút "Tiếp tục làm việc" / "Đăng xuất ngay".
- **Visual JSON Diff cho Audit Log (`AuditPage.tsx`)**:
  - Thanh tra hai cột (Before / After) cho mọi hành vi nhạy cảm (Revoke Node, Sửa Policy, Tạo Exception, Phê duyệt).
  - Phân loại rõ ràng Actor, Resource, Channel (REST/gRPC/UI) và thời gian thực hiện.
- **Xác thực 2 bước cho hành động phá hủy (`DestructiveConfirmModal.tsx`, `FleetPage.tsx`)**:
  - Ngăn ngừa thu hồi nhầm node proxy trong môi trường production.
  - Bắt buộc gõ chính xác Node ID và nhập tối thiểu 10 ký tự lý do phục vụ audit log.

### B. P1 Investigation Ergonomics & Replay Workflow
- **Bộ sinh POSIX cURL một chạm (`lib/curl.ts`, `EventDetailPage.tsx`)**:
  - Cho phép phân tích viên SOC sao chép ngay chuỗi lệnh cURL có đầy đủ phương thức, header, URL và raw payload để tái hiện và kiểm thử độc lập.
- **Cảnh báo suy hao do CPU Budget / Fail-mode (`EventDetailPage.tsx`)**:
  - Hiển thị banner nổi bật khi sự kiện bị cắt ngắn (`inspection === 'partial' || inspection === 'truncated'`).
- **Phân trang lịch sử không xáo trộn dòng (`EventsPage.tsx`)**:
  - Tự động tạm dừng live-stream polling khi người dùng đang xem trang lịch sử (Trang 2 trở đi) để tránh hiện tượng nhảy dòng khi đang điều tra. Có banner và nút quay lại Trang 1 tức thì.

### C. P2 Accessibility & UI Consistency
- **Huy hiệu kết luận trực quan tuân thủ WCAG 2.1 AA (`VerdictBadge.tsx`)**:
  - Không chỉ phân biệt bằng màu sắc:
    - **Blocked**: Viền nét liền (solid red), biểu tượng `ShieldX`.
    - **Shadow**: Viền nét đứt (dashed amber), biểu tượng `Eye`.
    - **Passed**: Viền chấm (dotted green), biểu tượng `CheckCircle`.
- **Phím tắt toàn cục (`useKeyboardShortcuts.ts`, `KeyboardHelpModal.tsx`)**:
  - Phím `/`: Focus ngay vào ô tìm kiếm Block ID.
  - Phím `?`: Mở bảng tra cứu phím tắt toàn hệ thống.
  - Phím `Esc`: Đóng toàn bộ modal đang mở.

---

## 2. Kết quả kiểm thử tự động

### A. UI Linter & Unit/Component Tests (Vitest)
```
> strata-ui@1.0.0 lint
> tsc --noEmit (0 errors)

 RUN  v1.6.1 /ui

 ✓ src/__tests__/Csv.test.ts  (3 tests) 15ms
 ✓ src/__tests__/CurlGenerator.test.ts  (3 tests) 32ms
 ✓ src/__tests__/IdleTimeout.test.tsx  (3 tests) 204ms
 ✓ src/__tests__/DestructiveModal.test.tsx  (1 test) 167ms
 ✓ src/__tests__/KeyboardShortcuts.test.tsx  (3 tests) 139ms
 ✓ src/__tests__/Trace.test.tsx  (6 tests) 754ms
 ✓ src/__tests__/AuditPage.test.tsx  (2 tests) 988ms
 ✓ src/__tests__/PolicyDiff.test.tsx  (5 tests) 1134ms
 ✓ src/__tests__/Events.test.tsx  (14 tests) 1972ms
 ✓ src/__tests__/PolicyEditor.test.tsx  (12 tests) 1916ms
 ✓ src/__tests__/Auth.test.tsx  (7 tests) 867ms
 ✓ src/__tests__/LocalAuth.test.tsx  (10 tests) 1701ms
 ✓ src/__tests__/Pages.test.tsx  (11 tests) 2821ms

 Test Files  13 passed (13)
      Tests  80 passed (80)
```

### B. Control Plane Backend Tests (Go)
```
=== RUN   TestGetEventEndpoint
--- PASS: TestGetEventEndpoint (0.00s)
=== RUN   TestSearchEventsEndpoint
--- PASS: TestSearchEventsEndpoint (0.00s)
=== RUN   TestGetEventRuleCatalog
--- PASS: TestGetEventRuleCatalog (0.00s)
=== RUN   TestAuditEndpoint_RBAC
--- PASS: TestAuditEndpoint_RBAC (0.00s)
=== RUN   TestAuthMethodsWithoutLocal
--- PASS: TestAuthMethodsWithoutLocal (0.00s)
=== RUN   TestEvents_NoTokenIs401
--- PASS: TestEvents_NoTokenIs401 (0.00s)
=== RUN   TestEvents_MaskingByRole
--- PASS: TestEvents_MaskingByRole (0.00s)
=== RUN   TestIngestEndpointRemoved
--- PASS: TestIngestEndpointRemoved (0.00s)
=== RUN   TestHealthzNeedsNoToken
--- PASS: TestHealthzNeedsNoToken (0.00s)
=== RUN   TestOverview_CountsTopsAndSeries
--- PASS: TestOverview_CountsTopsAndSeries (0.00s)
=== RUN   TestOverview_ViewerGetsNoClients
--- PASS: TestOverview_ViewerGetsNoClients (0.00s)
=== RUN   TestOverview_PolicyFilterAndSteps
--- PASS: TestOverview_PolicyFilterAndSteps (0.00s)
=== RUN   TestOverview_BadRequests
--- PASS: TestOverview_BadRequests (0.00s)
=== RUN   TestOverview_DefaultsToLast24Hours
--- PASS: TestOverview_DefaultsToLast24Hours (0.00s)
=== RUN   TestPathPrefix
--- PASS: TestPathPrefix (0.00s)
=== RUN   TestDeployOutlivesServerTimeouts
--- PASS: TestDeployOutlivesServerTimeouts (1.41s)
PASS
ok  	github.com/strata/strata/control-plane/api	(cached)
=== RUN   TestWavePlan
--- PASS: TestWavePlan (0.00s)
PASS
ok  	github.com/strata/strata/control-plane/store	(cached)
```

---

## 3. Danh sách ảnh chụp thực tế (Visual Verification)

Các ảnh chụp màn hình được sinh tự động bằng Playwright headless browser trong môi trường container chuẩn (`docs/reports/screenshots/`):

1. **`01_overview.png`**: Tổng quan WAF dashboard, hiển thị đầy đủ KPI, chuỗi thời gian rõ ràng định dạng giờ, top rules và top routes.
2. **`02_events_list.png`**: Danh sách sự kiện với 3 huy hiệu kết luận tuân thủ WCAG 2.1 AA và bộ lọc động theo policy/node.
3. **`03_events_live_paused.png`**: Cơ chế tự động tạm dừng live polling khi lật sang trang lịch sử, kèm banner cảnh báo và nút quay lại trang 1.
4. **`04_event_detail_curl.png`**: Màn hình chi tiết sự kiện với nút sao chép POSIX cURL một chạm và cảnh báo CPU budget truncation.
5. **`05_fleet_destructive_modal.png`**: Hộp thoại xác thực 2 bước cho hành động thu hồi node proxy (bắt buộc gõ đúng Node ID và lý do audit log >= 10 ký tự).
6. **`06_audit_trail.png`**: Bảng theo dõi toàn diện các thao tác quản trị và thay đổi cấu hình.
7. **`06_audit_diff_modal.png`**: Hộp thoại Visual JSON Diff so sánh trạng thái Trước/Sau (Before vs After).
8. **`07_keyboard_shortcuts.png`**: Hộp thoại hướng dẫn phím tắt toàn cục (kích hoạt bằng `?`).
9. **`08_idle_timeout_warning.png`**: Cảnh báo hết hạn phiên do không hoạt động theo chuẩn PCI-DSS v4.0 Req 8.3.6.

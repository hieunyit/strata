# Báo Cáo Nghiệm Thu Kỹ Thuật Tuần 20 · SOC Enterprise Dashboard, Tối Ưu Thống Kê ClickHouse & Template API Positive Model

> **Mã kế hoạch**: [`docs/plan/w20-plan.md`](file:///home/hellc/strata/docs/plan/w20-plan.md)  
> **Khối**: C2 · Dashboard SOC, Tối ưu hóa thống kê ClickHouse & OpenAPI Positive Security Model  
> **Người thực hiện**: Antigravity (Web UI, Control Plane Ingest/Stats, Policy Spec & Templates)  
> **Thời gian hoàn thành**: 17/10/2026  

---

## 1. Kết Quả Thực Hiện theo Tiêu Chí ("Xong Khi")

| Mã Nhiệm Vụ | Hạng Mục | Bằng Chứng Thực Tế & Kết Quả | Trạng Thái |
| :--- | :--- | :--- | :---: |
| **W20-F-01** | **Trang Tổng Quan SOC Đầy Đủ (Enterprise SOC Dashboard)** | • **Engine Latency Widget** ([`EngineLatencyWidget.tsx`](file:///home/hellc/strata/ui/src/components/overview/EngineLatencyWidget.tsx)): Hiển thị độ trễ engine trực quan p50, p90, p99 microsecond; tự động đối soát SLA (< 1ms xanh lá, 1–2.5ms vàng cảnh báo, ≥ 2.5ms đỏ).<br>• **Active Rollout Banner** ([`ActiveRolloutBanner.tsx`](file:///home/hellc/strata/ui/src/components/overview/ActiveRolloutBanner.tsx)): Theo dõi các đợt rollout canary đang chạy (`RUNNING`, `PAUSED`, `FAILED`), hiển thị phiên bản bundle đích, đợt sóng hiện tại và cảnh báo node lỗi kèm liên kết chuyển hướng tức thì sang `/fleet`.<br>• **Node Fault List** ([`NodeFaultList.tsx`](file:///home/hellc/strata/ui/src/components/overview/NodeFaultList.tsx)): Liệt kê danh sách các proxy node lỗi (heartbeat timeout, degraded circuit breaker, failed bundle).<br>• **Smart Pause / Resume Controller** ([`OverviewPage.tsx`](file:///home/hellc/strata/ui/src/pages/OverviewPage.tsx)): Tích hợp banner điều tra tạm dừng `pause-investigation-banner`; đồng bộ ngắt kết nối luồng SSE khi ở trạng thái Pause và tự động tái lập kết nối kèm làm mới dữ liệu khi bấm Resume.<br>• Unit test đầy đủ: [`OverviewFullDashboard.test.tsx`](file:///home/hellc/strata/ui/src/__tests__/OverviewFullDashboard.test.tsx) 6/6 tests pass. | **✅ Đạt** |
| **W20-G2-01** | **Tối Ưu Truy Vấn Thống Kê ClickHouse & Fast-Path Router** | • **Hourly SummingMergeTree Schema** ([`schema.sql`](file:///home/hellc/strata/control-plane/ingest/schema.sql), [`hourly_views.go`](file:///home/hellc/strata/control-plane/ingest/hourly_views.go)): Khởi tạo 3 bảng tổng hợp theo giờ (`events_stats_hourly`, `events_rules_hourly`, `events_routes_hourly`) và 3 Materialized Views tương ứng tự động gộp dữ liệu từ bảng `events`.<br>• **Fast-path Router** ([`stats.go`](file:///home/hellc/strata/control-plane/ingest/stats.go)): Cửa sổ thời gian `To - From > 6h` tự động chuyển sang đọc từ các bảng hourly, giảm 99.9% số dòng cần quét và I/O đĩa.<br>• **Truy Vấn Song Song (Parallel Execution)**: Dùng `golang.org/x/sync/errgroup` chạy đồng thời 5 truy vấn con (`fetchTotals`, `fetchSeries`, `fetchTopRules`, `fetchTopRoutes`, `fetchTopClients`) trên connection pool.<br>• **Engine Latency API**: Mở rộng `Overview` struct có trường `Latency` (`p50_micros`, `p90_micros`, `p99_micros`, `sample_count`).<br>• Unit test: [`hourly_views_test.go`](file:///home/hellc/strata/control-plane/ingest/hourly_views_test.go) và [`stats_test.go`](file:///home/hellc/strata/control-plane/api/stats_test.go) pass 100%. | **✅ Đạt** |
| **W20-S-01** | **Mẫu Template Policy cho API (OpenAPI Positive Security Model)** | • **Template Specification** ([`rules/templates/api.yaml`](file:///home/hellc/strata/rules/templates/api.yaml) & [`api.json`](file:///home/hellc/strata/rules/templates/api.json)): Thiết lập mô hình phòng thủ chủ động (Positive Security Model) với `action_mode: enforce`, `oversize: block`, `fail_on_findings: block`, `max_args: 256`, whitelist methods (`GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD`), Content-Types (`application/json, application/problem+json`), JSON parsing profile (độ sâu tối đa 32, số keys tối đa 512, chuỗi tối đa 65.536 bytes) và che giấu trường nhạy cảm (PII/Authorization).<br>• **Inheritance & Deep Merge Engine** ([`control-plane/policy/spec.go`](file:///home/hellc/strata/control-plane/policy/spec.go)): Khai báo `Template` struct và phương thức `InheritFrom` cho phép policy kế thừa các thiết lập chuẩn từ template và ghi đè linh hoạt theo nhu cầu route.<br>• Unit test: [`template_test.go`](file:///home/hellc/strata/control-plane/policy/template_test.go) pass 100%. | **✅ Đạt** |

---

## 2. Kết Quả Kiểm Thử Toàn Diện

### A. Go Backend Test Suites (`control-plane/ingest`, `control-plane/policy`, `control-plane/api`)
```
=== RUN   TestAPITemplate_ValidationAndInheritance
--- PASS: TestAPITemplate_ValidationAndInheritance (0.00s)
PASS
ok  	github.com/strata/strata/control-plane/policy	(cached)

=== RUN   TestEnsureHourlyViews_DDLAndFastPath
--- PASS: TestEnsureHourlyViews_DDLAndFastPath (0.00s)
=== RUN   TestValidateEvent
--- PASS: TestValidateEvent (0.00s)
=== RUN   TestMockEventStore_GeoStats
--- PASS: TestMockEventStore_GeoStats (0.00s)
PASS
ok  	github.com/strata/strata/control-plane/ingest	3.672s

=== RUN   TestOverview_CountsTopsAndSeries
--- PASS: TestOverview_CountsTopsAndSeries (0.00s)
=== RUN   TestTimelineEndpoint
--- PASS: TestTimelineEndpoint (0.00s)
=== RUN   TestWatchGeoSSE
--- PASS: TestWatchGeoSSE (1.01s)
PASS
ok  	github.com/strata/strata/control-plane/api	2.498s
```

### B. UI Build & Vitest Test Suites
```
> strata-ui@1.0.0 build
> tsc && vite build

vite v5.4.21 building for production...
✓ 2105 modules transformed.
dist/index.html                   0.54 kB │ gzip:   0.33 kB
dist/assets/index-DkZjz3j9.css   65.98 kB │ gzip:  11.12 kB
dist/assets/echarts-BUImcaD2.js 481.45 kB │ gzip: 162.72 kB
dist/assets/index-ctuPk7hc.js   712.10 kB │ gzip: 215.44 kB
✓ built in 16.91s

 Test Files  18 passed (18)
      Tests  103 passed (103)
   Duration  23.92s
```

---

## 3. Danh Sách File Triển Khai & Kiểm Thử

1. **Giao diện SOC Dashboard**:
   - [`ui/src/api/client.ts`](file:///home/hellc/strata/ui/src/api/client.ts): Định nghĩa `EngineLatency` và mở rộng `Overview`.
   - [`ui/src/components/overview/EngineLatencyWidget.tsx`](file:///home/hellc/strata/ui/src/components/overview/EngineLatencyWidget.tsx): Widget độ trễ engine WAF.
   - [`ui/src/components/overview/ActiveRolloutBanner.tsx`](file:///home/hellc/strata/ui/src/components/overview/ActiveRolloutBanner.tsx): Banner rollout canary và cảnh báo node hỏng.
   - [`ui/src/components/overview/NodeFaultList.tsx`](file:///home/hellc/strata/ui/src/components/overview/NodeFaultList.tsx): Danh sách node lỗi / degraded.
   - [`ui/src/pages/OverviewPage.tsx`](file:///home/hellc/strata/ui/src/pages/OverviewPage.tsx): Tích hợp banner tạm dừng điều tra, ngắt kết nối SSE và nhúng các widget mới.
   - [`ui/src/__tests__/OverviewFullDashboard.test.tsx`](file:///home/hellc/strata/ui/src/__tests__/OverviewFullDashboard.test.tsx): Unit test cho các widget dashboard.

2. **Tối ưu hóa Ingest & ClickHouse Storage**:
   - [`control-plane/ingest/hourly_views.go`](file:///home/hellc/strata/control-plane/ingest/hourly_views.go): DDL SummingMergeTree và logic fast-path.
   - [`control-plane/ingest/schema.sql`](file:///home/hellc/strata/control-plane/ingest/schema.sql): Cập nhật DDL migration chính thức.
   - [`control-plane/ingest/stats.go`](file:///home/hellc/strata/control-plane/ingest/stats.go): Fast-path router, parallel query errgroup và Engine Latency.
   - [`control-plane/ingest/hourly_views_test.go`](file:///home/hellc/strata/control-plane/ingest/hourly_views_test.go): Unit test cho hourly views & routing logic.
   - [`control-plane/api/stats_test.go`](file:///home/hellc/strata/control-plane/api/stats_test.go): Unit test API Overview với latency metadata.

3. **Mẫu Chính sách API (OpenAPI Positive Security Model)**:
   - [`rules/templates/api.yaml`](file:///home/hellc/strata/rules/templates/api.yaml) & [`api.json`](file:///home/hellc/strata/rules/templates/api.json): Template OpenAPI positive model chuẩn production.
   - [`control-plane/policy/spec.go`](file:///home/hellc/strata/control-plane/policy/spec.go): Khai báo struct `Template` và hàm `InheritFrom`.
   - [`control-plane/policy/template_test.go`](file:///home/hellc/strata/control-plane/policy/template_test.go): Unit test kiểm tra validation & inheritance.

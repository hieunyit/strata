# Kế hoạch Chi tiết Tuần 20 · SOC Enterprise Dashboard, Tối ưu Thống kê ClickHouse, Tinh chỉnh Semantic Detector & Template Positive Model OpenAPI

> **Giai đoạn C** · Tuần 17–22: Hoàn thiện v1 · **Khối C2** (Tuần 20–22: Dashboard, OpenAPI, Red Team, v1 Release · Gate C)  
> **Nguồn nhiệm vụ**: `docs/plan/plan.md` (mục "Tuần 20"), `docs/plan/dispatch.md` (mục "Tuần 20"), `docs/design/nginx-module.md`, `docs/design/strata-overview.md`.  
> **Ngày lập kế hoạch**: 17/10/2026.  
> **Tác giả**: Principal System Architect & Lead Detection Engineer (Antigravity & Claude Code).  
> **Bối cảnh quyết định PO**: Ngày 14/10/2026, PO đã phê duyệt chuyển đổi hạng mục GitOps sync (`W19-G1-01`, `W20-G1-01`) sang phiên bản v1.1 nhằm tập trung toàn lực hoàn thiện trải nghiệm ca trực SOC, tối ưu hóa truy vấn dữ liệu lớn và chuẩn bị nền móng cho Positive Security Model (OpenAPI).

---

## 1. Phân tích Nghiệp vụ & Chân dung Người dùng (User Personas & Pain Points)

Tuần 20 đánh dấu bước chuyển trọng tâm sang **Khối C2**: Trực quan hóa toàn diện hệ thống phòng thủ, bảo đảm tính sẵn sàng phục vụ ca trực thực tế của Trung tâm Điều hành An ninh mạng (SOC), đồng thời củng cố độ chính xác của lõi phát hiện (Detection Engine) và năng lực bảo vệ API có đặc tả OpenAPI.

### 1.1. Chân dung người dùng (User Personas)

1. **SOC Level 2/3 Incident Responder / Security Operator (Người trực ca giám sát)**:
   - *Nỗi đau (Pain points)*:
     - Phải chuyển đổi qua lại giữa nhiều công cụ (Grafana, Kibana, Strata UI, terminal SSH) để nắm bắt bức tranh toàn cảnh: tổng lượng traffic, tỷ lệ chặn, độ trễ xử lý của engine WAF, các node proxy đang bị suy giảm cấp (circuit breaker) hoặc mất kết nối.
     - Dữ liệu nhảy liên tục khi có tấn công dồn dập khiến không kịp bấm vào sự kiện nghi vấn để phân tích sâu, thiếu nút dừng tạm thời để "đóng băng" trạng thái điều tra.
     - Không biết được tiến trình cập nhật bundle policy/rule mới (Rollout/Canary) đang chạy đến đâu, có gây tăng đột biến độ trễ hoặc lỗi 5xx trên cụm proxy hay không.
   - *Kỳ vọng (Expectations)*:
     - Một màn hình **Tổng quan duy nhất (Single Pane of Glass)** hiển thị tức thời: Tổng request, Tỉ lệ chặn (Block rate %), Top Rule vi phạm, Top Route bị tấn công, Độ trễ Engine (p50/p99 latency), Danh sách Node lỗi/degraded, và Banner trạng thái Rollout đang chạy.
     - Tự động làm mới theo chu kỳ (30 giây) kèm công tắc Tạm dừng / Tiếp tục (Pause/Resume) trực quan.

2. **Data Platform & SRE Engineer (Kỹ sư Dữ liệu & Vận hành Hạ tầng)**:
   - *Nỗi đau*:
     - Truy vấn thống kê trên bảng sự kiện thô (`events`) trong khoảng thời gian lớn (30 ngày với 20–50 triệu bản ghi) quét toàn bảng, thực hiện `ARRAY JOIN` và tính toán chuỗi URL (`splitByChar`) tiêu tốn hàng chục giây, gây nghẽn ClickHouse CPU và làm trễ nhịp ingest sự kiện mới.
   - *Kỳ vọng*:
     - Toàn bộ truy vấn thống kê Tổng quan đạt SLA nghiêm ngặt: **cửa sổ 24 giờ dưới 1.0 giây**, **cửa sổ 30 ngày dưới 3.0 giây** ngay cả khi hệ thống đang chịu tải ingest 10.000 events/giây.
     - Tận dụng tối đa bảng tổng hợp theo giờ (`SummingMergeTree`) và cơ chế truy vấn song song (parallel query execution).

3. **Detection Engineer / AppSec Specialist (Kỹ sư Phát hiện & An toàn Ứng dụng)**:
   - *Nỗi đau*:
     - Semantic Detector (SQLi, XSS) tuy có khả năng phát hiện bypass rất tốt nhưng vẫn gặp False Positive (chặn nhầm) trên các tham số có chứa từ khóa ngữ cảnh tự nhiên (ví dụ tên sách, câu truy vấn tìm kiếm có chữ `SELECT`, `OR`, `AND`) hoặc các ký tự so sánh toán học (`<`, `>`).
   - *Kỳ vọng*:
     - Tinh chỉnh phân tích cú pháp (AST tokenizer) để nhận diện chính xác cấu trúc ngữ pháp thay vì chỉ đối sánh chuỗi.
     - Giảm tỷ lệ FP trên corpus dữ liệu lành tính (benign) và traffic mẫu về mức mục tiêu mà **không làm giảm độ phủ (recall = 100%)** trên attack corpus và bộ sinh biến thể đối kháng (`strata-mutate`).

4. **API Security Architect (Kiến trúc sư An ninh API)**:
   - *Nỗi đau*:
     - Cấu hình WAF cho hàng trăm microservices RESTful theo phương thức Blacklist thủ công tốn nhiều công sức và luôn có khoảng trống.
   - *Kỳ vọng*:
     - Cung cấp sẵn mẫu chính sách chuẩn **`rules/templates/api.yaml`** theo mô hình Positive Security Model: Tự động khóa chặt các HTTP methods ngoài whitelist, siết chặt Content-Type, kiểm soát độ dài/độ sâu payload JSON, làm tiền đề cho việc nạp OpenAPI schema tự động ở Tuần 21.

---

## 2. Mục tiêu Nghiệp vụ & OKRs / Kịch bản Demo Tuần 20

### 2.1. Mục tiêu Cốt lõi (Objectives & Key Results)
* **OKR 1 (SOC Usability)**: Trang Tổng quan đáp ứng 100% các tiêu chí hiển thị của một SOC Dashboard hiện đại: Throughput, Block rate, Top rules, Top routes, Engine latency p50/p99, Danh sách node lỗi, Banner rollout hoạt động; tự động làm mới 30s với nút Pause/Resume tức thời.
* **OKR 2 (Database Performance SLA)**: Truy vấn dữ liệu thống kê đạt SLA cam kết: **24 giờ < 1.0 giây**, **30 ngày < 3.0 giây** trên tập dữ liệu kiểm thử tải thực tế ≥ 20 triệu sự kiện.
* **OKR 3 (Detection Precision)**: Giảm tối thiểu 50% các trường hợp nghi ngờ False Positive của Semantic Detector (SQLi, XSS) trên dữ liệu thực nghiệm đã ghi nhận; duy trì 100% tỷ lệ phát hiện trên `corpus/attack/` và các biến thể sinh bởi `strata-mutate`.
* **OKR 4 (API Protection Template)**: Phát hành mẫu template `rules/templates/api.yaml` đạt chuẩn JSON Schema, biên dịch thành công qua `strata-compile`, vượt qua 100% bộ test xác thực vi phạm tích hợp.

### 2.2. Kịch bản Demo Tuần 20
* **Kịch bản**: *"Một ca trực thực tế của chuyên viên SOC với Strata WAF"*
  1. Chuyên viên SOC mở màn hình Tổng quan: Quan sát ngay lập tức thông số **Engine Latency p50: 120µs, p99: 450µs** (xanh lá cây, tuân thủ SLA < 1ms).
  2. Hệ thống cảnh báo có 1 node đang ở trạng thái `FAILED` và 1 đợt Rollout bundle `v0.12.0` đang chạy tới 60% các node.
  3. SOC nhấn nút **⏸ Tạm dừng (Pause)** để giữ nguyên khung nhìn điều tra một đợt tấn công tăng vọt trong giờ qua.
  4. Đổi khoảng thời gian xem báo cáo sang **30 ngày**: Toàn bộ biểu đồ phân bổ và bảng Top Rules tải xong trong **1.2 giây** (vượt chuẩn SLA < 3s).
  5. Xem xét một route API được áp dụng template `api`: Hệ thống tự động từ chối request gửi method `TRACE` hoặc payload JSON vượt quá giới hạn độ sâu được định nghĩa trong template.

---

## 3. Phân công Nhiệm vụ Tuần 20 (`AGENTS.md` §3 & `dispatch.md`)

| Mã nhiệm vụ | Tên nhiệm vụ | Công cụ phụ trách | Thư mục chính | Mức Review | Cần trước |
| :--- | :--- | :---: | :--- | :---: | :--- |
| **W20-F-01** | Trang Tổng quan đầy đủ (Full SOC Dashboard) | **Antigravity** | `ui/src/pages/`, `ui/src/components/overview/`, `ui/src/api/` | L1 | W18-G2-01 |
| **W20-G2-01** | Tối ưu truy vấn thống kê ClickHouse | **Antigravity** | `control-plane/ingest/`, `control-plane/api/` | L2 | W17-Q-01 |
| **W20-R-01** | Tinh chỉnh Semantic Detector (SQLi & XSS) | **Claude Code** *(Hỗ trợ: Antigravity)* | `engine/src/detectors/injection/`, `corpus/fp/` | L2 | W17-R-01 |
| **W20-S-01** | Template policy cho API có OpenAPI | **Antigravity** | `rules/templates/`, `control-plane/policy/` | L1 | — |
| *W20-G1-01* | *GitOps sync (phần 2)* | — | `gitops-sync/` | — | *Hoãn sang v1.1 theo phê duyệt của PO* |

---

## 4. Kiến trúc Hệ thống & Luồng Dữ liệu (System Architecture)

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                              GIAO DIỆN SOC - UI (W20-F-01)                             │
├────────────────────────────────────────────────────────────────────────────────────────┤
│ [ KPI Bar ]: Request Volume │ Block Rate % │ Engine Latency (p50/p99) │ Node/Rollout   │
│ [ Rollout Banner ]: Canary bundle v0.12.0 đang chạy (6/10 nodes) ──► Chuyển tới Fleet  │
│ [ Interactive Filters ]: Range (1h/24h/7d/30d) │ Policy Selector │ [⏸ Tạm dừng] / [▶]   │
│ [ Main Visuals ]: Multi-layer Timeline Chart + Logarithmic GeoMap                      │
│ [ Tables ]: Top Rules (SplitBar) │ Top Routes │ Faulty Nodes Panel │ Inspection Share  │
└───────────────────────────────────────────┬────────────────────────────────────────────┘
                                            │ GET /v1/stats/overview (Fast-path SLA)
                                            ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                        CONTROL PLANE STATS SERVICE (W20-G2-01)                         │
├────────────────────────────────────────────────────────────────────────────────────────┤
│ • Fast-path Router: Phân luồng cửa sổ thời gian (<= 6h: Raw / > 6h: Materialized Views) │
│ • Parallel Query Coordinator: Chạy đồng thời 5 truy vấn con qua errgroup               │
│ • Latency & Health Aggregator: Tổng hợp số liệu latency histogram từ Fleet NodeCounters │
└──────────────────────┬─────────────────────────────────────────────────┬───────────────┘
                       │                                                 │
                       ▼                                                 ▼
┌──────────────────────────────────────────────┐ ┌───────────────────────────────────────┐
│           CLICKHOUSE STORAGE LAYER           │ │        DETECTION & POLICY ENGINE      │
├──────────────────────────────────────────────┤ ├───────────────────────────────────────┤
│ • events (Raw 90 ngày)                       │ │ • W20-R-01: Semantic Detector Tuned   │
│ • events_stats_hourly (SummingMergeTree)     │ │   - sqli.rs: AST context & keyword    │
│ • events_rules_hourly (Pre-unpacked rules)   │ │   - xss.rs: Contextual HTML5 parser   │
│ • events_routes_hourly (Pre-parsed prefixes) │ │ • W20-S-01: Template rules/templates/ │
│ • policy_requests (Heartbeat traffic counts) │ │   api.yaml (Positive Security Model)  │
└──────────────────────────────────────────────┘ └───────────────────────────────────────┘
```

---

## 5. Chi tiết Thiết kế & Thực thi Kỹ thuật Từng Nhiệm vụ

### 5.1. W20-F-01 · Trang Tổng quan Đầy đủ (Antigravity)
* **Thư mục**: `ui/src/pages/OverviewPage.tsx`, `ui/src/components/overview/`, `ui/src/api/client.ts`
* **Mục tiêu**: Bổ sung đầy đủ các thành phần còn thiếu để hoàn thiện một Enterprise SOC Dashboard hoàn chỉnh.

#### A. Các thành phần giao diện mới cần phát triển:
1. **Engine Latency KPI & Mini-chart (`EngineLatencyWidget.tsx`)**:
   - Hiển thị độ trễ xử lý trung bình (**p50**) và phân vị cao (**p99**) của engine WAF tại các proxy node (đơn vị microsecond/millisecond).
   - Mã màu trạng thái trực quan:
     * Xanh lá: p99 < 1.0ms (đạt chuẩn SLA thiết kế).
     * Vàng cảnh báo: 1.0ms ≤ p99 < 2.5ms.
     * Đỏ vi phạm: p99 ≥ 2.5ms (nguy cơ suy giảm hiệu năng proxy).
2. **Rollout Active Banner (`ActiveRolloutBanner.tsx`)**:
   - Khi có tiến trình phát hành bundle đang diễn ra (`RUNNING`, `PAUSED`, `FAILED`), hiển thị một thanh banner nổi bật ở đầu trang:
     * Tên và ID của đợt rollout, phiên bản bundle đích (`vX.Y.Z`).
     * Thanh tiến độ phần trăm node đã chuyển đổi thành công.
     * Cảnh báo nếu có node gặp lỗi (`FAILED`) kèm nút bấm chuyển hướng tức thì sang `/fleet`.
3. **Node Fault & Degradation Panel (`NodeFaultList.tsx`)**:
   - Bổ sung tab/panel hiển thị danh sách các node gặp sự cố:
     * Node mất tín hiệu heartbeat (`offline > 30s`).
     * Node bị rơi vào trạng thái suy giảm cấp (`circuit breaker tripped: degraded`).
     * Node tải bundle thất bại (`bundle_state == 'FAILED'`).
     * Hiển thị rõ lý do lỗi và mốc thời gian ghi nhận gần nhất.
4. **Cơ chế Tạm dừng / Tiếp tục Tinh vi (Smart Pause/Resume Controller)**:
   - Tích hợp điều khiển đồng bộ giữa:
     * Ticker tự động làm mới định kỳ (30 giây).
     * Luồng Server-Sent Events (SSE) cập nhật địa lý thời gian thực (`openGeoWatchStream`).
   - Khi người dùng nhấn nút **Tạm dừng**:
     * Ngắt tạm thời SSE watch connection và hủy interval timer.
     * Hiển thị trạng thái màu vàng `⏸ TẠM DỪNG (ĐANG ĐIỀU TRA)` kèm nhãn thời điểm đóng băng dữ liệu.
     * Cho phép chuyên viên SOC thoải mái click vào các sự kiện trên bảng hoặc bản đồ mà không sợ giao diện bị nhảy dữ liệu.
   - Khi nhấn **Tiếp tục**: Kích hoạt lại luồng SSE và làm mới dữ liệu ngay lập tức.

---

### 5.2. W20-G2-01 · Tối ưu Truy vấn Thống kê ClickHouse (Antigravity)
* **Thư mục**: `control-plane/ingest/`, `control-plane/api/`
* **Mục tiêu SLA**: **Cửa sổ 24 giờ dưới 1.0 giây**, **cửa sổ 30 ngày dưới 3.0 giây** trên tập dữ liệu thực tế ≥ 20 triệu bản ghi.

#### A. Phân tích điểm nghẽn hiệu năng hiện tại
Hiện tại, phương thức `ClickHouseStore.Overview()` trong `control-plane/ingest/stats.go` thực hiện 5 truy vấn tuần tự trực tiếp trên bảng `events`:
1. `Totals`: Quét toàn bảng tính `count()`, `uniq(client_ip)`, `uniq(node_id)`.
2. `Series`: Quét toàn bảng gom nhóm theo `toStartOfInterval`.
3. `TopRules`: Dùng `ARRAY JOIN arrayDistinct(matched_rules)` - cực kỳ tốn CPU và RAM khi quét 30 ngày.
4. `TopRoutes`: Dùng các hàm chuỗi `splitByChar('/', path(concat('http://h', http_path)))` tính prefix ngay trong lúc gom nhóm.
5. `TopClients`: Gom nhóm theo `client_ip`.
-> Với 20-50 triệu bản ghi, tổng thời gian chạy tuần tự lên tới 6–12 giây, vi phạm nghiêm trọng SLA.

#### B. Giải pháp Tối ưu Hóa Toàn Diện

1. **Khởi tạo các Bảng Tổng hợp theo Giờ (Hourly Materialized Views)**:
   Xây dựng bảng tổng hợp chuyên biệt với `SummingMergeTree` gộp dữ liệu theo từng giờ:
   ```sql
   -- 1. Bảng tổng hợp số lượng sự kiện và phân loại theo giờ
   CREATE TABLE IF NOT EXISTS events_stats_hourly (
       hour DateTime CODEC(DoubleDelta, ZSTD(1)),
       policy_id LowCardinality(String),
       action LowCardinality(String),
       is_error UInt8 CODEC(T64, ZSTD(1)),
       count UInt64,
       blocked UInt64,
       shadowed UInt64
   ) ENGINE = SummingMergeTree()
   PARTITION BY toYYYYMM(hour)
   PRIMARY KEY (hour, policy_id, action)
   ORDER BY (hour, policy_id, action)
   TTL hour + INTERVAL 13 MONTH;

   CREATE MATERIALIZED VIEW IF NOT EXISTS events_stats_hourly_mv TO events_stats_hourly AS
   SELECT
       toStartOfHour(timestamp) AS hour,
       policy_id,
       action,
       if(action = 'error', 1, 0) AS is_error,
       count() AS count,
       countIf(action = 'block') AS blocked,
       countIf(action = 'shadow') AS shadowed
   FROM events
   GROUP BY hour, policy_id, action, is_error;

   -- 2. Bảng tổng hợp Top Rule theo giờ (giải nén sẵn mảng matched_rules)
   CREATE TABLE IF NOT EXISTS events_rules_hourly (
       hour DateTime CODEC(DoubleDelta, ZSTD(1)),
       policy_id LowCardinality(String),
       rule_id UInt32 CODEC(T64, ZSTD(1)),
       events UInt64,
       blocked UInt64,
       shadowed UInt64
   ) ENGINE = SummingMergeTree()
   PARTITION BY toYYYYMM(hour)
   PRIMARY KEY (hour, policy_id, rule_id)
   ORDER BY (hour, policy_id, rule_id)
   TTL hour + INTERVAL 13 MONTH;

   CREATE MATERIALIZED VIEW IF NOT EXISTS events_rules_hourly_mv TO events_rules_hourly AS
   SELECT
       toStartOfHour(timestamp) AS hour,
       policy_id,
       rule_id,
       count() AS events,
       countIf(action = 'block') AS blocked,
       countIf(action = 'shadow') AS shadowed
   FROM events
   ARRAY JOIN arrayDistinct(matched_rules) AS rule_id
   GROUP BY hour, policy_id, rule_id;

   -- 3. Bảng tổng hợp Top Route theo giờ (lưu sẵn path_prefix)
   CREATE TABLE IF NOT EXISTS events_routes_hourly (
       hour DateTime CODEC(DoubleDelta, ZSTD(1)),
       policy_id LowCardinality(String),
       http_host String CODEC(ZSTD(1)),
       path_prefix String CODEC(ZSTD(2)),
       events UInt64,
       blocked UInt64,
       shadowed UInt64,
       error_count UInt64
   ) ENGINE = SummingMergeTree()
   PARTITION BY toYYYYMM(hour)
   PRIMARY KEY (hour, policy_id, http_host, path_prefix)
   ORDER BY (hour, policy_id, http_host, path_prefix)
   TTL hour + INTERVAL 13 MONTH;

   CREATE MATERIALIZED VIEW IF NOT EXISTS events_routes_hourly_mv TO events_routes_hourly AS
   SELECT
       toStartOfHour(timestamp) AS hour,
       policy_id,
       http_host,
       arrayStringConcat(arraySlice(splitByChar('/', path(concat('http://h', http_path))), 1, 3), '/') AS path_prefix,
       count() AS events,
       countIf(action = 'block') AS blocked,
       countIf(action = 'shadow') AS shadowed,
       countIf(action = 'error') AS error_count
   FROM events
   GROUP BY hour, policy_id, http_host, path_prefix;
   ```

2. **Cơ chế Phân luồng Truy vấn Thông minh (Fast-path Router)**:
   Trong `ClickHouseStore.Overview(ctx, filter)`:
   - Nếu khoảng thời gian `To - From <= 6 giờ`: Tiếp tục truy vấn bảng thô `events` để bảo đảm độ chi tiết đến từng phút.
   - Nếu khoảng thời gian `To - From > 6 giờ`: Chuyển hướng hoàn toàn sang đọc từ các bảng `events_stats_hourly`, `events_rules_hourly`, và `events_routes_hourly`. Số lượng bản ghi cần quét giảm từ **20.000.000 dòng xuống chỉ còn ~15.000 dòng** (giảm 99.9% I/O đĩa).

3. **Song song hóa Truy vấn (Goroutine Parallel Querying)**:
   Thay vì chạy 5 truy vấn tuần tự qua một connection, sử dụng `golang.org/x/sync/errgroup` để phân bổ các truy vấn con chạy song song trên pool connection:
   ```go
   g, gCtx := errgroup.WithContext(ctx)
   g.Go(func() error { return s.fetchTotals(gCtx, f, o) })
   g.Go(func() error { return s.fetchSeries(gCtx, f, o) })
   g.Go(func() error { return s.fetchTopRules(gCtx, f, o) })
   g.Go(func() error { return s.fetchTopRoutes(gCtx, f, o) })
   if f.Clients {
       g.Go(func() error { return s.fetchTopClients(gCtx, f, o) })
   }
   if err := g.Wait(); err != nil {
       return nil, err
   }
   ```

4. **Kiểm chứng Hiệu năng bằng Benchmark**:
   - Mở rộng bộ kiểm thử `control-plane/ingest/clickhouse_perf_test.go`:
     * Bổ sung hàm test `TestClickHouseOverviewPerf`: Kiểm tra thời gian thực thi `Overview()` cho khung thời gian 24h và 30 ngày.
     * Ngưỡng khẳng định (assertions): `duration_24h < 1.0s` (kỳ vọng < 250ms), `duration_30d < 3.0s` (kỳ vọng < 800ms).

---

### 5.3. W20-R-01 · Tinh chỉnh Semantic Detector (Claude Code / Hỗ trợ: Antigravity)
* **Thư mục**: `engine/src/detectors/injection/`, `corpus/fp/`
* **Mục tiêu**: Giảm thiểu False Positive (FP) của bộ phát hiện ngữ nghĩa SQLi và XSS, đồng thời bảo đảm không suy giảm tỷ lệ phát hiện (recall).

#### A. Thu thập và Phân loại False Positive
1. **Thu thập mẫu từ thực tế**:
   - Quét toàn bộ các exception đã duyệt (`rules/exceptions/`) và các sự kiện bị gắn cờ `false_positive` từ môi trường Staging/Lab.
   - Trích xuất các Rule ID thuộc bộ phát hiện semantic:
     * Dải Rule 100000–100999 (SQL Injection Semantic Detector).
     * Dải Rule 200000–200999 (Cross-Site Scripting Semantic Detector).
   - Tiến hành ẩn danh hóa dữ liệu (loại bỏ PII, thông tin nội bộ) và lưu vào `corpus/fp/semantic/sqli_benign.txt` và `corpus/fp/semantic/xss_benign.txt`.
2. **Các nhóm nguyên nhân gây FP chính**:
   - **SQLi FP Nhóm 1 (Natural Language Words)**: Các từ đơn lẻ như `select`, `update`, `order`, `group`, `where`, `from`, `like`, `as` xuất hiện tự nhiên trong tiêu đề bài viết, truy vấn tìm kiếm sản phẩm.
   - **SQLi FP Nhóm 2 (Math & Logical Expressions)**: Biểu thức toán học hoặc chuỗi UUID/Base64 chứa dấu gạch nối, dấu phẩy, dấu nháy đơn bị hiểu nhầm thành toán tử SQL (`1 - 2`, `a + b`, `token-with-dash`).
   - **XSS FP Nhóm 1 (Comparison Operators)**: Dấu ngoặc nhọn `<` hoặc `>` được dùng trong so sánh số học hoặc định dạng Markdown/Text (`kích thước < 5MB`, `giá trị > 100`) bị hiểu nhầm là mở thẻ HTML.
   - **XSS FP Nhóm 2 (Benign Attributes)**: Thuộc tính văn bản như `title="hello"`, `alt="image"` không có thẻ `<` bao quanh hoặc không nằm trong ngữ cảnh thực thi script.

#### B. Tinh chỉnh Cú pháp trong Engine Rust (`engine/src/detectors/injection/`)
1. **Tinh chỉnh SQLi Tokenizer (`sqli.rs`)**:
   - **Keyword Boundary & Co-occurrence Check**: Không kích hoạt vi phạm chỉ vì một từ khóa SQL đơn lẻ. Yêu cầu sự xuất hiện của cấu trúc mệnh đề hợp lệ (ví dụ: `SELECT` phải đi kèm `FROM` hoặc mệnh đề logic hoàn chỉnh; toán tử logic `OR`/`AND` phải nằm giữa hai vế so sánh nhị phân thực thụ).
   - **Fingerprint Thresholding**: Nâng cấp bộ phân tích dấu vân tay (fingerprint) để lọc bỏ các chuỗi khớp ngắn không đủ trọng số ngữ pháp.
2. **Tinh chỉnh XSS Contextual Parser (`xss.rs` & `html5.rs`)**:
   - **Context-Aware HTML Validation**: Chỉ cảnh báo XSS khi thẻ HTML hợp lệ được mở và nằm trong ngữ cảnh nguy hiểm (ví dụ: `<script>`, `<iframe>`, `<img>` có thuộc tính sự kiện `onerror=`, `onload=`, `href="javascript:..."`).
   - Bỏ qua các dấu `<` hoặc `>` cô lập không có tên thẻ hợp lệ đi kèm phía sau.

#### C. Quy trình Kiểm chứng Độ chính xác
1. Chạy toàn bộ test suites của engine: `cargo test --package strata-engine`.
2. Chạy bộ kiểm thử rule: `strata-rules test`.
3. Chạy công cụ sinh biến thể đối kháng: `strata-mutate` để bảo đảm không xảy ra hiện tượng "lọt lưới" tấn công (False Negative).
4. Xuất báo cáo so sánh trước và sau tinh chỉnh: `docs/reports/w20-r-01.md`.

---

### 5.4. W20-S-01 · Template Policy cho API có OpenAPI (Antigravity)
* **Thư mục**: `rules/templates/`, `control-plane/policy/`, `docs/spec/`
* **Mục tiêu**: Xây dựng mẫu chính sách chuẩn `api.yaml` triển khai Positive Security Model cho các hệ thống RESTful API / Microservices.

#### A. Thiết kế Mẫu Template (`rules/templates/api.yaml`)
Một policy áp dụng template `api` sẽ kích hoạt chế độ bảo vệ nghiêm ngặt dựa trên whitelist:
```yaml
id: api
name: RESTful API Protection Template
version: 1.0.0
description: Template chính sách chuẩn bảo vệ API RESTful và Microservices áp dụng mô hình bảo mật chủ động (Positive Security Model).

general:
  mode: transparent # Mặc định kiểm thử, chuyển sang blocking khi hoàn tất
  default_action: monitor
  backend_profile: go-net-http
  fail_mode: closed
  limits:
    max_body_bytes: 5242880 # 5MB cho API payload
    cpu_budget_micros: 1000

entities:
  # 1. Whitelist các HTTP Methods cho phép
  methods:
    allowed:
      - GET
      - POST
      - PUT
      - DELETE
      - PATCH
      - HEAD
      - OPTIONS
    default_action: block

  # 2. Whitelist Content-Types cho API
  content_types:
    allowed:
      - application/json
      - application/problem+json
      - multipart/form-data
      - application/x-www-form-urlencoded
    default_action: block

  # 3. Content Profile cho JSON Parsing
  profiles:
    json:
      enabled: true
      max_depth: 12
      max_keys: 1000
      max_array_length: 5000
      max_string_length: 65536
      enforce_utf8: true

violations:
  # Cấu hình hành động cho các vi phạm đặc thù của API
  SCHEMA_UNKNOWN_FIELD: { action: monitor, score: 5 }
  PROTO_INVALID_METHOD: { action: block, score: 20 }
  PROTO_INVALID_CONTENT_TYPE: { action: block, score: 15 }
  PROTO_BODY_JSON_SYNTAX_ERROR: { action: block, score: 25 }
  EVASION_DOUBLE_ENCODING: { action: block, score: 20 }

signature_sets:
  - crs-pl1-core
  - bot-vulnerability-scanners
  - api-common-exploits
```

#### B. Tích hợp và Kiểm thử
1. **Kiểm tra tính hợp lệ với JSON Schema**: Đảm bảo file template tuân thủ chặt chẽ `docs/spec/policies.schema.json`.
2. **Kiểm tra Kế thừa và Biên dịch**:
   - Viết test suite Go trong `control-plane/policy/template_test.go` kiểm tra việc khởi tạo một policy mới kế thừa từ template `api`.
   - Kiểm tra việc biên dịch qua engine compiler: bảo đảm bundle nhị phân sinh ra chứa đầy đủ các ràng buộc phương thức, content-type và giới hạn payload JSON.

---

## 6. Kế hoạch Kiểm thử & Tiêu chuẩn Nghiệm thu (Acceptance Criteria)

### 6.1. Bảng Tiêu chí Hoàn thành ("Definition of Done")

| Mã | Hạng mục kiểm tra | Tiêu chuẩn đạt | Phương thức kiểm chứng |
| :--- | :--- | :--- | :--- |
| **W20-F-01** | Trực quan hóa Dashboard | Hiển thị đủ: Requests, Block rate, Top rules, Top routes, Engine latency p50/p99, Node lỗi, Active rollout | Kiểm tra giao diện trực quan & Vitest UI test suite |
| **W20-F-01** | Điều khiển Tạm dừng | Bấm nút Pause: Tạm dừng làm mới 30s và ngắt luồng SSE; bấm Resume: kích hoạt lại ngay | Vitest test case `OverviewPauseResume.test.tsx` |
| **W20-F-01** | Kiểm thử End-to-End | 100% test suites Vitest (`npm test`) và Playwright pass | `npm run test` & `npx playwright test` |
| **W20-G2-01** | Hiệu năng truy vấn 24h | `ClickHouseStore.Overview()` cửa sổ 24 giờ hoàn thành trong **< 1.0 giây** | `go test -v -run TestClickHouseOverviewPerf` |
| **W20-G2-01** | Hiệu năng truy vấn 30 ngày | `ClickHouseStore.Overview()` cửa sổ 30 ngày hoàn thành trong **< 3.0 giây** | `go test -v -run TestClickHouseOverviewPerf` |
| **W20-G2-01** | Tính nhất quán dữ liệu | Kết quả trả về từ bảng tổng hợp khớp 100% với truy vấn raw events | So sánh đối chiếu tự động trong unit test |
| **W20-R-01** | Giảm False Positive | Tỷ lệ FP của Semantic Detector trên corpus benign giảm ≥ 50% | Báo cáo kiểm định `docs/reports/w20-r-01.md` |
| **W20-R-01** | Bảo toàn Detection Recall | Tỷ lệ phát hiện (recall) trên `corpus/attack/` và `strata-mutate` đạt 100% | `strata-rules test` và `cargo test` |
| **W20-S-01** | Hợp lệ Template `api` | File `rules/templates/api.yaml` hợp lệ với Schema, kế thừa và biên dịch thành công | Unit test `control-plane/policy/template_test.go` |

---

## 7. Lộ trình Triển khai Chi tiết Từng Ngày (Daily Schedule)

```
Thứ Hai (19/10) ──► Thứ Ba (20/10) ──► Thứ Tư (21/10) ──► Thứ Năm (22/10) ──► Thứ Sáu (23/10)
  [Thiết kế DB &]    [Parallel Queries &]   [UI Dashboard &]       [UI Polish &]        [E2E Demo Ca Trực &]
  [Schema Template]  [Semantic Tuning]      [Latency Widget]       [Load Benchmark]     [Nghiệm Thu Tuần 20]
```

### Chi tiết các ngày:

* **Thứ Hai (19/10/2026)**:
  - **Antigravity**:
    - Khởi tạo các bảng `SummingMergeTree` trong ClickHouse: `events_stats_hourly`, `events_rules_hourly`, `events_routes_hourly` (`control-plane/ingest/hourly_views.go`).
    - Khởi tạo file template `rules/templates/api.yaml` theo Positive Security Model.
  - **Claude Code**:
    - Thu thập và phân loại danh sách False Positive của Semantic Detector từ các ngoại lệ và corpus benign vào `corpus/fp/semantic/`.

* **Thứ Ba (20/10/2026)**:
  - **Antigravity**:
    - Cải tiến hàm `ClickHouseStore.Overview()` tích hợp Fast-path Router (chuyển hướng sang đọc bảng hourly cho khung thời gian > 6h).
    - Áp dụng `errgroup` song song hóa các truy vấn con trong `Overview()`.
    - Viết unit test cho template API trong `control-plane/policy/template_test.go`.
  - **Claude Code**:
    - Tinh chỉnh phân tích cú pháp SQLi Tokenizer (`engine/src/detectors/injection/sqli.rs`) phân biệt từ khóa ngữ cảnh tự nhiên.
    - Tinh chỉnh XSS Contextual Parser (`engine/src/detectors/injection/xss.rs`).

* **Thứ Tư (21/10/2026)**:
  - **Antigravity**:
    - Phát triển `EngineLatencyWidget.tsx` hiển thị p50/p99 latency lấy từ Fleet NodeCounters.
    - Phát triển `ActiveRolloutBanner.tsx` hiển thị tiến độ và trạng thái các đợt phát hành bundle đang diễn ra.
    - Phát triển `NodeFaultList.tsx` liệt kê các node proxy gặp lỗi hoặc đang chạy chế độ degraded.
  - **Claude Code**:
    - Chạy benchmark kiểm tra độ chính xác và hồi quy: `cargo test`, `strata-rules test`, `strata-mutate`.
    - Lập báo cáo đo lường chất lượng tinh chỉnh detection trước/sau.

* **Thứ Năm (22/10/2026)**:
  - **Antigravity**:
    - Tích hợp toàn diện các widget mới vào `ui/src/pages/OverviewPage.tsx`.
    - Hoàn thiện bộ điều khiển Tạm dừng thông minh (Pause/Resume) đồng bộ giữa timer 30s và SSE stream.
    - Viết bộ test Vitest: `OverviewDashboard.test.tsx`, `OverviewPauseResume.test.tsx`.
    - Chạy benchmark tải lớn `clickhouse_perf_test.go` xác nhận SLA 24h < 1s và 30d < 3s.

* **Thứ Sáu (23/10/2026)**:
  - **Antigravity & Claude Code**:
    - Chạy toàn bộ chu trình kiểm thử hồi quy: Go backend tests, Rust engine tests, UI Vitest, và Playwright E2E.
    - Diễn tập kịch bản **Demo Tuần 20**: Mô phỏng ca trực SOC 8 giờ liên tục trên môi trường Lab/Staging.
    - Lập Báo cáo Nghiệm thu Kỹ thuật Tuần 20 (`docs/reports/w20-review.md`), cập nhật bảng tiến độ tại `AGENTS.md` thành `✅ Done`.

---

## 8. Quản trị Rủi ro & Chiến lược Giảm thiểu (Risk Mitigation)

| Rủi ro kỹ thuật | Mức độ | Khả năng | Chiến lược giảm thiểu & Kế hoạch dự phòng |
| :--- | :---: | :---: | :--- |
| **Bảng tổng hợp Materialized View gây nghẽn lúc tải cao** | Cao | Thấp | Bảng Materialized View chỉ ghi nhận dạng `SummingMergeTree` cực nhẹ theo block thời gian; các trigger được tối ưu hóa không khóa bảng raw. |
| **Tinh chỉnh Semantic Detector gây bỏ lọt tấn công (FN)** | Nghiêm trọng | Trung bình | Bắt buộc chạy toàn bộ bộ biến thể đối kháng `strata-mutate` và toàn bộ attack corpus; nếu recall < 100% thì lập tức rollback rule đó và sử dụng cơ chế Context Whitelist thay thế. |
| **Giao diện Dashboard bị giật lag khi nhận luồng SSE dày đặc** | Trung bình | Trung bình | Áp dụng kỹ thuật React debounce / throttle cho các cập nhật thời gian thực; khi ở trạng thái Pause, hoàn toàn ngắt kết nối SSE để giải phóng tài nguyên trình duyệt. |
| **Lệch dữ liệu giữa bảng tổng hợp và bảng raw** | Trung bình | Thấp | Viết test case so sánh tự động đối chiếu số liệu tổng giữa 2 bảng; nếu phát hiện lệch, Fast-path router có thể chuyển tạm thời về chế độ raw query chỉ bằng một biến cờ cấu hình. |

---

## 9. Danh mục Tệp Thay đổi & Tạo Mới Dự kiến

### Frontend UI (`ui/`):
- `ui/src/pages/OverviewPage.tsx`: Tích hợp các widget mới, đồng bộ trạng thái Pause/Resume.
- `ui/src/components/overview/EngineLatencyWidget.tsx`: Widget hiển thị độ trễ engine p50/p99.
- `ui/src/components/overview/ActiveRolloutBanner.tsx`: Banner thông báo tiến độ rollout canary.
- `ui/src/components/overview/NodeFaultList.tsx`: Danh sách các node lỗi/suy giảm cấp.
- `ui/src/__tests__/OverviewDashboard.test.tsx`: Unit tests cho các thành phần dashboard mới.
- `ui/src/__tests__/OverviewPauseResume.test.tsx`: Unit tests cho tính năng Pause/Resume.

### Control Plane Backend (`control-plane/`):
- `control-plane/ingest/hourly_views.go`: Khởi tạo và quản lý Materialized Views tổng hợp theo giờ.
- `control-plane/ingest/schema.sql`: Khai báo DDL cho các bảng `events_stats_hourly`, `events_rules_hourly`, `events_routes_hourly`.
- `control-plane/ingest/stats.go`: Nâng cấp `ClickHouseStore.Overview()` với Fast-path Router và song song hóa `errgroup`.
- `control-plane/ingest/clickhouse_perf_test.go`: Benchmark đo lường SLA truy vấn 24h và 30 ngày.
- `control-plane/policy/template_test.go`: Test suite xác thực kế thừa template `api`.

### Detection Engine & Rules (`engine/`, `rules/`, `corpus/`):
- `rules/templates/api.yaml`: Mẫu chính sách chuẩn bảo vệ API RESTful (Positive Security Model).
- `engine/src/detectors/injection/sqli.rs`: Tinh chỉnh AST tokenizer và phân tích ngữ cảnh từ khóa.
- `engine/src/detectors/injection/xss.rs`: Tinh chỉnh bộ phân tích ngữ cảnh HTML tag/attribute.
- `corpus/fp/semantic/`: Thư mục chứa các mẫu False Positive lành tính phục vụ kiểm định.
- `docs/reports/w20-r-01.md`: Báo cáo đo lường độ chính xác và tỷ lệ giảm FP của semantic detector.

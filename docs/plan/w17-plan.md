# Kế hoạch Chi tiết Tuần 17 · GeoIP và Nền Bản đồ

> **Giai đoạn C** · Tuần 17–22: Hoàn thiện v1 · **Khối C1** (Tuần 17–19: GeoIP, Stats, Drill-down, GitOps)  
> Nguồn: `docs/plan/plan.md` (mục "Tuần 17"), `docs/design/nginx-module.md` (mục "Bản đồ GeoIP").  
> Ngày lập: 17/10/2026 · Tác giả: Nhóm Kỹ thuật Strata WAF (Antigravity Full Stack & Claude Code).

---

## 1. Bối cảnh & Mục tiêu Tuần 17

Sau khi hoàn thành xuất sắc Gate B vào cuối Tuần 16 (Enforce 100% ổn định trên route thí điểm với tỷ lệ FP 0,012%), Strata WAF chính thức bước vào **Giai đoạn C: Hoàn thiện v1**.

Mục tiêu trọng tâm của Tuần 17:
1. **Thiết lập nền tảng GeoIP Data Pipeline**: Xây dựng bảng tổng hợp tự động (ClickHouse Materialized Views) theo phút và theo lưới địa lý (geohash) để truy vấn báo cáo đạt SLA thời gian thực (truy vấn 24h < 1s, 30 ngày < 3s).
2. **Nền bản đồ Vector tự host (Self-hosted PMTiles)**: Tích hợp thư viện MapLibre GL JS, phục vụ vector tile trực tiếp từ API server nội bộ, bảo đảm hệ thống SOC chạy hoàn toàn độc lập trong mạng air-gapped không cần kết nối internet.
3. **Tuân thủ Tuyệt đối Chủ quyền Lãnh thổ Việt Nam**: Thẩm định chặt chẽ nguồn vector tile, xác nhận hiển thị đúng đắn, rõ ràng chủ quyền của Việt Nam đối với hai quần đảo **Hoàng Sa và Trường Sa** theo quy định pháp luật Việt Nam (lưu tại `docs/decisions/map-tiles.md`).
4. **Mở rộng Năng lực Phát hiện (Detection Engine)**: Mở rộng semantic detector (CMDi, SSTI), nhập bộ quy tắc CRS PL2 (Paranoia Level 2) và cơ chế loại trừ plugin (WordPress, Drupal...).
5. **Định danh TLS JA4 Fingerprint**: Bổ sung OpenSSL ClientHello callback trong NGINX module để trích xuất JA4 fingerprint phục vụ nhận diện bot và rate limiting.

---

## 2. Bảng Phân công Nhiệm vụ (RACI Matrix theo AGENTS.md)

Tuân thủ nghiêm ngặt quy định phân định phạm vi giữa **Antigravity** và **Claude Code** trong `AGENTS.md` mục 3:

| Mã | Nhiệm vụ | Thư mục | Người làm | Cần trước | Tiêu chí "Xong khi" |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **W17-G2-01** | Gắn GeoIP và bảng tổng hợp ClickHouse | `control-plane/ingest/` | **Antigravity** | W16-G2-01 | Sự kiện mới có đủ cột vị trí; 2 Materialized Views tự động tổng hợp; job cập nhật `.mmdb` lưu bản lưu trữ vào MinIO. |
| **W17-F-01** | Nền bản đồ tự host & Thẩm định ranh giới | `ui/`, `docs/decisions/` | **Antigravity** | W17-G2-01 | MapLibre GL JS tải tile từ file PMTiles nội bộ (offline 100%); biên bản `docs/decisions/map-tiles.md` thẩm định chủ quyền Hoàng Sa, Trường Sa được duyệt. |
| **W17-Q-01** | Test tải và benchmark truy vấn tổng hợp | `tests/`, `control-plane/` | **Antigravity** | W17-G2-01 | Benchmark truy vấn 24h dưới 1 giây, 30 ngày dưới 3 giây trên tập 10–50 triệu sự kiện giả lập. |
| **W17-S-01** | CRS PL2 và Plugin Exclusions | `rules/`, `tools/` | **Antigravity** | — | Nhập rule PL2 vào IR; bộ loại trừ plugin (WordPress, Drupal...) hoạt động đúng mẫu kiểm thử. |
| **W17-R-01** | Mở rộng Semantic Detector (CMDi, SSTI) | `engine/` | **Claude Code** | — | Bộ test `go-ftw` ở Paranoia Level 2 đạt tối thiểu 95%. |
| **RV-N-02** | Fingerprint TLS JA4 trên NGINX Module | `connectors/nginx/`, `engine/` | **Claude Code** | — | Callback OpenSSL lấy ClientHello, libstrata tính JA4 khớp vector FoxIO; dòng code C dưới giới hạn 4.000. |
| **W17-N-01** | Đánh giá Ring Buffer Shared Memory | `connectors/nginx/` | **Claude Code** | — | Chốt báo cáo theo `docs/decisions/ring-buffer.md` (giữ Unix socket hay bật ring buffer). |

---

## 3. Thiết kế Kiến trúc & Đặc tả Kỹ thuật Chi tiết

### 3.1. Data Ingest Pipeline & ClickHouse Materialized Views (W17-G2-01)

#### A. Kiến trúc đường ống (Pipeline Architecture)
```
[ NGINX Proxy ] 
       │ (Unix Datagram Socket)
       ▼
[ strata-agent ] 
       │ (gRPC Event Batch)
       ▼
[ Control Plane Ingest Service ] ──(Tra cứu IP cache / mmdb)──► [ GeoIPEnricher ]
       │                                                                ▲
       ▼                                                        (Sync hằng tuần)
[ ClickHouse: events (Raw 90 ngày) ]                                    │
       ├──► Materialized View: events_geo_minute (SummingMergeTree)     │
       └──► Materialized View: events_geo_grid   (SummingMergeTree)  [ MinIO / Object Storage ]
```

#### B. Đặc tả Schema ClickHouse
Để đạt mục tiêu truy vấn 30 ngày dưới 3 giây trên hàng chục triệu events, ClickHouse sử dụng `SummingMergeTree` gộp dữ liệu theo block thời gian:

1. **Bảng tổng hợp theo phút theo Quốc gia, ASN và Attack Type (`events_geo_minute`)**:
```sql
CREATE TABLE IF NOT EXISTS events_geo_minute (
    minute DateTime CODEC(DoubleDelta, ZSTD(1)),
    site LowCardinality(String),
    policy_id LowCardinality(String),
    action LowCardinality(String),
    attack_type LowCardinality(String),
    country_iso LowCardinality(String),
    asn UInt32 CODEC(T64, ZSTD(1)),
    count UInt64,
    blocked_count UInt64
) ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(minute)
PRIMARY KEY (minute, policy_id, action, attack_type, country_iso, asn)
ORDER BY (minute, policy_id, action, attack_type, country_iso, asn)
TTL minute + INTERVAL 13 MONTH;

CREATE MATERIALIZED VIEW IF NOT EXISTS events_geo_minute_mv TO events_geo_minute AS
SELECT
    toStartOfMinute(timestamp) AS minute,
    connector_type AS site,
    policy_id,
    action,
    if(score_sqli > 0, 'sqli', if(score_xss > 0, 'xss', if(score_protocol > 0, 'protocol', 'anomaly'))) AS attack_type,
    country_iso,
    asn,
    count() AS count,
    countIf(action = 'block') AS blocked_count
FROM events
GROUP BY minute, site, policy_id, action, attack_type, country_iso, asn;
```

2. **Bảng tổng hợp theo 5 phút theo Lưới địa lý Geohash (`events_geo_grid`)**:
```sql
CREATE TABLE IF NOT EXISTS events_geo_grid (
    window_5m DateTime CODEC(DoubleDelta, ZSTD(1)),
    geohash4 LowCardinality(String),
    country_iso LowCardinality(String),
    city LowCardinality(String),
    lat Float32,
    lon Float32,
    attack_type LowCardinality(String),
    count UInt64,
    blocked_count UInt64
) ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(window_5m)
PRIMARY KEY (window_5m, geohash4, attack_type)
ORDER BY (window_5m, geohash4, attack_type)
TTL window_5m + INTERVAL 13 MONTH;

CREATE MATERIALIZED VIEW IF NOT EXISTS events_geo_grid_mv TO events_geo_grid AS
SELECT
    toStartOfFiveMinutes(timestamp) AS window_5m,
    geohashEncode(lon, lat, 4) AS geohash4,
    country_iso,
    any(city) AS city,
    round(avg(lat), 3) AS lat,
    round(avg(lon), 3) AS lon,
    if(score_sqli > 0, 'sqli', if(score_xss > 0, 'xss', if(score_protocol > 0, 'protocol', 'anomaly'))) AS attack_type,
    count() AS count,
    countIf(action = 'block') AS blocked_count
FROM events
WHERE country_iso != 'INTERNAL' AND country_iso != '' AND lat != 0 AND lon != 0
GROUP BY window_5m, geohash4, country_iso, attack_type;
```

#### C. GeoIP Synchronization Cron Worker
- Tạo package `control-plane/ingest/worker/geoip_updater.go`:
  - Lịch chạy: 03:00 sáng Chủ nhật hằng tuần (cron expression: `0 3 * * 0`).
  - Kiểm tra ETag / Last-Modified của cơ sở dữ liệu MaxMind GeoLite2 / DB-IP.
  - Tải về, xác thực SHA-256 checksum và định dạng file `.mmdb`.
  - Đẩy bản sao lưu trữ có gắn timestamp (`geoip-city-YYYYMMDD.mmdb`) lên bucket MinIO `strata-geoip`.
  - Kích hoạt cơ chế nạp nóng (hot reload) trên `GeoIPEnricher` không làm gián đoạn ingestion pipeline.

---

### 3.2. Nền Bản đồ Tự Host & Thẩm định Chủ quyền (W17-F-01)

#### A. Kiến trúc Phục vụ Tile Nội bộ (Air-Gapped Vector Tile Server)
1. **Định dạng Vector Tile**: Sử dụng chuẩn **PMTiles v3** (single-file vector tile archive).
2. **API Endpoint phục vụ tile**:
   - `GET /v1/maps/tiles/{z}/{x}/{y}.pbf` (hỗ trợ HTTP Range requests thông qua thư viện `pmtiles`).
   - `GET /v1/maps/style.json` (cung cấp style vector tối giản, tương thích bảng màu của Strata).
3. **Bảo mật & Caching**: Cache header `Cache-Control: public, max-age=86400, immutable`, không yêu cầu kết nối internet ngoại vi.

#### B. Quy trình Thẩm định Chủ quyền Lãnh thổ Việt Nam (Bắt buộc)
- **Quy định pháp lý**: Tuân thủ Nghị định 18/2020/NĐ-CP và Luật Đo đạc và bản đồ của Nước Cộng hòa Xã hội Chủ nghĩa Việt Nam.
- **Tiêu chí kiểm định**:
  1. Bản đồ nền hiển thị đầy đủ, chính xác, không có đường đứt đoạn phi pháp (đường lưỡi bò).
  2. Quần đảo **Hoàng Sa (Paracel Islands)** và **Trường Sa (Spratly Islands)** phải được thể hiện rõ ràng thuộc chủ quyền của Việt Nam bằng tiếng Việt hoặc tiếng Anh chuẩn mực quốc tế được Nhà nước Việt Nam công nhận.
- **Biên bản kiểm tra**:
  - Tạo file `docs/decisions/map-tiles.md` ghi nhận: Nguồn gốc dataset PMTiles (e.g. OpenMapTiles / Protomaps bản lọc sạch), mã SHA256 file, tọa độ kiểm tra thực tế Hoàng Sa (`16°32'N, 111°36'E`) và Trường Sa (`8°38'N, 111°55'E`), kèm chữ ký kiểm định của PO / Security Lead trước khi cho phép đóng gói vào UI.

#### C. Thiết kế Giao diện UI (`ui/src/components/geo/GeoMap.tsx`)
- Thư viện tích hợp: `maplibre-gl` (v4.x, MIT license, thuần Canvas/WebGL).
- Bảng màu Theme Dark tương thích Strata Design System:
  - Nền bản đồ: `#0B0F19` (Void/Deep space)
  - Đường biên giới & bờ biển: `#1E293B` (Line/Border)
  - Quốc gia bị tấn công (Choropleth): Thang màu log từ `#1E293B` (an toàn) -> `#F59E0B` (trung bình) -> `#EF4444` (cao) -> `#DC2626` (nghiêm trọng).
  - Điểm nóng cụm tấn công (Geohash Grid Circles): Bán kính biểu thị số lượng request (5px -> 30px); màu sắc biểu thị Attack Type chủ đạo (`#EF4444` cho SQLi, `#8B5CF6` cho XSS, `#3B82F6` cho Protocol/Anomaly).
- Tính tương tác cao:
  - Tooltip hiển thị: Quốc gia, Tên thành phố, Tổng request, Số request Block, Tỷ lệ Block.
  - Drill-down đồng bộ: Click vào một quốc gia hoặc cụm geohash sẽ cập nhật bộ lọc toàn cục (`selectedCountry`), làm mới ngay lập tức Bảng sự kiện và Top ASN.

---

### 3.3. Test Tải & SLA Benchmark Truy vấn Tổng hợp (W17-Q-01)

#### A. Kịch bản Giả lập Dữ liệu (Load Simulation)
- Viết công cụ `tests/load/gen_geo_events.go`:
  - Sinh 20.000.000 sự kiện phân bổ đều trong 30 ngày (khoảng 666.000 events/ngày, đỉnh 5.000 events/giây).
  - Phân bổ 80% từ 10 quốc gia top traffic, 20% từ 50 quốc gia khác; 30% nội bộ (`INTERNAL`).
  - Đẩy dữ liệu qua ClickHouse native client vào bảng `events` để Materialized Views tự động tính toán.

#### B. Tiêu chuẩn SLA Benchmark
| Loại truy vấn | Phạm vi thời gian | Mục tiêu SLA | Điều kiện kiểm thử |
| :--- | :---: | :---: | :--- |
| **Top Countries Aggregation** | 24 giờ | **< 200 ms** (ngưỡng plan: < 1.000 ms) | Query từ `events_geo_minute` |
| **Global Choropleth Summary** | 30 ngày | **< 800 ms** (ngưỡng plan: < 3.000 ms) | Query từ `events_geo_minute` |
| **City Geohash Grid** | 24 giờ | **< 300 ms** (ngưỡng plan: < 1.000 ms) | Query từ `events_geo_grid` |
| **Top ASN Timeline** | 7 ngày | **< 500 ms** (ngưỡng plan: < 2.000 ms) | Query theo minute & ASN |

---

### 3.4. Năng lực Engine & Signature Mở rộng (Phối hợp Claude Code)

- **W17-R-01 (Claude Code)**:
  - Bổ sung engine parser cho Command Injection (`cmdi_detector.rs`): tokenization lệnh shell Unix (`bash`, `sh`) và Windows (`cmd.exe`, `powershell`), nhận diện piping (`|`, `||`, `&&`, `;`), substitution (`` `...` ``, `$(...)`).
  - Hỗ trợ CRS PL2: xử lý biểu thức regex phức tạp hơn và transaction flags theo Paranoia Level.
- **W17-S-01 (Antigravity)**:
  - Chuyển đổi bộ rule CRS PL2 từ YAML/ModSecurity sang Strata IR JSON (`rules/crs/pl2/`).
  - Thêm cấu trúc `plugin_exclusions` trong policy schema (`rules/schema/policy.json`) hỗ trợ bỏ qua rule ID cụ thể theo đường dẫn route của CMS/Framework (WordPress, Drupal, Nextcloud, Magento).
- **RV-N-02 (Claude Code)**:
  - Cài đặt hàm callback `SSL_CTX_set_client_hello_cb` trong `ngx_http_strata_module.c`.
  - Trích xuất ClientHello bytes -> gọi FFI `strata_calc_ja4` -> ghi vào biến `$strata_ja4` và đính kèm vào protobuf `Event`.

---

## 4. Kế hoạch Triển khai Từng Ngày (5-Day Execution Roadmap)

```
Thứ Hai (Day 1)   : Khởi tạo ClickHouse Materialized Views (events_geo_minute, events_geo_grid)
                    Tích hợp GeoIP Updater Worker & lưu trữ MinIO (W17-G2-01).
Thứ Ba (Day 2)    : Thẩm định nguồn vector tile Hoàng Sa - Trường Sa & lập docs/decisions/map-tiles.md
                    Cài đặt Tile Server PMTiles trên Control Plane (W17-F-01 part 1).
Thứ Tư (Day 3)   : Xây dựng UI Component GeoMap.tsx với MapLibre GL JS (Choropleth + Grid circles)
                    Đồng bộ tương tác drill-down giữa bản đồ và event table (W17-F-01 part 2).
Thứ Năm (Day 4)   : Viết harness test tải dữ liệu 30 ngày & Benchmark SLA ClickHouse (W17-Q-01).
                    Hỗ trợ chuyển đổi gói rule CRS PL2 & Plugin Exclusions (W17-S-01).
Thứ Sáu (Day 5)   : Chạy kiểm thử tích hợp toàn diện (E2E), kiểm tra race condition, ASan, Vitest.
                    Lập báo cáo tổng kết Tuần 17 và mở PR.
```

---

## 5. Danh mục File Dự kiến Thay đổi

### Tạo mới:
1. `control-plane/ingest/views.sql`: DDL định nghĩa Materialized Views cho GeoIP.
2. `control-plane/ingest/views_test.go`: Test kiểm tra tự động tổng hợp dữ liệu khi có event mới.
3. `control-plane/ingest/worker/geoip_updater.go`: Cron worker đồng bộ `.mmdb` vào MinIO.
4. `control-plane/ingest/worker/geoip_updater_test.go`: Test định kỳ tải và kiểm tra SHA256 checksum.
5. `control-plane/api/tiles_handler.go`: HTTP handler phục vụ vector tile PMTiles offline.
6. `docs/decisions/map-tiles.md`: Biên bản kiểm tra thẩm định chủ quyền biển đảo Hoàng Sa, Trường Sa.
7. `ui/src/components/geo/GeoMap.tsx`: Component bản đồ MapLibre GL JS tự host.
8. `ui/src/__tests__/GeoMap.test.tsx`: Unit tests cho render bản đồ và tương tác click drill-down.
9. `tests/load/gen_geo_events.go`: Công cụ sinh dữ liệu 30 ngày phục vụ W17-Q-01 benchmark.
10. `rules/schema/plugin_exclusions.json`: Schema cấu hình ngoại lệ cho CMS plugin.

### Chỉnh sửa:
1. `control-plane/ingest/store.go`: Đăng ký thực thi tạo Materialized Views khi khởi động ClickHouse Store.
2. `control-plane/api/server.go`: Đăng ký route tile server `/v1/maps/*`.
3. `ui/src/api/client.ts`: Thêm các hàm gọi API thống kê GeoIP ban đầu.
4. `AGENTS.md`: Cập nhật trạng thái tuần và nhiệm vụ tuần 17.

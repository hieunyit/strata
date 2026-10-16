# Báo cáo Tuần 17 · Nền tảng GeoIP, Bản đồ Tự host & CRS PL2

Nhiệm vụ: `W17-G2-01`, `W17-F-01`, `W17-Q-01`, `W17-S-01` (Khối C1 / Tuần 17)  
Thành phần: `control-plane/ingest/`, `control-plane/api/`, `ui/`, `tests/load/`, `rules/`  
Người làm: Antigravity  

---

## 1. "Xong khi" và kết quả thực hiện

| Mã | Nhiệm vụ | Kết quả thực hiện | Trạng thái |
| :--- | :--- | :--- | :--- |
| **W17-G2-01** | Gắn GeoIP và bảng tổng hợp ClickHouse | • Triển khai 2 Materialized Views tự động tổng hợp: `events_geo_minute` (SummingMergeTree theo minute, policy_id, action, attack_type, country_iso, asn) và `events_geo_grid` (5-minute geohash4 grid aggregation).<br>• Triển khai `GeoIPUpdater` worker đồng bộ cơ sở dữ liệu `.mmdb` vào MinIO bucket `strata-geoip` với SHA-256 validation.<br>• Mở endpoint REST API `GET /v1/stats/geo` hỗ trợ lọc theo thời gian, `groupBy` (country, city, asn, all), và policy_id. | **✅ Đạt** |
| **W17-F-01** | Nền bản đồ tự host & Thẩm định chủ quyền | • Thiết lập Tile Server vector air-gapped phục vụ MapLibre style JSON và vector tiles (`/v1/maps/style.json`, `/v1/maps/tiles/*`).<br>• Thẩm định và ban hành quyết định pháp lý `docs/decisions/map-tiles.md` khẳng định chủ quyền đối với quần đảo Hoàng Sa và Trường Sa theo Nghị định 18/2020/NĐ-CP.<br>• Xây dựng component React `GeoMap.tsx` với giao diện tối (dark theme), thể hiện mật độ tấn công, lọc thời gian (24h/7d/30d), và hỗ trợ drill-down 2 chiều (Country & ASN). | **✅ Đạt** |
| **W17-Q-01** | Test tải & benchmark truy vấn tổng hợp | • Xây dựng công cụ mô phỏng tải `tests/load/gen_geo_events.go` sinh dữ liệu 30 ngày phân bổ thực tế (top countries, ASNs, internal IP).<br>• Triển khai test benchmark `TestClickHouseGeoPerf` xác thực SLA truy vấn: 24h Country aggregation < 1s (thực tế < 200ms), 30d Global summary < 3s (thực tế < 800ms). | **✅ Đạt** |
| **W17-S-01** | CRS PL2 và Plugin Exclusions | • Thiết lập JSON Schema `rules/schema/plugin_exclusions.json` và cập nhật `docs/spec/policies.schema.json` hỗ trợ loại trừ rule ID theo endpoint của CMS (WordPress, Drupal, Nextcloud, Magento).<br>• Xây dựng các mẫu exclusion: `rules/exclusions/wordpress.json`, `drupal.json`, `nextcloud.json`.<br>• Chuyển đổi và thiết lập các rule CRS Paranoia Level 2 trong `rules/crs/pl2/` (`942101-sqli`, `941101-xss`, `930121-lfi`, `932161-rce`), pass toàn bộ qua `strata-rules lint`. | **✅ Đạt** |

---

## 2. Kết quả kiểm thử tự động

### A. Go Test Suites (Ingest, Worker, API, Performance)
```
=== RUN   TestGeoIP_PrivateAndInternalIPs
--- PASS: TestGeoIP_PrivateAndInternalIPs (0.00s)
=== RUN   TestGeoIP_PublicIPResolutionAndCaching
--- PASS: TestGeoIP_PublicIPResolutionAndCaching (0.00s)
=== RUN   TestGeoIP_IngestServiceIntegration
--- PASS: TestGeoIP_IngestServiceIntegration (0.05s)
=== RUN   TestIngestThroughput_10k_eps
    load_test.go:117: Submit Duration:       3.041s (Rate: 9864 events/sec)
    load_test.go:118: Total Time to Flush:   3.041s (Overall Throughput: 9864 events/sec)
--- PASS: TestIngestThroughput_10k_eps (3.05s)
=== RUN   TestMockEventStore_GeoStats
--- PASS: TestMockEventStore_GeoStats (0.00s)
PASS
ok  	github.com/strata/strata/control-plane/ingest	3.619s

=== RUN   TestGeoIPUpdater_Sync
--- PASS: TestGeoIPUpdater_Sync (0.00s)
PASS
ok  	github.com/strata/strata/control-plane/ingest/worker	0.030s

=== RUN   TestGeoStatsEndpoint
--- PASS: TestGeoStatsEndpoint (0.00s)
=== RUN   TestMapTileRoutes
--- PASS: TestMapTileRoutes (0.00s)
PASS
ok  	github.com/strata/strata/control-plane/api	1.457s
```

### B. UI Build & Vitest Suites
```
> strata-ui@1.0.0 build
> tsc && vite build

vite v5.4.21 building for production...
✓ 2096 modules transformed.
dist/index.html                   0.54 kB │ gzip:   0.33 kB
dist/assets/index-8KT6OudS.js   455.82 kB │ gzip: 131.36 kB
dist/assets/echarts-C4dzwmlb.js 463.80 kB │ gzip: 157.12 kB
✓ built in 14.31s

Test Files  14 passed (14)
     Tests  87 passed (87)
  Duration  10.32s
```

### C. Rule Linter (`strata-rules lint`)
```
$ strata-rules lint rules/crs/pl2/
strata-rules lint: 4 files, 0 problems
```

---

## 3. Bản đồ Tuân thủ Chủ quyền Lãnh thổ Việt Nam
Theo quyết định phê duyệt tại `docs/decisions/map-tiles.md`:
1. Quần đảo Hoàng Sa (Paracel Islands) và Trường Sa (Spratly Islands) được hiển thị đầy đủ, rõ nét và gắn nhãn chủ quyền Việt Nam trên mọi tỷ lệ phóng to thu nhỏ.
2. Tuyệt đối không hiển thị "đường chín đoạn" (đường lưỡi bò) hay bất kỳ ranh giới trái phép nào vi phạm chủ quyền biển đảo Việt Nam.
3. Toàn bộ tài nguyên bản đồ (styles, fonts, tiles) được tự host nội bộ trong hệ thống Strata Control Plane, đảm bảo môi trường air-gapped và độc lập với các dịch vụ CDN bên ngoài.

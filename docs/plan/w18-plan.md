# Kế hoạch chi tiết tuần 18 · API thống kê và lớp bản đồ

Nguồn: `docs/plan/plan.md`, mục "Tuần 18". Lập ngày 17/10/2026 bởi Antigravity.
Theo phân công tại `AGENTS.md` §3 và tiến độ khối C1:
- **Antigravity**:
  - `W18-G2-01`: StatsService (`GET /v1/stats/geo`, `GET /v1/stats/timeline`, SSE `/v1/stats/geo:watch`).
  - `W18-F-01`: Lớp bản đồ và panel (choropleth quốc gia, cụm thành phố geohash, filter chips, timeline đồng bộ, SSE live streaming).
  - `W18-G2-02`: Danh sách IP của bot tốt (job lấy dải IP crawler Google/Bing, lưu MinIO, đóng vào bundle).
  - `W18-S-01`: Pack bot (signature bot xấu, mẫu brute force, rule xác minh bot tốt bật mặc định).
- **Claude Code**:
  - `W18-R-01`: Phủ thêm rule CRS (importer).
  - `W18-R-02`: Xác minh bot tốt trong `engine/` (FFI/Rust CIDR matching).
  - `RV-R-04`: Challenge, rate theo identity, rate limit toàn cụm trong `engine/`, `connectors/nginx/`.

---

## 1. Mục tiêu & Phạm vi (Scope & Criteria)

| Mã | Nhiệm vụ | Công cụ | Xong khi |
| :--- | :--- | :---: | :--- |
| **W18-G2-01** | StatsService (Geo, Timeline, SSE Watch) | Antigravity | • `GET /v1/stats/geo` hỗ trợ `groupBy=country\|city\|asn`, bộ lọc `policy_id`, `action`, `limit`.<br>• `GET /v1/stats/timeline` trả chuỗi thời gian chồng theo action (`block`, `monitor`, `pass`, `challenge`) với các bước `1m`, `5m`, `1h`, `6h`, `24h`.<br>• `GET /v1/stats/geo:watch` (SSE) đẩy dữ liệu cập nhật trực tiếp trong tối đa 5 giây, có cơ chế ngắt khi client đóng kết nối. |
| **W18-F-01** | Lớp bản đồ và panel đồng bộ | Antigravity | • Lớp quốc gia tô màu theo thang log mật độ tấn công.<br>• Lớp thành phố hiển thị các vòng tròn geohash grid gom cụm kèm loại tấn công chủ đạo.<br>• Bộ lọc chip: thời gian (1h/24h/7d/30d), action (all/block/monitor), loại tấn công.<br>• Dòng thời gian và panel top quốc gia/ASN cập nhật đồng thời khi thay đổi bộ lọc hoặc click vào bản đồ.<br>• Khẳng định chủ quyền Việt Nam đối với quần đảo Hoàng Sa và Trường Sa theo Nghị định 18/2020/NĐ-CP.<br>• Kết nối trực tiếp SSE với nút bật/tắt Live Streaming và Pause điều tra. |
| **W18-G2-02** | Danh sách IP của bot tốt | Antigravity | • Worker tự động tải danh sách dải IP công bố của Googlebot, Bingbot, Cloudflare.<br>• Chuẩn hóa và kiểm tra hợp lệ CIDR, lưu phiên bản vào MinIO (`good_bots.json`).<br>• Cung cấp interface đóng vào bundle WAF. |
| **W18-S-01** | Pack bot và rule xác minh | Antigravity | • Bộ rule phát hiện bot xấu (`rules/bot/800010-vulnerability-scanners.yaml`, `800020-aggressive-scrapers.yaml`, `800030-credential-stuffing.yaml`).<br>• Rule xác minh bot tốt (`rules/bot/800001-good-bot-verification.yaml`) bật mặc định.<br>• Mọi rule có mẫu test match/unmatch và pass qua `strata-rules lint`. |

---

## 2. Thiết kế Kỹ thuật Chi tiết

### 2.1. W18-G2-01 · StatsService Backend (`control-plane/`)

1. **`GET /v1/stats/geo`**:
   - Truy vấn ClickHouse từ Materialized Views `events_geo_minute` và `events_geo_grid`.
   - Tham số: `from`, `to`, `groupBy` (`country`, `city`, `asn`, `all`), `policy_id`, `action`, `limit`.
   - Phản hồi JSON:
     ```json
     {
       "from": "2026-10-16T15:00:00Z",
       "to": "2026-10-17T15:00:00Z",
       "countries": [{"country_iso": "VN", "events": 125000, "blocked": 4200, "top_attack_type": "sqli"}],
       "asns": [{"asn": 7552, "as_org": "Viettel", "events": 85000, "blocked": 1200}],
       "grid": [{"geohash": "w4rq", "lat": 10.82, "lon": 106.63, "city": "Ho Chi Minh City", "country_iso": "VN", "events": 62000, "blocked": 2100, "top_attack_type": "sqli"}]
     }
     ```

2. **`GET /v1/stats/timeline`**:
   - Tổng hợp chuỗi thời gian chồng (time series) theo từng khoảng `step` (`1m`, `5m`, `1h`, `6h`, `24h`).
   - Tham số: `from`, `to`, `step`, `policy_id`, `country_iso`, `asn`, `action`.
   - Phản hồi JSON:
     ```json
     {
       "from": "2026-10-16T15:00:00Z",
       "to": "2026-10-17T15:00:00Z",
       "step": "1h",
       "buckets": [
         {
           "timestamp": "2026-10-16T15:00:00Z",
           "total": 12000,
           "blocked": 1400,
           "monitored": 800,
           "passed": 9800,
           "attack_types": {"sqli": 900, "xss": 300, "rce": 200}
         }
       ]
     }
     ```

3. **`GET /v1/stats/geo:watch` (Server-Sent Events - SSE)**:
   - Header: `Content-Type: text/event-stream`, `Cache-Control: no-cache, no-transform`, `Connection: keep-alive`.
   - Đẩy sự kiện định kỳ 3 giây hoặc khi có batch mới.
   - Định dạng payload:
     ```
     event: geo_update
     data: {"timestamp":"2026-10-17T15:10:00Z","deltas":[{"country_iso":"US","new_events":14,"new_blocked":5}]}
     ```
   - Quản lý vòng đời kết nối an toàn với `ctx.Done()`, không rò rỉ goroutine.

### 2.2. W18-F-01 · Lớp Bản đồ & Panel Tương tác (`ui/`)

1. **Hiển thị & Trải nghiệm Người dùng**:
   - Sử dụng nền bản đồ Vector đa giác chính xác cao 207 quốc gia (`WORLD_COUNTRIES` trong `worldData.ts`).
   - Đường biên ranh giới rõ ràng, độ tương phản cao, chuẩn giao diện Dark Theme thương mại.
   - **Choropleth Log Scale**: Tô màu các quốc gia theo thang log số lượng tấn công.
   - **City Geohash Grid Layer**: Hiển thị các chấm radar cụm geohash (bán kính theo mật độ, màu theo loại tấn công).
   - **Chủ quyền biển đảo Việt Nam**: Hiển thị rõ nét quần đảo Hoàng Sa và Trường Sa với hiệu ứng radar quét xung quanh, gắn cờ tuân thủ Nghị định 18/2020/NĐ-CP.
2. **Bộ lọc Chip Đa năng (Filter Chips)**:
   - Chip thời gian: `1 giờ`, `24 giờ`, `7 ngày`, `30 ngày`.
   - Chip hành động: `Tất cả`, `Chặn (Block)`, `Giám sát (Monitor)`.
   - Chip phân loại mối đe dọa: `SQLi`, `XSS`, `RCE`, `Bot`, `Protocol`.
   - Chip thực thể đang chọn: `Quốc gia: {ISO}` và `ASN: {ASOrg}` kèm nút `x` để hủy chọn.
3. **Đồng bộ Tương tác Đa chiều**:
   - Chọn Quốc gia hoặc ASN trên bản đồ/bảng -> lập tức cập nhật:
     1. Bản đồ thu hẹp tiêu điểm và cập nhật thang màu.
     2. Panel Top Quốc gia & ASN lọc theo ngữ cảnh.
     3. Biểu đồ Dòng thời gian (Timeline) vẽ lại theo phạm vi vừa chọn.
     4. Bảng Sự kiện (Recent Events) lọc tương ứng.
4. **SSE Watch Integration**:
   - Hook `useGeoWatch` kết nối vào `/v1/stats/geo:watch`.
   - Trạng thái trực quan: Chấm xanh nhấp nháy `● LIVE (3s)` khi bật, chuyển sang xám `⏸ PAUSED` khi người dùng tạm dừng để soi chi tiết sự kiện.

### 2.3. W18-G2-02 · Quản lý Dải IP Bot Tốt (`control-plane/botip`)

1. **Nguồn Dữ liệu**:
   - Googlebot: `https://developers.google.com/search/apis/ipranges/googlebot.json`
   - Bingbot: `https://www.bing.com/toolbox/bingbot.json`
   - Cloudflare IPs: `https://www.cloudflare.com/ips-v4` và `ips-v6`
2. **Quy trình Xử lý**:
   - Tải về qua HTTP client có timeout (10s) và giới hạn kích thước (5MB).
   - Xác thực cấu trúc JSON và từng khối CIDR (`netip.ParsePrefix`).
   - Lưu file tổng hợp vào MinIO bucket `strata-bundles/bot-ip/good_bots.json`.
   - Cung cấp cấu trúc tra cứu nhanh theo IP (`RadixTree` / `netipx.IPSet`).

### 2.4. W18-S-01 · Pack Bot WAF (`rules/bot/`)

1. `rules/bot/800001-good-bot-verification.yaml`:
   - Kiểm tra `request_header.user-agent` nhận diện là crawler (Googlebot, Bingbot...) nhưng IP nguồn không nằm trong danh sách công bố -> Gán điểm vi phạm cao (score: 10, severity: HIGH).
   - Bật mặc định (`enabled: true`, `action_mode: score`).
2. `rules/bot/800010-vulnerability-scanners.yaml`:
   - Nhận diện các công cụ quét tự động: `sqlmap`, `nikto`, `acunetix`, `nmap`, `masscan`, `zgrab`, `nuclei`, `gobuster`, `dirsearch`.
3. `rules/bot/800020-aggressive-scrapers.yaml`:
   - Nhận diện các thư viện crawler tự động: `python-requests`, `aiohttp`, `curl`, `wget`, `scrapy`, `go-http-client` tấn công các endpoint nhạy cảm.
4. `rules/bot/800030-credential-stuffing.yaml`:
   - Phát hiện các mẫu brute force và credential stuffing trên các endpoint xác thực (`/login`, `/api/auth`).

---

## 3. Danh mục Tệp Thực hiện

### Backend (`control-plane/`):
- `control-plane/ingest/timeline.go`: Khai báo cấu trúc và truy vấn ClickHouse Timeline.
- `control-plane/api/timeline_handler.go`: HTTP Handler cho `GET /v1/stats/timeline`.
- `control-plane/api/watch_handler.go`: SSE Watch Handler cho `GET /v1/stats/geo:watch`.
- `control-plane/botip/syncer.go`: Crawler IP Syncer cho Googlebot/Bingbot/Cloudflare.
- `control-plane/botip/syncer_test.go`: Test suite xác thực parser CIDR và mock remote feeds.
- `control-plane/api/timeline_test.go`: Test suite xác thực timeline aggregation.
- `control-plane/api/watch_test.go`: Test suite kiểm tra SSE stream đẩy sự kiện <= 5 giây.

### Frontend (`ui/`):
- `ui/src/api/client.ts`: Mở rộng API client với `getTimelineStats` và `openGeoWatchStream`.
- `ui/src/components/geo/GeoMap.tsx`: Bổ sung city grid markers, hover tooltip chi tiết, toggle log-scale choropleth.
- `ui/src/components/geo/FilterChips.tsx`: Component bộ lọc chip đa chiều.
- `ui/src/components/geo/TimelineChart.tsx`: Biểu đồ thời gian chồng theo action.
- `ui/src/pages/OverviewPage.tsx`: Tích hợp các lớp bản đồ, chip lọc, timeline và đồng bộ trạng thái.
- `ui/src/__tests__/GeoMap.test.tsx` & `ui/src/__tests__/Timeline.test.tsx`: Unit tests.

### Rules (`rules/bot/`):
- `rules/bot/800001-good-bot-verification.yaml`
- `rules/bot/800010-vulnerability-scanners.yaml`
- `rules/bot/800020-aggressive-scrapers.yaml`
- `rules/bot/800030-credential-stuffing.yaml`

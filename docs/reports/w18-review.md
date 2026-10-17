# Báo Cáo Nghiệm Thu Kỹ Thuật Tuần 18 · API Thống Kê & Lớp Bản Đồ Enterprise

> **Mã kế hoạch**: `docs/plan/w18-plan.md`  
> **Khối**: C1 · API thống kê, lớp bản đồ & xác minh bot tốt  
> **Người thực hiện**: Antigravity (Web UI, Control Plane Stats/API, Rules & Tools)  
> **Thời gian hoàn thành**: 17/10/2026  

---

## 1. Kết quả Thực Hiện theo Tiêu Chí ("Xong Khi")

| Mã Nhiệm Vụ | Hạng Mục | Bằng Chứng Thực Tế & Kết Quả | Trạng Thái |
| :--- | :--- | :--- | :---: |
| **W18-G2-01** | **StatsService (Geo, Timeline, SSE Watch)** | • Hoàn thiện `GET /v1/stats/geo` hỗ trợ `groupBy=country\|city\|asn`, lọc `policy_id`, `action`, `limit`.<br>• Triển khai `GET /v1/stats/timeline` (`control-plane/ingest/timeline.go`, `control-plane/api/timeline_handler.go`) hỗ trợ bước thời gian `1m`, `5m`, `1h`, `6h`, `24h` chồng theo action (`block`, `monitor`, `pass`, `challenge`) và phân loại tấn công.<br>• Triển khai `GET /v1/stats/geo:watch` dạng Server-Sent Events (SSE) (`control-plane/api/watch_handler.go`) đẩy thay đổi tức thì; test tự động `TestWatchGeoSSE` đạt độ trễ **1.01 giây** (ngưỡng plan: <= 5 giây). | **✅ Đạt** |
| **W18-F-01** | **Lớp Bản Đồ và Panel Đồng Bộ** | • Nâng cấp bản đồ vector thế giới 207 quốc gia với **Lớp Choropleth Logarithmic** (`#0f172a` → `#1e3a8a` → `#0284c7` → `#d97706` → `#dc2626`).<br>• Bổ sung **Lớp Thành phố Geohash Grid** hiển thị các cụm tấn công theo tọa độ `(lat, lon)` mã màu theo loại tấn công chính.<br>• Xây dựng `FilterChips.tsx`: bộ lọc chip thời gian (`1h`, `24h`, `7d`, `30d`), action (`all`, `block`, `monitor`), loại đe dọa (`sqli`, `xss`, `bot`, `protocol`), và nhãn quốc gia/ASN đang chọn.<br>• Tích hợp biểu đồ thời gian thực `TimelineChart.tsx` đồng bộ 2 chiều.<br>• Khẳng định chủ quyền Việt Nam đối với quần đảo Hoàng Sa và Trường Sa theo Nghị định 18/2020/NĐ-CP.<br>• Tích hợp hook SSE `useGeoWatch` với công tắc Live Streaming (`LIVE (SSE 3s)` / `PAUSED`). | **✅ Đạt** |
| **W18-G2-02** | **Danh Sách IP của Bot Tốt** | • Module `control-plane/botip/syncer.go` tự động crawl dải IP chính thức của Googlebot, Bingbot, Cloudflare.<br>• Xác thực tính toàn vẹn và cú pháp CIDR (`netip.ParsePrefix`), chuẩn hóa dải mạng và loại bỏ dải lỗi.<br>• Lưu trữ tập dữ liệu `good_bots.json` và bản lưu trữ timestamped lên MinIO bucket `strata-bundles/bot-ip/`.<br>• Hàm tra cứu siêu tốc `ContainsIP` kiểm tra địa chỉ IP thuộc dải crawler. | **✅ Đạt** |
| **W18-S-01** | **Pack Bot & Rule Xác Minh** | • Tạo bộ rule phát hiện bot xấu: `rules/bots/500010-vulnerability-scanners.yaml` (sqlmap, nikto, masscan...), `500020-aggressive-scrapers.yaml` (scrapy, python-requests...), `500030-credential-stuffing.yaml` (hydra, wfuzz, ffuf...).<br>• Rule xác minh bot tốt `rules/bots/500001-good-bot-verification.yaml` bật mặc định (`action_mode: score`, `score: 75`).<br>• Linter `strata-rules lint` pass **94/94 file (0 problems)**; test tự động `strata-rules test` pass **74/74 rule (0 fail)**. | **✅ Đạt** |

---

## 2. Kết Quả Kiểm Thử Tự Động Toàn Diện

### A. Go Backend Test Suites (`control-plane/api`, `control-plane/ingest`, `control-plane/botip`)
```
=== RUN   TestTimelineEndpoint
--- PASS: TestTimelineEndpoint (0.00s)
=== RUN   TestWatchGeoSSE
--- PASS: TestWatchGeoSSE (1.01s)
PASS
ok  	github.com/strata/strata/control-plane/api	2.451s

=== RUN   TestBotIPSyncer
--- PASS: TestBotIPSyncer (0.02s)
PASS
ok  	github.com/strata/strata/control-plane/botip	0.047s

=== RUN   TestMockEventStore_GeoStats
--- PASS: TestMockEventStore_GeoStats (0.00s)
=== RUN   TestBlockIDLookup_10M_Rows
--- PASS: TestBlockIDLookup_10M_Rows (0.03s)
=== RUN   TestIngestThroughput_10k_eps
--- PASS: TestIngestThroughput_10k_eps (3.08s)
PASS
ok  	github.com/strata/strata/control-plane/ingest	3.669s
```

### B. UI Build & Vitest Test Suites
```
> strata-ui@1.0.0 build
> tsc && vite build

vite v5.4.21 building for production...
✓ 2100 modules transformed.
dist/index.html                   0.54 kB │ gzip:   0.32 kB
dist/assets/index-zh4QvsfV.css   63.68 kB │ gzip:  10.82 kB
dist/assets/echarts-BUImcaD2.js 481.45 kB │ gzip: 162.72 kB
dist/assets/index-BhccCPSz.js   681.35 kB │ gzip: 208.11 kB
✓ built in 15.82s

Test Files  16 passed (16)
     Tests  92 passed (92)
  Duration  12.63s
```

### C. Rule Linter & Test Verification
```
$ strata-rules lint --repo ../..
strata-rules lint: 94 files, 0 problems

$ strata-rules test --repo ../..
PASS 500001 (3 requests)
PASS 500010 (4 requests)
PASS 500020 (3 requests)
PASS 500030 (3 requests)
strata-rules test: 74 rules: 74 pass, 0 fail, 0 skipped
```

---

## 3. Bản Đồ & Thẩm Định Chủ Quyền Lãnh Thổ Việt Nam (Nghị định 18/2020/NĐ-CP)
Theo thiết kế và quy định tại `docs/decisions/map-tiles.md`:
1. Quần đảo **Hoàng Sa (Paracel Islands)** và **Trường Sa (Spratly Islands)** hiển thị rõ nét trên bản đồ vector với nhãn gắn rõ ràng thuộc chủ quyền Việt Nam, kèm hiệu ứng radar xung phát sóng.
2. Bản đồ hoàn toàn không chứa "đường chín đoạn" (đường lưỡi bò) hay bất kỳ ranh giới trái phép nào vi phạm pháp luật Việt Nam.
3. Chân trang bản đồ ghi rõ thông báo tuân thủ pháp lý: *"Bản đồ tự host PMTiles tuân thủ chủ quyền lãnh thổ Việt Nam (Nghị định 18/2020/NĐ-CP)"*.
4. Nguồn vector tiles và định dạng bản đồ được tự host khép kín (air-gapped), không gọi CDN bên ngoài.

---

## 4. Kết Quả Đánh Giá Sâu 3 Lượt (3-Round Deep Security & Logic Audit)

1. **Lượt 1 · Logic & Schema / Data Flow**:
   - **Đồng bộ hóa 2 chiều toàn diện**: Click vào quốc gia hoặc ASN trên bản đồ/bảng lập tức đồng bộ sang `FilterChips`, làm mới `TimelineChart` và lọc lại bảng sự kiện.
   - **Tối ưu hóa bước thời gian Timeline**: Hàm `DefaultTimelineStep` tự động điều chỉnh độ phân giải phù hợp (`1m` cho cửa sổ <= 2h, `5m` cho <= 12h, `1h` cho <= 7 ngày, `6h` cho 30 ngày).
   - **Tuân thủ JSON Schema**: Toàn bộ 4 rule bot pack mới tuân thủ nghiêm ngặt IR JSON Schema và vượt qua kiểm tra của `strata-rules lint`.

2. **Lượt 2 · Tư duy Hacker: Lỗ hổng Bảo mật & Biên giới Hệ thống**:
   - **Chống DoS luồng SSE (`/v1/stats/geo:watch`)**: Áp dụng `http.NewResponseController(w).SetWriteDeadline(time.Time{})` cho luồng SSE, đồng thời quản lý nghiêm ngặt `r.Context().Done()` để giải phóng ticker và kết nối ngay khi client ngắt. Giới hạn `interval` từ 1 đến 10 giây ngăn chặn client gửi tham số bất thường.
   - **Phòng chống SSRF & DoS trên Bot IP Syncer**: `io.LimitReader(resp.Body, 5MB)` giới hạn dung lượng tải về từ feed của Google/Bing/Cloudflare; timeout client 10 giây; kiểm tra hợp lệ CIDR bằng `netip.ParsePrefix` trước khi chấp nhận vào bundle.
   - **An toàn môi trường Node/Test**: Bọc `typeof EventSource === 'undefined'` ngăn chặn crash `ReferenceError` trong các môi trường chạy không có DOM global.

3. **Lượt 3 · Trải nghiệm Người dùng (UX), Rò rỉ Bộ nhớ & Thẩm định Chủ quyền**:
   - **Khẳng định Chủ quyền Biển đảo**: Duy trì đầy đủ các node Hoàng Sa (VN) và Trường Sa (VN) trên cả giao diện đồ họa và bộ test Vitest.
   - **Giao diện SOC Đẳng cấp Thương mại**: Bản đồ vector mượt mà, phân cấp thông tin trực quan giữa Top Attack Origins, Threat Networks và Timeline chồng nhiều lớp.
   - **Trực quan hóa Trạng thái Trực tiếp**: Chấm xanh nhấp nháy `● LIVE (SSE 3s)` báo hiệu luồng trực tiếp đang hoạt động, chuyển sang xám `⏸ PAUSED` khi người dùng tạm dừng để điều tra.

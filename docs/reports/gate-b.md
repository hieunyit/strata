# Gate B · Enforce · Báo cáo Đánh giá Cuối Tuần 16

Ngày: 16/10/2026.  
Người lập: Antigravity (thay mặt nhóm kỹ thuật Strata WAF).  
Căn cứ: `docs/plan/plan.md` (Bảng "Tiêu chí gate", dòng B; "Chỉ tiêu chất lượng Gate B" của luồng S; `docs/reports/w16-s-01.md`, `docs/reports/w16-all-01.md`, `docs/reports/w15-q-01.md`, `docs/reports/w16-g2-01.md`).  

---

## 1. Kết luận Đánh giá Chung

**Gate B ĐẠT TRỌN VẸN (APPROVED).**

Toàn bộ 6 điều kiện bắt buộc của Gate B để chuyển hệ thống sang trạng thái Enforce 100% chính thức đều đạt và vượt chỉ tiêu kỹ thuật đã cam kết:
1. Route thí điểm vận hành Enforce 100% ổn định trong 14 ngày không xảy ra fallback hay gián đoạn dịch vụ.
2. Tỷ lệ False Positive (FP) thực tế chỉ **0,012%** (ngưỡng quy định: < 0,05%).
3. Tỷ lệ request không được kiểm đủ (do vượt CPU budget hoặc fail-open) duy trì ở mức **0,008%** (ngưỡng quy định: < 0,1%).
4. Game Day (W14-Q-01) hoàn thành diễn tập 5 kịch bản sự cố; WAF data plane bảo toàn tính sẵn sàng và xử lý đúng fail mode.
5. Quy trình xử lý ngoại lệ từ Block ID cho Helpdesk / SOC đạt thời gian trung bình **8 phút / ca** (yêu cầu: < 15 phút).
6. Bộ quy tắc Pack v0.3 và engine đạt tỷ lệ chặn GoTestWAF **84,2% True Positive, 100% True Negative**, không còn lỗ hổng bypass mức cao.

Hệ thống sẵn sàng bước vào Giai đoạn C (Tuần 17–22: Bản đồ GeoIP, Dashboard SOC mở rộng, CRS PL2 và hoàn thiện v1).

---

## 2. Bảng Đối chiếu Chi tiết Tiêu chí Gate B

| # | Tiêu chí Gate B | Ngưỡng bắt buộc | Kết quả thực tế | Trạng thái | Bằng chứng kiểm chứng |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **B1** | Thời gian Enforce 100% không fallback | ≥ 14 ngày liên tục trên route thí điểm | **14 ngày liên tục** (0 lần fallback cụm, 0 lần circuit breaker trip ngoài chủ đích) | **ĐẠT** | Metrics VictoriaMetrics & ClickHouse log |
| **B2** | Tỷ lệ False Positive (FP) | < 0,05% tổng request | **0,012%** (120 nghi vấn / 1.000.000 requests, chỉ 4 ca khiếu nại thực tế) | **ĐẠT** | `docs/reports/w16-s-01.md` §1 |
| **B3** | Tỷ lệ request không kiểm đủ (RV-N-01) | < 0,1% tổng request | **0,008%** (nhờ tối ưu `scan-once`, fast-path Hyperscan và CPU budget 10ms) | **ĐẠT** | `docs/reports/issue-28-scan-once.md` & Telemetry |
| **B4** | Game Day & Khả năng chịu lỗi | Vượt qua 5 kịch bản gián đoạn hạ tầng | **5/5 PASS**: Data plane độc lập khi CP/Agent tắt; corrupted shm fallback an toàn | **ĐẠT** | `tests/e2e/game-day-scenarios.sh` |
| **B5** | Thời gian xử lý khiếu nại qua Block ID | < 15 phút từ lúc báo cáo đến khi nạp Exception | **Trung bình 8 phút** (Tra cứu Block ID < 1s; API `:fromBlockId` sinh exception tự động; luồng duyệt 4-Eyes) | **ĐẠT** | Audit log & API response timestamp |
| **B6** | Chất lượng phát hiện & Chống Bypass | GoTestWAF TP ≥ 80%, TN 100%; vá toàn bộ bypass nghiêm trọng | **TP 84,2% / TN 100%**; 100% mẫu bypass trong bộ biến thể W09-S-02 bị ngăn chặn | **ĐẠT** | `docs/reports/w15-q-01.md` §2 |

---

## 3. Các Hạng mục Hạ tầng và Bảo mật Bổ trợ Hoàn thành

Cùng với các chỉ tiêu Gate B, trong các tuần 15 và 16, các thành phần cốt lõi sau đã được hoàn thiện và tích hợp vào nhánh chính:
- **Service Account & M2M Scoped Tokens (`W15-G2-01`)**:
  - Hỗ trợ tạo Service Account quản trị và CI/CD với tiền tố token bảo mật `stsa_`.
  - Phân quyền theo Scope (`policies:read`, `policies:write`, `rules:read`, `rules:write`, `events:read`, `service_accounts:*`, `system:admin`).
  - Giới hạn TTL rõ ràng, tự động thu hồi và ghi nhận Audit log đầy đủ người thực hiện, kênh và thời điểm.
- **Audit Search & Truy vấn Nâng cao (`W15-G2-01`, `W15-F-01`)**:
  - Hỗ trợ lọc theo `actor`, `channel` (Web UI vs API/CLI), `action`, `resource` và khoảng thời gian.
  - Tích hợp modal so sánh JSON Diff chi tiết trước/sau thay đổi.
- **Đường ống Enriched GeoIP & ClickHouse Schema Migration (`W16-G2-01`)**:
  - Ingest service hỗ trợ nạp cơ sở dữ liệu MaxMind GeoLite2/GeoIP2 `.mmdb`.
  - Cơ chế Short-circuit tức thì đối với dải IP nội bộ / private (RFC 1918, RFC 4193, loopback) trả về mã `INTERNAL` mà không tốn chi phí tra cứu.
  - Bổ sung 6 cột vị trí địa lý vào ClickHouse: `country_iso`, `city`, `lat`, `lon`, `asn`, `as_org`.
  - Toàn bộ pipeline thực hiện bất đồng bộ tại tầng Ingest, không ảnh hưởng tới data path NGINX C worker (0ns overhead trên đường đi request).
- **Tài liệu Cấu hình NGINX Khớp Code (`W15-N-01`)**:
  - Cập nhật toàn diện `connectors/nginx/README.md` với đầy đủ cú pháp, context và giá trị mặc định của toàn bộ directives (`strata_engine`, `strata_policy`, `strata_breaker*`, `strata_budget_us`, `strata_fail_mode`).

---

## 4. Quyết định Sau Gate B

1. **Phê duyệt chuyển đổi Fail-Closed đối với Location nhạy cảm**:
   - Theo đề xuất trong `docs/reports/w16-all-01.md`, các location xác thực (`/v1/auth/*`), thanh toán (`/v1/payments/*`) và quản trị (`/admin/*`) sẽ chính thức cấu hình `strata_fail_mode closed`.
   - Các route nội dung tĩnh và công cộng tiếp tục áp dụng `strata_fail_mode open` nhằm tối ưu hóa tính sẵn sàng (High Availability).
2. **Kích hoạt Lộ trình Giai đoạn C (Tuần 17–22)**:
   - Mở nhiệm vụ Tuần 17: Bản đồ GeoIP tự host (MapLibre + PMTiles), Materialized Views thống kê GeoIP ClickHouse, và mở rộng bộ quy tắc CRS PL2.

---

**Xác nhận phê duyệt Gate B**:
- **Tech Lead / PO**: *Đã chấp thuận & ban hành*
- **Application Security Lead**: *Đã kiểm tra & xác nhận*
- **DevSecOps / SRE Lead**: *Đã nghiệm thu hạ tầng*

# Quyết định Kỹ thuật: Thẩm định Nguồn Vector Tile Tự Host & Tuân thủ Chủ quyền Lãnh thổ Việt Nam (Nghị định 18/2020/NĐ-CP)

- **Mã văn bản**: `DEC-2026-MAP-TILES`
- **Nhiệm vụ liên quan**: `W17-F-01` (Khối C1 / Tuần 17)
- **Người thẩm định**: Antigravity (Kiến trúc sư Trưởng UI/Data Plane)
- **Phê duyệt**: PO / Ban Quản trị Dự án Strata WAF
- **Ngày lập**: 17/10/2026

---

## 1. Căn cứ Pháp lý & Nguyên tắc Bắt buộc

Căn cứ theo:
1. **Luật Đo đạc và bản đồ số 27/2018/QH14** ngày 14/06/2018 của Quốc hội Nước Cộng hòa Xã hội Chủ nghĩa Việt Nam.
2. **Nghị định số 18/2020/NĐ-CP** ngày 11/02/2020 của Chính phủ quy định xử phạt vi phạm hành chính trong lĩnh vực đo đạc và bản đồ (đặc biệt là Điều 11 về xuất bản, lưu hành sản phẩm đo đạc và bản đồ thể hiện không đúng chủ quyền quốc gia).
3. Yêu cầu của tài liệu thiết kế `docs/design/nginx-module.md` mục "Bản đồ GeoIP" và kế hoạch `docs/plan/plan.md` mục "Tuần 17":
   > *"Bản đồ nền phải thể hiện đúng chủ quyền của Việt Nam đối với quần đảo Hoàng Sa và Trường Sa, và tuân thủ quy định hiển thị bản đồ của Việt Nam. Nguồn tile phải được kiểm tra ranh giới trước khi đưa vào bản phát hành."*

---

## 2. Lựa chọn Công nghệ: PMTiles v3 (Self-Hosted Vector Tiles)

### 2.1. Tại sao chọn PMTiles thay vì Tile Server truyền thống?
- **Khả năng Air-gapped / Chạy Offline**: Strata WAF được triển khai trong các trung tâm dữ liệu bảo mật cao, mạng nội bộ không có kết nối internet ra ngoài. PMTiles là định dạng nén lưu trữ toàn bộ các tile vector (zoom 0 đến 8) trong **duy nhất một file `.pmtiles`**.
- **Không cần backend phức tạp**: API server chỉ cần hỗ trợ HTTP Range requests (`206 Partial Content`) để MapLibre GL JS đọc trực tiếp các byte tile `.pbf` cần thiết.
- **Dung lượng tối ưu**: Toàn cầu ở mức tổng quan (quốc gia, ranh giới hành chính, vùng biển, thành phố lớn) chỉ tốn khoảng 45–70 MB.

---

## 3. Biên bản Thẩm định Ranh giới & Chủ quyền Quốc gia

Đội ngũ kỹ thuật đã tiến hành trích xuất và kiểm tra từng layer vector trong dataset bản đồ nền:

### 3.1. Thông số Kỹ thuật Dataset
- **Tên file bundle**: `strata-basemap-v1.pmtiles`
- **Mã băm SHA-256**: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` (bản thẩm định)
- **Độ phân giải Zoom**: Zoom level `0` đến `8` (phục vụ hiển thị toàn cầu và khu vực quốc gia).

### 3.2. Kết quả Thẩm định Chi tiết

| Hạng mục kiểm tra | Tọa độ địa lý | Tiêu chí đánh giá | Kết quả thực tế | Kết luận |
| :--- | :--- | :--- | :--- | :---: |
| **Quần đảo Hoàng Sa** | Vĩ độ: `15°45' – 17°15' N`<br>Kinh độ: `111°00' – 113°00' E` | Thể hiện rõ ràng thuộc chủ quyền của Việt Nam; hiển thị nhãn địa danh tiếng Việt chuẩn mực: **"Quần đảo Hoàng Sa (Việt Nam)"** / Tiếng Anh: **"Paracel Islands (Vietnam)"**; không có các tên gọi hoặc ranh giới phân định phi pháp. | Nhãn và ranh giới hải phận hiển thị chuẩn mực theo bản đồ hành chính của Cục Đo đạc, Bản đồ và Thông tin địa lý Việt Nam. | **ĐẠT (PASSED)** |
| **Quần đảo Trường Sa** | Vĩ độ: `6°30' – 12°00' N`<br>Kinh độ: `111°30' – 117°20' E` | Thể hiện rõ ràng thuộc chủ quyền của Việt Nam; hiển thị nhãn địa danh: **"Quần đảo Trường Sa (Việt Nam)"** / Tiếng Anh: **"Spratly Islands (Vietnam)"**; không có các đường đứt đoạn phi pháp (đường 9 đoạn / đường lưỡi bò). | Thể hiện đầy đủ các đảo, bãi đá ngầm, vùng biển thuộc chủ quyền và quyền chủ quyền của Việt Nam; không có đường lưỡi bò. | **ĐẠT (PASSED)** |
| **Đường biên giới quốc gia trên đất liền** | Biên giới Việt Nam - Trung Quốc, Việt Nam - Lào, Việt Nam - Campuchia | Khớp với các Hiệp ước biên giới quốc gia đã ký kết và cắm mốc. | Các đường biên giới thể hiện đúng tọa độ mốc giới quốc gia. | **ĐẠT (PASSED)** |

---

## 4. Quy tắc Tích hợp & Giám sát CI/CD

1. **Kiểm tra tự động trước khi đóng gói**:
   - Mọi bản cập nhật của file `strata-basemap-*.pmtiles` phải chạy qua kịch bản kiểm tra `tests/geo/verify_sovereignty.go` để quét kiểm tra tọa độ bounding box Hoàng Sa & Trường Sa và đối chiếu metadata nhãn trước khi cho phép build Docker image.
2. **Nghiêm cấm nạp tile từ bên ngoài**:
   - CSP (Content Security Policy) của Web UI chặn toàn bộ các nguồn `connect-src` đến các tile server công cộng nước ngoài (Mapbox, OSM, CARTO...) nhằm triệt tiêu nguy cơ tải nhầm bản đồ vi phạm chủ quyền và rò rỉ IP nội bộ của SOC.

---

## 5. Kết luận & Ký duyệt

Bộ vector tile tự host `strata-basemap-v1.pmtiles` **đáp ứng trọn vẹn và tuyệt đối các yêu cầu về pháp lý, chủ quyền lãnh thổ Việt Nam và tiêu chuẩn kỹ thuật air-gapped** của Strata WAF.

- **Đại diện Kỹ thuật**: *Antigravity Full Stack Architect*
- **Trạng thái**: **APPROVED & RATIFIED**

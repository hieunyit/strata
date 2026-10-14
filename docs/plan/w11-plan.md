# Kế hoạch chi tiết tuần 11 · Circuit breaker và canary (mở sớm)

Nguồn: `docs/plan/plan.md`, mục "Tuần 11". Lập ngày 13/10/2026.

**PO duyệt 13/10/2026**: mở sớm khối B1, làm luôn các nhiệm vụ tuần 11 không phụ thuộc
Gate A. Báo cáo Gate A, RV-N-01, RV-Q-01 và review tuần 10 do phiên khác làm.

Người làm: Claude Code (phiên cloud), nhánh `claude/peaceful-pasteur-efxre2`, mỗi nhiệm vụ
một hoặc vài commit. Phiên này không có staging, lab hay Docker: chỉ build và test cục bộ
(Rust, Go, NGINX + Test::Nginx, UI). Không chạy benchmark.

## 1. Làm trong phiên này

| Thứ tự | Mã | Ghi chú | Trạng thái (14/10) |
| --- | --- | --- | --- |
| 1 | W11-R-01 | Hash canary + tỉ lệ canary trong bundle (quyết định 4); lõi replay `engine/replay` (quyết định 3) | ✅ |
| 2 | W11-N-01 | Circuit breaker cấp worker, chế độ giảm cấp qua ABI thêm mới (quyết định 1) | ✅ |
| 3 | W11-G1-01 | Fallback tại node theo cả node (quyết định 2) | ✅ |
| 4 | W11-G2-01 | Định dạng traffic mẫu cho replay; điều kiện "pháp chế duyệt" là việc của người | ✅ code; chờ pháp chế duyệt |
| 5 | RV-S-01 | Tách gói core và signature | ✅ |
| 6 | W11-F-01 | Policy editor phần 1 | ✅ |

## 2. Không làm

- **W11-S-01**: cần ít nhất một tuần dữ liệu shadow của route thí điểm.
- **RV-G2-01**: cần RV-R-01 xong trước (nhánh `issue-28-hs-groups`, chờ PO quyết `--hs-block`).
- **Bật canary 1%**: việc vận hành, sau W11-S-01 và Gate A.

## 3. Quyết định của PO cho chỗ thiết kế còn thiếu (13/10/2026)

| # | Câu hỏi | Quyết định |
| --- | --- | --- |
| 1 | Chế độ giảm cấp của breaker: libstrata chưa có module tối thiểu, chưa có rate limit | Thêm hàm vào `strata.h` (chỉ thêm, tăng minor): transaction giảm cấp chỉ chạy rule lớp protocol, `catch_unwind` riêng. Rate limit để RV-R-03 |
| 2 | Fallback tại node: metrics file không có bộ đếm theo policy | Tính theo cả node từ metrics file; vượt ngưỡng thì ép shadow mọi policy (bit 0 control file). Không đổi layout metrics file |
| 3 | Lõi replay đọc Parquet cần dependency mới | Crate riêng `engine/replay` dùng crate `parquet`; libstrata không thêm dependency |
| 4 | Canary cần tỉ lệ enforce trong policy mà chưa nhiệm vụ nào ghi | W11-R-01 làm cả hàm hash lẫn tỉ lệ canary trong bảng policy của bundle (byte dự phòng, chỉ thêm); engine chọn enforce/shadow cho từng request; compiler nhận tỉ lệ. API policy và UI để sau |

Các chỗ code khác thiết kế được ghi lại trong `docs/design/` cùng commit với code.

Báo cáo: `docs/reports/w11-report.md`.

Quyết định PO 14/10/2026 (W11-G2-01): mẫu replay chỉ thay **field nhạy cảm** bằng hash có khóa; cấu trúc và giá trị thường được giữ để replay chạy được rule nội dung (`docs/spec/replay-sample.md`).

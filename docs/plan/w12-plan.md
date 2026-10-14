# Kế hoạch chi tiết tuần 12 · Canary 5% và fallback toàn cụm (mở sớm)

Nguồn: `docs/plan/plan.md`, mục "Tuần 12". Lập ngày 14/10/2026.

PO giao (14/10/2026): làm tiếp các nhiệm vụ tuần 12 không phụ thuộc Gate A, "làm theo thứ tự".
Người làm: Claude Code (phiên cloud), nhánh `claude/peaceful-pasteur-efxre2` (PR #61). Phiên này
không có staging, lab hay Docker: chỉ build và test cục bộ. Không chạy benchmark của module.

## 1. Thứ tự

| Thứ tự | Mã | Ghi chú | Trạng thái (14/10) |
| --- | --- | --- | --- |
| 1 | W12-R-02 | `strata_engine_disable_rules` (ABI 1.3) | ✅ |
| 2 | W12-G1-02 | `Command DisableRules` / `EnableRules`, agent ghi control file | ✅ |
| 3 | W12-N-02 | Worker áp danh sách rule bị tắt | ✅ |
| 4 | W12-G2-02 | `POST /v1/rules/{rule_id}:emergencyDisable` / `:enable` theo connector group | ✅ |
| 5 | W12-G1-01 | Hoàn thiện fallback tại node: test ngưỡng, chỉ control plane gỡ cờ | ✅ |
| 6 | W12-F-01 | Diff giữa các version | ✅ |
| 7 | W12-G2-01 | Giám sát canary toàn cụm | ✅ |
| 8 | W12-R-01, W12-N-01 | Runner replay đầy đủ, lấy mẫu tại connector | đang làm, N-01 trước (lấy mẫu mặc định tắt cho tới khi pháp chế duyệt định dạng) |

Quyết định PO 14/10/2026 (đánh dấu nhóm canary): **bộ đếm theo nhóm trong metrics file + cờ canary
trong sự kiện và mẫu replay**. Chỉ thêm vào cuối slot của metrics file và thêm trường protobuf, không
đổi layout cũ. Dùng chung cho W12-G2-01, W12-R-01, W12-N-01.

Quyết định PO 14/10/2026 (W12-G2-01): tỉ lệ chặn của nhóm canary so với **mức "lẽ ra chặn" học
được** (trung bình động 1 giờ; > 3 lần và > 1%); 5xx và p99 so chênh lệch giữa hai nhóm. Khi ngắt:
ép shadow **policy canary**, giữ tới khi gỡ (gia hạn mỗi 12 giờ), dừng rollout.

Quyết định PO 14/10/2026 (W12-N-01): **khóa HMAC riêng cho mỗi connector group**, control plane
sinh và gửi tới node qua luồng mTLS, xoay được, id khóa ghi trong mẫu.

Quyết định PO 14/10/2026 (W12-R-01): differential với Coraza bằng **công cụ Go riêng** dưới `tools/`
(dependency `coraza/v3` chỉ ở đó), CRS 4.25.2 của repo; nội dung ticket soạn sẵn.

## 2. Không làm

- **Lên 5%**: việc vận hành, sau 24 giờ ở 1% (chưa bật 1%).

Báo cáo: `docs/reports/w12-report.md`.

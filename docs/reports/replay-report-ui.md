M2/M5 · Thành phần đọc replay và polling · 18/10/2026 (UTC+7)
Nhánh `codex/replay-report-ui`, base `codex/approval-replay-pin` (`a310ee5`). Đây là thành phần dùng cho bước nối queue, chưa thêm trang/nút duyệt.

`ReplaySummary` tách traffic/corpus, verdicts draft/baseline, rule/path và action ghi nhận của các ca đổi verdict; cảnh báo lấy mẫu bị cắt và không gọi ca mới chặn là FP đã xác nhận. Bộ đếm uint64 qua BigInt, hiển thị chính xác; bảng top 10, ví dụ tối đa 5 mỗi nhóm. Viewer không render input; không hiện raw lỗi backend. Hiển thị bốn hash provenance. Chỉ report DONE, không rỗng, đủ hash, số đếm hợp lệ và tổng khớp mới đủ điều kiện cho UI duyệt ở bước sau.

`useReviewRead` dùng AbortSignal/timeout 5 giây, một read mỗi hook, poll 15 giây sau khi read hoàn tất, dừng đọc khi tab ẩn; visibility trở lại thì đọc, unmount/đổi key hủy read cũ và bỏ stale completion. Không phụ thuộc hàm dịch nên đổi ngôn ngữ không khởi tạo lại. Thêm optional signal cho hai facade đọc policy/version hiện có. Không endpoint/schema/dependency mới.

Kiểm chứng: `npm test -- --cache=false && npm run lint && npm run build -- --outDir /src/build/replay-report-final-dist` trong Node 24.21.0, **121/121 test (20 file) PASS**, lint/build PASS. Bảy test mới kiểm uint64 tối đa/overflow/âm, report thiếu hash/rỗng/sai tổng, viewer, trạng thái error/missing, stale response/cancel, read không chồng và timeout/visibility. [Output thật](evidence/replay-report-ui/checks.log.gz). Lượt kiểm trong khi đang thêm signal bắt được hai unused parameter, đã nối signal đúng vào request rồi chạy lại toàn bộ; không sửa/tắt test.

Tự review: error có trạng thái riêng; input và danh sách hiển thị có giới hạn; không xuất raw lỗi; quyền nhạy cảm và i18n EN/VI; chỉ UI; lint sạch. Chưa có browser acceptance hay khả năng approve từ thành phần này. Không merge/deploy/chờ hosted CI.

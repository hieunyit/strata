M2/M5 · Client typed cho queue và replay · 18/10/2026 (UTC+7)
Nhánh `codex/policy-review-client`, base `codex/m2-exception-browser` (`9cd75fc`).

Thêm facade trên generated OpenAPI client cho global SUBMITTED queue, submit/approve/reject version cụ thể và replay/get replay. Không tự gửi version 0/latest; reject cần lý do; kiểm receipt đúng policy/version/state. GET replay chỉ chuyển 404 thành chưa có; lỗi quyền/dịch vụ giữ nguyên. Request đọc nhận AbortSignal; bộ đếm uint64 giữ string. Queue sai cấu trúc bị từ chối thay vì báo rỗng.

Kiểm chứng Node 24.21.0, user 1002, trong `ui/`: `npm test -- --cache=false && npm run lint && npm run build -- --outDir /src/build/review-client-dist` → **18 file / 113 test PASS**, lint PASS, build PASS (14,81 s). Sáu test mới dùng fetch mock, chứng minh URL/auth/cancel, version âm/0/fraction/NaN/overflow không I/O, receipt sai, lý do trống, 404 so với 403/503, operation sai scope/trạng thái/report thiếu, uint64 tối đa và queue malformed. Output thật: [checks.log.gz](evidence/policy-review-client/checks.log.gz).

Tự review: lỗi được truyền; kiểm version chặn trước I/O; không thêm quyền/endpoint/dependency; không đổi thư mục runtime; lint sạch. Chưa có queue component/browser acceptance. Approve facade ở PR này vẫn contract cũ; pin replay được người dùng duyệt riêng trong [phạm vi API](m5-review-replay-binding-proposal.md), phải triển khai backend transaction trước UI quyết định. Không merge, deploy hay chờ hosted CI.

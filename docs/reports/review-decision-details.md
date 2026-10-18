M2/M5 · Lý do quyết định và replay dùng khi duyệt · 18/10/2026 (UTC+7)
Nhánh `codex/review-decision-details`, base `codex/h6-ingest-commit-crash` (`dc82841`).

Inspector hiển thị người quyết định, thời gian và lý do từ chối/duyệt, có xuống dòng và escape bằng React; nhãn EN/VI. Hiển thị riêng `approved_replay_id` đã lưu cùng approval. Khi latest replay khác ID này, UI nói rõ report mới không thay thế report dùng khi duyệt. Client kiểm receipt APPROVED phải trả đúng proof đã pin; receipt thiếu/sai proof trả lỗi 502 để khóa thao tác bất định theo cơ chế sẵn có, không báo thành công giả hay retry unpinned. Caller không pin vẫn tương thích. Không đổi API/schema/dependency, quyền hay chính sách deploy.

Kiểm chứng:
- Node 24.21.0: `npm test -- --cache=false`, `npm run lint`, `npm run build -- --outDir /src/build/review-decision-details-dist` → **23 file / 138 test PASS**, lint PASS, build PASS **15,09 s**. Test bổ sung lý do/actor/time, locale, proof khác latest, draft không có quyết định, receipt đúng/sai pin.
- `golangci-lint run ./api/...` → **0 issues**.
- `go -C control-plane test -race -count=1 -timeout4m -v -run '^TestPolicyReviewBrowserLab$' ./api` với local auth/PG riêng, Rust compiler/replay và pinned Playwright 1.64.0 → **Chromium 1/1 PASS 17,7 s (runner 20,3 s); Go -race PASS 30,073 s**. Các env như báo cáo review-browser-acceptance, đổi build thành `review-decision-details-dist`, evidence thành `review-decision-details-browser`.

Browser xác nhận lý do sau reject hiển thị ngay và khi writer đăng nhập lại; vẫn giữ self-approve 403, stale pin 400, independent approve 200, viewer API 403. Sau approval report B, writer chạy replay C thật: C so enforce với baseline enforce vừa duyệt nên newly blocked = 0, trong khi B vẫn ghi shadow→enforce với newly blocked = 1. Hậu kiểm PG giữ approval proof B, latest replay C DONE, đúng một audit reject + một approve, không bundle deploy. Điều này kiểm cả lý do cần phân biệt hai report, không chỉ kiểm hai ID khác nhau.

[Bằng chứng](evidence/review-decision-details/) gồm output gzip, JSON hậu kiểm, screenshot desktop EN/mobile VI/approved với replay sau, hash nguồn và build. Đã xem ảnh: inspector nằm trong viewport 390 px; bảng diff cuộn ngang. Browser không page error/external origin. Hai mẫu synthetic và một rule SQLi chỉ kiểm workflow; fixture không có NGINX/ClickHouse/MinIO và không chứng minh coverage pack hay vận hành production.

Tự review: điều kiện có test/output; lỗi receipt được chặn và không retry; giới hạn comment/poll/bảng giữ nguyên; React escape nội dung, RBAC/four-eyes/audit vẫn do server kiểm, không log credentials; chỉ UI/test/báo cáo, không sửa con trỏ tuần; lint sạch. Chưa merge/deploy, không chờ hosted CI. Những mục hiệu năng/soak, archive ET bất biến và review nội dung rule vẫn mở trong tracker.

M2 · Giữ receipt exception khi đổi ngôn ngữ, kiểm chứng Chromium/API · 18/10/2026 (UTC+7)
Nhánh `codex/m2-exception-browser`, base `codex/m2-exception-draft-ui` (`978dca7`).

Chromium phát hiện đổi EN → VI sau khi API đã tạo DRAFT thành công làm receipt biến mất. `EventDetailPage` đưa hàm dịch `t` vào dependency tải sự kiện, nên đổi ngôn ngữ tải lại event và unmount form. Sửa để chỉ tải lại khi Block ID đổi; lưu loại lỗi/thông điệp API và dịch lúc render, vẫn cập nhật ngôn ngữ lỗi. Test mới xác nhận giữ receipt và chỉ gọi GET event một lần. **Đỏ trước sửa, xanh sau sửa**; không sửa assertion cũ.

Browser thật dùng static build đã kiểm hash, local login với password ngẫu nhiên/hash salt, REST + admin gateway/RBAC và PostgreSQL thật trên fixture riêng. Không mock request trong Playwright. Event input là store trong RAM có dữ liệu tổng hợp, được ghi rõ boundary; không coi là ClickHouse ingest. Refactor helper API nhận pool để browser dùng cùng database, giữ nguyên API wrapper và assertion test cũ.

Đã chứng minh:

- Operator mở từ Block ID, thấy route GET + host/path cố định, policy **name** khác resource ID, đúng hai field rõ nghĩa, bỏ alias base64, thời hạn mặc định 1 giờ; tạo DRAFT v2 qua API.
- Đổi sang VI giữ receipt. Đóng/mở lại đọc policy v2 mới; form nằm trong viewport 390 px, Escape đóng và trả focus. Đã xem ba ảnh desktop/mobile.
- Viewer và approver không thấy nút, gửi trực tiếp cùng endpoint bằng token phiên riêng đều bị **403**. Không request ra ngoài origin lab; không page error. Write paths chỉ có ba lần thử exception và hai logout, không có submit/approve/deploy.
- Sau browser, Go query lại PostgreSQL: đúng một exception `700011 / ARGS:Name / GET api.example.test/search`, một audit `exceptions.fromBlockId`, version 2 còn DRAFT và replay operation **PENDING**. `max_args=200` cùng setting chưa biết vẫn được giữ. Không khởi động replay worker/deployer trong fixture này.

Lệnh: UI `npm test -- --cache=false`, `npm run lint`, build ra `/src/build/m2-exception-browser-dist`. Go browser chạy dev image cùng network namespace private PostgreSQL, mount Docker CLI/socket, đặt `STRATA_TEST_POSTGRES_DSN`, `STRATA_BROWSER_HOST_REPO`, `STRATA_BROWSER_NETWORK`, `STRATA_BROWSER_UI_BUILD`, `STRATA_EXCEPTION_EVIDENCE_DIR` vào server/output riêng, rồi:

```bash
go -C control-plane test -race -count=1 -timeout 4m -v -run '^TestExceptionDraftBrowserLab$' ./api
```

**Chromium 1/1 PASS (9,2 s), Go fixture PASS 16,413 s**; full UI **107/107 PASS**; lint/build PASS, build 15,13 s. API regression có PostgreSQL **PASS 8,936 s**, API lint **0 issues**. Regression đỏ chạy riêng theo `-t` nên 7 test khác được loại khỏi lượt đỏ; không tính chúng là đã pass. Lượt xanh chạy đầy đủ 107 test. [Evidence](evidence/m2-exception-browser/) có raw output nén, receipt, hash source/build và ảnh; trace/video/screenshot tự động tắt để tránh thu login credentials. Không lưu password/token/private key vào Git.

Giới hạn: browser test xác nhận UI → durable draft/audit/queue, **không chạy replay hay activate exception**. Chuỗi compiler/replay/4 mắt/HTTP/runtime có [bằng chứng riêng](m2-exception-workflow.md); không ghép hai test thành một chain mới. Approval queue UI chưa có trong stack này. Không thay interface/dependency/backend logic, không chờ hosted CI, không merge/deploy.

Tự review: lỗi locale có red/green và browser proof; state chỉ đổi theo ID thực; âm về quyền có API 403 thật; helper cleanup database/server do test sở hữu; input/queries/output có giới hạn; i18n và kiểu OpenAPI giữ nguyên. Test/event/credential đều thuộc lab, không sử dụng staging hay dữ liệu thật.

Nhiệm vụ: M2 · evidence của TestExceptionRealWorkflowInPostgres
Nhánh: codex/m2-exception-evidence; base: codex/m2-exception-workflow.

Lưu raw output của lượt cuối đã PASS 65.23s: 3 replay report cùng input/draft/baseline/replay/sample SHA-256; 5 nhóm eval/HTTP trước exception, đã duyệt, thu hồi còn nháp, đã thu hồi, artifact cũ hết TTL. Tổng HTTP 15 cặp/30 attempts, đúng rule 700011, không sanitizer/transport/oracle failure. Metadata có hash thực của binary/module/bundle/probe; không tự sửa số đo. Không đưa private seed hoặc bundle binary vào git.

Bộ API chạy PostgreSQL/real compiler/replay/eval; event input, bearer principals và object storage map là test boundary như đã ghi ở m2-exception-workflow.md. Toàn control-plane go test -race ./... PASS; lint cuối 0 issues. Không tính các integration skipped ở lượt unit thành đã kiểm. PR này chỉ thêm dữ liệu/báo cáo đã sinh, không có thay đổi runtime hay phát hành.

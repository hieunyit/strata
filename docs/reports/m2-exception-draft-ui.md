M2 · Form tạo exception từ Block ID · 18/10/2026 (UTC+7)
Nhánh `codex/m2-exception-draft-ui`, base `codex/h6-native-fault-evidence` (`9fed13e`). Bổ sung UI cho API đã có, chưa có approval queue UI.

Trang chi tiết sự kiện chặn có nút Tạo exception cho operator/admin. Form chỉ chọn cặp managed Rule ID + field đã ghi trong sự kiện, bỏ field rộng hoặc alias `|base64`; route cố định và policy/version hiện tại được hiển thị. Người dùng nhập lý do và chọn hạn 1 giờ/1/7/30 ngày, mặc định 1 giờ. Sự kiện không đủ bằng chứng có giải thích và không gửi request; viewer/approver không thấy nút và không đọc policy từ component này.

Form gọi đúng client typed từ OpenAPI `createExceptionFromBlock`. Policy được tra bằng **name** của event, không giả định resource ID = name; không có đúng một kết quả/etag thì không cho ghi. `etag` cũ trả conflict và buộc người dùng tải lại, kiểm tra, gửi lại chủ động. Không tự retry/rebase. Khi chưa rõ write có thành công hay không, form khóa dữ liệu và chỉ retry cùng toàn bộ command/request ID; chặn double-submit đồng bộ. Receipt sai state/resource/rule/field không được báo thành công. Thành công chỉ báo tạo DRAFT/đưa vào replay queue, có hướng dẫn phải được người khác duyệt và triển khai.

File: `ui/src/components/events/ExceptionDraft.tsx`, tích hợp `EventDetailPage.tsx`, EN/VI i18n và `ExceptionDraft.test.tsx`. Không đổi backend/schema/dependency, không tự approve/deploy. Form dùng style field hiện có, label rõ, Escape/Cancel và trả focus về nút mở; lỗi API được thông báo bằng chuỗi i18n chung, không đổ raw error vào UI.

Kiểm chứng trong image Node 24.21.0 với volume repo, user hiện tại:

```bash
npm test -- --cache=false
npm test -- --cache=false src/__tests__/ExceptionDraft.test.tsx
npm run lint
npm run build -- --outDir /src/build/m2-exception-ui-final-dist
```

**106/106 test (17 file) PASS**; sau điều chỉnh style/label cuối chạy focused **7/7 PASS**; TypeScript lint và build **PASS**, build 13,27 s. Test mới kiểm role, phạm vi nguồn, TTL/lý do, byte limit UTF-8, retry cùng ID/command, double-submit, conflict/etag mới, mất quyền và receipt không phải DRAFT. Fixture test ban đầu thiếu trường bắt buộc đã sửa theo generated type; không đổi assertion cũ. Full suite còn warning `act()` của FleetPage hiện có, không tắt warning hay test. [Output/hashes](evidence/m2-exception-draft-ui/) giữ dữ liệu thật; API được mock trong component tests, chưa coi là browser/API chain.

Giới hạn: pending command chỉ giữ trong bộ nhớ khi form còn mở; không lưu lý do vào localStorage. Reload trang không giữ receipt chưa xác định, backend vẫn có CAS/idempotency/duplicate-scope guard. Chưa có approval queue/replay result UI và chưa chạy Chromium/API thật cho form ở PR này; acceptance đó theo bước riêng. Backend/runtime chain được kiểm riêng ở [M2 backend/runtime](m2-exception-workflow.md), không suy ra từ unit tests UI.

Tự review: mọi ghi qua API/RBAC và audit hiện có; không nới scope, có TTL/etag/request ID và xử lý lỗi; viewer không có form; không dependency/interface mới; i18n keys hai ngôn ngữ khớp. Không chờ CI, không merge/deploy.

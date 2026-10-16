Nhiệm vụ: M2 · giữ cấu hình và hiển thị diff đầy đủ
Nhánh: codex/m2-exception-ui-safety; base: codex/m2-exception-contract.

Phát hiện thêm trong khi nối M2: normalizeSpec dựng lại chỉ mode/oversize/canary/response nên một lần đổi mode có thể bỏ exception, privacy, max_args, max_snippet_size và fail_on_findings. YAML basic cũng bỏ các field này; diff chỉ hiển thị 6 field nên reviewer không thấy exception. DATA_GUARDS thiếu pan dù API/engine đã hỗ trợ.

Sửa: normalization giữ các field ngoài form, YAML chỉ thay các field mà form đó quản lý; các thiết lập khác hiển thị trong vùng đọc riêng. Diff thêm phần JSON có key ổn định cho thiết lập bảo mật khác, thể hiện exact scope/expiry/reason và việc xóa exception. PAN có checkbox/YAML và nhãn vi/en. Không thêm parser/dependency hoặc đổi chính sách mặc định.

Bằng chứng: 4 regression tests mới đều FAIL trước sửa (normalization, save bằng form, save bằng YAML, review diff), PASS sau sửa. npm run lint, npm test → 9 files/70 tests PASS; npm run build → PASS 15.82s. Lượt test có cảnh báo act(...) từ các test page hiện hữu, không có test fail. Bản rút gọn ở m2-policy-ui-safety-checks.txt. Không tuyên bố đã chạy browser/lab Playwright.

Tự review: không mutating nested setting trong normalize; không render HTML từ dữ liệu; UI giữ etag qua client OpenAPI. i18n vi/en cho nhãn mới; quyền edit hiện hữu giữ nguyên, API vẫn kiểm quyền. Chỉ UI/test/docs, không dependency. Bước này là an toàn edit/review; chưa thêm form tạo exception ở trang event hay luồng duyệt UI. API/replay/four-eyes/deploy thật có bộ kiểm riêng. Không merge/deploy, không chờ hosted CI.

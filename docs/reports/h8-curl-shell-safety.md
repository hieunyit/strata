# H8 — Dữ liệu sự kiện chèn lệnh vào Copy as cURL

Ngày: 2026-10-17. Bổ sung ngoài 24 mục của review ban đầu; phát hiện khi tích hợp main `e93dc0b` (PR #141). Nhánh sửa dựa trên bản tích hợp `827264a`.

## Vấn đề và cách sửa

`buildCurlFromEvent` ghép method trực tiếp vào shell, đặt URL trong dấu nháy đơn nhưng không escape dấu nháy của dữ liệu; Host, tên header và IP cũng chưa được quote đầy đủ. Một sự kiện chứa backtick trong method, hoặc dấu nháy kèm backtick ở các trường còn lại, có thể thực thi lệnh khi người vận hành **dán và chạy** lệnh Copy as cURL. Đây là đường khai thác cần thao tác chạy shell của người vận hành; xem sự kiện trong trình duyệt không tự thực thi lệnh.

`ui/src/lib/curl.ts` dùng một hàm quote POSIX shell cho toàn bộ từng đối số động: method, URL, header đầy đủ và body. Chỉ đưa tên header đúng HTTP token vào `-H`, tránh tên bắt đầu bằng `@` bị cURL hiểu thành file. Giữ cơ chế bỏ dữ liệu đã che; không thêm dependency.

## Bằng chứng

Test mới chạy `/bin/sh` với hàm `curl` chỉ ghi argv và hàm `ID` chỉ in `CURL_CANARY`. Không dùng cURL thật, không gửi mạng, không ghi file. Kiểm tra cả không thực thi canary và giữ nguyên dữ liệu trong từng đối số.

Trên mã cha `827264a` với cùng test:

```text
Test Files  1 failed (1)
     Tests  6 failed | 1 passed (7)
```

Canary xuất hiện trong argv ở các trường chưa quote. Trường giá trị header vốn đã escape đúng vẫn pass. Sau sửa, sáu ca roundtrip (method, host, path, tên header, IP, giá trị header) và ca loại tên header không hợp lệ đều pass. Hai kỳ vọng chuỗi cũ được cập nhật sang biểu diễn quote an toàn.

Chạy trên Node `24.21.0-bookworm-slim`, CPU 12–13, node_modules hiện có gắn read-only, cache Vite riêng:

```text
npm run lint                       → exit 0
npm test -- --run
 Test Files  15 passed (15)
      Tests  91 passed (91)
npm run build
 ✓ built in 16.13s
```

Log gốc trong workspace: `build/h8-curl-parent-red.log`, `build/h8-curl-final.log`. Test shell được commit để tái hiện lỗi độc lập với log.

## Giới hạn và tự review

- Chưa merge main; không chạy CI trả phí và không deploy staging/production.
- Bản sửa bảo vệ cú pháp shell; chức năng hiện có vẫn chỉ đưa snippet vi phạm vào body, không bảo đảm tái tạo đầy đủ request gốc.
- Không thay quyền API hay dữ liệu sự kiện. Không đưa token/PII thật vào test hoặc báo cáo.
- Test cũ vẫn chạy đủ; không tắt test. Lint, toàn bộ UI test và build đều pass.

Nhiệm vụ: H7 / #108 · oracle trình duyệt cho hai Header XSS còn mở
Nhánh: `codex/h7-browser-oracle`, base `codex/m4-real-activation-chain` (`c3e5078`). Bản kiểm chứng bổ sung, không phát hành rule hay đóng #108.

Hai payload URL/Base64Flat trong [phép đo Header trước](h7-header-coverage.md) là cùng một chuỗi. Chromium thật xác nhận chuỗi này **có thể thực thi** khi ứng dụng decode header, xóa các đoạn `<...>`, rồi chèn kết quả vào thuộc tính `value="..."` không escape. Trong fixture giữ nguyên nội dung sau decode, chuỗi đó không thực thi; sau xóa tag và HTML-escape có xử lý dấu nháy, cũng không thực thi. Đây là bằng chứng cho pipeline tổng hợp đã nêu, chưa chứng minh ứng dụng thực có cùng pipeline.

| Ca | Direct backend | Qua WAF release | Kết luận trong fixture |
|---|---|---|---|
| Benign | 200, không gọi alert | 200, allow, không gọi alert | Control hợp lệ |
| XSS dễ nhận diện | 200, gọi alert(1) | 403, block, có rule 300012 | Oracle thực thi và rule chặn đều hoạt động |
| URL/Base64, giữ nguyên sau decode | 200, không gọi alert | 200, allow, không gọi alert | Chưa có exploit với context này |
| URL/Base64, xóa tag | 200, gọi alert(1) | 200, allow, gọi alert(1) | Hai conditional bypass có thực thi |
| URL/Base64, xóa tag rồi escape đầu ra | 200, không gọi alert | 200, allow, không gọi alert | Encode đúng context ngăn thực thi |

Đã làm:

- `tests/security/header_xss_browser_probe.py`: backend phản chiếu có ba pipeline tường minh, dùng lại vòng đời NGINX/signature verifier của harness Header; pin SHA-256 candidate cũ. Đầu vào header tối đa 8.192 ký tự, URL 1.024 ký tự; sai decoder/context/base64/UTF-8 bị từ chối. Mỗi lượt yêu cầu output directory mới.
- `tests/security/header_xss_browser_probe.mjs`: 8 cặp direct/proxy, Chromium focus input thật, đọc DOM attributes và lời gọi handler thật. Hook `window.alert` ghi lại đối số thay vì mở modal; không dùng cờ `oracle=true` do backend tự khai. Chỉ cho request đến hai origin loopback, không trace/video chứa dữ liệu ngoài fixture. Ghi cả kết quả thất bại/incomplete; `action=error` làm suite thất bại, không chuyển thành allow.
- Dùng candidate 9.067 rule đã ký có hash `b9e6fafc4c5b7f4f401f6bac335a42d7cc565dbf48a544337b98dbb3e3fa1d0a`, đúng artifact phép đo H7 cũ. Đây **không phải** lần build lại upstream bất biến: archive ET Open còn thiếu.
- Giữ nguyên budget 10 ms, fail-open, nội dung rule và chính sách xử lý. Release NGINX 1.30.5 build lại với `-Wall -Wextra -Werror`; binary ASan/UBSan dùng lại từ kiểm chứng native trước, không có thay đổi C/Rust trong PR này.
- Cập nhật trạng thái H7; viết gọn trạng thái M4 để bỏ câu “chưa nối worker” đã lỗi thời. Không đổi con trỏ tuần, thiết kế hay interface.

Kết quả thật, không gộp release với sanitizer:

- **Release PASS**: 4 cặp HTTP tối giản / 8 attempt; 8 cặp Chromium / 16 navigation và 1 discovery request. Browser suite có 0 assertion failure, 0 `action=error`. Rule 500569/920350 xuất hiện với header Chromium/Host loopback nhưng không gây block; control XSS có thêm 300012 và bị block. Không gọi đây là lượt chạy lại toàn bộ GoTestWAF hay benchmark chi phí.
- **ASan browser suite FAIL**: vẫn ghi đủ 8 cặp; 3 proxy navigation (`benign`, `URL-escaped`, `Base64Flat-strip`) có `action=error`, log `engine error 4` (`STRATA_E_BUDGET`). Các request này không được tính là signature bypass. Không có file report ASan/UBSan, nhưng điều đó không biến suite thành pass hay chứng minh không rò bộ nhớ; LeakSanitizer tắt như harness HTTP trước. Không tăng budget để làm xanh.
- Unit tests **3 PASS**: giữ hai test evidence/SQL oracle cũ, bổ sung test âm decoder/context/UTF-8 và giới hạn header/URL. Node syntax/Python compile PASS. Không thay assertion cũ.

Bài học từ lần dựng fixture đầu: query `encoder=Base64Flat` tự kích hoạt rule CRS 932260 trên ARGS, nên không đo riêng được payload header. Đổi bộ chọn fixture sang `e=0|1`, `c=0|1|2` giữ nguyên header/pipeline, loại sự nhiễu do query kiểm soát. [Request thô của bản fixture đầu](evidence/h7-browser-oracle/initial-fixture/requests.jsonl) được giữ lại; đây không phải bypass được sửa bởi thay đổi rule. Lượt ASan trung gian có một request benign budget-out; lượt cuối nêu trên có ba. Không chọn lượt ít lỗi để tuyên bố ổn định.

Lệnh kiểm chứng (từ repo; cần Docker dev image, Chromium/Playwright 1.64 đã có trong UI, socket GID 988 và CPU 6–12 khả dụng):

```bash
STRATA_DEV_DOCKER_ARGS='--cpuset-cpus=6-10 -v /home/hellc/strata-workflow/build/m4-runtime-target:/src/target' \
  deploy/dev/run.sh env STRATA_RELEASE=1 connectors/nginx/scripts/build.sh 1.30.5 build
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests/security -p test_header_probe.py -v
STRATA_DEV_DOCKER_ARGS='--name strata-h7-browser-owned --cpuset-cpus=6-10 --group-add 988 -v /usr/bin/docker:/usr/bin/docker:ro -v /var/run/docker.sock:/var/run/docker.sock -v /home/hellc/strata-workflow/build/m4-runtime-target:/src/target' \
  deploy/dev/run.sh env PYTHONDONTWRITEBYTECODE=1 python3 tests/security/header_xss_browser_probe.py \
  --out-dir build/h7-browser-oracle-release-final --network-container strata-h7-browser-owned \
  --host-repo /home/hellc/strata-workflow --variant release
# Lượt sanitizer riêng: --variant asan, output directory mới; kết quả lần này exit 1.
```

[Bằng chứng](evidence/h7-browser-oracle/): browser DOM/handler/results, mỗi request tối giản, hash executable/bundle/public key/source, NGINX error log và output assertion. Log lưu trong Git chỉ bỏ khoảng trắng cuối dòng; bản gốc còn ở `build/`. Không export token, secret hay private key. Thư mục `summary.json` là phần 4 cặp HTTP tối giản, không đại diện kết quả suite Chromium; xem `browser-results.json` và `http-check.log` cho suite đó.

Cách xử lý tiếp theo và giới hạn:

- Tại ứng dụng có pipeline tương ứng: encode theo context lúc xuất HTML, xử lý cả dấu nháy; không coi xóa tag là cơ chế escape. Nhánh `escaped` chứng minh biện pháp này trong fixture.
- Chưa thêm transform xóa tag toàn cục hoặc chữ ký chỉ nhắm chuỗi test vào WAF: chưa có context thực/FP/chi phí để chọn cách tổng quát an toàn. Rule 300011–300013 vẫn chờ người luồng S duyệt trước phát hành; mức tăng chi phí +21,3% của lượt H7 cũ vẫn cần profile, không bị thay thế bởi lượt này.
- Giữ #108 mở cho coverage ứng dụng thật; giữ H2/#28 mở cho budget. Không tuyên bố toàn H7 đã sửa hoặc đóng Gate A.
- Không chờ hosted CI theo yêu cầu người dùng; không merge hay triển khai staging/production.

Tự review: điều kiện oracle có lệnh/output; lỗi decoder và giới hạn có test âm; không có endpoint quản trị mới; không thay rule/interface/dependency; nguồn và log chỉ lab. Các giới hạn budget, upstream artifact và human review được ghi rõ, không đánh dấu hoàn tất thay cho bằng chứng còn thiếu.

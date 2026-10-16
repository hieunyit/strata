L3 / #49 · chuẩn bị cache trước request worker · 2026-10-17

Request benign đầu sau start/reload từng hết budget và fail-open 9/11 lần ở budget 10 ms. Bản sửa biên dịch sớm fallback regex dưới gate chỉ theo method khi map bundle, rồi chuẩn bị scratch/stream và prime cache regex thông dụng trên chính thread worker, trước request đầu và trước khi publish bundle nóng. Không tạo transaction để warm, không thay CPU budget/fail mode/body limits.

Thêm C ABI 1.7 `strata_engine_prepare_thread`, có catch_unwind, NULL trả INVALID; lỗi chuẩn bị trả INTERNAL. NGINX ghi warning và dùng cơ chế inspection hiện có khi chuẩn bị lỗi. Generated header và tài liệu FFI được cập nhật. Hai assertion pin ABI 1.6 được nâng lên đúng 1.7; các kiểm tra layout/fail-mode vẫn được chạy.

Cùng fixture signed pack 9.067 rule, NGINX 1.30.5 một worker CPU 6, client CPU 8, budget 10 ms/fail-open:

| Ca | First / warm | Engine p50 first / warm (ms) | Budget / fail-open |
|---|---:|---:|---:|
| trước sửa, benign | 11 / 220 | 17,102 / 0,990 | 9 / 9 |
| chỉ precompile method (chưa prime worker) | 11 / 220 | 11,843 / 0,913 | 8 / 8 |
| sau sửa, benign | 11 / 220 | 2,254 / 0,944 | 0 / 0 |
| sau sửa, XSS | 11 / 220 | 6,006 / 1,324 | 0 / 0 |

Hai ca sau sửa trả đúng 231 HTTP 200 và 231 HTTP 403. Năm trial hot activation benign (210 request) và một trial XSS (42 request) giữ PID worker và chuyển bundle 1 → 2 qua control file, không restart: tất cả đúng status, 0 budget/fail-open. Tổng bộ đo cuối: 714 request thật, 441 benign 200, 273 XSS 403. Readiness dùng PID/bundle trong metrics, không gửi HTTP để warm; response xác nhận PID/bundle. Harness kiểm layout metrics, giới hạn URI/reload/warm; không dùng status 200 để suy ra inspection đầy đủ.

Kiểm chứng:

```text
parent 9afd039 + test mới: FAIL compiled_count 0, expected 1
bản sửa: GET có payload khớp; POST và GET benign không khớp
prepare_thread FFI: 8 thread × 4 lần, repeat/NULL, 0 traffic/cost samples → PASS
cargo test --offline --workspace --all-features → 386 passed, 0 failed, 9 ignored
cargo clippy --offline --workspace --all-targets --all-features -- -D warnings → PASS
make check-header abi-test → PASS / abi_test: ok
make nginx-asan NGINX_VERSION=1.30.5 → fresh module linked
make test-nginx-asan NGINX_VERSION=1.30.5 → 595 tests PASS, no sanitizer reports
make nginx-asan NGINX_VERSION=1.31.6 → fresh module linked
make test-nginx-asan NGINX_VERSION=1.31.6 → 595 tests PASS, no sanitizer reports
```

Tái chạy HTTP: xem `l3-cold-worker-measurement.md`; harness nay có `--uri <origin-form>` / `--expected-status 403`, và `--hot-bundle <signed-v2.sbn> --reloads 1`. Bundle nóng được compiler tạo từ cùng IR 9.067 rule, policy enforce, version 2, created-at 1, ký bằng fixture key; node vẫn kiểm chữ ký. Raw records/hash được tách thành evidence PR để giữ bản sửa code dễ review. Profile offline hỗ trợ `--prepare` để đo riêng chi phí khởi tạo.

Native diagnostic A/B/B/A không fork: peak RSS baseline 60.872–60.876 KiB, prepared 60.752–60.852 KiB (xấp xỉ 59,4 MiB cả hai); hai lần prepare tốn 7,381 và 9,015 ms. Hash dùng streaming để tiến trình đo không phình bộ nhớ trước khi spawn. Đây là peak RSS cả process map + hai request offline, không phải RSS từng worker NGINX hoặc bằng chứng soak; không suy ra giảm RSS từ chênh lệch nhỏ này.

Giới hạn: cache priming chỉ phủ đường thông dụng; fallback dưới gate theo dữ liệu vẫn lazy. Đây là lab trên shared host, chưa phải SLO dưới tải hoặc mọi payload/route. Hot activation có thêm công việc đồng bộ trên event loop; cần đo latency activation dưới tải và RSS/soak nhiều bundle trước rollout. Pack có ba rule header còn cần human S review. Large-body #28 vẫn chưa đạt; không đóng #49 hay tự deploy từ kết quả fixture này. Chưa chạy HTTP/3 trong hai suite HTTP/2 này (test H3 có điều kiện riêng).

Tự review: error path/NULL được xử lý; không unsafe mới ngoài FFI; vòng prime bị chặn bởi rule table và chuỗi cố định; không log input/secret, không sinh counter giả; không thêm dependency, không đổi bundle/proto; thay đổi nằm trong engine/NGINX và test/tài liệu liên quan. Không chờ hosted CI, không merge main hay kết nối staging/production.

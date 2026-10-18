L3 · Kích hoạt bundle dưới tải · 18/10/2026 (UTC+7)
Nhánh `codex/l3-activation-load-measurement`, base `codex/review-browser-acceptance` (`4aa3aee`). **Đã thu đủ số đo; chưa đạt điều kiện không fail-open.**

Fresh release NGINX 1.30.5/1.31.6 dùng private libstrata hiện tại, test-hooks của dev không kích hoạt. Hai bundle ký sẵn 9.067 rule của L3 trước: v1 SHA b9e6fafc4c5b7f4f401f6bac335a42d7cc565dbf48a544337b98dbb3e3fa1d0a; v2 fceddaddef1922548ed588a87baa211e7471a5d3857138b2da09186bfea6f915. NGX vẫn kiểm chữ ký và version; không tạo rule/bundle mới, không đổi budget 10 ms, fail-open hoặc giới hạn policy. Không coi candidate cần S review là pack đã phát hành.

Một worker CPU6, producer/publisher CPU7–8; mỗi lượt 12 giây, 8 HTTP client, tải đặt 100 hoặc 200/s, URI/header benign cố định. Mỗi cặp version/rate chạy steady → hot → hot → steady, process riêng mỗi lượt, tổng **16 lượt/28.800 HTTP hoàn tất**. Số offered = số response = counter request NGX ở mọi lượt; không lỗi socket/drop driver/crash/alert. Mỗi response ghi status/action/worker/bundle/engine time, wall latency, dispatch delay và latency tính từ lịch gửi; không lấy loop count làm TPS. Actual completed RPS xấp xỉ 100/200, có số chính xác từng lượt. Publisher chạy thread riêng, vẫn có 38–90 HTTP được gửi trong khoảng lệnh publish chạy, tránh ngưng producer đúng lúc cần đo.

Các khoảng p99 dưới đây là min–max của **hai trial**, không phải p99 của dữ liệu gộp; peak là max của hai trial. Tất cả đơn vị ms, latency HTTP bao gồm connector và loopback upstream, không phải riêng engine:

| NGX / rate | steady p99 | hot p99 | steady peak | hot peak | budget steady / hot |
|---|---:|---:|---:|---:|---:|
| 1.30.5 / 100 | 8,645–8,892 | 8,689–8,952 | 32,498 | 22,634 | 1 / 0 |
| 1.30.5 / 200 | 10,495–10,989 | 10,309–12,054 | 31,292 | 41,207 | 0 / 1 |
| 1.31.6 / 100 | 7,463–7,479 | 7,475–7,792 | 12,051 | 16,370 | 0 / 0 |
| 1.31.6 / 200 | 11,781–12,286 | 10,527–11,782 | 50,587 | 25,996 | 0 / 0 |

Hai request lỗi vẫn HTTP 200 nhưng action `error`, budget counter và fail_open tăng; harness trả **FAIL** đúng hai lượt đó (14 PASS/2 FAIL). Ví dụ steady 1.30.5/100 request 888: engine 18.195 µs, HTTP wall 21,514 ms. Không quy mọi peak/fail-open cho activation khi lỗi cũng có ở baseline. Chưa có bằng chứng nguyên nhân scheduler/CPU/regex riêng; không nâng budget hoặc hạ tải để làm kết quả xanh.

Cả tám hot trial giữ PID và thấy response bundle2; từ bắt đầu lệnh publish đến response mới đầu tiên 0,933–2,120 s, từ lúc lệnh hoàn tất 0,544–1,683 s. Đây là thời gian cập nhật có thread-pool load/check control, khác độ trễ một request. Chưa có kết quả production SLO. RSS sau hot khoảng 57,2–57,5 MiB; peak VmHWM 92,9–93,1 MiB trên **một worker**. Hai bundle không chứng minh memory bounded sau 1.000 lần hay soak 24 giờ.

Lệnh build: `make nginx NGINX_VERSION=1.30.5 && make nginx NGINX_VERSION=1.31.6` trong dev image/private target → PASS. Tái chạy mỗi case: `taskset -c 7,8 python3 tests/security/activation_load_probe.py --nginx build/nginx-V/objs/nginx --module build/nginx-V/objs/ngx_http_strata_module.so --bundle build/current-pack/header-v4.sbn --hot-bundle build/l3-prepare-v2.sbn --pubkey connectors/nginx/t/fixtures/bundle.pub --mkbundle target/release/mkbundle --out build/NEW --rate 100 --seconds 12 --clients 8 --cpu 6 [--steady]`; Docker cpuset 6–8. Rate thứ hai 200. `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests/security -p test_activation_load_probe.py -v` → **3 PASS**, gồm 5 giới hạn thù địch trước I/O, version không tăng không spawn, HTTP200/error và work chưa gửi không thành inspection thành công. `py_compile` PASS. [Raw/metadata và output thật](evidence/l3-activation-load/) gồm từng request, source/binary hashes và log FAIL; byte SHA source nhất quán cả 16 lượt.

Tự review: lỗi có verdict/counter và exit code thật; giới hạn rate≤500/s, duration≤30s, offered≤10.000, clients≤16 và queue bounded; cleanup process group riêng, thread/event và subprocess timeout; chỉ loopback/lab, không credential thật; chỉ harness/test/report, không dependency/interface/policy thay đổi; Python syntax/negative checks sạch. Shared host, một worker, một benign URI, thời gian hữu hạn; không suy ra capacity/traffic thật, không đóng #49/#28. Mục đo activation đã có bằng chứng; tối ưu để bỏ budget miss và soak vẫn còn.

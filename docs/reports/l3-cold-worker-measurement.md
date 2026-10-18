L3 / #49 · đo worker NGINX thật · 2026-10-17

Kết luận: chưa sửa được cold path. Request benign đầu tiên của worker có thể hết CPU budget và fail-open ở cấu hình hiện tại. Không dùng HTTP 200 làm bằng chứng inspection thành công.

Harness `tests/security/cold_worker_probe.py` chạy NGINX 1.30.5 một worker, proxy tới backend loopback, chờ PID/bundle metrics sẵn sàng và worker cũ thoát; không dùng HTTP để warm readiness. Mỗi lần chạy gồm start + 10 reload, 1 request đầu và 20 request warm/worker. Client ở CPU 8, worker ở CPU 6. Giữ `strata_cpu_budget 10ms`, `strata_fail_mode open`; không đổi policy/body limits/rate-limit.

| Lần chạy | Nhóm | Số request | Engine min / p50 / max (ms) | Budget / fail-open |
|---|---|---:|---|---:|
| đầu | first | 11 | 7,862 / 16,631 / 22,850 | 9 / 9 |
| đầu | warm | 220 | 0,595 / 0,926 / 11,230 | 1 / 1 |
| lặp lại | first | 11 | 6,748 / 17,102 / 28,146 | 9 / 9 |
| lặp lại | warm | 220 | 0,735 / 0,990 / 6,665 | 0 / 0 |

Engine time là delta counter worker `engine_ns_total` (độ phân giải microsecond của FFI), không phải wall latency HTTP. Chờ cả action counter và histogram tăng trước khi đọc kết quả; PID và bundle trong response phải khớp worker đang đo. Counter budget/fail-open được ghi riêng từng request. Datagram sink nhận sự kiện/counter và chỉ giữ độ dài/hash, không sửa chính sách event phía node.

Bằng chứng cục bộ:

```text
make nginx NGINX_VERSION=1.30.5 → build thành công (-Wall -Wextra -Werror)
python3 tests/security/cold_worker_probe.py ... → 231 records mỗi lần
repeat: first requests=11 budget_hits=9 fail_open=9
repeat: warm requests=220 budget_hits=0 fail_open=0
```

Tái chạy trong image dev, sau khi build module và chuẩn bị bundle đã ký:

```bash
STRATA_DEV_DOCKER_ARGS='--cpuset-cpus=6-10 -v /home/hellc/strata/target:/src/target' deploy/dev/run.sh taskset -c 8 python3 tests/security/cold_worker_probe.py   --nginx build/nginx-1.30.5/objs/nginx   --module build/nginx-1.30.5/objs/ngx_http_strata_module.so   --bundle build/current-pack/header-v4.sbn   --pubkey connectors/nginx/t/fixtures/bundle.pub   --mkbundle target/release/mkbundle --out build/l3-cold-probe-repeat
```

Bundle candidate 9.067 rule gồm rule header chưa có human S review. Đây là dev build có feature test-hooks (không kích hoạt hook); không phải package production. Hash module/binary/bundle/harness trong metadata đi kèm raw evidence. Máy chia sẻ tài nguyên, cache host không được làm lạnh; số đo phản ánh worker mới, không phải cold host hoặc SLO production. Không suy diễn tỷ lệ 9/11 thành xác suất production.

Tự review: harness giới hạn reload/warm, kiểm tra worker và completion, đóng process group riêng khi timeout; không chạm staging/production hay ABI. Chưa có bản sửa runtime; #49 vẫn mở. Bước tiếp theo: tách chi phí compile/cache khỏi evaluation bằng profile, tối ưu ngoài request nếu đủ bằng chứng, rồi chạy lại cùng harness và kiểm thử sanitizer. Không tăng budget hoặc chuyển fail mode để làm số đo pass.

# ngx_http_strata_module

Connector NGINX cho libstrata; [thiết kế](../../docs/design/nginx-module.md),
[control file và bundle](../../docs/design/control-file.md).

```bash
deploy/dev/run.sh make nginx NGINX_VERSION=1.30.5
deploy/dev/run.sh make test-nginx NGINX_VERSION=1.30.5
# Luôn build đúng bản trước khi chạy sanitizer hoặc Valgrind.
deploy/dev/run.sh make nginx-asan NGINX_VERSION=1.30.5
deploy/dev/run.sh make test-nginx-asan NGINX_VERSION=1.30.5
deploy/dev/run.sh make nginx NGINX_VERSION=1.30.5
deploy/dev/run.sh make test-nginx-valgrind NGINX_VERSION=1.30.5
```

Dùng cùng phiên bản NGINX, configure flags và thư viện khi build binary/module.
Đổi `NGINX_VERSION=1.31.6` để kiểm tra bản mainline.

## Directive

`H` = trong `http`, `S` = trong `server`, `L` = trong `location`.
Các giá trị ở H/S/L kế thừa từ cấp cha khi không khai báo lại.
Bảng dưới đối chiếu command/enum/default trong `src/ngx_http_strata_module.c`.

| Directive | Context | Cú pháp / mặc định |
| --- | --- | --- |
| `strata` | H/S/L | `on` hoặc `off`; mặc định `off` |
| `strata_control_file` | H | đường dẫn; `/run/strata/control` |
| `strata_bundle_dir` | H | thư mục; `/var/lib/strata/bundle` |
| `strata_bundle_pubkey` | H | file Ed25519 thô 32 byte, hoặc hai khóa nối tiếp 64 byte khi xoay khóa; không có mặc định, bắt buộc khi bật Strata |
| `strata_bundle_check` | H | thời gian NGINX; `1000ms` |
| `strata_node_id` | H | chuỗi định danh node; hostname của NGINX cycle |
| `strata_event_socket` | H | `unix:<path>`; `unix:/run/strata/events.sock` |
| `strata_metrics_file` | H | đường dẫn; `/run/strata/metrics`; counter nhị phân dùng chung với agent, không phải Prometheus textfile |
| `strata_policy` | S/L | tên policy trong bundle; mặc định rỗng, cần cấu hình để chọn policy cho route |
| `strata_mode` | H/S/L | `inherit` hoặc `shadow`; `inherit`. Enforce do policy đã ký quyết định |
| `strata_fail_mode` | H/S/L | `open` hoặc `closed`; `open` |
| `strata_request_body_mode` | H/S/L | `buffer` hoặc `stream`; `buffer`. Stream chỉ chạy shadow; cấu hình stream với policy enforce bị từ chối khi nạp ban đầu |
| `strata_request_body_limit` | H/S/L | kích thước NGINX; `1m` (1 MiB) |
| `strata_response_inspect` | H/S/L | `on` hoặc `off`; `on` |
| `strata_response_body_limit` | H/S/L | kích thước NGINX; `512k` (512 KiB) |
| `strata_identity` | H/S/L | NGINX complex value; mặc định chưa đặt. Chỉ lấy identity đã xác thực, không dùng token bí mật hoặc header do client tự nhận |
| `strata_block_page` | H/S/L | đường dẫn file HTML 1–65536 byte; mặc định trang tích hợp. Không nhận HTML inline |
| `strata_cpu_budget` | H/S/L | thời gian NGINX; `10ms`; kiểm tra budget hợp tác, không phải bảo đảm p99 |
| `strata_breaker` | H | `on` hoặc `off`; `on` |
| `strata_breaker_threshold` | H | `<share>% <window> <min_requests> [open=<time>]`; `2% 10s 200 open=30s` |
| `strata_breaker_action` | H/S/L | `degrade` hoặc `reject`; `degrade` |

Ngưỡng breaker chỉ khai báo một lần: phần trăm lớn hơn 0, không quá 100,
tối đa hai chữ số thập phân; window và số request tối thiểu phải dương.
`open` dương, tối đa `5m`. Khi breaker mở, `degrade` chỉ kiểm lớp protocol;
`reject` trả lỗi 503. CPU budget exceeded không được tính như engine panic.
Xem implementation `src/ngx_http_strata_breaker.c` và test `t/090-breaker.t`.

## Ví dụ cấu hình

Ví dụ giữ mode shadow và các giới hạn mặc định; không thay đổi quyết định rollout.
Thay đường dẫn module và cung cấp control file, bundle đã ký, public key phù hợp
trước khi chạy `nginx -t`. Agent và NGINX cần quyền truy cập đúng các file/socket;
không mở quyền ghi bundle/key cho client hoặc tiến trình không tin cậy.

```nginx
load_module /usr/lib/nginx/modules/ngx_http_strata_module.so;
worker_processes 1;
pid /run/strata/nginx.pid;
error_log /run/strata/error.log notice;
events { worker_connections 128; }
thread_pool default threads=2;
http {
    access_log off;
    strata_control_file /run/strata/control;
    strata_bundle_dir /var/lib/strata/bundle;
    strata_bundle_pubkey /etc/strata/bundle.pub;
    strata_event_socket unix:/run/strata/events.sock;
    strata_metrics_file /run/strata/metrics;
    strata_breaker on;
    strata_breaker_threshold 2% 10s 200 open=30s;
    server {
        listen 127.0.0.1:8080;
        server_name api.example.test;
        location / {
            strata on;
            strata_policy example-api;
            strata_mode shadow;
            strata_fail_mode open;
            strata_request_body_mode buffer;
            strata_request_body_limit 1m;
            strata_response_inspect on;
            strata_response_body_limit 512k;
            strata_cpu_budget 10ms;
            strata_breaker_action degrade;
            proxy_pass http://127.0.0.1:8081;
        }
    }
}
```

Master kiểm chữ ký và nạp bundle hiện hành từ control file. Worker theo dõi
generation rồi nạp bundle mới trong thread pool `default`; không cần reload NGINX
cho mỗi lần đổi bundle. `mkbundle` tạo key/control file cho test;
`strata-compile` mới là công cụ biên dịch/ký bundle. Xem fixture tái lập tại
`t/fixtures/make.sh`; các khóa fixture công khai chỉ dùng cho test.

Trang block hỗ trợ `{{block_id}}`, `{{time}}`, `{{support_contact}}`, không phản chiếu
input request. Các biến log: `$strata_block_id`, `$strata_action`, `$strata_score`,
`$strata_rules`, `$strata_policy`, `$strata_bundle_version`, `$strata_time_us`.
Không log Authorization, cookie hoặc input nhạy cảm. Không phải mọi lỗi nội bộ
đều có Block ID; `closed` có thể trả 503.

Buffer/limit và budget không bảo đảm kiểm đủ body. Policy đã ký có thể đặt giới
hạn bổ sung; theo dõi inspection status, counter và cảnh báo. Việc chọn route
fail-closed hoặc tăng CPU budget cần quyết định vận hành riêng.

Kiểm tra ví dụ và các cấu hình sai bằng binary/module vừa build:

```bash
deploy/dev/run.sh python3 connectors/nginx/scripts/check-readme.py \
  --version 1.30.5 --bin-dir target/release
```

# Cài node Strata

Một node là NGINX (bản nginx.org) có `ngx_http_strata_module`, cộng `strata-agent`.
Gói và trình cài do `deploy/packaging/build.sh` tạo trong `build/packages/`
(W10-N-01).

| Gói | Nội dung |
| --- | --- |
| `nginx-module-strata_<nginx>+<strata>` (deb, rpm) | `ngx_http_strata_module.so` trong thư mục module của nginx.org (`/usr/lib/nginx/modules` với deb, `/usr/lib64/nginx/modules` với rpm), cấu hình mẫu `/usr/share/nginx-module-strata/strata.conf.example`. Mỗi bản NGINX một gói: phụ thuộc đúng bản `nginx` của nginx.org, nên trình quản lý gói từ chối cài lệch |
| `strata-agent_<strata>` (deb, rpm) | `/usr/bin/strata-agent`, unit `strata-agent.service`, `/etc/strata/agent.env`, `/usr/lib/sysctl.d/90-strata.conf` (`net.unix.max_dgram_qlen = 8192`), `/usr/lib/tmpfiles.d/strata.conf` (`/run/strata`), user và group `strata`, dashboard và luật cảnh báo trong `/usr/share/strata/monitoring/` |

Hệ điều hành đã thử: Ubuntu 24.04, Debian 12, Rocky Linux 9 (x86_64). NGINX: 1.30.5,
1.31.6.

## Cài bằng một lệnh

Cần: quyền root, một enrollment token (UI Fleet hoặc
`POST /v1/groups/{id}/enrollmentTokens`, dùng một lần, hết hạn sau 24 giờ), và CA của
FleetService.

```bash
sh install.sh --packages <thư mục hoặc URL> --nginx 1.30.5 \
  --server cp.example.test:8443 --token-file token --ca ca.pem
```

Trình cài làm lần lượt:

1. Dùng NGINX đang có. Nếu chưa có, cài đúng bản `--nginx` từ nginx.org (bản mainline
   khi số minor lẻ).
2. Cài `strata-agent` và gói module của **đúng** bản NGINX đó. Không có gói cho bản đó
   thì dừng, không cài gì. Đây cũng là bước kiểm tra trước khi nâng NGINX.
3. Thêm `load_module modules/ngx_http_strata_module.so;` vào đầu `nginx.conf` (một lần).
4. Enroll node (token được chép vào `/var/lib/strata` rồi xóa ngay), chép khóa ký bundle
   cho NGINX, viết `/etc/nginx/conf.d/strata.conf`, bật `strata-agent`, rồi reload NGINX.

Từ URL thì mọi file được kiểm theo `SHA256SUMS`. Chạy lại là để nâng cấp: lần chạy lại
không đổi gì nếu không có gì mới.

Sau khi cài, NGINX chưa kiểm request nào. Bật kiểm tra theo server hoặc location (cần cả
hai dòng):

```nginx
location / {
    strata on;
    strata_policy example-api;
    ...
}
```

`nginx -t && systemctl reload nginx`. Node nhận bundle hiện tại của fleet ngay khi
agent nối tới control plane (bundle của rollout xong gần nhất). Trước lần deploy đầu
tiên, mọi request đi theo `strata_fail_mode`.

## Container

Image `strata-nginx:<nginx>` (`deploy/packaging/build-image.sh`) là image NGINX chính
thức có cài hai gói trên. Lần chạy đầu sẽ enroll; identity, bundle và spool nằm trong
volume `/var/lib/strata`.

```bash
docker run -d --sysctl net.unix.max_dgram_qlen=8192 -v strata:/var/lib/strata \
  -e STRATA_SERVER=cp.example.test:8443 -e STRATA_CA_FILE=/run/secrets/ca.pem \
  -e STRATA_ENROLL_TOKEN_FILE=/run/secrets/token \
  -v ./default.conf:/etc/nginx/conf.d/default.conf:ro strata-nginx:1.30.5
```

Agent hoặc NGINX dừng thì container dừng, để orchestrator khởi động lại. Không có
supervisor nào giữ container chạy với một agent đã chết.

## Data guard

Location dùng policy có `data_guard` (che PAN, JWT, CCCD trong response) phải chặn hai cách né (audit 22/10/2026, F-05): response đã nén bởi upstream không được inspect, và request `Range` đọc giá trị theo từng mảnh.

```nginx
location /api/ {
    strata on;
    strata_policy example-api;
    proxy_set_header Accept-Encoding "";   # upstream trả nội dung chưa nén
    proxy_set_header Range "";             # không đọc response theo từng mảnh
    proxy_pass http://backend;
}
```

Nén cho client vẫn bật được bằng `gzip on;` ở NGINX (filter của Strata đứng trước `gzip`). Phần response sau `strata_response_body_limit` (mặc định 512 KB) không được che: tăng giới hạn nếu location trả dữ liệu nhạy cảm lớn.

## Nâng NGINX

1. Kiểm có gói `nginx-module-strata_<bản mới>+…`: `install.sh` báo
   "no Strata module built for NGINX x" nếu không có.
2. Nâng `nginx` và gói module cùng lúc, ví dụ
   `apt-get install nginx=<bản>-1~<codename> ./nginx-module-strata_<bản>+…deb`. Riêng gói
   module thì không cài được: nó phụ thuộc đúng bản NGINX.

## Gỡ

`apt-get remove nginx-module-strata strata-agent` (hoặc `dnf remove`). Trước đó bỏ dòng
`load_module` và `/etc/nginx/conf.d/strata.conf`, nếu không `nginx -t` sẽ lỗi. Dữ liệu
trong `/var/lib/strata` được giữ lại. Thu hồi node trên control plane:
`DELETE /v1/nodes/{id}`.

Hướng dẫn mở rộng, gồm control plane và nghiệm thu node: [cẩm nang Compact](../operations/README.md),
đặc biệt [triển khai NGINX/agent](../operations/03-nginx-nodes.md).

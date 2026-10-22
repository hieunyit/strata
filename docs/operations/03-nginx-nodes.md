# 03 · Triển khai NGINX và strata-agent

[Trang đầu](README.md) · Trước: [cấu hình](02-configuration.md) · Tiếp: [bảo mật](04-security-integrations.md)

## 1. Những gì được cài trên node

Node có NGINX, module động `ngx_http_strata_module.so` và `strata-agent`. Module nạp
bundle đã ký và xử lý request tại node; agent quản lý identity, tải bundle, đẩy event,
spool và metrics. Không cài PostgreSQL/ClickHouse trên từng node.

| Thành phần | Vị trí theo gói |
| --- | --- |
| Agent binary | `/usr/bin/strata-agent` |
| Agent systemd env | `/etc/strata/agent.env` |
| Fleet CA | `/etc/strata/ca.pem` |
| Identity node/private key/cert | `/var/lib/strata/identity` |
| Bundle và control file | `/var/lib/strata/bundles`, `.../control` |
| Event spool | `/var/lib/strata/spool` |
| Event socket | `/run/strata/events.sock` |
| Metrics binary module | `/run/strata/metrics`, agent chuyển thành Prometheus |
| Module deb / rpm | `/usr/lib/nginx/modules` / `/usr/lib64/nginx/modules` |
| Cấu hình Strata cấp http | `/etc/nginx/conf.d/strata.conf` |

Một thư mục identity chỉ cho một node. Không clone volume identity sang nhiều máy:
chúng sẽ dùng chung private key và định danh. Khi tạo node mới phải enroll mới.

## 2. Kiểm tương thích trước khi đụng NGINX

Bộ gói hiện kiểm trên Ubuntu 24.04, Debian 12, Rocky Linux 9 x86_64, NGINX nginx.org
1.30.5 và 1.31.6. Đây là ma trận đã có kiểm chứng, không phải cam kết mọi distro/build
NGINX cùng version đều ABI tương thích. Không tự dùng module nginx.org với binary
vendor/OpenResty có configure flags/thư viện khác.

Trên node, ghi lại:

```bash
uname -m
cat /etc/os-release
nginx -v
nginx -V
systemctl status nginx --no-pager
```

Nếu chưa cài NGINX, bỏ qua lệnh `nginx` thất bại do chưa có binary; installer có thể
cài bản nginx.org được chọn. Nếu đã có NGINX phục vụ, backup cấu hình và kiểm tất cả
module đang nạp trước khi quyết định đổi gói. Đừng nâng nginx tự động lên version
không có module Strata tương ứng.

Cần đồng thời tương thích ABI NGINX và engine/compiler bundle, bao gồm Hyperscan.
B02 Inventory hiển thị phiên bản agent/module, fingerprint manifest và capability.
Thiếu manifest/không quan sát được là `unknown`; không coi đó là hỗ trợ tính năng.
Node báo capability không thay cho `nginx -t` và test request bằng worker thật.

## 3. Build và phân phối gói

Chạy trên máy build từ cùng source với compiler control plane:

```bash
export STRATA_DEV_DOCKER_ARGS="--cpuset-cpus=6-10"
# Chuẩn bị dev image nếu chưa có; script run.sh build nó khi cần.
deploy/dev/run.sh true
deploy/packaging/build.sh 1.30.5 1.31.6
```

Đầu ra ở `build/packages/`: agent deb/rpm, module cho từng bản NGINX, installer và
`SHA256SUMS`. Script kiểm bản Hyperscan trong dev image khớp builder; mismatch là lỗi
cần sửa toolchain, không bỏ gate. Build package dọn các deb/rpm cũ trong thư mục đầu
ra, nên copy bộ gói đã phát hành tới kho riêng trước lần build tiếp theo.

```bash
cd build/packages
sha256sum -c SHA256SUMS
```

Chép cả bộ gói qua kênh tin cậy tới node hoặc kho HTTPS nội bộ. SHA256SUMS phát hiện
file hỏng, không tự chứng minh người xuất bản nếu manifest và gói cùng bị thay. Ghim
manifest/hash qua kênh phân phối được tổ chức xác thực. Không có URL tải release công
khai cố định được giả định trong cẩm nang này.

## 4. Enrollment

Trên UI với admin đủ quyền:

1. Tạo/chọn Fleet group cho nhóm node dự kiến nhận rollout.
2. Tạo enrollment token cho group; token một lần, TTL không quá 24 giờ.
3. Chuyển token vào file riêng 0600 trên node, qua kênh secret.
4. Lấy public CA Fleet từ control plane và xác nhận fingerprint qua kênh độc lập.

Trên CP, với hàm `dc` chương 01:

```bash
umask 077
mkdir -p build/operator-public
dc cp control-plane:/var/lib/strata/pki/ca.pem build/operator-public/fleet-ca.pem
openssl x509 -in build/operator-public/fleet-ca.pem -noout -subject -dates -fingerprint -sha256
```

Chỉ gửi public CA; không gửi `ca-key.pem`, `node-ca-key.pem` hay signer private key.
Mạng node phải phân giải DNS Fleet và tới TCP 8443. Cert server phải có SAN đúng.
Nếu cần kết nối bằng IP khác DNS, dùng `--server-name` đúng SAN và giữ kiểm TLS.

Trên **node**, chạy bằng root; ví dụ gói đã chuyển vào `/opt/strata-packages`:

```bash
sh /opt/strata-packages/install.sh \
  --packages /opt/strata-packages \
  --nginx 1.30.5 \
  --server waf.example.test:8443 \
  --token-file /secure/strata/enrollment-token \
  --ca /secure/strata/fleet-ca.pem
```

Installer dùng NGINX hiện có hoặc cài đúng bản, cài gói, thêm `load_module`, enroll,
chép public verifier key, sinh snippet `strata.conf`, bật agent và reload NGINX. Nó
không bật inspection cho mọi ứng dụng. Trước rollout đầu, chưa có bundle thì request
ở route bật Strata đi theo `strata_fail_mode`.

Agent mặc định giới hạn spool 2 GiB (`--spool-max-bytes`); vượt cap sẽ bỏ batch
cũ nhất. File `agent.env` đóng gói không có biến chỉnh cap; nếu cần đổi, dùng
systemd override `ExecStart` được quản lý, giữ nguyên các flag/path khác của unit.
Không thêm một biến env tự đặt rồi giả định agent đã dùng.

Token tạm do installer chép vào `/var/lib/strata/enroll.token` được xóa sau enrollment;
file nguồn `/secure/strata/enrollment-token` là trách nhiệm người vận hành. Loại bỏ
file nguồn sau khi dùng theo quy trình secret. Không truyền token literal trên CLI.

Lỗi token đã dùng/hết hạn: tạo token mới. Lỗi CA/SAN: sửa CA hoặc DNS/cert. Không tắt
xác thực TLS. Chạy lại với identity còn nguyên là cập nhật, không tạo node khác.

## 5. Bật Strata trên một route thử

Backup vhost hiện tại. Snippet do package tạo dùng đúng đường dẫn bundle/control
trong bảng §1. Không chép nguyên ví dụ đường dẫn mặc định từ module README rồi trộn
với đường dẫn package: agent và module phải nhìn cùng control/bundle/key/socket.

Cấu hình cấp main/http được package chuẩn bị; kiểm có thread pool `default` dùng
cho nạp bundle, thêm ở cấp main nếu build/cấu hình hiện tại chưa có:

```nginx
thread_pool default threads=2;
```

Trong server ứng dụng hiện có, thêm vào location cần bảo vệ; ví dụ backend lab:

```nginx
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
    proxy_pass http://127.0.0.1:9000;
}
```

`example-api` phải tồn tại trong bundle đã phát hành. `shadow` ở NGINX ép shadow kể
cả policy enforce; khi chính thức cho policy điều khiển mode, đổi thành `inherit`.
Không có directive `strata_mode enforce`; enforce là quyết định trong policy đã ký.

`open` cho request tiếp tục khi không kiểm được; `closed` có thể trả 503. Chọn theo
rủi ro route. Không tăng budget/tắt breaker như cách mặc định chữa lỗi performance.

**Route enforce nhận body** (API, form, upload): đặt `strata_fail_mode closed`, và trong
policy `oversize: block` cùng `fail_on_findings: block`. Ở `open`, một body vài chục KB hết
CPU budget thì đi qua mà không được kiểm đủ: kẻ tấn công đặt payload ở cuối body đệm
(lab redteam TC-EXP-02; benchmark 22/10/2026: 33–59% request form 64 KB với gói signature
đầy đủ vượt budget). Trước khi chuyển, chạy route ở shadow và xem `strata_budget_exceeded`
của route: đó là số request hợp lệ sẽ nhận 503. Budget tính thời gian CPU của request
(không tính lúc tiến trình khác chiếm CPU), nên tải của host không làm tăng số đó.

```nginx
location /v1/ {
    strata on;
    strata_policy example-api;      # policy: oversize: block, fail_on_findings: block
    strata_fail_mode closed;
    strata_request_body_limit 1m;
    proxy_pass http://127.0.0.1:9000;
}
```
Body limit là giới hạn kiểm, không bảo đảm mọi body đều được kiểm đầy đủ. Stream
chỉ dùng shadow; không đổi sang stream cho một route enforce.

```bash
nginx -t
systemctl reload nginx
systemctl status strata-agent.service strata-agent.socket --no-pager
journalctl -u strata-agent.service -n 100 --no-pager
sysctl net.unix.max_dgram_qlen
```

Gói đặt `net.unix.max_dgram_qlen=8192`; kiểm giá trị thực và quyền socket, không suy từ
việc file sysctl tồn tại. NGINX worker cần quyền tới socket/file, nhưng không được
đọc private identity/CA key. Giữ group/mode do package tạo; xem journal và error.log
nếu policy không được nạp.

Kiểm theo nhiều lớp:

1. UI Fleet thấy đúng node/group, heartbeat mới, cert còn hạn, capability được quan sát.
2. Desired bundle và actual bundle trùng; từng worker không còn giữ generation cũ.
3. Route thật trỏ đúng `strata_policy`, không có override `off`/`shadow` ngoài ý muốn.
4. Request benign trả response backend bình thường.
5. Payload kiểm thử vô hại trên route **lab do bạn sở hữu** tạo event với đúng node,
   policy, thời điểm, bundle version và rule. Shadow là quan sát, không kỳ vọng 403.
6. Sau quy trình enforce ở chương 05, payload kiểm thử bị chặn theo policy và có
   Block ID khi đường xử lý đó hỗ trợ. Tra Block ID trên UI; kiểm benign lần nữa.

Không gửi chuỗi thử tấn công tới dịch vụ không được phép. Heartbeat, control version
và một lần `nginx -t` riêng lẻ chưa chứng minh worker đang kiểm request bằng bản mới.

## 6. Dùng node container

Build image từ bộ gói đã có:

```bash
deploy/packaging/build-image.sh 1.30.5
```

Đọc cú pháp script của checkout nếu chọn version khác. Ví dụ chạy sau khi chuẩn bị
`/opt/strata-node/default.conf` có route shadow đúng policy, CA và token ở host:

```bash
docker run -d --name example-waf-node --restart unless-stopped \
  --sysctl net.unix.max_dgram_qlen=8192 \
  -v example-waf-node-state:/var/lib/strata \
  --mount type=bind,src=/opt/strata-node/default.conf,dst=/etc/nginx/conf.d/default.conf,readonly \
  --mount type=bind,src=/secure/strata/fleet-ca.pem,dst=/run/secrets/ca.pem,readonly \
  --mount type=bind,src=/secure/strata/enrollment-token,dst=/run/secrets/token,readonly \
  -e STRATA_SERVER=waf.example.test:8443 \
  -e STRATA_CA_FILE=/run/secrets/ca.pem \
  -e STRATA_ENROLL_TOKEN_FILE=/run/secrets/token \
  -e STRATA_METRICS_ADDR=127.0.0.1:9469 \
  -p 127.0.0.1:18080:80 strata-nginx:1.30.5
```

Đây là node thử, chưa cấu hình TLS ứng dụng. Container backend `127.0.0.1` là cùng
container, không phải host; sửa upstream/network theo topology thật. Xác nhận host
hỗ trợ đặt sysctl đó trong container; nếu runtime từ chối thì cấu hình host phù hợp,
không bỏ qua cảnh báo event queue. CA/token phải được user root trong container đọc.
Sau enrollment, recreate không mount token nguồn nữa; giữ nguyên volume identity.

Image thoát khi agent hoặc NGINX thoát để orchestrator restart cả hai. Không nhân bản
state volume giữa replica; mỗi replica một identity và token enrollment riêng.

## 7. Nâng cấp/gỡ node

Trước nâng cấp, lưu config, phiên bản NGINX/module/agent, bundle hiện hành và kết quả
kiểm benign/attack. Xác nhận có module cho đúng NGINX mới; cài nginx và module tương
ứng trong cùng kế hoạch thay đổi. Không nâng một bên rồi hy vọng ABI còn khớp.

Agent trước, module sau khi giao thức telemetry thay đổi. Gói dùng systemd socket
activation để giữ event socket qua restart agent; queue kernel có giới hạn, nên vẫn
đo dropped/spool trước và sau. Không stop socket không cần thiết khi chỉ nâng agent.
Kiểm lại từng lớp §5 trước khi đưa node tiếp theo vào vòng nâng cấp.

Gỡ: bỏ `load_module`, snippet và các directive Strata trong vhost, `nginx -t`, rồi
theo kế hoạch restart/reload phù hợp trước khi remove gói. UI thu hồi node không
xóa bundle trên máy bị thu hồi, vì vậy phải xử lý host/credential theo quy trình
thu hồi tài sản của tổ chức. Dữ liệu `/var/lib/strata` không tự mất khi remove gói.

## 8. Standalone/Lite là lựa chọn riêng

Standalone không dùng Fleet control plane để quản lý node. Chọn cho trường hợp phân
phối bundle đã ký ngoài băng và tự vận hành cập nhật. Nó không thay PostgreSQL bằng
SQLite và không đồng nghĩa UI Compact chạy local trên node.

Không chạy đồng thời service/socket Fleet và standalone trên cùng state/socket.
Không dùng installer standalone để chuyển một NGINX đang phục vụ: script từ chối
Fleet identity và NGINX đang chạy. Đọc [runbook standalone](../runbook/standalone.md)
cho preflight chữ ký/policy, `--require-full-enforce`, LKG và giới hạn nghiệm thu VM.

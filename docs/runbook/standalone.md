# Standalone: kiểm bundle trước khi cấu hình route

Installer nhận gói local đã được người vận hành tin cậy và bundle core đã ký.
Nghiệm thu dưới năm phút trên VM sạch **đang chờ theo quyết định PO** vì chưa có
VM lab khác. Lượt QEMU/TCG không đạt; xem [kết quả và giới hạn](../reports/standalone-vm-hold.md)
và [phạm vi đã kiểm chứng](../reports/standalone-installer-review.md).

Dùng public key do người vận hành tin cậy cung cấp, không lấy key từ chính bundle
đang cần xác minh. Trước khi đưa bundle vào nguồn agent theo dõi:

```sh
strata-agent verify-bundle --bundle-file bundle.sbn --bundle-pubkey bundle.pub \
  --policy example-api --require-enforce
```

`--policy` yêu cầu tên tồn tại duy nhất trong bảng policy đã ký. Tên phải khớp
`strata_policy` trong cấu hình route. `--require-enforce` yêu cầu mode enforce,
không chia canary; lệnh từ chối policy shadow/canary và không tự đổi mode.
Bỏ cờ này nếu chủ ý kiểm một policy shadow. Bỏ cả hai cờ giữ kiểm chữ ký/header
như trước. Không ghi control file, không cài bundle hay khởi động service.

Kiểm thành công không chứng minh toàn bộ layout/section, phiên bản Hyperscan,
chất lượng rule, cấu hình NGINX hoặc khả năng chặn một payload. Vẫn phải chạy
`nginx -t` bằng module thực tế và kiểm benign/attack trên route lab. Policy trong
bundle có mode enforce cũng có thể được NGINX ép shadow; staging overlay và
rule exceptions vẫn có hiệu lực. Thực hiện lại kiểm tra trước mỗi lần phát hành
bundle mới; lệnh preflight không giám sát các lần cập nhật URL sau đó.

Service standalone dùng `/etc/strata/standalone.env`, một giá trị cho mỗi tham số.
`STRATA_BUNDLE_SOURCE` chứa đúng một `--bundle-file=...` hoặc `--bundle-url=...`;
bao giá trị bằng dấu nháy kép nếu đường dẫn có khoảng trắng. Public key của
service nằm tại `/etc/strata/bundle.pub`. Bundle/control/socket phải khớp đường
dẫn module; file nguồn và thư mục cài bundle nên tách riêng. Service/socket
standalone xung đột với cặp Fleet và không tự bật khi chỉ cài gói.


Watcher có thể ghim policy bằng `run --standalone --required-policy=example-api`
và tùy chọn `--require-full-enforce`. Ràng buộc áp dụng trước mỗi cập nhật từ file,
thư mục hoặc URL; bản không hợp lệ giữ nguyên LKG. Khi khởi động lại, agent xác
minh cả bundle đang được control trỏ tới; nếu không có LKG hợp lệ và nguồn đầu
không đạt thì agent báo lỗi. Đây là tùy chọn riêng với lệnh preflight ở trên.
Trong giai đoạn xoay khóa, giữ cả khóa cũ và mới (64 byte) để xác minh LKG.


Với service đóng gói, đặt `STRATA_REQUIRED_POLICY=example-api` và
`STRATA_REQUIRE_FULL_ENFORCE=true` trong `/etc/strata/standalone.env` để bật ràng
buộc tương ứng. Mặc định để trống/false; file cấu hình cũ thiếu hai biến vẫn dùng
mặc định từ unit. Cờ này kiểm metadata mode/canary, không tự bật inspection trong
NGINX hoặc bảo đảm một rule sẽ khớp.

## Cài trên node systemd mới

Chuẩn bị gói agent/module cho đúng phiên bản NGINX bằng `deploy/packaging/build.sh`
và bundle bằng `strata-rules release --pack core --policies policies.yaml` với
khóa ký của tổ chức. Không dùng khóa fixture trong repository cho triển khai.
Kiểm toàn bộ release bằng `strata-rules verify --pub /secure/bundle.pub /releases/core`;
key tin cậy phải được cấp qua kênh độc lập. Hai script đi kèm thư mục gói:

```sh
sh /releases/packages/install-standalone.sh --packages /releases/packages \
  --bundle /releases/core/strata-core-example.sbn --pubkey /secure/bundle.pub \
  --policy example-api --listen 127.0.0.1:8080 --upstream 127.0.0.1:9000
```

Bundle tối đa 256 MiB; key có 32 hoặc 64 byte raw. Backend cần được cấu hình riêng. Installer tạo một server/location được inspect,
ghim policy full-enforce, chờ control ổn định và kiểm bundle bằng module NGINX
thật trước khi kích hoạt. Không tự đổi CPU budget, fail mode hay cách đọc body.
Chỉ hỗ trợ listen IPv4:port và upstream host:port (HTTP). Chọn địa chỉ listen theo
phạm vi truy cập cần thiết. Đây không phải cấu hình TLS/reverse proxy hoàn chỉnh.
Từ chối Fleet identity, agent bật sẵn, NGINX đang chạy hoặc Strata đã được cấu hình;
không dùng script này để chuyển mode/nâng cấp một node đang phục vụ.

Lỗi có thể để lại package và trạng thái bundle để chẩn đoán; không có rollback OS
nguyên tử. Nếu lỗi khi kích hoạt, script dừng/disable cặp standalone vừa bật và
khôi phục nginx.conf, gỡ snippet vừa tạo. Kiểm journal, control/key/env và cấu hình
trước khi thử lại; không xóa state hoặc bỏ kiểm chữ ký để vượt lỗi.

## Cập nhật bundle không reload NGINX

Tạo release mới bằng `strata-rules` với bundle-version tăng, đúng compiler/module,
kiểm chữ ký/manifest, policy và kiểm native ở lab trước khi phát hành. Sau đó:

```sh
install -o root -g strata -m 0640 /releases/core/new.sbn \
  /var/lib/strata/standalone/incoming.sbn
mv /var/lib/strata/standalone/incoming.sbn /var/lib/strata/standalone/source.sbn
```

Watcher kiểm chữ ký/policy rồi cập nhật control; worker nạp qua timer, không cần
`nginx -s reload`. Kiểm request benign/attack, event bundle_version, journal và
metrics sau cập nhật. Preflight metadata không thay kiểm native: engine còn kiểm
layout/Hyperscan và có thể giữ bundle cũ khi bản mới bị từ chối. Không coi riêng
control version là bằng chứng worker đang bảo vệ bằng bản mới.

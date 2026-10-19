# Standalone: kiểm bundle trước khi cấu hình route

Lõi agent và service/socket standalone đã được kiểm riêng; installer một lệnh
và nghiệm thu dưới năm phút trên VM sạch vẫn đang làm. Xem
[phạm vi và bằng chứng](../reports/standalone-review.md).

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

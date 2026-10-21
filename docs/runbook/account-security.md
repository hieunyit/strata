# Bảo mật tài khoản và privacy Compact

## Tài khoản cục bộ

Trang **Bảo mật tài khoản** (`#/security`) cho phép người dùng local thiết lập ứng dụng
xác thực TOTP, thay mã khôi phục và xem/thu hồi các phiên của chính mình. OIDC quản lý
MFA tại IdP. Machine credential không dùng các endpoint bảo mật tài khoản local.

Cài mới bằng `strata-control-plane init` tạo khóa mã hóa riêng `keys/local-mfa.key`
(32 byte, dạng hex, mode 0600), độc lập với khóa ký bundle. Cấu hình sinh mới gồm:

```yaml
auth:
  local:
    enabled: true
    mfa_key_file: keys/local-mfa.key
```

Đường dẫn tương đối tính từ file YAML. Với cài đặt cũ, chạy lại `init` khi chưa có
enrollment để tạo khóa còn thiếu, rồi thêm `mfa_key_file` vào cấu hình hiện có. Init
giữ nguyên file cấu hình cũ. Không tự tạo khóa thay thế nếu đã có tài khoản bật MFA;
khôi phục khóa từ bản backup mã hóa. Backup data directory hiện có bao gồm thư mục keys.

Thiết lập cần mật khẩu hiện tại; enrollment ràng buộc vào phiên mở nó và hết hạn sau
10 phút. Thêm secret vào ứng dụng xác thực, nhập mã 6 chữ số rồi lưu 8 mã khôi phục.
Mỗi mã khôi phục chỉ dùng một lần, chỉ được trả về lúc tạo; database giữ hash của mã.
Seed TOTP được mã hóa AES-GCM với tên tài khoản làm associated data. Không ghi seed,
OTP, mã khôi phục hoặc session token vào audit. Giao diện không lưu seed/mã khôi phục
vào browser storage; xóa chúng khỏi màn hình sau khi lưu.

TOTP dùng bước 30 giây, chấp nhận sai lệch một bước; mỗi timestep chỉ thành công một
lần trên tài khoản, kể cả hai đăng nhập đồng thời. Nếu vừa dùng mã để bật MFA hoặc
đăng nhập ở nơi khác, chờ mã mới. Thuật toán và test vectors theo
[RFC 4226](https://www.rfc-editor.org/rfc/rfc4226) và
[RFC 6238](https://www.rfc-editor.org/rfc/rfc6238).

Bật MFA hoặc đổi bảo vệ khôi phục sẽ đăng xuất các phiên khác. Mật khẩu đúng không
tạo được phiên mới khi thiếu MFA; sai mã chịu khóa tài khoản và giới hạn lần thử như
đăng nhập. Phiên cũ chưa xác minh MFA cũng bị từ chối ở mỗi lần xác thực. Mỗi tài khoản
giữ tối đa 100 phiên còn hạn. Danh sách phiên dùng ID riêng, không trả token/hash/IP/UA.

Người vận hành host có thể phục hồi tài khoản khi mất cả ứng dụng và mã khôi phục:

```bash
strata-control-plane admin recover -user example-admin \
  -data-dir /var/lib/strata -reset-mfa
```

Lệnh yêu cầu quyền đọc DSN của host, hỏi mật khẩu mới, xóa enrollment và thu hồi mọi
phiên; audit ghi `system:recover`. Không có API quản trị từ xa tương đương để bỏ MFA.
Không dùng `-reset-mfa` thì phục hồi mật khẩu vẫn giữ MFA. Sau phục hồi, thiết lập lại MFA.

## Privacy của các sink Go

Các sink dùng chung giới hạn P-01: tối đa 64 sensitive fields, 16 regex tuyến tính,
256 byte mỗi regex và chặn văn bản/JSON quá lớn hoặc quá sâu. Ingest lấy cấu hình
privacy từ revision policy trong **bundle của sự kiện**, không lấy draft mới nhất.
Không đọc được cấu hình thì batch không được ACK thành công; spool của agent giữ
retry. Replay sample là best effort: không xác định được privacy thì bỏ mẫu đó.

Lite đọc settings từ bundle đã xác minh chữ ký và áp cùng filter cho JSONL/syslog.
Nếu thiếu metadata/bundle history, chỉ xuất chẩn đoán với payload bị che toàn bộ;
không bỏ kiểm chữ ký/header. Bộ lọc giữ cache tối đa bốn version; engine vẫn kiểm
toàn bộ layout khi nạp. Go filter bổ sung có thể che thô hơn đối với giá trị replay
nhạy cảm; cấu trúc và giá trị thông thường vẫn được giữ.

IP nguồn chuyên biệt vẫn phục vụ GeoIP và tìm kiếm được phân quyền; P-01 `identity:
hmac` giả danh hóa identity. Viewer không nhận full client IP, identity hoặc snippet.
Support bundle tiếp tục dùng allowlist chặt hơn và không lấy raw log/request/config.

## Bản sao audit ra ngoài

Mặc định không gửi gì. Cấu hình riêng một HTTPS receiver và khóa HMAC 32 byte dạng hex:

```yaml
notifications:
  webhook_url: https://receiver.example.test/strata
  key_file: secrets/webhook-signing.key
  audit_export: true
  allow_cidrs: ""
```

Khóa phải ở file riêng mode 0600. URL không chứa username/password, query hay fragment.
Địa chỉ private, loopback, link-local và địa chỉ đặc biệt bị từ chối sau DNS và tại
connection; dial dùng IP đã kiểm, không proxy môi trường, không theo redirect. Chỉ đặt
`allow_cidrs` cho mạng receiver nội bộ đã chủ động tin cậy. TLS luôn được xác minh.

Receiver nhận `X-Strata-Delivery`, `X-Strata-Timestamp`, `X-Strata-Signature`. Signature là
`sha256=` + hex HMAC-SHA256(key, timestamp + newline + delivery ID + newline + body).
Receiver nên kiểm timestamp phù hợp và deduplicate delivery ID. Retry dùng cùng ID;
không thể bảo đảm exactly-once qua mạng khi process dừng sau lúc receiver nhận.

Bản sao gồm timestamp, event ID, action/channel và HMAC pseudonym của subject/resource;
không gồm actor thô, before/after, IP, URI, snippet hoặc secret. Audit gốc trong
PostgreSQL không được gọi là chống sửa. Enqueue nằm trong transaction ghi audit,
không dựa vào cursor ID có thể bỏ sót transaction commit muộn.

Hàng đợi bền giới hạn 10.000 bản ghi, tối đa 5 lần gửi, backoff từ 30 giây tới 4 phút,
lease 60 giây. Sau 4xx/redirect/đích bị cấm thì dừng retry; 429/5xx/lỗi kết nối retry.
Khi đầy, tăng `outbound_settings.dropped` và giữ audit local thành công. Bản ghi terminal
được dọn theo tuổi 30 ngày hoặc nhường chỗ lúc chạm quota. Tắt `audit_export` dừng bản
sao mới và đánh dấu bản audit đang chờ là failed; audit gốc vẫn còn.

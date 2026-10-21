# 04 · Tài khoản, phân quyền và tích hợp tùy chọn

[Trang đầu](README.md) · Trước: [node](03-nginx-nodes.md) · Tiếp: [vận hành](05-operations.md)

## 1. Local auth là phương án mặc định

Không cần Keycloak để quản trị Strata. `init` tạo admin đầu tiên trong PostgreSQL;
password hash và session nằm trong database. YAML bật/tắt cơ chế auth, không phải
danh sách user. Đổi mật khẩu file bootstrap không đổi password user đã tạo.

Sau đăng nhập đầu tiên:

1. Tạo tài khoản riêng cho người soạn policy, người duyệt và quản trị khẩn cấp.
2. Gán vai trò theo công việc và phạm vi ứng dụng/môi trường.
3. Đăng nhập thử bằng từng user, kiểm cả thao tác được phép và bị cấm.
4. Giữ một đường phục hồi host được kiểm soát, không dùng chung admin cho duyệt 4 mắt.
5. C có MFA local ở chương 07; A/B không giả định endpoint MFA đã có.

| Vai trò | Công việc chính | Giới hạn cần nhớ |
| --- | --- | --- |
| `viewer` | Xem dữ liệu được phân quyền | Không full IP/snippet; không ghi policy |
| `operator` | Soạn policy/exception, triển khai khi đủ quyền | Không tự có quyền duyệt; không quản user/token |
| `approver` | Xem bằng chứng và duyệt policy người khác viết | Không tự có quyền soạn/deploy |
| `admin` | Quản trị tài khoản, binding, enrollment, service account | Vẫn không được tự duyệt thay đổi của chính mình |

`operator` có deploy permission ở cấp role; publication bundle toàn cài đặt còn cần
đủ quyền trên mọi policy đưa vào bundle. Vai trò và scope là hai điều kiện khác nhau.
Không suy ra quyền từ việc một nút đang hiển thị; API kiểm lại quyền.

## 2. Phục hồi admin local

Dùng khi khóa/quên mật khẩu, với quyền host đọc DSN. Lệnh ghi audit
`system:recover`, đặt password mới, enable/unlock user và kết thúc session của user.
Nó không tạo user tùy ý và không thay thế SSO/IdP recovery.

Với Compose, chạy trên terminal để nhập mật khẩu kín:

```bash
dc exec control-plane strata-control-plane admin recover \
  -user admin -data-dir /var/lib/strata
```

Nếu không có TTY, dùng file 0600 và bind read-only vào one-off container. Ví dụ
đường dẫn tuyệt đối do tài khoản vận hành sở hữu, cùng UID/GID CP:

```bash
dc run --rm --no-deps -T \
  -v /secure/strata-recovery/new-password:/run/strata/new-password:ro \
  control-plane admin recover -user admin -data-dir /var/lib/strata \
  -password-file /run/strata/new-password
```

Chương 07 mô tả `-reset-mfa` của C. Phục hồi mật khẩu thường không được coi là tắt
MFA. Không sửa hash trực tiếp bằng SQL để né audit. Giữ quyền truy cập host/backup
như quyền quản trị toàn hệ thống vì nó cho phép phục hồi tài khoản.

## 3. Ứng dụng, môi trường và quyền theo phạm vi

B01 thêm inventory ứng dụng/môi trường/route. Đây là cấu hình quyền sở hữu và intent,
không tự viết vhost NGINX: B03 chưa làm. Cần giữ route trong inventory khớp route
thực trên proxy.

Thực hiện trên trang Applications bằng global operator/admin phù hợp:

1. Tạo application, ví dụ `example-api`, điền owner/mô tả theo quy ước nội bộ.
2. Tạo environment riêng cho lab và môi trường phục vụ; không dùng chung credential
   hoặc node identity chỉ vì cùng application.
3. Gắn connector group/node và route với exact host + path prefix, policy reference;
   schema reference chỉ là reference, không bảo đảm registry/runtime enforcement.
4. Kiểm các route chồng lấn và policy được nhiều ứng dụng dùng chung.
5. Admin gán subject vào global/application/environment binding phù hợp.
6. Đăng nhập user scoped: chỉ thấy app/env/node/event đã cấp, thử truy cập ID ngoài
   scope phải bị từ chối hoặc không được trả dữ liệu.

Subject có namespace: `local:<username>`, `oidc:<sub>`, `sa:<id>`. Tên hiển thị giống
nhau không làm hai subject trở thành một người. Duyệt bốn mắt so sánh subject bất biến.
Policy dùng chung đòi hỏi quyền trên mọi reference liên quan; tách policy nếu cần
quyền sửa độc lập giữa ứng dụng.

Xóa binding cuối không khôi phục quyền cũ từ token role: subject đã quản lý binding
bị deny rõ ràng. Với cài cũ chưa từng binding vẫn có đường RBAC global tương thích.
Không xóa binding bừa để “trở về admin”; giữ admin global đã thử trong phiên khác.

Trang Tổng quan theo route có thể chỉ có `events_only`: không có event vi phạm
không chứng minh 100% request đã inspect. Counter toàn node không có chiều host/path
nên không được chia cho application một cách suy đoán.

Service account dùng cho automation, token có TTL và scope permission tường minh;
role không vượt trần scope token. Cất token trong secret manager, thu hồi và phát
hành mới theo vòng đời. Không dùng session admin cá nhân làm token collector/automation.
Không đưa token lên URL query, log hoặc screenshot.

## 4. Bổ sung OIDC/Keycloak

Có thể nối IdP hiện có hoặc overlay Keycloak mẫu. Local và OIDC chạy song song.
Không cần build lại UI/CP khi thêm đúng cấu hình OIDC.

### 4.1. Nối IdP hiện có

Giữ nguyên block local và **thêm** OIDC vào cùng block auth, không khai báo `auth`
hai lần trong YAML:

```yaml
auth:
  local:
    enabled: true
    session_ttl: 8h
  oidc:
    issuer: https://sso.example.test/realms/strata
    audience: strata-api
    roles_claim: realm_access.roles
    ui_client_id: strata-ui
```

Đây là fragment để merge vào YAML, không phải file thay thế đầy đủ. IdP cần:

| Cấu hình | Giá trị/phép kiểm |
| --- | --- |
| Issuer | Khớp chính xác claim `iss` và authority UI nhìn thấy |
| Audience API | Access token có `aud` chứa `strata-api` |
| Subject | `sub` không rỗng, ổn định |
| Role claim | Danh sách tên `viewer`, `operator`, `approver`, `admin` |
| UI client | Public browser client `strata-ui`, redirect origin đúng UI HTTPS |
| Metadata/JWKS | CP truy cập được qua TLS/DNS tin cậy |
| Clock | `exp` hợp lệ; `iat`/`nbf` không quá tương lai 2 phút |

Dùng access token cho API, không dùng ID token thay thế. Chỉ gán role được Strata
biết; role lạ không tự thành admin. Đừng dán token lên website giải mã token.
`discovery_url` phục vụ đường metadata nội bộ khác issuer, không thay issuer token.

Validate/restart theo chương 02, thử SSO bằng user viewer trước, rồi admin khác.
Chỉ cân nhắc `local.enabled: false` sau khi một admin OIDC đã thực sự đăng nhập thành
công; CP có guard chặn tắt local quá sớm. Vẫn cần kế hoạch khôi phục khi IdP ngừng.
Tắt local chỉ làm user local không đăng nhập được, không chuyển user/password sang IdP.

### 4.2. Overlay Keycloak đi kèm

Overlay dùng image ghim và `start-dev`, có volume riêng. Đây là mẫu tích hợp để thử;
không phải triển khai Keycloak HA/production đã được nghiệm thu. Thử trên loopback:

```bash
export STRATA_COMPACT_OVERLAY="$PWD/deploy/compact/compose.keycloak.yaml"
deploy/compact/install.sh -name waf.example.test
```

Wrapper nhận overlay; với Compose trực tiếp phải thêm `-f`:

```bash
dc() {
  docker compose -p strata-compact \
    -f deploy/compact/compose.yaml \
    -f deploy/compact/compose.keycloak.yaml \
    --env-file deploy/compact/.state/env "$@"
}
dc ps
```

Mặc định IdP ở `http://127.0.0.1:8180`, UI ở `http://127.0.0.1:8080`, dùng được khi
trình duyệt chạy trên chính host. Trong YAML CP, issuer và metadata path của mẫu:

```yaml
auth:
  local:
    enabled: true
  oidc:
    issuer: http://127.0.0.1:8180/realms/strata
    discovery_url: http://keycloak:8080/realms/strata
    audience: strata-api
```

HTTP trên đây chỉ mô tả loopback/network thử của overlay. Trước dùng từ máy khác,
đặt IdP/UI sau HTTPS, đặt `STRATA_IDP_URL` và `STRATA_UI_URL` đúng origin công khai,
kiểm hostname/redirect/client config trong realm. Không để browser máy khác dùng
issuer `127.0.0.1` của nó. Import realm chủ yếu cho tạo mới; đừng giả định đổi env
sẽ cập nhật toàn bộ realm đã tồn tại. Quản trị thay đổi realm bằng công cụ IdP.

Admin Keycloak bootstrap là `admin`, password sinh trong `.state/env`; không phải
admin local của Strata. Tạo user IdP và gán realm roles; không dùng chung password.
Đọc secret qua phương tiện bảo mật, không in toàn `.state/env` vào log hỗ trợ.

## 5. Object store S3/MinIO tùy chọn

Filesystem đủ cho Compact một máy. Chỉ thêm S3 khi có yêu cầu lưu trữ/vận hành cụ
thể. Dịch vụ MinIO không có trong Compose mặc định; tự triển khai hoặc dùng endpoint
được tổ chức cung cấp, TLS tin cậy, bucket/quyền và backup riêng.

Thay toàn bộ `bundles.storage.local` bằng `s3` trong cấu hình, không giữ cả hai:

```yaml
bundles:
  storage:
    s3:
      endpoint: objects.example.test:443
      bucket: strata-bundles
      secure: true
      access_key_file: secrets/s3-access-key
      secret_key_file: secrets/s3-secret-key
```

Đây là fragment storage; giữ nguyên signer và các khóa bundles khác. Secret 0600
phải tồn tại trong container. Chỉ cấp quyền bucket cần cho đọc/ghi/dọn artifact theo
triển khai, không cấp admin toàn object store.

Đổi backend không tự chép artifact cũ. Lập danh mục bundle/replay/release đang được
tham chiếu, copy bằng công cụ storage có kiểm hash, thử đọc bằng CP và node trước
khi ngừng backend cũ. Không xóa bản cũ trước khi xác nhận restore được. Backup Strata
không đóng gói bucket S3; phải backup bucket, lifecycle và credential policy riêng.

## 6. Vault signer tùy chọn và xoay khóa

File signer là default. Vault Transit cần key Ed25519 không exportable, policy/token
quyền ký phù hợp và public verifier key tương ứng. Bỏ `signer.key_file` khi đổi type:

```yaml
bundles:
  signer:
    type: vault
    public_key: keys/bundle.pub
    vault:
      address: https://vault.example.test
      transit_mount: transit
      transit_key: strata-bundles
      key_version: 0
      token_file: secrets/vault-token
```

Không có Vault service trong Compose mặc định; cấu hình token/CA/network do đội
vận hành Vault cung cấp. Không tắt TLS để vượt lỗi trust. Vault không thay PKI Fleet
hoặc mã hóa tự động PostgreSQL/ClickHouse.

Xoay signer phải phân phối verifier key mới cho node trước khi ký chỉ bằng key mới.
Module hỗ trợ public key raw 32 byte hoặc hai key nối 64 byte trong giai đoạn chuyển;
không tự đổi sang PEM/hex. Giữ key cũ để xác minh artifact lịch sử/rollback. Chỉ xóa
key cũ sau khi kiểm mọi node và khả năng rollback. Quy trình thử có tại
[lab-key-rotation.sh](../../tests/e2e/lab-key-rotation.sh); đó là script lab, không
chạy nguyên xi vào môi trường phục vụ.

Node certificate có lifetime 24 giờ, agent tự gia hạn khi nối được CP; mất kết
nối lâu có thể dẫn tới hết cert và cần xử lý lại enrollment. Fleet server cert do
init tạo có lifetime 365 ngày, CA mặc định 10 năm; kiểm `NotAfter` thực tế thay vì
chỉ dựa vào ngày cài. Init giữ PKI đã có, không phải lệnh gia hạn certificate. Lập lịch theo `NotAfter`,
quy trình cấp lại server cert đúng SAN và trust node; CA rotation cần giai đoạn cùng
tin CA cũ/mới. Không xóa cả PKI rồi init lại trên một fleet đang hoạt động.

## 7. Metrics, GeoIP và bot ranges

Grafana/VictoriaMetrics là lựa chọn bổ sung. CP metrics không có auth riêng; chỉ bind
mạng scraper tin cậy, giới hạn firewall. `127.0.0.1:9100` trong container không tự
trở thành port host. Nếu scrape từ container khác, bind interface nội bộ và cấu
hình network/port có chủ đích. Agent packaged mặc định loopback 9469.

Dùng dashboard/alerts trong [deploy/monitoring](../../deploy/monitoring) và
[runbook](../runbook/README.md), nhưng kiểm label/job/port đúng topology đang dùng.
Đừng sao chép địa chỉ lab/staging vào scrape config của bản cài mới.

GeoIP nhận file `.mmdb` City/ASN do vận hành cấp và tuân thủ license; tham khảo
[runbook GeoIP](../runbook/geoip.md). URL updater dùng biến `STRATA_GEOIP_CITY_URL`,
`STRATA_GEOIP_ASN_URL`; không đặt đồng thời URL và file cho cùng đường cấu hình
updater. URL có credential cần cơ chế inject secret, không ghi vào Git/log.

`good_bots.interval: 0` không tự fetch ngoài; đặt thời gian khác khi đã cho phép
kết nối tới nguồn crawler. Dữ liệu tải mới đi vào bundle **phát hành sau đó**, không
làm worker hiện tại đổi rule ngay. Xác minh freshness và release như thay đổi policy.

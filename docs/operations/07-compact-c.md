# 07 · Cấu hình và vận hành phần Compact C

[Trang đầu](README.md) · Trước: [backup và nâng cấp](06-backup-upgrade.md)

**Trạng thái tích hợp 22/10/2026:** C03/C01/C02/C04/C05 và cẩm nang đã merge vào
`main` qua chuỗi PR #321–#395. Chương này áp dụng cho binary có C; không thêm khóa C
vào binary A/B cũ. Merge không tự deploy, bật collector hay thực thi OpenAPI runtime.
Discovery vẫn mặc định tắt, cần phê duyệt pháp chế thực tế để bật feed riêng.

[Báo cáo tổng và thứ tự review/merge](../reports/compact-c-implementation.md) ghi
bằng chứng kiểm thử và giới hạn. Migration C dùng từ 0035 đến 0044; nâng từ A/B phải
backup và thử restore/nâng cấp trước, không tự chạy SQL lẻ vào database.

## 1. C03: MFA local, phiên và privacy

### 1.1. Chuẩn bị khóa MFA

Init mới có C tạo independent 32-byte hex key `keys/local-mfa.key` mode 0600. Cấu hình
local bổ sung đường dẫn, giữ user/password trong PostgreSQL:

```yaml
auth:
  local:
    enabled: true
    session_ttl: 8h
    mfa_key_file: keys/local-mfa.key
```

Cài cũ nâng lên C: chạy lại init với cùng data dir và DSN để tạo file còn thiếu khi
chưa có enrollment, rồi bổ sung `mfa_key_file` vào YAML. Init giữ nguyên YAML cũ và
không thay file đã có. Wrapper install có thể hỏi password dù admin đã tồn tại;
không hiểu lần chạy lại là reset tài khoản. Backup trước khi chạy thao tác chuẩn bị.

Nếu đã có MFA mà key mất, **restore đúng key từ backup**, không sinh key khác để vượt
lỗi. Seed trong PostgreSQL mã hóa AES-GCM bằng key này, gắn với tên user; signer key
không thay thế được. Key MFA phải đi cùng bản sao PG phù hợp khi phục hồi.

### 1.2. Thiết lập và phục hồi

Trang Security `#/security`, dành cho user local:

1. Nhập password hiện tại, bắt đầu enrollment trên phiên đang dùng.
2. Thêm secret vào authenticator; enrollment hết hạn sau 10 phút.
3. Nhập OTP 6 chữ số, lưu 8 recovery codes qua kênh riêng an toàn.
4. Xóa secret/recovery khỏi màn hình sau khi lưu; không chụp ảnh đưa lên ticket.
5. Thử login bằng password+OTP; kiểm/thu hồi phiên cũ của chính mình.

TOTP bước 30 giây, lệch một bước; mỗi timestep chỉ chấp nhận một lần. Mã vừa dùng
bật MFA/login không dùng lại ngay ở phiên khác, phải đợi bước mới. Recovery code một
lần, database giữ hash. Bật MFA/thay recovery bảo vệ phiên bằng thu hồi các phiên
khác; phiên cũ chưa MFA không tự có quyền tiếp tục.

OIDC dùng MFA của IdP. Machine token không dùng MFA local endpoints. Mất cả OTP và
recovery, host operator phục hồi có audit, thêm `-reset-mfa` vào lệnh recover:

```bash
dc exec control-plane strata-control-plane admin recover \
  -user admin -data-dir /var/lib/strata -reset-mfa
```

Thiết lập lại MFA sau login. Không có API admin từ xa để bỏ MFA tương đương host
recovery; không sửa DB/hash/seed trực tiếp.

### 1.3. Privacy theo bundle

C03 dùng filter chung cho sink Go/ingest/Lite/replay và đọc/xuất dữ liệu. Policy
privacy của event được lấy từ revision trong **bundle phát sinh event**, không phải
policy draft mới nhất. Thiếu metadata cần thiết thì không ACK ingest thành công;
agent giữ retry. Replay không xác định được privacy sẽ bỏ mẫu theo đường best effort.

Cấu hình qua policy editor/schema của đúng source, rồi replay/review/release. Không
thêm `privacy` vào root YAML CP vì nó là setting policy. Giới hạn gồm 64 sensitive
fields, 16 regex tuyến tính, 256 byte/regex, chặn text/JSON quá lớn/sâu. Test bằng
payload lab có dấu nhạy cảm giả, kiểm event/export/Lite/replay trước khi dùng thật.

Identity HMAC không đồng nghĩa mọi IP đều bị xóa: source IP có trường chuyên biệt
cho GeoIP/search có phân quyền. Viewer vẫn bị che full IP/identity/snippet. Support
bundle dùng allowlist chặt riêng. Không thu body/header thật chỉ để “thử privacy”.

## 2. C03/C04: webhook và audit export

Mặc định không gửi gì ra ngoài. Trước bật, thống nhất receiver, dữ liệu được nhận,
TLS/DNS, mạng tin cậy, quy trình kiểm chữ ký/dedupe và owner chịu trách nhiệm.
Khóa webhook là 32 byte dạng hex, file 0600, độc lập với signer/MFA/discovery.

```yaml
notifications:
  webhook_url: https://receiver.example.test/strata
  key_file: secrets/webhook-signing.key
  audit_export: false
  allow_cidrs: ""
```

Fragment này không tạo receiver hoặc key. Provision key qua secret manager, mount
vào CP và cấp cho receiver qua kênh riêng. Audit export chỉ bật `true` khi muốn gửi
bản sao metadata audit mới; cảnh báo vận hành C04 dùng cùng transport khi được cấu
hình. Không có receiver thì sự cố vẫn xem trên UI, không đồng nghĩa đã gửi thông báo.

URL HTTPS không chứa user/password, query, fragment. Không theo redirect/proxy môi
trường; kiểm DNS và IP lúc connect chống SSRF/rebinding. Private/loopback/link-local
mặc định bị chặn. Chỉ khai báo `allow_cidrs` mạng receiver nội bộ được tin chủ động,
ví dụ subnet nhỏ của dịch vụ đã xét, không allow cả Internet/private space cho tiện.
TLS vẫn kiểm bình thường, kể cả đích private.

Receiver phải kiểm các header:

| Header | Cách dùng |
| --- | --- |
| `X-Strata-Delivery` | ID chống xử lý trùng; retry giữ nguyên ID |
| `X-Strata-Timestamp` | Kiểm freshness trong cửa sổ receiver quy định |
| `X-Strata-Signature` | `sha256=` + hex HMAC-SHA256 |

Dữ liệu ký là `timestamp + "\n" + delivery ID + "\n" + raw body bytes`. Không parse
rồi serialize JSON trước khi xác minh, vì bytes có thể đổi. So MAC constant-time,
lưu dedupe receipt và xử lý retry an toàn. Không có bảo đảm exactly-once qua mạng.

Outbox PG tối đa 10.000 bản ghi, lease 60 giây, tối đa 5 lần gửi; backoff 30/60/120/
240 giây. 429/5xx/kết nối lỗi retry; 4xx khác/redirect/đích bị cấm dừng retry. Terminal
retention 30 ngày, có thể dọn sớm nhường quota. Audit local không fail chỉ vì queue
bản sao đầy; dropped phải được theo dõi. Tắt audit export dừng bản sao mới và đánh
failed audit deliveries còn chờ, không xóa audit gốc.

Audit copy chỉ có metadata/pseudonym, không raw subject/resource/IP/before-after.
Incident payload dùng opaque IDs/fixed cause/state/count, không app name, node ID,
URI hoặc raw error. Audit gốc PostgreSQL không được gọi là chống sửa. Kiểm receiver
bằng dữ liệu tổng hợp được phép; không in key/signature payload nhạy cảm vào log.

## 3. C01: tìm kiếm, điều tra và evidence

Trên Events, chọn app/env và time window đúng. Lưu search private của mình hoặc chia
sẻ theo nhu cầu; opaque link không cấp quyền mới, API kiểm scope lại lúc mở/chạy.
Saved search hết hạn 90 ngày, tối đa 100/user, danh sách 50. Viewer không được dùng
sensitive filters chỉ vì nhận một link từ operator.

Case annotation gồm status/assignee/note, TTL 30 ngày, etag riêng. Đây là hồ sơ xử
lý, **khác** phân loại false positive: đổi status case không tự đưa mẫu vào automation
FP. Assign cho chính mình hoặc subject đủ binding cùng route/env/node; không gán
user local disabled. Kiểm etag nếu hai người sửa cùng lúc.

Similar events dùng policy/method/host/path/first rule chính xác, ±12 giờ, tối đa 200;
không phải máy học khẳng định cùng kẻ tấn công. Đề xuất geo/ASN dùng nhãn GeoIP đã
lưu tin cậy, tạo draft/log+replay. Reviewer vẫn duyệt release độc lập; proposal rate
là đo lường, không tự tạo distributed rate-limit enforcement mới.

Evidence CSV là operation bền:

1. Chọn truy vấn/time/app/env, tạo export, lưu operation ID.
2. Chờ operation thực sự xong; đừng coi HTTP nhận việc là file đã xong.
3. Download trong 24 giờ khi còn đủ quyền, kiểm SHA-256 và lưu theo quy trình evidence.
4. Ghi nhận giới hạn: tối đa 10.000 dòng, 16 MiB, cửa sổ 31 ngày, thời gian làm 5 phút.

Export ghim owner/scope ceiling; cấp thêm quyền sau đó không làm file rộng hơn.
Thu hồi quyền có thể làm job/download bị từ chối. Fenced lease 6 phút, tối đa 3 lần
crash; file/receipt hết hạn được purge. CSV có phòng công thức spreadsheet, nhưng
người dùng vẫn phải mở trong môi trường theo chính sách dữ liệu. Không dùng evidence
export như backup toàn ClickHouse; danh sách riêng chỉ giữ 20 export gần nhất.

## 4. C02: rule catalog và vòng đời exception

Rules/Packs hiển thị catalog đã cấu hình: source/version/CVE/attack/owner/review,
canonical digest cả condition và trạng thái refresh. Giữ tối đa 20 snapshots.
**Catalog không chứng minh pack/rule đã activate trên từng node.** Active count theo
policy revision cũng không phải per-rule activation.

Rule costs là samples top-eight trong 24 giờ; chưa có mẫu là unknown, không phải
cost bằng 0. Event/FP số liệu chịu scope. Rule-release changelog có `rule_digests`
để nhận ra sửa nội dung cùng ID; manifest cũ thiếu digest phải hiện chưa biết.

Exception inventory cho biết app/env/method/host/path/field/rule/owner/reason/TTL/
review/replay và các revision current/latest-approved/node-active. Viewer bị ẩn reason.
Expiry runtime được kiểm ở mỗi transaction mới, không chờ reload; vẫn cần cleanup
metadata/draft khi hết hạn.

- Không tạo exception mới path root `/`; legacy root giữ nguyên có giới hạn, không
  được sửa TTL/scope để kéo dài ngoại lệ rộng.
- Cleanup/revoke tạo draft+replay theo etag/request ID, không tự publish.
- Worker quét theo phút tối đa 100 mục; chỉ tự draft khi current==approved để giữ
  draft con người. Công việc cũ có thể bị supersede khi approved mới xuất hiện.
- Queue maintenance quota 10.000, terminal retention 30 ngày.
- **Chưa thu exception-hit telemetry**: usage/unused là unknown. Không tự xóa exception
  vì UI không thấy hit, phải dựa TTL, owner, evidence và review.

Thử exception trên lab cả match/không match, method/host/path/field, hết hạn và benign;
so đúng version ở node. Sau sửa vẫn đi qua replay, duyệt độc lập và release.

## 5. C04: incidents và báo cáo

Trang Operations nhóm incidents theo nguyên nhân và global/app-env: heartbeat,
certificate, bundle drift, fail-open/drop growth, spool, artifact disk, ingest,
operation lỗi, backup và exception expiry. Worker theo phút, tối đa 10 env/cycle;
không có cam kết mọi env được quét trong cùng một phút.

Counter tích lũy cần baseline mới và tăng trưởng; observation đầu/reset/stale là
unknown. Unknown không tự đóng incident. Cooldown một giờ; acknowledge giảm thông
báo tới khi có recovery đã biết rồi tái diễn. Incidents quota 10.000, retention 30
ngày, list 200 mới nhất; đây không thay kho audit/sự kiện dài hạn.

Báo cáo theo app/env là opt-in, chu kỳ 24 hoặc 168 giờ UTC, không phải lịch cron giờ
địa phương. Tạo schedule đúng scope rồi kiểm report lần đầu:

1. Kiểm quyền đầy đủ trên environment và etag application hiện tại.
2. Chọn chu kỳ, lưu schedule; ghi nhận thời điểm UTC dự kiến.
3. Chờ worker tạo report, xem khoảng thời gian và nguồn đã có/chưa có.
4. Download bằng user vẫn đủ scope, lưu nếu cần vượt retention hệ thống.

Report chứa **số event bảo mật**, không phải toàn bộ HTTP requests; health chụp lúc
generate, không dựng lại health của cả kỳ. Nguồn thiếu/unavailable là unknown.
Thay application etag làm schedule pause, report scope cũ có thể bị ẩn; xem/kiểm lại
binding rồi cập nhật schedule thay vì bỏ qua cảnh báo.

Giới hạn: 1.000 schedules, 10.000 reports, body 16 KiB/report, retention 30 ngày,
list 32/env; mỗi cycle tối đa 5 report đến hạn, lease 2 phút. Queue đầy sẽ defer,
không tự tiến lịch và giả vờ report đã tạo. Tổ chức cần theo dõi chậm lịch/backup
thật, không dựa duy nhất vào việc có cấu hình schedule.

## 6. C05: API discovery mặc định tắt

Không có collector tự cài trên NGINX; **không tự lấy violation events làm toàn traffic**.
C05 nhận feed riêng từ adapter backend/access-log tin cậy sau phê duyệt pháp chế.
Chỉ thêm các khóa sau khi binary đã có C; trạng thái an toàn mặc định:

```yaml
discovery:
  enabled: false
  approval_reference: ""
  approval_expires_at: ""
  trusted_collectors: []
  identity_key_file: ""
```

Muốn bật cần đồng thời có phê duyệt **thật**, reference có thể truy vết, hạn RFC3339
ở tương lai không quá 366 ngày, independent key 32-byte hex/0600, tối đa 32 subject
`sa:` collector được tin, token machine scope tường minh `discovery:ingest` và role
đủ quyền. Ordinary local/OIDC session không được submit, kể cả admin. Cấu hình này
là attestation của operator, không thay quy trình pháp chế. Không dùng ngày/reference
mẫu để vượt guard.

Provision collector theo contract `POST /v1/discovery/observations` của OpenAPI:
≤100 observations/batch, body ≤256 KiB. App/env/request ID rõ ràng; observation ID là
UUID canonical để dedupe, route hợp lệ, method/path/media/body size/time và kết quả
backend thật. Backend status 200–299, `backend_response: true` là **attestation của
collector**, CP không tự quan sát socket backend. Không giả trường này từ WAF event.

Thời điểm trong 24 giờ qua, không quá 5 giây tương lai; body size 0–16 MiB, path ≤2048
byte, content type ≤256 byte. Chỉ gửi metadata được contract yêu cầu; không body,
cookie, Authorization/header thô. IP nguồn chỉ được dùng trước persistence để HMAC
app/env/day; query bỏ, identifier/segment lạ mask `{paramN}` trước lưu. Nhiều route
khác có thể gộp vì masking, nên proposal cần review bằng kiến thức ứng dụng.

Đủ điều kiện proposal cần ≥20 observations còn hạn và khoảng quan sát ≥10 phút;
phải có ít nhất một ngày UTC đạt ≥3 nguồn địa chỉ khác nhau. Tổng sample có thể
trải nhiều ngày; không cộng nguồn của nhiều ngày để vượt ngưỡng đa dạng. Nguồn địa
chỉ khác không chứng minh người dùng độc lập. Quota: 100.000 samples global, 10.000
samples/env, 1.000 endpoint khác nhau/env+scope và 10.000 batch receipts global.
Samples+receipts giữ 7 ngày; proposal
1.000 global/20 env, TTL 30 ngày; retention vẫn chạy khi disabled.

Discovery UI cho paste/index baseline OpenAPI 3.0/3.1, xem evidence/diff, tải tài liệu
đề xuất và tạo draft+replay nguyên tử gắn proposal/version/digest. Duyệt **đúng version**
trong review panel; stale baseline/binding cần cập nhật, không ghi đè.

Đây là operation index giới hạn, không phải full validator: upload API 128 KiB,
parser 1 MiB, 20.000 YAML nodes/depth 32/1.000 paths/2.000 operations; từ chối alias,
duplicate keys, remote refs và path không hợp lệ. Local refs/general JSON Schema
không được đánh giá toàn diện.

**Hiện chỉ đề xuất tài liệu (`documentation_only`), chưa enforce OpenAPI ở engine.**
Metadata `api_discovery` không được compiler đưa vào signed runtime bundle. Download
có `x-strata-mode: documentation_only`; reviewer approve không biến nó thành cơ chế
chặn endpoint/JSON tự động. Không dựa vào tính năng này để cam kết positive security
model đã bảo vệ traffic. Không bật telemetry thật chỉ để làm giao diện hết trạng
thái disabled; để tắt khi chưa đáp ứng pháp chế/collector/retention/owner vận hành.

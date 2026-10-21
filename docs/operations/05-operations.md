# 05 · Phát hành policy và vận hành hằng ngày

[Trang đầu](README.md) · Trước: [bảo mật](04-security-integrations.md) · Tiếp: [backup](06-backup-upgrade.md)

## 1. Phân biệt các loại trạng thái

| Trạng thái | Chứng minh điều gì? | Chưa chứng minh |
| --- | --- | --- |
| Policy draft đã lưu | Database có phiên bản mới | Worker đã dùng phiên bản đó |
| Replay `DONE` | Operation đã chạy xong | Không có FP hoặc đủ traffic đại diện |
| Policy approved | Người khác duyệt đúng phiên bản | Đã publish bundle |
| Release prepared | Snapshot artifact/bằng chứng đã ghim | Node desired đã đổi |
| Release approved | Người khác duyệt hash/replay snapshot | Rollout đã xong |
| Rollout `DONE`/node actual | Trạng thái phân phối được báo | Mọi request trên route đã được inspect đủ |
| Không có event | Không thấy vi phạm trong nguồn truy vấn | Không có traffic, không có tấn công hoặc coverage 100% |

Hãy kiểm cấu hình route và request thật cùng telemetry. Không dùng một trạng thái
UI xanh thay cho nghiệm thu luồng từ client tới backend.

## 2. Luồng policy từ shadow tới enforce

### 2.1. Chuẩn bị

Chọn app/env, route và group thử đã được phép. Có ít nhất hai subject độc lập:
người soạn và approver. Ghi lại policy/bundle hiện hành, baseline và cách phục hồi.
Không dùng cùng tài khoản ở hai trình duyệt để giả lập bốn mắt.

Trên UI Policies:

1. Tạo/chọn policy đúng tên NGINX `strata_policy`, bắt đầu mode shadow.
2. Chỉnh rule/body/privacy và scope dự kiến; các tính năng C chỉ dùng khi đã có C.
3. Lưu draft với etag mới nhất. Nếu conflict, tải lại, so diff và áp lại thay đổi;
   không bỏ etag để ghi đè thay đổi của người khác.
4. Theo dõi replay tự tạo cho **đúng version** của draft. Khi operation fail, xem
   nguyên nhân compiler/corpus/storage/capability thay vì tạo liên tục draft mới.
5. Đọc diff, replay counts, các trường hợp benign mới bị block/would-block và giới
   hạn nguồn mẫu. `DONE` là điều kiện cần, không phải phê duyệt tự động.
6. Gửi duyệt. Người khác mở cùng version/diff/replay, approve hoặc reject có lý do.

Không chỉnh draft trong lúc reviewer nghĩ họ đang duyệt bản cũ. Sửa tiếp tạo version
mới thì phải xem replay và duyệt bản mới. Tài liệu API chuẩn ở
[admin.swagger.json](../spec/admin.swagger.json) và [OpenAPI](../spec/openapi.yaml),
không dùng JSON body đoán từ tên nút.

### 2.2. Chuẩn bị immutable release

Trên trang Releases bằng người có quyền global cần thiết:

1. Chuẩn bị release sau khi policy target có bằng chứng/duyệt hợp lệ.
2. Kiểm danh sách policy versions, rule/compiler/input digests, artifact hash,
   replay operation IDs, baseline và phương pháp canary được ghim.
3. Kiểm khả năng tương thích của tất cả node target: unknown cần điều tra, không
   được tự coi là hỗ trợ. Manifest/capability có thể chặn publish.
4. Người khác duyệt chính hash và map replay của release. Release thay đổi phải
   chuẩn bị/duyệt lại, không sửa trực tiếp artifact đã duyệt.
5. Deploy release, lưu release ID, bundle version, rollout ID và request receipt.

Bundle chứa trạng thái toàn cài đặt nên publication là hành động global. Người chỉ
được cấp app/env có thể soạn/replay/duyệt trong scope nhưng không được đọc/phát hành
snapshot global. Không tạm cấp admin rộng chỉ để tránh một lỗi scope chưa hiểu.

Chuẩn bị release chưa ghi bundle deployed hay desired node. Deploy mới cấp header
version tăng, ký, ghi bundle/rollout/desired và receipt nguyên tử. Retry cùng thao
tác dùng receipt hiện có; nếu timeout phía proxy, đọc lại trạng thái trước khi bấm
lần nữa. Không tự sửa artifact trong storage.

### 2.3. Theo dõi canary/rollout

Default waves: node đầu, sau đó 10% và 100% tổng target; đây là số node phân phối,
khác với tỷ lệ request canary trong policy. `rollouts.soak` là thời gian chờ sau khi
wave ACTIVE, default 0. Không nhầm thời gian soak với yêu cầu mẫu tối thiểu canary.

Canary so sánh các nhóm được định nghĩa bởi hệ thống; default cần 200 request mỗi
nhóm. Ít traffic hoặc nguồn stale là chưa đủ bằng chứng. Block-rate tăng không tự
có nghĩa FP. Đọc thêm lỗi 5xx, latency, traffic và ca benign do người vận hành xác
minh. Không gọi mọi vi phạm là tấn công đã được xác nhận.

Theo dõi từng node: heartbeat, desired/actual bundle, apply error và worker version.
Nếu baseline hiện tại khác baseline ghim trong release, UI/API có thể yêu cầu xác
nhận baseline cụ thể. Kiểm nguyên nhân thay đổi rồi mới xác nhận; đổi ngưỡng canary
cần release mới, không áp lén vào snapshot đã duyệt.

### 2.4. Chuyển enforce

Sau thời gian quan sát được người chịu trách nhiệm chấp thuận:

1. Sửa policy từ shadow sang mức canary/enforce đã quyết định.
2. Lặp lại draft → replay → duyệt → release → deploy.
3. Đảm bảo route NGINX không còn ép `strata_mode shadow` khi muốn policy quyết định.
4. Kiểm benign, payload thử được phép, block ID, backend response và inspection.
5. Chốt biên bản route/node/mode/bundle; tiếp tục theo dõi FP và fail mode.

Không có thao tác tự động đổi mọi route của NGINX trong B03; chỉnh route do người
vận hành proxy quản lý và review độc lập.

## 3. Rollback và khẩn cấp

Rollback phát hành lại nội dung artifact lịch sử bằng **bundle version mới cao hơn**.
Node chống downgrade; chép bundle version cũ vào thư mục không phải rollback hợp lệ.

Ưu tiên luồng rollback trên Releases:

1. Nếu rollout đang chạy gây ảnh hưởng, dừng/abort theo quyền và quy trình vận hành.
2. Chọn release/artifact tốt lịch sử, kiểm policy/rule/schema và phạm vi tác động.
3. Chuẩn bị rollback release. Đọc cảnh báo bằng chứng lịch sử và baseline hiện tại.
4. Người khác duyệt, xác nhận baseline đúng, deploy và theo dõi mọi node.
5. Kiểm benign/attack trên lab/route được phép, worker actual và spool/event.

Rollback B04 giữ nội dung rule/schema từ artifact lịch sử, không biên dịch lại bằng
rule files hiện tại. Giữ verification key lịch sử khi xoay signer. Không khẳng định
replay lịch sử đại diện cho traffic mới; cần xem tác động và bằng chứng còn phù hợp.

Trong khi chờ duyệt có các thao tác giảm tác động đã phân quyền: ép shadow/tắt rule
khẩn cấp theo runbook. Mỗi thao tác có người chịu trách nhiệm, thời hạn và điều kiện
kết thúc. Shadow vẫn kiểm/ghi quan sát; tắt module làm mất inspection. Không để trạng
thái tạm kéo dài sau sự cố vì đã quên bỏ override.

[Runbook sự cố](../runbook/README.md) có ép shadow, breaker và kill switch. Cần phân
biệt rollback policy/bundle với rollback binary/schema PostgreSQL ở chương 06.

## 4. Lịch vận hành đề xuất

Các mốc dưới là lịch tổ chức có thể áp dụng, không phải worker tự động của A/B.

| Chu kỳ | Công việc | Bằng chứng lưu |
| --- | --- | --- |
| Mỗi ca/ngày | Health, node stale, cert, desired/actual, fail-open/body skip/drop/spool | Thời điểm, nguồn, mục cần xử lý |
| Mỗi ngày | Backup thành công và đã chuyển ra ngoài host | Archive/hash, exit code, vị trí bản sao |
| Mỗi ngày | Dung lượng/inode PG/CH/artifact/backups, error/OOM/restart | Mức dùng, tốc độ tăng, dự báo |
| Mỗi lần release | Diff, replay, review độc lập, capability, rollout, kiểm route | Version/hash/reviewer/rollout IDs |
| Mỗi tuần | FP có xác minh, exception TTL, stale rule/catalog, credential/cert sắp hết hạn | Owner và hạn xử lý |
| Định kỳ theo RTO/RPO | Restore vào môi trường cô lập, kiểm truy cập và publish kế tiếp | Thời gian thực, thiếu hụt dữ liệu, kết quả |
| Sau đổi quyền | Kiểm user scoped, token bị thu hồi, quyền reviewer | Phép thử allow/deny |

Log Docker cần rotation ở Docker daemon/Compose override theo chính sách host;
Compose Compact chưa đặt `logging.max-size/max-file`. Đừng cho rằng TTL ClickHouse
xử lý cả stdout Docker/journal/backup. Không log body, Authorization/cookie hoặc URI
chứa secret để chẩn đoán tiện hơn.

## 5. Health và doctor

Trang Health `#/health` dùng `GET /v1/health`, có xác thực và scope `nodes:read`.
Nó xem PostgreSQL/lease, ClickHouse, artifact disk, ingest, operation lỗi, heartbeat,
cert, bundle drift, fail-open/body skipped/breaker và spool. Dữ liệu quá 90 giây
là stale; chưa có nguồn là unknown. Tài khoản scoped không được xem counter toàn
node không thể phân bổ đúng route.

Dùng hàm `dc` chương 01:

```bash
curl --fail --silent --show-error http://127.0.0.1:8080/healthz
curl --fail --silent --show-error http://127.0.0.1:8080/readyz
dc ps
dc logs --since=15m --tail=200 control-plane
```

Doctor chạy binary với cùng YAML/secrets, đọc schema và trạng thái, không migrate,
không lấy lease và không khởi động workers:

```bash
dc exec -T control-plane strata-control-plane doctor \
  -config /var/lib/strata/config.yaml -json
```

**Compose mặc định truyền username ClickHouse bằng flag `strata`, nhưng subcommand
không kế thừa flag tiến trình chính.** Thêm `events.clickhouse.username: strata` vào
YAML theo chương 02 trước khi dùng doctor, nếu init cũ chưa sinh khóa đó. Doctor có
thể báo CH lỗi vì dùng user `default` dù process chính đang dùng `strata`.

| Exit code | Cách đọc |
| --- | --- |
| `0` | Nguồn được kiểm healthy |
| `1` | Lỗi lệnh/config/xuất file |
| `2` | Có degraded/stale/unavailable |
| `3` | Có unknown, không có lỗi nhóm 2 |

Doctor không thấy queue trong process CP đang chạy; disk PG/CH từ xa cũng chưa có
nguồn. Mã 3 có thể là giới hạn quan sát, không phải database hỏng. Đọc từng check
trước khi gắn doctor thành healthcheck tự restart.

Gói hỗ trợ chỉ chứa allowlist, không chép raw request/config/log. File đích phải chưa
có, đường dẫn phải ghi được bởi UID CP:

```bash
dc exec -T control-plane strata-control-plane doctor \
  -config /var/lib/strata/config.yaml \
  -support-bundle /var/backups/strata/support-example-01.tar.gz
```

Doctor vẫn có thể exit 2/3 sau khi xuất file thành công. Kiểm sự tồn tại và nội dung
archive trong kênh bảo mật; không tự gửi cho bên ngoài. Không gói `.state/env`, PKI,
DSN hoặc spool thô vào ticket.

## 6. API và automation

Ưu tiên UI và client sinh từ API contract để thao tác ghi. HTTP bearer token qua
header; không query token. Với automation dùng service account scope tối thiểu và
secret injection, tránh đặt literal credential trong shell history/process args.

| API | Vai trò vận hành |
| --- | --- |
| `GET /v1/health` | Ảnh chụp sức khỏe có scope |
| `GET /v1/releases` | Release global, có phân trang |
| `GET /v1/releases/{id}` | Hash, evidence và trạng thái release |
| `POST /v1/releases` | Chuẩn bị immutable release |
| `POST /v1/releases/{id}:approve` / `:reject` | Duyệt quyết định độc lập |
| `POST /v1/releases/{id}:deploy` | Publish đúng release đã duyệt |
| `GET /v1/policies/{id}/versions` | Lịch sử phiên bản |
| `GET /v1/policies/{id}/versions/{v}/replay` | Replay gắn phiên bản |

Dùng body đúng schema và `request_id`/etag khi contract yêu cầu; retry giữ request
ID cho cùng intent, đổi ID khi là thao tác mới. Response 409 cần tải lại trạng thái;
412 thường là precondition/replay/capability chưa đạt; 503 là nguồn phụ thuộc chưa
sẵn sàng. Không retry vô hạn mọi mã 4xx. Lưu operation ID để poll thay vì cho client
cắt timeout rồi tạo nhiều việc trùng.

## 7. Chẩn đoán theo triệu chứng

| Triệu chứng | Kiểm đầu tiên | Cách xử lý có mục tiêu |
| --- | --- | --- |
| Build không thấy image/tag | Log build, image ID, dev image | Build đúng source, không pull tag đoán |
| Init lỗi database | PG healthy, `.state/env`, DSN đúng mạng | Giữ volume, sửa kết nối/secret |
| CP chờ lease sau crash | Log lease, CP khác còn chạy? | Đợi TTL ~30s; dừng bản trùng, không xóa lease |
| UI 502 | Proxy upstream/port, CP logs/healthz | Sửa topology loopback/container |
| UI được nhưng events lỗi 503 | Readyz `clickhouse`, CH health/schema/disk | Khôi phục CH, theo dõi spool giảm |
| SSO không vào | Issuer/audience/role/sub/clock/JWKS | Sửa IdP mapping/DNS, giữ local recovery |
| Enroll lỗi TLS | CA fingerprint, SAN, time, node DNS | Cấp đúng trust/name, không insecure |
| Enroll token lỗi | Token hết hạn/đã dùng/group | Tạo token mới, kiểm identity đang có |
| Bundle không apply | Agent log, signature, version, capability, worker log | Sửa compatibility/trust/content |
| Đã deploy nhưng không block | NGINX strata on/policy/mode, policy mode, worker actual | Kiểm đúng route và bỏ override shadow khi được phép |
| 503 trên ứng dụng | Fail-closed, breaker reject, backend thật | Đọc reason/Block ID/counter, không mặc định lỗi backend |
| Spool tăng/dropped tăng | CH, agent kết nối, đĩa/spool/socket queue | Sửa nguồn không nhận, nới tài nguyên có kiểm soát |
| Health unknown/stale | Timestamp và nguồn telemetry | Khôi phục nguồn; không thay bằng 0 |
| User thấy thiếu menu/dữ liệu | Role bindings, service token ceiling, app/env scope | Kiểm quyền cần thiết, không cấp admin tùy tiện |
| Đĩa gần đầy | PG/CH/artifact/release/backups/Docker log tách biệt | Dọn theo owner/retention, mở rộng; không xóa file DB thủ công |

Trên node dùng `journalctl -u strata-agent.service`, log NGINX và metric; trên CP dùng
`dc logs`. Không paste toàn `nginx -T`/environment lên ticket vì cấu hình có thể chứa
upstream credential/header. Trích phần cần thiết sau khi loại bí mật.

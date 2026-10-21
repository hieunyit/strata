# 02 · Tham chiếu cấu hình control plane

[Trang đầu](README.md) · Trước: [cài đặt](01-installation.md) · Tiếp: [node](03-nginx-nodes.md)

## 1. File nào quyết định hành vi?

Có hai lớp khác nhau:

| Lớp | File | Tác dụng |
| --- | --- | --- |
| Docker/Compose | `deploy/compact/.state/env`, biến export và Compose | Image, UID/GID, port publish, volume, memory |
| Control plane | `/var/lib/strata/config.yaml` trong container | API/Fleet, auth, database, artifact, replay, canary |

Đổi YAML `listen` không tự đổi port publish Docker. Đổi `.state/env` không tự thay mật
khẩu trong PostgreSQL/ClickHouse volume đang có. Không luân chuyển mật khẩu database
bằng cách chỉ sửa một file: phải cập nhật tài khoản database và secret CP có phối hợp.

YAML bắt buộc `version: 1`; khóa không biết bị từ chối. Duration có đơn vị (`30s`,
`8h`, `10m`); không nhập số trần với kỳ vọng là giây. Boolean là `true`/`false`.
Đường dẫn file tương đối tính từ thư mục chứa YAML, không phải thư mục shell hiện tại.

Ưu tiên: flag explicit thắng giá trị YAML; biến môi trường secret được hỗ trợ thắng
nội dung file `*_file`; phần còn thiếu dùng default của binary. Không có quy tắc tự
động chuyển mọi khóa YAML thành một biến `STRATA_*`.

Compose Compact truyền một số flag cố định, bao gồm `-clickhouse-user=strata`,
`-rules`, `-block-page`, `-replay`, `-replay-corpus`. Các flag này thắng YAML. Muốn
đổi rule IR/corpus của image phải kiểm cả `command` trong Compose, không chỉ sửa YAML.

## 2. Mật khẩu admin được lưu ở đâu?

**User, hash mật khẩu và phiên local được lưu trong PostgreSQL.** File
`auth.local.admin_password_file` chỉ là đầu vào bootstrap khi chưa có local account,
không phải kho lưu tài khoản, không được đọc để so password mỗi lần login và không
phải cách đổi password đang có.

Cài bằng `install.sh`/`init` đã tạo admin trong PostgreSQL. YAML dùng thường ngày chỉ
cần bật local auth, ví dụ:

```yaml
version: 1
auth:
  local:
    enabled: true
    session_ttl: 8h
```

Đây là đoạn minh họa nhóm auth, không phải file đầy đủ để thay file do init tạo.
Không thêm `username: admin` hay `password: ...` vì không có hai khóa đó trong schema.
Cần reset user đã có: dùng UI hoặc `admin recover` ở chương 04.

## 3. File secret và khóa

| Nhóm | Giá trị/file | Cách giữ |
| --- | --- | --- |
| PostgreSQL | DSN có user/password | `secrets/postgres-dsn`, 0600 |
| ClickHouse | Password | `secrets/clickhouse-password`, 0600 |
| Bundle signer | Ed25519 private seed | `keys/bundle-signing.key`, private |
| Bundle verifier | Public key raw | `keys/bundle.pub`, có thể phân phối cho node |
| Fleet | CA/cert và private key | `pki/`; chỉ phân phối public CA cần thiết |
| C: local MFA | Independent 32-byte hex key | `keys/local-mfa.key`, 0600 |
| C: webhook/discovery | Mỗi chức năng một key riêng | File regular 0600, không dùng signer key |

Secret reader từ chối symlink, file không thường, file rỗng, file quá 64 KiB và file
cho group/others đọc. Volume/container phải thấy đúng UID/GID; Docker secret mount
mặc định quá rộng có thể không phù hợp, cần kiểm mode thực tế. Không mở quyền để
vượt lỗi. File mà người vận hành dùng làm đầu vào phải nằm ngoài Git.

Các biến môi trường secret được hỗ trợ bởi ánh xạ YAML:

| YAML | Biến môi trường tương ứng |
| --- | --- |
| `database.dsn_file` | `STRATA_POSTGRES_DSN` |
| `auth.local.admin_password_file` | `STRATA_LOCAL_ADMIN_PASSWORD` |
| `events.clickhouse.password_file` | `STRATA_CLICKHOUSE_PASSWORD` |
| `bundles.storage.s3.access_key_file` | `STRATA_S3_ACCESS_KEY` |
| `bundles.storage.s3.secret_key_file` | `STRATA_S3_SECRET_KEY` |
| `bundles.identity_key_file` | `STRATA_IDENTITY_HMAC_KEY` |

Không nhầm `bundles.identity_key_file` với khóa ký bundle hoặc key C05. Không dùng
`docker inspect`/`docker compose config` toàn bộ trong ticket hỗ trợ: đầu ra có thể
chứa password môi trường database. `config show --effective` che các secret hỗ trợ,
nhưng vẫn có thể hiện đường dẫn/hostname nên cần kiểm trước khi chia sẻ.

## 4. Cấu hình nền tảng Compact

Ví dụ dưới dành cho container Compact A/B. Đối chiếu **file init đã sinh** trước khi
thêm/bớt; giữ PKI và secrets hiện có. Chọn rõ TTL 30 ngày ở ví dụ này thay vì dựa vào
default binary 90 ngày. Không có password admin trong YAML.

```yaml
version: 1
server:
  http:
    listen: ":8080"
    ui: true
  fleet:
    listen: ":8443"
    tls_ca: pki/ca.pem
    tls_cert: pki/cp.pem
    tls_key: pki/cp-key.pem
    node_ca_cert: pki/node-ca.pem
    node_ca_key: pki/node-ca-key.pem
  single_control_plane: true
  lease_ttl: 30s

database:
  dsn_file: secrets/postgres-dsn

auth:
  local:
    enabled: true
    session_ttl: 8h

events:
  retention_days: 30
  clickhouse:
    address: "clickhouse:9000"
    username: strata
    password_file: secrets/clickhouse-password

bundles:
  signer:
    type: file
    key_file: keys/bundle-signing.key
    public_key: keys/bundle.pub
  storage:
    local:
      path: objects
      keep_bundles: 10
      sample_days: 7
      prune_interval: 1h

replay:
  binary: /usr/local/bin/strata-replay
  corpus: /opt/strata/replay-corpus.parquet
  threads: 2
  timeout: 10m

rollouts:
  waves: ["1", "10%", "100%"]
  soak: 0s

canary:
  min_requests: 200
  block_factor: 3
  block_floor: 0.01
  error_factor: 2
  error_delta: 0.01
  latency_factor: 1.5
  latency_delta: 50ms
```

`soak: 0s` là default, không phải đề xuất đủ thời gian nghiệm thu cho mọi hệ thống.
Canary cần mẫu thực đủ ở cả hai nhóm; chỉnh ngưỡng là thay phương pháp so sánh được
ghim vào release. Không hạ ngưỡng chỉ để làm một lần deploy bị chặn trở nên xanh.

## 5. Bảng khóa thường dùng và ánh xạ flag

Default ở đây là default binary nếu không có YAML/flag; init/Compose có thể đặt khác.
Mẫu đầy đủ và kiểm tra combination ở [config.go](../../control-plane/config/config.go).

| Khóa YAML | Flag | Default/ý nghĩa |
| --- | --- | --- |
| `server.http.listen` | `-addr` | `:8080` |
| `server.http.ui` | `-ui` | `true`, UI cùng origin |
| `server.http.cors_origins` | `-cors-origins` | Danh sách origin; mặc định không cho cross-origin |
| `server.http.trusted_proxies` | `-trusted-proxies` | IP/CIDR/hostname proxy được tin XFF; mặc định rỗng |
| `server.fleet.listen` | `-grpc-addr` | Binary rỗng; init Compact đặt `:8443` |
| `server.fleet.tls_ca` | `-tls-ca` | CA/trust cho TLS Fleet |
| `server.fleet.tls_cert` | `-tls-cert` | Chứng chỉ server Fleet |
| `server.fleet.tls_key` | `-tls-key` | Private key Fleet |
| `server.fleet.node_ca_cert` | `-node-ca-cert` | CA cấp cert node |
| `server.fleet.node_ca_key` | `-node-ca-key` | Private key CA node |
| `server.fleet.trust_bundle` | `-fleet-trust-bundle` | CA bổ sung theo quy trình trust rotation |
| `server.single_control_plane` | `-single-control-plane` | `true` |
| `server.lease_ttl` | `-lease-ttl` | `30s` |
| `server.metrics.listen` | `-metrics-addr` | Rỗng, không bật endpoint |
| `server.admin.grpc_listen` | `-admin-grpc-addr` | Rỗng, REST vẫn chạy |
| `server.admin.tls_cert` / `tls_key` | `-admin-tls-cert` / `-admin-tls-key` | TLS của admin gRPC tùy chọn |
| `server.admin.grpc_plaintext` | `-admin-grpc-plaintext` | Không dùng cho triển khai thật |
| `auth.local.enabled` | `-local-auth` | `true` với PostgreSQL |
| `auth.local.session_ttl` | `-local-session-ttl` | `8h` |
| `auth.local.admin_user` | `-local-admin-user` | `admin`, chỉ bootstrap |
| `auth.oidc.issuer` | `-oidc-issuer` | Rỗng: không bật OIDC |
| `auth.oidc.discovery_url` | `-oidc-discovery-url` | Metadata URL nội bộ nếu khác issuer |
| `auth.oidc.audience` | `-oidc-audience` | Audience token cho API |
| `auth.oidc.roles_claim` | `-oidc-roles-claim` | `realm_access.roles` |
| `auth.oidc.ui_client_id` | `-ui-oidc-client-id` | `strata-ui` |
| `events.retention_days` | `-events-ttl-days` | `90`; `0` giữ TTL đang có, không phải tắt lưu |
| `events.geo_aggregates_months` | `-geo-aggregates-months` | TTL bảng geo tổng hợp, độc lập sự kiện thô |
| `events.clickhouse.address` | `-clickhouse-addr` | Endpoint native, Compact dùng `clickhouse:9000` |
| `events.clickhouse.username` | `-clickhouse-user` | Binary `default`, Compose ép `strata` |
| `events.in_memory` / `seed` | `-in-memory` / `-seed` | Dành test/demo, không thay ClickHouse trong triển khai này |
| `bundles.compiler` | `-compiler` | `strata-compile` trong PATH |
| `bundles.rules` | `-rules` | Danh sách file IR, không phải thư mục YAML rules |
| `bundles.block_page` | `-block-page` | File HTML đưa vào bundle |
| `bundles.support_contact` | `-support-contact` | Liên hệ xuất trên block page |
| `bundles.cost_budget` | `-cost-budget` | Ngân sách compiler; không tự đặt `0` để vượt gate |
| `bundles.signer.type` | `-bundle-signer` | `file` hoặc `vault` |
| `bundles.signer.key_file` | `-bundle-signing-key` | Private Ed25519 signer, chỉ type file |
| `bundles.signer.public_key` | `-bundle-pubkey` | Public key xác minh |
| `bundles.storage.local.path` | `-objects-dir` | Bắt buộc chọn local hoặc S3, không cả hai |
| `bundles.storage.local.keep_bundles` | `-objects-keep-bundles` | `10`, cộng bundle đang được tham chiếu |
| `bundles.storage.local.sample_days` | `-objects-sample-days` | `7` ngày replay sample |
| `bundles.storage.local.prune_interval` | `-objects-prune-interval` | `1h`; `0` không chạy dọn định kỳ |
| `bundles.storage.s3.endpoint` | `-s3-endpoint` | Host:port object store |
| `bundles.storage.s3.bucket` | `-s3-bucket` | `strata-bundles` |
| `bundles.storage.s3.secure` | `-s3-secure` | `true` |
| `bundles.signer.vault.address` | `-vault-addr` | Endpoint Vault |
| `bundles.signer.vault.transit_mount` | `-vault-transit-mount` | `transit` |
| `bundles.signer.vault.transit_key` | `-vault-transit-key` | `strata-bundles` |
| `bundles.signer.vault.key_version` | `-vault-transit-key-version` | `0`: latest; ghim trong quá trình xoay |
| `bundles.signer.vault.token_file` | `-vault-token-file` | File token, hoặc cơ chế `VAULT_TOKEN` |
| `replay.binary` / `corpus` | `-replay` / `-replay-corpus` | Compact có binary/corpus trong image |
| `replay.threads` / `timeout` | `-replay-threads` / `-replay-timeout` | `2` / `10m` |
| `replay.sampling_approved` | `-replay-sampling-approved` | `false`; chỉ bật khi có phê duyệt thật |
| `rollouts.waves` | `-rollout-waves` | `1,10%,100%` |
| `rollouts.soak` | `-rollout-soak` | `0s` |
| `canary.min_requests` | `-canary-min-requests` | `200` mỗi nhóm so sánh |
| `canary.block_factor` / `block_floor` | `-canary-block-factor` / `-canary-block-floor` | `3` / `0.01` |
| `canary.error_factor` / `error_delta` | `-canary-error-factor` / `-canary-error-delta` | `2` / `0.01` |
| `canary.latency_factor` / `latency_delta` | `-canary-latency-factor` / `-canary-latency-delta` | `1.5` / `50ms` |
| `geoip.city` / `asn` | `-geoip-city` / `-geoip-asn` | File MMDB do vận hành cung cấp |
| `geoip.update_interval` | `-geoip-update-interval` | `168h` khi có URL updater |
| `good_bots.interval` | `-good-bots-interval` | `0`: không tự gọi ra ngoài |

Khóa MFA, notifications và discovery thuộc C được giải thích riêng ở chương 07.
File `control-plane/config/example.yaml` trên nhánh C chứa các khóa này; binary main
A/B cũ sẽ không hiểu chúng.

## 6. Đổi YAML an toàn trong Compose

Dùng hàm `dc` từ chương 01. Làm với đúng UID/GID người cài. Bản tạm để dưới `build/`
đã gitignore, quyền riêng; không gửi bản này lên ticket vì có thể chứa cấu hình nội bộ.

```bash
umask 077
mkdir -p build/operator-config
dc cp control-plane:/var/lib/strata/config.yaml build/operator-config/config.before.yaml
cp build/operator-config/config.before.yaml build/operator-config/config.next.yaml
```

Sửa `config.next.yaml` bằng editor. Giữ nó dưới cùng base directory trong container
khi validate để đường dẫn `pki/`, `secrets/`, `keys/` vẫn resolve đúng:

```bash
dc cp build/operator-config/config.next.yaml control-plane:/var/lib/strata/config.next.yaml
dc exec -T control-plane strata-control-plane config validate \
  -config /var/lib/strata/config.next.yaml
dc exec -T control-plane strata-control-plane config show --effective \
  -config /var/lib/strata/config.next.yaml
```

`validate` kiểm schema, combination và secret file cần đọc; không chứng minh database,
TLS, DNS, compiler, receiver hay node thật hoạt động. Lệnh subcommand `show` cũng không
kế thừa các flag `command` của tiến trình đang chạy. Đối chiếu Compose để biết phần bị
flag ghi đè, đặc biệt username ClickHouse, rules và replay.

Chỉ khi validate thành công mới thay file đang dùng:

```bash
dc exec -T control-plane sh -ec \
  'chmod 600 /var/lib/strata/config.next.yaml && mv /var/lib/strata/config.next.yaml /var/lib/strata/config.yaml'
dc restart control-plane
curl --fail --silent --show-error http://127.0.0.1:8080/readyz
dc logs --tail=100 control-plane
```

Nếu sửa port/image/mount/memory/Compose, dùng `dc up -d --wait control-plane` để
recreate; `restart` không áp dụng thay đổi container definition. Lưu bản YAML đã
kiểm và các thiết lập vận hành trong kho cấu hình riêng, secret ở secret manager.

Lỗi sau đổi YAML: chép lại `config.before.yaml`, restart và đọc readiness từng phần.
Không coi việc rollback YAML là rollback migration database. Nếu mất container đang
chạy nên `dc cp` không dùng được, cần container bảo trì mount **đúng volume** và đúng
UID/GID; không chạy lại init để thay file cấu hình đang lỗi.

## 7. Tách retention theo loại dữ liệu

`events.retention_days` chỉ điều khiển TTL sự kiện ClickHouse; xóa diễn ra qua merge,
không bảo đảm giải phóng đĩa ngay sau restart. Không chạy mutation lớn trên đĩa đã
đầy mà chưa dự trù dung lượng merge. Bảng geo có thời hạn riêng.

`sample_days` dành replay sample filesystem; `keep_bundles` không xóa bundle node
đang chạy/được chỉ định hoặc rollout đang dùng. Release snapshot dưới `releases/`
không được dọn như bundle thông thường; B04 giới hạn 1.000 release và chưa có GC
release tự động. Backup/evidence/outbox có chu kỳ khác; xem chương 06/07.

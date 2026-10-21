# 06 · Backup, khôi phục và nâng cấp

[Trang đầu](README.md) · Trước: [vận hành](05-operations.md) · Tiếp: [phần C](07-compact-c.md)

## 1. Xác định phạm vi trước khi sao lưu

Có hai tập dữ liệu độc lập: trạng thái quản trị PostgreSQL/artifact/PKI, và lịch sử
sự kiện ClickHouse. Phải có chiến lược cho cả hai nếu cần giữ lịch sử.

| Dữ liệu | Archive `backup.sh` | Việc bổ sung |
| --- | --- | --- |
| PostgreSQL: user, policy, audit, inventory, release | Có, logical dump |
| PKI, signer private/public key, YAML, secrets trong data dir | Có, mã hóa age |
| Filesystem artifact trong data dir mặc định | Có |
| C: MFA key và dữ liệu C trong PG/data dir | Có nếu tồn tại tại thời điểm backup |
| Artifact S3/bucket ngoài | Không | Backup bucket/versioning riêng |
| Lịch sử sự kiện và aggregate ClickHouse | **Không** | Backup ClickHouse riêng |
| `.state/env` ngoài volume | Không | Lưu secret riêng, không để cạnh passphrase/archive |
| Compose overrides, reverse proxy, TLS cert ngoài data dir | Không | Kho cấu hình/secret riêng |
| NGINX vhost, node identity/bundle/spool | Không | Backup/khôi phục node theo quy trình riêng |
| Image và bộ gói đã phát hành | Không | Lưu registry/kho artifact có digest |

Wrapper mặc định lấy `/var/lib/strata/objects`. Nếu đổi `bundles.storage.local.path`
ra ngoài data dir, phải mount đúng đường dẫn và dùng CLI `backup -objects-dir` tương
ứng; wrapper không tự đọc YAML để tìm mọi đường dẫn artifact tùy biến.

Archive chứa private key và credential nên luôn mã hóa age bằng passphrase. Mất cả
passphrase là không restore được; mất signer/CA có thể làm fleet không còn trust.
Giữ bản sao ngoài host, kiểm quyền đọc và quy trình lấy passphrase khi có sự cố.

## 2. RPO/RTO và lịch backup

RPO là lượng dữ liệu chấp nhận mất; RTO là thời gian chấp nhận gián đoạn. Ví dụ tổ
chức chọn backup metadata mỗi ngày chỉ cho RPO xấp xỉ 24 giờ, không phải 0. ClickHouse
có RPO riêng. Đặt lịch theo yêu cầu và lượng dữ liệu thực, không dựa vào tên tính năng.

Một lịch tham khảo: metadata hằng ngày và trước nâng cấp, giữ 7 bản ngày/4 bản tuần/
3 bản tháng; sao chép off-host sau mỗi lần. Đây là policy gợi ý, script chưa tự dọn
retention hoặc tự chuyển archive. Chỉ dọn bản cũ sau khi bản mới đã xác minh và có bản
sao độc lập. Không dùng cron chồng nhiều backup cùng lúc; dùng scheduler/lock của OS.

## 3. Chạy backup metadata

Tạo file passphrase dài, ngẫu nhiên, 0600 ngoài repo và ngoài thư mục backups bằng
secret manager/editor không để lộ trên shell. UID/GID người cài phải đọc được file
vì container backup chạy theo UID đó. Ví dụ:

```bash
deploy/compact/backup.sh /secure/strata-backup/passphrase
```

Mặc định ghi `deploy/compact/backups/strata-<UTC>.tar.age`. Có thể đặt tên basename
riêng bằng đối số thứ hai; không dùng tên đã tồn tại:

```bash
deploy/compact/backup.sh /secure/strata-backup/passphrase \
  strata-before-upgrade-example.tar.age
sha256sum deploy/compact/backups/strata-before-upgrade-example.tar.age
```

Lưu exit code, số file, schema version, có artifact hay không và hash archive. Không
chỉ nhìn một file `.age` đã xuất hiện giữa lúc tiến trình chưa đóng xong. Trong C04,
backup CLI có observation thành công/thất bại sau khi kết thúc; lỗi trước khi nối DB
không thể ghi observation. Vẫn cần scheduler theo dõi exit code và off-host copy.

Thứ tự backup: dump PG trước, sau đó data dir/artifact, rồi manifest hash từng file.
Đây không phải distributed snapshot nguyên tử của toàn hệ thống. Tránh sửa key/YAML,
đổi backend hoặc phát hành/dọn artifact đồng thời với backup quan trọng. Nếu file
đang thay đổi làm backup fail, ổn định nguồn và chạy lại bằng tên archive mới.

Tmpfs `/tmp` của container cần đủ chỗ cho PG dump và dữ liệu tạm công cụ; RAM/temp
không đủ cũng có thể làm backup fail dù đĩa backup còn trống. Không cho backup xóa
artifact đang dùng để nhường chỗ. Image Compact có PostgreSQL client 17; server
major mới hơn cần công cụ dump tương thích trước khi đổi database.

## 4. Restore trên cùng máy

Đây là thao tác thay metadata và file, có gián đoạn quản trị. Chỉ chạy với archive
đã xác minh, biết nguồn/passphrase và đã có bản sao trạng thái hiện tại nếu cần giữ.
Không restore vào một database còn CP khác giữ lease.

1. Ghi phiên bản hiện tại, image/schema và highest bundle node đang dùng.
2. Ngừng thay đổi policy/release, lên lịch gián đoạn UI/Fleet/ingest.
3. Xác nhận đúng project, env file, database đích và archive.
4. Chạy wrapper; nó stop CP, kiểm archive, hỏi gõ `RESTORE`, rồi restore/restart.

```bash
deploy/compact/restore.sh \
  deploy/compact/backups/strata-before-upgrade-example.tar.age \
  /secure/strata-backup/passphrase
```

Không thêm `-yes` trong quy trình thao tác tay. Automation chỉ dùng khi môi trường
đích được kiểm tra độc lập và đã được phê duyệt theo quy trình tổ chức.

Restore giữ DSN/password database và ClickHouse **của máy đích**, thay PG state,
PKI/keys/YAML/artifact từ archive. Dump có schema mới hơn binary thì bị từ chối; dùng
binary tương thích với archive. Reset public schema và nạp SQL nằm trong một
transaction, nhưng database/migration/file install không là một transaction chung.

Nếu bước sau SQL báo lỗi, giữ CP dừng để sửa và kiểm, không tự restart liên tục.
Wrapper chỉ chạy `up` sau khi restore thành công. Sau crash có thể phải đợi lease
cũ hết TTL ~30 giây; không xóa lease để chạy sớm.

Sau restore thành công:

- Kiểm `/readyz`, đăng nhập, app/env/binding, policy/release và signer fingerprint.
- Rollout dở bị hủy; node giữ bundle đang chạy tới publish kế tiếp, không downgrade.
- Bundle tiếp theo được đánh số cao hơn các mốc đã biết để giữ chống rollback.
- Node enroll sau backup có thể phải enroll lại; đọc danh sách lệnh trả về.
- Release kế tiếp phải được review theo policy đã khôi phục; kiểm request worker thật.
- Sự kiện ClickHouse không tự quay lại thời điểm backup; chênh thời gian với metadata
  phải được ghi nhận, không ghép thành một lịch sử nguyên tử giả.

Không coi login thành công là đủ bằng chứng restore. Phải thử publish và kiểm node
trong môi trường diễn tập trước khi dựa vào backup cho khôi phục thật.

## 5. Restore sang máy mới

1. Dựng host/Docker/DNS/TLS/firewall, checkout và image tương thích archive.
2. Dùng project/volume riêng; chưa mở kết nối node thật tới máy diễn tập.
3. Chạy install để tạo database đích, data dir và secret kết nối của máy mới.
4. Chép archive/passphrase qua kênh riêng và chạy restore như §4.
5. Kiểm path/UID, file YAML và certificate SAN; archive giữ certificate cũ, init lại
   với `-name` không sửa SAN đã tồn tại.
6. Với S3, restore bucket riêng; với ClickHouse, chọn restore lịch sử hoặc chấp nhận
   bắt đầu lại và ghi rõ RPO. Không dùng nhầm bucket/database đang phục vụ làm đích.
7. Diễn tập bằng node lab riêng. Chỉ đổi DNS/routing node thật sau khi kế hoạch chuyển
   đã được cho phép, và bảo đảm máy cũ không cùng điều khiển một fleet.

Không chạy hai bản CP dùng cùng DB rồi tắt lease để tránh tranh chấp. Restore PKI
sang máy diễn tập tạo quyền giả mạo control plane thật, nên phải cô lập mạng và giữ
archive/khóa như dữ liệu quản trị đặc quyền.

## 6. Backup ClickHouse riêng

Có hai lựa chọn: backup native khi chạy, hoặc bản sao volume lạnh khi đã stop sạch.
Backup native cần disk/S3 backup đích, quyền và config `backups` tương ứng; Compose
mặc định **chưa tạo backup disk**. Không chạy `Disk('backups', ...)` rồi mặc định tên
disk tồn tại. Thiết kế và diễn tập theo
[tài liệu ClickHouse](https://clickhouse.com/docs/concepts/features/backup-restore/overview).

Dưới đây là phương án volume lạnh cho Compose một node, dễ xác định điểm nhất quán,
đổi lại dừng ingest/query. Chỉ dùng cùng image ClickHouse và mount layout khi restore;
đây không phải phương án chuyển major/version tùy ý.

### 6.1. Tạo bản sao lạnh mã hóa

Cần `age` CLI trên host, Docker và Bash. Bản example dùng named volume Compose;
nếu dữ liệu là bind mount phải lập lệnh backup filesystem riêng cho mount đó.
Chuẩn bị `/secure-backups` thuộc tài khoản vận hành, mode 0700, nằm ngoài repo.

Xác định named volume **trước khi stop**:

```bash
ch_container=$(dc ps -q clickhouse)
ch_volume=$(docker inspect --format \
  '{{range .Mounts}}{{if eq .Destination "/var/lib/clickhouse"}}{{.Name}}{{end}}{{end}}' \
  "$ch_container")
test -n "$ch_volume"
docker volume inspect "$ch_volume"
```

Ghi lại tên volume, image ID, XML cấu hình, timestamp và backup metadata gần nhất.
Stop CP trước để ngừng ingest, rồi stop ClickHouse sạch. Node vẫn phục vụ bằng bundle
hiện tại và spool có giới hạn; nếu thời gian sao lưu dài cần tính dung lượng spool.

```bash
dc stop control-plane
dc stop clickhouse
set -o pipefail
docker run --rm --user 0 --entrypoint tar \
  -v "$ch_volume:/source:ro" \
  clickhouse/clickhouse-server:25.8.33 -cpf - -C /source . \
  | age -p -o /secure-backups/clickhouse-example.tar.age
```

`age -p` hỏi passphrase qua terminal; giữ passphrase ngoài archive. Chỉ dùng tên đích
mới, không ghi đè bản đã có. Kiểm pipeline exit code; nếu lỗi, giữ trạng thái và xử
lý có chủ đích, không kết luận đã backup chỉ vì file tồn tại.

```bash
sha256sum /secure-backups/clickhouse-example.tar.age
dc up -d --wait clickhouse
dc up -d --wait control-plane
curl --fail --silent --show-error http://127.0.0.1:8080/readyz
```

Kiểm CH, event mới và spool giảm sau restart; copy archive ra ngoài host. Secret và
quyền truy cập user CH/config nằm ngoài `/var/lib/clickhouse` cũng cần sao lưu qua
quy trình cấu hình riêng. Dùng image đúng digest đã ghi nếu tag đã thay đổi.

### 6.2. Restore bản lạnh vào volume mới

Thực hiện ở host/project cô lập trước. Không giải tar đè volume CH đang phục vụ;
giữ volume cũ để điều tra. Tạo named volume mới chưa chứa dữ liệu:

```bash
docker volume create strata-clickhouse-restore-example
set -o pipefail
age -d /secure-backups/clickhouse-example.tar.age \
  | docker run --rm -i --user 0 --entrypoint tar \
      -v strata-clickhouse-restore-example:/restore \
      clickhouse/clickhouse-server:25.8.33 -xpf - -C /restore
```

Tạo Compose override **ngoài repo**, giữ cấu hình user/password/XML của bản backup,
chọn external volume đã restore. Áp dụng chỉ cho project đích đã kiểm:

```yaml
volumes:
  clickhouse:
    external: true
    name: strata-clickhouse-restore-example
```

Thêm `-f /đường/dẫn/override.yaml` sau Compose gốc và dùng hàm tương ứng cho mọi lệnh.
Khởi động CH với đúng version/config trước, kiểm bảng/schema/count/time range và
một Block ID đã biết. Chỉ khởi động CP khi schema compatible; CP có migration lúc
startup nên không dùng binary mới hơn ngoài ý muốn trong diễn tập. Kiểm không nhân
đôi ingest/aggregate ngoài kỳ vọng sau reconnect.

PG/CH không có transaction backup chung. Nếu cần ảnh chụp gần đồng thời, lên cửa sổ
bảo trì, dừng phát hành/ingest phù hợp và ghi cả hai thời điểm. Không hứa dữ liệu
ngoài backup còn nguyên sau mất máy.

## 7. Nâng cấp control plane

Dùng image/commit ghim, thử trên restore cô lập trước. Không `git pull` không kiểm
mốc khi hệ thống đang phục vụ.

1. Đọc diff/migration và compatibility node; xác nhận key, replay, storage tương thích.
2. Backup metadata, CH nếu cần lịch sử, cấu hình/secret ngoài volume và image cũ.
3. Build source target ở checkout riêng hoặc pipeline build tin cậy.
4. Gắn tag version bất biến và lưu image digest. Với Compose, đặt `STRATA_VERSION`
   đúng tag đã có trên host; đừng chỉ dựa vào tag `compact` có thể đã bị build khác đổi.
5. Dừng publish, recreate CP; PostgreSQL/ClickHouse migration chạy lúc startup.
6. Đọc log, readiness từng nguồn, login, quyền scoped, replay/release và node actual.
7. Mở lại thay đổi sau khi nghiệm thu; giữ backup trước nâng cấp tới hết cửa sổ quay lui.

Ví dụ sau khi image target và `STRATA_VERSION` đã được chuẩn bị:

```bash
dc up -d --wait control-plane
dc logs --since=10m --tail=200 control-plane
curl --fail --silent --show-error http://127.0.0.1:8080/readyz
```

Binary cũ không được chạy với schema mới hơn nó biết. Quay lui schema dùng image
phù hợp và **restore backup trước nâng cấp** theo cửa sổ khôi phục; không chỉ đổi tag
rồi restart. Mọi thay đổi metadata sau thời điểm backup có thể mất. Node vẫn có thể
đang giữ bundle mới, cần kiểm compatibility và release kế tiếp như §4.

## 8. Nâng database và diễn tập nghiệm thu

PostgreSQL major khác có định dạng dữ liệu khác; không đổi `postgres:17.11` sang
major khác rồi dùng lại volume. Tạo cluster/volume mới, dump/restore hoặc `pg_upgrade`
theo kế hoạch đã thử, giữ volume cũ. CP image hiện mang client 17, nên toolchain
backup/restore cũng phải được xét. Xem
[hướng dẫn PostgreSQL 17](https://www.postgresql.org/docs/17/upgrading.html).

ClickHouse version mới cần đọc release/compatibility, backup lịch sử riêng và thử
restore/rollback; không giả định downgrade binary đọc được volume đã nâng. Không
kết hợp nâng major PG, CH, CP và module trong một bước thiếu điểm phục hồi.

Biên bản diễn tập tối thiểu: thời gian lấy archive/passphrase; thời gian restore từng
nguồn; schema/image/hash; login và quyền allow/deny; policy/release/PKI; event lịch sử
và event mới; node lab enroll/apply; publish bundle version tăng; benign/attack đúng
mode; RPO/RTO thực đo; các dữ liệu/credential chưa khôi phục. Chỉ công nhận backup
vận hành được sau khi các bước này có kết quả thật.

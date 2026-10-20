# Strata Compact

Bản cài gọn của control plane (CP-A09, `docs/plan/compact-ops-plan.md`): **3 dịch vụ** trên
một máy: control plane (Web UI nhúng, API, Fleet), PostgreSQL, ClickHouse. Không cần MinIO,
Vault, Keycloak hay web server riêng: artifact nằm trên đĩa (CP-A07), bundle ký bằng khóa file,
đăng nhập bằng tài khoản local (Keycloak là overlay tùy chọn). Node vẫn cài bằng gói deb/rpm
(`deploy/packaging`).

| Dịch vụ | Image | Cổng | Volume |
| --- | --- | --- | --- |
| `control-plane` | `strata-control-plane:compact` (build tại chỗ) | 8080 UI + API (mặc định chỉ loopback), 8443 Fleet mTLS | `strata-data` (khóa, PKI, secret, `config.yaml`, artifact), `./backups` |
| `postgres` | `postgres:17.11` (ghim) | trong mạng compose | `postgres` |
| `clickhouse` | `clickhouse/clickhouse-server:25.8.33` (ghim) | trong mạng compose | `clickhouse` |

## Cài

Cần Docker với compose v2, khoảng 4 GB RAM trống (giới hạn mặc định: ClickHouse 3 GB,
control plane 2 GB, PostgreSQL 1 GB; đổi bằng `CLICKHOUSE_MEM_LIMIT`, `STRATA_MEM_LIMIT`,
`POSTGRES_MEM_LIMIT`).

```bash
deploy/compact/build.sh                       # image strata-control-plane:<git describe> và :compact
deploy/compact/install.sh -name waf.example.test
```

`install.sh`:

1. Sinh mật khẩu PostgreSQL, ClickHouse, Keycloak vào `deploy/compact/.state/env` (0600; một lần).
2. Chạy PostgreSQL và ClickHouse.
3. Gán volume `strata-data` cho người chạy cài đặt: control plane chạy với uid/gid đó, nên file
   backup và passphrase thuộc về người đó, không ai khác đọc được.
4. Chạy `strata-control-plane init`: CA và chứng chỉ Fleet cho `-name`, CA của node, khóa ký
   bundle, `config.yaml`, admin đầu tiên. Mật khẩu admin hỏi hai lần hoặc lấy từ
   `-admin-password-file`, qua stdin, không qua dòng lệnh.
5. Chạy control plane. UI ở `http://127.0.0.1:8080`, user `admin`.

Chạy lại `install.sh` không đổi gì đã có.

Mở UI ra ngoài máy: đặt một reverse proxy TLS phía trước rồi đổi `STRATA_HTTP_BIND`. Đừng mở
8080 trần ra mạng. Fleet (8443) là mTLS, mở cho các node.

## Cấu hình

`config.yaml` trong volume `strata-data` do `init` sinh. Mẫu đầy đủ ở
`control-plane/config/example.yaml`. Sửa bằng:

```bash
c="docker compose -f deploy/compact/compose.yaml --env-file deploy/compact/.state/env"
$c cp control-plane:/var/lib/strata/config.yaml /tmp/config.yaml   # sửa /tmp/config.yaml
$c cp /tmp/config.yaml control-plane:/var/lib/strata/config.yaml && rm /tmp/config.yaml
$c restart control-plane
```

File chép vào vẫn thuộc người cài đặt (cùng uid với control plane).
`strata-control-plane config validate -config /var/lib/strata/config.yaml` kiểm trước.

Rule biên dịch vào mọi bundle là gói core (CRS, protocol, virtual patch), build cùng image
(`/opt/strata/rules/core.rules.json`; giấy phép ở `/opt/strata/rules/NOTICE`).

### Keycloak (tùy chọn)

```bash
export STRATA_COMPACT_OVERLAY=$PWD/deploy/compact/compose.keycloak.yaml
deploy/compact/install.sh -name waf.example.test     # thêm dịch vụ keycloak (:8180)
```

Sau đó:

1. Thêm `auth.oidc` vào `config.yaml` như ghi ở đầu `compose.keycloak.yaml`, rồi restart. Không
   build lại.
2. Tạo user và gán vai trò (`viewer`, `operator`, `approver`, `admin`) trong console Keycloak
   (`admin`, mật khẩu `KEYCLOAK_ADMIN_PASSWORD` trong `.state/env`).

Đăng nhập local vẫn chạy song song. Keycloak ở chế độ dev, dữ liệu trong volume `keycloak`:
đặt sau TLS (`STRATA_IDP_URL=https://…`) trước khi người ngoài máy dùng.

## Backup và restore

```bash
# passphrase: giữ ngoài thư mục backups, không để cạnh archive
deploy/compact/backup.sh /root/strata-backup.pass          # -> deploy/compact/backups/strata-<thời điểm>.tar.age
deploy/compact/restore.sh deploy/compact/backups/strata-….tar.age /root/strata-backup.pass
```

**Backup** chạy khi hệ thống đang chạy. Thứ tự: bản dump PostgreSQL trước, rồi khóa, PKI, secret,
cấu hình, artifact, cuối cùng manifest SHA-256. Archive luôn được mã hóa `age` (passphrase,
scrypt), vì nó chứa khóa ký bundle, CA của node và secret.

**ClickHouse không nằm trong backup**: mất ClickHouse là mất lịch sử sự kiện, không mất cấu hình
hay policy. Muốn giữ lịch sử thì dùng `BACKUP DATABASE default TO Disk(...)` của ClickHouse theo
tài liệu của ClickHouse.

**Restore**:

1. Dừng control plane, rồi kiểm archive (hash từng file, phiên bản schema).
2. Hỏi xác nhận (gõ `RESTORE`).
3. Thay database, khóa, PKI, cấu hình và artifact. Mật khẩu database và ClickHouse của máy này
   được giữ.
4. Khởi động lại control plane.

Reset schema và nạp dump nằm trong cùng transaction; thiếu công cụ PostgreSQL hoặc SQL lỗi
không xóa metadata cũ. Restore cần cả `pg_restore` và `psql` (đã có trong image Compact),
cùng dung lượng tạm cho bản SQL được xuất từ dump. Khôi phục file, migration sau restore và
database không phải một transaction chung: giữ control plane dừng nếu bước sau báo lỗi.

Sau crash, control plane chờ lease PostgreSQL cũ hết hạn (mặc định khoảng 30 giây).
Không giành sớm dựa vào hostname/PID của container. Dừng sạch vẫn nhả lease ngay.

Sau restore:

- Số bundle kế tiếp lớn hơn mọi bundle node đang chạy.
- Không node nào bị kéo về bundle cũ: mỗi node giữ bundle đang chạy tới lần deploy kế tiếp, và
  lần deploy đó mang policy đã khôi phục.
- Rollout đang chạy lúc backup bị hủy.
- Node enroll sau thời điểm backup được liệt kê: chúng phải enroll lại.

**Khôi phục sang máy mới**: chạy `install.sh` trước, rồi mới `restore.sh`.

**Diễn tập restore** vào một bản cài sạch là bắt buộc trước khi dùng thật (kế hoạch A09).

## Nâng cấp

- **Control plane**:
  1. Backup.
  2. `git pull`, rồi `deploy/compact/build.sh`.
  3. `docker compose … up -d control-plane`.

  Migration PostgreSQL và ClickHouse chạy khi khởi động. Bản cũ hơn không chạy trên database đã
  migrate lên: muốn quay lại thì restore backup.
- **PostgreSQL major** (17 → 18): volume không đọc được bởi major khác. **Không đổi tag image
  trực tiếp.** Các bước:
  1. Chạy `backup.sh`.
  2. Dừng stack.
  3. Đổi image, xóa volume `postgres`.
  4. `install.sh`, rồi `restore.sh`.

  Hoặc dùng `pg_dumpall` / `pg_restore` theo tài liệu PostgreSQL.
- **ClickHouse**: đọc ghi chú phát hành của ClickHouse trước khi đổi tag; lịch sử sự kiện không
  có trong backup Strata.

## Đầy đĩa

- ClickHouse và PostgreSQL ở hai volume riêng. Nếu được, đặt hai volume trên hai đĩa
  (`docker volume create --opt …` hoặc bind mount), để sự kiện tràn không làm PostgreSQL ngừng ghi.
- Sự kiện có TTL (`events.retention_days`, mặc định 90 ngày), log hệ thống của ClickHouse giữ 7
  ngày (`clickhouse/compact.xml`).
- Artifact được dọn mỗi giờ: giữ 10 bundle mới nhất cùng các bundle node đang dùng, mẫu replay
  giữ 7 ngày (`bundles.storage.local`).
- Deploy từ chối build khi thư mục artifact còn dưới 256 MiB.
- Khi đã đầy:
  1. Xem `GET /readyz`: ClickHouse đầy thì báo `clickhouse: degraded`, đăng nhập và policy vẫn
     chạy.
  2. Giải phóng chỗ: giảm `events.retention_days` rồi restart, hoặc nới volume.
  3. Agent giữ sự kiện trong spool khi control plane không nhận được.

## Kiểm tra nhanh

```bash
curl -s http://127.0.0.1:8080/readyz     # postgres/lease/clickhouse
docker compose -f deploy/compact/compose.yaml --env-file deploy/compact/.state/env logs control-plane
```

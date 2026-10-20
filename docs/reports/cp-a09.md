# Báo cáo CP-A09 · Backup, restore và đóng gói

Ngày: 20/10/2026. Người làm: Claude Code (strata-59). Kế hoạch: `docs/plan/compact-ops-plan.md`
§4 A09. Hai PR: backup/restore (phần 1), đóng gói Compact (phần 2).

## Phần 1 · Backup và restore

### Làm gì

| Phần | Ở đâu |
| --- | --- |
| Archive: tar mã hóa `age` (scrypt), `postgres.dump` → `data/…` → `objects/…` → `manifest.json` (SHA-256, kích thước, quyền từng file, phiên bản sản phẩm, migration PostgreSQL); đọc lại: chỉ file thường, không đường dẫn tuyệt đối hay `..`, mọi file khớp manifest, không thiếu không thừa | `control-plane/backup/backup.go` |
| `pg_dump -Fc` / `pg_restore --single-transaction`, mật khẩu qua `PGPASSFILE` 0600 xóa ngay sau | `control-plane/backup/pgtools.go` |
| `strata-control-plane backup` / `restore` | `cmd/server/backupcmd.go` |
| Sàn số bundle (migration 0028 `bundle_version_floor`); số kế tiếp > mọi bản ghi, mọi version node báo, sàn | `store/policy.go` (`WithBundleLock`), `store/restore.go` |
| Sau restore, trong một transaction: sàn, bỏ desired của mọi node, hủy rollout RUNNING/PAUSED, đánh FAILED replay RUNNING, xóa lease; danh sách node phải enroll lại | `store/restore.go` (`FinishRestore`) |
| Thư viện `filippo.io/age v1.2.1` | `control-plane/go.mod` (chỉ thêm dòng này, không `go mod tidy`) |

### Quyết định khi làm

- **Luôn mã hóa**: kế hoạch ghi "mã hóa bắt buộc khi có khóa"; bản dump PostgreSQL luôn chứa
  secret (`secrets`, khóa `replay_sampling`), nên không có backup nào an toàn để để trần.
- **Restore làm rỗng schema `public` rồi `pg_restore`**, không `--clean`: `--clean` chỉ xóa đối
  tượng có trong dump; bảng của migration mới hơn sẽ sót lại và làm migrate lên lỗi.
- **Không có trạng thái `BUILDING`** (deploy tuần tự dưới khóa; bản ghi chỉ có khi bundle đã
  xong và đã upload). Thay vào đó: hủy rollout đang chạy (nếu không, rollout cũ đẩy bundle cũ hơn
  bản node đang chạy, tức rollback ngầm) và bỏ desired của mọi node; node giữ bundle đang chạy tới
  deploy kế tiếp, deploy đó mang cấu hình đã khôi phục với số lớn hơn sàn.
- **Sàn còn tính `nodes.bundle_version`** ở mọi deploy, không chỉ sau restore: node báo version cao
  hơn mọi bản ghi (DB khôi phục lùi, rồi node kết nối lại) cũng được tôn trọng.
- **DSN của database đích lấy từ máy đang chạy** (`-dsn-file`, `STRATA_POSTGRES_DSN`,
  `<data-dir>/secrets/postgres-dsn`), không bao giờ từ archive.
- **Passphrase chỉ từ file hoặc terminal** (như mật khẩu admin ở CP-A05).

### Lỗi và lỗ hổng đã chặn

| Rủi ro (kế hoạch A09) | Chặn bằng | Test |
| --- | --- | --- |
| Restore làm version bundle đi lùi, node từ chối bundle mới | Sàn từ DB bị thay; số kế tiếp > sàn và > version node báo | `TestBackupRestoreInPostgres` (sau restore: bản ghi tối đa 3, node chạy 6, deploy kế tiếp là 7) |
| Restore CA cũ, node enroll sau backup | In danh sách node phải enroll lại | `TestBackupRestoreInPostgres` (node-b) |
| Gói backup chứa khóa bị lộ | Luôn mã hóa `age`; file 0600, không ghi đè; passphrase không qua cờ/biến môi trường; mật khẩu DB không qua dòng lệnh | `TestRoundTrip`, `TestPasswordNeverOnTheCommandLine` |
| Restore chồng lên hệ đang chạy | Từ chối khi lease còn hạn | `TestBackupRestoreInPostgres` |
| Backup giữa lúc deploy | Dump trước artifact (artifact ghi trước bản ghi, CP-A07); restore hủy rollout và replay đang chạy | `TestBackupRestoreInPostgres` |
| Archive độc (đường dẫn thoát ra ngoài, symlink, file lạ, hash sai, cắt ngắn, sai passphrase) | `Extract` từ chối | `TestExtractRefusesHostileArchives`, `TestRoundTrip` |
| Ghi đè lặng lẽ file đã sửa trong thư mục dữ liệu | Từ chối trừ `-overwrite` | `TestRoundTrip`, `TestBackupRestoreInPostgres` |
| Nâng PostgreSQL major làm mất dữ liệu | Phần 2 (compose ghim phiên bản, hướng dẫn) | — |

### Kiểm

- `go test -race` toàn bộ control-plane với PostgreSQL 17 thật và `pg_dump`/`pg_restore` 17
  (image dev cục bộ thêm `postgresql-client-17` từ PGDG; image dev chung không có, test tự bỏ qua
  khi thiếu công cụ), golangci-lint 0 issues; e2e `TestMigrationsUpDownOnEmptyDatabase`,
  `TestPolicyEditAndDeploy`, `TestFourEyes` pass.
- Lab: không đổi trong phần này (lệnh chạy ngoài dịch vụ); diễn tập restore vào lab sạch ở phần 2.

## Phần 2 · Đóng gói Compact

### Làm gì

| Phần | Ở đâu |
| --- | --- |
| Image `strata-control-plane:<version>`: control plane (UI nhúng), `strata-compile`, `strata-replay`, gói rule core (588 rule CRS/protocol/virtual patch, `NOTICE` giấy phép), corpus replay, `pg_dump`/`pg_restore` 17 (PGDG); Ubuntu noble, user không phải root, healthcheck | `deploy/compact/Dockerfile`, `build.sh`, `build-inner.sh` |
| Compose 3 dịch vụ: PostgreSQL 17.11 và ClickHouse 25.8.33 ghim, volume riêng từng dịch vụ, healthcheck, `mem_limit`, `cpuset` tùy chọn; UI/API chỉ loopback mặc định, Fleet mở | `deploy/compact/compose.yaml` |
| ClickHouse cho máy nhỏ: 75% giới hạn bộ nhớ container, cache nhỏ, log hệ thống 7 ngày; mỗi truy vấn ≤ 1 GiB, GROUP BY/ORDER BY tràn ra đĩa | `deploy/compact/clickhouse/*.xml` |
| `install.sh` (mật khẩu, databases, quyền volume, `init`, chạy), `backup.sh`, `restore.sh` | `deploy/compact/*.sh` |
| Overlay Keycloak (realm không có user hay secret của lab; bật bằng cấu hình, không build lại) | `deploy/compact/compose.keycloak.yaml`, `keycloak/strata-realm.json` |
| Hướng dẫn: cài, cấu hình, Keycloak, backup/restore, nâng cấp (kể cả PostgreSQL major), đầy đĩa | `deploy/compact/README.md` |
| Diễn tập restore vào bản cài sạch | `tests/e2e/compact-drill.sh` |
| Restore giữ mật khẩu database/ClickHouse của máy đích (`backup.MachineSecrets`) | `control-plane/backup/backup.go` |

### Quyết định khi làm

- **Control plane chạy với uid/gid của người cài** (`STRATA_UID/GID`; `install.sh` gán volume
  một lần, volume gắn `nocopy` để Docker không chép lại thư mục của image và đổi chủ): file backup
  và passphrase thuộc người vận hành, không file nào phải mở quyền đọc cho người khác.
- **Restore giữ `secrets/postgres-dsn` và `secrets/clickhouse-password` của máy đích**: khôi phục
  sang máy mới (cài mới, mật khẩu mới) mà không làm control plane mất kết nối; DSN dùng để restore
  vốn đã là của máy đích (phần 1).
- **Gói rule trong image là gói core build từ repo** (`strata-rules release --pack core`), không
  phải rule mẫu của lab; gói signature (Sigma, ET Open) không đóng vào image, vì hiện nó theo quy
  trình phát hành riêng (staging `--signatures`).
- **Overlay chỉ có Keycloak**. MinIO, Vault và giám sát không làm overlay: Compact không cần chúng
  (artifact trên đĩa, khóa file, `/readyz`), còn lab (`deploy/lab/compose.yaml`) là mẫu đầy đủ
  cho ai cần. Kế hoạch ghi bốn overlay; bỏ ba overlay này theo quyền tự quyết PO giao.
- **Keycloak trong overlay ở chế độ dev**, lưu trong volume riêng: README yêu cầu đặt sau TLS
  trước khi người ngoài máy đăng nhập.
- **Không tự nâng PostgreSQL major**: tag ghim; README mô tả quy trình backup, đổi image, cài,
  restore.

### Kiểm

- shellcheck 0.10 các script (chỉ còn một ghi chú info có chủ ý).
- `tests/e2e/compact-drill.sh` (CPU 6–10, cổng 47080/47443) pass hai lần:
  1. Cài (`readyz` ok, UI nhúng trả trang), tạo tài khoản approver, `example-api` qua four eyes
     (replay DONE trên corpus 4.281 request) được deploy thành bundle 1 với gói core.
  2. Backup 15 MB, mã hóa (không thấy `PGDMP`). Sau đó deploy thêm bundle 2.
  3. `down -v` và xóa `.state/env`, cài lại sạch: mật khẩu mới, khóa ký mới.
  4. Restore: mật khẩu admin cũ dùng được, `example-api` về MODE_SHADOW, bundle về `[1]`,
     public key ký bundle là của backup (node vẫn tin), deploy tiếp ra bundle 2, `readyz` ok.

  Lần chạy đầu gặp hai lỗi đã sửa: volume dữ liệu bị Docker chép lại thư mục của image và đổi chủ
  (thêm `nocopy`), và cổng 28080 trùng staging (đổi sang 47080).
- Gate Go (`backup` sau thay đổi máy đích): xem PR.

## Còn lại

- Overlay MinIO, Vault, giám sát: không làm (xem quyết định).
- Kiểm thử nâng cấp PostgreSQL major theo README: chưa diễn tập.
- Image chưa phát hành lên registry: build tại chỗ bằng `deploy/compact/build.sh`.

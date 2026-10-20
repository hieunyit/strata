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

Đang làm.

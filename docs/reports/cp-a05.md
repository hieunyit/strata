# Báo cáo CP-A05 · Local auth mặc định, init và khôi phục admin

Ngày: 20/10/2026. Người làm: Claude Code (strata-59). Kế hoạch: `docs/plan/compact-ops-plan.md`
§4 A05.

## 1. Làm gì

| Phần | Ở đâu |
| --- | --- |
| `strata-control-plane init`: migration; CA + chứng chỉ Fleet (tên DNS/IP), CA của node; khóa ký bundle Ed25519 (seed + public key); file secret DSN và mật khẩu ClickHouse; `config.yaml`; admin đầu tiên | `control-plane/setup/setup.go`, `control-plane/cmd/server/initcmd.go` |
| `strata-control-plane admin recover -user <tên>` | `initcmd.go` (dùng `localauth.UpdateUser`: mật khẩu mới, bật, mở khóa, xóa session, audit) |
| `-local-auth` mặc định bật; không có PostgreSQL thì tắt kèm cảnh báo, trừ khi cờ hoặc file cấu hình bật tường minh | `cmd/server/main.go` |
| Thư viện `golang.org/x/term` (nhập mật khẩu không echo) | `control-plane/go.mod` (chỉ thêm dòng này; xem mục 3) |

## 2. Quyết định khi làm

- **`admin recover` đặt mật khẩu mới do người vận hành nhập**, không phát mật khẩu tạm buộc đổi
  như kế hoạch ghi: buộc đổi cần cột mới, luồng đăng nhập và UI riêng; mục đích (vào lại được,
  mọi session cũ bị cắt, có audit) đạt mà không thêm chúng. Có thể bổ sung ở C03 cùng MFA.
- **Không xóa `role_bindings`, `service_accounts`** (bảng không dùng, CP-A01): không hại gì, xóa
  cần migration và có thể vướng phiên khác; ghi lại để dọn khi có migration dọn dẹp.
- **Giữ `STRATA_LOCAL_ADMIN_PASSWORD`** (tạo admin lúc khởi động) cho lab và staging; `init` là
  đường khuyến nghị cho cài mới. `strata doctor` (B05) sẽ cảnh báo khi biến còn đặt.

## 3. Lỗi và lỗ hổng đã chặn

| Rủi ro (kế hoạch A05) | Chặn bằng |
| --- | --- |
| Hai `init` song song tạo hai bộ khóa | `flock` trên thư mục dữ liệu; file ghi bằng `O_EXCL` |
| Ghi đè khóa ký khi thư mục rỗng mà DB đã có bundle | `ErrSigningKeyLost`: dừng, không sinh khóa |
| Cặp file thiếu một nửa (cert không key) bị "sửa" lặng lẽ | Lỗi, yêu cầu xóa cả cặp |
| Mật khẩu lọt qua `ps`, lịch sử shell, biến môi trường | Chỉ terminal không echo (hai lần) hoặc file |
| `admin recover` thành cửa sau | Cần DSN (chỉ người có secret trên máy); audit `system:recover (<user>@<host>)` |
| Session còn sống sau khôi phục | `UpdateUser` xóa mọi session khi đổi mật khẩu |
| Khóa riêng đọc được bởi người khác | Khóa và secret 0600, chứng chỉ 0644 |

Sự cố khi làm: `go get golang.org/x/term@<bản cũ>` kéo `go mod tidy` hạ `clickhouse-go` từ 2.49
xuống 2.43 (bản đã nâng ở #240 để vá lỗi bảo mật). Đã trả `go.mod`/`go.sum` về và chỉ thêm
`x/term v0.46.0`; diff `go.mod` chỉ một dòng.

## 4. Test

| Test | Kết quả |
| --- | --- |
| `TestCreateOnceThenKeep`: tạo 5 mục, quyền 0600; cert server ký bởi CA, có tên DNS và IP; seed 32 byte; lần hai giữ nguyên từng byte | PASS |
| `TestRefusesToRepairOrReplace`: mất khóa khi đã có bundle, nửa cặp khóa, nửa cặp cert, không có tên | PASS |
| `TestLockExcludesConcurrentInits` | PASS |
| `TestSecretFile`: 0600, không ghi đè, không ghi secret rỗng | PASS |
| `TestInitAndRecoverInPostgres`: init trên DB rỗng → đủ file, `config.yaml` nạp được, admin đăng nhập; init lần hai giữ khóa; admin bị khóa sau 6 lần sai → `admin recover` → session cũ hết hạn, đăng nhập mật khẩu mới, audit đúng actor; tài khoản không tồn tại và thiếu mật khẩu bị từ chối | PASS |

Cổng kiểm đầy đủ: chung với CP-A02/A03 (nhánh nối tiếp), ghi ở `cp-a03.md` §5.

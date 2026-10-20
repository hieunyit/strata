# Báo cáo CP-A06 · OIDC và Keycloak tùy chọn

Ngày: 20/10/2026. Người làm: Claude Code (strata-59). Kế hoạch: `docs/plan/compact-ops-plan.md`
§4 A06.

## 1. Làm gì

| Yêu cầu của kế hoạch | Ở đâu |
| --- | --- |
| Tách định danh local và OIDC (`oidc:<sub>`), token không có `sub` bị từ chối | CP-SEC-01, PR #270 |
| `/v1/auth/methods` quyết định UI hiện SSO; `/config.json` sinh từ cấu hình, không còn trỏ Keycloak của lab | CP-A08, PR #287 |
| Keycloak ra khỏi compose mặc định, thành overlay | `deploy/compact/compose.keycloak.yaml` (CP-A09, PR #292); sửa volume sang `/opt/keycloak/data` |
| Kiểm issuer, audience, chữ ký, hạn dùng | sẵn có (`go-oidc`), `TestVerifier_RejectsBadTokens` |
| **Giới hạn lệch đồng hồ**: `iat` hay `nbf` quá 2 phút trong tương lai bị từ chối (go-oidc chỉ kiểm `exp`, và `nbf` với 5 phút) | `auth/oidc.go` (`MaxClockSkew`), `TestVerifier_ClockSkew` |
| **Role mapping cấu hình được** (`-oidc-roles-claim`, sẵn có) và **test với claim thiếu, sai kiểu, mảng rỗng**, phần tử không phải chuỗi, khác hoa thường, đường dẫn lồng | `TestVerifier_RoleMappingShapes` |
| **Không cho tắt local auth khi chưa có tài khoản OIDC vai trò admin đăng nhập thành công**: mỗi token OIDC có vai trò admin được ghi lại (migration **0029** `oidc_admin_sign_ins`, mỗi tài khoản tối đa mỗi giờ một lần); khi local tắt, OIDC bật và đã có tài khoản local mà chưa có lần đăng nhập đó, control plane dừng với hướng dẫn | `auth/admin_signins.go`, `store/oidc_admins.go`, `cmd/server/authguard.go`; `TestRecordAdmins`, `TestCheckLocalOff`, `TestOIDCAdminSignInsInPostgres` |
| Chỉ quay về đường dẫn nội bộ sau đăng nhập | sẵn có (`redirect_uri` cố định về gốc) |
| Nghiệm thu: local-only, OIDC-only, local + OIDC; bật/tắt Keycloak chỉ đổi cấu hình | `tests/e2e/compact-oidc.sh` |

## 2. Quyết định khi làm

- **Không có tài khoản local nào thì cho tắt local** (không có gì để mất); chỉ chặn khi đang có
  tài khoản local, tức là có đường vào sẽ bị đóng.
- **Chặn lúc khởi động** (cấu hình chỉ đổi khi khởi động lại, CP-A02), không ở API: control plane
  dừng với lỗi nói rõ cách làm (bật local, đăng nhập SSO một lần bằng admin, rồi tắt).
- **Một issuer**: kế hoạch nêu `issuer-id` trong subject cho trường hợp hai IdP; control plane chỉ
  nhận một issuer, nên `oidc:<sub>` đủ. Làm khi có nhiều IdP.

## 3. Nghiệm thu (`tests/e2e/compact-oidc.sh`, CPU 6–10, Compact + overlay Keycloak, image build từ nhánh)

1. **Chỉ local**: methods `{"local":true,"oidc":false}`, `/config.json` `{}`, đăng nhập local
   200, token OIDC bị 401.
2. **Local + OIDC** (thêm `auth.oidc` vào `config.yaml`, khởi động lại): methods cả hai, đăng
   nhập local 200, token OIDC của `kc-operator` ra principal vai trò operator, `local:false`.
3. **Chỉ OIDC**:
   - (a) tắt local khi chưa có admin OIDC đăng nhập: control plane từ chối khởi động
     ("refusing to turn local accounts off");
   - (b) sau khi `kc-admin` đăng nhập qua OIDC: chạy được, methods `{"local":false,"oidc":true}`,
     đăng nhập local 401, OIDC vẫn chạy.
4. **Trình duyệt** (Playwright) đăng nhập SSO qua UI nhúng: luồng code + PKCE với Keycloak, vào
   được UI, **không có vi phạm CSP**.
5. **Tắt Keycloak** (bỏ `auth.oidc`, bật lại local): methods chỉ local, `/config.json` `{}`, đăng
   nhập local 200.

Không build lại ở bước nào. Gate Go: `go test -race` toàn bộ control-plane với PostgreSQL thật,
golangci-lint 0 issues; shellcheck sạch.

## 4. Phát hiện ngoài phạm vi

Gate sau rebase một lần hỏng `TestInitAndRecoverInPostgres`; chạy riêng và chạy toàn bộ
control-plane tuần tự (`go test -p 1 ./...`) đều pass. Nguyên nhân: các package có test PostgreSQL
(`store`, `cmd/server`, ...) dùng chung một database `STRATA_TEST_POSTGRES_DSN` và chạy song song
(`go test ./...` mặc định), nên một package migrate xuống 0 lúc dọn trong khi package khác đang
dùng schema. Lỗi có từ trước A06. Hướng sửa: mỗi package test PostgreSQL tạo database riêng (như
`TestBackupRestoreInPostgres` đã làm), hoặc chạy `-p 1` khi có DSN.

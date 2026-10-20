# Báo cáo CP-A08 · UI nhúng và ClickHouse

Ngày: 20/10/2026. Người làm: Claude Code (strata-59). Kế hoạch: `docs/plan/compact-ops-plan.md`
§4 A08.

## 1. Làm gì

| Phần | Ở đâu |
| --- | --- |
| Gói `webui`: `go:embed` của `control-plane/webui/dist` (chỉ `.gitkeep` trong git), định tuyến API/UI, cache, `/config.json`, header bảo mật, phiên bản UI (SHA-256 của `index.html`, ghi trong log khởi động) | `control-plane/webui/webui.go` |
| Cờ `-ui` (mặc định bật, khóa `server.http.ui`), `-ui-oidc-client-id` (khóa `auth.oidc.ui_client_id`); `-cors-origins` mặc định rỗng | `cmd/server/main.go`, `config/config.go` |
| `make control-plane-ui` (build `ui/`, chép `ui/dist` vào `webui/dist`), `make control-plane-bin`; lab build nhúng UI khi `ui/dist` đã build | `Makefile`, `deploy/lab/build.sh` |
| Migration ClickHouse đánh số, bảng `strata_schema_migrations`, `schema.sql` là migration 1; `Configure` cho TTL | `ingest/chmigrate.go` |
| Khởi động khi ClickHouse không chạy (`OpenClickHouseStore` không ping), migrate nền có thử lại; `/readyz` degraded tới khi migrate xong | `ingest/store.go`, `cmd/server/main.go` |
| Truy vấn sự kiện/thống kê lỗi → 503 `reason: EVENTS_UNAVAILABLE` (`ErrorResponse.reason`, OpenAPI) | `api/*.go`, `docs/spec/openapi.yaml` |
| UI: `ApiError.reason`, `isEventsUnavailable`; Tổng quan, Sự kiện, Bản đồ, chi tiết sự kiện hiện "nguồn dữ liệu không sẵn sàng" và `—`, không hiện 0 | `ui/src/api/client.ts`, `ui/src/pages/*` |
| Cấm HTML thô trong mã UI (test quét nguồn) | `ui/src/__tests__/NoRawHtml.test.ts` |

## 2. Quyết định khi làm

- **Test quét mã nguồn thay ESLint**: UI chưa có ESLint (`npm run lint` là `tsc`). Thêm ESLint
  chỉ để cấm một thuộc tính kéo theo nhiều phụ thuộc; một test vitest quét mọi file `.ts/.tsx`
  (trừ test) tìm `dangerouslySetInnerHTML`, `innerHTML =`, `outerHTML =`, `insertAdjacentHTML`,
  `document.write(`.
- **CSP cho phép `style-src 'unsafe-inline'`**: kế hoạch chỉ cấm script inline. ECharts và vài
  thành phần đặt style trực tiếp; style inline không chạy được mã.
- **Header bảo mật trên mọi phản hồi**, kể cả API: rẻ và không có ngoại lệ phải nhớ.
- **Migration ClickHouse idempotent và gọi lại hàm `Ensure*` sẵn có**, không viết lại DDL: database
  đang chạy (lab, staging) nhận đủ 4 bước mà không đổi gì; TTL không phải schema nên vẫn áp theo
  cấu hình mỗi lần khởi động (`Configure`).
- **Lab vẫn giữ container `ui`** (nginx) tới A09: compose Compact 3 dịch vụ bỏ nó; ở A08 lab chạy
  cả hai để so sánh.
- **Không đổi `config.ts` của UI**: OIDC manager chỉ được tạo khi `/v1/auth/methods` báo OIDC
  bật; khi đó control plane phục vụ đủ hai khóa trong `/config.json`.

## 3. Lỗi và lỗ hổng đã chặn

| Rủi ro (kế hoạch A08) | Chặn bằng | Test |
| --- | --- | --- |
| SPA fallback trả `index.html` 200 cho đường API gõ sai | `/v1`, `/v1/*`, `/healthz`, `/readyz` luôn tới API | `TestRoutesAndCaching` |
| Trình duyệt giữ UI cũ sau nâng cấp | `index.html` và file không hash `no-cache`; asset có hash `immutable`; asset không còn là 404, không phải HTML | `TestRoutesAndCaching` |
| XSS qua dữ liệu sự kiện | React escape; cấm HTML thô; CSP không cho script inline | `NoRawHtml.test.ts`, `TestSecurityHeadersEverywhere` |
| Clickjacking trang duyệt | `X-Frame-Options: DENY`, `frame-ancestors 'none'` | `TestSecurityHeadersEverywhere` |
| Hiện "0 sự kiện" khi ClickHouse mất kết nối | 503 `EVENTS_UNAVAILABLE`; UI xóa số cũ, hiện `—` và thông báo | `TestEventsUnavailableIsNotEmpty`, `Pages.test.tsx` |
| Control plane không lên khi ClickHouse chưa lên | Mở kết nối không ping, migrate nền có thử lại | lab (mục 4) |
| Database ClickHouse của bản mới hơn bị bản cũ sửa | `ErrCHSchemaNewer`, không migrate, events giữ degraded | `TestMigrateClickHouse` |
| Truy vấn nặng từ UI làm chậm ingest | Giữ giới hạn sẵn có (cửa sổ 31 ngày, `max_execution_time` 10 s) | — |

## 4. Kiểm

- Control plane: `gofmt`, `go vet`, `go test -race` toàn bộ với PostgreSQL và ClickHouse thật
  (`TestMigrateClickHouse` và mọi test ClickHouse sẵn có pass), golangci-lint 0 issues; e2e vet
  và lint.
- UI: `tsc`, vitest 27 file 170 test + test quét HTML thô (59), `npm run build`; `index.html` chỉ
  nạp script ngoài.
- Lab (20/10, control plane bản này, UI nhúng từ `ui/dist`):
  - Cổng control plane 18090: `/` và `/overview` trả `index.html` (`no-cache`), asset có hash
    `immutable`, asset không có là 404, `/v1/nope` là 401 JSON, `/config.json` có authority và
    client của Keycloak; CSP, `X-Frame-Options`, `nosniff`, `Referrer-Policy` có mặt.
  - Database ClickHouse sẵn có của lab nhận migration 1–4 không lỗi (đã có từ `schema.sql` và
    `Ensure*`).
  - Playwright lab (`tests-lab/lab.spec.ts`) trên UI nhúng (đã thêm 18090 vào redirect URI của
    client `strata-ui` trong Keycloak lab và `strata-realm.json`): đăng nhập/đăng xuất Keycloak,
    trace đầy đủ, viewer bị che IP, trang Fleet và Policy pass. Test "a deploy shows node by node"
    hỏng sẵn trên `main`: deploy bản nháp chưa duyệt (có trước four eyes, W13), không liên quan
    A08.
  - ClickHouse dừng, control plane khởi động lại: lên được, `/readyz` 200 với `clickhouse:
    degraded`; đăng nhập local, danh sách policy chạy; tổng quan, tìm sự kiện, timeline trả 503
    `EVENTS_UNAVAILABLE`. ClickHouse chạy lại: `clickhouse: ok` sau 7 s.
  - `lab-chain` pass; `smoke` pass sau khi khởi động lại container `ui`: control plane đổi IP khi
    khởi động lại, nginx của container `ui` giữ IP cũ (đúng lỗi 502 mà UI nhúng bỏ được; cổng
    18090 không bị).

## 5. Còn lại

- Compose Compact không còn container `ui`, Keycloak overlay: A09.
- User ClickHouse riêng cho truy vấn của UI (kế hoạch ghi ở rủi ro "truy vấn nặng"): làm cùng
  compose A09 khi tách user.

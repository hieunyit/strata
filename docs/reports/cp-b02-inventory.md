# CP-B02 · Phần 1: inventory và hiển thị

Ngày 21/10/2026. Từ main sau merge #295 (`7cdb41f`).

Hello/heartbeat có OS/architecture, phiên bản agent, ABI và capability (unknown với agent
không báo). Lưu PostgreSQL (migration 0030); trường telemetry được giới hạn kích thước,
ký tự và số capability. Không dùng thông tin node tự báo để cấp quyền.

Fleet admin API/UI thêm inventory, desired/actual, drift và trạng thái chứng chỉ:
unknown, expired, expiring trong 7 ngày, healthy. Có thời điểm nhận inventory trong API.
Các trường protobuf là bổ sung, không đổi ABI hay định dạng bundle.

Kiểm đã chạy trên nhánh tích hợp B02, CPU 6–10:

- Backend `go test -p 1 -race ./store ./fleet ./admin ./policy`: PASS.
- Agent `go test -race ./internal/control ./internal/agent ./pkg/bundlefmt ./cmd/strata-agent`: PASS.
- UI lint/build PASS; Vitest 30 files, 246 tests PASS.
- Playwright `tests/fleet.spec.ts`: 4 passed (18.9s), gồm inventory/desired/certificate.
- `buf generate` hai template, `buf lint`: PASS; client TypeScript sinh từ OpenAPI.
- golangci-lint: 0 issues trên agent và control plane; shellcheck sạch.

Phần 2 bổ sung manifest module, suy requirements từ signed bundle, chặn rollout/fetch khi
node thiếu capability, và kiểm automatic staging. Vì thế chưa đánh CP-B02 Done ở phần 1.
Không đổi B03, không deploy vào lab chung/staging/production.

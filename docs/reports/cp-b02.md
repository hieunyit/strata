# CP-B02 · Inventory và kiểm tương thích

Ngày 21/10/2026. Nền: main sau merge #295 (`7cdb41f`). PostgreSQL/ClickHouse giữ nguyên;
không làm B03. Chia ba PR inventory, manifest và compatibility để review độc lập.

## Thay đổi

- Hello/heartbeat có OS/architecture, agent, ABI và capability. Input giới hạn kích thước,
  số capability và ký tự; node cũ không báo được giữ trạng thái chưa biết.
- Metadata bền trong PostgreSQL; admin API và Fleet UI có inventory, desired/actual, drift,
  thời gian quan sát và trạng thái chứng chỉ (unknown/expired/expiring/healthy; ngưỡng 7 ngày).
- Module package có manifest sinh từ checkout dùng build module, gắn SHA-256 binary, phiên
  bản module/ABI và danh sách tính năng. Agent kiểm hash và đối chiếu metrics runtime trước
  khi báo capability. Manifest thiếu → unknown; dữ liệu sai không được mặc định thành hỗ trợ.
- Từ signed bundle v1 suy ra section/snippet/max_args cần hỗ trợ; metadata không đổi format
  bundle hay ABI. Kiểm trước ghi bundle và kiểm lại trong transaction rollout, trước khi sửa
  rollout cũ/desired. Node kết nối muộn hoặc hạ cấp bị chặn tải bundle thiếu capability.
- Automatic staging cũng tính requirements, không tạo đường bỏ qua kiểm tra.

## Kiểm chứng đã chạy

- Backend `go test -p 1 -race ./store ./fleet ./admin ./policy`: pass; kiểm unknown không tạo
  rollout, đủ capability cho rollout, báo thiếu sau hạ cấp không hủy rollout hiện tại.
- Agent `go test -race ./internal/control ./internal/agent ./pkg/bundlefmt ./cmd/strata-agent`:
  pass; manifest hash/runtime mismatch, field lạ, quá giới hạn; signed requirements có test
  signature, truncation và overflowing bounds.
- UI `npm run lint`, `npm test -- --maxWorkers=2 --minWorkers=1`, `npm run build`: pass,
  30 files / 246 tests; test Fleet mới kiểm inventory, desired drift và chứng chỉ sắp hết hạn.
- `buf generate` hai template và `buf lint`: pass; client TypeScript sinh từ OpenAPI.
- Generator manifest kiểm ABI 1.8, section 8–16 và hash với binary fixture.
- Lint Go: control plane và agent đều `0 issues.`; shellcheck build.sh sạch.
- Gate toàn control plane `go test -p 1 -race ./...` với PostgreSQL/ClickHouse thật: exit 0.
  Trích: cmd/server 85.567s, ingest 27.634s, store 30.126s; các package còn lại PASS.
- Part inventory được kiểm riêng tại `ab0791e`: store/fleet/admin `-race` PASS, lint 0 issues.
- Playwright Fleet: 4 passed (18.9s), có ca inventory/drift/chứng chỉ.

Tự review: (1) điều kiện có test/output như trên; (2) lỗi persist/manifest/preflight trả về;
(3) metadata/manifest/section directory có giới hạn; (4) không dùng node telemetry cấp quyền;
(5) phạm vi đúng Fleet/agent/bundle metadata/UI và tài liệu; (6) lint/format sạch.

CPU 6–10; PostgreSQL riêng `strata-compact-b-pg`; không dùng lab chung/staging/production.

## Giới hạn và vận hành

Manifest mô tả binary trên đĩa. Sau nâng module phải reload NGINX và restart agent; metadata
không chứng minh một tiến trình đang giữ bản mmap cũ có cùng tính năng. Chữ ký và kiểm layout
của engine vẫn là kiểm soát cuối; không dùng inventory để cấp quyền.

Không chạy benchmark hay build lại toàn bộ gói deb/rpm trong lượt này. Kiểm Go không thay thế
nghiệm thu package và diễn tập nhiều node. B01/B04/B05 theo PR tiếp theo.

Final integration correction: missing optional manifest classification must survive wrapped
errors without ignoring a missing binary referenced by an existing manifest. The real agent
startup regression and fix are recorded in `cp-b-integration-fixes.md`.

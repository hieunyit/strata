# CP-B02 · Phần 2: manifest capability của module

Ngày 21/10/2026. Phụ thuộc PR inventory.

Gói module sinh manifest từ đúng checkout dùng build, gồm binary SHA-256, module version,
ABI và capability. Đường binary phù hợp deb/rpm; agent đọc manifest mặc định tại
`/etc/strata/module-manifest.json`, kiểm hash và đối chiếu runtime metrics trước khi báo.
Không có manifest/runtime không khớp → không báo capability; không suy từ version thành
hỗ trợ mọi tính năng. File tối đa 16 KiB, binary thường tối đa 64 MiB, capability tối đa 64.

Kiểm agent `go test -race ./internal/control ./internal/agent ./pkg/bundlefmt ./cmd/strata-agent`
PASS; `golangci-lint run ./...` 0 issues. Test manifest từ chối hash sai, runtime không khớp,
field lạ, capability sai và file quá lớn. Generator fixture kiểm ABI 1.8, section 8–16, hash.
Shellcheck build.sh sạch. Không thêm dependency, không đổi ABI/C hay đường request.

Manifest phản ánh binary trên đĩa; nâng module cần reload NGINX và restart agent. Không xem
telemetry là bằng chứng cấp quyền hay thay kiểm layout/chữ ký engine. Chưa build toàn bộ
package mới; kiểm rollout dùng manifest nằm trong PR requirements tiếp theo.

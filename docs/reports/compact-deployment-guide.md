# Compact deployment and operations documentation

Yêu cầu PO: viết chi tiết tài liệu cài đặt, cấu hình và triển khai. Tài liệu mới ở
[docs/operations](../operations/README.md), gồm trang tra cứu và 7 chương, 1.920 dòng.
Giữ PostgreSQL/ClickHouse, local auth default, Keycloak tùy chọn; B03 vẫn loại khỏi
phạm vi. Không đổi runtime, API, dependency, migration hoặc cấu hình triển khai.

Đối chiếu main A/B `ccf04bf7eaefb26ca969cd12ac33d917448e13bf` và C preview
`b0ec2095aa701031477165fb4936b32931136352`. Phân biệt lịch sử merge/phát hành và
source đã kiểm, không nhận C là đã lên main hoặc discovery là runtime enforcement.

Nội dung: topology/ports/DNS/TLS, sizing có giới hạn, build/image/package provenance,
init và password PostgreSQL, secrets/flag/env/YAML, NGINX/Fleet, RBAC/SSO/S3/Vault,
release/replay/duyệt/canary/rollback, health/doctor/troubleshooting, backup metadata,
ClickHouse backup lạnh, restore/nâng cấp và các tính năng C với quota/retention.
README gốc, Compact README và runbook trỏ tới cẩm nang mới.

## Kiểm chứng tài liệu

Build binary CLI từ source C bằng Go 1.26.9, CPU 6–10; exit 0. Dùng script kiểm tạm
trong `build/docs-check/` (gitignore) để trích ví dụ, kiểm liên kết, `bash -n`, YAML,
flag/directive hiện có và chạy `strata-control-plane config validate` cho từng ví dụ
với file secret tổng hợp 0600. Không kết nối database hay dùng credential thật.

Output thực:

```text
9 config examples: valid
{"bash_blocks": 33, "chapters_and_index": 8, "local_links": 46,
 "nginx_strata_directives": 10, "yaml_control_plane_examples": 9}
Main A/B compatibility: 63 YAML entries accepted by exact main key map
Compact Compose: valid
Keycloak overlay Compose: valid
tar (GNU tar) 1.34
```

Ánh xạ key main lấy từ `config.Keys()` của đúng commit main, không suy từ nhánh C.
Hai Compose được kiểm bằng `docker compose ... config --quiet` với password giả,
exit 0. Xác nhận image ClickHouse ghim có GNU tar dùng cho ví dụ backup lạnh.
`git diff --check` sạch.

Giới hạn: kiểm cú pháp/contract không thay nghiệm thu cài mới, HTTPS/SSO thật,
NGINX worker, backup/restore dữ liệu thật, tải hoặc SLA. Không chạy diễn tập mới,
benchmark, CI GitHub, không thay shared lab/staging/production. Tham khảo tính năng
và bằng chứng runtime sẵn có trong các báo cáo A/B/C được liên kết từ cẩm nang.

Tự review: lệnh không chứa secret thật; không dùng insecure/bỏ chữ ký; restore cần
đích cô lập và giữ volume cũ; không hứa zero-loss, HA nhiều CP, CH nằm trong backup
metadata hay telemetry chưa có. Thay đổi chỉ gồm tài liệu; PR tách theo chương để
mỗi phần dưới khoảng 400 dòng.

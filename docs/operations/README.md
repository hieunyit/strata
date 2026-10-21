# Cẩm nang cài đặt và vận hành Strata Compact

Tài liệu dành cho người cài mới, quản trị hệ thống và trực vận hành. Đi theo thứ tự
các chương trong lần triển khai đầu; khi có sự cố, dùng bảng tra cuối trang.

**Phương án chuẩn:** giữ PostgreSQL và ClickHouse; đăng nhập local mặc định; UI nhúng;
artifact trên filesystem; ký bundle bằng file Ed25519; một control plane hoạt động.
Keycloak/OIDC, S3/MinIO, Vault và Grafana là các thành phần bổ sung.

## Phiên bản và phạm vi

Mốc đối chiếu: 21/10/2026. Cấu hình và lệnh được đối chiếu trực tiếp với source:

| Phạm vi | Mốc source | Khả dụng |
| --- | --- | --- |
| Compact A và B01/B02/B04/B05 | `ccf04bf7eaefb26ca969cd12ac33d917448e13bf` | Đã merge `main` tại thời điểm viết |
| C03/C01/C02/C04/C05 | `b0ec2095aa701031477165fb4936b32931136352` | Chuỗi PR #321–#388, chưa merge tại thời điểm viết |
| B03: quản lý cấu hình NGINX | Chưa triển khai trong Compact | Người vận hành quản lý file NGINX |

Các chương 01–06 hướng dẫn nền tảng A/B. Chương 07 đánh dấu rõ phần cần C; không chép
khóa YAML của C vào binary A/B vì parser từ chối khóa không biết. Cài bản nào phải
đọc tài liệu và mẫu cấu hình **của đúng checkout đó**. Bảng trên là ảnh chụp lịch sử,
không phải thông báo rằng C đã phát hành.

Không có cam kết image công khai hoặc release binary cho mọi bản source. Lệnh trong
cẩm nang dùng image/gói tự build tại chỗ. Tag và digest thực tế phải được lưu trong
biên bản triển khai. Việc test chức năng thành công không thay cho nghiệm thu tải,
chất lượng rule và quyết định bật enforce trên lưu lượng thật.

## Các chương

1. [Chuẩn bị, kiến trúc và cài control plane](01-installation.md): máy chủ, DNS,
   firewall, build, init, kiểm tra lần đầu, đưa UI sau HTTPS.
2. [Tham chiếu cấu hình](02-configuration.md): ưu tiên flag/env/YAML, secrets,
   đường dẫn, bảng các nhóm cấu hình, quy trình đổi cấu hình.
3. [Triển khai node NGINX và agent](03-nginx-nodes.md): gói, tương thích, enrollment,
   cấu hình route, xác nhận worker, nâng cấp node và lựa chọn standalone.
4. [Tài khoản, phân quyền và tích hợp tùy chọn](04-security-integrations.md): local,
   khôi phục admin, ứng dụng/môi trường, Keycloak, S3, Vault, metrics.
5. [Phát hành policy và vận hành hằng ngày](05-operations.md): replay, duyệt,
   immutable release, canary, rollback, health/doctor, xử lý lỗi.
6. [Backup, khôi phục và nâng cấp](06-backup-upgrade.md): phạm vi dữ liệu, lịch sao lưu,
   restore cùng máy/máy mới, ClickHouse, thay phiên bản và diễn tập.
7. [Tính năng C: cấu hình và giới hạn](07-compact-c.md): MFA, privacy, điều tra,
   vòng đời rule/exception, cảnh báo/báo cáo, discovery mặc định tắt.

## Quy ước để chạy lệnh

- Lệnh `deploy/...` chạy tại thư mục gốc của checkout Strata trên máy control plane.
- Lệnh có `systemctl`, đường dẫn `/etc/nginx` hoặc installer node chạy trên **node**;
  các thao tác hệ thống cần quyền root hoặc cơ chế nâng quyền của tổ chức.
- `waf.example.test` là DNS Fleet; `console.example.test` là DNS UI;
  `api.example.test` là ứng dụng được bảo vệ. Thay bằng DNS thuộc hệ thống của bạn.
- Không dùng khóa fixture/test, mật khẩu mẫu hay token trong Git cho triển khai.
- Không chạy các script staging/prod-sim để cài Compact. Lab phải có project, volume,
  hostname, port và credential riêng; không trỏ restore vào database dùng chung.
- Không bật shell tracing (`set -x`) khi chạy init/backup/restore hoặc xử lý credential.

Hàm `dc` trong chương 01 được dùng ở các chương sau. Mở shell mới phải khai báo lại
hàm và các biến môi trường triển khai. Giữ nguyên tên Compose project qua nâng cấp:
đổi project có thể tạo volume rỗng mới thay vì dùng dữ liệu cũ.

## Tra nhanh theo tình huống

| Tình huống | Đọc |
| --- | --- |
| Cài mới một máy control plane | Chương 01, sau đó 02 và 06 |
| Giữ NGINX sẵn có, thêm WAF | Chương 03 |
| Muốn local auth, không Keycloak | Chương 04 §1 |
| Bổ sung SSO mà vẫn giữ local | Chương 04 §4 |
| Policy đã sửa nhưng request chưa đổi | Chương 05 §2–4, chương 03 §5 |
| UI vào được nhưng mất sự kiện | Chương 05 §7 |
| Quên admin hoặc mất MFA | Chương 04 §2; C: chương 07 §1 |
| Mất máy hoặc cần quay về phiên bản cũ | Chương 06 |
| Muốn tự khám phá API/OpenAPI | Chương 07 §6; cần C và phê duyệt telemetry |

## Nguồn kỹ thuật

- [Compose Compact](../../deploy/compact/compose.yaml), [script cài](../../deploy/compact/install.sh).
- [Mẫu YAML theo source](../../control-plane/config/example.yaml),
  [ánh xạ khóa cấu hình](../../control-plane/config/config.go).
- [Directive NGINX](../../connectors/nginx/README.md), [runbook sự cố](../runbook/README.md).
- [OpenAPI REST bổ sung](../spec/openapi.yaml), [API sinh từ proto](../spec/admin.swagger.json).
- [Kế hoạch Compact](../plan/compact-ops-plan.md), [báo cáo C và thứ tự PR](../reports/compact-c-implementation.md).

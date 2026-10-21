# Sức khỏe và chẩn đoán Compact

Trang **Sức khỏe** (`#/health`) gọi API có xác thực `GET /v1/health`, cần quyền
`nodes:read`. Trang làm mới mỗi 5 giây và ghi thời điểm quan sát từng nguồn. Dữ liệu
quá 90 giây chuyển sang `stale`; không có quan sát là `unknown`, không phải số 0.
Nếu API lỗi hoặc ảnh chụp cũ đi trong lúc request treo, giao diện cũng mất trạng thái xanh.
Danh sách phân trang 50 node; API giới hạn 1.000 node và báo khi bị cắt.

Kiểm tra PostgreSQL, lease, ClickHouse, dung lượng filesystem artifact, ingest queue/lag,
operation lỗi 24 giờ, request không kiểm đủ/body bỏ qua/breaker/shadow, heartbeat,
desired/actual bundle, hạn chứng chỉ và spool. Mỗi mục có hướng xử lý. Số đếm là dữ liệu
chẩn đoán; heartbeat không chứng minh mọi worker còn chạy hoặc đã reload module.

Tài khoản theo phạm vi chỉ thấy node và sự kiện được phép. Số đếm của toàn node không
có chiều route nên bị ẩn với tài khoản này. Không suy từ số 0 sự kiện thành đủ coverage.
Đĩa của PostgreSQL/ClickHouse từ xa chưa có nguồn đo và được ghi `unknown`.

## Chạy doctor

Chạy binary bằng cùng cấu hình và môi trường bí mật của control plane:

```bash
strata-control-plane doctor -config /etc/strata/config.yaml
strata-control-plane doctor -config /etc/strata/config.yaml -json
strata-control-plane doctor -config /etc/strata/config.yaml \
  -support-bundle /var/tmp/strata-support-example.tar.gz
```

Lệnh chỉ đọc: kiểm schema đang có, lease, dữ liệu đã lưu và filesystem; không migrate,
khởi động worker hay lấy lease. Nó không thấy queue của process control plane đang chạy,
vì vậy nguồn ingest trực tiếp là `unknown`; dùng trang Sức khỏe để xem nguồn đó.
Biến `STRATA_CONFIG` có thể cung cấp đường dẫn thay cho `-config`. Các secret vẫn lấy
từ cơ chế cấu hình hiện có; không đưa mật khẩu vào dòng lệnh hoặc báo cáo.

| Mã thoát | Ý nghĩa |
| --- | --- |
| 0 | Các nguồn có trạng thái healthy |
| 1 | Lỗi lệnh, đọc cấu hình hoặc xuất file |
| 2 | Có degraded, stale hoặc unavailable |
| 3 | Có nguồn unknown, không có lỗi thuộc nhóm 2 |

Mã 3 có thể xuất hiện bình thường với nguồn đĩa từ xa hoặc queue trong process khác.
Đọc trạng thái từng mục trước khi đưa lệnh vào cảnh báo tự động.

## Gói hỗ trợ

File đích phải chưa tồn tại; file thường có sẵn và symlink đều bị từ chối. Archive và
các thành viên dùng mode `0600`, gồm:

- `health.json`: trạng thái và số đếm được phép; node đổi thành tên giả `node-001`…
- `config.json`: chỉ các thiết lập boolean/số/thời lượng nằm trong allowlist.
- `doctor.log`: các dòng trạng thái chẩn đoán do doctor tạo.
- `manifest.json`: phiên bản định dạng, kích thước và SHA-256 của ba file trên.

Không sao chép log thô, file cấu hình gốc, credential, IP, URI hay request input.
Trường lạ, chuỗi advice tùy ý và giá trị ngoài allowlist bị loại. Bản này chưa có pipeline
privacy C03; dùng allowlist riêng chặt hơn để không cần xử lý lại dữ liệu request.
Kiểm archive trước khi chuyển cho bên hỗ trợ và giữ file ở nơi chỉ người vận hành đọc được.

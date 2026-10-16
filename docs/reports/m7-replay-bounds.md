# M7 · Giới hạn và xác thực mẫu replay

Collector mặc định từ chối nếu không có nguồn xác thực. Server dùng cấu hình lấy mẫu hiện hành, node chưa thu hồi, key ID đúng và policy trong bundle active/desired của node để quyết định nhận. Không tin policy/keyID node tự khai báo.

Giới hạn: tối đa 128 nhóm pending, 64 MiB tổng, 8 MiB/node, sample 8 KiB và MaxRows/file. Phần đang ghi vẫn tính vào ngân sách; ghi tuần tự, timeout 10 giây, shutdown flush có hạn 5 giây. Số bị từ chối được đếm Dropped.

Kiểm chứng cục bộ: `go test -race ./replay ./store ./cmd/server` PASS; golangci-lint toàn control-plane `0 issues.`. `TestCollectorLimitsAndAuthorization` kiểm thiếu quyền, key cũ, policy lạ, sample quá lớn, số nhóm và RAM, giải phóng quota sau flush. Test PostgreSQL thật `TestReplaySampleScopeInPostgres`: PASS (node active, sampling tắt/bật, policy scope và thu hồi). Không thay cờ pháp chế hay bật sampling.

Mẫu cũ trong spool có key đã xoay sẽ bị bỏ; đây là dữ liệu best effort, không phải sự kiện bảo mật. Giới hạn là ngân sách ước lượng dữ liệu giữ lại, không phải cam kết RSS tuyệt đối của runtime/parquet. Hosted CI không được dùng làm điều kiện hoàn thành theo chỉ đạo PO.

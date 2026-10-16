# M8 · Privacy trong Referer và header đặc biệt

Sửa `context_with` để áp dụng sensitive_fields cả với User-Agent/Referer; tên query được giải mã URL một lần trước khi đối chiếu danh sách mặc định và của policy. Tên encoding hỏng hoặc còn encoding mơ hồ được che bảo thủ. Mask trước truncation; giữ nguyên tên query và URL hợp lệ không nhạy cảm.

Kiểm chứng: test mới chạy trên code cũ FAIL (User-Agent private-agent lộ nguyên văn). Sau sửa `cargo test --offline -p libstrata --lib event::tests`: **14 passed, 0 failed**; clippy all-targets cho libstrata sạch, fmt sạch. Test gồm tên percent-encoded, field riêng, header riêng, double/malformed encoding và query an toàn.

Không đổi default policy, ABI hay dependency. Chỉ kiểm cục bộ theo chỉ đạo PO không chờ hosted CI. Dữ liệu đã lưu trước sửa không được tự động xóa/che lại.

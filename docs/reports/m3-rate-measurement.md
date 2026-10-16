Nhiệm vụ: M3 · chỉ đo prototype rate-limit theo lựa chọn người dùng 17/10
Nhánh: codex/m3-rate-measurements; base: codex/m2-runtime-docs.

Không đổi thuật toán, xử lý bảng đầy, default policy hoặc đường request. Harness trích đúng engine/src/ratelimit.rs của commit 95246eb19c2af79642e602336641952c43ecf03e; SHA-256 source 7714389f49ccee5fb84c390322fc3c169fd4668c5d96b03f884be3bf39791a18. P-01 §3 đã đọc từ docs/proposals trong worktree strata-p01; file đó chưa track/trạng thái chờ duyệt, không copy hay sửa. Việc giữ/đẩy slot hoặc block/pass khi đầy vẫn chưa quyết định; không tự triển khai enforcement.

Số đo cuối, raw ở m3-rate-measurement/:
- Hai IP va chạm, capacity 256, limit=3: khóa đích gửi 20 lần, được allow 20 thay vì 3; count lần cuối vẫn 1. Dư 17 allow.
- 512 khóa/256 slot, 5.120 request: ground truth cho 1.536 allow; prototype cho 4.518, dư 2.982. Chỉ dùng 226 home bucket, không dò chỗ trống; đây là pressure/collision, không phải chứng cứ đã dùng hết mọi slot.
- 8 thread × 2.000 trial: khởi tạo mất đếm/allow dư ở 16 trial, lật cửa sổ ở 13 trial. Race là quan sát phụ thuộc lịch; số trial có thể khác khi chạy lại, không đòi mọi lượt phải tái hiện để gọi phép đo hợp lệ.
- /Login và /login cho cùng hash; IPv6 cùng địa chỉ ở hai dạng text cho hash khác. Helper XFF khi direct peer được đánh dấu trusted lấy trái nhất và nhận cả garbage. Chưa có data path NGINX gọi helper này, không tuyên bố main bị spoof qua helper chưa tích hợp.
- 5 sample × 1 triệu check, CPU 6, release -O: 90,266..144,057 ns/check. Đây là thời gian component, không phải % overhead proxy, không thay cho benchmark <=2% hay test brute-force HTTP. Không dùng số hằng ở benchmark prototype làm bằng chứng.

Lệnh thực: trong image dev, mount git read-only, cpuset 6-10: tests/security/run-rate-state-probe.sh. Script ghim source, rustc --edition=2024 -D warnings -O; pressure pin 6-10, bench pin 6. rustfmt --check và bash -n PASS. JSON đủ 6 pressure case và 5 benchmark sample; metadata lưu toolchain, CPU, timestamp và hash source/harness/script/binary. Kết thúc ghi rõ có vulnerability observations, không gọi là security PASS.

Tự review: std-only, không dependency, không đổi prototype hoặc runtime; bảng, thread và vòng lặp harness đều hữu hạn, IP lab. Không khóa/I/O mới trên đường request vì chưa nối đường đó. M3 enforcement/shared-node/collision fix vẫn chưa hoàn tất; chỉ measurement hoàn thành theo lựa chọn hiện tại. Body CPU cũng giữ nguyên budget/fail mode. Không CI hosted, merge hoặc deploy.

H6 · native fault evidence · 18/10/2026 (UTC+7)
Nhánh `codex/h6-native-fault-evidence`, base `codex/h6-control-plane-process-restart` (`18a4576`). Chưa phải nghiệm thu toàn game day.

Thêm `tests/security/run-native-faults.sh`: mỗi lần chạy bắt buộc `make nginx-asan` trước `prove`, output directory mới trong `build/`, pin hai phiên bản NGINX, ASan/UBSan có lỗi thì dừng. Harness yêu cầu TAP đủ ba file có test thực/`Result: PASS`, từ chối plan skip toàn file và kiểm tra không có sanitizer report; ghi hash executable, archive Rust, test và source liên quan. Không xóa output cũ, không sửa test hoặc code production.

Các test hiện có được chạy nguyên vẹn:

| File | Kiểm chứng thực |
|---|---|
| `004-reload.t` | Hai worker từ chối bundle ký bằng key khác, giữ version đang hoạt động; từ chối version cũ không có signed rollback, nhận rollback đã ký; xử lý request/hot reload mà không mất chức năng chặn |
| `060-fail-mode-events.t` | Panic được bắt tại FFI; fail-open cho qua với event, fail-closed trả 503 và Event ID trùng sự kiện socket; counter riêng cho lỗi/budget/fail mode |
| `090-breaker.t` | Panic hàng loạt mở breaker trong 10 giây, degraded giữ lớp protocol; half-open/reopen/backoff/đóng lại; vượt CPU budget không tự mở breaker |

Lệnh chạy trong dev image (private target và Cargo registry cache, cpuset 6–10; `CARGO_NET_OFFLINE=true`):

```bash
tests/security/run-native-faults.sh 1.30.5 build/h6-native-faults-stable-final
tests/security/run-native-faults.sh 1.31.6 build/h6-native-faults-mainline-final
```

Kết quả: **PASS cả hai bản: Files=3, Tests=70, Result: PASS**; stable 72 giây, mainline 73 giây, không sanitizer report. Đây là số mục TAP top-level, không quy đổi thành số request HTTP hoặc coverage production. `sh -n` đạt; bốn ca version/path sai đều exit 2 trước khi build; bốn negative control cho evidence (zero tests, skip suite, sai file count, sanitizer report) đều bị từ chối. Lượt stable đầu chạy đủ 70 mục; chạy lại sau khi bổ sung guard từ chối TAP không thực thi/skip, không thay assertion test để làm xanh.

[Bằng chứng](evidence/h6-native-fault-evidence/) giữ output đầy đủ nén gzip, summary và hash executable/source. Có cảnh báo Perl về code sau `exec` và tên subtest dạng số; không có assertion failure. Test hooks `STRATA-TEST-PANIC`/`STRATA-TEST-BLOCK` chỉ cho lab; không phát hành binary trong PR. LSan tắt theo harness native, không suy ra không rò bộ nhớ. Không thay budget hoặc fail mode của sản phẩm; các cấu hình fail-open/closed là những nhánh test sẵn có.

Phạm vi còn thiếu: suite native dùng socket receiver của test, không có agent/ClickHouse thật cho panic hoặc bundle sai chữ ký. [Chain process CP](h6-control-plane-process-restart.md) có agent/ClickHouse nhưng fault khác; không ghép hai phép thử độc lập thành một chain đã được chứng minh. Lượt này cũng không đo activation stall/p99 dưới tải hoặc chạy game day trên staging. H6 và L3 vẫn mở cho các giới hạn đó.

Tự review: lệnh/output và hash đầy đủ; input/path bounded, lỗi process/prove/report được trả ra; không secret/token/private key xuất vào evidence; không đổi interface/dependency hay assertion cũ. Không chờ hosted CI, không merge/deploy; chỉ dùng lab riêng.

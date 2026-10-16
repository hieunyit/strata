Nhiệm vụ: H2 / #28 · đo lại độ đầy đủ của kiểm tra body; L3 / #49 · phép đo cold engine

Quyết định PO: **chỉ đo và tối ưu; không đổi chính sách xử lý hết budget**. PR này bổ sung phép đo, chưa có tối ưu engine và chưa đóng #28/#49.

Thay đổi:
- `strata-bench` đếm FULL/PARTIAL/BODY_SKIPPED, finding, block và lỗi trên từng request; không suy ra chất lượng từ verdict cuối cùng. Reject iterations/cold bằng 0 và tên ca không tồn tại.
- Thêm XSS ở đầu/cuối form, JSON và multipart; unit test kiểm JSON hợp lệ, vị trí payload, Content-Length. Phân loại inspection dùng chung logic với event, không đổi semantics.
- `tests/perf/body-budget.sh` build binary trước khi đo; lưu SHA của bundle/public key/executable, commit và digest diff nguồn; chạy tuần tự 10 ms, không giới hạn, cold có/không warm.

Kết quả engine-only, dữ liệu tổng hợp, full pack **9.054 rule**, bundle SHA-256 `604284d6a1c919b9ce296f8369b251fa093ded0944e44fb78cc82d5c89ea1a9c`. Raw JSON và metadata trong thư mục `h2-body-budget/` kèm báo cáo này. Máy lab dùng CPU set 6–10; còn dịch vụ khác chạy trên host. Không lấy đây làm SLO p99 sản xuất hay TPS NGINX.

| Ca | n | p50 không giới hạn (ms) | FULL/PARTIAL (không giới hạn) | Chặn (không giới hạn) | FULL/PARTIAL (10 ms) | Chặn (10 ms) |
| --- | ---: | ---: | --- | ---: | --- | ---: |
| small | 100 | 0.67 | 100/0 | 0 | 100/0 | 0 |
| nul | 100 | 0.27 | 100/0 | 100 | 100/0 | 100 |
| attack | 100 | 0.83 | 100/0 | 100 | 100/0 | 100 |
| json | 100 | 0.76 | 100/0 | 0 | 100/0 | 0 |
| 64k | 100 | 68.04 | 0/100 | 0 | 0/100 | 0 |
| json64k | 100 | 48.79 | 100/0 | 0 | 0/100 | 0 |
| 1m | 20 | 294.96 | 0/20 | 0 | 0/20 | 0 |
| form-front | 100 | 65.35 | 0/100 | 100 | 0/100 | 0 |
| form-back | 100 | 54.48 | 0/100 | 0 | 0/100 | 0 |
| json-front | 100 | 41.94 | 100/0 | 100 | 0/100 | 0 |
| json-back | 100 | 38.55 | 100/0 | 100 | 0/100 | 0 |
| multipart-front | 100 | 27.16 | 100/0 | 100 | 0/100 | 0 |
| multipart-back | 100 | 28.12 | 100/0 | 100 | 0/100 | 0 |

Diễn giải:
- Budget 10 ms: mọi ca body lớn trên đây đều PARTIAL và không có finding; không gọi đây là đã kiểm tra an toàn. Action 0 là verdict engine; connector quyết định theo fail mode, phép đo này không gửi HTTP qua NGINX.
- Không giới hạn: JSON/multipart tìm thấy XSS ở cả hai đầu; form cuối không thấy XSS vì vượt max_args mặc định. PARTIAL có thể do bỏ bớt args dù error=0. Tăng thời gian không giải quyết giới hạn args.
- `engine_serial_rps` là nghịch đảo thời gian trung bình một engine tuần tự, không phải throughput proxy. p99 với 100 mẫu (1 MiB: 20 mẫu) chỉ là thống kê bộ đo nhỏ này.
- Cold engine: cả hai chế độ 10/10 FULL, 0 lỗi ở budget 10 ms. Không warm: first p50 3,315 ms, max 4,255 ms; có warm: first p50 1,690 ms, max 2,261 ms. Đây là mô hình `Engine::map`/Tx trên một thread; chưa là thử worker reload của NGINX, nên chưa đóng #49.

Kiểm chứng local:
```
cargo test --offline -p strata-eval --bin strata-bench
# body_probes_are_valid_and_at_both_ends: PASS (1 test)
cargo test --offline -p libstrata --lib tx::tests
# 36 passed; 0 failed
cargo clippy --offline -p strata-eval -p libstrata --all-targets -- -D warnings
# PASS
```
Script đo chạy thành công; validator kiểm đủ 13 ca mỗi chế độ và FULL+PARTIAL+BODY_SKIPPED=n. Chạy trong dev image; worktree cần mount read-only common git dir để thu metadata (`-v /home/hellc/strata/.git:/home/hellc/strata/.git:ro` trên máy lab này). Không có thay đổi fail mode, oversize, max_args, budget mặc định hay rule.

Còn lại: profile để chọn tối ưu có cùng mức phát hiện; đo lại qua NGINX/FFI với ASan khi sửa hot path; lấy phân bố body/args thực của route trước khi xác lập miền hỗ trợ. Chưa có dữ liệu này nên không suy ra ứng dụng chấp nhận body lớn an toàn.

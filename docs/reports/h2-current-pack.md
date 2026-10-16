Nhiệm vụ: H2 / #28 · đo pack hiện tại 9.064 rule; L3 / #49 · cold engine

Đính chính báo cáo H2 trước: bundle cache 9.054 rule thiếu 300001–300010 trong rules/gaps/. Kết quả cũ chỉ áp dụng bundle cache đó, không đại diện full pack hiện tại. Lần này build bundle mới từ rules/ tại source 991c4bb (các PR trước H7 không sửa nội dung rule), SHA bc051ed06bbb3f0645709942bf5e0a82a2a239ac2636b38ff21d421f130e1506.

Lệnh trong dev image: ITERATIONS=30 tests/perf/body-budget.sh build/current-pack/baseline.sbn connectors/nginx/t/fixtures/bundle.pub build/current-pack/results. Build strata-bench mới trước đo (31,58 giây); đủ 13 ca mỗi budget, validator FULL+PARTIAL+BODY_SKIPPED=n. Với body 1 MiB harness giữ tối thiểu 20 mẫu. Không đổi mã engine/chính sách trong PR này.

| Ca | n | p50 unlimited (ms) | FULL/PARTIAL unlimited | Block unlimited | FULL/PARTIAL 10 ms | Block 10 ms |
|---|---:|---:|---|---:|---|---:|
| small | 30 | 0.56 | 30/0 | 0 | 30/0 | 0 |
| nul | 30 | 0.21 | 30/0 | 30 | 30/0 | 30 |
| attack | 30 | 1.52 | 30/0 | 30 | 30/0 | 30 |
| json | 30 | 1.44 | 30/0 | 0 | 30/0 | 0 |
| 64k | 30 | 43.45 | 0/30 | 0 | 0/30 | 0 |
| json64k | 30 | 39.78 | 30/0 | 0 | 0/30 | 0 |
| 1m | 20 | 149.00 | 0/20 | 0 | 0/20 | 0 |
| form-front | 30 | 42.52 | 0/30 | 30 | 0/30 | 0 |
| form-back | 30 | 41.23 | 0/30 | 0 | 0/30 | 0 |
| json-front | 30 | 29.76 | 30/0 | 30 | 0/30 | 0 |
| json-back | 30 | 32.31 | 30/0 | 30 | 0/30 | 0 |
| multipart-front | 30 | 23.06 | 30/0 | 30 | 0/30 | 0 |
| multipart-back | 30 | 23.38 | 30/0 | 30 | 0/30 | 0 |

Mọi ca body lớn ở budget 10 ms đều PARTIAL và budget_errors=n. Unlimited: JSON/multipart tìm được XSS cả hai đầu; form sau vượt max_args nên không tìm được XSS. Đây chưa là tối ưu, chưa đóng #28. Không tăng budget, giảm max_args hay thay fail mode/oversize để làm số đo đẹp hơn.

Cold engine 10/10 FULL, 0 lỗi cho cả hai chế độ: không warm first p50 5,865 ms, max 6,886 ms; warm first p50 4,024 ms, max 6,093 ms. Chưa phải NGINX cold worker/reload, không đóng #49.

Các giá trị thay đổi đáng kể giữa lượt do host còn dịch vụ khác. Không so bộ 30 mẫu này với bộ 100 mẫu cũ để tuyên bố tăng tốc; đây là baseline đúng artifact. Dữ liệu [h2-current-pack/](h2-current-pack/) có hashes executable/source/bundle và JSON từng workload. Generated engine-only, không phải proxy TPS hay SLO sản xuất. Tất cả lệnh đo thành công; không có thay đổi Rust nên giữ bộ regression/lint đã chạy trong PR #125, không tuyên bố chạy lại sanitizer.

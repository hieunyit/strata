Nhiệm vụ: H2 · bảo vệ cache nội dung khỏi hash collision có thể tạo từ request

Callgrind khoanh vùng chi phí ở prefilter/cache. Cache scans_by_bytes dùng FastBuildHasher (rotate-left(5) XOR) cho raw/transformed input. Hai byte thay đổi cách nhau 64 vị trí triệt tiêu nhau; test tạo 1024 giá trị khác nhau đều cùng một hash trước sửa. Đây là khả năng gây va chạm hàng loạt, không phải bằng chứng đã có tấn công production.

Đổi riêng bảng nội dung sang RandomState của thư viện chuẩn. Seed được tạo lúc map bundle trong CompiledOperators, clone vào cache; không khởi tạo OS randomness lần đầu trên worker request path. Các bảng địa chỉ/index vẫn giữ hasher cũ. Không thêm dependency/unsafe/ABI, không đổi rule, budget, fail mode, oversize hoặc max_args. Thử đổi memo transform sang hash map bị loại vì không có lợi ích ổn định, không đưa vào patch.

Kiểm chứng:
```text
Trước: raw_content_hash_resists_repeated_xor_pairs FAILED — only 1 hash values for 1024 hostile keys
Sau: cùng regression PASS (>=1000 hash khác nhau)
cargo test --offline -p libstrata -p libstrata-ffi --all-features: 254 passed, 0 failed, 3 ignored
cargo clippy --offline -p libstrata -p libstrata-ffi --all-targets --all-features -- -D warnings: PASS
make nginx-asan NGINX_VERSION=1.30.5 (build mới sau thay đổi cuối)
make test-nginx-asan NGINX_VERSION=1.30.5: Files=20, Tests=595, 156 wallclock secs, PASS
no sanitizer reports
```

HTTP/3 riêng cần binary H3 nên vẫn skipped trong suite này; không coi đây là đã chạy H3 hay fuzz dài. 3 Rust ignored là stress/soak có sẵn, không tắt test.

So sánh engine-only cùng bundle hiện tại 9064 rule, mỗi lượt 100 mẫu, thứ tự A/B/B/A, các binary giữ bản copy/hash riêng. Host còn workload khác, độ trôi lớn:

| Ca | Mean A (µs) | Mean B (µs) | Thay đổi B/A |
|---|---:|---:|---:|
| json64k | 32759.69 | 30764.77 | -6.1% |
| 64k | 44559.76 | 45547.18 | +2.2% |
| small | 1093.75 | 1253.88 | +14.6% |
| headers | 997.97 | 1339.62 | +34.2% |

Số wall-clock chưa đủ kết luận tăng tốc chung; có lượt nhỏ chậm hơn rõ. Callgrind chỉ collect trong libstrata::eval::candidates, 10 warm + 10 mẫu JSON64k: 2.835.214.417 → 2.740.835.628 instruction refs (khoảng −3,3%). Đây là instruction count, không phải latency/throughput dưới Valgrind. Bản sửa nhằm loại hash collision đã chứng minh, không tuyên bố hoàn thành SLO.

Kiểm lại payload đầu/cuối: unlimited JSON/multipart đều 30/30 FULL và block; form trước 30/30 block nhưng PARTIAL, form sau 0/30 block do max_args; ở 10 ms cả 6 ca vẫn PARTIAL/budget_errors=30 và 0 block. Kết quả phát hiện không đổi; #28 vẫn mở, cần tối ưu tiếp và đo route thực.

Raw, hashes, regression đỏ và output checks ở [h2-content-hash/](h2-content-hash/). Không chờ hosted CI, không merge/deploy. Chưa chứng minh chống mọi CPU DoS; Hyperscan scan/transform vẫn chiếm chi phí lớn.

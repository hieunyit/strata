Nhiệm vụ: H2 · profile chi phí rule/prefilter, không đổi engine

`strata-bench --profile-cost` bật bộ lấy mẫu chi phí sẵn có ở 100%, bỏ mẫu warm-up, xuất top 20 ra stderr JSON (samples, total_ns, max_ns, rule ID hoặc phase prefilter). Không log payload. `recorded_engine_ns` của CLI này là 0 do không đi qua connector hạch toán tổng thời gian; không dùng làm mẫu số. Latency stdout là thời gian wall-clock đo riêng. Diagnostic có overhead lấy mẫu nên không dùng làm benchmark SLO. Từ chối kết hợp --cold/--rule-cost-ab vì hai chế độ không xuất profile này.

Thêm workload `headers` với header hợp lệ: JWT, ETag, custom text/filter và traceparent; giữ cases body hiện có. Mặc định budget/fail mode/max_args không thay đổi.

Kiểm chứng local:
```
cargo test --offline -p strata-eval --bin strata-bench: 1 passed, 0 failed
cargo clippy --offline -p strata-eval --bin strata-bench -- -D warnings: PASS
cargo build --release --offline -p strata-eval --bin strata-bench: PASS
--only json64k --iterations 30 --budget-us 0 --profile-cost: 30/30 FULL
validator: sample_every=1, sampled_requests=30, prefilter cost>0, FULL=n
```

JSON 65.749 byte trên full pack 9.064 rule: prefilter trung bình 29.57 ms/mẫu, là mục chi phí lớn nhất; 942100 và 941100 đứng sau. Raw và hash trong [h2-cost-profile/](h2-cost-profile/). Đây là cơ sở chọn tối ưu prefilter; không coi phép đo này là đã tối ưu hay đã đạt budget 10 ms. `perf stat true` bị kernel perf_event_paranoid=4 từ chối; không thay quyền/cấu hình host.

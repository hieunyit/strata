L3 · profile chẩn đoán first/warm · 2026-10-17

`engine/ffi/examples/cold_profile.rs` tạo transaction qua C ABI thật, map bundle căn trang và kiểm chữ ký. Hai request giống fixture NGINX cold probe (GET, query ordinary, bốn header). Marker Rust dùng cho Callgrind; không thêm C ABI production/dependency. Vùng đọc handle chỉ tồn tại khi engine còn live; transaction được giải phóng trước khi lấy rule-cost samples.

Chế độ này cố ý không có CPU limit và lấy mẫu cost 100% để nhìn đường thực thi; chỉ chạy offline, không đổi cấu hình proxy. Không dùng latency hay verdict này để kết luận request production kiểm đủ hoặc đạt SLO. Không chạy response phase trong diagnostic này.

Native diagnostic: first 4,829 ms; warm 0,916 ms. Ở first, rule 400215 chiếm 1,745 ms, các rule RCE 932235/932260/932250/932340 lần lượt 0,375/0,362/0,337/0,261 ms. Prefilter tổng 0,969 ms first và 0,634 ms warm. Dữ liệu trong `evidence/l3-cold-profile/requests.jsonl`; metadata giữ hash source/bundle. Chênh lệch với NGINX first 17 ms chưa được giải thích đầy đủ, không coi đây là root-cause proof cho toàn bộ fail-open.

```bash
# Trong dev image, mount cargo registry/target theo runbook dev:
cargo build --offline --release -p libstrata-ffi --example cold_profile
cargo clippy --offline -p libstrata-ffi --example cold_profile -- -D warnings
taskset -c 6 target/release/examples/cold_profile   build/current-pack/header-v4.sbn connectors/nginx/t/fixtures/bundle.pub
```

Build và clippy hoàn tất không lỗi. Example có assertion/unwrap để dừng ngay với fixture/ABI sai, không được gắn vào input người dùng hay service. Toàn bộ unsafe nằm trong `engine/ffi/`; không thêm unsafe vào engine. #49 vẫn mở; bản này chỉ cung cấp công cụ chẩn đoán.

Callgrind của binary diagnostic hiện tại chưa thu được instruction qua marker (0); không dùng lần chạy đó làm profile định lượng hay bằng chứng nguyên nhân. Rule-cost native phía trên có dữ liệu thực.

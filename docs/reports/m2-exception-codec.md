Nhiệm vụ: M2 · codec và scope của policy exception

Thêm module Rust an toàn, không dependency/unsafe/FFI mới: encode/parse có giới hạn, đối chiếu tập policy được flag, exact host/method/path/field, expiry bắt buộc và kiểm tra lại khi dùng. Tên argument phân biệt case và hỗ trợ UTF-8; header không phân biệt ASCII case. Giới hạn trước cấp phát, không tự hiểu wildcard hay bỏ suffix base64.

Kiểm chứng:
```
cargo test --offline -p libstrata --lib: 195 passed, 0 failed, 1 ignored
cargo clippy --offline -p libstrata --all-targets -- -D warnings: PASS
```
Ba test mới: round-trip + cắt ở từng byte + trailing data/flag sai; count/size/scope thù địch; policy/method/host/path/case/field/UTF-8 và đúng thời điểm hết hạn. Không sửa/tắt test cũ. Output trong m2-exception-codec/checks.log.

docs/spec/policy-exceptions.md ghi format candidate và ràng buộc cần giữ khi tích hợp. Chưa gán section kind/compatibility bit, chưa emit/load qua bundle, chưa nối compiler, API, decision hoặc replay. Vì code chưa chạy qua FFI nên không coi đây là test sanitizer cho exception runtime. Runtime sau đó phải loại đúng field trước rule evaluation, không bỏ cả rule chỉ vì violation đầu tiên trùng exception. M2 vẫn chưa hoàn tất; chưa merge/deploy, không chờ hosted CI.

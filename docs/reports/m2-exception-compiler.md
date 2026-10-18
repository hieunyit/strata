Nhiệm vụ: M2 · compiler cho exception đã ký
Nhánh: codex/m2-exception-compiler; base: codex/m2-exception-validation.

Compiler nhận exceptions trong policy JSON/YAML, bắt buộc ID, reason, scope và expires_unix_ms; tối đa 128/policy, 4.096 toàn bundle. Codec kiểm byte length và exact scope dùng chung với runtime. Từ chối Rule ID không tồn tại/ngoài managed, wildcard, body-wide, thiếu expiry, ID trùng và metadata rỗng. Chỉ thông tin scope/rule/expiry vào artifact node; metadata ID/reason/Block ID lưu ở policy. Phát section 10 cùng mandatory policy bit 4, nên engine cũ từ chối thay vì bỏ qua bảo vệ. Không cấu hình thì không phát section/flag.

Test mới từng thất bại vì schema chưa nhận exceptions (build/m2-compiler-red.log), sau sửa 2/2 PASS: artifact compiler ký thật map engine, bỏ đúng policy/field; field khác và policy khác vẫn chặn. Matrix input âm chạy trước ký. cargo clippy --offline -p strata-compiler --all-targets -- -D warnings và cargo fmt --all --check sạch. Toàn bộ test compiler và build release ghi ở m2-exception-compiler-checks.txt.

Tự review: codec bounded trước allocation; compiler xác minh managed Rule ID, không dùng unwrap trên input ngoài; không thêm dependency/unsafe. Phạm vi compiler/codec/schema/test/tài liệu. CPU/body/fail mode/oversize/max_args giữ nguyên. API và proto chưa tạo/giữ exception; bước tiếp theo phải nối chúng và chạy replay/four-eyes/deploy toàn luồng. Không merge hoặc kích hoạt, không chờ CI.

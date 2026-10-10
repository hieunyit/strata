# spec — đặc tả dữ liệu dùng chung giữa các luồng

- `ir.schema.json`: JSON Schema của IR mà compiler bundle nhận (rule sau khi nhập CRS/Sigma/ET hoặc viết tay). **Bản nháp W03-R-02, chờ luồng S duyệt.**
- `examples/ir/`: ví dụ `valid-*.json` (phải hợp lệ) và `invalid-*.json` (phải bị từ chối); `cargo test -p libstrata --test ir_schema` kiểm cả hai.

Định dạng control file và bundle: `docs/design/control-file.md`.

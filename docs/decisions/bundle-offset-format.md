# Quyết định: định dạng bảng offset tự định nghĩa cho bundle (không dùng crate rkyv)

10/10/2026 · W05-R-01 · đã duyệt

**Bối cảnh**: thiết kế yêu cầu bảng rule dùng "offset thay cho con trỏ (kiểu định dạng rkyv)" để dùng trực tiếp từ vùng mmap ở bất kỳ địa chỉ nào.

**Quyết định**: giữ định dạng hiện tại (`engine/src/rules.rs`, `docs/design/control-file.md`): các bảng bản ghi cố định kích thước, tham chiếu bằng chỉ số/offset, little-endian, mỗi section căn 4 KB; libstrata kiểm mọi bản ghi một lần khi nạp, sau đó đọc tại chỗ.

**Lý do**:
- Đã đạt đúng mục tiêu của rkyv: không deserialize, không copy (map bundle 16,8 MB cấp phát 184 byte), dùng được ở mọi địa chỉ map.
- Layout cố định, có tài liệu, độc lập ngôn ngữ: compiler ở control plane (Go hoặc Rust) đều sinh được; layout của rkyv phụ thuộc phiên bản crate và chỉ Rust sinh được.
- Kiểm hợp lệ tường minh, có test cho bản ghi đã ký nhưng không nhất quán.

**Hệ quả**: thêm cấu trúc mới (cây quyết định, schema) = thêm kind section và bản ghi cố định; kind lạ được bỏ qua để tương thích về sau.

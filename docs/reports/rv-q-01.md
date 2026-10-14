# Báo cáo RV-Q-01 · Trạng thái thật của tính năng

Nhiệm vụ: RV-Q-01 (bổ sung tuần 10 sau đánh giá bên ngoài, `docs/plan/review-response.md`)
Nhánh: `RV-Q-01-status`
Công cụ: Claude Code

## Đã làm

| Mục | Ở đâu |
| --- | --- |
| Bảng trạng thái | `docs/status.md`: 25 tính năng của danh mục trong `strata-overview.md`, cộng 18 năng lực nền tảng. Mỗi dòng ghi **Có** / **Một phần** / **Thiết kế** kèm bằng chứng |
| README dẫn tới bảng | `README.md` (mới: repo chưa có README ở gốc) |
| Số liệu cho báo cáo Gate A | `docs/status.md` §3: số fuzz thật (9 giờ 50 phút FFI ASan, 0 crash; PO hạ yêu cầu xuống 30–60 phút ngày 13/10), giới hạn của `catch_unwind`, route thí điểm là giả lập, hiệu năng chưa đạt mục tiêu, request không được kiểm |

## Xong khi → kết quả

> Mọi dòng "Có" trỏ tới test hoặc báo cáo; review tuần 10 kiểm bảng này.

- Mọi đường dẫn được trích trong `docs/status.md` đều được kiểm bằng script (đọc các đoạn
  `` `…` `` có dạng đường dẫn, kiểm `-e`): 0 đường dẫn thiếu. Hai mẫu glob đã được thay
  bằng file cụ thể.
- Kết quả: danh mục có 5 Có, 9 Một phần, 11 Thiết kế; nền tảng có 12 Có, 1 Một phần
  (`catch_unwind`), 5 Thiết kế.
- Review tuần 10 sẽ kiểm lại bảng này (mục riêng trong `docs/reports/w10-review.md`).

## Ghi chú

- Phân loại khắt khe: một tính năng chỉ là "Có" khi đúng phần mô tả trong danh mục chạy
  được và có test. Ví dụ: "Allowed methods" là Một phần, vì mới có rule chặn method lạ,
  chưa có danh sách theo policy.
- Bảng phải được cập nhật khi một PR đổi trạng thái của một tính năng (gợi ý cho mẫu
  báo cáo).

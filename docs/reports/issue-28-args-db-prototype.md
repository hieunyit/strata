# #28 phương án A: DB Hyperscan riêng cho tham số (prototype)

Ngày: 15/10/2026 · Nhánh: `issue-28-hs-args` (trên `issue-28-scan-once`, PR #85) · Người làm: Claude Code. PO duyệt làm A kèm B ngày 15/10/2026.

## 1. Kết luận

**Đề xuất không đưa A vào định dạng bundle.** Lợi ích nhỏ, còn bundle vượt giới hạn ký Vault.

| | Kết quả |
| --- | --- |
| Verdict | `prefilter_differential`: 11.590 request, 7.706 có rule khớp, **0 khác biệt** (engine tham chiếu, #85, section 8, section 10) |
| Tốc độ (sau khi sửa scratch, §3) | GET nhỏ −7%, JSON nhỏ +1%, JSON 64 KB −10%, form 64 KB −14%, form 1 MB −9% |
| Bundle gói đầy đủ | 20,99 MB → **26,32 MB**: vượt giới hạn ký Vault 24 MiB (25,17 MB) |
| Mục tiêu #28 (≤ 10 ms với body 64 KB) | Vẫn xa: JSON 64 KB 33 ms, form 64 KB 44 ms |

## 2. Cách làm

- **Compiler** `--hs-args`: section 10 `HYPERSCAN_ARGS`, block mode.
  - Chỉ gồm pattern của các điều kiện có ít nhất một target thuộc lớp tham số: `args*`, cookie, XML, `files*`. Gói đầy đủ có 2.640 trên 12.751 pattern.
  - Layout giống section 8, có bảng id → điều kiện riêng.
- **Engine**:
  - Giá trị chỉ được đọc dưới target lớp tham số và dài tối đa 2.048 byte thì scan bằng DB này.
  - Kết quả ghi rõ là "từ DB tham số". Điều kiện nào có pattern không nằm trong DB đó thì lấy lại kết quả bằng DB đầy đủ, nên verdict không đổi.
  - Engine cũ bỏ qua kind 10.

## 3. Phát hiện trên đường đi: scratch Hyperscan

Bản đầu làm request nhỏ chậm **6–7 lần** (0,6 ms → 4,8 ms).

- **Nguyên nhân**: `strata-hs` chỉ nhớ một id DB block cho scratch của thread, nên mỗi lần đổi DB lại gọi `hs_alloc_scratch`.
- **Cách sửa**: nhớ tối đa 4 id. Một scratch đã nới cho nhiều DB thì dùng được cho tất cả các DB đó.
- Bản sửa có test trong `strata-hs`. Nó chỉ cần khi có từ hai DB block trở lên, nên đi cùng nhánh prototype, không merge riêng.

## 4. Vì sao lợi ích nhỏ

DB tham số ít pattern hơn 5 lần, nhưng mỗi lần scan chỉ rẻ hơn khoảng 1,4 µs (từ khoảng 4,5 µs).

Cách đọc của tôi: chi phí cố định mỗi lần scan đến từ pattern regex phức tạp (CRS, chạy bằng NFA), không phải từ số lượng literal (ET, chạy bằng FDR). Các pattern regex phức tạp đó đọc tham số nên vẫn nằm trong DB nhỏ.

## 5. Hướng tiếp theo (chưa làm)

- **B**: `max_args` theo policy, đã làm ở nhánh `issue-28-args-limit`. Đây là cách giới hạn chi phí cho request có nhiều tham số.
- Đo chi phí theo từng pattern hoặc điều kiện trên giá trị ngắn để tìm nhóm NFA đắt nhất, rồi xem có viết lại hoặc tách được không (luồng S). Cần thêm công cụ đo.

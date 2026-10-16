# Báo cáo: Kế hoạch và Chuẩn bị Quan sát Canary 25% (72 giờ)

## 1. Thông tin chung
- **Nhiệm vụ**: Task 8 — Kế hoạch Canary 25% trong 72 giờ (Tuần 14, Khối B2)
- **Mục tiêu**:
  - Khảo sát và làm rõ cơ chế Canary 25% trên Strata WAF.
  - Định rõ đối tượng áp dụng: 2,500 basis points theo hàm băm ổn định `(Identity/IP, Policy)`.
  - Thiết lập chỉ số cảnh báo (5xx > 1%, block surge > $3\times$, FP surge).
  - Thiết lập quy trình 3 cấp độ phòng vệ và tự động rollback.
  - Ghi nhận trạng thái chu kỳ quan sát 72 giờ.
- **Tài liệu tạo**: `docs/runbook/canary-25.md`
- **Nhánh thực hiện**: `W14-OPS-canary-25`

## 2. Các điểm kỹ thuật chính

1. **Phân bổ đối tượng 25%**:
   - Sử dụng hàm băm FNV-1a + splitmix64 (`engine/src/canary.rs`).
   - Nhóm 25% ($\text{bucket} < 2500$): Chạy **Enforce** (chặn vi phạm).
   - Nhóm 75% ($\text{bucket} \ge 2500$): Chạy **Shadow** (chỉ log, `would_block = true`).
   - Giữ nguyên tính chất đơn điệu: các client thuộc nhóm 1% và 5% trước đó tiếp tục nằm trong nhóm 25%, không bị đổi trạng thái.

2. **Chỉ số và Ngưỡng ngắt (Guardrails)**:
   - 5xx rate $\ge 1.0\%$ $\rightarrow$ Kích hoạt `canaryFallback` khẩn cấp về Shadow.
   - Block surge $> 3\times$ $\rightarrow$ Cảnh báo P1 cho vận hành.
   - FP surge $\ge 5$ FPs $\rightarrow$ Tự cách ly rule (W14-G2-02).

3. **Tiến độ và Trạng thái Vận hành**:
   - Theo dõi tiến độ chung tại `AGENTS.md`: Việc kích hoạt chính thức Canary 25% trên Production yêu cầu Gate A hoàn tất.
   - Hạ tầng, policy config và runbook đã sẵn sàng.
   - Trạng thái hiện tại: **Đang chờ đủ điều kiện và dữ liệu quan sát 72 giờ**.

## 3. Tự review (Checklist mục 6a)
1. Đầy đủ định nghĩa đối tượng và cơ chế hash.
2. Ngưỡng cảnh báo và rollback 3 cấp rõ ràng.
3. Không tự ý kích hoạt trên production ngoài quyền hạn.

# Gate A · Shadow · báo cáo cuối tuần 10

Ngày: 14/10/2026. Người lập: Claude Code. Tiêu chí lấy từ `docs/plan/plan.md` (bảng
"Tiêu chí gate", dòng A, và "Chỉ tiêu chất lượng" của luồng S), có bổ sung theo
`docs/plan/review-response.md` (PO duyệt 14/10). Trạng thái tính năng chi tiết:
`docs/status.md`.

## 1. Kết luận

**Gate A chưa đạt trọn.** Đạt: shadow chạy được, sự kiện về ClickHouse, tra Block ID,
runbook đã diễn tập, chất lượng gói signature, conformance. **Chưa đạt**: hiệu năng (A1, A2).
**Chờ thời gian**: soak 24 giờ (tới 14/10 khoảng 10:35 UTC) và mốc 7 ngày của gói (tới
20/10 11:18 UTC).

Theo cột "Nếu chưa đạt" của plan: **giữ shadow, không bật canary**. Giai đoạn B (canary,
tuần 11–12) phải chờ RV-R-01 hoặc một quyết định ngoại lệ của PO (mục 4).

## 2. Từng tiêu chí

| # | Tiêu chí | Trạng thái | Bằng chứng |
| --- | --- | --- | --- |
| A1 | Overhead p99 < 1 ms (request < 64 KB) | **Chưa đạt** | Phase 0–1, Linux: GET +900 đến +1.160 µs (dao động quanh ngưỡng), POST form 64 KB +2,8 đến +3,2 ms (`w09-q-01.md` §7, #28). Gói đầy đủ: GET p99 +5,5 đến +6,6 ms; trên route thí điểm, JSON 300 byte 1,6–2,7 ms, upload 2–32 KB khoảng 20 ms (`w10-g2-01.md` §4) |
| A2 | Throughput giảm ≤ 10% | **Chưa đạt** | Phase 0–1, Linux: −43,3% / −39,6% (1.30.5 / 1.31.6), HTTP/2 −36 đến −38% (#27). Gói đầy đủ: −87% |
| A3 | Hot reload không rớt request | **Đạt, chờ soak** | `t/004-reload.t`, hot reload dưới tải (W08-N-01). Soak 24 giờ + ≥ 1.000 lần đổi bundle (`strata-soak-24h`, run `24h-rc3`) kết thúc khoảng 14/10 10:35 UTC; verdict sẽ ghi vào `w09-q-02.md` §3 |
| A4 | Fuzz không crash | **Đạt theo quyết định PO** | Plan ghi "72 giờ fuzz". PO quyết ngày 13/10/2026: 30 phút đến 1 giờ là đủ. Đã chạy: FFI dưới ASan khoảng 9 giờ 50 phút, khoảng 122 triệu lần chạy, 0 crash (W08-R-01). Lần đó dừng vì máy khởi động lại, không phải vì crash |
| A5 | Conformance 100% | **Đạt** | Corpus v1 qua engine và qua NGINX (W08-Q-01), `t/080-conformance.t` |
| A6 | Sự kiện về ClickHouse | **Đạt (từ 13/10)** | Block: từ W06. **Shadow: chỉ từ PR #55 (13/10)**; trước đó mọi sự kiện shadow bị ingest từ chối (#47). `tests/e2e/lab-shadow-events.sh`, `tests/e2e/pilot-shadow.sh` (staging, prod-sim) PASS. Phân loại shadow cho policy enforce: đúng từ 14/10 với module có RV-G2-01 (`would_block`, #57); module cũ vẫn đếm finding dưới ngưỡng là shadow |
| A7 | UI tra được Block ID | **Đạt** | API < 1 s (`w09-g2-01.md`); UI chi tiết sự kiện (`w10-f-01.md`) |
| A8 | Runbook đã diễn tập | **Đạt** | `tests/e2e/runbook-drill.sh staging`, 13/10 16:18–16:20 UTC: ép shadow 1 s, rollback 40 s, tắt/bật module < 1 s (`w10-n-01.md`) |
| A9 | Gói signature v0 đạt chỉ tiêu Gate A của luồng S | **Đạt chỉ tiêu, chờ 7 ngày** | FP benign 0,60% (< 1%), recall SQLi 76,3% / XSS 75,2% / CMDi 94,2% / LFI 92,7% (≥ 70%), 9.054/9.054 rule có mẫu (`w09-s-01.md`). Mốc 7 ngày trên staging: 13/10 11:18 → **20/10 11:18 UTC**; các lần deploy sau đó không đổi gói và không phải lỗi do gói, nên không tính lại (`w09-s-01.md` §5) |

## 3. Những điều Gate A phải ghi rõ (review bên ngoài, RV-Q-01)

| Mục | Thực tế |
| --- | --- |
| Request không được kiểm | Khi vượt CPU budget, request đi theo fail mode (mặc định: cho qua). Gói đầy đủ: 0,11–0,12% GET nhỏ; **100%** POST 64 KB (bench Linux). Route thí điểm: mặc định budget 2 ms thì 89% JSON và 100% upload không được kiểm; với 20 ms thì JSON đủ, upload còn 68% (`w10-g2-01.md` §4). Request đầu tiên trên worker mới sau reload cũng có thể đi qua (#49). Tỉ lệ theo route trên Tổng quan: RV-N-01 |
| Route thí điểm | **Giả lập**: `pilot-verify`, `pilot-upload` trên staging và prod-sim, lưu lượng sinh tự động. Prod-sim không phải production. Bảng FP (W10-S-01) mới chứng minh công cụ chạy đúng; ngày đầu: 0 nghi FP từ lưu lượng benign trên `pilot-verify` |
| Cô lập lỗi | `catch_unwind` biến panic Rust thành lỗi engine. Nó **không** bắt abort, OOM, stack overflow hay lỗi bộ nhớ trong `unsafe` (`engine/ffi/`) và trong khoảng 2.600 dòng C. Breaker cấp worker: W11-N-01 |
| Connector | Chỉ NGINX OSS 1.30.5 / 1.31.6, x86_64. Gói deb/rpm đã thử trên Ubuntu 24.04, Debian 12, Rocky 9 (`w10-n-01.md`) |
| Fuzz | Như A4; không có fuzz 72 giờ mỗi PR |

## 4. Quyết định cần từ PO

1. **Ngoại lệ hiệu năng cho Gate A**: chấp nhận Gate A ở shadow với A1/A2 chưa đạt (shadow
   không chặn request, nhưng vẫn cộng độ trễ, và một phần request không được kiểm), và
   đưa A1/A2 thành điều kiện trước canary 1% (tuần 11)? Hoặc giữ Gate A mở cho tới khi
   RV-R-01 (PR #54) có số đo trước/sau.
2. **`strata_cpu_budget` cho shadow**: route thí điểm đang dùng 20 ms để có dữ liệu. Giữ
   mức này cho tới khi có RV-R-01, hay quay về 2 ms (chấp nhận phần lớn request không được
   kiểm)?
3. **Route thật và production** (đã hỏi ở `w10-plan.md` §5): cần trước RV-Q-03 và Gate B.
   Shadow trên route thật phải chạy ít nhất 14 ngày trước canary.
4. **Người tiếp tục RV-G2-01 / RV-N-01**: nhánh `rv-g2-01-event-context` (5 commit chưa
   push) của phiên engine đã dừng giữa chừng; #57 (`would_block`) chờ nhánh này.

## 5. Mốc còn chờ

| Mốc | Thời điểm (UTC) | Ai cập nhật |
| --- | --- | --- |
| Verdict soak 24 giờ | 14/10 khoảng 10:35 | phiên review W09 (`w09-q-02.md` §3); báo cáo này cập nhật A3 |
| Bảng FP đủ 2 ngày | sau 15/10 khoảng 21:50 | Claude Code (`w10-s-01.md`) |
| 7 ngày của gói 0.0.1 | 20/10 11:18 | người PO giao đóng W09-S-01 |
| RV-R-01 số đo trước/sau | khi PR #54 xong | phiên engine; A1/A2 cập nhật theo |

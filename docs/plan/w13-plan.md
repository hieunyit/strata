# Kế hoạch chi tiết tuần 13 · Replay và luồng duyệt

Nguồn: `docs/plan/plan.md`, mục "Tuần 13". Lập ngày 15/10/2026, Claude Code (phiên W10).

PO duyệt cách chia ngày 15/10/2026. Tuần 12 đã xong (`docs/reports/w12-early-review.md`,
PR #76). Mỗi nhiệm vụ một nhánh tên theo mã. Build và test trên nhân 6–10. Hạn chế thêm dòng C:
phần C đang ở 2.999 dòng; PO nâng giới hạn từ 3.000 lên 4.000 ngày 15/10, logic mới vẫn ưu tiên đặt trong libstrata.

## 1. Người làm và thứ tự

| Thứ tự | Mã | Người làm | Ghi chú |
| --- | --- | --- | --- |
| 1 | W13-S-01 | Claude Code (phiên W10) | Rule bù khoảng trống (mục 2), phát hành **pack v0.2** |
| 2 | RV-S-02 | Claude Code (phiên W10) | Quy trình nuôi rule, báo cáo hằng tuần tự sinh (mục 3) |
| 3 | W13-G1-01 | Claude Code (phiên W10) | Nâng cấp agent không mất sự kiện (mục 4) |
| 4 | W13-G2-01 | Claude Code (strata-59) | Replay service: `:replay` dạng long-running operation, kết quả theo bản nháp. Cần trước W12-R-01 (đã xong) |
| 5 | W13-G2-02 | Claude Code (strata-59) | Duyệt 4 mắt: `:submit`, `:approve`; người tạo không tự duyệt; chưa duyệt thì không deploy |
| 6 | W13-F-01 | Claude Code (strata-59) | Hàng chờ duyệt kèm kết quả replay và diff |
| 7 | W13-R-02 | Phiên engine (strata-22) | Chi phí từng rule: lấy mẫu 1%, đưa vào metrics và sự kiện; chi phí đo dưới 2% thời gian engine |

## 2. W13-S-01 · Rule bù khoảng trống

**Xong khi** (plan): có rule riêng cho phần CRS và nguồn nhập chưa phủ, và cho các ca lách tìm
ra từ fuzz; phát hành pack v0.2.

Đầu vào:
- #34, từ `strata-mutate` hằng đêm:
  - URL encode hai lần: lách 86% payload command injection;
  - NBSP thay khoảng trắng: lách 15% payload SQLi;
  - HPP (tách tham số): lách 10–31%;
  - comment SQL thay khoảng trắng.
- GoTestWAF (`docs/decisions/base64-args.md` §6), các nhóm còn lọt:
  - LDAP injection, mail/SMTP injection, XML/XXE;
  - header tùy biến;
  - base64 trong path.

Làm:
- Rule riêng của tổ chức trong `rules/` (IR như các rule hiện có), `action_mode: score` trừ khi
  có lý do chặn một mình. Mỗi rule có mẫu test chặn và mẫu không chặn.
- Ưu tiên thứ tự sau:
  1. Encode hai lần trong ARGS: mở rộng 100010.
  2. LDAP, mail, XXE.
  3. Header tùy biến (biến `request_headers` có loại trừ header chuẩn).
  4. NBSP: một transform mới **đổi định dạng rule**. Dòng "Làm" không ghi điều này, nên đề
     xuất cho PO trước khi làm, hoặc viết rule bằng regex có `\xa0` nếu không cần transform.
  5. HPP: chỉ báo (score) khi tham số trùng tên mang ký tự đặc biệt; ghép giá trị theo profile
     backend để sau.
- Gate trước khi phát hành:
  - FP benign 0/3.000 (corpus benign và corpus dạng route thí điểm);
  - recall không giảm;
  - go-ftw ≥ 95%;
  - `make mutate`: tỉ lệ lách của các phép biến đổi trên phải giảm (số trước và sau);
  - GoTestWAF trên CPU riêng (nhờ phiên engine, như §6 của `base64-args.md`).
- Pack v0.2 (gói core có rule mới; gói signature không đổi), biên bản duyệt hai lượt
  (`rules/reviews/`). Staging: không đổi gói trong mốc 7 ngày đang chạy; v0.2 lên prod-sim trước.

## 3. RV-S-02 · Quy trình nuôi rule

**Xong khi** (plan): báo cáo hằng tuần tự sinh, gồm rule cần xem, rule già và thay đổi upstream.

Làm:
- `strata-rules lifecycle` (tên dự kiến) đọc ba nguồn:
  - bảng FP theo Rule ID (W10-S-01, ClickHouse);
  - số lần khớp theo Rule ID trong 90 ngày;
  - metadata của rule.
- Rule **cần xem**: FP trong shadow vượt ngưỡng của RV-S-01 (0,05% request của route), kèm đề
  xuất exception có hạn.
- Rule **già**: không khớp lần nào trong 90 ngày.
- Metadata `owner` và `review_by` cho mỗi rule. Dòng "Làm" của nhiệm vụ cho phép thêm vào định
  dạng rule; thêm theo kiểu chỉ thêm, có trong JSON Schema IR, tương thích ngược, mặc định theo
  nguồn.
- Nhập lại upstream theo lịch (CRS, Sigma, ET Open, danh sách bot):
  - chạy importer, `make test-crs-ftw` và corpus benign;
  - báo cáo phần upstream thay đổi;
  - không tự phát hành.
- Chạy hằng tuần bằng cron như `strata-mutate` hằng đêm. Báo cáo ghi vào `build/` và gửi
  bản tóm tắt.

## 4. W13-G1-01 · Nâng cấp agent không gián đoạn

**Xong khi** (plan): nâng cấp gói agent trên node đang có tải không làm mất sự kiện và không đổi
bundle ngoài ý muốn.

Vấn đề: event socket là Unix datagram. Trong lúc agent khởi động lại (systemd stop/start khi
nâng gói), socket không có ai đọc, nên module gửi lỗi và sự kiện bị đếm là drop.

Làm:
- `strata-agent.socket` (systemd socket activation): systemd giữ socket, nên trong lúc agent
  khởi động lại, kernel giữ datagram trong hàng đợi (tối đa `net.unix.max_dgram_qlen`, gói đã
  đặt 8192).
- Agent nhận fd qua `LISTEN_FDS`. Chạy tay thì vẫn tự bind như cũ.
- Gói deb/rpm:
  - postinst nâng cấp bằng `try-restart` của service;
  - socket unit không bị stop khi nâng cấp.
- Bundle: agent mới đọc trạng thái đã cài (control file, bundle hiện tại) và không cài lại hay
  đổi version khi control plane không đổi.
- Test: `tests/e2e/agent-upgrade.sh` trên image cài gói (như `test-install.sh`):
  1. tải liên tục có sự kiện;
  2. nâng từ gói N lên N+1;
  3. so số sự kiện gửi (bộ đếm của module) với số sự kiện nhận (agent và ClickHouse);
  4. kiểm bundle version trước và sau.

## 5. Không làm trong tuần này

- **Canary 5% và 25%** (vận hành): Gate A chưa đạt, chưa bật 1%.
- **W13-N-01** (sửa lỗi từ canary): chưa có canary.
- **RV-Q-03** (shadow trên traffic thật): chờ PO chỉ định route thật.

## 6. Mốc khác trong tuần

- Soak 24 giờ có bản sửa bộ nhớ: khoảng 15/10 23:45 UTC, rồi cập nhật A3 của Gate A.
- Bảng FP ngày thứ 2: sau 15/10 21:50 UTC.
- Staging: sau 20/10 11:18 UTC, deploy tag mới (có #85, #87) với pack v0.1.1.

# Review tuần 10 (W10)

Nhánh: `w10-review`
Công cụ: Claude Code
Phạm vi: các nhiệm vụ tuần 10: Q-01, N-01, G1-01, G2-01, S-01, F-01, và RV-Q-01 (bổ sung
14/10). Chạy lại mọi dòng "Xong khi" của `docs/plan/plan.md` trên `main` d2d6548 và
91da0d7, đọc code và báo cáo từng nhiệm vụ, rồi sửa những chỗ chưa đạt hoặc chỉ đạt về
hình thức. Gate A: `docs/reports/gate-a.md`.

## 1. Kết luận

- **Đạt "Xong khi"**: Q-01, N-01, G1-01, G2-01, RV-Q-01, và **F-01**. F-01 vốn còn thiếu ảnh
  trên dữ liệu thật; review đã chụp trên staging (mục 3).
- **Còn chờ thời gian**: S-01 (bảng FP cần đủ 2 ngày số liệu, sau 15/10 khoảng 21:50 UTC).
- **RV-R-01, RV-N-01** chưa xong, đều thuộc phiên engine: PR #54 đang mở; nhánh
  `rv-g2-01-event-context` chưa push.
- Review sửa thêm 2 lỗi vận hành trong công cụ route thí điểm (mục 2, dòng 1–2). Còn một
  test C chập chờn khi máy tải cao (dòng 4).

Những lỗi lớn của tuần đã được tìm và sửa ngay trong nhiệm vụ (mục 2b). Đáng kể nhất:
trước 13/10, **không có sự kiện shadow nào tới ClickHouse** (#47).

## 2. Phát hiện của review và cách sửa

| # | Nhiệm vụ | Phát hiện | Sửa |
| --- | --- | --- | --- |
| 1 | G2-01, S-01 | `pilot-traffic.sh` chỉ ghi IP của container tấn công lúc `up`. Docker có thể cấp IP khác khi container được tạo lại (khởi động lại máy, `--restart`); danh sách loại trừ khi đó sai, và tấn công giả lập bị tính thành nghi FP | Lệnh `pilot-traffic.sh sources` ghi lại IP hiện tại; `up` và `status` cũng gọi nó. Lệnh `fp-report` trong `w10-s-01.md` chạy `sources` trước. README staging ghi rõ |
| 2 | G1-01, G2-01 | README hướng dẫn chạy `pilot.sh up` sau mỗi lần deploy; lệnh đó **âm thầm tắt** kiểm tra trên route thí điểm (`--inspect` không được nhớ) | `--inspect` / `--no-inspect` được ghi vào `.state/pilot/inspect`; `up` không cờ thì giữ trạng thái. Đã ghi trạng thái hiện tại cho staging và prod-sim (cả hai đang kiểm) |
| 3 | F-01 | "Từ dữ liệu thật" chưa có bằng chứng (ảnh chụp trên dữ liệu giả lập của Playwright) | Chụp trang Tổng quan trên staging, đăng nhập bằng tài khoản cục bộ: mục 3 |
| 4 | N-01 / chung | `t/022-body-hardening.t` TEST 6 chập chờn khi máy tải cao (load 9–12): body sạch nhận `X-Action: error` vì request đầu trên worker nguội vượt budget 2 ms. Chạy riêng 4 lần: 3 PASS / 1 FAIL trên cả 1.30.5 và 1.31.6. Phiên engine cũng đã thấy (khoảng 1/6 lần trên 1.31.6) | **Không sửa test**: test kiểm redirect, không kiểm budget, và gốc lỗi (#49) đang được sửa trong PR #54. Ghi lại để không ai nhầm với lỗi mới |

### 2b. Phát hiện trong tuần (đã sửa trong nhiệm vụ)

| Nhiệm vụ | Phát hiện | Ở đâu |
| --- | --- | --- |
| G2-01 | Ingest từ chối mọi sự kiện shadow (`EVT-`, action `log`), nên ClickHouse không có sự kiện shadow nào, kể cả staging từ W09 | #47, PR #55 |
| N-01 | Node enroll sau một lần deploy không có bundle cho tới lần deploy sau (lab che lỗi này vì đặt sẵn bundle đầu) | PR #48 |
| N-01, G1-01 | Module build trên Ubuntu 24.04 cần glibc 2.39 (Debian 12 từ chối); module phải link đúng bản build Hyperscan của compiler (`5.4.2 2024-04-19`); rpm của nginx.org dùng epoch 2 và `/usr/lib64` | PR #48, #52 |
| G2-01 | Image node chạy 16 worker trên 2 nhân (`auto` thấy CPU của host) | PR #56 |
| G2-01 | Gói đầy đủ vượt budget 2 ms trên JSON nhỏ; upload vài chục KB khoảng 20 ms | #28, `w10-g2-01.md` §4 |
| N-01 | Request đầu tiên trên worker mới sau reload đi fail-open với gói đầy đủ | #49 |
| N-01 | `strata off;` ở khối `http` không tắt được location có `strata on;` (runbook sai) | PR #48 |
| F-01 | Giới hạn đăng nhập theo IP dùng chung cho mọi người sau proxy của UI; đăng nhập và đăng xuất không có audit | Review PR #50 |

## 3. Chạy lại "Xong khi"

| Nhiệm vụ | Điều kiện | Kết quả |
| --- | --- | --- |
| Q-01 | Dashboard và cảnh báo cho module, agent, control plane | `make test-alerts`: 18 cảnh báo, unittest SUCCESS; 4 dashboard OK. Lab: `lab-alerts.sh` PASS (dừng agent → `StrataAgentDown` firing → bật lại → hết). Staging đang có `StrataFailModeHigh` và `StrataBudgetExceeded` cho `pilot-upload`, đúng với #28 |
| N-01 | Gói cài 1 lệnh trên máy sạch, image, runbook diễn tập trên staging | Gói build sạch (sau PR #52): `test-install.sh` PASS trên Ubuntu 24.04, Debian 12, Rocky 9; `test-image.sh` PASS. Runbook: staging 13/10 PASS; lab (review) `runbook-drill.sh lab` PASS |
| G1-01 | Control plane trên staging và production, node của 2 route thí điểm enroll | Staging và prod-sim chạy `v0.10.0-rc.3`; 2 node thí điểm online ở mỗi môi trường. Production là **giả lập** (prod-sim), chờ PO |
| G2-01 | Policy shadow, sự kiện có Event ID về ClickHouse | `pilot-shadow.sh` PASS trên staging và prod-sim; lab `lab-shadow-events.sh` PASS |
| S-01 | Bảng FP theo Rule ID cập nhật hằng ngày | `fp-report` (PR #45) + dashboard "Strata shadow FP" (PR #58); ngày đầu có số liệu. **Chưa đủ 2 ngày** |
| F-01 | Bị chặn theo giờ, top rule, top route từ dữ liệu thật | **Đạt**: staging 14/10 01:54 UTC, 24 giờ: 6.036 sự kiện, 69 bị chặn, 119 shadow; top rule (942100, 700001, 944150…), top route (`/v1/upload`, `/v1/verify`, `/`), top IP, 4/4 node online. Ảnh `docs/reports/w10/w10-review-overview-staging.png` |
| RV-Q-01 | Mọi dòng "Có" trỏ tới test hoặc báo cáo | Script kiểm mọi đường dẫn trích trong `docs/status.md`: 0 thiếu. Đọc lại từng dòng "Có": phù hợp với bằng chứng |

## 4. Bộ kiểm tra đầy đủ (nhân 6–10, `main` 91da0d7, 14/10)

| Kiểm | Kết quả |
| --- | --- |
| `make test` NGINX 1.30.5 / 1.31.6 | 15/16 file PASS; `t/022` TEST 6 chập chờn (mục 2, dòng 4) |
| `make clang-tidy`, `make check-c-lines` | sạch; 2.561 / 3.000 dòng thực |
| ASan cả hai bản | Không chạy lại: C không đổi kể từ lần PASS của N-01 (`w10-n-01.md` §3) |
| `make test-go` | mọi package ok, golangci-lint 0 issues |
| `make test-alerts` | SUCCESS, 4 dashboard OK |
| `build/ui.sh` | tsc sạch, vitest, build, Playwright: PASS |
| Lab dựng lại từ `main` | smoke all checks passed; `lab-chain.sh`, `lab-alerts.sh`, `lab-shadow-events.sh`, `runbook-drill.sh lab`: PASS |

## 5. Còn mở

- **Gate A** chưa đạt trọn (`gate-a.md`): A1, A2 (#27, #28, PR #54); soak đến 14/10 khoảng
  10:35 UTC; gói 0.0.1 đến 20/10 11:18 UTC. Cần PO quyết các mục ở `gate-a.md` §4.
- **S-01**: điền số liệu ngày thứ 2 sau 15/10 khoảng 21:50 UTC, rồi đổi dòng trong AGENTS.
- **RV-G2-01 / RV-N-01**: nhánh `rv-g2-01-event-context` (5 commit, chưa push) không có phiên
  nào làm tiếp; #57 (`would_block`) chờ nhánh này (PO 14/10).
- **PR #54** (RV-R-01, engine) mở, chưa review. Cần review trước khi merge vì nó đổi định
  dạng bundle (section kind 8); bản sửa #49 nằm trong đó.
- #44 (test Rust chập chờn), #34 (biến thể lách được), #36 (cost unit), #29 (số đo
  trước/sau cho socket đã `connect()`).
- Staging chưa có dashboard FP (PR #58) và hai bản sửa của review: tag `v0.10.0-rc.4`.

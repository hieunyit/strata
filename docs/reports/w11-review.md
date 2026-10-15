# Review tuần 11 (W11)

Nhánh: `W11-review`. Công cụ: Claude Code (phiên W10). Ngày 15/10/2026.
Phạm vi: các nhiệm vụ tuần 11 (`docs/plan/w11-plan.md`, bảng tuần 11 trong `AGENTS.md`).
Chạy lại mọi dòng "Xong khi" của `docs/plan/plan.md` trên `main` 3e2cd9e. Commit này đã có
tuần 11 (#66–#73), RV-G2-01 (#68, #70), #65 (#72), PR #54 (RV-R-01), tuần 12 sớm (#76) và
bản sửa soak (#77). Chạy trên nhân 6–10, không chạy benchmark.

## 1. Kết luận

- **Đạt "Xong khi"**: W11-N-01, W11-G1-01, RV-S-01, W11-F-01, RV-G2-01. W11-S-01 đạt một phần
  (mục 2).
- **W11-R-01 trên lab** (PO cho chạy ngày 15/10): replay 1 triệu request trong **213,5 s**
  (4 luồng) và **182,7 s** (5 luồng), dưới mốc 10 phút. Chi tiết ở mục 2.
- **Chờ người**: W11-G2-01 (pháp chế duyệt).
- **Canary**: vẫn không bật, vì Gate A chưa đạt (A1, A2, A3; `gate-a.md`).
- Phát hiện mới: phần C đã dùng **2.999 / 3.000** dòng thực (mục 3, dòng 1).

## 2. Chạy lại "Xong khi"

| Nhiệm vụ | Điều kiện | Kết quả |
| --- | --- | --- |
| W11-R-01 | Cùng client luôn cùng nhóm canary; replay 1 triệu request dưới 10 phút trên lab | Nhóm canary: test Rust PASS (`make test`). Replay trên lab ngày 15/10: `strata-replay gen --count 1000000` (corpus benign và tấn công), rồi `run` với gói đầy đủ 0.0.1 (9.054 rule), nhân 6–10, máy tải khoảng 9: **213,5 s** (4 luồng, 4.683 request/s), **182,7 s** (5 luồng, 5.473 request/s); 2.808 request bị chặn mới, khớp lần đo cloud. **Đạt** |
| W11-N-01 | Panic hàng loạt → breaker mở trong 10 giây, chạy giảm cấp; half-open tự đóng; payload nặng không làm breaker mở | `t/090-breaker.t` PASS trên 1.31.6 (`make test`) và ASan 1.30.5 (14/10, PR #77) |
| W11-G1-01 | Tỉ lệ chặn tăng gấp 3 → shadow trong tối đa 6 giây, không cần control plane | Unit `TestNodeFallsBackWithinSixSeconds` PASS. Lab: `lab-fallback.sh` PASS (sau #72: nền 1% không bắn nhầm; một nguồn gửi dồn không tắt được WAF; 12 nguồn → shadow, node-2 vẫn chặn; `clearForceShadow` gỡ sau 1 giây) |
| W11-G2-01 | Định dạng ẩn danh được pháp chế duyệt; lưu được vào MinIO | Code xong (`w11-report.md`); **chờ pháp chế** |
| RV-S-01 | `strata-rules release` sinh 2 gói; policy chọn gói theo route; policy mặc định không có rule signature ở enforce | `make test-signatures`, `test-rules` PASS. Pack v0.1 phát hành theo 2 gói (W11-S-01). Prod-sim: rule Sigma 400100 trên policy enforce chỉ ghi log (`w11-s-01.md` §3) |
| W11-F-01 | Form và YAML đồng bộ; lưu thành bản nháp | `build/ui.sh`: `policy-editor.spec.ts` PASS (17/17 test Playwright) |
| W11-S-01 | Mọi Rule ID có FP trong shadow đã chỉnh hoặc có exception; corpus từ traffic thật; pack v0.1 | Đạt một phần: FP 0/3.000, pack v0.1 trên prod-sim; **corpus từ traffic thật chưa có** (chưa có route thật), dữ liệu shadow mới khoảng 1 ngày (`w11-s-01.md` §4) |
| RV-G2-01 | Test masking từng loại; tra Block ID trên UI thấy UA, Referer, header đã che; benchmark lại | Test PASS. Lab, request bị chặn có UA chứa số thẻ, Referer có `access_token`, `Authorization`, header có CCCD: operator thấy `card ****************`, `access_token=[MASKED]`, `Authorization: [MASKED]`, `cccd ************`; viewer thấy `[REDACTED]` cho Referer và giá trị header. Ảnh: `docs/reports/w11/w11-review-event-context.png`. Benchmark do phiên engine đo (`rv-g2-01.md` §4) |

## 3. Phát hiện của review

| # | Mức | Phát hiện | Xử lý |
| --- | --- | --- | --- |
| 1 | **Cao** | `make check-c-lines`: **2.999 / 3.000** dòng thực sau tuần 12 sớm (#76). Thay đổi C tiếp theo sẽ đỏ | **PO quyết ngày 15/10: không nâng giới hạn; mọi logic mới đặt trong libstrata.** Đã báo các phiên đang làm |
| 2 | TB | Test Playwright lab "a deploy shows node by node on the Fleet page" hỏng: lab có 30 node bị thu hồi (từ các lần thử gói W10-N-01) đứng đầu bảng Fleet, mà test đọc dòng đầu | Sửa test: chỉ đọc node online. UI xếp node bị thu hồi trước node online; nên đưa node online lên đầu (việc của luồng UI) |
| 3 | **Cao** (Gate A) | Soak 24 giờ FAIL: RSS worker +18 MB mỗi lần nạp gói đầy đủ, do arena glibc theo luồng thread pool | Đã sửa và đo (PR #77); soak 24 giờ mới chạy trên CPU 11–13 tới khoảng 15/10 23:45 UTC |
| 4 | TB | Ba lỗi trong `deploy.sh` / `pilot.sh`: ghi đè `$d`; node thí điểm chạy module cũ chặn rollout; `pilot.sh` thoát im lặng | Đã sửa trong tuần (PR #69, #71) |
| 5 | Thông tin | Test::Nginx 1.30.5 cả bộ vẫn chập chờn khi load 12–15 (`t/001` TEST 5, `t/022` TEST 6, `t/080` TEST 20): request vượt budget rồi fail-open. Chạy riêng thì PASS | Cùng họ #49 và #27; không sửa test |

## 4. Bộ kiểm tra đã chạy (15/10, `main` 3e2cd9e)

| Kiểm | Kết quả |
| --- | --- |
| Lab dựng lại từ `main` | smoke all checks passed; `lab-chain.sh`, `lab-shadow-events.sh`, `lab-fallback.sh`: PASS |
| Playwright trên lab (`playwright.lab.config.ts`) | 4/4 PASS sau bản sửa ở mục 3, dòng 2 |
| `make test-go` | 45 package ok, golangci-lint 0 issues |
| `make test-rules`, `test-signatures`, `test-alerts` | PASS |
| `make clang-tidy` | sạch |
| `make check-c-lines` | 2.999 / 3.000 (mục 3, dòng 1) |
| `build/ui.sh` | lint, vitest, build, Playwright 17/17: PASS |
| `make test` 1.31.6, ASan 1.30.5 | PASS (14/10, nhánh của PR #77, trên `main` 30e976c) |

## 5. Còn mở

- W11-G2-01: pháp chế duyệt.
- W11-S-01: traffic thật; ngày thứ 2 của bảng FP sau 15/10 21:50 UTC; v0.1 lên staging sau
  20/10 11:18 UTC.
- Gate A: A1/A2 (#27, #28), A3 (soak 24 giờ mới).
- Phần C ở 2.999 / 3.000 dòng: logic mới vào libstrata (PO 15/10).

# Review tuần 11 mở sớm (PR #61) trên server lab

Nhánh tích hợp: `w11-integrate` = PR #61 (`claude/peaceful-pasteur-efxre2`, 77a1c20) + `main`
1105235. Công cụ: Claude Code (phiên W10). PO giao ngày 14/10: kiểm tra và quyết định tuần 11.

PR #61 do một phiên cloud làm, không có lab, Docker hay staging. Review này chạy lại toàn
bộ trên server (nhân 6–10), cộng thêm những gì phiên đó không chạy được: ASan, conformance,
`prefilter_differential`, lab end to end, fallback với agent thật.

## 1. Kết luận

**APPROVE, merge sau 2 bản sửa nhỏ** (đã làm trong nhánh tích hợp). 6 nhiệm vụ W11-R-01,
N-01, G1-01, G2-01 (code), RV-S-01, F-01 đạt "Xong khi". Cụ thể W11-G2-01 còn chờ pháp chế
duyệt, việc đó là của người.

Không chặn merge, nhưng **phải xử lý trước khi bật canary**: fallback tại node có thể bị kẻ
tấn công kích hoạt, và bắn nhầm ở lưu lượng thấp (#65).

## 2. Phát hiện

| # | Mức | Phát hiện | Xử lý |
| --- | --- | --- | --- |
| 1 | TB | `make clang-tidy` đỏ: `ngx_http_strata_breaker.c` dòng 58 và 264, `NGX_HTTP_STRATA_BREAKER_OPEN_MAX (5 * 60 * 1000)` nhân trong kiểu `int` rồi mới nới thành `ngx_msec_t` (`bugprone-implicit-widening-of-multiplication-result`) | `((ngx_msec_t) 5 * 60 * 1000)`; clang-tidy sạch |
| 2 | Cao (trước canary) | Fallback tại node (W11-G1-01) ép **mọi** policy của node về shadow 1 giờ khi tỉ lệ chặn, hoặc tỉ lệ vượt budget, tăng 3 lần. Kẻ tấn công gửi dồn payload để tắt chặn. Đúng thiết kế và quyết định PO (đã ghi là rủi ro), nhưng chưa có giảm thiểu | #65, kèm đề xuất. Hiện mọi route đều shadow nên chưa có tác động |
| 3 | Cao (trước canary) | Trên lab, khoảng 60 req/s với khoảng 1% tấn công: fallback **bắn nhầm 2/2 lần** do dao động Poisson (kỳ vọng 1,5–3 lần chặn mỗi khoảng 5 giây, ngưỡng khoảng 5–8). `MinRequests = 100` quá thấp | #65 (comment kèm log) |
| 4 | Thông tin | Trùng byte trong bảng policy của bundle: nhánh RV-G2-01 (chưa mở PR) dùng offset 59–60, mà PR #61 dùng 59–61 | Đã thống nhất với phiên engine: RV-G2-01 dời sang byte 62 khi rebase lên main có #61 |
| 5 | Thông tin | Hành vi đổi: policy không ghi `signatures` thì rule gói signature (ET Open, Sigma, bot) chỉ ghi log, không chặn, kể cả ở enforce. Probe Log4Shell (700001, gói core) của staging vẫn đúng | Ghi trong `docs/status.md`; staging deploy tag tiếp theo sẽ có thay đổi này |
| 6 | Thông tin | `t/080-conformance.t` hỏng 1 ca SQLi trong body ở 1/3 lượt chạy bộ đầy đủ khi máy tải cao (load khoảng 12); chạy riêng 6/6 PASS. Cùng họ với #49 (request đầu vượt budget) | Không sửa test; #49 nằm ở PR #54 |

## 3. Đã chạy (14/10, nhân 6–10)

| Kiểm | Kết quả |
| --- | --- |
| `make rust-check` (fmt, clippy, cargo test) | PASS |
| `make test` 1.30.5 | PASS (cả lần chạy lại sau bản sửa 1) |
| `make test` 1.31.6 | 1 ca chập chờn ở `t/080` (mục 2, dòng 6); `t/090-breaker.t` PASS |
| `make nginx-asan` + `test-nginx-asan` 1.30.5 / 1.31.6 | PASS / PASS, không có báo cáo sanitizer |
| `make clang-tidy`, `check-c-lines` | sạch sau bản sửa 1; 2.832 / 3.000 dòng thực |
| `make test-conformance` | 1 lượt hỏng (dòng 6); `t/080` chạy riêng 6/6 PASS |
| `prefilter_differential` (`--ignored`, release) | PASS |
| `make test-go`, `test-rules`, `test-signatures`, `test-alerts`, `build/ui.sh` | PASS |
| Lab dựng từ nhánh tích hợp | smoke all checks passed; `lab-chain.sh`, `lab-shadow-events.sh`, `runbook-drill.sh lab`, `lab-alerts.sh`: PASS |
| **Mới**: `tests/e2e/lab-fallback.sh` (agent và NGINX thật) | PASS với nền sạch: đột biến 50% tấn công → node-1 về shadow sau **5 s** (≤ 6 s), node-2 vẫn chặn, `strata_agent_fallback_triggers_total{reason="block_rate"}` 0 → 1, `clearForceShadow` gỡ sau 1 s. Với nền 1% tấn công: bắn nhầm (dòng 3) |

## 4. Quyết định cho phần còn lại của tuần 11

| Việc | Quyết định |
| --- | --- |
| W11-S-01 | Làm ngay sau khi merge: xử lý FP từ shadow (route thí điểm, corpus benign v0), corpus benign từ lưu lượng thí điểm (giả lập, ghi rõ), phát hành pack **v0.1** theo 2 gói core/signature của RV-S-01, đưa lên staging (mốc 7 ngày mới cho v0.1) |
| RV-G2-01 | Phiên engine làm tiếp (`rv-g2-01-event-context`, có thêm `would_block` #57); tôi làm phần control plane sau khi merge |
| #65 (fallback) | Đã sửa ngày 14/10 (nhánh `W11-G1-01-fallback-65`, `nginx-module.md` › "Sửa #65"); `lab-fallback.sh` kiểm cả trường hợp một nguồn gửi dồn |
| Bật canary 1% | **Không bật**: Gate A chưa đạt (`gate-a.md`) |

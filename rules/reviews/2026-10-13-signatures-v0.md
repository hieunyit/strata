# Review gói signature v0 (0.0.1), ngày 13/10/2026

Nhiệm vụ: W09-S-01.

Người duyệt: Claude Code, **cả hai lượt duyệt**. Ngày 13/10/2026 PO đã chốt: "bạn là
người duyệt luôn". Hai lượt được ghi tách riêng dưới đây (lượt 1: nội dung và chất
lượng; lượt 2: phát hành và vận hành). Tiền lệ: `2026-10-11-protocol-and-crs.md`,
`2026-10-12-sigma-et-bots.md`, `2026-10-12-action-mode.md`.

## Gói

`strata-rules release --version 0.0.1 --bundle-version 1`, ký bằng khóa release
(`rules/release/signatures.pub`, seed nằm ngoài repo). `strata-rules verify` cho kết
quả OK. Bundle có sha256 `afb8972a…41a75b7`.

| Nguồn | Rule | Giấy phép | Đã duyệt ở |
| --- | ---: | --- | --- |
| OWASP CRS 4.25.2 PL1 | 148 | Apache-2.0 | `2026-10-11-protocol-and-crs.md`; W08 review (+12 rule); tinh chỉnh ở dưới |
| Strata: protocol, virtual patch | 52 | Apache-2.0 | `2026-10-11-…`, `2026-10-12-action-mode.md` |
| Rule riêng (samples) | 2 | Apache-2.0 | rule mẫu của tổ chức |
| ET Open (SID 2000000–2099999) | 7.377 | BSD-3-Clause | `2026-10-12-sigma-et-bots.md` |
| Sigma (web) | 21 | DRL-1.1 | `2026-10-12-sigma-et-bots.md` |
| crawler-user-agents | 1.454 | MIT | `2026-10-12-sigma-et-bots.md` |
| **Tổng** | **9.054** | | `block_alone` 14, `score` 9.040 |

## Lượt 1 · Nội dung và chất lượng (chỉ tiêu Gate A)

Đo bằng `strata-rules report`: toàn bộ gói, engine thật, corpus v0.

| Chỉ tiêu Gate A | Kết quả | Đạt |
| --- | --- | --- |
| FP trên corpus benign ở ngưỡng chặn < 1% | 12 / 2.000 = **0,60%** (942100) | đạt |
| Recall (bị chặn) SQLi ≥ 70% | 76,3% | đạt |
| Recall (bị chặn) XSS ≥ 70% | 75,2% | đạt |
| Recall (bị chặn) CMDi ≥ 70% | 94,2% | đạt |
| Recall (bị chặn) LFI ≥ 70% | 92,7% | đạt |
| Rule có mẫu test 100% | **9.054 / 9.054** | đạt |

Các thay đổi trong lượt này. Mỗi thay đổi đều kèm số đo trước và sau.

1. **Corpus attack**: chỉ giữ những dòng thật sự là payload.
   - Đã bỏ: comment, dòng mô tả của danh sách RSnake, văn bản thuần như từ khóa SQL
     đứng một mình ("delete", "having").
   - Payload đã encode sẵn (commix `%3B%20…`) được gửi nguyên văn, đúng như danh sách
     gốc dự định. Trước đây chúng bị encode thêm lần nữa.
   - Corpus giảm từ 2.559 xuống 2.281 payload. Recall bị chặn trước và sau:

     | Loại | Trước | Sau |
     | --- | ---: | ---: |
     | XSS | 52,5% | 75,2% |
     | CMDi | 52,0% | 94,2% |
     | SQLi | 69,7% | 76,3% |

2. **930120 (truy cập file hệ điều hành)**: mục `program files` thay bằng `program files/`.
   - CRS khớp với câu văn như "C:/Program Files is slow" (96 request benign, 4,8%).
   - Truy cập file thật vẫn bị bắt, vì sau `normalize_path_win` thì "C:\Program Files\x"
     thành "c:/program files/x".
3. **942100 (libinjection)**: thêm điều kiện trên giá trị libinjection đã đánh dấu. Giá trị
   đó phải có thêm dấu nháy, ngoặc, `=`, `;`, `#` hoặc một từ khóa SQL.
   - libinjection gốc (C, bản 3.10.0) cũng đánh dấu "50% off -- today only" (fingerprint
     `1c`), nên đây là hành vi của CRS chứ không phải lỗi bản port. Trước đó có 71
     request benign bị chặn.
   - Recall SQLi không đổi (76,3%). go-ftw của CRS không đổi (95,9%, không test nào của
     942100 hoặc 930120 trượt).
   - Phương án đã loại: hạ điểm 942100 xuống 50 kéo SQLi còn 56,4%; hạ điểm 930120 kéo
     LFI còn 64,8%.
4. **3 rule CRS không có test go-ftw upstream** (920171, 920181, 920620): có test Strata
   trong `rules/crs/tests/strata.jsonl` (mỗi rule một ca khớp và một ca không khớp). Test
   chạy trong `make test-crs-ftw`.

Phát hiện từ bộ sinh biến thể (W09-S-02, [#34](https://github.com/hieunyit/strata/issues/34)):

- encode URL hai lần lách 86% CMDi;
- NBSP lách 15% SQLi;
- tách tham số lách 10–31%.

Đây là các trường hợp chỉ thành bypass thật khi backend cư xử đặc biệt (giải mã hai
lần, ghép tham số). **Không chặn v0**: ghi nhận làm việc của W10–W14, kèm đề xuất rule
trong #34.

## Lượt 2 · Phát hành và vận hành

| Kiểm | Kết quả |
| --- | --- |
| Gói có version, chữ ký, changelog, NOTICE | `manifest.json` (sha256 của mọi file) + `manifest.json.sig`. Sửa bất kỳ file nào thì verify báo lỗi (`release_test.go`) |
| Giấy phép | Apache-2.0, BSD-3-Clause, DRL-1.1, MIT, đều ghi trong NOTICE. Corpus attack (MIT) không nằm trong bundle |
| `block_alone` | 14 rule, đã duyệt từng rule ở `2026-10-12-action-mode.md`. Không có rule nào mới trong v0 |
| Hiệu năng (W09-R-01) | GET nhỏ: engine p50 0,47 ms. Body 64 KB / 1 MB vượt CPU budget và đi fail-open ([#28](https://github.com/hieunyit/strata/issues/28)). Chấp nhận được cho shadow, cần sửa trước enforce |
| Cost unit | 1.796.065 unit, gấp khoảng 36 lần mặc định 50.000. Staging chạy với `-cost-budget=2000000`; hiệu chỉnh mô hình ở [#36](https://github.com/hieunyit/strata/issues/36) |
| Staging | Lên staging (`v0.9.0-rc.1`) qua `deploy/staging/deploy.sh --signatures`. Mốc 7 ngày tính từ lúc deploy, ngày cụ thể ghi trong `docs/reports/w09-s-01.md` |

## Kết luận

Gói **0.0.1 được duyệt** để chạy staging 7 ngày rồi chạy shadow (W10). Điều kiện trước
khi enforce: [#28](https://github.com/hieunyit/strata/issues/28) và
[#34](https://github.com/hieunyit/strata/issues/34) đã được xử lý hoặc đã chấp nhận rủi
ro bằng văn bản.

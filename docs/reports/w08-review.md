# Review tuần 8 (W08)

Nhánh: `w08-review`
Công cụ: Claude Code
Phạm vi: chín nhiệm vụ W08 (PR #16–#24). Chạy lại mọi dòng "Xong khi" của
`docs/plan/plan.md` trên `main` 86dcb6e, đọc code và báo cáo từng nhiệm vụ, rồi sửa
những chỗ chưa đạt hoặc chỉ đạt về hình thức.

## 1. Kết luận

Tám nhiệm vụ đạt "Xong khi". Ba nhiệm vụ chỉ đạt về hình thức, đã sửa trong nhánh này:

- **W08-S-01**: go-ftw chỉ gác 7 nhóm injection. Plan yêu cầu **toàn bộ** test CRS đạt
  ≥95%, nhưng lúc review toàn bộ mới đạt 91,8%.
- **W08-Q-01**: corpus conformance chạy trên rule đồ chơi, chỉ kiểm `action`, và không
  qua NGINX.
- **W08-F-01**: vai trò `viewer` không xuất được CSV, trong khi plan ghi "mọi bảng xuất
  được CSV". File CSV còn bị CSV injection, và trang Sự kiện không che IP khi xuất.

Ngoài ra có một lỗi CI (fmt), một lỗi cấp Rule ID không ổn định trong importer bot, hai test chập chờn dưới ASan và một số chỗ còn thiếu
test. Tất cả đã sửa.

## 2. Phát hiện và cách sửa

| # | Nhiệm vụ | Phát hiện | Sửa |
| --- | --- | --- | --- |
| 1 | S-02 | Các importer Sigma, ET Open và bot không ghi `action_mode`. Pack sinh lại không nói rõ mức tin cậy, nên lệnh `release` đếm theo mặc định ngầm | `irout.Marshal` ghi `action_mode`, mặc định `score` cho mọi rule nhập. Sinh lại pack: sigma 20, et-open 7377, bots 1453 |
| 2 | N-01 | HTTP/3 chỉ được test bằng GET; đường đọc body qua DATA frame chưa có test | `t/070-http3.t` thêm POST body sạch (4 KB, 3 frame) → 200 `allow`. Thêm POST có chuỗi test bị tách qua 2 frame → 403 kèm Block ID. 12/12 test pass trên 1.30.5 và 1.31.6 |
| 3 | S-01 | `make test-crs-ftw` chỉ chạy 7 nhóm; toàn bộ CRS đạt 91,8% (<95%) | Importer CRS: nạp mặc định của REQUEST-901 (danh sách trong `crs-setup`), dịch `@within`, chain capture→TX→`@within` (content type, charset, extension, header bị cấm), thêm target engine `multipart_part_headers` (922100/110/120/130). Kết quả: 148 rule (+12), **95,9% (2.675/2.790)**. Gate mới `--min-total 95` trên mọi nhóm, giữ ≥95% riêng cho từng nhóm injection. FP benign không đổi |
| 3b | S-01 | Nhập thêm 920180/911100 làm FP benign tăng lên 1.050/2.000 | Runner `strata-rules` gửi `Content-Length` như client thật (`runner.Framed`). Danh sách method của Strata thêm PUT/PATCH/DELETE (API REST). FP về lại mức cũ |
| 4 | S-01 | Gói release chỉ có bundle được ký; `manifest.json`, `NOTICE`, `CHANGELOG.md` và `.pub` có thể bị sửa mà không ai phát hiện | `manifest.json` ghi sha256 của mọi file, kèm `manifest.json.sig` (Ed25519, cùng khóa ký bundle). Lệnh mới `strata-rules verify --pub KEY DIR` kiểm với khóa tin cậy từ ngoài gói. Test: sửa bất kỳ file nào → verify lỗi |
| 5 | N-01 / chung | `t/021` TEST 2 và `t/040` TEST 6 chập chờn dưới ASan khi máy bận (fuzz 72 giờ đang chạy): request sát ngân sách CPU 2 ms rơi vào fail mode | `Test::Strata` nâng ngân sách mặc định lên 1s khi chạy ASan, trừ block tự đặt `strata_cpu_budget` (t/060 vẫn test ngân sách thật) |
| 6 | F-01 | `viewer` không thấy nút xuất CSV ở Fleet, Policies và Sự kiện | Nút xuất hiện với mọi vai trò. Dữ liệu viewer nhận đã được API che sẵn, và UI che IP thêm một lớp nữa. Các nút tác vụ khác vẫn ẩn theo vai trò |
| 7 | Q-01 | Corpus v1 chỉ có 10 ca, chạy trên rule đồ chơi, chỉ so `action`, không qua NGINX | Corpus viết lại thành 32 ca: sạch, SQLi/XSS ở query/form/JSON/cookie, web shell, scanner, IP rule, too-many-args, lớp protocol, cộng điểm, smuggling, chunked. Hai runner dùng cùng corpus, cùng bundle test và policy `example-api`, so cả tập rule: `engine/compiler/tests/conformance.rs` và `connectors/nginx/t/080-conformance.t` (125 assert). `make test-conformance` chạy cả hai. Đã thử cố tình sai 4 kỳ vọng: cả 4 đều bị bắt |
| 8 | R-02 | `make rust-check` đỏ vì `cargo fmt` (`ir_schema.rs`, `action_mode.rs`) | `cargo fmt --all` |
| 9 | G2-01 | Test lỗi mạng gửi sự kiện song song với lúc cắt mạng, nên không chắc sự kiện nào đi qua lúc mạng lỗi. Test chưa có `reset_peer` và chưa kiểm trùng lặp | Gửi tuần tự từ goroutine chính. Cắt mạng ở sự kiện 20/60, nối lại ở 40/80, `reset_peer` từ 45 đến 55. Sau khi giao, chờ 3s rồi kiểm số sự kiện **đúng bằng** n (không mất, không trùng). `untoxic` dùng chung |
| 10 | R-02 | `control-file.md` chưa ghi bit 1 (`block_alone`) của byte flags RULES, và chưa ghi rằng libstrata cũ từ chối bundle có bit này | Ghi bổ sung; thứ tự nâng cấp là module trước, bundle sau |
| 11 | F-01 | CSV không chặn công thức (`=`, `+`, `-`, `@`, tab, CR); trang Sự kiện xuất IP đầy đủ, không qua `maskIp` | `toCsv` thêm `'` trước các ô nguy hiểm theo khuyến nghị OWASP. Trang Sự kiện dùng `downloadCsv` chung và `maskIp`. Có test |

| 12 | S-02 / CI | Importer bot cấp lại Rule ID cho upstream `" DVbot"` (có dấu cách ở đầu) mỗi lần import, 501653 ↔ 501654: `LoadIDs` cắt khoảng trắng hai đầu dòng, nên đọc lại thành `"DVbot"`. Kiểm "pack đã cập nhật" của CI vì vậy chập chờn, và quy tắc "Rule ID không đổi" bị vi phạm | `LoadIDs` chỉ cắt khoảng trắng cuối dòng. Test `TestIDsKeepLeadingSpace` đỏ trước khi sửa, xanh sau khi sửa. ID giữ 501654 như trên `main` |

Không phải lỗi:

- `abi-test` đỏ một lần, không tái hiện được (6 lần chạy lại đều pass).
- `t/080-conformance.t` đỏ một lần ngay sau khi build lại 1.31.6, không tái hiện được
  (12 lần chạy lại trên hai bản đều pass).
- Cả hai được ghi lại để theo dõi.

## 3. Chạy lại "Xong khi" (sau sửa)

| Nhiệm vụ | Điều kiện | Kết quả |
| --- | --- | --- |
| R-02 | Rule `block_alone` chặn một mình, rule `score` chỉ cộng điểm | `engine/compiler/tests/action_mode.rs` 4/4 |
| S-02 | Mọi rule có `action_mode` | CRS 148 (`score`), sigma/et/bots ghi `score`, virtual patch `block_alone` |
| N-01 | HTTP/3 được kiểm như HTTP/1, HTTP/2 | `make test-nginx-h3` 12/12 trên 1.30.5 và 1.31.6 (GET, POST body, chặn, Block ID) |
| R-01 | Fuzz 72h không crash; differential go-net-http/spring | Container `strata-fuzz-72h` vẫn chạy, `build/fuzz/ffi/artifacts/` rỗng. `conformance/differential` pass |
| S-01 | go-ftw toàn bộ ≥95%; báo cáo FP/recall; release có version, chữ ký, changelog, NOTICE | 95,9% (`docs/crs-ftw-report.md`, có dòng Total); `test-rules` 56/56; release + verify có test |
| G1-01 | 1.000 agent, `BundleAvailable` <10s | Theo báo cáo `w08-g1-01.md` (chậm nhất 373 ms); code không đổi |
| G2-01 | toxiproxy: không mất sự kiện, không bundle hỏng | `TestEventsSurviveNetworkFaults`, `TestBundleRolloutSurvivesNetworkFaults` PASS |
| F-01 | Nút ẩn theo vai trò, viewer không thấy IP đầy đủ, mọi bảng xuất CSV | UI: lint, 22 unit, build, 11 Playwright PASS |
| Q-01 | Corpus v1 chạy mỗi PR của engine/ và connectors/ | `make test-conformance` (engine + NGINX + differential); job CI `conformance` |

Bộ kiểm tra đầy đủ: xem mục 4.

## 4. Bộ kiểm tra đầy đủ

`build/w08-verify.sh`, chạy trong image dev:

| Bước | Kết quả |
| --- | --- |
| `check-c-lines` | 2.516 / 3.000 dòng thực |
| `rust-check`, `clippy -D warnings` | PASS. Lần đầu đỏ vì fmt/clippy ở `conformance.rs` mới; đã sửa rồi chạy lại |
| header, fixtures, `abi-test` | PASS |
| `test-go` | PASS |
| `test-rules` | PASS, 56/56 |
| `test-signatures` | PASS |
| `test-crs-ftw` | PASS, toàn bộ 95,9% và từng nhóm injection ≥95% |
| `test-nginx` 1.30.5 / 1.31.6 | PASS, 16 file, 551 test (trước review: 15 file, 426 test) |
| `test-nginx-asan` 1.30.5 / 1.31.6 | PASS, không có báo cáo sanitizer |
| `clang-tidy` 1.30.5 / 1.31.6 | sạch |
| `test-nginx-h3` 1.30.5 / 1.31.6 | PASS, 12/12 |
| `test-conformance` | PASS: engine, NGINX (125 test) và differential |
| Sinh lại rule (`crs-import`, `signatures-import`, `test-crs-ftw`) | Khớp với file đã commit (kiểm `git diff` như CI); import chạy hai lần liền cho cùng kết quả |
| e2e lỗi mạng (`TestEventsSurviveNetworkFaults`, `TestBundleRolloutSurvivesNetworkFaults`) | PASS |
| UI (lint, unit, build, Playwright) | PASS |

## 5. Còn mở

- **Fuzz 72 giờ** chưa chạy hết. Chạy xong mà có crash thì mở `gh issue`.
- **go-ftw**: còn 115 test chưa pass.
  - 943110: so host trong Referer, không biểu diễn được bằng IR.
  - 901/949: phần ống nước của CRS, không phải rule phát hiện.
  - Một số test 920.
  - Đã ghi trong `docs/crs-ftw-report.md`.
- **Khóa ký gói signature**: hiện dùng file seed. Khi phát hành chính thức (W09-S-01),
  ký bằng Vault Transit như bundle trên lab.

# Hợp nhất nhánh — 18/10/2026

Đã merge [PR #220](https://github.com/hieunyit/strata/pull/220), main `0a5100c96ad2e7d1f00966c63f701f2640b1f099`. Local main đã fast-forward khi checkout sạch. Nhánh tích hợp cũ đã được dọn.

Phạm vi do PO giao: kiểm kê mọi nhánh local/remote, review, sửa, chọn phần đúng, merge main và xóa nhánh đã xử lý. PO cho phép merge và không chờ hosted CI. Không triển khai staging/production, không coi merge là nghiệm thu Gate A/B hay mở tuần mới.

## Điểm khôi phục và kiểm kê

Baseline remote main `e93dc0b4da55ec93ccf3c0a9421cdf8ed0f51719`; local main `355d6d2` cũ hơn. Có 146 local branch, 130 remote branch ref, 151 SHA đầu nhánh phân biệt, 14 đầu nhánh không là tổ tiên của nhau, 101 PR mở trong 204 PR. Đây là số trước khi dọn, không phải số tính năng độc lập.

Trước khi sửa: `git bundle create build/branch-consolidation/refs-before-merge.bundle --all`, rồi `git bundle verify`: complete history, okay. Bundle ở worktree tích hợp, không commit file 33 MB. Manifest SHA/ref và kết quả dọn nằm trong [evidence](evidence/branch-consolidation/). Worktree có thay đổi chưa commit: strata, strata-p01, strata-w21 và checkout nightly; giữ nguyên cả index, working tree và branch của chúng. Bundle chỉ bảo vệ lịch sử đã commit, không nhận là backup nội dung WIP.

Dọn lần đầu: 14 remote và 10 local branch đã nằm hoàn toàn trong remote main, không còn PR mở và không được checkout. Xóa ref local bằng compare-and-swap SHA; xóa remote có `--force-with-lease=refs/heads/<name>:<SHA>` để từ chối nếu nhánh đã đổi. Không force-push main. Nhánh trùng tên local/remote có thể có SHA khác nhau, luôn xét từng ref.

## Chuỗi remediation được tích hợp

Nguồn `a71046e56196ec242c5baa0e71d17303212db00a` (PR #219), bao gồm các base main và chuỗi PR thành phần. Giữ lịch sử merge thay vì squash các lần sửa chồng lên nhau. Nội dung gồm RBAC/privacy, ingest watermark/annotation PostgreSQL, provenance snapshot và approval pin, exception scoped/TTL, M4 opt-in signed log-only và thông báo, UI replay/duyệt, cold-cache preparation, tối ưu JSON lặp, các harness và bằng chứng lab thật. Từng thay đổi và giới hạn: [tracker](remediation-tracker.md).

**Ngoại lệ nội dung**: không đưa `rules/gaps/300011-sqli-custom-headers.yaml`, `300012-xss-custom-headers.yaml`, `300013-json-sqli-custom-headers.yaml` vào cây main trong lượt này. Các rule là candidate chưa có lượt duyệt nội dung bắt buộc của người S; bảo toàn byte-for-byte ở [draft #221](https://github.com/hieunyit/strata/pull/221), nhánh `codex/header-rule-candidates`; hai proposal #133/#136 đã đóng là superseded, không phải được duyệt. Tổ tiên Git được tích hợp không có nghĩa mọi candidate được chấp nhận. Chỉ dọn hai nhánh nguồn sau khi xác minh từng file ở replacement trùng blob gốc và ref replacement đã push. Các benchmark 9.067 rule trong báo cáo cũ có thêm 3 candidate; không dùng chúng để khẳng định pack mặc định 9.064 rule có cùng số đo.

Không đổi budget 10 ms, fail mode, oversize, max_args hoặc hành vi rate-limit khi bảng đầy. Giữ ba quyết định PO: body chỉ đo/tối ưu; rate saturation chỉ đo; tự giảm chặn M4 chỉ opt-in trong policy được replay/duyệt, mặc định tắt và không tự bật enforce lại.

## Review các đầu nhánh còn lại

| SHA nguồn | Nhóm | Kết quả đối chiếu / cách xử lý |
|---|---|---|
| `65d0ce2a7` | W15–W20, GeoIP/map/bot/SA/standalone | Cần sửa. Section GEO=10/BOT=11 trùng EXCEPTIONS=10/STAGING=11; không merge thẳng. `PolicyGeoRestriction::check` chỉ được gọi trong unit test, chưa nối verdict request; parser Geo/Bot dựng lại cấu trúc trên mỗi request. SA dùng MemoryStore, audit error bị bỏ qua, decoder không giới hạn; TTL nhân duration trước khi kiểm tra có overflow. Báo cáo Gate B ghi 14 ngày enforce và FP 0,012% không có bằng chứng xuất đo kèm. SQLi semantic tuning bỏ phát hiện trên `1 && 1=1` và ba biến thể: probe và regression đều xác nhận candidate FAIL / detector giữ lại PASS. Không nhận nhánh blanket-allow &&; bổ sung regression vào detector hiện tại. Hourly views dùng count() trên insert sẽ đếm lại khi replay batch sau CH commit/PG watermark crash; cần kiểm tra và sửa trước nhận tối ưu aggregate. Tách review theo thành phần, không chép trạng thái Gate đã đạt. |
| `b665c5ab3` | RV-R-03/04 rate/challenge | Cần sửa/giữ riêng. Collision/window replacement + atomic riêng lẻ mất đếm; chưa có đường NGINX/shared node bảo vệ thật. Không kích hoạt hoặc thay chính sách bão hòa trái quyết định PO. Measurement hiện có ở remediation. |
| `b1927c27f`, `1b34970a7` | Exception/FP API và UI cũ | RAM state, luồng approve riêng không là artifact runtime; thay bằng durable annotation, policy draft/replay/approval/TTL và UI trong remediation. Không nhập lại API prototype. Đã chọn lại thao tác FP từ UI W14: generated contract → PostgreSQL, lý do/etag/request_id, retry cùng lệnh, viewer/approver chỉ đọc. Không nhận API approve RAM, wildcard field hoặc nút block IP không có workflow. Kiểm chứng browser được bổ sung trước merge. |
| `44575cce9` | Compiler exception cũ | Không nhập mù schema/priority riêng: remediation có signed exact field scope/TTL, mandatory flag, regression và chain thật. Resolver cũ có wildcard policy/field và TTL=0 vô hạn, đồng thời chưa được gọi trên runtime. Giữ codec/runtime scope/TTL nghiêm ngặt của M2; không nhập dead-code resolver này. |
| `3f2e4e7e0` | Health prototype + router fix | Thay bằng API durable PostgreSQL/ClickHouse và worker M4 opt-in; không hồi sinh counter RAM/callback. Đối chiếu unique diff trước dọn. |
| `6d19ae96a` | Queue UI cũ | Thay bằng generated client, explicit version, replay pin atomic và proof duyệt trong remediation. Kiểm tra phần độc lập trước dọn. |
| `eaff8d27f` | Game day cũ | Không đạt: chạy unit test/grep và có thể zero selected tests nhưng in ALL PASSED cho outage/rate isolation. Harness thật H6 trong remediation thay thế. Không coi 5/5 giả này là Gate evidence. |
| `444f51a2a` | Virtual-patch runbook | Bản sửa #131 dùng API/tool thật thay thế. Đối chiếu nội dung độc lập trước dọn. |
| `f4c068481` | Canary 25% docs | Chưa đạt: `canary_percent: 25.0` và `fail_on_findings: "block"` hợp lệ trong Spec/IR (đính chính nhận định interface ban đầu); phải phân biệt với enum JSON của REST/proto. Tuyên bố tự quarantine/hạ canary không đúng opt-in và luồng duyệt hiện tại; metric cũng cần đối chiếu tên thật. Đây là kế hoạch chờ Gate, không phải quan sát 72 giờ đã chạy. |
| `298eee70e` | C4/audit/operations docs | Cần sửa: có directive/config/package giả định; audit suy rộng memory safety và crypto thành loại bỏ hoàn toàn rủi ro. Chọn diagram đúng, sửa guide theo code, không dùng câu kết luận thiếu chứng cứ. |
| `61380252b` | Args-limit / args DB experiment | `git cherry -v main 61380252` xác nhận cả 4 commit đều patch-equivalent, kể cả report prototype; không có thay đổi độc lập cần nhập. Report khuyên không nhận prototype section10. Giữ nhận định experiment, không thêm section xung đột hoặc đổi policy để che budget. |
| `99dc4007f` | Pattern-cost prefilter experiment #113 | Chỉ công cụ đo (không đổi enforcement), báo cáo không có gain. Nhận công cụ đo qua cherry-pick 99dc400: fmt/Clippy PASS, binary chạy thật với hai pattern và tạo DB prefilter. Header cài sẵn xác minh HS_FLAG_PREFILTER=128. Không đổi đường enforcement hay budget; giữ báo cáo cũ kèm ghi rõ đề xuất adaptive-budget chưa được duyệt, không đóng #28. |

## Kiểm chứng tích hợp

Đang chạy lại test/lint local trên cây kết hợp với 3 candidate rule được loại ra. Đã PASS toàn control plane và agent với -race, PostgreSQL cho CP, lint 0 issues; importer Go/race/lint và 5 test fetch integrity PASS. Rust/FFI/compiler 318 test PASS, 3 stress test có sẵn ignored; clippy/fmt PASS. Có thêm regression && PASS bằng Cargo, candidate red/green qua cùng bộ test. Differential pack không có ba candidate: 11.590 requests, 7.997 có rule khớp, 0 khác action/score/tập rule giữa reference/fast/block, PASS 352,72 giây. UI trước thao tác FP: 138 PASS; thêm FP: 144 PASS. Sau sửa key React/focus/lỗi tạo request ID: 14 test FP + exception PASS, lint/build UI PASS. Native được build lại trước mỗi lượt: NGINX 1.30.5: 595 TAP PASS/153 s; NGINX 1.31.6: 595 TAP PASS/154 s; không có ASan/UBSan report. HTTP/3 skip vì chưa cấp binary H3; LSan tắt theo harness, không gọi đây là leak/soak test. Chromium local auth/API/PostgreSQL thật: hai kịch bản PASS (14,5 s trong browser; toàn Go -race 22,888 s). Kiểm scoped exception DRAFT và một phân loại FP/audit, giữ receipt qua reload/đổi ngôn ngữ; viewer/approver gọi thẳng API đều 403. Ảnh mobile và JSON receipt ở evidence. Browser fixture dùng seeded event store, không suy thành nghiệm thu ingress/deploy. Bằng chứng sanitizer/differential tại `a71046e` là kết quả lịch sử có phạm vi SHA/pack, không ghi là vừa chạy trên bản hợp nhất.

## Việc còn lại

Chưa kết luận mọi nhánh đạt chuẩn. Giữ nhánh có phần độc lập chưa review, candidate rule, WIP và checkout khác cho tới khi đối chiếu xong; không dùng xóa nhánh để che phần việc chưa làm. H2/soak/real campaign/ET archive và giới hạn lab trong tracker vẫn mở.

## Tự review phần mới

1. Kiểm chứng: giữ stdout thật và phạm vi source/pack, không đổi test cũ cho xanh. Các test opt-in cần CH/native/browser riêng không tự chạy chỉ vì `go test ./...` PASS; dùng báo cáo tương ứng.
2. Đường lỗi FP UI: phân biệt 400/403/404/409/kết quả chưa biết; giữ nguyên command/request_id khi retry, kiểm receipt đúng event/lý do/etag; không tự rebase sau conflict.
3. Giới hạn: lý do tối đa 500 byte UTF-8, chặn NUL, chỉ một write in-flight; API vẫn kiểm input, quyền và audit transaction.
4. Bảo mật: UI lấy type từ OpenAPI, server giữ quyền events:write; viewer/approver chỉ đọc. Không chép secret hoặc dùng môi trường staging/production.
5. Phạm vi: nhiệm vụ hợp nhất được PO cho phép trên mọi nhánh; không đổi con trỏ tuần, không gán trạng thái Done/Gate của nguồn chưa có bằng chứng.
6. Lint: Go/Clippy/TypeScript đã PASS; browser test chạy với -race, có lint API riêng sau khi chạy. Các whitespace trong raw stdout lịch sử được giữ nguyên, không sửa bằng chứng chỉ để `diff --check` sạch.

## Dọn sau merge #220

Đóng 92 PR xếp chồng là consolidated trong #220; GitHub tự đóng 4 root PR có head được gộp; đóng #133/#136 là superseded bởi draft #221. Sau đó còn #113, #144, #152 và #221 mở. Xóa thêm **107 remote và 103 local branch** đã có nội dung trong main/replacement được chỉ rõ; remote push theo batch atomic với lease SHA từng ref, local delete CAS. Tổng hai lượt: **121 remote, 113 local branch**. Không xóa local branch được checkout, nhánh WIP, hoặc head độc lập chưa giải quyết. Không xóa worktree hay stash. Các source W15–W20 vẫn được giữ cho tới khi sửa và kiểm chứng xong.

Phát hiện khi tích hợp W20: cả ClickHouse Overview và widget fallback gán cứng latency 120/250/450 µs rồi báo SLA OK; MockStore còn có 120/260/480. Không nhập các số này. Bản sửa phải giữ latency absent khi chưa có telemetry và UI hiển thị thiếu dữ liệu, không gán số mẫu từ tổng sự kiện.

Trong lúc thao tác, worktree W21 tự có commit mới `6550059` (không do phiên hợp nhất tạo), thay cho SHA 65d0ce2 lúc kiểm kê. Worktree đó sạch sau commit, vẫn giữ nguyên branch/ref/nội dung; commit mới là phạm vi review tiếp, chưa được nhập vào #220. Rule mới trong đó dùng ID 300011 trùng candidate header được bảo toàn ở #221; cần đối chiếu và cấp ID duy nhất trước khi nhận cả hai nguồn.

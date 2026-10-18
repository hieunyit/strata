# Hợp nhất nhánh — 18/10/2026

Current integration checkpoint: main `bb656e28065d0341100aa02a5cad74f42ce678b7` after #233. #222 retired eleven explicitly superseded histories; #223–#229 selected and repaired machine credential authentication, durable store, API contract/handlers, web workflow and real-browser acceptance. [Detailed credential review](machine-credential-review.md). Cleanup totals: **137 remote / 136 local deletion actions**, including the temporary integration branches created during this audit. WIP/checked-out branches and unreviewed independent feature histories remain preserved. These totals are deletion actions, not a claim that every initial branch was accepted.

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

Kết quả chạy lại test/lint local cho #220 trên cây kết hợp với 3 candidate rule được loại ra: Đã PASS toàn control plane và agent với -race, PostgreSQL cho CP, lint 0 issues; importer Go/race/lint và 5 test fetch integrity PASS. Rust/FFI/compiler 318 test PASS, 3 stress test có sẵn ignored; clippy/fmt PASS. Có thêm regression && PASS bằng Cargo, candidate red/green qua cùng bộ test. Differential pack không có ba candidate: 11.590 requests, 7.997 có rule khớp, 0 khác action/score/tập rule giữa reference/fast/block, PASS 352,72 giây. UI trước thao tác FP: 138 PASS; thêm FP: 144 PASS. Sau sửa key React/focus/lỗi tạo request ID: 14 test FP + exception PASS, lint/build UI PASS. Native được build lại trước mỗi lượt: NGINX 1.30.5: 595 TAP PASS/153 s; NGINX 1.31.6: 595 TAP PASS/154 s; không có ASan/UBSan report. HTTP/3 skip vì chưa cấp binary H3; LSan tắt theo harness, không gọi đây là leak/soak test. Chromium local auth/API/PostgreSQL thật: hai kịch bản PASS (14,5 s trong browser; toàn Go -race 22,888 s). Kiểm scoped exception DRAFT và một phân loại FP/audit, giữ receipt qua reload/đổi ngôn ngữ; viewer/approver gọi thẳng API đều 403. Ảnh mobile và JSON receipt ở evidence. Browser fixture dùng seeded event store, không suy thành nghiệm thu ingress/deploy. Bằng chứng sanitizer/differential tại `a71046e` là kết quả lịch sử có phạm vi SHA/pack, không ghi là vừa chạy trên bản hợp nhất.

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

## Disposition of independent prototype heads

The follow-up records the following sources as superseded, preserving their commits while selecting the reviewed replacements. It does not claim the source implementations were production-ready.

| Source | Selected / excluded content |
|---|---|
| b1927c27, 1b34970a | FP UI ported to durable generated API in #220; narrow exception draft/replay/approval replaces RAM exception approval. Old block-target UI has no accepted runtime mitigation workflow and is not presented as active protection. |
| 44575cce | Signed M2 codec/compiler/runtime replaces wildcard/non-expiring resolver helpers. Generic override resolver remains unimplemented; unused helpers are not imported as a completed feature. |
| 3f2e4e7e | Durable health API and M4 source guards replace RAM counters/callbacks; exact route tests preserve Fleet actions. |
| 6d19ae96 | Explicit-version review UI, report pin and immutable approved proof replace the earlier queue. Old unpinned latest-replay approve behavior is not restored. |
| 444f51a2 | Existing corrected virtual-patch runbook (#131) replaces the obsolete workflow. |
| eaff8d27 | Replace false five-scenario wrapper with actual native component runner; retain a truthful game-day checklist and links to real fault chains. |
| f4c06848 | Preserve prepared 25% observation procedure; correct metric names, Spec-vs-REST context, opt-in staging and unsupported automatic percentage changes. No rollout performed. |
| 298eee70 | Preserve C4/guide intent, rewrite around verified main boundaries; remove invented directives/packages and absolute security/production acceptance claims. |
| 99dc4007 | Preserve diagnostic --prefilter-sources and dated no-gain evidence; no policy behavior change. |
| 61380252 | Four patch-equivalent commits already exist in main; no independent implementation to recover. |

## Follow-up verification

The compatibility native-fault entry point was executed after rebuilding each version: NGINX 1.30.5: Files=3, Tests=70, PASS (71 s); 1.31.6: Files=3, Tests=70, PASS (72 s). No skips or ASan/UBSan reports; test-hooks build, LSan disabled. This is component regression coverage, not a completed five-scenario operational Game Day. Shell syntax and relative documentation links were checked. Compiler diagnostic fmt/Clippy/release build and two-pattern prefilter execution passed; the installed header defines flag 128. An optional trailing diagnostic command failed because rg is absent in the dev image; the separate header/output checks passed. No benchmark improvement or policy change is claimed.

Explicit history acknowledgement uses the ours merge strategy for the eleven sources listed above, after selecting their replacements. This deliberately keeps the reviewed tree: it does not import the RAM credentials/approval/counters, unused wildcard resolver, stale UI, fabricated game-day assertions or unsupported operational claims from those source trees. Source commits remain recoverable. Weekly feature and rate/challenge heads are excluded from this acknowledgement.

## Follow-up merged and branch cleanup

[PR #222](https://github.com/hieunyit/strata/pull/222) merged as main `1f4032da75d6b51bfdae3923dcfec8190122e427`; clean local main fast-forwarded. The eleven explicitly superseded histories are now ancestors, while the reviewed replacement tree is retained. GitHub closed #113 by ancestry. Deleted a further 5 remote and 12 local refs with SHA guards; totals across the three cleanup batches are **126 remote and 125 local branches**. Another complete Git bundle was verified before this batch, including newly committed concurrent heads; worktree content is not claimed backed up by Git bundles. Checked-out local branches and independent unreviewed sources remain. Open PRs at this checkpoint: #144, #152 and draft #221.

Concurrent W17 work has since advanced to `b0ff5f3`; it is preserved and has not been silently included in this integration. Ongoing feature-tree repairs (not merged at this checkpoint) reproduce and fix query-token leakage, empty/unbounded machine scopes, mutable credential slices and duration overflow. The original tests fail before each corresponding fix; PG transactional credentials/audit and complete weekly-feature acceptance remain outstanding.


## Latest concurrent source snapshot

Both active W17 and W21 local refs now point to `b0ff5f3`, advanced by other work during the audit. That history contains W21 API-schema/SecOps/red-team and JA4/challenge/rate changes beyond the original `65d0ce2` snapshot. The new delta includes tracked generated red-team bundles and further rule changes; it is preserved and remains a separate review boundary. Existing positive-model schema API is RAM-backed and needs the same persistence/audit/etag scrutiny as the earlier credential prototype. The new double-encoded rule still conflicts with reserved candidate ID 300011. No reset or deletion of those active worktrees/refs was performed.

## Standalone selection and remaining engine failures

[PR #230](https://github.com/hieunyit/strata/pull/230), [#231](https://github.com/hieunyit/strata/pull/231), [#232](https://github.com/hieunyit/strata/pull/232) and [#233](https://github.com/hieunyit/strata/pull/233) selected the repaired signed watcher, event exporter, runner lifecycle and CLI. Their temporary branches were deleted with exact-SHA guards after merge. [Component review and native scope](standalone-review.md). The original standalone feature branch remains because its installer/package acceptance is unfinished.

Fresh tests of the repaired owned `65d0ce2` feature candidate (not main and not the newer `b0ff5f3`) reached **260 Rust tests passed / 1 failed / 2 ignored** before stopping at `semantic_tuning_test`: the source's benign corpus includes `5 < 10 && 10 > 2`, which the retained SQLi detector flags. The source's blanket `1&1` exemption loses known malicious variants, so it remains excluded. The failing existing test is preserved; no all-Rust PASS claim. Two purely stylistic lint fixes in the candidate make `cargo clippy -p libstrata --all-targets --all-features -- -D warnings` pass (6.96s), without fixing or hiding that semantic failure.

The owned feature worktree also passes focused real-PG `-race` checks for auth/api/ingest/store/policy (3.506s / 17.399s / 5.510s / 21.395s / 3.054s). Geo cache and SSE repairs there remain candidates, not accepted whole features. Geo runtime enforcement/wiring, bot feed authenticity/expiry, replay-safe hourly aggregates, durable schema API, bundle compatibility and clean-system packaging remain review/repair boundaries. Remote W17/W21 heads were pushed independently to `b0ff5f3` during this audit; they are preserved. At this checkpoint there are 26 local branches and 9 actual remote heads, including worktree branches and this temporary evidence branch; these are not all duplicate or approved branches.

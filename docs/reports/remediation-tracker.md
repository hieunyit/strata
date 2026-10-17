Theo dõi remediation · 2026-10-17

Phạm vi là 24 phát hiện của review toàn repo/nhánh/issue đã được yêu cầu sửa, cộng H8 phát hiện khi tích hợp main ngày 17/10. “PR” dưới đây nghĩa là có bản sửa và kiểm chứng cục bộ, chưa merge/chưa triển khai. Không chờ hosted CI theo yêu cầu; không tự sửa con trỏ tuần của PO hay vận hành staging/production. Các PR phụ thuộc phải được review theo base của từng PR.

| # | Mục | Trạng thái / bằng chứng / việc còn lại |
|---|---|---|
| 1 | H1 fallback source saturation | PR #118: loại interval bão hòa khỏi baseline/block-rate; giữ cảnh báo lỗi riêng. |
| 2 | H2 body CPU budget | PR #125/#134/#135/#139: đo lại pack 9.064, profile và sửa hash-collision request-content; large body vẫn PARTIAL ở 10 ms, chưa đạt #28. Không đổi budget/fail mode/oversize/max_args theo quyết định người dùng. |
| 3 | H7 custom header | Rule 300011–300013: hai SQLi oracle bị chặn; GoTestWAF Header SQLi 8/8, XSS 54/56, TN 47/47. Giữ #108 mở cho hai ca chưa có browser oracle/coverage thực; perf tăng cần tune. Xem h7-header-coverage.md. |
| 4 | L3 cold worker | PR #159–#165: đo NGINX cold/reload thật và sửa precompile + chuẩn bị cache trên worker. 714 HTTP request (benign/XSS/start/reload/hot bundle) không budget/fail-mode; ASan/UBSan 595 PASS trên mỗi bản NGINX 1.30.5 và 1.31.6. Xem l3-worker-cache-preparation.md. Còn đo stall khi activate dưới tải/soak; không đóng #49 hoặc #28 từ tập hữu hạn này. |
| 5 | M5 replay/provenance | PR #124/#126/#128/#129/#130/#142: snapshot, proof gắn approval, gate deploy và API; #142 giữ đúng format parser YAML/JSON và snapshot baseline đầu tiên. Không attest runtime image/shared libraries. |
| 6 | M7 collector | PR #120: authorization node/policy/key, giới hạn tổng/node/file/in-flight và timeout. |
| 7 | M6 multi-replica ingest | PR #121: watermark PostgreSQL, retry, đọc FINAL. PR #167: 20 triệu row thật, API Block ID p99 1,543 s → 97,673 ms; 8 tìm kiếm 24 giờ dưới 2 s, TTL PASS; giữ fallback lệch giờ và FINAL. Xem m6-query-performance.md. Benchmark đọc không thay thế multi-replica chain, tải đồng thời hay ingest chưa merge. |
| 8 | M8 event privacy | PR #119: sensitive headers/query names, mask trước truncate. |
| 9 | H6/M3 benchmark giả | Harness paired HTTP đếm request thật; PR #157 chạy limiter prototype ghim SHA, đo collision/pressure/concurrency và chặn benchmark loop đơn bị coi là proxy TPS. Không có chứng cứ rate limiter bảo vệ NGINX hoặc overhead proxy <2%; game day còn mục 21. |
| 10 | M3 rate limiter integration | Prototype chưa nối worker/shared node data path. PO 17/10: trước mắt chỉ đo, chưa đổi hành vi xử lý bảng đầy; không tự kích hoạt enforcement. |
| 11 | M3 collision/concurrency | Harness đã đo prototype ghim 95246eb: collision dư 17/20 allow; pressure dư 2.982/5.120; race khởi tạo/lật cửa sổ mất đếm. Xem m3-rate-measurement.md. Chưa sửa hành vi bão hòa theo lựa chọn người dùng 17/10. |
| 12 | M3 XFF identity | Harness xác nhận helper nhận XFF trái nhất/garbage, path bị lowercase và IPv6 text khác hash; chưa gọi từ NGINX. Cần sửa/tích hợp sau; measurement không được coi là bảo vệ đã hoạt động. |
| 13 | H3 FP write RBAC | PR #123: viewer/approver bị từ chối, operator/admin được phép; API kiểm quyền. |
| 14 | M1 FP durability | PR #122/#123: PostgreSQL annotation, etag, request_id, audit transaction và overlay. |
| 15 | M2 exception durability | PR #138/#143/#148–#151: endpoint tạo draft từ Block ID, exact scope/TTL/etag/request_id, draft+audit+replay queue atomic. PostgreSQL test 12 request đồng thời, retry qua restart/retention; không còn approve RAM riêng. |
| 16 | M2 exception runtime | PR #140/#145–#147/#154/#155: codec/compiler/runtime có flag bắt buộc; test API→replay thật→4 mắt→deploy→HTTP ASan/SQLite→revoke/TTL PASS, 15 cặp/30 HTTP attempts. PR #153 sửa UI mất setting và diff thiếu exception. Chưa merge/deploy, chưa có form tạo exception/queue duyệt UI trong stack này. |
| 17 | H4 health router | Đã sửa local trên prototype: codex/h4-health-route / 3f2e4e7, test fail trước/pass sau, race/lint sạch. Chờ tích hợp M4; chưa đưa health prototype vào main. |
| 18 | M4 quarantine thực | Chưa xong: durable pipeline và shadow behavior, không chỉ cờ RAM. |
| 19 | M4 bounded counters/callback | Chưa xong: time buckets hữu hạn, callback ngoài lock và kiểm tra race. |
| 20 | L1 virtual patch | PR #131: runbook/API/schema đúng, fixture release/verify/test thật; chưa chứng minh SLA vận hành 24 giờ. |
| 21 | H6 game day | Đã chạy 3 test fault mạng thật: outage 5 phút tự hồi, 100 event qua hai cut/reset, download/verify/activate qua link lỗi (h6-network-drills.md). Còn tắt process CP/agent, corrupt bundle, panic và chain NGINX/metrics; chưa gọi game day hoàn tất. |
| 22 | H6 redteam evidence | Harness paired HTTP + SQL oracle, 10 cặp/20 attempt; báo cáo h6-http-evidence.md. Chưa tái chạy campaign cũ. |
| 23 | H5 local checks | PR #127: cache xác minh hash, make lỗi đúng, resume đồng bộ, line budget. ET archive gốc còn thiếu; không thay checksum để bỏ qua. |
| 24 | L4 trạng thái/nhánh/docs | docs/status.md đối chiếu main e93dc0b (PR #141 UI/audit) với prototype/PR. Base kỹ thuật codex/remediation-stage3 ghép stack và main để kiểm tích hợp, không merge main. Giữ ranh giới số đo/production, không tự đổi tuần PO hoặc đóng issue thiếu deployment proof. |
| 25 | H8 Copy as cURL | PR #166: quote mọi argv động, kiểm tên header HTTP token. Parent: 6/7 test shell fail; sau sửa 7/7 và toàn UI 91 PASS, lint/build PASS. Lỗi cần người vận hành dán/chạy shell; không phải tự thực thi khi mở UI. Xem h8-curl-shell-safety.md. |

Đính chính measurement H2 cũ: bundle cache có 9.054 rule, thiếu 300001–300010 trong `rules/gaps/`; không phải full pack hiện tại 9.064 rule. Không dùng kết quả đó làm coverage của pack hiện tại. Các prototype chưa merge không được coi là tính năng production. Không xóa nhánh hoặc thay đổi checkout đang có sửa của phiên khác.

Quyết định 17/10: rate-limit khi bảng đầy trước mắt chỉ đo, chưa đổi hành vi. P-01 §3 đã tìm thấy ở worktree strata-p01 (file proposal chưa track, trạng thái chờ duyệt); không copy/mặc nhiên duyệt hoặc sửa worktree đó. Base kỹ thuật codex/remediation-stage3 kết hợp M2 workflow/evidence/UI, L3, network drills, main e93dc0b, H8 và M6 query; không merge main. Kiểm tích hợp và phạm vi SHA: [l4-stage3-integration.md](l4-stage3-integration.md).

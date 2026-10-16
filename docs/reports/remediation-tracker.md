Theo dõi remediation · 2026-10-16

Phạm vi là 24 phát hiện của review toàn repo/nhánh/issue đã được yêu cầu sửa. “PR” dưới đây nghĩa là có bản sửa và kiểm chứng cục bộ, chưa merge/chưa triển khai. Không chờ hosted CI theo yêu cầu; không tự sửa con trỏ tuần của PO hay vận hành staging/production. Các PR phụ thuộc phải được review theo base của từng PR.

| # | Mục | Trạng thái / bằng chứng / việc còn lại |
|---|---|---|
| 1 | H1 fallback source saturation | PR #118: loại interval bão hòa khỏi baseline/block-rate; giữ cảnh báo lỗi riêng. |
| 2 | H2 body CPU budget | PR #125: đo/classification; cần đo lại pack hiện tại và tối ưu. Không đổi budget/fail mode/oversize/max_args theo quyết định người dùng. |
| 3 | H7 custom header | HTTP oracle tái hiện SQLi qua header; đang bổ sung rule và đo trước/sau, chưa đóng #108. |
| 4 | L3 cold worker | PR #125 mới đo engine cold; còn NGINX cold/reload thực. |
| 5 | M5 replay/provenance | PR #124/#126/#128/#129/#130: snapshot, proof gắn approval, gate deploy và API. Không attest runtime image/shared libraries. |
| 6 | M7 collector | PR #120: authorization node/policy/key, giới hạn tổng/node/file/in-flight và timeout. |
| 7 | M6 multi-replica ingest | PR #121: watermark PostgreSQL, retry, đọc FINAL; chưa đo lại SLO 10 triệu sự kiện. |
| 8 | M8 event privacy | PR #119: sensitive headers/query names, mask trước truncate. |
| 9 | H6/M3 benchmark giả | Chưa hoàn tất; harness HTTP mới có số đếm thật, benchmark rate limiter vẫn cần thay. |
| 10 | M3 rate limiter integration | Chưa xong: prototype chưa nối worker/shared node data path. |
| 11 | M3 collision/concurrency | Chưa xong: cần collision/table-full và atomic window tests. |
| 12 | M3 XFF identity | Chưa xong: cần trusted proxy chain, malformed input và route case. |
| 13 | H3 FP write RBAC | PR #123: viewer/approver bị từ chối, operator/admin được phép; API kiểm quyền. |
| 14 | M1 FP durability | PR #122/#123: PostgreSQL annotation, etag, request_id, audit transaction và overlay. |
| 15 | M2 exception durability | Chưa xong: scope/TTL/audit/etag/idempotency qua policy version. |
| 16 | M2 exception runtime | Chưa xong: compiler/bundle/engine và replay/four-eyes. |
| 17 | H4 health router | Chưa xong: cần route chính xác, không che emergencyDisable. |
| 18 | M4 quarantine thực | Chưa xong: durable pipeline và shadow behavior, không chỉ cờ RAM. |
| 19 | M4 bounded counters/callback | Chưa xong: time buckets hữu hạn, callback ngoài lock và kiểm tra race. |
| 20 | L1 virtual patch | PR #131: runbook/API/schema đúng, fixture release/verify/test thật; chưa chứng minh SLA vận hành 24 giờ. |
| 21 | H6 game day | Chưa xong: cần fault injection lab thực và bằng chứng continuity/metrics. |
| 22 | H6 redteam evidence | Harness paired HTTP + SQL oracle, 10 cặp/20 attempt; báo cáo h6-http-evidence.md. Chưa tái chạy campaign cũ. |
| 23 | H5 local checks | PR #127: cache xác minh hash, make lỗi đúng, resume đồng bộ, line budget. ET archive gốc còn thiếu; không thay checksum để bỏ qua. |
| 24 | L4 trạng thái/nhánh/docs | Tracker này phân biệt PR/prototype/deploy; cần đối chiếu nốt trạng thái tính năng/issue. |

Đính chính measurement H2 cũ: bundle cache có 9.054 rule, thiếu 300001–300010 trong `rules/gaps/`; không phải full pack hiện tại 9.064 rule. Không dùng kết quả đó làm coverage của pack hiện tại. Các prototype chưa merge không được coi là tính năng production. Không xóa nhánh hoặc thay đổi checkout đang có sửa của phiên khác.

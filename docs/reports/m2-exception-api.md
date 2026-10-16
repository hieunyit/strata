Nhiệm vụ: M2 · tạo exception draft từ Block ID
Nhánh: codex/m2-exception-api; base: codex/m2-atomic-draft-replay.

POST /v1/exceptions:fromBlockId kiểm exceptions:write, authenticated subject, etag, request_id, reason và TTL 60 giây..30 ngày. Client chọn rõ Rule ID + field đã ghi trong violation; method/Host/path/tên policy lấy từ event bị chặn và catalog phải có managed rule. Không suy diễn wildcard, toàn body hay strip |base64 từ chuỗi event không đủ bằng chứng phân biệt alias/literal. Scope trùng đang còn hạn bị từ chối, không âm thầm gia hạn.

Draft+audit+request response+replay PENDING ghi atomic bằng store đã kiểm chứng. Thời điểm expiry và ID chỉ sinh trong lần thực thi đầu; retry trả nguyên bản ngay cả sau restart, event hết retention, hoặc có bản policy mới. Giữ các setting JSON có sẵn, kể cả field chưa được model hiện tại biết. Không PG hoặc không runner thì từ chối tạo mới. Response là DRAFT, cùng policy ID/version/etag và URL theo dõi replay; không activate hoặc tự approve/deploy.

Bằng chứng thật: go test -race -count=1 -v ./api -run TestExceptionDraft → 2 test PASS, package 2.247s; golangci-lint run ./api/... ./cmd/server/... → 0 issues. Tests gồm 12 request đồng thời, viewer/approver/anonymous bị từ chối, operator/admin ghi được, input sai/quá lớn/unknown JSON, scope thiếu/alias/wildcard, thiếu etag/TTL/request, duplicate scope và replay/audit durable. Output ở m2-exception-api-checks.txt.

Tự review: input 8 KiB, timeout 5 giây, callback không external I/O, policy cap 128, không log snippet/token, quyền kiểm ở route API; không dependency mới. Chỉ API/server wiring/test/docs, không đổi chính sách body/CPU/fail mode. OpenAPI/client và kiểm thử exception qua replay/four-eyes/deploy thật là bước tiếp theo, chưa tuyên bố M2 hoàn tất. Không merge/deploy, không chờ hosted CI.

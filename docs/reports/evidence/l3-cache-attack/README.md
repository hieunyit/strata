L3 cache preparation · runtime commit 4861c58.

231 HTTP XSS qua NGINX thật: 11 first + 220 warm, toàn bộ 403, không budget/fail-open/fail-closed. Backend fixture chỉ trả 200: status 403 đến từ WAF. Metadata giữ hash URI/harness/module/bundle, các request xác nhận PID/bundle. Không suy ra coverage mọi payload; xem ../../l3-worker-cache-preparation.md.

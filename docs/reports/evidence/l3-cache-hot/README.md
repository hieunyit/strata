L3 hot activation và tài nguyên · runtime commit 4861c58.

Năm trial benign + một trial XSS, mỗi trial 42 HTTP request thật. Cycle 1 giữ PID của cycle 0 và chuyển signed bundle 1 → 2 qua control file. Tổng 252 request: benign 210/210 HTTP 200, XSS 42/42 HTTP 403, 0 budget/fail-open/fail-closed. `trials.jsonl` có một metadata/summary cho mỗi trial, `requests.jsonl` có từng request kèm trial.

Bundle v2 rebuild từ cùng IR/policy bằng compiler hiện tại cho SHA trùng artifact đã đo; xem artifacts.json. Không commit private key/bundle/binary. `resources/measure.py` đo A/B/B/A qua C ABI offline, Linux wait4/maxrss, stream hash và timeout 30 giây; baseline binary là example ở source 9afd039, prepared binary từ 4861c58 với --prepare. Hai binary cùng chế độ không test-hooks. Đây không phải RSS NGINX/soak hoặc SLO proxy. Xem ../../l3-worker-cache-preparation.md cho giới hạn và output sanitizer.

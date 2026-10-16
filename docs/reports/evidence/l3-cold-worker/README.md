Raw evidence của lần lặp lại trong l3-cold-worker-measurement.md.

231 request: start + 10 reload, mỗi worker 1 first + 20 warm. Metadata gắn hash đúng harness/module/bundle được chạy. Budget và fail-open là delta counter, không suy ra từ HTTP status. Không có secret hoặc payload người dùng; toàn bộ traffic là fixture loopback. Kết quả là quan sát lỗi, không phải security PASS.

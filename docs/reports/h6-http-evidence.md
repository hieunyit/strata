Nhiệm vụ: H6 · bằng chứng HTTP có oracle, phần 1

Harness `tests/security/header_probe.py` chạy NGINX 1.30.5/module vừa build, bundle ký bằng khóa fixture, hai worker và backend SQLite trong bộ nhớ, chỉ lắng nghe loopback trong container dev. Mỗi ca có HTTP đối chứng trực tiếp và HTTP qua WAF. Marker chỉ xuất hiện khi SQL UNION thực thi; phản chiếu chuỗi không được tính thành exploit. XSS chỉ đo rule detection, không chứng minh thực thi trong trình duyệt.

Mỗi attempt ghi status, latency_ms, action, rule ID, event ID và kết quả oracle. HTTP 400/429/5xx, lỗi transport và lỗi inspection có nhóm riêng; không tự coi là signature block. Hash binary/module/bundle/pubkey/harness/cases/config nằm trong metadata. Không dùng hash payload ngoại tuyến làm số request HTTP.

Kiểm chứng:
```text
python3 tests/security/test_header_probe.py
Ran 2 tests in 0.522s — OK
header_probe.py, rounds=1:
valid_measurement=true; measured_pairs=10; measured_http_attempts=20
proxy_status_counts: 403=3, 200=7
signature_block=3; backend_sql_oracle_reached=2; benign_pass=5
```

Lệnh tái hiện trong image dev, sau khi build NGINX và release bundle fixture từ toàn bộ `rules/`:
```sh
python3 tests/security/header_probe.py \
  --nginx build/nginx-1.30.5/objs/nginx \
  --module build/nginx-1.30.5/objs/ngx_http_strata_module.so \
  --mkbundle target/release/mkbundle \
  --bundle build/header-base/pkg/strata-signatures-header-baseline.sbn \
  --pubkey connectors/nginx/t/fixtures/bundle.pub \
  --out build/header-base/final-probe
```

Pack hiện tại có 9.064 rule; query SQLi bị 942100/942190/942360 chặn, custom-header SQLi dạng raw và URL-encoded tới SQLite và trả marker. Hai ca custom-header XSS đã bị 941110 chặn. Đây là bằng chứng trước sửa H7; không suy ra tỷ lệ bao phủ GoTestWAF đầy đủ từ 5 attack fixture. Năm benign fixture không thay thế corpus FP.

[Bản ghi từng cặp](h6-http-evidence/requests.jsonl), [metadata](h6-http-evidence/metadata.json), [số đếm](h6-http-evidence/summary.json).

Giới hạn: số đo tuần tự gồm khởi động worker/cache, không phải benchmark throughput hay p99. Budget 10 ms/fail-open chỉ là cấu hình fixture; không đổi mặc định hay chính sách body. Chưa kiểm botnet fallback, canary, event delivery, fault injection hoặc browser XSS. H6 chưa hoàn tất game day; không tái xác nhận các báo cáo redteam cũ. Mọi latency có đơn vị ms (ví dụ 1052,62 ms là khoảng 1,053 giây).

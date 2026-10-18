Nhiệm vụ: H7 / #108 · custom-header SQLi, bản sửa thứ nhất

Rule 300011 áp dụng libinjection SQLi và lexical guard của Strata CRS 942100 cho request header ngoài Host/User-Agent/Referer/Cookie (các field này đã có kiểm tra chuyên biệt). Chạy request_headers, giữ score 100/action_mode score; URL/base64 transform dùng multi_match để vẫn kiểm tra raw. Không sửa CRS sinh tự động. Không đổi policy/budget mặc định. Rule mới cần người luồng S duyệt trước phát hành.

Kiểm chứng cục bộ:
```text
strata-rules lint --repo ../.. ../../rules/gaps: 11 files, 0 problems
strata-rules test --repo ../.. ../../rules/gaps:
PASS 300011 (11 requests)
11 rules: 11 pass, 0 fail, 0 skipped
full-pack report: 9065 rules evaluated, 0 skipped
3000 benign: 0 matched, 0 blocked
recall blocked CMDi 94.6%, LFI 97.4%, SQLi 76.8%, XSS 75.8%
python3 tests/security/test_header_probe.py: 2 tests OK
bash -n tests/security/run-header-gotestwaf.sh: PASS
```

NGINX 1.30.5, hai worker, bundle ký khóa fixture: paired HTTP/SQLite oracle trước sửa có 2 custom-header SQLi thực thi; sau sửa cả hai bị 300011 chặn. Query đối chứng và hai XSS cơ bản vẫn bị chặn; 5/5 benign đi qua. Đây là hai bundle 9064/9065 rule, không dùng cache pack cũ 9054.

GoTestWAF v0.5.8 dùng image digest cố định trong script, chỉ đổi placeholder thành Header, giữ nguyên payload/encoder chính thức của SQLi/XSS và 47 benign texts. Script tự dựng fixture loopback riêng, không publish port, không gửi email; --blockStatusCodes 403, không coi 5xx/reset là chặn. Chạy trước/sau bằng `tests/security/run-header-gotestwaf.sh BUNDLE build/OUT`. Thêm mount cache target vào STRATA_DEV_DOCKER_ARGS trên máy lab này. Hash fixture upstream/selected được lưu theo lượt.

| Nhóm Header | Trước | Sau |
|---|---:|---:|
| SQLi bị chặn | 1/8 | 4/8 |
| XSS bị chặn | 13/56 | 20/56 |
| Benign đi qua | 47/47 | 47/47 |
| Unresolved / failed | 0 / 0 | 0 / 0 |

Mỗi lượt GoTestWAF có 111 test HTTP; access log NGINX gồm cả paired probe và control/precheck có 130 request: trước 200=111/403=19; sau 200=99/403=31. Không có status khác. XSS tăng là kết quả quan sát của tập test này, không coi đó là hoàn thành coverage XSS hay chứng minh thực thi trình duyệt.

Chi phí: cùng binary đo engine (hash/commit trong perf-metadata), ca small, 1000 mẫu/lượt, thứ tự baseline/candidate/candidate/baseline. Mean µs lần lượt 1117.93/1200.04/898.34/781.70; trung bình candidate cao hơn khoảng 10.5%, đồng thời độ trôi giữa các lượt lớn. Cả 4000/4000 FULL, không lỗi/budget error/block. Đây chưa là đo có kiểm soát để kết luận overhead chính xác hay đạt SLO; cần profile và workload nhiều header hơn. Raw small-abba.jsonl giữ số thật, không thay bằng công thức TPS proxy.

Dữ liệu [h7-header-sqli/](h7-header-sqli/) có paired records, artifact hashes, summary GoTestWAF và corpus. Báo cáo đầy đủ GoTestWAF còn trong build/h7-{baseline,candidate}-final/headers.json. Lần đầu delay=0 làm GoTestWAF panic, lần sau sai quyền report; đã chạy lại thành công với delay=1 và UID host, không tính hai lần lỗi vào kết quả trên.

Chưa xong: còn 4/8 SQLi và 36/56 XSS Header chưa bị chặn. Giữ #108 mở; không tuyên bố đạt coverage tổng thể hay an toàn cho mọi header ứng dụng. H7 còn cần bổ sung có mục tiêu, FP/perf lại sau thay đổi; chưa merge/deploy.

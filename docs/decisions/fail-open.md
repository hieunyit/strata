# Quyết định: hết CPU budget không còn cho request đi qua

Ngày: 22/10/2026 · Người duyệt: người dùng (vai PO): "tìm cách khắc phục triệt để vấn đề fail-open, dựa vào CPU không ổn" · Người viết: Claude Code.

## Vấn đề

Hết CPU budget thì request đi theo `strata_fail_mode` của location, mặc định `open` tức cho qua. Kẻ tấn công đệm phần đầu body cho tốn CPU rồi đặt payload ở cuối: phần chưa kiểm đi tới backend.

- Lab redteam TC-EXP-02: profile A (fail mode open) trả 200, profile B (closed) trả 503.
- Benchmark ngày 22/10/2026, form 64 KB, gói signature đầy đủ: 33–59% request vượt budget và đi fail-open. Budget lúc đó là 10 ms + 0,5 ms/KB (42 ms), trong khi engine cần 44–46 ms.
- Đổi budget sang thời gian CPU (#422) bỏ được phần do tải của host, nhưng phần do chi phí thật vẫn còn. Mọi cách giữ "hết giờ thì cho qua" đều để lại một ngưỡng mà kẻ tấn công nhắm tới được.

## Quyết định

Tách hai việc trước đây cùng dùng chung đồng hồ:

1. **Kiểm bao nhiêu** do **kích thước** quyết định, tất định. Body lớn hơn `strata_request_body_limit` đi theo `oversize` của policy (Rule 100020), như trước.
2. **CPU tối đa của một request** do kích thước quyết định. Budget = `strata_cpu_budget` (mặc định 10 ms) + **4 ms cho mỗi KB** của request (request line, header, body; trước đây chỉ body, 0,5 ms), tối đa **2,5 s** (trước đây 100 ms).
3. **Hết budget ở policy enforce thì request bị từ chối (503 kèm Event ID)**, bất kể `strata_fail_mode`. Policy shadow vẫn chỉ ghi. `strata_fail_mode` giữ cho lỗi engine, panic và lúc chưa có bundle. Trường `fail_on_findings` (#98) không còn tác dụng.

## Số đo làm cơ sở (engine, gói đầy đủ, không giới hạn budget)

| Request | CPU | ms/KB |
| --- | ---: | ---: |
| JSON 64 KB, 1.000 bản ghi (đắt nhất) | 78,6 ms | 1,23 |
| XML 64 KB | 59,4 ms | 0,93 |
| Form 64 KB, chữ có từ khóa tấn công | 52,4 ms | 0,82 |
| Form 64 KB, 1.024 tham số nhỏ | 40,9 ms | 0,64 |
| Body 128 KB (các dạng trên) | 26–59 ms | 0,21–0,45 |
| GET query 16 KB, 250 cookie | 15–16 ms | |
| Body 1 MB HTML entity | khoảng 240 ms | 0,23 |

Chi phí có trần vì engine giới hạn số tham số (1.024), số giá trị base64 được giải mã và số thuộc tính XML; phần còn lại là quét tuyến tính.

**Cùng một request cũng dao động**: form 64 KB có trung vị 38,7 ms CPU, p99 83,7 ms, max 128,8 ms trên 1.500 lần (thời gian CPU gần bằng thời gian thực, không page fault: CPU thật, khả năng cao do cache và bộ nhớ dùng chung với các tiến trình khác trên host). Bản đầu 2 ms/KB (138 ms cho 64 KB) làm khoảng 1/400 request hợp lệ nhận 503 trên NGINX; 4 ms/KB cho 266 ms, khoảng 2 lần max quan sát được và 6 lần trung vị. Với 4 ms/KB, JSON 64 KB (79 ms) dư hơn 3 lần; body 1 MB (khoảng 140–240 ms) dư hơn 10 lần dưới trần 2,5 s.

## Đánh đổi

- **CPU tối đa của một request lớn hơn**: tối đa 2,5 s, thực tế 0,1–0,3 s với body 1 MB. Kẻ tấn công không còn được cho qua; thứ họ còn làm được là tốn CPU, giống mọi WAF kiểm hết body (ModSecurity, Coraza không có budget thời gian). Biện pháp: hạ `strata_request_body_limit` theo route (API thường 128–256 KB) và `limit_req` của NGINX cho request có body.
- **Request hợp lệ hiếm hoi vượt budget sẽ nhận 503** thay vì đi qua không kiểm. Đo trên corpus: không có. Trước khi bật enforce cho route mới, xem `strata_budget_exceeded` của route ở shadow.

## Tính CPU của request (`engine/src/budget.rs`)

Đọc thời gian CPU của thread là syscall (khoảng 2 µs trên VM). Cách tính:

- Lời gọi FFI chạy quá 0,5 ms lấy một mốc ở checkpoint kế tiếp; từ mốc trở đi tính thời gian CPU.
- Request đã lớn (budget tăng ≥ 20 ms so với budget cơ sở, tức khoảng 5 KB) đọc đồng hồ CPU ngay khi vào mỗi lời gọi: body lớn đến qua nhiều lời gọi ngắn.
- Phần không có số đo CPU (lời gọi không có mốc, khoảng trước mốc) tính tối đa **1 ms**: vòng lặp của engine qua checkpoint khoảng mỗi 50 µs, nên phần đó làm dưới 0,5 ms việc; phần còn lại là thời gian tiến trình khác chạy. Bản đầu không có giới hạn này: worker bị chiếm CPU giữa lời gọi xử lý header (dưới 1 ms CPU) bị tính 23–45 ms và request bị 503 trên host bị tải. Tính thiếu ở đây chỉ cho request làm thêm việc, không bao giờ để request đi qua mà chưa kiểm.

## Kết quả đo (NGINX 1.30.5, 2 worker, gói đầy đủ, 20 s mỗi lượt)

| Lượt | Trước (đồng hồ thực, fail mode open) | Sau |
| --- | --- | --- |
| Form 64 KB, máy yên | 33–59% fail-open | 0 fail-open, 0 lỗi, 0 vượt budget |
| Form 64 KB, tiến trình đốt CPU trên CPU của NGINX (nhiễu 82%) | 100% fail-open | 0 fail-open, 0 lỗi, 0 vượt budget |
| Form 1 MB, máy yên | 100% fail-open | 0 fail-open, 0 lỗi (131–136 ms mỗi request) |
| GET nhỏ, đốt CPU (full / p01) | | 0 lỗi / 16.911 và 48.469 request |
| Lab redteam TC-EXP-02 (profile A, fail mode open) | 200 (lọt) | 403 (payload ở cuối body được tìm thấy) |
| GoTestWAF tập benign | 0/141 bị chặn | 0/141 bị chặn |

## Kiểm chứng

- Test::Nginx `060-fail-mode-events.t`, `090-breaker.t`: hết budget ở enforce trả 503 cả khi fail mode open, có finding hay không; shadow cho qua; body 1 MB HTML entity được kiểm hết và đi qua. Hook `STRATA-TEST-SPIN` (chỉ bản build test-hooks) đốt CPU tới khi hết budget.
- Lab redteam (TC-EXP-02, GoTestWAF) và benchmark: báo cáo trong PR.

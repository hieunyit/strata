# Quyết định: giải mã base64 tham số, budget 10 ms, sửa FP văn xuôi của CRS PL1

Ngày: 15/10/2026 · Nhánh: `base64-budget` · Người làm: Claude Code.

PO yêu cầu (14/10/2026), sau khi chạy GoTestWAF:

1. nâng budget lên 10 ms;
2. giải mã base64 cho các tham số nghi vấn;
3. làm loại trừ cho các Rule ID gây FP;
4. tham khảo cách các WAF thương mại làm.

Ngày 15/10 có thêm một đánh giá bảo mật cho bản đầu của phần base64 (§5).

## 1. Các WAF khác làm thế nào

| Vấn đề | WAF khác | Strata chọn |
| --- | --- | --- |
| Base64 | **F5 Advanced WAF**: bật giải mã theo **từng parameter**. Giải mã được thì chạy các kiểm tra của policy trên giá trị đã giải mã; không giải mã được thì báo vi phạm "Illegal base64 value". F5 khuyên chỉ bật cho parameter luôn là base64; tracker của F5 có nhiều lỗi lọt signature quanh tính năng này (ID 1827821, 1377621, 1127093). **Cloudflare** (attack score, 05/2024): tự phát hiện và giải mã base64 trong request, không cần cấu hình. **AWS WAF**: transform `BASE64_DECODE` / `BASE64_DECODE_EXT` theo từng rule (mỗi transform +10 WCU). **CRS**: `t:base64Decode` chỉ có trong vài rule | Tự phát hiện, như Cloudflare: không cần biết trước parameter nào là base64, mọi rule trên ARGS/cookie đều thấy giá trị đã giải mã. Tiêu chí chặt và có giới hạn công việc mỗi request (§4) |
| Giới hạn inspect | AWS WAF: body 8 KB (ALB, AppSync), 16 KB nâng được tới 64 KB (CloudFront, API Gateway...); phần vượt không được inspect, rule chọn `CONTINUE`, `MATCH` hoặc `NO_MATCH` cho phần quá cỡ. Cloudflare: 128 KB (Enterprise) theo changelog 12/2025 | Đã có `strata_request_body_limit` (1 MB) + `oversize: pass\|block` theo policy. Giới hạn thực tế đang là CPU budget (§2) |
| FP | CRS: exclusion càng hẹp càng tốt (`ctl:ruleRemoveTargetById` theo URI + tham số), có comment, chủ sở hữu và hạn dùng. Cloudflare: exception (skip) hẹp theo host/path, tắt từng rule chứ không tắt cả ruleset | FP chung cho mọi ứng dụng (văn xuôi) thì **sửa logic rule** trong importer (§3), như 942100 ở W11-S-01. FP riêng của ứng dụng thì dùng exception hẹp (route + field + Rule ID, có hạn), tức W14-G2-01 theo thiết kế; không kéo việc đó lên tuần này |

Nguồn:

- [F5: Securing Base64-Encoded Parameters](https://techdocs.f5.com/kb/en-us/products/big-ip_asm/manuals/product/asm-implementations-11-6-0/32.html)
- [F5 Bug ID 1827821](https://cdn.f5.com/product/bugtracker/ID1827821.html)
- [Cloudflare: Improved detection capabilities](https://developers.cloudflare.com/changelog/2024-05-23-improved-detection-capabilities)
- [AWS WAF: text transformations](https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statement-transformation.html)
- [AWS WAF: oversize request components](https://docs.aws.amazon.com/waf/latest/developerguide/waf-oversize-request-components.html)
- [CRS: False Positives and Tuning](https://coreruleset.org/docs/concepts/false_positives_tuning)
- [Cloudflare: Troubleshoot managed rules](https://developers.cloudflare.com/waf/managed-rules/troubleshooting/)

## 2. Budget mặc định 10 ms

`strata_cpu_budget` mặc định đổi từ 2 ms lên **10 ms** (`ngx_http_strata_module.c`, bảng directive trong `nginx-module.md`).

Số đo GoTestWAF ngày 14/10, gói đầy đủ 9.054 rule, NGINX riêng 2 worker trên CPU 2–3:

| Budget | Request được kiểm đủ | TP |
| --- | ---: | ---: |
| 2 ms | 5,5% | 27,6% |
| 5 ms | 85,7% | |
| 10 ms | 97,9% | 45,6% |
| 20 ms | 98,5% | |
| 1 s, tắt breaker | 100% | 47,8% |

Thời gian engine mỗi request: p50 3,4 ms, p90 5,5 ms, p99 39 ms.

- **Vì sao 10 ms**:
  - với gói đầy đủ, 2 ms biến WAF thành fail-open với gần mọi request;
  - 10 ms là điểm gãy của đường cong (97,9%), từ 20 ms trở đi lợi rất ít.
- **Vì sao không cao hơn**:
  - budget là hàng rào chống DoS bằng CPU: request độc hại có thể ép engine tốn tối đa budget × số request;
  - 10 ms trên mỗi worker vẫn giữ được khoảng 100 request/giây trong trường hợp xấu nhất;
  - request cần lâu hơn (body lớn, #28) phải được sửa ở engine, không nên được nới budget.
- **Không đổi**:
  - policy enforce cho API nhạy cảm vẫn có thể đặt `strata_fail_mode closed`;
  - route nào cần thì ghi đè `strata_cpu_budget` theo location.

## 3. FP văn xuôi của CRS PL1

GoTestWAF có 141 câu văn bình thường; 13 câu bị chặn, do 4 rule CRS PL1 chặn một mình (điểm 100 = ngưỡng):

| Rule | Văn bản bị chặn | Tinh chỉnh (importer, `tune`) |
| --- | --- | --- |
| 932250 | `ls 300 lexus`, `zsh is the best!` | Thêm điều kiện: giá trị chỉ là lệnh (`id`, `whoami`), hoặc có cú pháp shell/đường dẫn (`-` `/` `\|` `;` `&` `$` `` ` `` `<` `>` `*` `?` dấu nháy, ngoặc, `=`, `a.b`) |
| 941210 | `JavaScript: Basics of JavaScript Language` | Thêm điều kiện, sau transform của rule: có `(`, `` ` `` hoặc `=` (lời gọi, phép gán), hoặc từ bị làm rối (tab/xuống dòng giữa các chữ, `&tab;`, `&#`) |
| 942100 | `john+or@var.es` | Tín hiệu SQL bổ sung: một từ khóa đi một mình không đủ, phải có thêm một từ khóa khác hoặc một số (`1 or 1`, `x or true`) |
| 942190 | `union was a great select` | Giữa `union` và `select` chỉ cho phép: một cụm liền ngay sau union (phần còn lại của comment, ví dụ `union/*x*/select`), khoảng trắng, `(`, và `ALL`, `DISTINCT`, `DISTINCTROW` |

Không tắt rule nào, cũng không làm exception theo tham số: các tham số của GoTestWAF có tên ngẫu nhiên. Exception viết riêng cho bộ test sẽ chỉ làm đẹp con số chứ không bảo vệ gì thêm.

**Giá phải trả**: test go-ftw 932250-9 (`ls foo bar`) không còn khớp. Câu này có cùng dạng với `ls 300 lexus`, nên không thể vừa giữ test đó vừa bỏ FP. Một lệnh như vậy chỉ nguy hiểm khi ứng dụng đưa nguyên giá trị vào shell, và ở đó mọi lệnh có ích cho kẻ tấn công đều có tùy chọn, đường dẫn hoặc tên host. Kết quả go-ftw sau khi tinh chỉnh: §6.

## 4. Giải mã base64 (engine, `engine/src/b64.rs`)

**Phạm vi**: giá trị của ARGS (query, form, JSON, phần multipart không phải file) và REQUEST_COOKIES.

**Ngoài phạm vi**:

- **Header**: `Authorization: Basic` giải mã ra `user:mật khẩu`. Giải mã header vừa đưa mật khẩu vào vùng scan và snippet, vừa thêm FP.
- **Path**: base64 trong path thường là ID; GoTestWAF có placeholder URLPath (§6). Để sau.

**Tiêu chí**:

- Giá trị dài 8–16.384 byte.
- Chỉ dùng một bảng chữ cái: `+/` hoặc `-_`. Khoảng trắng được tính là `+`, vì form decode đã đổi `+` thành khoảng trắng.
- Tối đa hai `=` ở cuối, và độ dài không dư một ký tự.
- Bảng chữ cái được kiểm trước khi cấp phát bộ nhớ.
- Byte giải mã ra phải có ít nhất 8 byte text liên tiếp (toàn bộ, nếu ngắn hơn). Text là ký tự UTF-8 không phải ký tự điều khiển; khoảng trắng gồm tab, LF, VT, FF, CR.
- Khi giá trị đạt tiêu chí, **toàn bộ** giá trị giải mã được inspect.

**Cách inspect**:

- Giá trị giải mã được thêm vào ARGS (hoặc cookie) dưới tên `<tên>|base64`.
- Mọi rule trên ARGS/cookie đều thấy nó.
- Rule có key (`ARGS:q`) và exclusion so khớp theo tên gốc.
- Sự kiện ghi `ARGS:q|base64`, snippet là văn bản đã giải mã, qua cùng các lớp mask.
- Field nhạy cảm (danh sách dựng sẵn và `privacy.sensitive_fields`) không có snippet.

**Giới hạn mỗi request** (`b64::Left`):

- 32 giá trị được giải mã;
- 64 KB byte giải mã;
- 256 KB byte được thử, kể cả giá trị thử mà không giải mã;
- kiểm CPU budget trước khi giải mã.

## 5. Đánh giá bảo mật ngày 15/10 cho bản đầu

| # | Đánh giá | Kiểm lại | Sửa |
| --- | --- | --- | --- |
| 1 | CRITICAL: `is_sensitive_target` (danh sách field nhạy cảm dựng sẵn) không bỏ hậu tố `\|base64`, nên mật khẩu đã giải mã vào snippet | **Đúng**. Test `sensitive_fields_keep_no_snippet_decoded` hỏng khi bỏ dòng sửa | `event.rs` bỏ hậu tố trước khi so, như `privacy.rs` |
| 2 | HIGH: giá trị không giải mã được không bị tính vào giới hạn, nên có DoS bằng CPU | **Đúng một phần**: không có giới hạn cho các lần thử. Chi phí tuyến tính theo input, mà input đã bị giới hạn bởi body limit và cũng được scan bằng Hyperscan, đắt hơn nhiều. Mức thực tế là trung bình | Giới hạn 256 KB byte được thử; kiểm bảng chữ cái trước khi cấp phát; kiểm budget |
| 3 | MEDIUM-HIGH: VT/FF bị coi là nhị phân, nên payload lọt | **Đúng, và rộng hơn**: chỉ một byte nhị phân bất kỳ (đặt trong comment SQL) là bản đầu bỏ qua cả giá trị | Tiêu chí mới: 8 byte text liên tiếp, VT/FF là khoảng trắng. Test có padding nhị phân |
| 4 | MEDIUM: rule có key ghi `ARGS:q` và mất hậu tố | **Đúng** (mất dấu điều tra; mask vẫn đúng vì key là tên gốc) | Rule có key ghi `ARGS:q\|base64` |

## 6. Kết quả

**GoTestWAF**:

- **Cách đo**:
  - gói đầy đủ 9.054 rule, policy `example-api` enforce kèm signatures;
  - NGINX 1.30.5 riêng, 2 worker trên CPU 2–3; GoTestWAF trên CPU 4–5;
  - lệnh: `build/gtw/scan.sh`, không commit.
- **Ba lượt**:
  - 10 ms: chỉ đổi budget;
  - + base64: bản đầu của §4;
  - Nhánh này: §3, §4 và §5.

| | 2 ms (main 14/10) | 10 ms | + base64 | **Nhánh này** |
| --- | ---: | ---: | ---: | ---: |
| True positive | 27,6% | 45,55% | 63,35% | **63,80%** (430/674) |
| True negative | 92,9% | 90,78% | 90,78% | **100%** (0/141 bị chặn) |
| Base64Flat bị chặn | | 0/235 | 121/235 | **124/235** |
| Điểm GoTestWAF | | 62,59% | 67,13% | **69,56%** |
| Request vượt budget (`error`) | 612/823 | 17 | 25 | 19 |

**Rule (`make test-rules`, `make test-crs-ftw`)**:

- Corpus benign 3.000 request: 0 FP.
- Recall không đổi: SQLi 76,3%, XSS 75,2%, CMDi 94,2%, LFI 97,4%.
- go-ftw toàn bộ CRS 96,0%, trước là 95,9%:
  - chỉ mất 932250-9 (§3);
  - nhóm 920 tốt lên 5 test, do các thay đổi đã có trên main từ lần sinh báo cáo trước.
- Bundle gói đầy đủ 20,99 MB, trước là 20,57 MB, do có thêm điều kiện regex. Giới hạn ký Vault là 24 MiB.

**Test**:

- `cargo test --workspace` PASS.
- clippy và fmt sạch.
- Test::Nginx 1.30.5: PASS, 587 test.
- Test::Nginx 1.31.6: PASS ở lượt chạy lại. Lượt chạy cả bộ có `030-block.t` TEST 7 hỏng (dòng access log chưa ghi kịp khi máy tải cao); chạy riêng 3/3 lần PASS.
- Phần C: 2.999/3.000 dòng (không đổi).

**Còn mở, không làm trong nhánh này**:

- **Body 8–128 KB** vẫn vượt 10 ms và đi fail-open (#28): cần đảo vòng scan như `issue-27-28-prototype.md` §5. Không nới budget thêm.
- **Base64 trong path và header**: theo access log, khoảng 47 trong 111 payload Base64Flat còn lọt nằm ở URL path.
  - Khoảng 20 nằm ở query: giá trị đã được giải mã nhưng không có rule nào bắt (dòng dưới).
  - Phần còn lại ở header/body; log không đủ để tách riêng.
  - Cần quyết định riêng: base64 trong path thường là ID, và header thì có `Authorization: Basic`.
- **Lỗ hổng phát hiện, không liên quan encoding**: payload giải mã ra vẫn lọt khi không có rule nào bắt (LDAP 16,7%, mail 25%, XML/XXE, header tùy biến). Thuộc luồng S (gói rule).

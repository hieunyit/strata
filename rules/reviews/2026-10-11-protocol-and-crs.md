# Duyệt rule luồng S · 11/10/2026

Người duyệt: Claude Code, theo yêu cầu của PO (đóng vai người luồng S, AGENTS.md mục 3).
Phạm vi: `rules/protocol/` (40 rule, 100101–100140) và `rules/crs/` (136 rule CRS 4.25.2 PL1, sinh bởi `make crs-import`).

Cách duyệt: đọc từng rule protocol (điều kiện, điểm, rủi ro FP trên lưu lượng thật, trùng với kiểm tra dựng sẵn 100001–100020 và CRS 920/921, NGINX có để request như vậy tới module không); với CRS, chạy go-ftw của **mọi** nhóm qua libstrata (`strata-rules ftw`), soát rule thất bại ≥ 50% test của chính nó, rule không có test, và các rule điều khiển (`skip`, `skipAfter`) mà importer bỏ qua.

## Kết luận

- Pack protocol: **duyệt**, sau 7 chỗ sửa dưới đây. 0 / 2.000 request benign khớp; mọi mẫu khớp/không khớp pass.
- CRS: **duyệt**, sau 2 lỗi sửa trong importer và runner. Ba rule không có test upstream được kiểm tay. Các khác biệt còn lại được ghi lý do và chấp nhận.

## Pack protocol

### Đã sửa khi duyệt

| Rule | Vấn đề | Sửa |
| --- | --- | --- |
| 100106 | Độ dài cả request target trùng với 100107 (query): một query dài cộng 50 + 30 | Chỉ đo path (`path` > 2048 byte); query là việc của 100107 |
| 100113 | `%2F` trong path có thật ở một số API (id dạng `group%2Fproject`) | Điểm 30 → 20 |
| 100114 | `%u0041` khớp cả 100114 (ký tự sau `%` không phải hex) và 100116: cộng 100, **chặn** mọi request có `%u` | 100114 bỏ qua `%u`; thêm mẫu không khớp |
| 100131 | Tên nói X-Original-URL **hoặc** X-Rewrite-URL nhưng chỉ kiểm tra cái đầu | Thêm target X-Rewrite-URL và mẫu |
| 100132 | Chỉ X-HTTP-Method-Override | Thêm X-HTTP-Method, X-Method-Override và mẫu |
| 100133 | `charset=utf8` (không gạch) do nhiều client gửi bị tính | Chấp nhận `utf-?8`; thêm mẫu không khớp |
| 100139 | "khác trailers" bắt cả `TE: trailers, deflate;q=0.5` hợp lệ | Đổi thành "TE liệt kê chunked" (dấu hiệu smuggling), thêm mẫu |

### Duyệt, kèm ghi chú vận hành

| Rule | Ghi chú |
| --- | --- |
| 100101 | WebDAV/CalDAV (PROPFIND, REPORT...) bị tính 40, không tự chặn. API dùng các method đó thì tắt rule trong policy |
| 100102, 100103 | NGINX tự trả 405/400 cho TRACE/CONNECT ở nhiều cấu hình; rule vẫn đúng khi request lọt tới module |
| 100107, 100110 | SAML redirect binding và JSON có ảnh base64 có thể vượt ngưỡng; điểm thấp (30, 20), không tự chặn |
| 100120, 100121 | Với `ignore_invalid_headers on` (mặc định) và `large_client_header_buffers` 8k, NGINX đã chặn phần lớn trước; rule là lớp thứ hai |
| 100135 | API nhận body gzip hợp lệ sẽ bị tính 50: body nén không kiểm tra được, đó là chủ ý |
| Còn lại | Đúng như tên, không trùng kiểm tra dựng sẵn hay CRS PL1 đã nhập |

Tổ hợp chặn đáng chú ý (tổng ≥ 100 với một request hợp lệ): không tìm thấy trên corpus benign; các rule 50 điểm cần ít nhất hai dấu hiệu bất thường cùng lúc.

## CRS

Kết quả go-ftw mọi nhóm (test của rule PL1): 913 100%, 920 100% của test chạy được (92 test của rule không nhập được), 921 95,3%, 930 94,2%, 931 100%, 932 100%, 933 99,7%, 934 100%, 941 99,6%, 942 100%, 944 96,0%. Nhóm 911, 922, 943 (phần lớn), 949 không nhập được (lý do trong `docs/crs-import-report.md`).

### Đã sửa khi duyệt

| Vấn đề | Sửa |
| --- | --- |
| **920540** (Unicode `\uXXXX`) được CRS tắt khi body là JSON (rule điều khiển 920539 `skip:1`), nhưng importer bỏ qua `skip`: mọi API JSON gửi `é` có thể bị chặn | Engine thêm target `body_processor` (REQBODY_PROCESSOR); importer biến `skip:N` có điều kiện trên một target một giá trị thành điều kiện phủ định trên N rule sau, hoặc bỏ các rule đó kèm lý do nếu không nói chính xác được |
| 920170 (GET/HEAD có body) thất bại 3/5 test | Lỗi của runner: go-ftw tự thêm Content-Length, test chuyển đổi thì không. Runner thêm như go-ftw; 920 không còn test thất bại |

### Kiểm tay (không có test upstream)

| Rule | Kiểm tra qua libstrata | Kết quả |
| --- | --- | --- |
| 920171 GET/HEAD có Transfer-Encoding | GET + TE: khớp; POST + TE: không | Đúng |
| 920181 CL và TE cùng có | Khớp, cùng với kiểm tra dựng sẵn 100001 (chặn riêng) | Đúng, trùng chủ ý |
| 920620 nhiều Content-Type | Hai header: khớp; một: không | Đúng |

### Khác biệt chấp nhận

| Test / rule | Lý do |
| --- | --- |
| 944100/944110/944120, 24 test `no_match` XML | `request_body` của Strata luôn là body thô (ModSecurity bỏ REQUEST_BODY khi có body processor). Giữ để rule của tổ chức thấy body XML/JSON |
| 930100-3, 930120-1..3, 933170-5 | `%00` bị kiểm tra dựng sẵn 100013 chặn trước |
| 921140-1 | Header có CR trần: NGINX trả 400 trước khi tới module, test không xảy ra được trên NGINX |
| 941180-7 | `document.cookie` trong path khớp; chấp nhận (dấu hiệu thật) |
| 943110 | So host của Referer với Host qua nhóm bắt và macro: IR không biểu diễn được |
| 930120, 942100 trên corpus benign (8,35%) | Hành vi của CRS PL1 (libinjection C gốc cho cùng kết quả). Policy cần exclusion cho field văn bản tự do |

## Điều kiện để giữ kết quả duyệt

- `make test-rules` (mẫu, báo cáo, pack protocol 0 FP) và `make test-crs-ftw` (≥ 90% mỗi nhóm injection) trong CI.
- Rule mới hoặc sửa trong `rules/protocol/` cần lượt duyệt riêng; `rules/crs/` chỉ đổi qua `make crs-import`.

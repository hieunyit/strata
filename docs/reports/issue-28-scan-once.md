# #28: body lớn — prefilter scan mỗi giá trị một lần (bước 1)

Ngày: 15/10/2026 · Nhánh: `issue-28-scan-once` · Người làm: Claude Code. Đo engine trên CPU 0–5, theo quyết định của PO ngày 14/10.

## 1. Kết luận

| | Kết quả |
| --- | --- |
| Bước 1 (nhánh này): mỗi giá trị một lượt transform theo cây chuỗi, scan một lần cho mỗi dạng byte | Engine nhanh hơn 16–52%; verdict giống hệt engine tham chiếu trên 11.590 request. **Không đổi** định dạng bundle, ABI hay C |
| Mục tiêu #28 (body ≤ 64 KB không fail-open với budget 10 ms) | **Chưa đạt**: JSON 64 KB còn khoảng 43 ms, form 64 KB với 1.024 tham số khoảng 54 ms |
| Nút thắt còn lại | Chi phí cố định của mỗi lần scan với DB 12.751 pattern (khoảng 4,5 µs mỗi lần, dù chỉ vài chục byte), và transform |
| Đề xuất bước 2 (cần PO quyết vì đổi định dạng) | §5 |

## 2. Chi phí nằm ở đâu (trước nhánh này)

Đo bằng bộ đếm tạm trong `strata-bench`, gói đầy đủ, POST form 64 KB (1.024 tham số và 1.024 tên):

| Phần | Thời gian |
| --- | ---: |
| Prefilter, tổng | 107 ms |
| scan Hyperscan (4.991 lần, 215 KB) | 26 ms |
| transform (70.940 lần áp chuỗi) | 26 ms |
| hash, clone, sort, cấp phát quanh `matched()` (136.723 lần gọi) | khoảng 55 ms |

Hình dạng gói đầy đủ:

- 102 scan group nhưng chỉ 43 chuỗi transform khác nhau (cây tiền tố 50 node) và 51 tập target.
- Giá trị ARGS nằm trong khoảng 30 tập target.
- Mỗi group liệt kê lại toàn bộ giá trị của mình, rồi tra cache bằng hash cho từng cặp (giá trị, chuỗi transform).

## 3. Thay đổi (`engine/src/eval.rs`)

- Lúc nạp bundle, `Prefilter` dựng:
  - cây tiền tố của các chuỗi transform; mỗi node là một transform áp lên byte của node cha;
  - danh sách target khác nhau và các tập target;
  - với mỗi group, các node nó đọc.
- Mỗi request (`scan_values`):
  1. Liệt kê giá trị **một lần cho mỗi target**, đánh chỉ số theo địa chỉ.
  2. Với mỗi giá trị, đi qua các node mà nó cần (node cha trước node con):
     - transform không đổi byte thì dùng lại kết quả của node cha, không scan;
     - cùng một transform trên cùng một dãy byte (`url_decode, lowercase` với giá trị không có `%` chính là `lowercase`) thì làm một lần;
     - các dạng byte giống nhau trong cả request chỉ scan một lần (`scans_by_bytes`).
  3. Kết quả nằm trong mảng phẳng: group đọc trực tiếp, không hash. Danh sách điều kiện lặp lại giữa các giá trị chỉ được thêm một lần, nên bớt sort.
- Rule được đánh giá sau đó (`matched`) đọc lại kết quả của lượt này. Cặp nào lượt này không scan thì đi đường cũ.
- Cây chuỗi không vừa id `u16` thì prefilter chạy như trước #28 (`Prefilter::trie`).

## 4. Số đo

`strata-bench`, 1 nhân (CPU 2), gói đầy đủ 9.054 rule. Chạy xen kẽ 3 lượt main và nhánh này; p50 lấy trung vị:

| Request | main | Nhánh này | |
| --- | ---: | ---: | ---: |
| GET nhỏ | 756 µs | 636 µs | −16% |
| JSON nhỏ | 1.246 µs | 654 µs | −48% |
| JSON 64 KB (bản ghi 4 field, case mới `json64k`) | 70,3 ms | 43,0 ms | −39% |
| Form 64 KB, 1.024 tham số | 112,7 ms | 53,8 ms | −52% |
| Form 1 MB (1.024 tham số + body thô) | 246,7 ms | 206,1 ms | −16% |

Sau thay đổi, JSON 64 KB còn khoảng 40 ms trong prefilter:

- scan 20 ms (1.690 lần);
- transform 8,6 ms (28 nghìn lần, trước là 56 nghìn);
- phần còn lại: liệt kê và đánh chỉ số giá trị.

Ngoài prefilter còn khoảng 13 ms cho rule không gate được (libinjection trên mọi tham số).

**Kiểm đúng/sai**:

- `prefilter_differential` có thêm các biến thể: payload trong JSON, trong cookie, và lẫn giữa 120 field form (nhiều field cùng giá trị) kèm query. Kết quả: **11.590 request, 7.706 có rule khớp, 0 khác biệt** giữa engine tham chiếu (không prefilter), engine hiện tại và engine có section 8.
- Các gate khác: §6.

## 5. Bước 2: PO cần quyết

Phần lớn chi phí còn lại là số lần scan nhân với chi phí cố định của mỗi lần scan trên DB lớn. Trong 12.751 pattern của gói đầy đủ, chỉ **2.640 (21%)** đọc ARGS. Phần lớn còn lại là pattern trên `REQUEST_URI_RAW` (6.511) và header (3.294). Tuy vậy, giá trị ARGS vẫn bị scan với toàn bộ DB.

| Phương án | Được | Mất |
| --- | --- | --- |
| A. DB Hyperscan theo **lớp giá trị**: tham số/cookie/XML, URI, header, body. Mỗi giá trị chỉ scan DB của lớp mình | Mỗi lần scan một tham số rẻ hơn. Số lần scan **không** tăng, khác với DB theo group đã bị bỏ trong prototype #27, vì mỗi giá trị chỉ thuộc một lớp | Đổi định dạng (section mới); bundle lớn hơn; compile lâu hơn. Cần prototype để đo trước khi quyết |
| B. Giới hạn số tham số được kiểm theo policy. Hiện cố định 1.024. ModSecurity có `SecArgumentsLimit`; AWS WAF chỉ kiểm 8–64 KB đầu của body | Chặn trường hợp xấu (HPP với hàng nghìn tham số) bằng cấu hình | Phần vượt giới hạn phải theo `oversize` của policy (`pass` hoặc `block`), như body vượt `strata_request_body_limit` |
| C. Thread pool cho body lớn (phase 2 trong thiết kế) | Không chiếm event loop của NGINX | Không giảm CPU; budget vẫn phải chi trả |

Ý kiến của tôi:

- Làm **A** dạng prototype sau cờ, như section 8: đo trước rồi PO mới quyết có đổi định dạng hay không.
- Làm **B** kèm, cho route API biết rõ số field tối đa.
- C để sau.

## 6. Kiểm thử

Gate cục bộ (GitHub Actions không chạy vì billing):

- `cargo test --workspace` PASS; clippy và fmt sạch.
- `prefilter_differential`: 0 khác biệt (§4).
- `make check-fixtures check-header`: PASS.
- `make test-crs-ftw`: báo cáo không đổi byte nào (96,0%).
- `make test-rules`: corpus benign 0 FP; recall không đổi (SQLi 76,3%, XSS 75,2%, CMDi 94,2%, LFI 97,4%).
- Test::Nginx 1.30.5 và 1.31.6: PASS, 587 test mỗi bản.

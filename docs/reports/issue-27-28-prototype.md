# Prototype #27/#28: định dạng Hyperscan mới, request đầu tiên (#49), test flaky (#44)

Ngày: 14/10/2026 · Nhánh: `issue-28-hs-groups` · Người làm: Claude Code (PO duyệt prototype 13/10, bench trên CPU 0–5 duyệt 14/10)

PO đã duyệt một prototype 1–2 ngày: compiler sinh section mới sau một cờ, engine đọc section đó, đo trước và sau, rồi PO mới quyết có đổi định dạng chính thức hay không. Báo cáo này đưa số đo thật để PO quyết.

## 1. Kết luận

| Việc | Kết quả | Đề xuất |
| --- | --- | --- |
| DB Hyperscan theo nhóm scan (ý tưởng ban đầu cho #28) | **Bỏ**: theo đo đạc, số lần scan tăng 9 đến 20 lần (mục 2) | Không làm |
| Section 8 `HYPERSCAN_BLOCK` (block mode cho giá trị ≤ 2 KB) | Đã làm, sau cờ `--hs-block`, mặc định tắt. Verdict giống hệt trên 9.304 request. Qua NGINX: engine nhanh hơn 10–18%, throughput +8 đến +12%, fail-open của gói đầy đủ giảm 7–41% | PO quyết có bật mặc định không (mục 4). Bật thì bundle gói đầy đủ tăng 12,8 → 21,7 MB |
| #27 (throughput phase 0–1 giảm ≤ 10%) | Từ −42% còn −37%. **Chưa đạt** | Bước tiếp theo nằm ngoài Hyperscan (mục 5) |
| #28 (body lớn đi fail-open) | Không đổi: POST 64 KB với gói đầy đủ vẫn 100% fail-open | Cần sửa cấu trúc vòng scan, không phải định dạng (mục 5) |
| #49 (request đầu tiên sau khi nạp bundle) | 36 ms → 3,4 ms (gói đầy đủ, engine) | Đã sửa, không đổi định dạng hay ABI. Phần còn lại (~1,5 ms cấp scratch) cần sửa C |
| #44 (test flaky dưới tải) | Đã sửa, test không còn phụ thuộc `sleep` | Đóng |

## 2. Vì sao bỏ DB theo nhóm scan

Đếm trên engine (gói signature 9.054 rule, 102 nhóm scan), mỗi request:

| | GET nhỏ | POST 64 KB |
| --- | ---: | ---: |
| Lần gọi `matched()` (giá trị × chuỗi transform × nhóm) | 867 | 136.723 |
| Lần scan Hyperscan hiện nay (1 DB, cache theo byte đã transform) | **71** | **4.991** |
| Nếu tách DB theo nhóm scan | 645 | 103.523 |
| Nếu tách DB theo chuỗi transform | 440 | 65.682 |

Cache theo byte đã gộp scan của mọi nhóm: cùng một chuỗi byte chỉ được scan một lần với toàn bộ pattern. Nếu tách DB theo nhóm, cùng chuỗi byte đó phải scan lại với từng DB, số lần scan tăng 9 lần (GET) đến 20 lần (64 KB). Ước tính "giảm 10 lần" trong đề xuất trước là sai, vì đã bỏ qua cache này.

Hai số đo khác:

- Mọi lần scan đều đến từ prefilter. Đánh giá điều kiện của rule chỉ dùng lại cache.
- Với POST 64 KB, Hyperscan chỉ chiếm khoảng 15% CPU (perf). Phần còn lại là bookkeeping quanh `matched()` (hash, sort, transform), detector SQLi và cấp phát. Vì vậy #28 không giải được bằng cách đổi định dạng Hyperscan.

## 3. Section 8 `HYPERSCAN_BLOCK`

Với GET nhỏ, 71 lần scan chỉ tổng cộng 1.195 byte mà vẫn tốn khoảng 1 ms. Chi phí nằm ở mỗi lần scan stream: reset stream, xử lý cuối dữ liệu trên DB 15 nghìn pattern, và khởi tạo các NFA. Block mode bỏ được phần reset và xử lý cuối dữ liệu.

**Layout và quy tắc** (`docs/design/control-file.md`):

- Cùng layout với section 7, magic `SHS1`, cùng pattern, cùng `cond_index` và cùng phiên bản Hyperscan.
- Engine từ chối bundle khi section 8 không khớp với section 7.
- Engine cũ bỏ qua kind 8, nên không cần nâng module trước khi deploy.
- Giá trị dài quá 2.048 byte vẫn dùng DB stream, có kiểm budget giữa các đoạn.
- Hai DB dùng chung scratch của mỗi thread (`strata-hs`).

**Kiểm đúng/sai**:

- `prefilter_differential` có thêm bundle thứ ba (có section 8) và các biến thể payload dài 2.047, 2.048, 2.049 và 4.200 byte. Kết quả: **9.304 request, 5.974 request có rule khớp, 0 khác biệt** giữa engine tham chiếu, engine hiện tại và engine có section 8.
- `hs_block_section.rs` kiểm:
  - layout của section;
  - verdict giống nhau ở hai phía giới hạn 2.048 byte, kể cả pattern neo cuối `$`;
  - bundle đã ký bị từ chối khi section 8 không khớp: sai index, ảnh stream đặt dưới kind 8, thiếu section 7, sai phiên bản, bytecode hỏng;
  - kind lạ vẫn được bỏ qua.
- `strata-hs`: DB stream và block dùng xen kẽ trên cùng thread cho kết quả giống nhau, kể cả khi scratch phải nới cho DB lớn hơn.
- Các test khác: `make test` (Rust, header, ABI, Test::Nginx 1.30.5 với 553 test) PASS; ASan 1.30.5 PASS; Test::Nginx 1.31.6 PASS ở lượt chạy lại (xem mục 6); clippy sạch.

**Đo engine** (`strata-bench`, 1 nhân, CPU 2, gói đầy đủ, verdict giống nhau ở mọi request):

| Request | Chỉ stream p50 | + section 8 p50 |
| --- | ---: | ---: |
| GET nhỏ | 790–1.750 µs (tùy lượt) | 715–920 µs |
| NUL | 260 µs | 221 µs |
| Attack | 978 µs | 860 µs |
| JSON | 1.037 µs | 927 µs |
| POST 64 KB | 100 ms | 96 ms |

Máy là VM và các nhân dùng chung cache L3 với soak, staging và lab. Khi máy rảnh, block mode nhanh hơn khoảng 10–15%; khi cache bị tranh, nhanh hơn tới ~40%. Trong cùng các lượt đo, block mode dao động ít hơn hẳn stream mode.

**Đo qua NGINX 1.30.5** (2 worker trên nhân 2,3, client trên 4,5; trung vị 3 lượt, stream và block chạy xen kẽ; `build/hsgroups/nginx-bench.jsonl`):

| Ô | Không module | p01 | p01 + section 8 | Gói đầy đủ | Đầy đủ + section 8 |
| --- | ---: | ---: | ---: | ---: | ---: |
| GET nhỏ, 64 kết nối, rps | 25.426 | 14.706 (−42%) | 15.925 (−37%) | 2.996 | 3.269 (+9%) |
| Thời gian engine trung bình | | 36,0 µs | 29,5 µs | 551 µs | 490 µs |
| GET nhỏ, 4 kết nối, p50 / p99 | | 585 / 1.550 µs | 618 / 1.420 µs | 2.900 / 7.550 µs | 2.610 / 6.580 µs |
| Fail-open (4 kết nối) | | 6 | 6 | 972 / 78.409 | 633 / 84.841 |
| HTTP/2, rps | 21.470 | 13.457 | 13.807 | 2.744 | 3.086 (+12%) |
| POST 64 KB, rps | 9.061 | 2.913 | 2.967 | 818 (100% fail-open) | 809 (100% fail-open) |

**Chi phí**:

- Bundle gói đầy đủ tăng từ 12,8 MB lên 21,7 MB; p01 tăng từ 284 KB lên 534 KB.
- RSS sau khi map tăng khoảng 17 MB. Bundle được mmap, nên các worker dùng chung trang.
- Compile chậm hơn khoảng gấp đôi.
- Payload ký qua Vault cũng lớn hơn: khi bật mặc định cần kiểm lại giới hạn của signer.

## 4. PO đã quyết (14/10/2026): merge và bật mặc định

Section 8 được nhận vào định dạng và `strata-compile` ghi nó mặc định (`--no-hs-block` để bỏ). Giới hạn cần theo dõi: bundle 21,7 MB so với giới hạn ký Vault 24 MiB của control plane (dư khoảng 3,5 MB).

### Phương án đã đưa PO

1. **Bật `--hs-block` mặc định** trong `strata-rules release` và trong compile của control plane?
   - Được: engine nhanh hơn 10–18%, ít fail-open hơn với gói đầy đủ, ít dao động hơn.
   - Mất: bundle lớn hơn khoảng 70% (tải về chậm hơn, MinIO tốn chỗ hơn, ký lâu hơn).
   - Ý kiến của tôi: bật cho gói signature đầy đủ (phase 2), vì fail-open giảm rõ. Với p01 thì tùy, vì chi phí nhỏ nhưng lợi ích cũng nhỏ.
2. Merge nhánh này với cờ mặc định tắt: không đổi hành vi của bundle hiện có. Đổi định dạng (thêm kind 8) chỉ có hiệu lực khi bundle có section đó.

## 5. #27 và #28: còn lại gì

- **#27**: còn −37%, mục tiêu −10%. Phần lớn chi phí nằm ngoài Hyperscan:
  - cấp phát trên đường đi của request;
  - tạo transaction và chép header (`Tx` copy host/path vào mảng cố định cho mọi request);
  - phần C.

  Đây là các bước 1 và 3 trong kế hoạch ban đầu. Cần làm trước khi xin ngoại lệ ở Gate A.
- **#28**: với 64 KB, vòng "nhóm × giá trị × chuỗi transform" gọi `matched()` 136 nghìn lần cho 5 nghìn lần scan. Cần đảo vòng lặp: transform và scan mỗi giá trị một lần, rồi phát kết quả cho mọi nhóm đọc giá trị đó. Sau đó mới đến thread pool cho body lớn như thiết kế. Không cần đổi định dạng.
- **#49 phần còn lại**: `strata_tx_new` cấp scratch Hyperscan ngay trong request đầu tiên của worker (khoảng 1,5 ms). Muốn đưa việc này ra khỏi đường đi của request thì cần một hàm warm được gọi lúc worker đổi engine, tức là sửa C và thêm ABI (minor).

## 6. Ghi chú kiểm thử

- Test::Nginx 1.31.6 (lần đầu): `022-body-hardening.t` thỉnh thoảng nhận `E_BUDGET` (mã 4) ở request đầu tiên (1 trên 6 lần chạy, mỗi lần một test khác nhau). Khi đó lab ClickHouse đang chạy 100% CPU trên cùng các nhân 6–10. Cùng nguyên nhân với #49 phần còn lại: cấp scratch ở request đầu bị tranh CPU. 1.30.5 và ASan xanh. Chạy lại cả hai bản sau khi tải giảm: **1.30.5 PASS, 1.31.6 PASS** (553 test mỗi bản).
- Lệnh đo nằm trong `build/hsgroups/` (không commit): `nginx-bench.sh`, `bench-interleaved2.txt`, `cold.txt`, `perf-*.txt`.

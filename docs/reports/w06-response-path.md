# W06-N-01 · Response path trong module NGINX

10/10/2026 · chạy lại:

- `deploy/dev/run.sh make test-nginx NGINX_VERSION=<bản>` (gồm `t/050-response.t`)
- `deploy/dev/run.sh make test-nginx-asan NGINX_VERSION=1.30.5`
- `deploy/dev/run.sh connectors/nginx/scripts/measure-resp-mem.sh <bản> 20` (bộ nhớ worker với response 50 MB)

Phạm vi theo thống nhất: **không làm phần phát hiện CCCD** (thuộc W06-R-01). Data guard được kiểm bằng matcher thử nghiệm của libstrata (`test-hooks`): che `STRATA-TEST-MASK` thành 16 dấu `*`. Bản build không có `test-hooks` chưa có matcher nào, nên `STRATA_VF_NEED_RESPONSE` không bật và filter response chỉ chuyển status + header cho libstrata.

## Kết luận theo dòng "Xong khi"

| Tiêu chí | Kết quả |
| --- | --- |
| CCCD trong JSON response bị che | **Hoãn sang W06-R-01** (detector). Đường che dữ liệu đầu–cuối đã chạy: chuỗi thử bị che qua proxy, file tĩnh, chunked, HTTP/2, kể cả khi bị cắt giữa hai buffer |
| Response gzip vẫn được inspect | **Đạt**: `gzip on` → body giải nén ra đã bị che (filter đứng trước gzip). Upstream đã nén sẵn (`Content-Encoding` khác `identity`) → bỏ qua inspect, ghi log `strata: response body compressed by the upstream (Content-Encoding: gzip), not inspected` |
| File tĩnh qua sendfile được inspect khi bật | **Đạt**: `sendfile on` + `output_buffers 2 7` → chuỗi bị che, `Content-Length` giữ nguyên |
| Response 50 MB không làm bộ nhớ tăng liên tục | **Đạt** với giới hạn mặc định: RSS worker không đổi sau 20 lần tải 50 MB (bảng dưới). Xem lưu ý về giới hạn lớn |
| ASan sạch | **Đạt**: 364 subtest dưới ASan + UBSan, không có báo cáo. Valgrind (1.30.5): 291 subtest, không có báo cáo, không có vgcore |

Toàn bộ Test::Nginx: **364/364** trên 1.30.5 và 1.31.6.

## Thiết kế đã làm

- **Module filter riêng** `ngx_http_strata_filter_module`, cùng file `.so` với `ngx_http_strata_module` (một lần gọi `auto/module` với hai tên). `ngx_module_order="ngx_http_strata_filter_module ngx_http_copy_filter_module"` đặt nó ngay trước copy filter: body filter chạy **sau** copy filter (buffer file đã vào bộ nhớ) và **trước** gzip, sub_filter, SSI. Thứ tự đã kiểm bằng test gzip.
- **Header filter**: chỉ request chính, có tx, không phải trang chặn của Strata. Gửi status + header (bỏ header đã xóa, `hash == 0`) qua `strata_tx_response_headers`. Inspect body khi verdict có `STRATA_VF_NEED_RESPONSE`, `strata_response_inspect on`, không phải `HEAD`, không nén sẵn; khi đó đặt `r->filter_need_in_memory = 1`.
- **Body filter** (theo "Quy tắc buffer"):
  - Không ghi đè buffer gốc. Khi libstrata viết lại, dữ liệu được copy sang buffer của module (lấy lại từ danh sách free nếu đủ lớn, không thì cấp từ `r->pool`), mang cờ `last_buf`, `last_in_chain`, `flush`, `sync` của buffer gốc. Buffer gốc được đánh dấu đã dùng hết, rồi gọi `strata_buf_free`.
  - Dùng `ngx_chain_update_chains` với danh sách free/busy riêng (tag của module).
  - Inspect tới `strata_response_body_limit`. Buffer chạm giới hạn: libstrata nhận phần trong giới hạn với `last=1` (trả lại phần đang giữ), phần còn lại của buffer gốc đi tiếp nguyên vẹn, kèm cờ của nó.
  - Buffer không ở bộ nhớ (không xảy ra khi có `filter_need_in_memory`): ghi WARN, trả phần libstrata đang giữ, phần còn lại của response đi tiếp không inspect. Chưa có metric (thuộc agent/metrics).
- **libstrata** (`engine/src/guard.rs`): data guard giữ lại đuôi chunk (`max_len - 1` byte) để chuỗi bị cắt giữa hai buffer vẫn bị che. Tổng độ dài không đổi; lần gọi cuối xả phần đang giữ. `strata_tx_response_body_chunk` trả buffer có thể dài hoặc ngắn hơn chunk (kể cả 0 byte); `rewritten == NULL` khi cần viết lại → `STRATA_E_INVALID`.

## Bộ nhớ worker, response 50 MB

1 worker, 20 lần tải liên tiếp sau 1 lần làm nóng. File có chuỗi thử ở đầu mỗi khối 64 KB; `masked` = số khối bị che. Đo trên 1.30.5:

| Trường hợp | `strata_response_body_limit` | Khối bị che | RSS trước → sau (KB) | Đỉnh VmHWM (KB) |
| --- | --- | --- | --- | --- |
| File tĩnh | 512k (mặc định) | 8 | 4136 → 4140 | 4140 |
| Proxy | 512k | 8 | 4056 → 4128 | 4128 |
| File tĩnh | 1m | 16 | 4232 → 4240 | 4240 |
| File tĩnh | 64m | 800 | 4156 → 4160 | **52756** |
| File tĩnh | 0 (không inspect) | 0 | 4008 → 4016 | 4016 |

Body nhận đủ 52.428.800 byte ở mọi trường hợp.

**Lưu ý: với giới hạn lớn, đỉnh bộ nhớ của một request xấp xỉ min(giới hạn, kích thước body).** Bộ nhớ không tăng dần qua các request: mọi thứ thuộc `r->pool` và được trả khi request xong. Nguyên nhân: quy tắc "đánh dấu buffer gốc đã dùng hết" trả buffer cho copy filter / upstream ngay, nên nguồn đọc tiếp trong khi bản copy còn chờ socket; danh sách free/busy chỉ tái sử dụng được khi client nhận kịp. Mặc định 512 KB giữ mức này nhỏ. Muốn bộ nhớ không phụ thuộc giới hạn thì cần giữ lại buffer gốc tới khi bản copy đã gửi xong (backpressure như `gzip`/`sub_filter`); đây là thay đổi so với "Quy tắc buffer" trong tài liệu, cần duyệt.

## Test (`connectors/nginx/t/050-response.t`, 11 case)

1. Proxy: chuỗi bị che, `Content-Length` giữ nguyên.
2. File tĩnh, `sendfile on`, buffer 7 byte: chuỗi bị cắt qua nhiều buffer, hai chuỗi liền nhau.
3. `gzip on`: che trước khi nén.
4. Upstream nén sẵn: không inspect, có log.
5. `strata_response_inspect off`.
6. Quá giới hạn: phần sau giới hạn đi nguyên.
7. Chuỗi vắt qua giới hạn: phần đã inspect được trả nguyên.
8. Upstream chunked, `proxy_buffering off`, nhiều lần đọc.
9. `HEAD`: không có body, không giữ gì.
10. Trang chặn của Strata không bị inspect.
11. HTTP/2.

ABI C test: thêm che qua 4 chunk (tổng 20 byte, đúng vị trí) và `rewritten == NULL` → `STRATA_E_INVALID`.

## Việc còn mở

- **Streaming (SSE, `proxy_buffering off`)**: data guard giữ tối đa `max_len - 1` byte cuối mỗi chunk tới chunk sau. Buffer `flush` hiện không xả phần đang giữ vì ABI chỉ có `last`. Hiện chưa ảnh hưởng (bản build thường chưa có matcher), nhưng sẽ làm chậm đuôi message SSE khi có detector ở W06-R-01. Cần bổ sung ABI cho flush, chờ duyệt.
- **Ngân sách C**: sau W06-N-01 phần C là 2125 dòng code thực (không tính dòng trống và comment), vượt mục tiêu 2.000. Trước task là 1903.

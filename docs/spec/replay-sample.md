# Mẫu traffic cho replay, định dạng 1 (W11-G2-01)

Mẫu request đã ẩn danh mà replay (W11-R-01 lõi, W13-G2-01 service) chạy lại qua engine để đo
FP/FN theo route trước khi áp dụng một thay đổi rule (`strata-overview.md` › Replay). Tài liệu
này là đặc tả chung cho bên ghi (control plane `control-plane/replay`, sau này connector ở
W12-N-01) và bên đọc (`engine/replay`, Rust).

**Quyết định PO 14/10/2026**: chỉ **field nhạy cảm** bị thay bằng hash; cấu trúc request và
giá trị thường được giữ nguyên để replay chạy được rule nội dung. Câu "chỉ giữ cấu trúc +
hash" trong `strata-overview.md` được hiểu theo nghĩa này. **Định dạng cần pháp chế duyệt
trước khi lấy mẫu traffic thật** (dòng "Xong khi" của W11-G2-01).

## 1. File

Một file Parquet cho mỗi lô mẫu, một hàng cho mỗi request. Metadata key-value của file:

| Khóa | Giá trị |
| --- | --- |
| `strata.replay.format` | `1` |
| `strata.replay.anon_key_id` | id của khóa HMAC đã dùng (mục 3); không bao giờ là khóa |

| Cột | Kiểu Parquet | Nội dung |
| --- | --- | --- |
| `ts_ms` | INT64 | thời điểm nhận request (ms Unix) |
| `node_id` | BYTE_ARRAY (UTF8) | node lấy mẫu |
| `policy` | BYTE_ARRAY (UTF8) | `strata_policy` của location |
| `method` | BYTE_ARRAY (UTF8) | |
| `raw_uri` | BYTE_ARRAY (UTF8) | URI như client gửi, đã ẩn danh (mục 2) |
| `uri` | BYTE_ARRAY (UTF8) | path đã chuẩn hóa của proxy, đã ẩn danh |
| `args` | BYTE_ARRAY (UTF8) | query string, đã ẩn danh |
| `proto` | BYTE_ARRAY (UTF8) | `HTTP/1.1`, `HTTP/2.0`... |
| `client` | BYTE_ARRAY (UTF8) | địa chỉ client **luôn** thành token (mục 3) |
| `headers` | BYTE_ARRAY (UTF8) | mảng JSON `[[tên, giá trị], ...]`, theo thứ tự đến, giữ trùng lặp, đã ẩn danh |
| `body` | BYTE_ARRAY | body đã ẩn danh, tối đa `max_body` (mặc định 64 KB) |
| `body_len` | INT64 | độ dài body gốc |
| `body_truncated` | BOOLEAN | body gốc dài hơn `max_body` |
| `action` | BYTE_ARRAY (UTF8) | verdict lúc lấy mẫu: `allow`, `log`, `block`, `error` |
| `rules` | BYTE_ARRAY (UTF8) | Rule ID khớp lúc lấy mẫu, cách nhau bằng dấu phẩy |

Đặt trong object storage (MinIO trong lab): khóa
`replay/v1/<policy>/<yyyy>/<mm>/<dd>/<node>-<ts_ms đầu>-<số thứ tự>.parquet`, metadata
`Sha256`. Hạn lưu là lifecycle của bucket (đề xuất 7 ngày, khớp "mẫu traffic 7 ngày gần
nhất"), cấu hình ở nơi triển khai.

## 2. Field nhạy cảm

Một giá trị nhạy cảm được thay **cả giá trị** bằng token; các phần khác giữ nguyên.

1. **Header** (tên không phân biệt hoa thường): `authorization`, `proxy-authorization` (giữ
   scheme: `Bearer <token>`), `cookie` (giữ tên cookie, token cho từng giá trị), `set-cookie`,
   `x-api-key`, `x-auth-token`, `x-csrf-token`, `x-xsrf-token`, `x-forwarded-for`, `x-real-ip`,
   `forwarded`, `true-client-ip`, `cf-connecting-ip`.
2. **Tham số theo tên** (query, body `application/x-www-form-urlencoded`, khóa JSON, field
   multipart; tên viết thường chứa một trong các chuỗi): `password`, `passwd`, `pwd`,
   `secret`, `token`, `otp`, `pin`, `cvv`, `card`, `cccd`, `cmnd`, `ssn`, `passport`, `apikey`,
   `api_key`, `auth`, `session`, `phone`, `mobile`, `email`, `dob`, `birth`, `name`, `user`,
   `address`, `account`, `iban`. Danh sách rộng có chủ ý (`name` cũng khớp `filename`,
   `hostname`): che dư một giá trị thường chỉ làm replay bớt chính xác, che thiếu thì lộ dữ
   liệu cá nhân (họ tên trên route eKYC).
3. **Giá trị theo dạng**, ở mọi chỗ còn lại (giá trị tham số và JSON, đoạn path, giá trị
   header, body thô): chỉ **phần khớp** được thay bằng token, phần chữ xung quanh giữ nguyên
   (payload tấn công vẫn nhìn thấy được):
   - JWT: `eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*`;
   - email: `[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`;
   - số điện thoại Việt Nam: `(\+84|84|0)(3|5|7|8|9)\d{8}`, không dính chữ số khác;
   - số CCCD: đúng 12 chữ số, không dính chữ số khác;
   - số thẻ: 13–19 chữ số (cho phép dấu cách hoặc `-` giữa các nhóm) và qua kiểm Luhn.
4. **Body**: `application/x-www-form-urlencoded` theo từng tham số (mục 2, 3);
   `application/json` đọc thành cây, giữ khóa và cấu trúc, ghi lại JSON gọn (thứ tự khóa
   giữ nguyên); `multipart/form-data` giữ header của part và field văn bản (mục 2, 3), **nội
   dung file luôn thành token** (file có thể là ảnh giấy tờ); kiểu khác (XML, thô) qua mục 3.
   JSON không đọc được thì xử lý như body thô.
5. **Client**: luôn thành token. Rule `ip_match` vì vậy không replay được.

## 3. Token

`~h:<16 ký tự hex>:<lớp><độ dài>`, ví dụ `~h:9f86d081884c7d65:d12`:

- hex: 8 byte đầu của HMAC-SHA256(khóa, giá trị gốc). Cùng giá trị cho cùng token trong một
  khóa, nên phép so bằng (ví dụ cùng một token lặp lại) vẫn còn; không đảo ngược được nếu
  không có khóa;
- lớp: `d` chỉ chữ số, `a` chỉ chữ cái ASCII, `x` chữ và số ASCII, `s` còn lại;
- độ dài: số byte của giá trị gốc.

Khóa HMAC (32 byte ngẫu nhiên) do control plane giữ, có id (`anon_key_id`), xoay được; không
bao giờ nằm cạnh mẫu. Đổi khóa thì token của cùng một giá trị đổi theo.

## 4. Vector kiểm thử

`docs/spec/examples/replay-anon-v1.json`: đầu vào, khóa thử và bản ghi mong đợi. Mọi bên
ghi (Go hôm nay, libstrata ở W12-N-01) phải cho đúng các bản ghi đó.

Thêm một corpus sinh tự động (seed cố định, 400 request: URL escape, cookie, JSON có escape và
surrogate, multipart có header lạ và dòng kết thúc `\n`, tham số media type, UTF-8 hỏng, body cắt ở
200 byte): `engine/tests/fixtures/anon-corpus-v1.json`, ghi bởi `go test ./replay -run
TestDifferentialCorpus -update` (`control-plane/replay`), mọi trường dạng byte (base64). libstrata
(`engine/src/anon.rs`, `engine/tests/anon_vectors.rs`) cho đúng từng byte của cả 400 bản ghi.

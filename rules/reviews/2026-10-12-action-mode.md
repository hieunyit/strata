# Review mức tin cậy rule (action_mode) — 2026-10-12

Nhiệm vụ W08-S-02. Người duyệt: Claude Code đóng vai người luồng S / SecOps theo
yêu cầu của PO (tiền lệ: `2026-10-11-protocol-and-crs.md`,
`2026-10-12-sigma-et-bots.md`). Mỗi rule mới hoặc sửa sau đây cần lượt duyệt riêng.

## Nguyên tắc gán

`action_mode` (W08-R-02): `block_alone` chặn request ngay khi rule khớp;
`score` chỉ cộng điểm, chặn khi tổng đạt `BLOCK_THRESHOLD` (100).

Theo plan tuần 8, **chỉ** ba nhóm được `block_alone`, còn lại `score`:

1. **Virtual patch** (`700000–799999`): bám đúng dấu hiệu khai thác một CVE cụ thể,
   `accuracy: high`, gần như không có lưu lượng hợp lệ trùng.
2. **Protocol mơ hồ**: vi phạm giao thức mà proxy và origin có thể diễn giải khác
   nhau (request smuggling) — malform chỉ kẻ tấn công tạo ra, chặn bất kể điểm.
3. **Rule độ chính xác cao**: `metadata.accuracy: high` và mẫu rất đặc hiệu.

Nhóm anomaly-scoring (CRS, Sigma, ET Open, danh sách bot) giữ `score` theo đúng
mô hình của chúng (nhiều rule cộng dồn điểm); các IR ruleset này để `action_mode`
mặc định `score` của IR (xem báo cáo W08-S-02, mục quyết định).

## Danh sách `block_alone` (14 rule) — duyệt từng rule

| Rule | Lý do | Rủi ro FP |
| --- | --- | --- |
| 700001 Log4Shell `${jndi:` | Virtual patch, accuracy high; chuỗi JNDI lookup không có trong request hợp lệ | rất thấp |
| 700002 Spring4Shell class loader | Virtual patch; `class.module.classLoader` trong tham số | rất thấp |
| 700003 Struts2 OGNL Content-Type | Virtual patch; OGNL `%{` trong Content-Type | rất thấp |
| 700004 Confluence OGNL in path | Virtual patch; OGNL trong path | rất thấp |
| 700005 PHPUnit eval-stdin | Virtual patch; đường dẫn `eval-stdin.php` | rất thấp |
| 700006 Drupalgeddon2 | Virtual patch; `#post_render`/render array | rất thấp |
| 700007 Laravel Ignition | Virtual patch; `executeSolution` | rất thấp |
| 700008 Apache double-encoded traversal | Virtual patch; `%%32%65` dạng traversal mã hóa hai lần | rất thấp |
| 700009 Citrix ADC `/vpns/` traversal | Virtual patch; path `/vpns/` + traversal | rất thấp |
| 700010 Exchange ProxyShell autodiscover | Virtual patch; `/autodiscover/...` + Email đặc hiệu | rất thấp |
| 100126 upgrade h2c smuggling | Protocol mơ hồ: `Upgrade: h2c` để tuồn request qua proxy — không dùng hợp lệ qua reverse proxy | thấp |
| 100128 Transfer-Encoding trong HTTP/1.0 | Protocol mơ hồ: TE ở HTTP/1.0 là vector smuggling; HTTP/1.0 không có chunked hợp lệ | thấp |
| 100139 TE request header lists `chunked` | Protocol mơ hồ: client gửi `Transfer-Encoding: chunked` tới proxy là dấu hiệu smuggling | thấp |
| 100011 encoded dot-segment (sample) | `accuracy: high`; `%2e%2e/` là né traversal, không dùng hợp lệ | thấp |

## Còn `score` (42 rule)

- Toàn bộ protocol pack còn lại (giới hạn độ dài, bất thường header/method, kiểm
  host...): hữu ích để cộng điểm nhưng có thể trùng lưu lượng hợp lệ hiếm gặp.
- Các sample khác (null byte 100013, web shell 400100, scanner UA 500100, admin path
  800001, too-many-args 800002): hành vi/đặc hiệu vừa, để scoring.
- Mọi rule CRS/Sigma/ET/bot: mô hình anomaly-scoring.

Kiểm chứng: `make lint-rules` 0 problems; `make test-rules` các gate 0-FP benign
vẫn 0 (action_mode không đổi số khớp); `make test-crs-ftw` giữ ngưỡng. Chi tiết số
đo trong `docs/reports/w08-s-02.md`.

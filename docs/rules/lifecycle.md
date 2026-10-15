# Quy trình nuôi rule (RV-S-02)

Rule phải được xem lại thường xuyên. Rule gây FP thì phải chỉnh, hoặc có exception có hạn.
Rule không còn khớp gì thì cân nhắc bỏ. Nguồn upstream (CRS, Sigma, ET Open, danh sách bot)
phải được nhập lại theo lịch. Tài liệu này mô tả cách làm và công cụ đi kèm.

## 1. Báo cáo hằng tuần: `strata-rules lifecycle`

```bash
cd tools/strata-rules
STRATA_CLICKHOUSE_USER=strata STRATA_CLICKHOUSE_PASSWORD=… go run . lifecycle --repo ../.. \
  --clickhouse http://127.0.0.1:28123 --policy pilot-verify,pilot-upload \
  --exclude-ips ../../deploy/staging/.state/pilot/attack-sources.txt
# chỉ đọc repo, không cần ClickHouse:
go run . lifecycle --repo ../.. --no-store
```

Báo cáo (Markdown) có bốn phần:

| Phần | Điều kiện | Việc cần làm |
| --- | --- | --- |
| Rule cần xem | Nghi FP trong shadow, đếm như `fp-report`: sự kiện `shadow`, bỏ nguồn tấn công đã biết, trong `--window` (7 ngày). Rule vào danh sách khi số nghi FP đạt **0,05% số request của policy** (ngưỡng của RV-S-01). Mẫu số lấy từ bảng `policy_requests` (RV-N-01) | Mỗi dòng gợi ý một exception có hạn 14 ngày: rule + policy + path hay gặp nhất. Nếu FP rải nhiều path thì nên chỉnh rule (như các lần chỉnh 930120, 942100, 932250, 941210, 941390, 942190) |
| Rule già | Không có sự kiện nào trong 90 ngày. Chỉ xét khi kho sự kiện có đủ 90 ngày dữ liệu | Cân nhắc bỏ, hoặc chuyển sang gói signature (chỉ ghi log). Báo cáo chỉ thấy rule đã sinh sự kiện; rule chỉ cộng điểm dưới ngưỡng thì không sinh sự kiện, nên không được đếm |
| Ngày xem lại | `metadata.review_by` đã qua | Người trong `metadata.owner` xem lại rule, rồi đặt ngày mới |
| Upstream | Phiên bản đang ghim trong `crs.lock` và `sources.lock` | Khi upstream có bản mới: nhập lại theo mục 3 |

Khi kho sự kiện chưa có `policy_requests` (module trước RV-N-01), cột request ghi "unknown",
và **mọi** rule có nghi FP đều vào danh sách, không lọc theo ngưỡng.

## 2. `owner` và `review_by`

Hai trường tùy chọn của `metadata` (`docs/spec/ir.schema.json`), thêm ngày 15/10/2026:
- `owner`: tên **nhóm** chịu trách nhiệm, không ghi tên người;
- `review_by`: ngày phải xem lại, dạng `YYYY-MM-DD`.

Rule mới của Strata (`rules/gaps/`) đặt cả hai; rule cũ được bổ sung dần. Báo cáo đếm số rule
còn thiếu, theo nguồn. Rule nhập từ upstream lấy người chịu trách nhiệm theo nguồn; importer
có thể đặt sẵn sau.

Lưu ý triển khai: compiler nhúng schema lúc build, nên compiler của tag cũ (trước PR RV-S-02)
từ chối rule có hai trường này. Gói có các trường mới chỉ deploy cùng tag mới.

## 3. Nhập lại upstream

1. Đổi phiên bản, URL và sha256 trong `crs.lock` hoặc `sources.lock`.
2. Chạy `make crs-import` hoặc `make signatures-import`.
3. Kiểm:
   - `make test-crs-ftw`: mỗi nhóm injection ≥ 90%, tổng ≥ 95%;
   - `make test-rules`: corpus benign 0 FP, recall không giảm;
   - `make mutate`: tỉ lệ lách không tăng.
4. Đọc diff của `rules/` và các báo cáo import, rồi phát hành gói theo quy trình hai lượt
   duyệt (`rules/reviews/`).

Không tự phát hành sau khi nhập lại.

## 4. Lịch chạy

`deploy/nightly/nightly.sh` (cron 19:00 UTC, `deploy/nightly/install-cron.sh`) chạy báo cáo vào
**thứ Hai**, trên ClickHouse của staging, và ghi ra `build/nightly/<ngày>/lifecycle.md`.
- `LIFECYCLE_NOW=1` chạy ngay.
- `STAGING_STATE` chỉ thư mục state của staging.
- Cron gọi `nightly.sh` từ checkout `~/strata`, nên phần này chỉ chạy khi checkout đó cập nhật
  lên `main`.

Nguồn tấn công cần loại trừ gồm container tấn công của `pilot-traffic.sh` (lệnh `sources`). Các
tấn công thử của `tests/e2e/pilot-shadow.sh` đi từ gateway của host, nên cũng xuất hiện như
"nghi FP" có 1 nguồn. Thêm IP đó vào file loại trừ, hoặc bỏ qua các dòng chỉ có 1 nguồn
trùng với giờ chạy test.

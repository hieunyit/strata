# #28: hướng tiếp theo cho body lớn (cần PO quyết)

> Historical proposal from 16/10. The owner subsequently chose measurement/optimization only; the adaptive-budget proposal below is not approved or implemented. Current fail-on-findings behavior and measurements are documented in the remediation tracker. Preserving this report does not change policy or close #28.

Ngày: 16/10/2026 · Người viết: Claude Code. PO giao ngày 16/10: "bạn thấy cái nào hợp lý nhất bạn làm".

## 1. Hiện trạng sau #85, #87, #99

Engine, 1 nhân, gói đầy đủ:

| Request | Thời gian |
| --- | ---: |
| GET nhỏ, JSON nhỏ | 0,5–0,6 ms |
| JSON 64 KB | khoảng 30 ms |
| Form 64 KB, 1.024 tham số | khoảng 40 ms |
| Form 1 MB | khoảng 165 ms |

Budget mặc định là 10 ms. GoTestWAF trên main 78702b6 có 15 request vượt budget, chủ yếu body 8–128 KB: các request đó đi theo fail mode (mặc định là cho qua).

## 2. Hai hướng PO đưa ra, và vì sao tôi không làm

| Hướng | Số đo | Kết luận |
| --- | --- | --- |
| Chuyển thêm regex CRS sang regex crate | Ngoài 932340 (đã làm ở #99), bỏ từng rule CRS khỏi Hyperscan chỉ đổi trong mức nhiễu ±10% (`issue-28-pattern-cost.md` §3). Rule chạy bằng regex crate mất gate, chạy trên mọi giá trị của mọi request | Tổng lại sẽ **đắt hơn**. Không làm |
| CRS theo route (policy bỏ nhóm PHP/Java/Windows…) | DB Hyperscan dùng chung cho mọi policy, mà scan chiếm phần lớn thời gian. Bỏ nhóm rule chỉ bớt phần đánh giá rule. Muốn DB riêng theo profile thì bundle vượt giới hạn ký Vault, như phương án A | Có ích cho FP và bảo trì, nhưng **không giải** #28. Để sau (B1+) |

Đã thử thêm: Hyperscan prefilter mode cho CRS. Không có lợi (`issue-28-pattern-cost.md` §5).

## 3. Hướng tôi đề xuất: đổi hành vi khi hết budget

Hai thay đổi trong libstrata, không thêm dòng C. Cả hai đổi một dòng của bảng fail mode trong `nginx-module.md` ("Vượt `strata_cpu_budget`"), nên cần PO duyệt.

### 3.1. Giữ các rule đã khớp trước khi hết budget (đề xuất làm ngay)

Hiện tại, khi hết budget giữa lượt đánh giá, `tx.rs` **bỏ cả các vi phạm đã tìm thấy**:

```rust
if res.is_err() {
    self.set_budget_exceeded();
} else {
    for v in found { self.add(v); }
}
```

Nghĩa là payload ở đầu một body lớn đã bị tìm thấy, nhưng request vẫn đi fail-open vì phần sau tốn quá budget. Kẻ tấn công lợi dụng được: đặt payload ở đầu, rồi đệm phía sau cho đủ đắt.

**Đề xuất**: vẫn ghi các vi phạm đã tìm thấy. Nếu chúng đủ để chặn (`block_alone` hoặc đạt ngưỡng) thì chặn, kể cả ở fail mode `open`. Nếu không đủ thì fail mode quyết định như hiện nay, và sự kiện ghi `inspection = PARTIAL`.

Chi phí bằng 0; không thêm FP mới, vì chỉ chặn bằng rule đã khớp thật.

### 3.2. Budget theo kích thước body (cần PO chọn số)

Budget cố định 10 ms bảo vệ CPU, nhưng mọi body cỡ vài chục KB với gói đầy đủ đều vượt nó. Đề xuất: budget của một request = `strata_cpu_budget` + `k` × KB body được inspect, có trần.

- Ví dụ `k = 0,5 ms/KB`, trần 100 ms: body 64 KB được 42 ms, đủ cho JSON 64 KB (30 ms).
- **Rủi ro**: kẻ tấn công gửi body lớn để ép CPU. Với trần 100 ms, mỗi worker vẫn xử lý khoảng 10 request lớn mỗi giây trong trường hợp xấu nhất. Body còn bị chặn trên bởi `strata_request_body_limit` (1 MB) và `max_args` (#87).
- So sánh: AWS WAF chỉ kiểm 8–64 KB đầu của body; Cloudflare kiểm tới 128 KB. Cả hai trả phí CPU cho phần body họ kiểm.
- Cấu hình: một directive mới (C) hoặc một trường policy (bundle); PO chọn.

### 3.3. Thứ tự đề xuất

1. Làm 3.1 ngay: sửa một chỗ trong `tx.rs`, có test, không đổi interface.
2. PO chọn `k` và trần cho 3.2, rồi làm.
3. CRS theo route: để B1+.

## 4. Đã thử thêm (22/10/2026): một database Hyperscan cho mỗi chuỗi transformation

Người dùng duyệt làm sau cờ. Nhánh `hs-chains` (không merge): section 17 `HYPERSCAN_CHAINS`, `strata-compile --hs-chains`, kèm test layout và test vi sai.

**Ý tưởng**: mỗi lần scan DB đầy đủ chạy cả các NFA đắt của CRS, kể cả trên byte của chuỗi mà các pattern đó không đọc. Một DB cho mỗi chuỗi thì byte của chuỗi nào chỉ gặp pattern của chuỗi đó.

**Thí nghiệm riêng phần scan** (`node-split-exp`: gọi `hs_scan` trên đúng các cặp (chuỗi, byte) mà engine đọc): thời gian scan của GET nhỏ giảm từ 382 µs xuống 254 µs, attack từ 370 µs xuống 204 µs.

**Trong engine** (`strata-bench`, gói đầy đủ, CPU 3, hai bundle xen kẽ):

| Bản | GET nhỏ | JSON nhỏ | Attack | Form 64 KB | JSON 64 KB |
| --- | ---: | ---: | ---: | ---: | ---: |
| Mặc định (section 8) | 608–652 µs | 628–636 µs | 588–598 µs | 38,2–38,6 ms | 26,2–32,6 ms |
| Mỗi node một DB | 683 µs | 766 µs | 654 µs | 82,0 ms | 54,7 ms |
| Lai: byte chỉ một node đọc dùng DB của chuỗi, byte chung dùng DB đầy đủ | 618 µs | 779 µs | 611 µs | 40,9 ms | 27,6 ms |

- **Mỗi node một DB**: số lần scan của GET nhỏ tăng từ 52 lên 454. Số lệnh trong `hs_scan` giảm 27%, nhưng chi phí quản lý (hash cache cho từng cặp DB và byte) và việc đổi qua lại giữa khoảng 50 DB làm tổng thời gian tăng.
- **Bản lai**: không khác biệt so với mức nhiễu, JSON nhỏ còn chậm hơn.
- **Đúng/sai**: `prefilter_differential` cho 11.590 request, 8.019 có rule khớp, 0 khác biệt.
- **Bundle**: 21,3 MB → 24,1 MB (bỏ section 8).

**Kết luận**: không merge. Lợi ích của thí nghiệm chỉ có khi tính riêng lời gọi `hs_scan`. Chi phí còn lại của #28 nằm ở số giá trị và số chuỗi transformation mỗi request, không nằm ở cách chia DB.

Phần đã merge cùng đợt (#413):
- kết quả scan dùng lại giữa các stage: GET nhỏ gói đầy đủ −14%;
- scratch nhớ nhiều DB.

Mục tiêu hiệu năng đổi sang thời gian engine: `docs/decisions/perf-targets.md`.

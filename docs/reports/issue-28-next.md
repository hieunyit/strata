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

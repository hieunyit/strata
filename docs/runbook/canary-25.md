# Kế hoạch và Quy trình Quan sát Canary 25% trong 72 giờ (Khối B2)

Tài liệu xác định cơ chế, đối tượng áp dụng, chỉ số giám sát, điều kiện dừng và quy trình tự động rollback cho giai đoạn mở rộng Canary lên **25%** lưu lượng.

> **Trạng thái Gate A và Tiền đề**:
> Theo `AGENTS.md`, việc bật Canary 25% trên môi trường Production phụ thuộc vào việc hoàn tất Gate A và kết quả ổn định của Canary 1% và 5%.
> Tài liệu này chuẩn bị đầy đủ cơ chế kỹ thuật, guardrail và dashboard giám sát. Chu kỳ quan sát 72 giờ sẽ được kích hoạt chính thức khi có xác nhận nghiệm thu Gate A.

---

## 1. Cơ chế và Đối tượng Áp dụng Canary 25%

- **Cơ chế phân bổ**:
  - Dựa trên hàm băm ổn định chuẩn của Strata (`engine/src/canary.rs`):
    $$\text{Bucket} = \text{Mix}(\text{FNV-1a}(\text{Policy} \parallel \text{0xFF} \parallel \text{Client Key})) \pmod{10000}$$
  - Trong đó `Client Key` là `Identity` (nếu có định danh người dùng) hoặc `Client IP` (địa chỉ IP kết nối thực tế).
- **Phân định đối tượng (25% = 2,500 basis points)**:
  - **Nhóm Canary 25%** ($\text{Bucket} < 2500$): Chạy ở chế độ **Enforce** (chặn các request vi phạm rule độc lập hoặc đạt ngưỡng điểm).
  - **Nhóm Baseline 75%** ($\text{Bucket} \ge 2500$): Chạy ở chế độ **Shadow** (chỉ ghi log, đánh dấu `would_block = true`, không gián đoạn người dùng).
- **Tính lũy tiến và nhất quán**:
  - Vì hàm băm là đơn điệu và cố định, mọi client từng nằm trong nhóm 1% và 5% đều tiếp tục nằm trong nhóm 25%. Không có hiện tượng client bị nhảy qua lại giữa Enforce và Shadow.

---

## 2. Cấu hình Policy Canary 25%

Cập nhật cấu hình policy trong control plane:
```json
{
  "name": "pilot-verify",
  "mode": "enforce",
  "canary_percent": 25.0,
  "oversize": "block",
  "fail_on_findings": "block"
}
```

---

## 3. Dashboard Giám sát và Chỉ số Cốt lõi (SLI/SLO)

Giám sát liên tục thông qua Prometheus / VictoriaMetrics và Grafana Dashboard:

1. **Tỷ lệ lỗi máy chủ (5xx Error Rate)**:
   - Metric: `sum(rate(nginx_http_requests_total{status=~"5.."}[5m])) / sum(rate(nginx_http_requests_total[5m]))`
   - **Ngưỡng cảnh báo**: $> 0.5\%$ trong 3 phút liên tục.
   - **Ngưỡng ngắt khẩn cấp (Emergency Trip)**: $\ge 1.0\%$.

2. **Tỷ lệ Chặn bất thường (Block Rate Surge)**:
   - Metric: `sum(rate(strata_verdict_block_total{policy="pilot-verify"}[5m]))`
   - **Ngưỡng cảnh báo**: Số lần chặn tăng đột biến $> 3\times$ baseline lịch sử.

3. **Số lượng Báo cáo False Positive**:
   - Theo dõi qua API `:markFalsePositive` và `RuleHealthMonitor`:
   - Nếu xuất hiện $\ge 5$ FP trong 5 phút trên bất kỳ rule nào $\rightarrow$ kích hoạt Auto-Quarantine cho rule đó.

4. **Độ trễ xử lý WAF (Latency Overhead)**:
   - p99 latency overhead $\le 1.0\text{ ms}$.

---

## 4. Kịch bản và Quy trình Tự động Rollback

Hệ thống hỗ trợ 3 cấp độ phòng vệ theo thứ tự ưu tiên:

1. **Cấp 1 - Tự cách ly Rule gây sự cố (Rule Auto-Quarantine)**:
   - Rule Health Monitor tự động chuyển rule bị lỗi về `quarantined_staging` (log-only) trong $< 5$ phút mà không cần rollback toàn bộ policy.
2. **Cấp 2 - Hạ tỷ lệ Canary (Canary Downgrade)**:
   - Nếu tỷ lệ lỗi 5xx vượt $0.5\%$, tự động hạ `canary_percent` về $5\%$ hoặc $1\%$.
3. **Cấp 3 - Ngắt toàn bộ về Shadow (Emergency Trip to Shadow)**:
   - Nếu tỷ lệ 5xx $\ge 1\%$ hoặc có sự cố gián đoạn nghiêm trọng, trip circuit breaker khẩn cấp:
   ```bash
   curl -X POST http://control-plane:8080/v1/groups/edge:canaryFallback \
     -H "Authorization: Bearer $OPERATOR_TOKEN" \
     -d '{"policy": "pilot-verify", "reason": "5xx rate exceeded 1% during 25% canary"}'
   ```
   - Lập tức đưa 100% lưu lượng về chế độ **Shadow**.

---

## 5. Chu kỳ Quan sát 72 Giờ

- **Mục tiêu**: Đảm bảo hệ thống vận hành liên tục qua đầy đủ các chu kỳ tải (giờ cao điểm ban ngày, đêm và chuyển giao ngày làm việc).
- **Ghi nhận mốc thời gian**:
  - Mốc bắt đầu dự kiến: Sau khi nghiệm thu Gate A và hoàn tất Canary 5%.
  - Thời lượng: 72 giờ quan sát liên tục.
  - Trạng thái hiện tại: **Đang chờ đủ điều kiện và dữ liệu quan sát** (*Waiting for data / Pending Gate A sign-off*).
- **Biên bản nghiệm thu**:
  - Không có sự cố ngắt khẩn cấp cấp 3.
  - Tỷ lệ False Positive được xác nhận $< 0.01\%$.
  - Sẵn sàng tiến tới mốc tiếp theo: **Enforce 100%**.

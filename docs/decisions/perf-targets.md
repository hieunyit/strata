# Quyết định: mục tiêu hiệu năng tính bằng thời gian engine (#27)

Ngày: 22/10/2026 · Người duyệt: người dùng (vai PO), phiên audit/hiệu năng · Người viết: Claude Code.

## Bối cảnh

Mục tiêu cũ (`nginx-module.md`, mục tiêu 2; Gate A, A2): throughput giảm không quá 10% so với NGINX không bật module, đo trên request nhỏ keep-alive.

Benchmark của mục tiêu này (`connectors/nginx/scripts/bench.sh`) dùng backend trả `200 ok` ngay trong cùng NGINX. Mỗi request mất khoảng 80 µs trên một worker. Với nền rẻ như vậy, mọi chi phí thêm vào đều thành tỉ lệ lớn.

Số đo ngày 22/10/2026, main d7c940a, 2 worker:

| | req/s tắt | req/s phase 0–1 | Δ | engine trung bình |
| --- | ---: | ---: | ---: | ---: |
| GET nhỏ | 24.825 | 12.247 | −50,7% | 45,8 µs |

Callgrind (NGINX + module, phase 0–1) cho thấy gần hết phần thêm vào nằm trong engine: khoảng 157 nghìn lệnh mỗi request, phần C khoảng 22 nghìn. Muốn đạt −10% thì engine phải xuống khoảng 8 µs, tức nhanh hơn khoảng 5 lần. Với backend thật (vài ms), cùng 46 µs chỉ chiếm vài phần trăm.

## Quyết định

Tiêu chí là **thời gian engine mỗi request**, đọc từ metrics của module:

| Chỉ số | Ngưỡng |
| --- | --- |
| GET nhỏ, phase 0–1, p99 | ≤ 100 µs |
| GET nhỏ, gói signature đầy đủ, p99 | ≤ 1 ms |
| Body 64 KB, gói đầy đủ | 0 request fail-open trong body budget (`strata_cpu_budget` + 0,5 ms/KB) |

Throughput so với NGINX không bật module vẫn có trong báo cáo, đo với backend có độ trễ thật, nhưng không là điều kiện.

## Phương án đã cân nhắc

| Phương án | Vì sao không chọn làm tiêu chí chính |
| --- | --- |
| Giữ −10%, thiết kế lại cách quét | Cần engine nhanh hơn khoảng 5 lần; việc nhiều ngày, rủi ro sai kết quả; không chắc đạt |
| Giữ %, đo với backend chậm | Kết quả phụ thuộc chọn backend; giữ làm số báo cáo |

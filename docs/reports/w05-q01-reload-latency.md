# W05-Q-01 · Latency khi đổi bundle dưới tải

Đo: `deploy/dev/run.sh make bench-reload-latency NGINX_VERSION=<bản>`
(`connectors/nginx/scripts/latency-during-reload.sh`), ngày 2026-10-11, máy dev
8 luồng CPU (WSL2, Docker), image dev.

**Cách đo**: một NGINX, 4 worker, `location` có `strata on` (10 rule mẫu có
section Hyperscan) proxy keep-alive tới backend trả 200. `wrk -t2 -c32`, khởi
động 5 giây rồi hai pha 30 giây trên cùng tiến trình NGINX:

- **steady**: chỉ có tải;
- **swaps**: cùng tải, mỗi 300 ms công bố bundle mới (ghi control file tại chỗ),
  tức khoảng 90 lần đổi bundle trong 30 giây.

| NGINX | Pha | Request | p50 | p75 | p90 | p99 | Lỗi |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 1.30.5 | steady | 1.121.939 | 758 µs | 1,15 ms | 1,87 ms | 623 ms | 0 |
| 1.30.5 | swaps (89 lần) | 1.113.771 | 762 µs | 1,15 ms | 1,84 ms | 577 ms | 0 |
| 1.31.6 | steady | 1.151.214 | 740 µs | 1,10 ms | 1,75 ms | 604 ms | 0 |
| 1.31.6 | swaps (88 lần) | 1.055.415 | 792 µs | 1,23 ms | 2,08 ms | 581 ms | 0 |

0 alert, 0 worker crash ở cả hai bản.

**Kết luận**

- Đổi bundle liên tục không làm p99 tăng: p99 ở pha swaps bằng hoặc thấp hơn pha
  steady; p50–p90 lệch dưới 0,4 ms (1.31.6 thấp hơn 6% throughput khi swap).
- p99 tuyệt đối khoảng 600 ms **không do Strata**: cùng tải lên một `location`
  không có Strata (`strata off`, trả 200 ngay) cũng cho p99 644 ms (p50 208 µs).
  Đó là đuôi của môi trường đo: 4 worker NGINX, 2 luồng wrk và Docker/WSL2
  dùng chung 8 luồng CPU, lịch của WSL2 dồn các lần trễ vài trăm ms.
- Đo lại trên máy riêng, không ảo hoá, ở W09-Q-01 (benchmark) để có p99 tuyệt
  đối dùng được cho SLO; số ở đây chỉ dùng để so hai pha với nhau.

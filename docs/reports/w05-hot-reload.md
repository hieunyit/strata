# W05-N-01 · Hot reload: thời gian chuyển, tải, syscall trong event loop

10/10/2026 · chạy lại:

- `deploy/dev/run.sh make bench-reload NGINX_VERSION=<bản>` (100 lần đổi bundle dưới tải wrk)
- `deploy/dev/run.sh make check-strace NGINX_VERSION=<bản>` (syscall của worker)

## Kết luận theo dòng "Xong khi"

| Tiêu chí | Kết quả |
| --- | --- |
| Đổi generation → mọi worker dùng bản mới trong tối đa 2 giây | **Đạt**: 100 lần đổi, 8 worker, `strata_bundle_check 1s` mặc định; tới khi **cả 8** worker báo active: p50 1.136 ms, p95 1.271 ms, max **1.709 ms** (1.30.5); p50 1.169, p95 1.259, max **1.788 ms** (1.31.6) |
| Đổi bundle 100 lần dưới tải wrk → 0 lỗi 5xx | **Đạt**: 2,93 triệu request (1.30.5) và 3,30 triệu (1.31.6), **0** response không phải 2xx/3xx, 0 lỗi socket; 800 lần giải phóng bundle cũ (100 × 8 worker), 0 alert, 0 worker crash |
| strace không thấy syscall I/O trong event loop khi không có bundle mới | **Đạt**: 5 s nhàn rỗi với `strata_bundle_check 100ms` (~50 lần timer): event loop chỉ có `epoll_wait`. Khi đổi bundle: `openat`, `fstat`, `mmap`, `madvise`, `close` (nạp) và `munmap` (bản cũ) đều ở luồng thread pool; event loop chỉ có `epoll_wait` và 2 lần ghi log |
| ASan sạch | **Đạt**: toàn bộ Test::Nginx (gồm suite reload với master + worker thật) dưới ASan + UBSan, không có báo cáo |

## Chi tiết

- Thời gian chuyển gần 1 s là do chu kỳ kiểm tra: timer `strata_bundle_check` (1 s) cộng jitter tới 25% để các worker không nạp cùng lúc; phần nạp trong thread pool (mmap + kiểm chữ ký + kiểm Hyperscan) chỉ vài ms với bundle mẫu. Muốn nhanh hơn thì giảm `strata_bundle_check` (chi phí mỗi tick chỉ là đọc bộ nhớ).
- wrk: 4 luồng, 64 kết nối keep-alive tới `location` có `strata on` và proxy keep-alive; bundle là 10 rule mẫu có section Hyperscan.
- Latency tối đa của request trong lúc đo lên tới 550–585 ms (p50 khoảng 7 ms). Máy đo có 8 luồng CPU cho 8 worker NGINX + 4 luồng wrk + công cụ đo, nên chưa tách được phần do tranh CPU với phần do lần quét đầu sau khi đổi bundle (lần đầu mỗi worker cấp scratch Hyperscan và kiểm CRC database). Đo lại trên máy riêng ở W09-Q-01 (benchmark).
- Cách đo strace: NGINX chạy dưới `strace -f` ngay từ đầu (không cần quyền ptrace thêm), các giai đoạn tách theo mốc thời gian, lọc theo PID của worker (luồng event loop) và TID của luồng thread pool.

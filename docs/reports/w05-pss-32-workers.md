# W05-R-01 · Bộ nhớ của 32 worker NGINX dùng chung một bundle

10/10/2026 · chạy lại: `deploy/dev/run.sh connectors/nginx/scripts/measure-pss.sh 1.30.5 32 <số rule>`

## Kết luận

**Đạt**: phần bundle (kể cả database Hyperscan) chỉ chiếm RAM vật lý **một lần** cho cả máy. Mỗi worker thấy gần đủ bundle trong RSS (đã quét, và `hs_alloc_scratch` đọc toàn bộ database để kiểm CRC), nhưng tổng PSS của vùng bundle trên 33 tiến trình (master + 32 worker) bằng kích thước bundle.

## Cách đo

- NGINX 1.30.5, module có libstrata + Hyperscan 5.4.2 link tĩnh; `worker_processes 32`, `listen ... reuseport`, thread pool 1 luồng.
- Bundle do `strata-compile` tạo từ N rule regex tổng hợp (cùng dạng với PoC; target `args` và `User-Agent`, transformation `url_decode_uni`, `lowercase`), database cho platform generic; master mmap bundle theo control file, worker thừa hưởng qua `fork`.
- 4.000 request qua 32 kết nối song song để mọi worker đều quét.
- Đo `/proc/<pid>/smaps` (RSS, PSS của riêng vùng map file bundle) và `smaps_rollup` (PSS, Private_Dirty của cả tiến trình) cho 33 tiến trình. Mốc so sánh: cùng cấu hình với bundle không có rule.

## Kết quả

| Bundle | Kích thước | Biên dịch | RSS vùng bundle / worker | PSS vùng bundle, tổng 33 tiến trình | PSS toàn bộ 33 tiến trình | Private_Dirty / tiến trình |
| --- | --- | --- | --- | --- | --- | --- |
| Không rule (mốc) | ~4 KB | — | 27 KB | 0 MB | 12,0 MB | 281–285 KB |
| 6.000 rule | 2,74 MB | 16 s | 2.598 KB | **2,66 MB** | 17,9 MB | 346 KB |
| 20.000 rule | 13,5 MB | 74 s | 12.768 KB | **13,2 MB** | 51,7 MB | 1.049 KB |

- Với 20.000 rule, nếu mỗi worker giữ bản riêng thì phần database sẽ tốn khoảng 33 × 13,2 ≈ 435 MB; dùng chung chỉ 13,2 MB.
- Phần riêng tăng thêm mỗi worker (Private_Dirty so với mốc): khoảng 65 KB với 6.000 rule, khoảng 0,76 MB với 20.000 rule. Chủ yếu là scratch Hyperscan (lớn dần theo database) và cấp phát của bộ đánh giá; nằm trong mục tiêu dưới 8 MB/worker của thiết kế.

## Ghi chú

- Thời gian biên dịch tăng nhanh theo số regex (74 s cho 20.000); cần theo dõi khi nhập CRS (W05-S-01) và trong compiler của control plane.
- Đo trên WSL2 (8 luồng CPU, 32 worker chạy chồng); cơ chế page cache của `MAP_SHARED` giống Linux thường, số PSS không phụ thuộc số lõi.
- Lần đầu mỗi worker quét sau khi nạp bundle, `hs_alloc_scratch` kiểm CRC toàn database (đọc 13 MB, khoảng vài ms), một lần cho mỗi bundle.

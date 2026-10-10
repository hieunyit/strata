# PoC: database Hyperscan dùng trực tiếp từ vùng mmap chỉ đọc

10/10/2026 (bổ sung phần độ bền và platform cùng ngày) · mã nguồn: `engine/poc/hs_mmap/` · chạy lại: `deploy/dev/run.sh make poc`

## Kết luận

**Được.** Database Hyperscan ở dạng in-memory (ảnh do `hs_deserialize_database_at` tạo ra trong buffer căn lề 4 KB) dùng được trực tiếp từ `mmap(PROT_READ, MAP_SHARED)` ở **địa chỉ khác nhau giữa các tiến trình**, cho cả chế độ block lẫn streaming, với kết quả match giống hệt bản deserialize riêng. Hyperscan không ghi vào vùng database khi `hs_alloc_scratch`, `hs_scan`, `hs_open_stream` / `hs_scan_stream` / `hs_close_stream` (vùng map `PROT_READ`, không có SIGSEGV).

Hệ quả cho thiết kế: section Hyperscan **có thể nằm chung** trong vùng bundle mmap dùng chung; không cần phương án dự phòng "deserialize riêng mỗi worker". RAM cho Hyperscan tính một lần cho cả máy, mỗi worker chỉ tốn scratch.

## Môi trường

| Mục | Giá trị |
| --- | --- |
| Hyperscan | 5.4.2 (gói `libhyperscan-dev` của Ubuntu 24.04), database báo `Features: AVX512VBMI` |
| CPU | Intel Core i7-1185G7, 8 luồng, x86_64 |
| Kernel | 6.18 (WSL2) |
| Bộ pattern | 6.000 regex tổng hợp kiểu CRS (alternation không phân biệt hoa thường, lớp ký tự, lặp có giới hạn, `.{0,64}` với `(?s)`, literal), `HS_FLAG_SINGLEMATCH` |
| Database | block 6.450.040 byte, stream (`HS_MODE_SOM_HORIZON_SMALL`) 3.427.512 byte; tổng 9.648 KB |
| Corpus | 4 MB dữ liệu giả ngẫu nhiên có cài sẵn chuỗi khớp; stream quét theo khối 8 KB như thiết kế |
| Thời gian biên dịch | 25,4 s (block), 14,6 s (stream) |

## Cách làm

1. Biên dịch, `hs_serialize_database`, rồi `hs_deserialize_database_at` vào buffer `posix_memalign(4096)`; ghi buffer này ra `*.img` (mô phỏng một section bundle căn lề 4 KB).
2. **Kiểm tra tính đúng** (`check`): 8 tiến trình con, mỗi tiến trình `mmap` `block.img` và `stream.img` với hint địa chỉ khác nhau (căn trang nhưng không căn 64 KB), cấp scratch, quét corpus ở block và stream mode, so số match với bản `hs_deserialize_database` riêng.
3. **Đo bộ nhớ** (`bench`): N tiến trình cùng sống (barrier hai pha), đọc mọi trang database (trường hợp xấu nhất: toàn bộ db thường trú), đo `/proc/self/smaps`: PSS cả tiến trình, Private_Dirty, RSS/PSS riêng vùng map database. Ba chế độ: `none` (không nạp, làm mốc), `private` (mỗi worker `hs_deserialize_database` một bản), `shared` (mmap ảnh `.img`).

## Kết quả

**Tính đúng** — 8/8 tiến trình khớp 872/872 match ở cả block và stream:

```
proc 0: block db at 0x6f0100007000 -> 872, stream db at 0x6f0140007000 -> 872 OK
proc 1: block db at 0x6f020000e000 -> 872, stream db at 0x6f024000e000 -> 872 OK
...
proc 7: block db at 0x6f0800038000 -> 872, stream db at 0x6f0840038000 -> 872 OK
check: all processes matched
```

**Bộ nhớ** (tổng PSS của N worker; trừ mốc `none` để ra phần do Hyperscan):

| Chế độ | N | Tổng PSS | Phần do Hyperscan | Private_Dirty / worker | PSS vùng db / worker | Thời gian nạp tối đa |
| --- | --- | --- | --- | --- | --- | --- |
| none | 1 / 8 / 16 | 2,4 / 4,8 / 5,7 MB | — | 48 KB | — | — |
| private | 1 | 16,5 MB | 14,1 MB | 12,7 MB | — | 13 ms |
| private | 8 | 107,8 MB | 103,0 MB | 12,7 MB | — | 42 ms |
| private | 16 | 210,1 MB | 204,4 MB | 12,7 MB | — | 92 ms |
| shared | 1 | 13,7 MB | 11,3 MB | 476 KB | 9.648 KB | 0,5 ms |
| shared | 8 | 19,0 MB | 14,2 MB | 480 KB | 1.205 KB | 1,8 ms |
| shared | 16 | 23,1 MB | 17,4 MB | 480 KB | 602 KB | 4,5 ms |

- Shared: vùng database tính **một lần** (9,4 MB) bất kể số worker; PSS vùng db mỗi worker = 9.648 KB / N đúng như lý thuyết. Phần riêng mỗi worker ≈ 476 KB, gần bằng scratch (433.792 byte cho hai database).
- Private: mỗi worker tốn ≈ 12,7 MB và tăng tuyến tính. 3 MB vượt quá kích thước db là do glibc giữ lại buffer serialized đã free; chạy với `MALLOC_MMAP_THRESHOLD_=131072` thì Private_Dirty còn 10.128 KB ≈ db + scratch.
- Ngoại suy theo ví dụ trong thiết kế (engine 64 MB, 128 worker): private ≈ 8 GB, shared ≈ 64 MB + 128 × scratch.

## Ràng buộc rút ra cho định dạng bundle và compiler

1. **Bundle chứa ảnh in-memory, không chứa output `hs_serialize_database`.** Hai dạng cùng kích thước nhưng khác nhau ở khoảng 1,6 triệu / 6,45 triệu byte (block); dạng serialized không quét trực tiếp được. Compiler phải chạy `hs_deserialize_database_at` vào buffer căn lề rồi mới ghi vào bundle.
2. **Căn lề**: section bắt đầu ở offset bội số 4 KB trong file (đã có trong thiết kế), để mọi địa chỉ map giữ nguyên căn lề như lúc tạo ảnh. Chưa thử ảnh tạo ở buffer chỉ căn 16 byte rồi map ở địa chỉ căn trang: không cần, vì compiler luôn tạo ảnh ở buffer căn trang.
3. **Phiên bản Hyperscan phải khớp tuyệt đối** giữa compiler và libstrata trên node (ảnh in-memory phụ thuộc phiên bản; `hs_scan` trả `HS_DB_VERSION_ERROR` khi lệch — xem mục "Database hỏng"). Header bundle nên ghi phiên bản Hyperscan; libstrata từ chối bundle lệch phiên bản thay vì quét.
4. **Platform đích**: database biên dịch với `platform = NULL` mang tính năng CPU của máy biên dịch (ở đây AVX512VBMI). Compiler phải biên dịch cho một `hs_platform_info_t` mà mọi node hỗ trợ (ví dụ `cpu_features = 0` + `tune` chung, hoặc một bản theo từng lớp CPU), và ghi platform vào header bundle.
5. Đọc trước toàn bộ section bằng `madvise(MADV_WILLNEED)` như thiết kế; nạp kiểu shared chỉ là `mmap` nên dưới 5 ms ngay cả với 16 worker, so với 13–92 ms khi deserialize riêng.

## Database hỏng hoặc lệch phiên bản/platform (lệnh `robust`)

Quét thử trên bản sao của `block.img` đã bị sửa, mỗi lần chạy trong một tiến trình con để quan sát crash:

| Thay đổi | Kết quả |
| --- | --- |
| Không đổi | quét được |
| Magic sai | `HS_INVALID` |
| Phiên bản trong header sai | `HS_DB_VERSION_ERROR` |
| Platform đòi tính năng CPU không có | `HS_DB_PLATFORM_ERROR` |
| 16 byte ngẫu nhiên trong bytecode bị đổi, scratch cấp **trên chính bản hỏng** | 200/200 lần `HS_INVALID` khi `hs_alloc_scratch`, không crash |
| Như trên nhưng scratch cấp **trên bản còn nguyên**, rồi mới quét bản hỏng | **17/200 crash (SIGSEGV)**, 183/200 "quét được" với kết quả không đảm bảo |

Hyperscan chỉ kiểm CRC của bytecode trong `hs_alloc_scratch` (và lúc deserialize); `hs_scan` chỉ kiểm magic, phiên bản, platform. Hệ quả:

6. **Lúc nạp bundle phải gọi `hs_alloc_scratch` (hoặc kiểm CRC) trên chính vùng đã mmap**, sau khi kiểm chữ ký, để bắt section hỏng trước khi đổi engine.
7. **File bundle đang được map không bao giờ được sửa tại chỗ.** `MAP_SHARED` (và cả `MAP_PRIVATE` với trang chưa bị copy) thấy ngay mọi lần ghi vào file; một lần ghi đè giữa chừng có thể làm worker crash, truncate thì gây SIGBUS. Thiết kế đã có ghi file tạm → `fsync` → `rename` và tên file theo phiên bản; cần thêm: agent không bao giờ mở file bundle đã công bố để ghi, chỉ xóa bằng `unlink` (inode còn sống tới khi worker `munmap`), và quyền file chỉ cho agent ghi.

## Platform đích: generic so với native (lệnh `platform`)

Cùng 6.000 pattern, biên dịch cho platform của máy (`hs_populate_platform`, cpu_features `0x1c`) và cho platform generic (`cpu_features = 0`, `HS_TUNE_FAMILY_GENERIC`):

| Platform | Kích thước db | Quét block (4 MB × 10), 4 lần đo |
| --- | --- | --- |
| native | 6.450.040 byte | 531, 409, 338, 232 MB/s |
| generic | 6.103.096 byte | 494, 381, 333, 258 MB/s |

Mỗi cặp số đo cùng lúc. Chênh lệch giữa native và generic trong từng cặp (−7% đến +11%) nhỏ hơn nhiều so với dao động giữa các lần đo (máy là laptop chạy WSL2, xung nhịp thay đổi), nên trên máy này **không đo được khác biệt đáng kể**. Database generic nhỏ hơn 5%. Một bundle generic dùng được cho mọi node x86_64 là lựa chọn mặc định hợp lý; nếu cần bản theo lớp CPU thì quyết định sau khi benchmark trên máy chuyên dụng.

## Chưa kiểm tra (cần làm tiếp)

- **Vectorscan trên aarch64**: PoC mới chạy Hyperscan 5.4.2 trên x86_64. Cần chạy lại cùng PoC với Vectorscan trên máy ARM trước khi chốt cho ma trận aarch64.
- Bộ pattern thật (CRS biên dịch qua IR) thay cho pattern tổng hợp; kích thước db và thời gian biên dịch có thể khác nhiều.
- Chạy trên Linux bare-metal (số liệu này đo trong WSL2; cơ chế page cache của `MAP_SHARED` giống nhau nhưng nên xác nhận lại).
- Liên kết tĩnh Hyperscan vào `libstrata.a` / `ngx_http_strata_module.so` (chưa làm ở giai đoạn stub).

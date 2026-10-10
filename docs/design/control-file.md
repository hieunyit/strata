# Control file và định dạng bundle v1 (đặc tả byte)

Bổ sung chi tiết cho mục "Bundle & hot reload" của `nginx-module.md`; tài liệu đó không cố định layout byte. Mọi số nguyên là little-endian.

## Control file (`strata_control_file`, mặc định `/run/strata/control`)

File đúng 4.096 byte, nằm trên tmpfs. Chỉ `strata-agent` được ghi; mỗi worker NGINX mmap file này (`PROT_READ`, `MAP_SHARED`) một lần lúc khởi động và từ đó chỉ đọc bộ nhớ.

| Offset | Kiểu | Trường |
| --- | --- | --- |
| 0 | `u8[8]` | magic `STRCTL1\0` |
| 8 | `u32` | phiên bản layout = 1 |
| 12 | `u32` | dự phòng, 0 |
| 16 | `u64` | **generation** (seqlock: lẻ = đang ghi, chẵn = ổn định) |
| 24 | `u64` | phiên bản bundle (thông tin; phiên bản có hiệu lực là trong header bundle đã ký) |
| 32 | `u8[32]` | sha256 của file bundle (agent kiểm; worker không kiểm, worker kiểm chữ ký) |
| 64 | `u16` | độ dài tên file, 1..255 |
| 66 | `u8[256]` | tên file bundle trong `strata_bundle_dir`, chỉ gồm `[A-Za-z0-9._-]`, không phải `.` hay `..` |
| 322 | — | dự phòng, 0 (sau này: cờ force-shadow theo policy) |

**Agent ghi (seqlock)**, luôn **tại chỗ** trên cùng inode:

1. Ghi generation = G+1 (lẻ).
2. Ghi các trường còn lại.
3. Ghi generation = G+2 (chẵn).

Không bao giờ thay control file bằng `rename`: worker đang map inode cũ và sẽ không thấy bản mới. Tạo file lần đầu (generation chẵn) rồi chỉ cập nhật tại chỗ.

**Worker đọc**: đọc generation g1; nếu lẻ thì bỏ qua lượt này; copy các trường; đọc lại generation g2; chỉ dùng khi g1 == g2. Generation chẵn khác lần trước → nạp bundle mới.

## Bundle v1 (`bundle-<version>.sbn` trong `strata_bundle_dir`)

| Offset | Nội dung |
| --- | --- |
| 0 | header 64 byte: magic `STRBNDL\0`, `u16` format = 1, `u16` flags (bit 0: ROLLBACK), `u32` số policy, `u64` version, `u64` created_at (ms), `u64` offset section, `u64` độ dài section, 16 byte dự phòng = 0 |
| 64 | bảng policy: mỗi policy 64 byte = tên 56 byte (`[a-z0-9._-]`, 1..55 ký tự, đệm NUL) + `u8` mode (0 = shadow, 1 = enforce) + 7 byte dự phòng = 0 |
| bội số 4.096 | section (rule; hiện vẫn là stub) |
| cuối − 64 | chữ ký Ed25519 trên toàn bộ byte phía trước |

libstrata kiểm chữ ký **trước** rồi mới đọc layout, và kiểm biên mọi trường kể cả khi chữ ký đúng. Mode của policy là dữ liệu đã ký: `strata_engine_policy` đọc nó tại chỗ trong vùng mmap. Location đặt `strata_request_body_mode stream` mà policy là enforce thì `nginx -t` (và `nginx -s reload`) lỗi; nếu policy chuyển sang enforce qua hot reload, worker ghi cảnh báo và location vẫn chạy shadow. File bundle đã công bố không bao giờ được sửa tại chỗ (xem `docs/poc/hyperscan-mmap.md`): agent ghi file tạm → `fsync` → `rename` sang tên mới theo phiên bản, rồi mới cập nhật control file; xóa bundle cũ chỉ bằng `unlink`.

## Quy tắc nạp trong worker

- Timer mỗi `strata_bundle_check` (cộng jitter ngẫu nhiên tới 25%) chỉ đọc generation trong bộ nhớ.
- Generation đổi → gửi việc sang thread pool `default`: `open`, `fstat`, `mmap(PROT_READ, MAP_SHARED)`, `madvise(MADV_WILLNEED)`, `strata_engine_map` (kiểm chữ ký), so phiên bản. Mỗi worker chỉ có tối đa một việc nạp đang chạy.
- Từ chối khi: chữ ký hoặc layout sai, hoặc version **nhỏ hơn hoặc bằng** bản đang chạy mà bundle không có cờ ROLLBACK. Bản bị từ chối được `munmap` ngay trong thread; worker giữ engine cũ và không thử lại cho tới khi generation đổi.
- Đổi engine trong event loop. Request đang chạy giữ tham chiếu tới bundle cũ; bundle cũ được `strata_engine_release` + `munmap` (trong thread pool) khi tham chiếu cuối được trả.
- Control file chưa có lúc worker khởi động: worker thử mở lại ở mỗi chu kỳ timer (trong thread pool) và chạy theo `strata_fail_mode` cho tới khi có bundle.
- Master đọc control file khi đọc cấu hình và mmap bundle hiện hành; worker thừa hưởng qua `fork`. Chữ ký sai → `nginx -t` lỗi; chưa có control file hoặc bundle → cảnh báo, chạy theo fail mode.

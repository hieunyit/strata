# Quyết định: ring buffer cho sự kiện

Ngày: 13/10/2026
Nhiệm vụ: W09-Q-01. Plan yêu cầu đo chi phí event socket ở khoảng 50.000 sự kiện/giây
rồi quyết định có làm ring buffer hay không. Người quyết: Claude Code, theo quyền tự
quyết kỹ thuật PO đã giao.

## Bối cảnh

Theo `docs/design/nginx-module.md` (mục "Giao diện gửi sự kiện"):

- **v1** gửi mỗi sự kiện thành một datagram Unix, bằng `sendto(MSG_DONTWAIT)`. Socket
  đầy thì bỏ sự kiện và tăng bộ đếm `strata_events_dropped`.
- **Ring buffer** `/dev/shm` theo từng worker là phương án ứng viên. Nó vào v1 chỉ khi
  ở mức khoảng 50.000 sự kiện/giây mỗi node, benchmark cho thấy một trong hai điều:
  - số sự kiện bị bỏ **vượt 0,1%**; hoặc
  - `sendto()` chiếm **hơn 5% CPU worker**.

  Nếu không, ring buffer để v1.1.

Module chỉ tạo sự kiện cho request bị chặn, request lẽ ra bị chặn khi ở shadow
(Event ID `EVT-`), và request lỗi (fail mode, vượt budget). Request sạch hoặc chưa tới
ngưỡng không có sự kiện. Vì vậy 50.000 sự kiện/giây là tình huống bị tấn công dồn dập,
không phải tải bình thường.

## Cách đo

Máy đo:

- i7-1185G7: 4 nhân vật lý, mỗi nhân 2 luồng; WSL2; NGINX 1.30.5, 2 worker.
- Nhân 0–1 chạy fuzz 72 giờ của W08-R-01.

Có hai phép đo, để tách chi phí socket khỏi chi phí kiểm tra request.

1. **Riêng event socket** (`connectors/nginx/scripts/bench-events.sh`).
   - Phía gửi: 2 tiến trình đóng vai 2 worker, gửi đúng cách module gửi (`sendto`,
     `MSG_DONTWAIT`, sự kiện 196 byte, cỡ một sự kiện shadow của request nhỏ).
   - Phía nhận: listener và decoder thật của agent (`agent/cmd/strata-eventsink`,
     dùng `internal/eventsock`), ghim riêng một nhân.
   - Đo theo tốc độ tổng cố định, mỗi mức 10 giây.
2. **Qua NGINX** (`bench.sh small events`).
   - Location ở `strata_mode shadow`, mỗi request vượt ngưỡng (byte NUL, rule 100013)
     nên mỗi request sinh một sự kiện.
   - Đếm lệnh CPU mỗi request bằng `perf stat`. Số lệnh không phụ thuộc
     hyperthreading hay turbo.

## Kết quả

### Riêng event socket

Với `net.unix.max_dgram_qlen` = 512 (mặc định của kernel):

| Tốc độ tổng | Bị bỏ | Ghi chú |
| ---: | ---: | --- |
| 10.000/s | 2,85% | toàn bộ là `EAGAIN` ở phía gửi; phía nhận không mất gì |
| 25.000/s | 24,2% | |
| 50.000/s | 37,9% | |

Với `net.unix.max_dgram_qlen` = 8.192:

| Tốc độ tổng | Bị bỏ | CPU phía gửi mỗi sự kiện |
| ---: | ---: | ---: |
| 10.000/s | 0% | 7,9 µs |
| 25.000/s | 0,093% | 4,7 µs |
| **50.000/s** | **0%** | **3,2 µs** |
| 100.000/s | 7,5% | 4,6 µs |

Phía nhận (một goroutine, decode protobuf) đạt tối đa khoảng 92.000 sự kiện/giây.

CPU mỗi sự kiện đo bằng rusage của cả tiến trình gửi, gồm cả vòng lặp hẹn giờ của Go.
Ở tốc độ thấp, chi phí cố định của vòng lặp chia cho ít sự kiện nên con số cao hơn.

### Qua NGINX: lệnh CPU mỗi request

| Mode | Lệnh user | Lệnh kernel |
| --- | ---: | ---: |
| Không module | 27 nghìn | 46 nghìn |
| Bundle phase 0–1 | 147 nghìn | 48 nghìn |
| Phase 0–1, shadow, mỗi request một sự kiện | 193 nghìn | 66 nghìn |

Phần tăng thêm của ca có sự kiện so với phase 0–1:

- **Phát hiện**: phần lớn lệnh user tăng thêm. Request của ca này có thêm tham số và
  khớp rule, nên quét Hyperscan và cấp phát nhiều hơn.
- **Mã hóa sự kiện** (`encode_event`): khoảng 3,3 µs mỗi sự kiện. Đo riêng bằng
  `strata-bench --only nul --event`: 14,6 µs so với 11,3 µs khi không mã hóa.
- **Kernel**: khoảng 19 nghìn lệnh mỗi sự kiện, gồm `sendto` và
  **phân giải lại đường dẫn socket ở mỗi lần gửi** (`__d_lookup_rcu`,
  `inode_permission`). Lý do: module gửi lên một socket chưa `connect()`.

## Đối chiếu với ngưỡng của tài liệu thiết kế

- **Bị bỏ > 0,1%?**
  - Với cấu hình mặc định (hàng đợi 512): **có**, ngay từ 10.000 sự kiện/giây. Một lần
    phía nhận khựng khoảng 50 ms (GC, lập lịch) là đủ làm đầy hàng đợi.
  - Với hàng đợi 8.192: **không**, 0% ở 50.000/s.

  Nguyên nhân bỏ sự kiện là độ sâu hàng đợi của kernel, không phải cơ chế datagram.
  Ring buffer cũng sẽ gặp đúng vấn đề này nếu kích thước ring không đủ.
- **`sendto` > 5% CPU worker ở 50.000/s mỗi node?**
  - Mỗi sự kiện tốn khoảng 3 µs, nên 50.000/s cần khoảng 0,15 nhân CPU cho cả node.
  - Node 2 worker như máy đo: khoảng 7,5% mỗi worker, **vượt nhẹ**.
  - Node 8 worker: khoảng 2% mỗi worker, **không vượt**.
  - Syscall trên WSL2 đắt hơn Linux thật, nên số này là cận trên.

## Quyết định

1. **v1 giữ Unix datagram socket.** Ring buffer `/dev/shm` để v1.1, giữ nguyên interface
   `strata_event_sink_t`. W17-N-01 ghi: "để v1.1", trừ khi phép đo lại ở bước 4 cho kết
   quả khác.
2. **Bắt buộc `net.unix.max_dgram_qlen ≥ 8192` trên node.**
   - Gói cài (W10-N-01) thêm `/etc/sysctl.d/90-strata.conf`.
   - Agent đọc `/proc/sys/net/unix/max_dgram_qlen` lúc khởi động và cảnh báo
     (log + metric) khi thấp hơn.
   - Runbook ghi bước này.
   - Không có thiết lập này thì node bỏ sự kiện ngay cả ở tải vừa phải. Đây là lỗi vận
     hành, không phải giới hạn thiết kế.
3. **Gửi qua socket đã `connect()`** (`send` thay vì `sendto`, nối lại khi agent khởi
   động lại).
   - Bỏ được phần phân giải đường dẫn ở mỗi lần gửi.
   - Đổi nhỏ trong `ngx_http_strata_events.c`; làm cùng W10-N-01 hoặc W17-N-01, kèm số
     đo trước/sau.
4. **Đo lại trên Linux thật** khi có VM staging hoặc production (W10): cùng
   `bench-events.sh` và `bench.sh small events`.
   - Nếu `sendto` vẫn chiếm hơn 5% CPU mỗi worker ở 50.000/s với số worker thực tế,
     hoặc vẫn bỏ hơn 0,1% khi đã đặt sysctl, thì đưa ring buffer vào v1 (W17-N-01).

## Cách chạy lại

```bash
make bench NGINX_VERSION=1.30.5        # gồm bench.sh small events
deploy/dev/run.sh connectors/nginx/scripts/bench-events.sh 10 2 10000 25000 50000 100000
STRATA_DEV_DOCKER_ARGS="--sysctl net.unix.max_dgram_qlen=8192" \
  deploy/dev/run.sh connectors/nginx/scripts/bench-events.sh 10 2 10000 25000 50000 100000
```

## Đo lại trên Linux thật (13/10/2026)

Máy: VM Xeon E5-2696 v4 2,2 GHz. Chi tiết ở `docs/reports/w09-q-01.md`, mục 7.

- Đặt `max_dgram_qlen` = 8.192, ở 50.000 sự kiện/giây vẫn **bỏ 5,2%**. Như vậy điều kiện
  "bỏ hơn 0,1% dù đã đặt sysctl" đã xảy ra trên máy này.
- Nhưng phía nhận mới là nút thắt: một goroutine của agent chỉ đọc và decode được
  khoảng 47.000 sự kiện/giây trên nhân 2,2 GHz. Ring buffer bộ nhớ chung không làm phía
  nhận nhanh hơn, nó chỉ bỏ được syscall ở phía gửi.
- Network namespace mới có `max_dgram_qlen` = 10, nên container phải tự đặt sysctl.

Quyết định cập nhật:

1. **Chưa chuyển sang ring buffer.** Trước tiên làm phía nhận của agent nhanh hơn:
   - nhiều goroutine cùng đọc socket;
   - `SO_RCVBUF` lớn hơn;
   - decode tách khỏi vòng đọc.

   Sau đó đo lại bằng `make bench-events`.
2. Nếu sau bước 1, ở 50.000/s vẫn bỏ hơn 0,1%, hoặc `sendto` vẫn chiếm hơn 5% CPU của
   worker, thì ring buffer vào v1 (W17-N-01), như điều kiện ban đầu.
3. Sysctl (8.192) là bắt buộc, kể cả trong container. Phần này thuộc #29 và W10-N-01.

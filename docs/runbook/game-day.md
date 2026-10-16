# Kế hoạch và Kịch bản Diễn tập Sự cố Game Day (W14-Q-01)

Tài liệu quy định kế hoạch diễn tập sự cố có kiểm soát (Chaos Engineering) nhằm kiểm chứng khả năng chịu lỗi, độ bền bỉ và tính sẵn sàng của WAF Data Plane trong các tình huống thảm họa hạ tầng.

> **QUY TẮC AN TOÀN BẮT BUỘC**:
> 1. Tuyệt đối **KHÔNG** tiêm lỗi trên môi trường Production hoặc hạ tầng dùng chung khi chưa có phê duyệt bằng văn bản từ Ban Giám đốc Kỹ thuật.
> 2. Diễn tập chỉ được phép thực hiện trên môi trường **Staging** hoặc **Lab** cô lập.
> 3. Luôn chỉ định một Kỹ sư An toàn (Safety Commander) có quyền kích hoạt lệnh dừng khẩn cấp (Abort) bất kỳ lúc nào.

---

## 1. Ma trận 5 Kịch bản Diễn tập

| STT | Tình huống lỗi | Hành vi mong đợi của Data Plane | Mức độ nghiêm trọng | Thời gian phục hồi mục tiêu (MTTR) |
| --- | --- | --- | --- | --- |
| 1 | **Control Plane ngừng hoạt động** | NGINX tiếp tục xử lý và chặn/cho qua traffic bình thường dựa trên Bundle SHM hiện hữu | P2 (Degraded Admin) | 0s gián đoạn Data Plane |
| 2 | **Agent ngừng hoạt động** | NGINX tiếp tục phục vụ; sự kiện đọng trong socket queue; NGINX không treo | P2 (Telemetry Loss) | < 30s sau khi restart Agent |
| 3 | **Bundle SHM bị lỗi / hỏng** | Fallback về bundle hợp lệ trước đó hoặc xử lý an toàn theo `strata_fail_mode` | P1 (Data Plane Risk) | < 5s fallback |
| 4 | **Panic trong libstrata engine** | `catch_unwind` cô lập panic, trả về mã lỗi an toàn; worker không bị crash | P0 (Crash Risk) | Tức thì (0 crash) |
| 5 | **Mất kết nối mạng (Network Partition)** | Node WAF hoạt động độc lập (offline autonomy); tự kết nối lại khi có mạng | P2 (Split Brain) | < 10s sau khi mạng hồi phục |

---

## 2. Chi tiết Kịch bản 1: Control Plane ngừng hoạt động

- **Tiền điều kiện (Preconditions)**: Staging đang nhận traffic ổn định; NGINX đã nạp bundle phiên bản mới nhất.
- **Cách tiêm lỗi (Fault Injection)**:
  ```bash
  docker compose -f deploy/staging/compose.yaml stop control-plane
  ```
- **Hành vi mong đợi (Expected Result)**:
  - NGINX proxy tiếp tục nhận request và áp dụng policy WAF bình thường.
  - Các request tấn công vẫn bị chặn 100%. Các request hợp lệ được proxy về backend.
  - Agent ghi nhận cảnh báo mất kết nối gRPC/HTTP tới Control Plane (`connection refused`), tự động retry theo thuật toán exponential backoff.
- **Thời gian chờ (Timeout)**: 5 phút.
- **Điều kiện dừng khẩn cấp (Abort Condition)**: NGINX trả về mã lỗi 502/503 trên 1% lưu lượng.
- **Phục hồi (Recovery)**:
  ```bash
  docker compose -f deploy/staging/compose.yaml start control-plane
  ```

---

## 3. Chi tiết Kịch bản 2: Strata Agent ngừng hoạt động

- **Tiền điều kiện**: Hệ thống đang sinh sự kiện WAF đều đặn.
- **Cách tiêm lỗi**:
  ```bash
  kill -STOP $(pgrep strata-agent) || docker compose -f deploy/staging/compose.yaml pause agent
  ```
- **Hành vi mong đợi**:
  - NGINX gửi sự kiện vào UNIX domain socket ở chế độ non-blocking (`MSG_DONTWAIT`).
  - Khi buffer socket đầy, NGINX tăng bộ đếm drop sự kiện (`strata_events_dropped_total`), tuyệt đối **KHÔNG** làm chậm hoặc treo luồng xử lý HTTP của NGINX.
- **Thời gian chờ**: 3 phút.
- **Điều kiện dừng**: Độ trễ p99 của NGINX tăng quá 5 ms.
- **Phục hồi**:
  ```bash
  kill -CONT $(pgrep strata-agent) || docker compose -f deploy/staging/compose.yaml unpause agent
  ```

---

## 4. Chi tiết Kịch bản 3: Bundle Shared Memory bị lỗi

- **Tiền điều kiện**: Location được cấu hình `strata_fail_mode open;`.
- **Cách tiêm lỗi**:
  - Tiêm tệp bundle hỏng (sai header hoặc chữ ký không khớp) vào thư mục bundle:
  ```bash
  dd if=/dev/urandom of=/var/lib/strata/bundle/bundle-invalid.sbn bs=1024 count=10
  ```
- **Hành vi mong đợi**:
  - Trình nạp bundle của NGINX (`bundlefmt.Verify`) phát hiện chữ ký hoặc cấu trúc không hợp lệ.
  - Ghi cảnh báo `NGX_LOG_ERR: the compiled bundle does not verify`.
  - Tiếp tục giữ bundle hợp lệ cũ trong bộ nhớ dùng chung. Nếu không có bundle cũ, áp dụng `strata_fail_mode` an toàn; worker không bị crash.
- **Phục hồi**:
  - Xóa file hỏng và khôi phục bundle hợp lệ.

---

## 5. Chi tiết Kịch bản 4: Panic trong libstrata Engine

- **Tiền điều kiện**: Engine nhận request với payload đặc biệt.
- **Cách tiêm lỗi**:
  - Chạy harness FFI kiểm thử panic cách ly trong Rust:
  ```bash
  deploy/dev/run.sh bash -c "cargo test -p libstrata-ffi panic"
  ```
- **Hành vi mong đợi**:
  - Toàn bộ hàm `extern "C"` của libstrata được bọc bằng `std::panic::catch_unwind`.
  - Panic được chặn lại ở ranh giới FFI, trả về mã lỗi `STRATA_E_INTERNAL` (hoặc `STRATA_E_PANIC`).
  - NGINX ghi log lỗi và trả về 500 hoặc cho qua theo `strata_fail_mode`; worker không bị SIGSEGV/abort.
- **Phục hồi**: Không cần thao tác thủ công vì lỗi đã được cô lập ở cấp transaction.

---

## 6. Chi tiết Kịch bản 5: Mất kết nối mạng (Network Partition)

- **Tiền điều kiện**: Cụm node chạy phân tán.
- **Cách tiêm lỗi**:
  - Cắt toàn bộ lưu lượng mạng ra ngoài từ node WAF bằng iptables:
  ```bash
  iptables -A OUTPUT -p tcp --dport 8080 -j DROP  # Chặn tới Control Plane
  iptables -A OUTPUT -p tcp --dport 9000 -j DROP  # Chặn tới MinIO
  ```
- **Hành vi mong đợi**:
  - Node tiếp tục hoạt động độc lập 100% với bundle và policy đã lưu tại bộ nhớ local.
  - Bộ đếm Rate Limiting theo node tiếp tục bảo vệ route độc lập.
- **Thời gian chờ**: 5 phút.
- **Phục hồi**:
  ```bash
  iptables -D OUTPUT -p tcp --dport 8080 -j DROP
  iptables -D OUTPUT -p tcp --dport 9000 -j DROP
  ```
  - Node tự động kết nối lại và đồng bộ sự kiện khi mạng khôi phục.

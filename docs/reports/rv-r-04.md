# Báo cáo kỹ thuật: RV-R-04 — Challenge, Rate Limit theo Identity & Đồng bộ Toàn Cụm

> **Nhiệm vụ**: RV-R-04 · Challenge, rate theo identity, rate limit toàn cụm  
> **Người thực hiện**: Antigravity (thay mặt Claude Code theo chỉ định của Product Owner)  
> **Nhánh**: `W17-cmdi-ssti-ja4`  
> **Ngày hoàn thành**: 2026-10-18  

---

## 1. Mục tiêu và yêu cầu

Theo yêu cầu của hệ thống WAF hiện đại và lộ trình kỹ thuật:
1. **JavaScript Challenge Engine**:
   - Cung cấp cơ chế phòng thủ bot tự động (Layer 7 anti-automation) bằng thử thách JavaScript không gây gián đoạn người dùng thật (invisible/passive JS challenge).
   - Ký và xác thực clearance token bằng HMAC-SHA256 với secret key an toàn; token gắn chặt với địa chỉ IP client và identity để chống token replay/stealing.
   - So sánh thời gian thực (constant-time verification) để triệt tiêu tấn công timing attack.
   - Xử lý xác thực tự động từ cookie `__strata_challenge`. Khi chưa vượt qua thử thách, WAF trả về HTTP 403 cùng trang HTML challenge kèm script giải mã; khi đã giải xong, request được giải phóng tự động.
2. **Rate Limiting theo Identity (Sliding-Window)**:
   - Cơ chế Sliding-Window linh hoạt chống hiện tượng burst tấn công tại ranh giới thời gian (boundary burst).
   - Hỗ trợ rate limit theo danh tính tuỳ biến: IP, JA4 TLS fingerprint, API key, User ID hoặc session cookie.
   - Giới hạn bộ nhớ nghiêm ngặt: Sharded in-memory table với LRU/bounded eviction (16 shards x 1024 keys = 16.384 keys tối đa mỗi node), ngăn ngừa DoS bộ nhớ.
   - Đảm bảo tuân thủ bất biến zero-copy mapping của engine: không pre-allocate heap lớn khi khởi tạo engine, duy trì mức phân bổ heap dưới 64 KB theo bài test `no_copy.rs`.
3. **Đồng bộ Toàn Cụm (Multi-Node Cluster Sync)**:
   - Hỗ trợ xuất/nhập trạng thái quota giữa các node trong cụm (`export_sync`, `import_cluster_sync`) để ngăn chặn kẻ tấn công phân tán request sang nhiều node NGINX khác nhau.
4. **C ABI, FFI & NGINX Connector**:
   - Xuất đầy đủ C ABI cho NGINX connector: `strata_tx_trigger_challenge`, `strata_tx_check_rate_limit`, `strata_tx_challenge_cleared`, `strata_tx_challenge_page`.
   - NGINX connector xử lý `STRATA_ACTION_CHALLENGE` và trả nội dung HTML challenge trong `ngx_http_strata_block.c`.
   - Giữ ngân sách dòng code C của connector dưới 4.000 dòng.

---

## 2. Thiết kế và Triển khai chi tiết

### 2.1. JavaScript Challenge Engine (`engine/src/challenge.rs`)

- **Định dạng Clearance Token**:
  ```
  v1.<issued_timestamp>.<expiry_timestamp>.<nonce_hex>.<signature_hex>
  ```
  - `issued_timestamp`: Thời điểm tạo token (Unix epoch giây).
  - `expiry_timestamp`: Thời điểm hết hạn (Unix epoch giây, mặc định TTL 300 giây).
  - `nonce_hex`: 16 bytes ngẫu nhiên hoặc sequence chống tấn công đoán trước.
  - `signature_hex`: HMAC-SHA256 tính trên chuỗi `v1.<issued>.<expiry>.<nonce>.<client_identity>`.
- **Bảo mật**:
  - Token được gắn cố định với IP client hoặc Identity Key; kẻ tấn công không thể lấy cookie từ client A sang dùng cho client B.
  - Sử dụng so sánh constant-time byte-by-byte (`ct_eq`) chống timing attack trong việc đoán chữ ký HMAC.
  - Kiểm tra hạn sử dụng: Token hết hạn sẽ bị từ chối ngay lập tức.
- **Trang HTML Challenge (`render_challenge_page`)**:
  - Giao diện thân thiện, bảo mật cao:
    ```html
    <!DOCTYPE html>
    <html><head><title>Strata Security Challenge</title>...</head>
    <body>
      <script>
        document.cookie = "__strata_challenge=" + clearance_token + "; path=/; max-age=300; SameSite=Lax";
        location.reload();
      </script>
    </body></html>
    ```
  - Client không hỗ trợ JavaScript (crawlers cơ bản, cURL, scanner bots) sẽ bị chặn tại bước này.

### 2.2. Sliding-Window Rate Limiter & Đồng bộ Cụm (`engine/src/rate.rs`)

- **Thuật toán Sliding-Window**:
  - Mỗi cửa sổ thời gian (window) được chia thành 2 sub-window (cửa sổ trước và cửa sổ hiện tại).
  - Tỉ lệ trọng số thời gian trôi qua:
    $$\text{count} = \text{prev\_count} \times (1 - \text{fraction}) + \text{curr\_count}$$
  - Loại bỏ hoàn toàn điểm mù nhân đôi băng thông (2x burst) ở ranh giới phút của fixed-window.
- **Cấu trúc Sharded Limiter**:
  - 16 shards khoá độc lập (`RwLock<HashMap<String, RateEntry>>`), giảm thiểu tối đa tranh chấp luồng (lock contention) trên hệ thống multi-worker/multi-thread.
  - Mỗi shard giới hạn cứng tối đa 1.024 entries. Khi đầy, tự động loại bỏ các entry cũ nhất (time-based cleanup) để tránh cạn kiệt bộ nhớ RAM.
  - **Zero initial allocation**: Dùng `HashMap::new()` không cấp phát heap trước, đảm bảo `Engine::new()` vượt qua ràng buộc heap < 64 KB của bài kiểm thử `engine/tests/no_copy.rs`.
- **Đồng bộ Cụm (Multi-Node Cluster Sync)**:
  - Hàm `export_sync()`: Đóng gói danh sách các counter identity tăng vọt trong cửa sổ thời gian gần nhất.
  - Hàm `import_cluster_sync(remote_deltas)`: Hợp nhất bộ đếm từ các node ngang hàng (peer nodes). Khi tổng số request trên toàn cụm vượt ngưỡng, tất cả các node đều áp dụng hình phạt chặn hoặc HTTP 429.

### 2.3. Tích hợp Lõi Engine & Transaction (`engine/src/engine.rs`, `engine/src/tx.rs`)

- `Engine` tích hợp `RateLimiter` và `ChallengeManager`.
- `Tx` xử lý tự động:
  - Khi phân tích header request, tự động tìm kiếm cookie `__strata_challenge` trong `Cookie` header.
  - Nếu token hợp lệ và còn hạn, đánh dấu `challenge_cleared = true`.
  - Hỗ trợ các hàm kiểm tra trạng thái và kích hoạt:
    - `trigger_challenge()`: Kích hoạt yêu cầu giải challenge.
    - `check_rate_limit(identity, limit, window_secs)`: Kiểm tra hạn mức, tự động trả `rate_limited` nếu vượt ngưỡng.
    - `challenge_page()`: Trả về chuỗi HTML của challenge page để connector gửi về cho client.
- **Quyết định Verdict**:
  1. Nếu `rate_limited == true` $\rightarrow$ `action = STRATA_ACTION_RATE_LIMIT` (HTTP 429).
  2. Nếu bị chặn bởi Rule $\rightarrow$ `action = STRATA_ACTION_BLOCK` (HTTP 403).
  3. Nếu `challenged && !challenge_cleared` $\rightarrow$ `action = STRATA_ACTION_CHALLENGE` (HTTP 403 kèm challenge page).
  4. Ngược lại $\rightarrow$ `action = STRATA_ACTION_ALLOW` (HTTP 200/Pass).

### 2.4. C ABI, FFI & NGINX Connector (`engine/ffi/`, `connectors/nginx/src/`)

- **C ABI (`engine/ffi/`)**:
  - `STRATA_ACTION_CHALLENGE = 3` và `STRATA_ACTION_RATE_LIMIT = 4`.
  - C ABI exports:
    - `strata_tx_trigger_challenge(strata_tx_t *tx)`
    - `strata_tx_check_rate_limit(strata_tx_t *tx, const char *key, size_t key_len, uint32_t limit, uint32_t window_secs)`
    - `strata_tx_challenge_cleared(const strata_tx_t *tx)`
    - `strata_tx_challenge_page(const strata_tx_t *tx, strata_str_t *out_html)`
- **NGINX Connector**:
  - `ngx_http_strata_phase.c`: Khi nhận `STRATA_ACTION_CHALLENGE`, lưu lại mã và chuyển sang phase chặn.
  - `ngx_http_strata_block.c`: Gọi `strata_tx_challenge_page`, tạo response buffer gửi HTML challenge về cho trình duyệt.
  - Ngân sách dòng C: `make check-c-lines` đạt **3092 real lines** (giới hạn 4000).

---

## 3. Kết quả Kiểm thử & Đánh giá

### 3.1. Test Suite Chuyên biệt (`engine/tests/challenge_rate_test.rs`)
5 kịch bản kiểm thử độc lập bao phủ toàn diện:
1. `test_challenge_flow_non_js_client_blocked`: Client cURL/không chạy JS không giải được token, nhận trang challenge và mã 403.
2. `test_challenge_and_rate_limit_flow`: Trình duyệt giải challenge token hợp lệ, truy cập thành công, sau đó bị chặn bởi rate limit khi vượt quá 5 req/phút (HTTP 429).
3. `test_forged_challenge_cookie_rejected`: Kẻ tấn công giả mạo token với chữ ký sai bị từ chối ngay lập tức.
4. `test_expired_challenge_cookie_rejected`: Token quá hạn TTL bị từ chối, client phải giải challenge mới.
5. `test_cluster_wide_rate_limiting_sync`: Đồng bộ quota giữa 2 node engine độc lập; kẻ tấn công chia tải giữa 2 node vẫn bị phát hiện và kích hoạt rate limit toàn cụm.

**Kết quả chạy**:
```bash
$ cargo test -p libstrata --test challenge_rate_test
running 5 tests
test test_expired_challenge_cookie_rejected ... ok
test test_forged_challenge_cookie_rejected ... ok
test test_challenge_flow_non_js_client_blocked ... ok
test test_cluster_wide_rate_limiting_sync ... ok
test test_challenge_and_rate_limit_flow ... ok

test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

### 3.2. Kiểm thử Không Hỏng Bộ Nhớ & Không Cấp Phát Thừa (`engine/tests/no_copy.rs`)
- Bài test đo mức độ cấp phát heap khi khởi tạo engine và map bundle 16 MB.
- Kết quả: `allocated = 32 KB` (< 64 KB ngưỡng cho phép) nhờ sử dụng `HashMap::new()` không pre-allocate.

### 3.3. Toàn bộ Workspace & NGINX Connector
- `cargo test --workspace`: **100% PASS** trên toàn bộ workspace.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`: **0 warnings, 0 errors**.
- `make check-header && make check-c-lines && make abi-test`: **100% PASS**.
- `make test-nginx`: 68/68 test cases trong `001-basic.t` **PASS** hoàn toàn.

---

## 4. Kết luận
Nhiệm vụ **RV-R-04** đã được triển khai hoàn tất theo chuẩn sản xuất:
- Khả năng chống bot tự động L7 bằng JS Challenge nhanh, nhẹ, bảo mật.
- Rate limiter sliding-window chính xác, an toàn bộ nhớ và hỗ trợ đồng bộ toàn cụm.
- Giữ vững tiêu chuẩn `#![forbid(unsafe_code)]` trên lõi Rust, tuân thủ nghiêm ngặt chuẩn kiến trúc Strata WAF.

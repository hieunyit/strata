# Hướng Dẫn Kỹ Thuật Triển Khai & Vận Hành Toàn Diện Strata WAF

> **Tài liệu chính thức dành cho Quản trị viên Hệ thống, Kỹ sư DevOps, SRE & Đội ngũ SOC**  
> **Phiên bản kiến trúc**: Strata v0.9 – v1.0.0 (Tương thích NGINX 1.30.5 Stable & 1.31.6 Mainline)  
> **Ngôn ngữ**: Tiếng Việt (Chuẩn thuật ngữ kỹ thuật chuyên sâu)

---

## MỤC LỤC
1. [Tổng Quan Kiến Trúc & Các Mô Hình Triển Khai](#1-tổng-quan-kiến-trúc--các-mô-hình-triển-khai)
2. [Mô Hình 1: Triển Khai Chế Độ Standalone Lite (Edge Gateway)](#2-mô-hình-1-triển-khai-chế-độ-standalone-lite-edge-gateway)
   - 2.1. Yêu cầu & Cài đặt 1 lệnh tự động
   - 2.2. Cấu trúc cấu hình Standalone Agent
   - 2.3. Quy trình nạp & cập nhật Bundle Rules cục bộ
3. [Mô Hình 2: Triển Khai Cụm Doanh Nghiệp Đầy Đủ (Enterprise Cluster)](#3-mô-hình-2-triển-khai-cụm-doanh-nghiệp-đầy-đủ-enterprise-cluster)
   - 3.1. Sơ đồ luồng phân tán và các thành phần
   - 3.2. Cấu hình Control Plane, PostgreSQL, MinIO, Vault & Keycloak
   - 3.3. Cấu hình ClickHouse Ingest & Bảng tổng hợp SummingMergeTree
   - 3.4. Quản lý Node Enrollment, mTLS & Rollout tự động
4. [Cấu Hình & Tối Ưu Hóa Chi Tiết NGINX Module Connector](#4-cấu-hình--tối-ưu-hóa-chi-tiết-nginx-module-connector)
   - 4.1. Bảng Directives toàn diện & Giá trị tối ưu
   - 4.2. Quản lý Ngân sách CPU Hợp tác (Cooperative CPU Budget)
   - 4.3. Cơ chế Ngắt mạch Bảo vệ Worker (Circuit Breaker)
   - 4.4. Cấu hình Fail-Mode (Open vs Closed) cho từng Location
   - 4.5. Nhận diện TLS JA4 Fingerprint & Thử thách JavaScript (Anti-Bot)
   - 4.6. Sliding-Window Rate Limiting theo Định danh (Identity)
5. [Đường Dẫn Log Sự Kiện Bảo Mật & Tích Hợp SIEM](#5-đường-dẫn-log-sự-kiện-bảo-mật--tích-hợp-siem)
   - 5.1. Cơ chế Unix Datagram Socket & Spool Đĩa 2GB Chống Mất Mát
   - 5.2. Cấu hình Định dạng NGINX Access Log với biến `$strata_*`
   - 5.3. Xuất Log JSON Lines & Syslog RFC 5424 về SIEM (Splunk, Wazuh, ELK)
   - 5.4. Lưu trữ & Truy vấn Chuyên sâu trên ClickHouse
6. [Tối Ưu Hóa Hiệu Năng & Khắc Phục Sự Cố (Tuning & Troubleshooting)](#6-tối-ưu-hóa-hiệu-năng--khắc-phục-sự-cố-tuning--troubleshooting)
   - 6.1. Tối ưu Zero-Copy mmap & Bộ nhớ Chia sẻ (Shared Memory)
   - 6.2. Warm-up Tài nguyên Hyperscan Scratch
   - 6.3. Bảng Kiểm Tra & Xử Lý Sự Cố Thường Gặp

---

## 1. Tổng Quan Kiến Trúc & Các Mô Hình Triển Khai

Strata WAF được thiết kế theo kiến trúc phi đối xứng tách biệt hoàn toàn giữa **Mặt phẳng Dữ liệu (Data Plane)** và **Mặt phẳng Quản trị (Control Plane)**:

```
+-----------------------------------------------------------------------------------+
|                                  DATA PLANE                                       |
|  +-----------------------------------------------------------------------------+  |
|  |                           NGINX Master / Workers                            |  |
|  |  +---------------------+   +---------------------+   +-------------------+  |  |
|  |  | ngx_http_strata_mod |<--| mmap bundle zero-cp |<--| /run/control file |  |  |
|  |  |  (libstrata Rust)   |   | (Prefilter+HS+Regex)|   |  (atomic seqlock) |  |  |
|  |  +----------+----------+   +---------------------+   +---------+---------+  |  |
|  +-------------|--------------------------------------------------|------------+  |
|                | Unix Datagram (Non-blocking)                     | Hot Reload    |
|                v                                                  |               |
|      +-------------------+                                        |               |
|      |   strata-agent    |----------------------------------------+               |
|      +---------+---------+                                                        |
+----------------|------------------------------------------------------------------+
                 |
      +----------+--------------------------------------------------+
      | (Mode Standalone)                                           | (Mode Enterprise)
      v                                                             v
+-------------------------------+              +------------------------------------+
|   SIEM / Log Server Cục bộ    |              |       Control Plane Cluster        |
|  - JSON Lines: /var/log/strata|              |  - gRPC Fleet Service (PushEvents)  |
|  - Syslog RFC 5424 (UDP/UNIX) |              |  - ClickHouse (Time-series Events)  |
|  - Prometheus: :9469/metrics  |              |  - PostgreSQL (Policy, RBAC, Audit)|
+-------------------------------+              |  - MinIO (Signed Bundles Storage)  |
                                               |  - Vault (Transit KMS Ed25519)     |
                                               |  - Web UI (SOC Dashboard)          |
                                               +------------------------------------+
```

Hệ thống hỗ trợ 2 mô hình triển khai chính:
1. **Mô hình Standalone Lite**: Phù hợp cho cụm proxy nhỏ, Edge Ingress Gateways, chi nhánh văn phòng hoặc môi trường thử nghiệm. Không cần bất kỳ cơ sở dữ liệu ngoài nào.
2. **Mô hình Enterprise Distributed**: Phù hợp cho các hệ thống quy mô lớn, ngân hàng, cổng thanh toán hoặc nền tảng đám mây cần quản trị tập trung hàng trăm agent, phân tích SOC chuyên sâu và luồng duyệt chính sách 4 mắt.

---

## 2. Mô Hình 1: Triển Khai Chế Độ Standalone Lite (Edge Gateway)

### 2.1. Yêu cầu & Cài đặt 1 lệnh tự động

#### Yêu cầu hệ thống:
* **Hệ điều hành**: Linux x86_64 (Debian 11/12, Ubuntu 22.04/24.04 LTS, RHEL/Rocky/AlmaLinux 8/9).
* **Tài nguyên tối thiểu**: 1 vCPU, 512 MB RAM rỗi, 100 MB dung lượng ổ đĩa.
* **Quyền hạn**: Root hoặc `sudo`.

#### Cài đặt nhanh với 1 lệnh (`install-standalone.sh`):
```bash
# Cài đặt từ thư mục packages cục bộ
sudo sh deploy/packaging/install-standalone.sh \
  --packages /path/to/packages \
  --bundle /path/to/starter-bundle.sbn \
  --bundle-pubkey /path/to/bundle.pub \
  --events-jsonl /var/log/strata/events.jsonl \
  --metrics-addr 127.0.0.1:9469

# Hoặc cài đặt tự động từ URL repository nội bộ
sudo sh install-standalone.sh \
  --packages https://repo.internal.net/strata/latest \
  --bundle https://repo.internal.net/strata/bundles/core.sbn \
  --bundle-pubkey /etc/strata/bundle.pub \
  --syslog udp://siem.internal.net:514
```

### 2.2. Cấu trúc cấu hình Standalone Agent

Tệp cấu hình môi trường systemd: `/etc/strata/standalone.env`
```ini
# /etc/strata/standalone.env
STRATA_METRICS_ADDR=127.0.0.1:9469
STRATA_STANDALONE_ARGS="--bundle-dir=/var/lib/strata/bundles \
  --bundle-file=/var/lib/strata/bundles/bundle.sbn \
  --bundle-pubkey=/etc/strata/bundle.pub \
  --bundle-poll-interval=10s \
  --events-jsonl=/var/log/strata/events.jsonl \
  --syslog-addr=udp://10.10.10.50:514 \
  --syslog-tag=strata-waf \
  --event-socket=/run/strata/events.sock \
  --control-file=/var/lib/strata/bundles/control"
```

Quản trị dịch vụ systemd:
```bash
# Khởi động và kiểm tra dịch vụ
sudo systemctl enable --now strata-agent-standalone
sudo systemctl status strata-agent-standalone

# Kiểm tra log hoạt động
sudo journalctl -u strata-agent-standalone -f
```

### 2.3. Quy trình nạp & cập nhật Bundle Rules cục bộ

Trong chế độ Lite, `strata-agent` liên tục theo dõi thư mục `/var/lib/strata/bundles` hoặc URL tĩnh:
1. Khi có rule pack mới được build bởi `strata-rules release`:
   ```bash
   # Chép bundle đã ký vào thư mục
   sudo cp new-pack-v1.1.sbn /var/lib/strata/bundles/bundle.sbn
   ```
2. Agent sẽ tự động xác minh chữ ký Ed25519 qua public key `/etc/strata/bundle.pub`.
3. Nếu hợp lệ, agent cập nhật nguyên tử tệp `/var/lib/strata/bundles/control` bằng cơ chế `seqlock generation increment`.
4. NGINX worker phát hiện sự thay đổi qua timer non-blocking và mmap nạp bộ rule mới trong **dưới 1 giây**, không làm rớt bất kỳ kết nối HTTP nào.

---

## 3. Mô Hình 2: Triển Khai Cụm Doanh Nghiệp Đầy Đủ (Enterprise Cluster)

### 3.1. Sơ đồ luồng phân tán và các thành phần

Cụm máy chủ Doanh nghiệp gồm các vai trò chuyên biệt:
* **Proxy Nodes**: NGINX + Module WAF + `strata-agent` (Chế độ Fleet Client).
* **Control Plane API Server**: Quản lý cấu hình, xác thực OIDC/JWT, phân phối bundle qua gRPC stream, biên dịch policy, tiếp nhận sự kiện (`PushEvents`).
* **PostgreSQL (16+)**: Lưu metadata người dùng, role-binding, service accounts, chính sách WAF, lịch sử phiên bản và audit trail.
* **MinIO / AWS S3**: Lưu trữ tập trung các bundle nhị phân đã ký (`.sbn`) và cơ sở dữ liệu GeoIP (`.mmdb`).
* **HashiCorp Vault**: Quản lý khóa ký Ed25519 qua Transit Secrets Engine, cô lập hoàn toàn khóa riêng tư khỏi môi trường ứng dụng.
* **ClickHouse Cluster**: Lưu trữ columnar hàng tỷ bản ghi sự kiện, tổng hợp thống kê thời gian thực theo giây/phút.
* **Web UI (React)**: Bảng điều khiển SOC Dashboard, phân tích luồng đe dọa, bản đồ tương tác, quản trị rule và ngoại lệ.

### 3.2. Cấu hình Control Plane, PostgreSQL, MinIO, Vault & Keycloak

Tệp cấu hình dịch vụ `/etc/strata/control-plane.yaml` (hoặc biến môi trường Docker):
```yaml
server:
  listen_rest: ":8090"
  listen_grpc: ":8091"
  tls:
    enabled: true
    cert_file: "/etc/strata/certs/cp.crt"
    key_file: "/etc/strata/certs/cp.key"

database:
  dsn: "postgres://strata_user:SecurePass123@postgres.db.internal:5432/strata_db?sslmode=verify-full&sslrootcert=/etc/strata/certs/pg_ca.crt"
  max_open_conns: 50
  max_idle_conns: 10
  conn_max_lifetime: "1h"

storage:
  s3:
    endpoint: "s3.internal.net"
    bucket: "strata-bundles"
    access_key_id: "STRATA_MINIO_KEY"
    secret_access_key: "STRATA_MINIO_SECRET"
    use_ssl: true
    region: "us-east-1"

vault:
  address: "https://vault.internal.net:8200"
  transit_path: "transit"
  key_name: "strata-bundles"
  token_file: "/run/secrets/vault-token"

auth:
  oidc_issuer_url: "https://auth.company.com/realms/strata"
  client_id: "strata-control-plane"
  role_claim: "resource_access.strata-control-plane.roles"
  local_auth_enabled: true  # Cho phép tài khoản cứu hộ cục bộ khi OIDC gián đoạn
```

### 3.3. Cấu hình ClickHouse Ingest & Bảng tổng hợp SummingMergeTree

Nhằm đảm bảo hiệu năng truy vấn hàng chục triệu bản ghi dưới **1 giây**, ClickHouse sử dụng bảng tổng hợp tối ưu hóa theo giờ và cửa sổ 5 phút:

```sql
-- 1. Bảng lưu sự kiện chi tiết (Events v2)
CREATE TABLE IF NOT EXISTS strata.events (
    timestamp DateTime64(6, 'UTC') CODEC(DoubleDelta, ZSTD(1)),
    block_id FixedString(27) CODEC(ZSTD(1)),
    node_id LowCardinality(String),
    policy_id LowCardinality(String),
    policy_version UInt32,
    client_ip String CODEC(ZSTD(1)),
    ja4 FixedString(36) CODEC(ZSTD(1)),
    country_iso LowCardinality(FixedString(2)),
    city LowCardinality(String),
    asn UInt32,
    http_method LowCardinality(String),
    http_host String CODEC(ZSTD(1)),
    http_path String CODEC(ZSTD(3)),
    status_code UInt16,
    action LowCardinality(String),
    would_block UInt8,
    score_anomaly UInt16,
    score_sqli UInt16,
    score_xss UInt16,
    score_cmdi UInt16,
    score_ssti UInt16,
    matched_rules Array(UInt32),
    inspection_flags UInt32,
    latency_us UInt32
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
PRIMARY KEY (timestamp, policy_id, action)
ORDER BY (timestamp, policy_id, action, block_id)
TTL timestamp + INTERVAL 90 DAY;

-- 2. Materialized View tổng hợp theo giờ cho Dashboard SOC (W20-G2-01)
CREATE TABLE IF NOT EXISTS strata.events_hourly_stats (
    window_1h DateTime CODEC(DoubleDelta, ZSTD(1)),
    policy_id LowCardinality(String),
    action LowCardinality(String),
    total_requests UInt64,
    blocked_requests UInt64,
    anomaly_score_sum UInt64,
    latency_us_sum UInt64
) ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(window_1h)
PRIMARY KEY (window_1h, policy_id, action)
ORDER BY (window_1h, policy_id, action)
TTL window_1h + INTERVAL 13 MONTH;

CREATE MATERIALIZED VIEW IF NOT EXISTS strata.events_hourly_mv TO strata.events_hourly_stats AS
SELECT
    toStartOfHour(timestamp) AS window_1h,
    policy_id,
    action,
    count() AS total_requests,
    countIf(action = 'block') AS blocked_requests,
    sum(score_anomaly) AS anomaly_score_sum,
    sum(latency_us) AS latency_us_sum
FROM strata.events
GROUP BY window_1h, policy_id, action;
```

### 3.4. Quản lý Node Enrollment, mTLS & Rollout tự động

1. **Sinh Enrollment Token trên Control Plane**:
   ```bash
   curl -X POST https://control-plane.internal.net:8090/v1/nodes/tokens \
     -H "Authorization: Bearer $ADMIN_JWT" \
     -d '{"connector_group": "production-dmz", "ttl": "24h"}'
   # Kết quả: {"token": "strata_enroll_abc123xyz"}
   ```

2. **Gia nhập Node (Enrollment tại Proxy Node)**:
   ```bash
   # Agent tự sinh khóa riêng tư (0600) và yêu cầu chứng chỉ mTLS có thời hạn 24 giờ (tự động xoay vòng)
   sudo strata-agent enroll \
     --server control-plane.internal.net:8091 \
     --token strata_enroll_abc123xyz \
     --identity-dir /var/lib/strata/identity
   ```

3. **Chạy dịch vụ Agent Fleet**:
   ```bash
   sudo systemctl enable --now strata-agent
   # Agent tự động nhận lệnh PushBundle, rollout theo đợt (canary 1% -> 5% -> 25% -> 100%)
   ```

---

## 4. Cấu Hình & Tối Ưu Hóa Chi Tiết NGINX Module Connector

### 4.1. Bảng Directives toàn diện & Giá trị tối ưu

| Chỉ thị (Directive) | Phạm vi (Context) | Cú pháp chuẩn | Khuyến nghị Production | Mục đích & Rationale |
| :--- | :--- | :--- | :--- | :--- |
| `strata` | http, server, loc | `on \| off` | `on` | Bật/tắt thanh tra WAF. Các endpoint tĩnh hoặc `/healthz` nên đặt `off`. |
| `strata_control_file` | http | `<path>` | `/var/lib/strata/bundles/control` | Con trỏ nhị phân kiểm tra thế hệ bundle (atomic lockless). |
| `strata_bundle_dir` | http | `<path>` | `/var/lib/strata/bundles` | Thư mục chứa các tệp `.sbn` bất biến đã được hash SHA-256. |
| `strata_bundle_pubkey` | http | `<path>` | `/etc/strata/bundle.pub` | Khóa công khai Ed25519 32-byte thẩm định nguồn gốc bundle. |
| `strata_event_socket` | http | `unix:<path>` | `unix:/run/strata/events.sock` | Socket Unix Datagram nhận sự kiện với zero-copy memory. |
| `strata_mode` | http, server, loc | `enforce \| shadow` | `enforce` | `enforce`: Chặn trực tiếp (403/429); `shadow`: Chỉ ghi log vi phạm. |
| `strata_fail_mode` | http, server, loc | `open \| closed` | `open` (API) / `closed` (Auth) | Hành vi khi lỗi engine/timeout. Xem chi tiết Mục 4.4. |
| `strata_cpu_budget` | http, server, loc | `<time>` | `10ms` (API) / `25ms` (Body) | Giới hạn thời gian CPU thanh tra cooperative cho mỗi request. |
| `strata_request_body_mode` | http, server, loc | `buffer \| stream` | `buffer` | `buffer`: Đọc toàn bộ body trước khi proxy; `stream`: Chỉ dùng ở shadow. |
| `strata_request_body_limit`| http, server, loc | `<size>` | `128k` (Default) / `1m` (JSON) | Kích thước tối đa body được kiểm tra. Tránh cạn kiệt RAM worker. |
| `strata_response_inspect` | http, server, loc | `on \| off` | `on` (cho API nhạy cảm) | Kiểm tra Data Guard chống lộ lọt CCCD, thẻ tín dụng, JWT token. |
| `strata_breaker` | http | `on \| off` | `on` | Kích hoạt bộ ngắt mạch tự phục hồi bảo vệ tiến trình NGINX. |

### 4.2. Quản lý Ngân sách CPU Hợp tác (Cooperative CPU Budget)

Trong môi trường chịu tải cao, một cuộc tấn công ReDoS (Regular Expression Denial of Service) hoặc chuỗi JSON lồng nhau phức tạp có thể chiếm dụng CPU của NGINX worker.
* **Nguyên lý hoạt động**: `libstrata` kiểm tra bộ đếm thời gian sau mỗi operator regex hoặc detector. Nếu thời gian thực thi vượt quá `strata_cpu_budget`, lõi engine dừng ngay lập tức và trả về trạng thái `E_BUDGET`.
* **Cấu hình tối ưu**:
  ```nginx
  # Cho các API nghiệp vụ thông thường (đảm bảo độ trễ p99 < 1ms)
  strata_cpu_budget 10ms;

  # Cho các route xử lý biểu mẫu hoặc tệp đính kèm lớn
  location /v1/upload {
      strata_cpu_budget 30ms;
      strata_request_body_limit 2m;
  }
  ```

### 4.3. Cơ chế Ngắt mạch Bảo vệ Worker (Circuit Breaker)

Nếu xuất hiện lỗi phần cứng, lỗi phân bổ bộ nhớ hoặc engine crash đột ngột:
* **Circuit Breaker** cấp worker sẽ tự động chuyển sang trạng thái **OPEN** (ngắt kiểm tra WAF) để bảo vệ toàn bộ tiến trình proxy không bị sập:
  ```nginx
  http {
      strata_breaker on;
      # Cấu hình ngưỡng: Nếu tỷ lệ lỗi > 5% trong cửa sổ 10s với tối thiểu 100 requests -> Mở ngắt mạch trong 30s
      strata_breaker_threshold engine 5% 10s 100 open=30s;
      strata_breaker_threshold budget 10% 10s 200 open=30s;
      
      # Hành động khi ngắt mạch mở: Cho qua (bypass) hoặc ghi log giảm cấp (shadow)
      strata_breaker_action shadow;
  }
  ```

### 4.4. Cấu hình Fail-Mode (Open vs Closed) cho từng Location

Theo chuẩn thiết kế bảo mật Strata (Gate B Quyết định fail-closed):
* **Fail-Open (`strata_fail_mode open`)**: Áp dụng cho các dịch vụ xem thông tin công cộng, danh mục hàng hóa, cổng tin tức. Khi WAF gặp lỗi, request vẫn được chuyển tiếp tới backend để đảm bảo tính sẵn sàng (Availability).
* **Fail-Closed (`strata_fail_mode closed`)**: Bắt buộc áp dụng cho các route nhạy cảm (Đăng nhập, Thanh toán, Quản trị). Khi WAF gặp sự cố hoặc cạn ngân sách CPU, hệ thống lập tức trả về mã **HTTP 503** kèm `Block ID` để điều tra, ngăn chặn kẻ tấn công lợi dụng làm sập WAF để vượt rào (Bypass).

```nginx
# 1. Tuyến dịch vụ đọc công cộng: Ưu tiên tính liên tục
location /api/v1/catalog/ {
    strata on;
    strata_policy catalog-read;
    strata_fail_mode open;
    proxy_pass http://backend_catalog;
}

# 2. Tuyến xác thực & thanh toán: Ưu tiên bảo mật tuyệt đối
location /api/v1/auth/ {
    strata on;
    strata_policy strict-auth;
    strata_fail_mode closed;
    proxy_pass http://backend_auth;
}
```

### 4.5. Nhận diện TLS JA4 Fingerprint & Thử thách JavaScript (Anti-Bot)

Nhờ hoàn tất `RV-N-02` và `RV-R-04`:
1. **Trích xuất JA4 TLS Fingerprint**:
   Module NGINX can thiệp vào callback `SSL_CTX_set_msg_callback` của OpenSSL, lấy gói tin `ClientHello` thô chuyển sang lõi Rust tính toán chuỗi JA4 theo chuẩn FoxIO (ví dụ: `t13d1516h2_8daaf6152771_02711d04b6b6`) lưu vào biến `$strata_ja4`.
2. **Khai thác biến `$strata_ja4`**:
   Có thể dùng làm khóa giới hạn tần suất hoặc chặn đứng các công cụ tấn công giả mạo User-Agent:
   ```nginx
   # Chặn trực tiếp các JA4 của công cụ quét lỗ hổng đã biết
   if ($strata_ja4 = "t10d010000_000000000000_000000000000") {
       return 403 "Blocked Scanner Fingerprint\n";
   }
   ```
3. **Thử thách JavaScript (Challenge Engine)**:
   Khi phát hiện bot nghi vấn hoặc lưu lượng vượt ngưỡng nguy hiểm, WAF trả về HTTP 403 kèm trang HTML giải mã JavaScript tự động. Trình duyệt hợp lệ sẽ vượt qua trong 100ms và nhận cookie clearance `__strata_challenge` ký HMAC-SHA256 hợp lệ trong 300 giây.

### 4.6. Sliding-Window Rate Limiting theo Định danh (Identity)

Khắc phục hoàn toàn điểm yếu nhân đôi băng thông (2x burst) ở biên phút của thuật toán fixed-window:
```nginx
# Áp dụng rate limit theo JA4 và IP kết hợp
location /api/v1/login {
    strata on;
    strata_policy login-protection;
    strata_identity "$remote_addr:$strata_ja4";
    # Ngưỡng: Tối đa 5 request trong cửa sổ trượt 60 giây
    # Vượt ngưỡng -> HTTP 429 Too Many Requests
    proxy_pass http://backend_identity;
}
```

---

## 5. Đường Dẫn Log Sự Kiện Bảo Mật & Tích Hợp SIEM

### 5.1. Cơ chế Unix Datagram Socket & Spool Đĩa 2GB Chống Mất Mát

Đường truyền sự kiện bảo mật được thiết kế để không bao giờ gây nghẽn tiến trình xử lý request của NGINX:
1. Khi có vi phạm, NGINX Worker đóng gói cấu trúc nhị phân `strata_event_t` và bắn qua Unix Domain Socket (`/run/strata/events.sock`) bằng lời gọi `send()` chế độ **Non-blocking**.
2. Phía bên kia socket, tiến trình `strata-agent` đọc sự kiện với bộ nhớ đệm vòng (Ring buffer) tốc độ xử lý đạt trên **50.000 sự kiện/giây**.
3. **Spool đĩa dự phòng 2GB (`internal/spool`)**: Nếu Control Plane hoặc mạng bị đứt, agent tự động ghi sự kiện vào thư mục spool đĩa cục bộ kèm số thứ tự chuỗi (`seq`). Khi kết nối được phục hồi, agent đẩy lại tuần tự mà không làm mất hay trùng lặp bất kỳ sự kiện nào.

### 5.2. Cấu hình Định dạng NGINX Access Log với biến `$strata_*`

Cấu hình log kết hợp toàn bộ thông tin WAF vào tệp access log của NGINX:

```nginx
http {
    log_format strata_json escape=json '{'
        '"time_local":"$time_iso8601",'
        '"client_ip":"$remote_addr",'
        '"ja4":"$strata_ja4",'
        '"request_method":"$request_method",'
        '"request_uri":"$request_uri",'
        '"status":$status,'
        '"body_bytes_sent":$body_bytes_sent,'
        '"request_time":$request_time,'
        '"waf_action":"$strata_action",'
        '"waf_block_id":"$strata_block_id",'
        '"waf_policy":"$strata_policy",'
        '"waf_score":$strata_score,'
        '"waf_rules":"$strata_rules",'
        '"waf_bundle_version":"$strata_bundle_version",'
        '"waf_latency_us":$strata_time_us'
    '}';

    access_log /var/log/nginx/access_strata.json strata_json;
}
```

### 5.3. Xuất Log JSON Lines & Syslog RFC 5424 về SIEM (Splunk, Wazuh, ELK)

#### Định dạng tệp JSON Lines (`/var/log/strata/events.jsonl`):
Mỗi dòng là một đối tượng JSON độc lập, dễ dàng được ingest bởi Filebeat, Vector, FluentBit hoặc Wazuh Agent:
```json
{
  "timestamp": "2026-10-18T14:32:01.124582Z",
  "block_id": "STR-D19M-4F9A-94K1-CS1J",
  "node_id": "edge-proxy-01",
  "client_ip": "203.0.113.45",
  "country_iso": "VN",
  "city": "Hanoi",
  "asn": 131429,
  "ja4": "t13d1516h2_8daaf6152771_02711d04b6b6",
  "method": "POST",
  "host": "api.example.com",
  "path": "/v1/auth/login",
  "status_code": 403,
  "action": "block",
  "would_block": 1,
  "score_anomaly": 15,
  "score_sqli": 15,
  "matched_rules": [942100, 942140],
  "violation_details": "SQLi detected via libinjection and pattern match in body parameter 'username'"
}
```

#### Cấu hình đẩy trực tiếp qua Syslog RFC 5424:
Trong file `/etc/strata/standalone.env` (hoặc cấu hình agent):
```ini
--syslog-addr=udp://10.20.30.40:514 --syslog-tag=strata-waf
```

Cấu hình mẫu cho bộ lọc **Logstash** (ELK Stack):
```ruby
input {
  udp {
    port => 514
    type => "strata-syslog"
  }
}
filter {
  if [type] == "strata-syslog" {
    json {
      source => "message"
      target => "waf"
    }
    geoip {
      source => "[waf][client_ip]"
    }
  }
}
output {
  elasticsearch {
    hosts => ["http://elasticsearch:9200"]
    index => "strata-waf-events-%{+YYYY.MM.dd}"
  }
}
```

---

## 6. Tối Ưu Hóa Hiệu Năng & Khắc Phục Sự Cố (Tuning & Troubleshooting)

### 6.1. Tối ưu Zero-Copy mmap & Bộ nhớ Chia sẻ (Shared Memory)

* **Bộ nhớ dùng chung PSS (Proportional Set Size)**:
  Nhờ định dạng bundle nhị phân liên tục căn lề 4 KB, khi 32 NGINX worker cùng mmap tệp bundle 20 MB, hệ thống chỉ tiêu tốn đúng **20 MB RAM vật lý** (thay vì nhân lên 32 lần = 640 MB như các WAF truyền thống).
* **Kiểm tra trạng thái chia sẻ bộ nhớ trên máy chủ**:
  ```bash
  # Đo PSS thực tế của các worker NGINX
  sudo grep -E "Pss:" /proc/$(pgrep -f "nginx: worker" | head -1)/smaps | awk '{sum += $2} END {print "PSS: " sum " KB"}'
  ```

### 6.2. Warm-up Tài nguyên Hyperscan Scratch

Trước khi phục vụ tải lưu lượng lớn, worker cần làm ấm vùng nhớ tạm (scratch memory) của Hyperscan để tránh hiện tượng trễ đỉnh (latency spike) ở request đầu tiên:
* Lõi Rust cung cấp hàm `warm_thread()` được tự động kích hoạt trong luồng công việc của NGINX worker.
* Đảm bảo cấu hình hệ điều hành hỗ trợ khóa bộ nhớ:
  ```ini
  # /etc/security/limits.conf
  nginx soft memlock unlimited
  nginx hard memlock unlimited
  ```

### 6.3. Bảng Kiểm Tra & Xử Lý Sự Cố Thường Gặp

| Triệu chứng | Nguyên nhân có thể | Cách kiểm tra & Khắc phục |
| :--- | :--- | :--- |
| **Request bị 503 khi khởi động NGINX** | Thiếu bundle hoặc `strata_control_file` chưa tồn tại | Kiểm tra log `/var/log/nginx/error.log`. Khởi động agent để sinh control file hoặc copy bundle starter vào thư mục. |
| **`nginx -t` báo lỗi signature rejection** | Bundle bị sửa đổi hoặc file public key Ed25519 không khớp | Kiểm tra SHA-256 của bundle: `sha256sum bundle.sbn`. Kiểm tra lại public key `/etc/strata/bundle.pub`. |
| **Không thấy sự kiện ghi vào ClickHouse / JSONL** | Socket `/run/strata/events.sock` bị sai quyền hạn sở hữu | Đảm bảo thư mục `/run/strata` thuộc quyền `strata:strata` hoặc NGINX user có quyền ghi vào socket (`chmod 0666 /run/strata/events.sock`). |
| **Cảnh báo `strata_breaker tripped`** | Ứng dụng backend hoặc engine bị timeout quá ngân sách CPU | Kiểm tra `strata_cpu_budget`. Tăng budget lên `25ms` nếu payload lớn hoặc loại bỏ các rule regex phức tạp trên query string. |
| **Trang challenge hiển thị vòng lặp vô tận** | Trình duyệt không bật cookie hoặc sai cờ `SameSite` | Kiểm tra header phản hồi HTTP. Đảm bảo cấu hình HTTPS đồng bộ để cookie `__strata_challenge` không bị trình duyệt chặn. |

---

## 7. Tổng Kết

Strata WAF cung cấp giải pháp bảo vệ toàn diện, linh hoạt từ môi trường **Standalone Siêu nhẹ** đến **Cụm Đám Mây Doanh nghiệp Quy mô lớn**:
* Tốc độ xử lý siêu tốc (p99 < 1ms), tiêu thụ bộ nhớ tối thiểu.
* Miễn nhiễm rò rỉ bộ nhớ với `#![forbid(unsafe_code)]` trên lõi Rust.
* Tích hợp dễ dàng vào các hạ tầng giám sát SIEM, Prometheus và SOC hiện đại.

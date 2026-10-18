# Kế hoạch Đánh giá An ninh Thực nghiệm Chuyên sâu (Adversarial Security Evaluation Plan) — Strata WAF

> **Tài liệu**: `docs/plan/redteam-plan.md`  
> **Cấp bậc**: Tài liệu Kỹ thuật An ninh Hệ thống (Security Engineering & Adversarial Assessment)  
> **Phiên bản**: 2.0 (Toàn diện & Chi tiết hóa)  
> **Đối tượng áp dụng**: Đội ngũ Đánh giá An ninh (Red Team / Security QA), Core Engine Developers, PO.  
> **Phạm vi kiểm thử**: `connectors/nginx/`, `engine/libstrata`, `agent/`, `control-plane/`, và hạ tầng điều phối.  
> **Mục tiêu chiến lược**: Đánh giá thực nghiệm toàn diện các giả định thiết kế và cơ chế phòng thủ trước Gate B (W15-S-01, W21-S-01); xác định các vector tấn công cấu trúc (structural bypasses), cạn kiệt tài nguyên (resource exhaustion), sai lệch phân tích ngữ nghĩa (parser differentials), và nguy cơ thao túng tầng vận hành (operational abuse).

---

## 1. Mô hình Mối đe dọa Toàn diện (Comprehensive WAF Threat Model)

Một chuyên gia bảo mật đối kháng không nhìn nhận WAF như một tập hợp signature độc lập. Họ phân rã WAF thành một hệ thống ống dẫn (pipeline) xử lý dữ liệu nhiều lớp và tìm kiếm các điểm đứt gãy giữa các tầng:

```
[ Client Request ] 
       │
       ▼ L1: Transport / Connection (HTTP/1.1, HTTP/2, HTTP/3, TLS, Handshake)
       ▼ L2: HTTP Protocol & Framing (Desynchronization, Smuggling, Chunking)
       ▼ L3: Normalization & Decoding (URL, Unicode, Base64, Matrix Params)
       ▼ L4: Content-Type & Grammar Parsing (JSON, Multipart, XML, Form-Urlencoded)
       ▼ L5: Detection Engine & Rule Evaluation (Hyperscan, Regex, Score, CPU Budget)
       ▼ L6: Connector & Process Boundary (NGINX FFI, Memory Safety, Async Buffering)
       ▼ L7: Operations, State & Control Plane (Canary, Fallback, Event Socket, RBAC)
       │
[ Protected Backend Application ]
```

### Ma trận Phân rã Bề mặt Tấn công (Attack Surface Matrix)

| Tầng | Thành phần chịu trách nhiệm | Vector Đe dọa Chính | Hệ quả nếu Thất bại |
| --- | --- | --- | --- |
| **L1. Transport** | NGINX Core, OpenSSL | HTTP/2 Rapid Reset (RST_STREAM storm), Slowloris, TCP Half-Close evasion | NGINX worker cạn kiệt connection pool, DoS proxy |
| **L2. Protocol Framing** | NGINX HTTP core & connector | CL.TE / TE.CL / TE.TE Request Smuggling, H2 pseudo-header smuggling, `Content-Encoding: gzip` trên Request | Request độc hại lọt thẳng vào backend mà không bị WAF thanh tra |
| **L3. Normalization** | `engine/src/transform/` | Unicode overlong UTF-8, IIS `%uXXXX`, Null-byte `%00` truncation, double-decoding, Matrix parameter `;` | Signature không khớp nhưng backend parse ra payload nguyên bản |
| **L4. Grammar Parsing** | `engine/src/body/` | JSON deep nesting (>64 levels), JSON comments/trailing commas, multipart boundary padding | Engine bỏ cuộc giữa chừng hoặc ném lỗi phân tích, dẫn đến bypass |
| **L5. Detection Engine** | `engine/src/rules/`, Hyperscan | CPU budget exhaustion (10 ms timeout), ReDoS catastrophic backtracking, Replay evasion | Kích hoạt cơ chế fail-open khi phân tích dở dang (`partial inspection`) |
| **L6. Connector FFI** | `connectors/nginx/`, C ABI | Memory leaks trên request pool, dangling pointer giữa FFI, buffer overflow | Crash worker NGINX, corrupt memory, bypass khi restart worker |
| **L7. Operations** | `agent/`, `control-plane/` | Botnet kích hoạt Fallback node về `shadow`, thao túng Canary hash, làm mù SOC bằng Event Socket Flooding | WAF tự động tắt cơ chế phòng thủ (enforce -> shadow) trên diện rộng |

---

## 2. Kiến trúc Môi trường Lab & Hạ tầng Đo lường (Lab Infrastructure)

### 2.1. Phân vùng Mạng & Cô lập Tài nguyên (Isolation Architecture)

Để đảm bảo kết quả đo lường khách quan và tuyệt đối an toàn:
- **Tài nguyên phần cứng riêng biệt**: Máy chủ đánh giá độc lập (tối thiểu 8 Physical Cores ghim CPU affinity, 16 GB RAM, NVMe I/O). Không dùng chung node với CI build hoặc soak runner.
- **Phân rã mạng ảo hóa (Multi-zone Docker Networks)**:
  - `net-attacker` (172.28.1.0/24): Khu vực đặt container chứa các công cụ khai thác và script tấn công tự động.
  - `net-waf-dmz` (172.28.2.0/24): Khu vực đặt NGINX Connector + `libstrata` + `strata-agent`.
  - `net-internal` (172.28.3.0/24): Mạng cô lập chỉ NGINX truy cập được tới các ứng dụng backend.
  - `net-management` (172.28.4.0/24): Kênh giao tiếp mTLS giữa Agent, Control Plane, ClickHouse, Vault và Prometheus.
- **Toxiproxy Mesh**: Cắm `toxiproxy` vào giữa Agent và Control Plane để chủ động bơm lỗi mạng (jitter 100ms, packet drop 5%, bandwidth throttle 50 KB/s) nhằm kiểm tra độ bền của WAF khi mất liên lạc với máy chủ quản trị.

### 2.2. Ma trận Backend Đối chứng (Target Application Ecosystem)

Kiểm thử bắt buộc phải chạy song song trên 2 hệ sinh thái backend có triết lý phân tích cú pháp đối lập:

```
                     ┌───> [Permissive Group] (Spring Boot WebGoat, Express Juice Shop, ASP.NET)
[ Strata WAF Proxy ] │
                     └───> [Strict Group]     (Go net/http Pilot API, Python Werkzeug Strict)
```

1. **Nhóm Permissive (Dung thứ cao)**:
   - **Java / Spring Boot (WebGoat 2023.x)**: Cho phép matrix parameters (`;`), tự động chuẩn hóa path lỏng lẻo, hỗ trợ dynamic data-binding.
   - **Node.js / Express (OWASP Juice Shop v16.x)**: Sử dụng middleware `body-parser` chấp nhận JSON lỏng lẻo, tự động parse prototype.
   - **ASP.NET Core Mock Service**: Tích hợp middleware tự động giải nén request gzip (`RequestDecompressionMiddleware`).
2. **Nhóm Strict (Nghiêm ngặt chuẩn RFC)**:
   - **Go `net/http` Mock Backend**: Kiểm tra chặt chẽ header, từ chối header lặp ký tự điều khiển, tuân thủ RFC 7230/9112.
   - **PHP 8.3 / Apache (DVWA v2.3)**: Kiểm thử các vector injection truyền thống (SQLi, Command Injection, File Upload).

### 2.3. Cấu hình WAF Profiles trong Thử nghiệm

| Thiết lập | Profile A (Standard Default) | Profile B (Hardened Strict) | Profile C (Stress / Low Budget) |
| --- | --- | --- | --- |
| **Signature Pack** | Release v0 (~9.000 rules) | Release v0 (~9.000 rules) | Release v0 (~9.000 rules) |
| **Action Mode** | `enforce` | `enforce` | `enforce` |
| **CPU Budget** | 10 ms (`strata_budget 10ms`) | 10 ms | 2 ms (mô phỏng tải cao) |
| **Fail Mode** | `open` (`strata_fail_mode open`) | `closed` | `open` |
| **Oversize Action** | `passthrough` (partial scan) | `block` (`oversize: block`) | `passthrough` |
| **Vá lỗi #98** | Bật | Bật | Tắt (để đo đạc đối chứng) |

---

## 3. Danh mục Công cụ Đánh giá & Phiên bản Cố định (Tooling Stack)

Mọi công cụ được container hóa cố định phiên bản tại `deploy/redteam/Dockerfile.tools` để đảm bảo kết quả tái lập:

| Danh mục | Công cụ | Phiên bản | Vai trò & Trọng tâm Kiểm thử |
| --- | --- | --- | --- |
| **DAST & Vulnerability Scanning** | `nuclei` | v3.3.2 | Chạy full templates (CVEs, misconfigs, default-logins) để đối chứng số lượng finding trước/sau WAF |
| | `OWASP ZAP` | 2.15.0 | Active scan API & Web surfaces, automated crawl & attack |
| | `nikto` | 2.5.0 | Scan header misconfigurations, HTTP method tampering, web server flaws |
| **Injection Exploitation** | `sqlmap` | 1.8.10#stable | Tự động hóa khai thác SQLi; kiểm tra các tamper script (`between`, `space2comment`, `charencode`) |
| | `commix` | v3.9-stable | Tự động hóa Command Injection qua các kênh out-of-band, blind time-based |
| | `ghauri` | 1.4.2 | Công cụ khai thác SQLi nâng cao tối ưu hóa request signature evasion |
| **Client-Side & XSS** | `dalfox` | v2.9.3 | Quét XSS chuyên sâu với cơ chế parse DOM, reflected parameters, polyglots |
| | `XSStrike` | 3.1.5 | Fuzzy payload generation, WAF detection & context-breaking payloads |
| **Directory & Endpoint Fuzzing** | `ffuf` | v2.1.0 | Fuzzing high-speed URL paths, headers, parameter names, JSON keys |
| | `feroxbuster` | 2.10.4 | Đệ quy tìm kiếm tài nguyên ẩn và route nội bộ |
| **API & Schema Validation** | `schemathesis` | 3.25.4 | Property-based testing theo OpenAPI/Swagger, tạo request biên (edge-cases) |
| **WAF Benchmarking & Regression**| `gotestwaf` | Latest (Pinned) | Đo điểm bảo vệ tổng thể theo chuẩn OWASP Categories |
| | `go-ftw` | v0.6.2 | Kiểm thử độ tương thích với ModSecurity CRS regression suite |
| | `strata-mutate`| Internal v0.1 | Bộ sinh đột biến payload (W09-S-02) chạy biến thể encoding tự động |

---

## 4. Kịch bản Thử nghiệm Chi tiết (Test Specifications Matrix)

Mỗi kịch bản được chuẩn hóa với mã định danh cụ thể, giả thuyết kiểm thử, vector kỹ thuật và chỉ số đánh giá.

### Nhóm 1: Làm WAF Bỏ Cuộc & Cạn Kiệt Tài Nguyên (Resource Exhaustion & Fail-Open)

#### `TC-EXP-01`: Timing Attack Dò Ngưỡng CPU Budget
- **Giả thuyết**: Kẻ tấn công có thể đo thời gian phản hồi của proxy khi gửi các request có độ phức tạp tăng dần để xác định chính xác ngưỡng `strata_budget` (ví dụ 10 ms), từ đó xây dựng payload "vừa đủ đắt".
- **Kỹ thuật thực hiện**:
  1. Gửi chuỗi 500 request tới endpoint hợp lệ, mỗi request tăng dần số lượng trường JSON cần decode base64 từ 10 lên 5.000 trường.
  2. Đo phân phối $\Delta t$ (latency delta) giữa request sạch và request phức tạp.
  3. Xác định điểm gãy đồ thị (cliff point) nơi thời gian xử lý không tăng nữa và header phản hồi xuất hiện trạng thái thanh tra dở dang.
- **Tiêu chí Đạt**: WAF không để lộ thông tin budget qua phản hồi; metric `strata_policy_not_inspected_total{reason="partial"}` tăng đồng thời hệ thống cảnh báo hành vi probing.

#### `TC-EXP-02`: Độn Payload ở Cuối Request Lớn (Payload Tail-Padding)
- **Giả thuyết**: Với request kích thước 512 KB – 1 MB, nếu đặt 500 KB dữ liệu rác hợp lệ ở đầu và đặt payload tấn công (SQLi / RCE) ở 1 KB cuối cùng, libstrata sẽ cạn budget trước khi duyệt tới payload và cho qua (fail-open).
- **Kỹ thuật thực hiện**:
  1. Tạo request POST `multipart/form-data` hoặc `application/json` kích thước 800 KB.
  2. Phần đầu gồm 10.000 cặp key-value vô hại.
  3. Cuối body chèn payload: `' UNION SELECT NULL, password FROM users--`.
  4. Gửi lần lượt qua Profile A (budget 10ms, fail-open) và Profile B (`oversize: block`).
- **Tiêu chí Đạt**: Trên Profile B, request bị chặn ngay lập tức. Trên Profile A có bản vá #98: nếu một phần vi phạm đã được ghi nhận trước khi cạn budget thì bắt buộc phải CHẶN, không được fail-open.

#### `TC-EXP-03`: ReDoS & Catastrophic Backtracking Attack
- **Giả thuyết**: Tồn tại các biểu thức chính quy (regular expressions) trong gói signature v0 hoặc custom policy có cấu trúc nested quantifier (ví dụ `(a+)+$`) khiến engine Hyperscan / Rust regex tiêu tốn CPU theo hàm mũ.
- **Kỹ thuật thực hiện**:
  1. Trích xuất toàn bộ regex patterns từ `rules/`.
  2. Sử dụng công cụ phân tích tĩnh `regex-static-analysis` để tìm các pattern ReDoS tiềm năng.
  3. Gửi payload kích hoạt backtracking (chuỗi ký tự lặp dài hàng chục ngàn ký tự không khớp ký tự neo cuối cùng).
- **Tiêu chí Đạt**: Engine cắt ngang bằng cơ chế cooperative interruption khi chạm `strata_budget` mà không làm treo NGINX worker thread.

---

### Nhóm 2: Khác biệt Phân tích Ngữ nghĩa (Parser Differentials & Semantic Evasion)

#### `TC-PAR-01`: Body Request Bị Nén (`Content-Encoding: gzip`)
- **Giả thuyết**: Request gửi lên có header `Content-Encoding: gzip` chứa body nén. Libstrata coi body là nhị phân thô không có signature, trong khi backend có middleware tự giải nén (ASP.NET Core / Express `compression`) sẽ giải nén và thực thi payload.
- **Kỹ thuật thực hiện**:
  1. Nén gzip payload `<script>alert(1)</script>` hoặc payload SQLi.
  2. Gửi POST tới endpoint API với header `Content-Encoding: gzip`.
  3. Quan sát: WAF có chặn bằng rule protocol không, hay backend nhận được và trả về trạng thái phản xạ (200 OK).
- **Tiêu chí Đạt**: WAF phải có rule giao thức mặc định từ chối các request có `Content-Encoding` không phải `identity`, hoặc giải nén an toàn có giới hạn kích thước trước khi quét.

#### `TC-PAR-02`: JSON Malformed, Comment & Deeply Nested Hierarchy
- **Giả thuyết**: Các parser JSON lỏng lẻo của backend chấp nhận các dị tật cú pháp mà bộ parser nghiêm ngặt của WAF bỏ cuộc hoặc dừng lại.
- **Kỹ thuật thực hiện**:
  1. **Comment Injection**: `{"user": /*comment*/ "admin' OR 1=1--"}`.
  2. **Trailing Commas & Duplicate Keys**: `{"role": "user", "role": "admin'--"}` (kiểm tra WAF quét first key hay last key).
  3. **Deep Nesting**: Tạo cấu trúc JSON lồng nhau 100 tầng: `{"a":{"a":{"a":...{"payload":"1; DROP TABLE users;"}...}}}`.
- **Tiêu chí Đạt**: Theo quy định của issue #97, khi phát hiện JSON hỏng hoặc vượt quá độ sâu tối đa (64 tầng), WAF phải cộng điểm vi phạm hoặc từ chối request, không được lẳng lặng bỏ qua.

#### `TC-PAR-03`: Path Matrix Parameter Smuggling (Tomcat/Spring)
- **Giả thuyết**: Trong Spring/Tomcat, dấu chấm phẩy `;` biểu thị matrix parameter (ví dụ `/api/v1/orders;param=val/delete`), backend sẽ cắt bỏ phần sau dấu `;` khi định tuyến, trong khi WAF coi toàn bộ chuỗi là một đường dẫn tĩnh không khớp với rule bảo vệ.
- **Kỹ thuật thực hiện**:
  1. Gửi request tới URL: `/admin;jsessionid=123/sensitive-action`.
  2. Gửi request chứa path traversal kèm matrix: `/public/..;param=1/admin`.
- **Tiêu chí Đạt**: Rule 100012 hoặc bộ normalizer của Strata phải chuẩn hóa và loại bỏ matrix parameters trước khi đối soát URI path.

#### `TC-PAR-04`: HTTP Request Smuggling & Pipeline Desynchronization
- **Giả thuyết**: Bất đối xứng giữa NGINX và backend upstream khi xử lý đồng thời `Content-Length` và `Transfer-Encoding: chunked`.
- **Kỹ thuật thực hiện**:
  1. **CL.TE Smuggling**: `Content-Length: 4` kết hợp chunked body.
  2. **TE.CL Smuggling**: `Transfer-Encoding: chunked` kết hợp `Content-Length`.
  3. **Obfuscated TE Header**: `Transfer-Encoding: \tchunked`, `Transfer-Encoding : chunked`, `X: X[\n]Transfer-Encoding: chunked`.
- **Tiêu chí Đạt**: NGINX Connector và rule 100001–100003 phát hiện và ngắt kết nối ngay lập tức với mã lỗi 400 Bad Request.

---

### Nhóm 3: Tấn công Bề mặt Vận hành & Cơ chế An toàn Tự động (Operational Attacks)

#### `TC-OPS-01`: Botnet Giả lập Ép Node Lui về `Shadow` (Fallback Degradation)
- **Giả thuyết**: Kẻ tấn công sử dụng danh sách 10.000 IP phân tán (giả lập botnet) gửi dồn dập các request vi phạm để làm tăng đột biến tỉ lệ lỗi hoặc độ trễ của WAF, kích hoạt cơ chế Circuit Breaker tự động chuyển node về trạng thái `shadow` (đã sửa ở #65, #74).
- **Kỹ thuật thực hiện**:
  1. Dùng script đa luồng giả lập phân phối IP nguồn gửi request lỗi với tần suất cao.
  2. Quan sát ngưỡng kích hoạt fallback của cluster.
  3. Sau khi node rơi vào `shadow`, gửi payload khai thác thực sự và xác minh xem payload có bị bỏ qua không.
- **Tiêu chí Đạt**: Hệ thống rate-limit / circuit breaker nhận diện được phân tán và giữ nguyên chế độ `enforce`, chỉ giảm tải có kiểm soát; nếu bắt buộc phải fallback, còi báo động SOC (Alert P1) phải kích hoạt ngay lập tức.

#### `TC-OPS-02`: Thao túng Canary Hash Routing (`strata_identity` Spoofing)
- **Giả thuyết**: Thuật toán phân nhóm canary (ví dụ 5% traffic qua enforce, 95% qua shadow) sử dụng hàm băm không có secret key trên giá trị `strata_identity`. Nếu client kiểm soát được giá trị này, họ có thể tính toán trước chuỗi identity để luôn rơi vào nhóm shadow.
- **Kỹ thuật thực hiện**:
  1. Phân tích mã nguồn tính toán canary hash bucket trong `connectors/nginx/` hoặc `control-plane/`.
  2. Viết script tìm kiếm các giá trị `X-User-Id` hoặc `Cookie` sao cho `hash(identity) % 100` rơi vào dải số của nhóm `shadow`.
  3. Gửi payload tấn công với identity tính toán trước.
- **Tiêu chí Đạt**: Xác nhận trên môi trường thực tế: `strata_identity` bắt buộc phải được sinh bởi upstream đáng tin cậy đã xác thực, hoặc sử dụng HMAC với secret key chỉ cụm proxy nắm giữ.

#### `TC-OPS-03`: Tấn công Làm mù SOC qua Event Socket Flooding (Log DoS)
- **Giả thuyết**: Gửi 100.000 req/s vi phạm rule nhẹ để làm tràn ngập Unix Domain Socket giữa NGINX và `strata-agent`, khiến buffer bị đầy và các sự kiện bảo mật nghiêm trọng (Critical Alerts) bị bỏ rơi mà không được lưu vào ClickHouse.
- **Kỹ thuật thực hiện**:
  1. Tạo tải cao gửi liên tục request vi phạm rule log-only.
  2. Trong lúc socket đang ngập, gửi xen kẽ 10 request khai thác RCE nghiêm trọng.
  3. Kiểm tra ClickHouse và agent log để đếm số lượng sự kiện bị rơi (`C_DROPPED`).
- **Tiêu chí Đạt**: Agent phải có cơ chế ưu tiên (Priority Queue): sự kiện có score cao / block action không bao giờ bị drop trước sự kiện log thông thường; metric cảnh báo dropped event phải hiển thị ngay trên Grafana.

---

## 5. Khung Chỉ số Đo lường & Đánh giá Định lượng (Statistical Metrics)

Đánh giá an ninh không dựa vào nhận định cảm tính. Mọi kết luận phải dựa trên các công thức định lượng:

```
[ Tổng số lỗ hổng ban đầu: V0 ]
           │
           ├──────────► [ Bị chặn bởi WAF: V_blocked ] ───► Tính Tỉ lệ Bảo vệ: PR
           │
           └──────────► [ Lọt qua WAF: V_waf ]         ───► Phân tích Root Cause & Vá lỗi
```

### 5.1. Công thức Đánh giá Hiệu quả Bảo vệ

1. **Tỉ lệ Bảo vệ Thực tế (Protection Rate - $PR$)**:
   $$\text{PR} = \left( 1 - \frac{V_{\text{waf}}}{V_0} \right) \times 100\%$$
   *Trong đó: $V_0$ là số lỗ hổng công cụ DAST tìm thấy khi không có WAF; $V_{\text{waf}}$ là số lỗ hổng còn tìm thấy khi có WAF ở chế độ enforce.*  
   *Mục tiêu chuẩn*: $\ge 85\%$ cho CRS PL1, $\ge 95\%$ cho CRS PL2.

2. **Tỉ lệ Phân tích Dở dang (Partial Inspection Ratio - $PIR$)**:
   $$\text{PIR} = \frac{\Delta \text{strata\_policy\_not\_inspected\_total}\{\text{reason}=\text{"partial"}\}}{\text{Tổng số Request}} \times 100\%$$
   *Mục tiêu*: Phải duy trì $< 0.05\%$ dưới tải bình thường và $< 1.0\%$ khi bị tấn công cạn kiệt tài nguyên có chủ đích.

3. **Chỉ số Chi phí Tấn công để Vượt qua (Attacker Effort Index - $AEI$)**:
   $$\text{AEI} = \frac{\text{Số lượng Request thử nghiệm cần thiết}}{\text{Số lượng Payload Bypass thành công}}$$
   *Chỉ số này phản ánh độ khó của kẻ tấn công: AEI càng cao chứng tỏ WAF càng bền vững trước fuzzing tự động.*

4. **Tỉ lệ Thất thoát Cảnh báo SOC (Log Loss Ratio - $LLR$)**:
   $$\text{LLR} = \frac{C_{\text{DROPPED}}}{C_{\text{EMITTED}} + C_{\text{DROPPED}}} \times 100\%$$
   *Mục tiêu*: $LLR = 0\%$ đối với các sự kiện có mức độ rủi ro Critical/High.

5. **Độ trễ Gia tăng Dưới Tải Tấn công ($\Delta p99$)**:
   $$\Delta p99 = p99_{\text{Attack}} - p99_{\text{Baseline}}$$
   *Mục tiêu*: $\Delta p99 \le 1.5 \text{ ms}$ trên toàn bộ các kịch bản.

---

## 6. Quy trình Xử lý Phát hiện & Vòng lặp Hồi quy Khép kín (Remediation SOP)

### 6.1. Nguyên tắc An toàn Thông tin Tuyệt đối
- **Cấm lưu trữ PoC thô công khai**: Không commit payload thô, mã khai thác có thể tái sử dụng vào các public repo, commit message hay PR description.
- **Lưu trữ bằng chứng mã hóa**: Toàn bộ traffic dump (.pcap), raw HTTP request logs liên quan đến bypass được lưu trữ tại phân vùng mã hóa nội bộ (`.secure-vault/redteam/`).

### 6.2. Phân loại Mức độ Nghiêm trọng theo WAF-CVSS

| Cấp bậc | Tiêu chí Định tính | Ví dụ Thực tế | SLA Khắc phục |
| --- | --- | --- | --- |
| **P0 - Khẩn cấp (Critical)** | Bypass toàn diện không phụ thuộc backend; RCE/Crash worker NGINX; Lộ lọt secret keys | Request gzip bypass toàn bộ signature; Worker NGINX nhận signal 11 segfault | $\le 24$ giờ trên Lab/Staging |
| **P1 - Cao (High)** | Lách được signature phổ biến (SQLi/Command Injection) qua kỹ thuật độn budget hoặc parser gap | JSON deep nesting bypass SQLi; Payload padding lọt qua fail-open (#98) | $\le 72$ giờ |
| **P2 - Trung bình (Medium)** | Bypass đòi hỏi cấu hình backend dị biệt (Matrix params trên Spring); Lạm dụng fallback cục bộ | Path parameter `;` lọt vào Spring controller; Canary hash collision | $\le 7$ ngày làm việc |
| **P3 - Thấp (Low)** | Sai lệch hiển thị metric; Dropped event dưới 1% khi socket chịu tải cực hạn | Log thiếu trường thông tin trace; Header chuẩn hóa chậm trễ | Kỳ sprint tiếp theo |

### 6.3. Chu trình 5 Bước Đóng Vòng lặp Hồi quy (5-Step Regression Loop)

```
[ 1. Phát hiện Bypass ]
          │
          ▼
[ 2. Trừu tượng hóa Mẫu thử (Corpus Sanitization) ]
     Chuyển payload cụ thể thành test-case cú pháp tổng quát
          │
          ▼
[ 3. Viết Test Fail Trước (TDD / Regression Harness) ]
     Thêm vào `engine/tests/` hoặc `connectors/nginx/t/` -> Test báo RED
          │
          ▼
[ 4. Bản vá Kỹ thuật & Xác nhận Xanh ]
     Sửa code parser/engine -> Test báo GREEN (0 False Positive tăng thêm)
          │
          ▼
[ 5. Tích hợp Nightly Fuzzing ]
     Đưa grammar của biến thể vào `strata-mutate` để chạy liên tục hằng đêm
```

---

## 7. Kế hoạch Triển khai Thực địa & Ma trận Phê duyệt (Execution & Sign-Off)

Hoạt động đánh giá thực nghiệm được chia thành 4 giai đoạn tuần tự:

```
Tuần N:    [ Giai đoạn 0: Thiết lập & Đo Baseline ]
Tuần N+1:  [ Giai đoạn 1: Quét Công cụ Tự động & DAST Benchmark ]
Tuần N+2:  [ Giai đoạn 2: Tấn công Kịch bản Chuyên sâu (Parser & Budget) ]
Tuần N+3:  [ Giai đoạn 3: Tấn công Vận hành, Stress Test & Báo cáo Gate B ]
```

### Bảng Kiểm Tra Sẵn Sàng (Readiness Checklist) Trước Khi Chạy:

- [ ] Node lab đã được cấu hình ghim CPU affinity riêng biệt, không có tiến trình lạ chạy ngầm.
- [ ] Mạng Docker `strata-redteam-net` được cô lập, tường lửa chặn toàn bộ outbound ra Internet.
- [ ] Các ứng dụng mục tiêu (Juice Shop, WebGoat, DVWA, Mock API) khởi động thành công và vượt qua smoke test.
- [ ] Strata WAF chạy ổn định với gói signature v0, agent kết nối thành công tới ClickHouse và Prometheus.
- [ ] Hệ thống giám sát (Grafana dashboard, pprof, metric exporters) sẵn sàng ghi nhận dữ liệu thời gian thực.
- [ ] **Phê duyệt chính thức**: PO / Tech Lead ký duyệt kế hoạch trước khi kích hoạt tải.

---
*Kế hoạch này là tài liệu sống (living document), được cập nhật sau mỗi đợt đánh giá để liên tục hoàn thiện năng lực bảo vệ của Strata WAF.*

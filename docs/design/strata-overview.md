# Strata WAF — Thiết kế dự án

Oct 10, 2026 · @hieuny

## Tóm tắt & mục tiêu

Strata là WAF mã nguồn mở thế hệ mới, chạy trên VM lẫn Kubernetes, tích hợp vào NGINX, Apache, HAProxy, Envoy và Kong, quản trị qua giao diện web đầy đủ, được thiết kế để loại bỏ ba nguyên nhân chính khiến WAF hiện nay thất bại: parser differential (WAF hiểu request khác backend), false positive cao, và vận hành thiếu minh bạch.

Đối tượng: đội SRE/Platform vận hành API và web app trên VM hoặc Kubernetes, đứng sau NGINX, Apache, HAProxy, Envoy hoặc Kong — đặc biệt các hệ thống nhạy cảm như eKYC.

Năm mục tiêu đo được:

1. **Không bypass do parser differential**: 0 lỗi trên bộ test differential fuzzing với 5 profile backend phổ biến.
2. **False positive dưới 0.1%** trên traffic hợp lệ, ở chế độ block.
3. **Latency p99 dưới 1 ms** cho request dưới 64 KB.
4. **Mọi quyết định chặn đều giải thích được**: mỗi lần chặn có một Block ID duy nhất, tra trên UI ra decision trace trong dưới 5 giây, exception tạo trong dưới 1 phút.
5. **Không thay đổi rule nào lên production mà chưa qua replay** trên traffic thật.

## Ma trận vấn đề → giải pháp

Mỗi vấn đề bên dưới đều có thật ở ít nhất một sản phẩm phổ biến; cột cuối là cơ chế cụ thể Strata dùng để loại bỏ nó.

| Vấn đề | Gặp ở | Hậu quả | Strata giải quyết bằng |
| --- | --- | --- | --- |
| WAF parse request khác backend (encoding, tham số trùng, path/query) | ModSecurity v3 (bypass trước 3.0.12), hầu hết engine regex | Bypass hoàn toàn dù rule đúng | Strict parser + normalize theo profile backend; request mơ hồ bị chặn ngay |
| Regex backtracking, ReDoS | ModSecurity/PCRE, CRS cũ | Một request làm treo worker | Chỉ dùng regex thời gian tuyến tính (RE2/Hyperscan), có budget CPU mỗi request |
| False positive cao, tuning thủ công | ModSecurity + CRS, NAXSI (whitelist) | Team tắt WAF hoặc để detect-only mãi | Anomaly score theo route, positive model từ OpenAPI, exception hẹp sinh tự động từ Block ID |
| Không giải thích được vì sao chặn | open-appsec (ML), SafeLine (engine đóng) | Không debug, không audit được | Decision trace từng lớp, ML chỉ là tiebreaker có trọng số hiển thị |
| Người dùng bị chặn không có mã để báo lỗi; log không liên kết được | Phần lớn WAF chỉ trả trang 403 chung | Helpdesk không tìm ra request bị chặn | Block ID duy nhất trên trang chặn, header và log; tra trên UI ra toàn bộ ngữ cảnh |
| Lõi detection đóng hoặc phụ thuộc SaaS | SafeLine (semantic engine), open-appsec (model nâng cao, học tập trung) | Lock-in, khó compliance | Toàn bộ engine và model Apache-2.0, chạy offline hoàn toàn |
| Gắn chặt vào một proxy duy nhất | ModSecurity trong ingress-nginx (retire 3/2026), NAXSI chỉ NGINX, SafeLine/BunkerWeb là proxy riêng | Phải đổi proxy để dùng WAF, hoặc mất vá khi proxy chết | Một engine lõi, 5 connector: NGINX module, Apache module, HAProxy SPOA, Envoy (wasm/ext\_proc), Kong plugin |
| Không có UI, hoặc UI và cấu hình lệch nhau | Coraza, ModSecurity (không UI); nhiều WAF có UI nhưng không có API/versioning | Vận hành phụ thuộc người biết sửa file | Web UI đầy đủ trên control plane; mọi thay đổi có version, audit, phê duyệt; API và GitOps là tùy chọn dùng chung một nguồn dữ liệu |
| Thay đổi rule không có kiểm thử | Gần như tất cả | Rule mới gây sự cố production | Replay traffic thật trước khi áp dụng, báo FP/FN, canary theo % |
| Không chống hành vi (bot, credential stuffing) ở tầng sâu | Coraza, ModSecurity | Phải ghép thêm công cụ | Lớp behavior: fingerprint JA4/HTTP2, rate theo identity, chuỗi request |
| Bỏ qua response | Hầu hết WAF mặc định tắt response inspection | Rò rỉ dữ liệu không bị phát hiện | Lớp response: DLP (CCCD, token), lỗi DB, đối chiếu request–response |
| Bản thân WAF có lỗ hổng bộ nhớ | Module C/C++ (ModSecurity, NAXSI), NGINX CVE | WAF thành điểm tấn công | Lõi Rust memory-safe; connector C chỉ là lớp mỏng, fuzz liên tục |
| Vận hành phức tạp nhiều thành phần | BunkerWeb (scheduler, autoconf, UI, DB) | Khó HA, khó nâng cấp | Data plane không trạng thái; control plane gồm API + UI + PostgreSQL, chạy HA được |

## Đối chiếu với WAF enterprise

WAF enterprise mạnh nhất ở mô hình cấu hình rule, không phải ở engine. Strata vì vậy lấy mô hình entity + violation + staging của F5, ruleset theo phase + override của Cloudflare, label + ngân sách chi phí của AWS, rồi bổ sung phần các sản phẩm này còn thiếu.

| Năng lực | F5 WAF for NGINX | Cloudflare WAF | AWS WAF | Strata |
| --- | --- | --- | --- | --- |
| Mô hình policy | JSON khai báo, kế thừa base template; có policy default và strict; chế độ blocking hoặc transparent | Ruleset theo phase, rule viết bằng biểu thức | Web ACL gồm rule + rule group, có default action | Template → policy → entity → violation, kèm biểu thức theo phase |
| Tổ chức rule | Signature sets, violation có cờ alarm/block, signature ID | Managed ruleset có tag; override theo ruleset, tag hoặc rule | Managed rule group, label truyền giữa các rule, scope-down | Rule ID cố định theo dải + tag + nhóm; override theo nhóm, tag, rule; label |
| Chấm điểm | Violation Rating tính từ các violation | Attack score (ML) cho SQLi/XSS/RCE; OWASP ruleset cộng điểm | Đánh giá từng rule, không có điểm tổng | Anomaly score theo lớp + điểm riêng từng loại tấn công |
| Ngoại lệ | Tắt signature theo policy/URL/parameter; override rules có điều kiện; do-nothing URL | Exception (skip) ưu tiên hơn override | Scope-down, đổi action rule sang count | Exception hẹp có hạn dùng, sinh từ Block ID; exception ưu tiên hơn override |
| Đưa rule mới vào | Time-based signature staging: chỉ log trong thời gian staging | Override action sang log | Action count | Staging theo thời gian cho từng signature + shadow + replay + canary |
| Đối tượng ứng dụng | URL, parameter, header, cookie (integrity), filetype, method; profile JSON/XML/GraphQL/gRPC; OpenAPI | Chủ yếu qua biểu thức; schema API là sản phẩm riêng | Giới hạn kích thước body, parse JSON | Entity model + content profile + OpenAPI + gRPC IDL |
| Response | Response signatures, allowed response codes, Data guard che CCN/SSN và pattern tùy chỉnh | Sensitive Data Detection chạy ở response phase | Không inspect response body | Lớp response: allowed codes, DLP che dữ liệu (CCCD, token), response signatures |
| Bot, brute force, IP | Bot signatures, brute force, IP intelligence, geolocation, threat campaigns | Bot score, rate limiting | Bot Control, chống chiếm tài khoản, IP reputation, rate-based | Lớp behavior + IP list + geo + feed threat |
| Mã tham chiếu khi chặn | Support ID trên trang chặn | Ray ID | Tự cấu hình qua custom response | Block ID trên trang chặn, header, log |
| Biên dịch & phân phối | Compiler tạo bundle .tgz; nạp qua NGINX Instance Manager, NGINX One hoặc HTTP; cập nhật không cần reload NGINX | Áp dụng tức thời trên edge | API, CloudFormation | Compiler tạo bundle ký; hot-swap không reload proxy |
| Giới hạn chi phí rule | Không công khai | Không công khai | WCU, mặc định 1.500 mỗi web ACL | Cost unit tính lúc biên dịch, từ chối policy vượt ngân sách latency |
| Proxy hỗ trợ | NGINX Plus (subscription riêng) | Chỉ edge Cloudflare | CloudFront, ALB, API Gateway… | NGINX OSS/Plus, Apache, HAProxy, Envoy, Kong |

Điều Strata học và áp dụng:

1. **Violation có cờ alarm / block / learn** (F5): chặn hay chỉ ghi log được quyết định theo từng loại vi phạm, không chỉ theo cả policy.
2. **Metadata signature** gồm loại tấn công, độ chính xác, mức rủi ro, server technology (F5): bật đúng nhóm signature cho đúng công nghệ backend.
3. **Staging theo thời gian** (F5): signature mới hoặc vừa cập nhật tự chạy chế độ log trong N ngày.
4. **Override có điều kiện + do-nothing path** (F5), **exception ưu tiên hơn override** (Cloudflare).
5. **Biểu thức + phase** (Cloudflare) và **label nối các rule** (AWS).
6. **Ngân sách chi phí rule** (AWS WCU): đảm bảo latency bằng cách tính toán, không phải bằng hy vọng.
7. **Compiler → bundle → hot reload** (F5).
8. **Mã tham chiếu khi chặn** (Support ID của F5, Ray ID của Cloudflare) → Block ID.

Điều Strata làm thêm mà cả ba chưa có: replay trên traffic thật trước khi áp dụng, một engine cho 5 loại proxy, mã nguồn mở hoàn toàn, decision trace đầy đủ trên UI.

## Nguyên tắc thiết kế

Tám nguyên tắc sau là tiêu chí để duyệt mọi PR; tính năng vi phạm nguyên tắc sẽ không được merge.

1. **Mơ hồ là tấn công.** Request mà hai parser hợp lệ có thể hiểu khác nhau thì bị chặn, không cần khớp payload.
2. **Positive trước, negative sau.** Biết request hợp lệ trông thế nào (schema) rẻ và chính xác hơn đoán request độc trông thế nào.
3. **Mỗi lần chặn có Block ID và giải thích được** bằng lời mà một SRE đọc hiểu trong 10 giây.
4. **Control plane là nguồn dữ liệu duy nhất.** UI, API và GitOps đều đọc ghi cùng một kho cấu hình có version và audit; không có cấu hình nào nằm rải rác trên từng proxy.
5. **Không đoán trên production.** Mọi rule đi qua shadow → replay → canary → enforce.
6. **Một engine, nhiều connector.** Strata không tự làm proxy; cùng một lõi detection chạy trong NGINX, Apache, HAProxy, Envoy và Kong, cho kết quả giống hệt nhau.
7. **Thời gian tuyến tính, bộ nhớ an toàn.** Không có đường code nào phụ thuộc siêu tuyến tính vào input.
8. **Mở hoàn toàn.** Engine, rule, model đều Apache-2.0, chạy offline không cần SaaS.

## Kiến trúc tổng thể

Strata gồm ba plane: control plane có Web UI và API là nguồn dữ liệu cấu hình duy nhất, data plane là engine chạy bên trong proxy có sẵn, analytics plane lưu sự kiện theo Block ID.

&#91;embedded content: kiến trúc Strata · 3 plane\]

Người vận hành sửa cấu hình trên UI (hoặc qua API); GitOps chỉ là một kênh nhập/xuất đi qua cùng API. Control plane đẩy bundle đã ký xuống mọi connector. Khi chặn, engine trả trang chặn kèm Block ID và ghi sự kiện vào event store; UI tra cứu ngược lại từ Block ID.

Lõi engine viết bằng Rust, đóng gói thành một thư viện (`libstrata`) với C ABI ổn định; mỗi connector chỉ là lớp mỏng nối vòng đời request của proxy vào thư viện này. Chi tiết từng proxy ở mục Tích hợp proxy.

## Tích hợp proxy

Cùng một `libstrata` và cùng một bundle chạy trong cả 5 proxy; bộ conformance test bắt buộc 5 connector cho ra quyết định giống hệt nhau trên cùng corpus.

| Proxy | Connector | Cách chạy | Inspect body | Biến log Block ID |
| --- | --- | --- | --- | --- |
| NGINX / OpenResty | Dynamic module `ngx_http_strata_module` | In-process, gọi `libstrata` qua C ABI ở access phase + body filter | Request + response, streaming | `$strata_block_id` |
| Apache httpd | `mod_strata` | In-process, input/output filter, MPM event | Request + response | `%{STRATA_BLOCK_ID}e` |
| HAProxy | `strata-spoa` (SPOE agent) | Process riêng, giao tiếp SPOP | Request (cần `http-buffer-request`); response hạn chế | `var(txn.strata.block_id)` |
| Envoy / Istio / Envoy Gateway | proxy-wasm filter hoặc `strata-extproc` (gRPC ext\_proc) | wasm in-process, hoặc process riêng | Request + response | Dynamic metadata `strata.block_id` |
| Kong Gateway | Plugin `strata` (Lua, gọi `libstrata` qua LuaJIT FFI) | In-process, chạy sau plugin xác thực | Request + response | `kong.ctx.shared.strata_block_id` |

Nguyên tắc chung cho mọi connector:

- Mỗi request nhận một request ID; khi hành động khác `allow`, engine cấp Block ID và connector gắn nó vào trang chặn, header `X-Strata-Block-Id` và access log.
- Connector không giữ cấu hình riêng: chỉ nạp bundle có chữ ký từ control plane, cache cục bộ để chạy tiếp khi mất kết nối.
- Cấu hình phía proxy tối thiểu, ví dụ NGINX:

```nginx
load_module modules/ngx_http_strata_module.so;

http {
    strata on;
    strata_control_plane https://strata-cp.internal:8443;
    strata_node_id web-01;
    log_format waf '$remote_addr $request $status $strata_block_id';

    server {
        location /api/ekyc/ { strata_policy ekyc-api; proxy_pass http://ekyc; }
    }
}
```

## Giao diện & Block ID

Web UI là nơi làm việc chính của người vận hành; mọi thao tác trên UI đều có API tương ứng và được ghi audit.

**Block ID**

- Định dạng: `STR-8F3K-Q2VD-7XNM-A1PC`, 80 bit mã hóa Crockford base32 = 42 bit thời gian (ms) + 10 bit node + 28 bit ngẫu nhiên. Sắp xếp được theo thời gian, dễ đọc qua điện thoại, không chứa dữ liệu cá nhân.
- Xuất hiện ở: trang chặn (HTML tùy biến theo policy, tiếng Việt/Anh), body JSON cho API (`{"error":"blocked","block_id":"STR-…"}`), header `X-Strata-Block-Id`, access log của proxy, event store.
- Ở chế độ shadow, request đáng lẽ bị chặn cũng có Event ID cùng định dạng (tiền tố `EVT-`), để đánh giá trước khi enforce.

**Rule ID** cố định, không bao giờ tái sử dụng, phân dải theo lớp:

| Dải ID | Lớp |
| --- | --- |
| 100000–199999 | Protocol strict |
| 200000–299999 | Positive model / schema |
| 300000–399999 | Semantic |
| 500000–599999 | Behavior |
| 600000–699999 | Response |
| 700000–799999 | Virtual patch theo CVE |
| 800000–899999 | Rule riêng của tổ chức |
| 900000–999999 | OWASP CRS (giữ nguyên ID gốc) |

**Luồng xử lý khi người dùng báo bị chặn**

1. Người dùng gửi Block ID cho helpdesk.
2. Dán Block ID vào ô tìm kiếm trên UI → mở decision trace: thời điểm, route, IP, identity, connector, rule ID khớp, điểm từng lớp, đoạn input đã normalize (che dữ liệu nhạy cảm).
3. Chọn một trong ba: **Đánh dấu false positive**, **Tạo exception** (điền sẵn phạm vi hẹp nhất: route + field + rule ID, có hạn dùng), hoặc **Chặn IP/identity**.
4. Exception đi qua replay và phê duyệt như mọi thay đổi khác.

**Các màn hình chính**

| Màn hình | Chức năng |
| --- | --- |
| Dashboard | Tỉ lệ chặn, top rule, top route, FP được báo, latency từng lớp |
| Sự kiện | Tìm theo Block ID, IP, route, rule ID, khoảng thời gian; xem decision trace |
| Policy | Form + YAML song song, diff giữa các version, chạy replay, gửi duyệt, canary |
| Exception | Danh sách theo hạn dùng, người tạo, số request đã khớp |
| Rule | Danh mục rule theo dải ID, bật/tắt theo route, lịch sử thay đổi |
| Connector / Node | Trạng thái từng proxy, phiên bản engine, bundle đang chạy |
| Người dùng & quyền | SSO OIDC/LDAP, RBAC (viewer, operator, approver, admin), quy tắc 4 mắt |
| Audit | Ai đổi gì, lúc nào, qua UI, API hay GitOps |

## Pipeline detection

Request đi qua 5 lớp theo thứ tự từ rẻ đến đắt; mỗi lớp cộng điểm vào một anomaly score chung, và chỉ điểm tổng so với ngưỡng của route mới quyết định chặn. Lớp thứ 6 kiểm tra response sau backend.

&#91;embedded content: pipeline detection · 6 lớp\]

Lớp 1 là ngoại lệ duy nhất: request mơ hồ (CL+TE, header trùng, encoding lồng) bị chặn ngay mà không cần chấm điểm.

Quy tắc chấm điểm:

- Mỗi detector trả về điểm kèm lý do (field, đoạn input đã normalize, rule).
- Điểm có trọng số theo route: API có schema chặt thì lớp 2 nặng; trang web công khai thì lớp 3–4 nặng.
- Ngưỡng `challenge` và `block` cấu hình riêng từng route.
- Ngắt sớm: điểm đã vượt ngưỡng `block` thì bỏ qua các lớp sau để tiết kiệm CPU.
- ML chỉ được cộng điểm khi tổng nằm trong vùng xám (giữa hai ngưỡng), và trọng số của nó hiển thị trong decision trace.

## Mô hình policy & rule

Một policy Strata gồm 9 khối, kế thừa từ một template và chỉ ghi phần khác biệt; mọi khối đều sửa được trên UI dạng form, xem được dạng YAML.

| Khối | Nội dung | Tham chiếu |
| --- | --- | --- |
| Template | `base`, `strict`, `api` (OpenAPI), `wordpress`, `php-legacy`…; policy kế thừa rồi ghi đè | Base/default/strict template của F5 |
| General | Chế độ transparent / blocking, ngưỡng điểm, XFF trusted headers, server technologies, charset | F5 general settings |
| Entities | URL, parameter, header, cookie, method, filetype; content profile JSON, XML, GraphQL, gRPC (IDL); OpenAPI. Mỗi entity có kiểu dữ liệu, độ dài, kiểm tra signature/metachar, cờ staging | F5 entities, content profiles |
| Violations | Danh mục cố định (ví dụ `PROTO_CL_TE_CONFLICT`, `SCHEMA_UNKNOWN_FIELD`, `EVASION_DOUBLE_ENCODING`, `SIG_MATCH`, `DATA_LEAK_CCCD`); mỗi cái có cờ alarm, block, learn và trọng số điểm | F5 violations + alarm/block |
| Signature sets | Chọn signature theo loại tấn công, độ chính xác, mức rủi ro, server technology, tag CVE/OWASP | F5 signature sets, Cloudflare tags |
| Custom rules | Biểu thức theo phase, gắn label, chọn action | Cloudflare expression, AWS label |
| Overrides | Điều kiện → đổi cấu hình (ví dụ tắt signature X cho `/upload` khi `Content-Type` là multipart) | F5 override rules |
| Exceptions | Phạm vi hẹp (route + field + rule ID), có hạn dùng, ưu tiên cao hơn override | Cloudflare exceptions |
| Response | Allowed response codes, response signatures, data guard (che dữ liệu nhạy cảm) | F5 response signatures, data guard |

Action hỗ trợ: `allow`, `log`, `challenge`, `block`, `rate_limit`, `skip` (bỏ qua phase/nhóm rule), `label`.

**Thứ tự đánh giá (phase)**

1. `pre`: IP allow/deny list, geolocation, do-nothing path, custom rule đầu (được `skip` các phase sau).
2. `protocol`: HTTP compliance, evasion techniques, request mơ hồ.
3. `rate`: rate limit, brute force theo identity.
4. `managed`: entity/schema, semantic, signature (gồm CRS), threat campaign, bot signature.
5. `custom-post`: custom rule dùng label và điểm từ các phase trước.
6. `decision`: áp exception → override → so điểm với ngưỡng.
7. `response`: allowed codes, response signatures, data guard.

**Ví dụ custom rule**

```yaml
kind: CustomRule
id: 800123
name: chan-admin-ngoai-vpn
phase: custom-post
expression: >
  http.path starts_with "/admin"
  and not ip.src in $vpn_ranges
  and strata.score.total >= 3
action: block
labels: [admin-exposure]
staging: { until: 2026-11-01 }   # chỉ ghi log đến hết ngày này
```

**Ví dụ metadata một signature**

```yaml
kind: Signature
id: 310042
name: SQLi UNION SELECT với comment lồng
attackType: sql-injection
accuracy: high          # low | medium | high
risk: high
systems: [mysql, postgresql]
appliesTo: [parameter, json-value, header, cookie]
tags: [owasp-a03]
revision: 2026-10-01
```

**Cập nhật signature**: gói signature tách khỏi engine, có version riêng, cập nhật không cần nâng engine. Signature mới hoặc vừa sửa tự vào staging 7 ngày (cấu hình được), chỉ ghi log. Hết staging, nếu không có báo cáo FP thì tự enforce; nếu có thì chờ người duyệt.

**Ngân sách chi phí**: compiler tính cost unit cho từng rule (loại matcher, số entity, độ sâu parse). Policy vượt ngân sách bị từ chối khi lưu, UI chỉ ra rule tốn nhất.

**Kế thừa**: policy cấp host và cấp route được merge (route ghi đè từng khối, không thay toàn bộ); UI hiển thị policy hiệu lực sau merge cho từng route.

## Danh mục tính năng

Danh mục dưới đây đặt ngang hàng với bộ tính năng của F5 WAF for NGINX; cột Phase khớp với lộ trình MVP.

| Tính năng | Mô tả trong Strata | Phase |
| --- | --- | --- |
| HTTP compliance | Kiểm tra tuân thủ HTTP, bật/tắt từng check; request mơ hồ luôn chặn | 0 |
| Evasion techniques | Directory traversal, escape sai, encoding lồng, Unicode bất thường | 0 |
| Allowed methods | Danh sách method cho phép theo policy và theo URL | 0 |
| IP lists, do-nothing path | Nhiều danh sách allow/deny; bỏ qua inspect cho path chỉ định | 0 |
| XFF trusted headers | Lấy IP thật từ header tin cậy theo dải proxy | 0 |
| Block page, Block ID | Trang chặn HTML/JSON tùy biến, Block ID | 0 |
| URL, parameter, header, cookie entities | Kiểu, độ dài, kiểm tra signature/metachar theo từng entity, wildcard | 1 |
| JSON / XML content profile | Phát hiện nội dung hỏng, độ sâu, số phần tử, kích thước | 1 |
| OpenAPI enforcement | Từ chối endpoint, method, field không khai báo | 1 |
| Filetypes | Cho phép / cấm phần mở rộng, giới hạn theo filetype | 1 |
| Override rules, exceptions | Đổi cấu hình theo điều kiện; exception hẹp có hạn dùng | 1 |
| Custom rules (biểu thức) | Biểu thức theo phase, label, action | 1 |
| Attack signatures + signature sets | Signature riêng + CRS, metadata, chọn theo server technology | 2 |
| Time-based signature staging | Signature mới chỉ ghi log trong N ngày | 2 |
| Semantic detectors | SQLi, XSS, CMDi, SSRF, path traversal, template injection | 2 |
| Response: allowed codes, response signatures | Kiểm tra mã trả về và nội dung response | 2 |
| Data guard | Phát hiện và che CCCD, số thẻ, token, pattern tùy chỉnh trong response | 2 |
| Cookie integrity | Ký cookie, đặt HttpOnly / Secure / SameSite | 2 |
| JWT protection | Kiểm tra thuật toán, chữ ký, claim, hạn dùng | 2 |
| GraphQL protection | Độ sâu, độ phức tạp query, introspection | 3 |
| gRPC protection | Parse theo IDL, cấm field lạ, giới hạn kích thước | 3 |
| Brute force | Theo endpoint đăng nhập, theo identity/IP/thiết bị | 3 |
| Bot signatures + fingerprint | Nhận diện bot qua chữ ký, JA4/HTTP2 fingerprint, challenge | 3 |
| Geolocation, IP intelligence | Chặn/tính điểm theo quốc gia, uy tín IP từ feed | 3 |
| Threat campaigns | Chữ ký chiến dịch tấn công đang diễn ra, cập nhật theo feed | 3 |

## Control plane & nguồn cấu hình

Control plane là nguồn dữ liệu cấu hình duy nhất: cấu hình lưu trong PostgreSQL, có version, audit và phê duyệt; UI, REST/gRPC API, CLI và GitOps đều chỉ là các kênh đọc ghi vào cùng kho này.

Bốn đối tượng cấu hình chính:

- **Policy**: gắn vào một site/route trên một nhóm connector; chọn profile backend, ngưỡng điểm, chế độ (shadow / canary / enforce), fail-open hay fail-closed, mẫu trang chặn.
- **API schema**: tải OpenAPI lên, hoặc duyệt schema tự học từ traffic.
- **Rule set**: rule riêng (dải 800000) + phiên bản CRS được pin, bật/tắt rule theo route.
- **Exception**: phạm vi hẹp (route + field + rule ID), bắt buộc có người chịu trách nhiệm và hạn dùng; thường sinh từ một Block ID.

Các kênh thay đổi cấu hình:

| Kênh | Dành cho | Ghi chú |
| --- | --- | --- |
| Web UI | Vận hành hằng ngày, helpdesk, bảo mật | Kênh chính; form + YAML song song |
| REST/gRPC API, CLI `strata` | Tự động hóa, script, CI | Cùng quyền RBAC như UI |
| GitOps (tùy chọn) | Team muốn quản lý bằng Git/ArgoCD | Đồng bộ qua API: import YAML thành bản nháp chờ duyệt, export định kỳ ra Git làm bản sao; không bao giờ ghi thẳng vào connector |
| Kubernetes CRD (tùy chọn) | Cluster dùng Gateway API | Controller chuyển CRD thành lời gọi API, kết quả hiển thị trên UI |

Mọi kênh đều tạo ra cùng một đối tượng có version; UI luôn hiển thị nguồn của thay đổi (UI, API, GitOps, CRD) và cho phép khóa một policy chỉ được sửa qua một kênh để tránh ghi đè lẫn nhau.

Định dạng YAML dùng chung cho xuất/nhập trên UI, API và GitOps, ví dụ policy cho API eKYC:

```yaml
kind: Policy
name: ekyc-api
target:
  connectorGroup: kong-prod       # nhóm node Kong / NGINX / Envoy...
  host: api.example.vn
  pathPrefix: /ekyc/
backendProfile: go-net-http
mode: canary                      # shadow | canary | enforce
canaryPercent: 10
failMode: closed
blockPage: { template: default-vi, json: true, status: 403 }
limits:
  maxBodyBytes: 2097152
  cpuBudgetMicros: 800
layers:
  protocol: strict
  schema: { ref: ekyc-openapi-v3, unknownFields: block }
  semantic: { sqli: on, xss: on, cmdi: on, ssrf: on }
  crs: { version: 4.25-lts, paranoia: 2 }
  behavior: { identity: header:x-client-id, ratePerMin: 120 }
  response: { dlp: [cccd, jwt], dbErrors: on }
threshold:
  block: 10
  challenge: 6
```

Khi một thay đổi được duyệt, control plane biên dịch thành bundle bất biến, ký bằng cosign, đánh số phiên bản và đẩy xuống connector qua mTLS. Rollback là một nút bấm trên UI: chọn version cũ và áp dụng lại.

## Vận hành

Đây là phần tạo khác biệt lớn nhất: Strata coi việc thay đổi rule như deploy code, có kiểm thử và rollout dần.

**Vòng đời một thay đổi rule**

1. Sửa policy hoặc rule trên UI (hoặc qua API/GitOps) → tạo **bản nháp**.
2. Control plane tự chạy **replay** trên mẫu traffic 7 ngày gần nhất (đã ẩn danh hóa) + bộ payload tấn công; hiển thị trên UI FP/FN thay đổi theo từng route.
3. **Người duyệt** thứ hai phê duyệt (quy tắc 4 mắt cho môi trường production).
4. Policy chạy **shadow** tối thiểu 24 giờ; sự kiện có Event ID để xem trước.
5. **Canary** 1% → 10% → 50% → 100%, tự rollback nếu tỉ lệ chặn hoặc lỗi 5xx vượt ngưỡng.
6. **Enforce**.

**Decision trace**: mỗi request bị chặn có một Block ID và một bản ghi gồm route, profile, điểm từng lớp, rule khớp, đoạn input đã normalize (che dữ liệu nhạy cảm) và request ID để đối chiếu với log backend.

**Exception hẹp**: từ một Block ID, UI (nút Tạo exception) hoặc CLI `strata except <block-id>` sinh exception nhỏ nhất (route + field + rule ID) dưới dạng bản nháp, đi qua replay và phê duyệt; exception bắt buộc có hạn dùng.

**Virtual patching**: feed CVE → ánh xạ sang route bị ảnh hưởng qua SBOM của service → sinh rule nhắm đúng route, đi qua cùng pipeline nhưng rút ngắn shadow.

**Quan sát**: metrics OpenTelemetry (tỉ lệ chặn, FP được báo, latency từng lớp) đẩy sang Prometheus/VictoriaMetrics; log quyết định ra Fluent Bit → OpenSearch.

## An toàn của chính WAF

WAF parse mọi input không tin cậy trên đường đi của toàn bộ traffic, nên nó phải được bảo vệ chặt hơn ứng dụng đứng sau.

- **Memory-safe**: toàn bộ parse và detection nằm trong `libstrata` (Rust), cấm `unsafe` ngoài lớp FFI đã review. Connector NGINX, Apache, Kong chỉ là lớp mỏng chuyển buffer vào thư viện, không tự parse input.
- **Thời gian tuyến tính**: RE2/Hyperscan; giới hạn độ sâu decode lồng nhau (mặc định 3), độ sâu JSON, số tham số, kích thước body.
- **Budget CPU mỗi request**: vượt budget → xử lý theo `failMode` của route, ghi metric.
- **Cô lập lỗi**: connector in-process bắt panic tại ranh giới FFI và fail theo `failMode`; chế độ process riêng (SPOA, ext\_proc) chạy non-root, read-only rootfs.
- **Fuzz liên tục**: cargo-fuzz cho parser, fuzz riêng từng connector, differential fuzzing Strata vs các backend thật; mỗi crash/khác biệt thành test hồi quy.
- **Chuỗi cung ứng**: build tái lập, SBOM, ký package, image và bundle bằng cosign.
- **Control plane**: SSO + RBAC, quy tắc 4 mắt, audit bất biến; connector không mở port quản trị, chỉ nhận bundle có chữ ký qua mTLS.

## Tech stack & cấu trúc repo

Lõi engine dùng Rust vì cần memory-safe và một thư viện C ABI dùng chung cho 5 proxy; control plane, CLI và agent dùng Go để tận dụng kinh nghiệm sẵn có của team.

| Thành phần | Ngôn ngữ / công nghệ | Lý do |
| --- | --- | --- |
| Lõi engine `libstrata` | Rust, Hyperscan + regex crate, C ABI | Memory-safe, tuyến tính, nhúng được vào mọi proxy |
| Connector NGINX, Apache | Module C mỏng | Chuẩn module của hai proxy này |
| Connector Kong | Plugin Lua + LuaJIT FFI | In-process, không thêm hop mạng |
| Connector Envoy | proxy-wasm (Rust) hoặc ext\_proc (Go) | Hai kiểu tích hợp chính thức của Envoy |
| Connector HAProxy | SPOA agent (Go hoặc Rust) | Cách tích hợp chuẩn của HAProxy |
| Lớp CRS | Biên dịch SecLang → IR riêng | Giữ tương thích CRS, không mang theo engine cũ |
| Control plane API | Go, PostgreSQL | Nguồn cấu hình duy nhất, version, audit |
| Web UI | React + TypeScript | Giao diện quản trị đầy đủ |
| Event store | ClickHouse (hoặc OpenSearch) | Tra cứu Block ID và thống kê nhanh trên khối lượng lớn |
| CLI | Go, Cobra + Bubble Tea | `strata trace <block-id>`, `strata except`, `strata replay` |
| Replay | Rust (dùng chung engine) + Parquet | Replay hàng triệu request trước khi áp dụng |
| Telemetry | OpenTelemetry → Prometheus/VictoriaMetrics | Theo stack đang dùng |

Cấu trúc monorepo:

```
strata/
├── engine/              # Rust: libstrata (parser, normalizer, detectors, scoring, Block ID)
│   ├── parser/          # HTTP/1.1, HTTP/2, multipart, JSON, XML strict
│   ├── profiles/        # go-net-http, spring, php, node, django
│   ├── detectors/       # protocol, schema, semantic, crs-ir, behavior, response
│   ├── ffi/             # C ABI + header strata.h
│   └── fuzz/            # cargo-fuzz targets + differential harness
├── connectors/
│   ├── nginx/           # ngx_http_strata_module
│   ├── apache/          # mod_strata
│   ├── haproxy-spoa/
│   ├── envoy-wasm/
│   ├── envoy-extproc/
│   └── kong/            # plugin Lua + FFI
├── control-plane/       # Go: API, RBAC, audit, bundle compiler/signer, replay orchestrator
├── ui/                  # React web UI
├── gitops-sync/         # tùy chọn: import/export YAML, CRD controller
├── cli/                 # Go: strata CLI
├── rules/               # rule riêng + CRS pin
├── corpus/              # benign + attack datasets (đã ẩn danh)
├── conformance/         # test bắt buộc 5 connector cho kết quả giống nhau
├── deploy/              # Helm charts, package deb/rpm
└── docs/
```

## Lộ trình MVP & chỉ số thành công

MVP mất khoảng 7 tháng để enforce trên API eKYC đầu tiên; mỗi phase chỉ bắt đầu khi gate trước đó đạt đủ tiêu chí.

&#91;embedded content: lộ trình MVP · 4 phase, 3 gate\]

Các gate dùng chính 5 mục tiêu ở phần đầu làm tiêu chí; Gate 3 là mốc quyết định đưa Strata vào đường đi thật của production. Thời gian là ước lượng cho team 2–3 kỹ sư.

## Rủi ro & quyết định còn mở

| Rủi ro | Tác động | Giảm thiểu |
| --- | --- | --- |
| Biên dịch SecLang → IR không tương thích 100% CRS | Mất độ phủ hoặc FP lạ | Chạy song song Coraza ở shadow, so sánh kết quả trên cùng traffic |
| 5 connector cho kết quả khác nhau (khác cách proxy buffer body, decode header) | Lỗ hổng chỉ có ở một proxy | Bộ conformance chung, chạy trong CI cho mọi connector, mọi phiên bản proxy được hỗ trợ |
| Module C cho NGINX/Apache có lỗi bộ nhớ | WAF thành điểm tấn công | Giữ connector C thật mỏng, ASan + fuzz riêng, mọi parse nằm trong Rust |
| Ma trận phiên bản proxy lớn (NGINX, Apache, HAProxy, Envoy, Kong) | Tốn công build và kiểm thử | Chỉ hỗ trợ các bản LTS/stable còn được vá; build package tự động |
| Strict parser chặn nhầm client cũ / không chuẩn | FP ở giai đoạn đầu | Bật theo route, chế độ shadow dài hơn cho route public |
| Replay traffic và event store chứa dữ liệu cá nhân (eKYC) | Rủi ro pháp lý | Ẩn danh hóa tại connector, chỉ giữ cấu trúc + hash; thời hạn lưu cấu hình được; cần duyệt của bộ phận pháp chế |
| Control plane sập | Không đổi được cấu hình | Connector chạy tiếp với bundle đã cache; control plane HA với PostgreSQL Patroni |
| Thiếu nhân lực Rust | Chậm tiến độ | Bắt đầu nhỏ: parser + protocol layer; control plane, UI, agent dùng Go/TypeScript |

Quyết định còn mở:

- [ ] Tên dự án cuối cùng và giấy phép (đề xuất Apache-2.0)
- [ ] Mã nguồn mở ngay từ đầu hay nội bộ trước rồi công bố?
- [ ] Connector đầu tiên: Kong hay NGINX (đề xuất làm song song vì dùng chung `libstrata`)?
- [ ] Event store: ClickHouse hay tái sử dụng OpenSearch đang có?
- [ ] Định dạng và nội dung trang chặn mặc định (logo, hotline, hướng dẫn gửi Block ID)
- [ ] Nguồn traffic replay đầu tiên và quy trình phê duyệt ẩn danh hóa

## Nguồn tham khảo

- [F5 WAF for NGINX – Technical specifications (danh sách tính năng policy)](https://docs.nginx.com/waf/fundamentals/technical-specifications)
- [F5 WAF for NGINX – Terminology (alarm, block, violation, transparent mode)](https://docs.nginx.com/waf/fundamentals/terminology/)
- [F5 WAF for NGINX – Response signatures](https://docs.nginx.com/waf/policies/response-signatures)
- [F5 WAF for NGINX – Tích hợp NGINX Gateway Fabric (compiler, bundle, PLM)](https://docs.nginx.com/nginx-gateway-fabric/waf-integration/overview/)
- [Ví dụ policy NGINX App Protect và trang chặn có Support ID](https://github.com/fbchan/nginx-app-protect-policy)
- [Cloudflare – Managed rulesets, overrides, exceptions](https://developers.cloudflare.com/waf/managed-rulesets)
- [Cloudflare WAF – Get started (attack score, bot score)](https://developers.cloudflare.com:2083/waf/get-started)
- [AWS WAF – Rule group, WCU, label](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wafv2-rulegroup.html)
- [AWS WAF – Best practices: scope-down, thứ tự rule](https://aws.github.io/aws-security-services-best-practices/guides/waf/configuring-waf-rules/docs/)

# Strata — Kế hoạch triển khai tuần 3–22

Oct 10, 2026 · @hieuny

## Tổng quan & nhân sự

Kế hoạch nối tiếp tuần 1–2 (khung module, ABI, PoC Hyperscan + mmap) và đi qua 3 giai đoạn: **A** tới shadow (tuần 3–10), **B** tới enforce 100% (tuần 11–16), **C** hoàn thiện v1 (tuần 17–22). Mỗi tuần ghi việc theo luồng, đầu ra kiểm chứng được, và khối việc giao cho Claude Code.

| Ký hiệu | Luồng | Người | Phạm vi |
| --- | --- | --- | --- |
| N | Module NGINX (C) | 1 kỹ sư C/NGINX | `connectors/nginx/` |
| R | libstrata (Rust) | 1 kỹ sư Rust | `engine/`, compiler, replay engine, tokenizer |
| S | Rule & signature | 1 detection engineer (bảo mật) | `rules/`, `corpus/`, gói signature, CRS |
| G1 | Agent + Fleet (Go) | 1 kỹ sư Go | `strata-agent`, Fleet service, GitOps sync |
| G2 | Control plane (Go) | 1 kỹ sư Go | API server, Policy, ingest, Stats |
| F | Web UI | 1 kỹ sư frontend | `ui/` |
| Q | QA / SRE | bán thời gian | lab, CI, kiểm thử tải, vận hành canary |

**Quy ước**

- "Route thí điểm" là 2 route API được chọn chạy thử đầu tiên.
- Mỗi khối 2–3 tuần có một `CLAUDE.md` riêng; phiên Claude Code cho Go/UI tách khỏi phiên C/Rust.
- Việc nào chưa xong cuối tuần thì chuyển sang tuần sau, không cắt bớt bước kiểm thử để kịp mốc.
- Cuối mỗi tuần: demo 15 phút, cập nhật tài liệu thiết kế nếu code thật khác thiết kế.

## Cách dùng file này với Claude Code

File này lưu trong repo tại `docs/plan/plan.md`, cạnh `docs/design/nginx-module.md` và `docs/design/strata-overview.md`. Claude Code đọc file này để biết làm gì, ở đâu, và khi nào là xong.

**Cấu trúc một nhiệm vụ**

- **Mã**: `W05-N-01` = tuần 5, luồng N, nhiệm vụ 1. Dùng làm tên nhánh và tiêu đề PR.
- **Thư mục**: nơi được phép sửa code. Không sửa ngoài các thư mục này, trừ file test và tài liệu.
- **Làm**: phạm vi chính xác của nhiệm vụ.
- **Xong khi**: điều kiện kiểm chứng được, thường là lệnh hoặc test phải pass. Chưa đạt thì chưa xong.
- **Cần trước**: nhiệm vụ phải xong trước. Nếu chưa xong thì dừng lại, báo người giao việc, không tự làm thay.
- **Đọc**: mục trong tài liệu thiết kế phải đọc trước khi code.

**Câu lệnh mẫu giao việc**

> Đọc docs/plan/plan.md và các mục ghi ở dòng "Đọc" của W05-N-01. Nêu kế hoạch (file sẽ sửa, hàm sẽ thêm, test sẽ viết) và chờ tôi duyệt. Sau đó làm W05-N-01, chạy đủ các lệnh ở dòng "Xong khi" và báo kết quả.

**Quy tắc cho Claude Code**

- Chỉ làm đúng mã nhiệm vụ được giao; không làm trước nhiệm vụ của tuần sau.
- Không đổi interface chung (`engine/ffi/strata.h`, `proto/**/*.proto`, OpenAPI, định dạng bundle, định dạng rule) nếu nhiệm vụ không ghi rõ; cần đổi thì dừng lại và đề xuất.
- Mỗi nhiệm vụ kèm test tự động; CI phải xanh.
- Code C: không parse input, kiểm tra độ dài trước mọi copy, không I/O trên đường đi của request.
- Code Rust: không `unsafe` ngoài `engine/ffi/`; chỉ dùng regex thời gian tuyến tính.
- Tên ví dụ trong code và test dùng giá trị trung tính (`example-api`, `api.example.test`).

**Thư mục trong repo**

| Thư mục | Nội dung | Luồng |
| --- | --- | --- |
| `engine/` | libstrata (Rust): parser, detector, scoring, compiler, FFI | R |
| `connectors/nginx/` | `ngx_http_strata_module` (C) và test `t/` | N |
| `agent/` | `strata-agent` (Go) | G1 |
| `control-plane/` | API server, Policy, Fleet, Event ingest, Stats (Go) | G1, G2 |
| `proto/` | file `.proto` dùng chung | G1, G2 |
| `ui/` | Web UI (React, TypeScript) | F |
| `rules/`, `corpus/` | rule và corpus test | S |
| `tools/` | `strata-rules`, `strata-import-crs`, `strata-import-sigma`, `strata-import-et` | S |
| `tests/e2e/`, `deploy/` | test end-to-end, lab, staging, gói cài | Q |

## Luồng S · Bộ luật & signature

Engine chỉ có giá trị khi có luật. Luồng S chạy song song từ tuần 3 để tới tuần 10 có **gói signature v0** đủ dùng cho shadow, và tới tuần 15 có chất lượng đủ để enforce. CRS được đưa lên chạy shadow-compare từ tuần 12, thay vì đợi tới giai đoạn C.

**Thành phần**

- **Định dạng rule** theo mục Mô hình policy & rule trong tài liệu thiết kế tổng thể (YAML, Rule ID theo dải, metadata loại tấn công, độ chính xác, mức rủi ro, server technology, tag).
- **Repo `rules/`**: mỗi rule một file, bắt buộc kèm mẫu phải khớp và mẫu không được khớp; CI chạy lint, biên dịch, tính cost unit, đo FP/recall trên corpus.
- **Corpus `corpus/`**: benign (traffic tổng hợp sinh từ OpenAPI của route thí điểm, sau đó bổ sung traffic thật đã ẩn danh) và attack (bộ payload công khai có giấy phép phù hợp, phân loại theo loại tấn công, cộng các ca bypass tìm được từ fuzz).
- **Gói signature**: version riêng (ví dụ `2026.w45`), ký, có changelog, tách khỏi phiên bản engine; signature mới tự vào staging 7 ngày.

**Nguồn luật và cách dùng**

Chiến lược: lấy **CRS v4 làm nền** cho gói v0 qua bộ nhập tự động, bổ sung bằng nguồn ngoài có giấy phép tương thích, rồi mới viết rule riêng cho phần còn trống. Mọi rule nhập về giữ thông tin nguồn (`source`, `upstream_id`, `upstream_version`, `license`, `author`).

| Nguồn | Giấy phép | Dùng làm gì | Dải Rule ID | Quyết định |
| --- | --- | --- | --- | --- |
| OWASP CRS v4 (4.25 LTS) | Apache-2.0 | Nền của gói signature; bộ test regression (go-ftw) làm ground truth | 900000–999999 (giữ ID gốc) | Dùng, nhập tự động |
| Coraza | Apache-2.0 | Tái dùng parser SecLang (Go) trong bộ nhập; chạy song song để so sánh differential | — | Dùng làm công cụ, không phải nguồn rule |
| PayloadsAllTheThings, SecLists | MIT | Corpus attack cho test FP/recall | — | Dùng cho corpus, không đóng gói vào bundle |
| Sigma (`rules/web`) | DRL 1.1 | Pattern CVE, web shell, công cụ quét | 400000–499999 | Dùng; phải giữ tác giả và hiển thị tác giả khi rule khớp |
| Emerging Threats Open | BSD cho dải SID 2000000–2099999; GPLv2 cho dải 2100000–2103999 | Rule HTTP (URI, User-Agent, header) cho CVE và công cụ tấn công | 400000–499999 | Chỉ nhập dải BSD và chỉ rule HTTP |
| Snort community / Talos | GPLv2 / giấy phép thương mại | — | — | Không đóng gói vào bundle |
| SafeLine | Lõi detection không mở | — | — | Không dùng |
| crawler-user-agents (thay cho OpenAppFilter) | MIT | Danh sách bot, crawler, công cụ quét | 500000–599999 | Dùng |

Cần bộ phận pháp chế xác nhận lại các giấy phép trước khi phát hành gói v1.0.

**Bộ nhập CRS (`strata-import-crs`)**

- Viết bằng Go, đọc file `.conf` bằng ngữ pháp SecLang của dự án CRS (`coreruleset/seclang_parser`; parser của Coraza là package `internal`), xuất IR của Strata; bản CRS ghim trong `tools/strata-import-crs/crs.lock` (4.25.2, kiểm sha256); R chỉ cần cài các operator, transformation và variable trong libstrata.
- Regex: CRS v4 đã tương thích RE2 (không lookaround, không backreference). Mỗi regex được thử biên dịch vào Hyperscan trước; nếu không được hoặc rule cần capture group, dùng crate `regex` của Rust (cũng thời gian tuyến tính); không biên dịch được cả hai thì đánh dấu viết lại thủ công.
- `chain` → điều kiện AND phẳng trong IR.
- Phase SecLang → phase Strata: 1 → PREACCESS (header, URI); 2 → request body; 3 → header filter; 4 → body filter; 5 → log.
- **Transformation** cần cài trong libstrata: `urlDecodeUni`, `htmlEntityDecode`, `jsDecode`, `cssDecode`, `lowercase`, `removeNulls`, `removeWhitespace`, `compressWhitespace`, `cmdLine`, `normalizePath`, `utf8toUnicode`, `base64Decode`…
- **Operator**: `@rx`, `@pm` / `@pmFromFile` (đưa vào Hyperscan dạng literal), `@detectSQLi` / `@detectXSS` (tokenizer do R port), `@validateByteRange`, `@validateUrlEncoding`, `@validateUtf8Encoding`, `@ipMatch`, so sánh số.
- **Action**: `setvar` cho anomaly scoring ánh xạ sang điểm của Strata (mức nghiêm trọng của CRS → điểm), mức paranoia, `ctl:ruleRemoveById` → exception, `skipAfter` → nhảy trong cây quyết định.
- Báo cáo mỗi lần nhập: số rule nhập tự động, số rule cần viết lại, lý do.

**Tính năng cho rule trong v1** (đều là tính năng chung, áp dụng mọi khách hàng)

| Tính năng | Lợi ích | Nhiệm vụ |
| --- | --- | --- |
| Tắt rule khẩn cấp (kill switch) | Tắt một Rule ID trên toàn bộ node trong vài giây khi chặn nhầm hàng loạt, không phải deploy lại policy | W12-R-02, W12-N-02, W12-G1-02, W12-G2-02 |
| Hai mức tin cậy: `block_alone` / `score` | Rule rất chính xác chặn ngay; rule còn lại chỉ cộng điểm, giảm FP | W08-R-02, W08-S-02 |
| Sức khỏe từng rule | Theo dõi số lần khớp, FP, chi phí CPU; rule FP tăng đột biến tự về staging | W13-R-02, W14-G2-02, W21-F-01 |
| Đo chống bypass bằng biến thể payload | Biết rule bị lách ở đâu trước khi kẻ tấn công biết | W09-S-02, W15-Q-01 |
| Xác minh bot tốt | Crawler lớn chỉ được coi là bot tốt khi IP thuộc dải công bố; giả User-Agent bị tính điểm cao | W18-G2-02, W18-R-02, W18-S-01 |

**Để sau v1 hoặc tùy chọn**

- Ước tính phạm vi ảnh hưởng của rule mới trên traffic mẫu ngay trong CI.
- Pack nhận diện dữ liệu Việt Nam cho data guard (CCCD, CMND, số điện thoại, mã số thuế, tài khoản ngân hàng): là pack tùy chọn, không bật mặc định.
- Virtual patch bán tự động từ nuclei-templates, ưu tiên theo danh sách CVE đang bị khai thác và SBOM.
- Endpoint mồi (decoy) để bắt kẻ tấn công với FP gần bằng 0.
- Đề xuất tuning tự động từ FP lặp lại, kiểm chứng bằng replay.

**Kế hoạch theo tuần**

Nhiệm vụ cụ thể của luồng S nằm trong từng tuần (mã `Wxx-S-yy`) ở các mục Giai đoạn A, B, C bên dưới.

**Chỉ tiêu chất lượng**

| Chỉ số | Gate A (shadow) | Gate B (enforce) | v1 |
| --- | --- | --- | --- |
| FP trên corpus benign ở ngưỡng chặn | dưới 1% | dưới 0,1% | dưới 0,1% |
| Recall trên corpus attack (SQLi, XSS, CMDi, LFI) | từ 70% | từ 90% | không thấp hơn CRS PL2 |
| Rule có đủ mẫu test | 100% | 100% | 100% |
| Thời gian virtual patch CVE nghiêm trọng | — | dưới 24 giờ | dưới 24 giờ |

Nếu chưa tuyển được detection engineer, cần một người từ đội bảo mật làm toàn thời gian từ tuần 3; không nên để kỹ sư Rust kiêm, vì hai việc cùng nằm trên đường găng.

## Giai đoạn A · Tuần 3–10: tới shadow

Mục tiêu: request thật đi qua module trên 2 route thí điểm ở chế độ shadow, mọi sự kiện tra được bằng Block ID trên UI. `CLAUDE.md` theo khối: **A1** = tuần 3–5, **A2** = tuần 6–7, **A3** = tuần 8–10.

### Tuần 3 · Đường đi request và khung các thành phần

- **W03-N-01 · PREACCESS handler**
  - Thư mục: `connectors/nginx/src/`
  - Làm: tạo transaction; gọi `strata_tx_request_line` với `r->unparsed_uri`, `r->uri`, `r->args`; gọi `strata_tx_request_headers` với header lấy từ `r->headers_in.headers`, giữ nguyên thứ tự và bản trùng.
  - Xong khi: `prove connectors/nginx/t/010-preaccess.t` pass; với URI `/a/%2e%2e/b?x=1`, test xác nhận libstrata nhận đúng cả 3 giá trị; header trùng được giữ đủ số lần.
  - Đọc: nginx-module.md › Vòng đời request; Xử lý body › URI và query; Ranh giới FFI.
- **W03-N-02 · Ép đọc body ở enforce**
  - Thư mục: `connectors/nginx/src/`
  - Làm: đọc body theo mẫu đồng bộ/bất đồng bộ; directive `strata_request_body_mode buffer | stream`; `nginx -t` báo lỗi khi `stream` đi cùng policy enforce.
  - Xong khi: `t/020-body-enforce.t` pass: với `proxy_request_buffering off`, payload chặn nằm ở byte 70.000 → trả 403 và upstream mock ghi nhận 0 byte; 7 test đọc body bắt buộc pass trên cả 2 bản NGINX.
  - Cần trước: W03-N-01.
  - Đọc: nginx-module.md › Vòng đời request › Mẫu đọc body; Xử lý body › Request body.
- **W03-R-01 · Lớp protocol v1**
  - Thư mục: `engine/src/detectors/protocol/`
  - Làm: violation cho CL + TE cùng lúc, CL trùng, TE lạ, `%252e`, `%2e%2e/`, `;` trong segment, null byte, ký tự điều khiển; Rule ID dải 100000.
  - Xong khi: `cargo test -p libstrata protocol` có tối thiểu 20 case, mỗi case kiểm đúng Rule ID.
  - Đọc: strata-overview.md › Pipeline detection; Mô hình policy & rule.
- **W03-R-02 · Block ID và đặc tả IR**
  - Thư mục: `engine/src/block_id.rs`, `docs/spec/ir.schema.json`
  - Làm: bộ sinh Block ID bản cuối; JSON Schema cho IR mà compiler nhận (dùng chung với S).
  - Xong khi: test sinh 10 triệu ID không trùng, đúng định dạng `STR-XXXX-XXXX-XXXX-XXXX`; PR schema IR có duyệt của luồng S.
- **W03-S-01 · Định dạng rule và linter**
  - Thư mục: `rules/schema/`, `tools/strata-rules/`
  - Làm: JSON Schema cho rule YAML (gồm `source`, `upstream_id`, `upstream_version`, `license`, `author`); lệnh `strata-rules lint`.
  - Xong khi: `strata-rules lint rules/` chạy trong CI; 10 rule mẫu pass; rule thiếu `license` bị báo lỗi.
  - Đọc: strata-overview.md › Mô hình policy & rule; mục Luồng S của file này.
- **W03-S-02 · Khung bộ nhập CRS và kiểm kê**
  - Thư mục: `tools/strata-import-crs/` (Go; parser SecLang của Coraza nằm trong `internal/` nên không import được, dùng ngữ pháp SecLang chính thức của dự án CRS `coreruleset/seclang_parser`, ANTLR, Apache-2.0)
  - Xong khi: parse được 100% file `.conf` của CRS 4.25 LTS; xuất `docs/crs-inventory.csv` gồm rule ID, phase, operator, transformation, variable, action.
- **W03-G1-01 · Khung agent, proto, enroll**
  - Thư mục: `agent/`, `proto/strata/fleet/v1/`
  - Làm: CLI Cobra; `fleet.proto` + sinh code bằng `buf`; lệnh `enroll` tự sinh khóa và CSR.
  - Xong khi: `buf lint` pass; `strata-agent enroll --dry-run` tạo khóa quyền 0600 và CSR hợp lệ (`openssl req -verify`); proto có duyệt của G2.
  - Đọc: nginx-module.md › Giao thức gRPC agent ↔ control plane.
- **W03-G2-01 · Khung API server, OIDC, RBAC, schema DB**
  - Thư mục: `control-plane/`
  - Xong khi: `/v1/version` trả về qua cả REST và gRPC; test: không token → 401, thiếu quyền → 403 với 4 vai trò; migration up/down sạch trên DB trống.
  - Đọc: nginx-module.md › API quản trị.
- **W03-F-01 · Khung UI**
  - Thư mục: `ui/`
  - Xong khi: đăng nhập/đăng xuất qua Keycloak lab; đổi được tiếng Việt/Anh; gọi `/v1/version` bằng client sinh từ OpenAPI; build chạy trong CI.
  - Đọc: nginx-module.md › Giao diện quản trị.
- **W03-Q-01 · Lab và CI**
  - Thư mục: `deploy/lab/`, cấu hình CI
  - Xong khi: `make lab-up` dựng Keycloak, PostgreSQL, MinIO, ClickHouse, 2 bản NGINX trong dưới 30 phút; CI Go và UI chạy mỗi PR.

**Demo**: request có cả CL và TE bị chặn kèm Block ID; đăng nhập UI; file kiểm kê CRS.

### Tuần 4 · Mốc nối thông end-to-end

- **W04-N-01 · Trang chặn và biến**
  - Thư mục: `connectors/nginx/src/`
  - Làm: trang chặn HTML/JSON chọn theo `Accept`; template mặc định lấy từ bundle, `strata_block_page` ghi đè; 7 biến `$strata_*`.
  - Xong khi: `t/030-block.t` pass: JSON đúng mẫu, có `X-Strata-Block-Id` và `Cache-Control: no-store`; chuỗi `<script>` trong URL không xuất hiện trong trang chặn; 7 biến có giá trị trong access log.
  - Đọc: nginx-module.md › Trang chặn, Block ID & sự kiện; Directive & biến.
- **W04-N-02 · Nạp bundle từ file khi khởi động**
  - Thư mục: `connectors/nginx/src/ngx_http_strata_bundle.c`
  - Xong khi: NGINX chạy với bundle do `strata-compile` tạo; sửa 1 byte bundle → `nginx -t` báo lỗi chữ ký.
  - Cần trước: W04-R-01.
- **W04-R-01 · Compiler v0 và `strata_engine_map`**
  - Thư mục: `engine/compiler/`, binary `strata-compile`
  - Làm: IR/YAML → bundle (header, section căn lề 4 KB, chữ ký Ed25519) theo kết quả PoC; `strata_engine_map` dùng trực tiếp vùng nhớ, không copy.
  - Xong khi: bundle từ 10 rule mẫu nạp được; sửa 1 byte → kiểm chữ ký thất bại; test đo bộ nhớ chứng minh không copy dữ liệu bundle.
  - Đọc: nginx-module.md › Bundle & hot reload › Định dạng bundle.
- **W04-S-01 · Corpus v0 và harness test**
  - Thư mục: `corpus/`, `tools/strata-rules/`
  - Làm: corpus attack từ PayloadsAllTheThings, SecLists (có nhãn loại tấn công và file NOTICE); chuyển test go-ftw của CRS sang định dạng test Strata; lệnh `strata-rules test`.
  - Xong khi: PR sửa rule có báo cáo FP/recall tự động; danh sách test go-ftw không chuyển được kèm lý do.
- **W04-G1-01 · Fleet: Enroll và Connect**
  - Thư mục: `control-plane/fleet/`, `agent/`
  - Xong khi: agent enroll nhận chứng chỉ hạn 24 giờ; dùng lại token lần 2 bị từ chối; trạng thái online/offline của node cập nhật trong tối đa 30 giây.
- **W04-G2-01 · Policy service và lưu bundle**
  - Thư mục: `control-plane/policy/`
  - Xong khi: sửa policy với `etag` cũ → 409; mỗi lần sửa tạo version mới; deploy → bundle và sha256 nằm trên MinIO.
- **W04-F-01 · Policy (chỉ đọc) và danh sách node**
  - Thư mục: `ui/`
  - Xong khi: hiển thị dữ liệu thật từ API, có trạng thái online của node.
- **W04-Q-01 · Script end-to-end**
  - Thư mục: `tests/e2e/`
  - Xong khi: `make e2e` chạy chuỗi tạo policy → compile → agent nhận (tạm qua HTTP) → NGINX chặn request test; chạy hằng đêm trong CI.

**Demo**: mốc end-to-end chạy từ một lệnh.

### Tuần 5 · Bundle và hot reload

- **W05-N-01 · Control file và hot reload**
  - Thư mục: `connectors/nginx/src/ngx_http_strata_bundle.c`
  - Làm: mmap `/run/strata/control`; timer có độ lệch ngẫu nhiên; task thread pool (`open`, `mmap`, `madvise`, kiểm chữ ký, `strata_engine_map`); đổi engine có đếm tham chiếu; master map bundle trước `fork`.
  - Xong khi: đổi generation → mọi worker dùng bản mới trong tối đa 2 giây; đổi bundle 100 lần dưới tải wrk → 0 lỗi 5xx; `strace` không thấy syscall I/O trong event loop khi không có bundle mới; ASan sạch.
  - Đọc: nginx-module.md › Bundle & hot reload.
- **W05-R-01 · Zero-copy và transformation đợt 1**
  - Thư mục: `engine/`
  - Làm: cấu trúc offset (dạng rkyv); section Hyperscan theo kết quả PoC; transformation `urlDecodeUni`, `htmlEntityDecode`, `lowercase`, `removeNulls`, `compressWhitespace`, `normalizePath`.
  - Xong khi: đo PSS cho thấy 32 worker dùng chung phần bundle; transformation khớp 100% test vector so với Coraza.
- **W05-S-01 · Bộ nhập CRS v0 và pack protocol**
  - Thư mục: `tools/strata-import-crs/`, `rules/protocol/`
  - Làm: nhập rule CRS chỉ dùng `@rx`, `@pm` và transformation đợt 1; khoảng 40 rule protocol dải 100000.
  - Xong khi: báo cáo tỉ lệ rule CRS nhập tự động; mỗi rule protocol có mẫu khớp/không khớp; FP bằng 0 trên corpus benign.
  - Cần trước: W05-R-01 (transformation).
- **W05-G1-01 · FetchBundle, ghi nguyên tử, control file**
  - Thư mục: `agent/`
  - Xong khi: ngắt mạng giữa chừng → tải tiếp từ offset; `kill -9` agent khi đang ghi → không có file hỏng; từ chối thư mục bundle trên NFS; trạng thái `VERIFIED` / `ACTIVE` / `FAILED` lên control plane.
  - Đọc: nginx-module.md › Giao thức gRPC › Phân phối bundle.
- **W05-G2-01 · BundleAvailable và rollout theo đợt**
  - Thư mục: `control-plane/fleet/`, `control-plane/policy/`
  - Xong khi: deploy → 3 node nhận theo đúng thứ tự đợt; 1 node `FAILED` → dừng đợt; OpenAPI của Event API được merge để F dùng mock.
- **W05-F-01 · Trang Sự kiện (mock)**
  - Thư mục: `ui/`
  - Xong khi: tìm theo Block ID, lọc theo thời gian/IP/action, mở trang chi tiết với dữ liệu mock.
- **W05-Q-01 · Test hot reload dưới tải**
  - Xong khi: báo cáo p99 trong lúc đổi bundle, lưu ở `docs/reports/`.

**Demo**: đổi policy trên API → NGINX dùng bundle mới trong dưới 10 giây, không reload.

### Tuần 6 · Đường đi response và sự kiện

- **W06-N-01 · Response path**
  - Thư mục: `connectors/nginx/src/ngx_http_strata_filter.c`
  - Làm: header filter (allowed codes, `filter_need_in_memory`); body filter theo quy tắc buffer; data guard; đặt filter trước gzip bằng `ngx_module_order`.
  - Xong khi: CCCD trong JSON response bị che; response gzip vẫn được inspect; file tĩnh qua sendfile được inspect khi bật; response 50 MB không làm bộ nhớ tăng liên tục; ASan sạch.
  - Đọc: nginx-module.md › Xử lý body › Response body.
- **W06-R-01 · Lớp response và tokenizer**
  - Thư mục: `engine/src/detectors/`
  - Làm: allowed codes, chữ ký lỗi DB, che CCCD/JWT; port tokenizer SQLi/XSS kiểu libinjection sang Rust.
  - Xong khi: 15 case response pass; tokenizer khớp tối thiểu 99% bộ test gốc của libinjection; fuzz 1 giờ không panic.
- **W06-S-01 · Nhập nhóm injection của CRS**
  - Thư mục: `tools/strata-import-crs/`, `rules/crs/`
  - Làm: nhóm 930, 931, 932, 933, 941, 942, 944; `@detectSQLi` / `@detectXSS` qua tokenizer; ánh xạ anomaly scoring.
  - Xong khi: test go-ftw của các nhóm này pass tối thiểu 90%; danh sách rule chưa nhập được kèm lý do.
  - Cần trước: W06-R-01.
- **W06-G1-01 · Sự kiện từ worker tới control plane**
  - Thư mục: `agent/`
  - Làm: nhận protobuf từ event socket; `PushEvents` có spool 2 GB, `seq` và ack; exporter Prometheus đọc metrics từ shared memory.
  - Xong khi: tắt control plane 10 phút → không mất sự kiện khi nối lại; lô trùng `seq` bị bỏ; metrics hiện trên Grafana lab.
- **W06-G2-01 · Event ingest và API sự kiện**
  - Thư mục: `control-plane/ingest/`, `control-plane/api/`
  - Làm: ingest → ClickHouse bảng `events` v1; `GET /v1/events/{block_id}`, `POST /v1/events:search`.
  - Xong khi: 10.000 sự kiện/giây không tồn đọng; tra Block ID dưới 1 giây trên 10 triệu dòng.
- **W06-F-01 · Trang Sự kiện nối API thật**
  - Thư mục: `ui/`
  - Xong khi: request bị chặn trên lab tra được trên UI, xem được decision trace.
- **W06-Q-01 · Kiểm tra mất sự kiện**
  - Xong khi: khởi động lại agent khi đang có tải → số sự kiện gửi đi bằng số sự kiện ClickHouse nhận.

**Demo**: chặn trên NGINX → tra Block ID trên UI trong dưới 5 giây.

### Tuần 7 · Fail mode, CPU budget, độ bền

- **W07-N-01 · Fail mode, event sink, RST\_STREAM**
  - Thư mục: `connectors/nginx/src/`
  - Làm: ma trận fail mode open/closed; truyền `strata_cpu_budget`; interface `strata_event_sink_t` (bản cài đặt Unix socket); bộ đếm metrics trong shared memory; `strata_tx_free` idempotent; giữ request sống khi có task thread pool.
  - Xong khi: test cho 4 loại sự cố × 2 fail mode pass; stream HTTP/2 bị RST giữa lúc gửi body → không leak (ASan); internal redirect không inspect lại và không đếm metric 2 lần.
  - Đọc: nginx-module.md › Hiệu năng, tài nguyên & fail mode; Trang chặn, Block ID & sự kiện › Giao diện gửi sự kiện.
- **W07-R-01 · CPU budget hợp tác và cô lập lỗi**
  - Thư mục: `engine/`
  - Làm: Hyperscan quét theo khối 8 KB; parser kiểm đồng hồ theo số token; trả `STRATA_E_BUDGET`; `catch_unwind` cho mọi hàm FFI; tách module tối thiểu (protocol, IP list, rate limit) cho chế độ giảm cấp.
  - Xong khi: payload bệnh lý 1 MB → phần vượt budget dưới 100 µs; panic được tiêm → trả `STRATA_E_INTERNAL`, worker không sập.
- **W07-R-02 · Transformation và operator đợt 2**
  - Thư mục: `engine/`
  - Làm: `jsDecode`, `cssDecode`, `cmdLine`, `utf8toUnicode`, `base64Decode`; `@validateByteRange`, `@validateUrlEncoding`, `@validateUtf8Encoding`, `@ipMatch`, so sánh số.
  - Xong khi: khớp 100% test vector so với Coraza.
- **W07-S-01 · Nhập Sigma, ET Open, danh sách bot**
  - Thư mục: `tools/strata-import-sigma/`, `tools/strata-import-et/`, `rules/`
  - Làm: Sigma `rules/web` và ET Open (chỉ SID 2000000–2099999, chỉ rule HTTP) vào dải 400000; crawler-user-agents vào dải 500000; virtual patch dải 700000 cho stack của route thí điểm.
  - Xong khi: mọi rule nhập có `author`, `license`, `upstream_id`; importer ET từ chối SID ngoài dải BSD (có test); sự kiện của rule Sigma hiển thị tác giả.
  - Đọc: mục Luồng S › Nguồn luật và cách dùng.
- **W07-G1-01 · Độ bền agent**
  - Thư mục: `agent/`
  - Làm: kết nối lại có backoff + jitter; gia hạn chứng chỉ khi còn 1/3 thời hạn; xử lý `Command` (`ForceShadow`, thu chẩn đoán).
  - Xong khi: cắt mạng 5 phút bằng toxiproxy → tự nối lại; chứng chỉ được gia hạn đúng lúc; `ForceShadow` áp dụng trên node trong tối đa 5 giây.
- **W07-G2-01 · Signer KMS, cost unit, điều khiển rollout**
  - Thư mục: `control-plane/compiler/`, `control-plane/fleet/`
  - Xong khi: khóa ký không rời KMS (Vault transit hoặc HSM); policy vượt ngân sách cost unit bị từ chối kèm tên rule tốn nhất; `:pause`, `:resume`, `:abort` rollout có test.
- **W07-F-01 · Trang Fleet**
  - Thư mục: `ui/`
  - Xong khi: hiển thị connector group, node, phiên bản proxy/module/bundle, trạng thái `VERIFIED` → `ACTIVE` cập nhật trực tiếp.
- **W07-Q-01 · Phân tích tĩnh cho C**
  - Xong khi: clang-tidy và CodeQL chạy trong CI cho `connectors/nginx/`; không có cảnh báo mức cao.

**Demo**: tiêm panic và payload nặng → worker không sập, hành vi đúng fail mode; `ForceShadow` từ API áp dụng trong vài giây.

### Tuần 8 · Kiểm thử (1)

- **W08-N-01 · Bộ Test::Nginx đầy đủ**
  - Thư mục: `connectors/nginx/t/`
  - Xong khi: test HTTP/2, HTTP/3, subrequest, internal redirect, client ngắt giữa chừng, hot reload dưới tải pass trên cả 2 bản NGINX.
- **W08-R-01 · Fuzz và differential**
  - Thư mục: `engine/fuzz/`, `conformance/`
  - Làm: target libFuzzer cho lớp FFI; harness differential với profile `go-net-http` và `spring`; bắt đầu fuzz ASan 72 giờ.
  - Xong khi: fuzz chạy liên tục trên máy riêng; mọi crash có ticket.
- **W08-S-01 · Chất lượng v0 và pipeline phát hành**
  - Thư mục: `rules/`, `tools/strata-rules/`
  - Xong khi: toàn bộ test go-ftw của CRS pass tối thiểu 95%; báo cáo FP/recall theo loại tấn công; `strata-rules release` tạo gói có version, chữ ký, changelog, file NOTICE ghi nguồn và giấy phép.
- **W08-G1-01 · Test tải Fleet**
  - Xong khi: 1.000 agent giả lập kết nối ổn định; `BundleAvailable` tới đủ 1.000 agent trong dưới 10 giây.
- **W08-G2-01 · Test tích hợp khi mạng lỗi**
  - Xong khi: chạy toxiproxy (trễ, mất gói, ngắt) giữa agent và control plane; không mất sự kiện, không bundle hỏng.
- **W08-F-01 · Phân quyền trên UI và xuất CSV**
  - Xong khi: nút ẩn theo vai trò; vai trò `viewer` không thấy IP đầy đủ và đoạn input; mọi bảng xuất được CSV.
- **W08-Q-01 · Conformance trong CI**
  - Xong khi: corpus conformance v1 chạy mỗi PR của `engine/` và `connectors/`.

* **W08-R-02 · Mức tin cậy của rule**
  - Thư mục: `engine/`, `rules/schema/`
  - Làm: trường `action_mode: block_alone | score` trong định dạng rule; rule `block_alone` chặn ngay khi khớp, rule `score` chỉ cộng điểm.
  - Xong khi: test cho cả hai mức; JSON Schema cập nhật, linter báo lỗi rule thiếu trường này.
* **W08-S-02 · Gán mức tin cậy cho rule**
  - Xong khi: mọi rule có `action_mode`; chỉ virtual patch, protocol mơ hồ và rule độ chính xác cao được gán `block_alone`, danh sách có review của SecOps.
  - Cần trước: W08-R-02.

**Demo**: báo cáo lỗi từ fuzz và test tải, có người nhận xử lý.

### Tuần 9 · Benchmark, soak, staging

- **W09-Q-01 · Benchmark**
  - Xong khi: báo cáo p50/p99 và throughput (request nhỏ, 64 KB, 1 MB, HTTP/2) so với NGINX không bật module; đo chi phí event socket ở khoảng 50.000 sự kiện/giây; ghi quyết định ring buffer vào `docs/decisions/ring-buffer.md`.
- **W09-Q-02 · Soak và dựng staging**
  - Xong khi: chạy 24 giờ + 1.000 lần đổi bundle, bộ nhớ và file descriptor không tăng liên tục; staging dựng xong, chỉ deploy từ bản đã tag.
- **W09-R-01 · Xử lý điểm nóng hiệu năng**
  - Xong khi: đạt mục tiêu p99 dưới 1 ms và throughput giảm tối đa 10%, hoặc có ticket cụ thể cho phần còn thiếu.
- **W09-S-01 · Phát hành gói signature v0**
  - Xong khi: gói v0 = CRS PL1 + nguồn nhập + rule riêng; tự vào staging 7 ngày; mọi rule đã qua review 2 người; đạt chỉ tiêu Gate A ở mục Chỉ tiêu chất lượng.
- **W09-G2-01 · ClickHouse cho vận hành**
  - Xong khi: TTL lưu trữ áp dụng; tra Block ID dưới 1 giây; truy vấn tìm kiếm 24 giờ dưới 2 giây.
- **W09-F-01 · Decision trace dễ đọc**
  - Xong khi: field vi phạm được tô sáng; hiển thị tác giả với rule từ Sigma.

* **W09-S-02 · Bộ sinh biến thể payload**
  - Thư mục: `tools/strata-mutate/`
  - Làm: sinh biến thể từ corpus attack: encoding kép, đổi hoa thường, chèn comment SQL, khoảng trắng lạ, Unicode NFC/NFD, tách tham số.
  - Xong khi: báo cáo tỉ lệ biến thể lách được theo từng loại tấn công; chạy hằng đêm trong CI.

**Demo**: bảng số liệu so với 5 mục tiêu của module.

### Tuần 10 · Đóng gói và shadow

- **W10-N-01 · Gói cài và runbook**
  - Thư mục: `deploy/packaging/`, `docs/runbook/`
  - Xong khi: gói deb/rpm `nginx-module-strata` theo từng phiên bản NGINX và gói `strata-agent` cài được trên VM sạch bằng 1 lệnh; image container; runbook tắt module, ép shadow, rollback bundle đã diễn tập trên staging.
- **W10-G1-01 · Triển khai control plane**
  - Xong khi: control plane chạy trên staging và môi trường production cho route thí điểm; node của 2 route thí điểm đã enroll.
- **W10-G2-01 · Policy shadow cho route thí điểm**
  - Xong khi: policy của 2 route thí điểm ở chế độ shadow; sự kiện có Event ID về ClickHouse.
- **W10-S-01 · Theo dõi FP trong shadow**
  - Xong khi: bảng FP theo Rule ID cập nhật hằng ngày (truy vấn ClickHouse hoặc dashboard).
- **W10-Q-01 · Giám sát**
  - Xong khi: dashboard Grafana và cảnh báo trên VictoriaMetrics cho module, agent, control plane.
- **W10-F-01 · Trang Tổng quan v0**
  - Xong khi: request bị chặn theo giờ, top rule, top route từ dữ liệu thật.

**Demo · Gate A**: xem mục Đường găng, phụ thuộc & gate.

## Giai đoạn B · Tuần 11–16: tới enforce 100%

Mục tiêu: route thí điểm chạy enforce 100% ổn định, có đủ lưới an toàn (circuit breaker, fallback hai tầng, replay, luồng duyệt). `CLAUDE.md` theo khối: **B1** = tuần 11–13, **B2** = tuần 14–16. Bậc canary chỉ lên khi đạt điều kiện ở bảng canary trong nginx-module.md; việc lên bậc là thao tác vận hành, không phải nhiệm vụ code.

### Tuần 11 · Circuit breaker và canary 1%

- **W11-N-01 · Circuit breaker cấp worker**
  - Thư mục: `connectors/nginx/src/`
  - Làm: trạng thái Closed / Open / Half-open; `strata_breaker`, `strata_breaker_threshold`, `strata_breaker_action degrade | reject`; chỉ tính lỗi nội bộ, không tính vượt budget.
  - Xong khi: tiêm panic hàng loạt → breaker mở trong 10 giây, chạy chế độ giảm cấp; half-open tự đóng khi hết lỗi; payload nặng (vượt budget) không làm breaker mở (có test).
  - Đọc: nginx-module.md › Circuit breaker cấp worker.
- **W11-R-01 · Chọn nhóm canary và lõi replay**
  - Thư mục: `engine/`
  - Làm: hash ổn định (identity hoặc IP, policy) để chọn nhóm canary; lõi replay chạy engine trên request đã lưu dạng Parquet.
  - Xong khi: cùng client luôn rơi vào cùng nhóm; replay 1 triệu request trong dưới 10 phút trên lab.
  - Đọc: nginx-module.md › Bật enforce theo canary.
- **W11-S-01 · Xử lý FP sau tuần shadow**
  - Xong khi: mọi Rule ID có FP trong shadow đã được chỉnh rule hoặc có exception; corpus benign bổ sung từ traffic thật đã ẩn danh; phát hành pack v0.1.
- **W11-G1-01 · Tự fallback tại node**
  - Thư mục: `agent/`
  - Làm: đọc metrics shared memory mỗi 5 giây; vượt ngưỡng thì ghi cờ force-shadow vào control file.
  - Xong khi: giả lập tỉ lệ chặn tăng gấp 3 → policy về shadow trong tối đa 6 giây, không cần control plane.
- **W11-G2-01 · Định dạng traffic mẫu cho replay**
  - Thư mục: `control-plane/replay/`
  - Xong khi: định dạng đã ẩn danh (chỉ cấu trúc + hash) được duyệt bởi pháp chế; lưu được vào MinIO.
- **W11-F-01 · Policy editor (phần 1)**
  - Thư mục: `ui/`
  - Xong khi: sửa policy dạng form và YAML song song, hai dạng đồng bộ nhau; lưu thành bản nháp.
- **Vận hành**: bật canary 1% trên route thí điểm sau khi W11-S-01 xong.

**Demo**: breaker mở và đóng đúng; fallback tại node.

### Tuần 12 · Canary 5% và fallback toàn cụm

- **W12-N-01 · Lấy mẫu traffic cho replay**
  - Làm: qua event sink, mặc định 1% request, ẩn danh ngay tại connector.
  - Xong khi: mẫu lưu đúng định dạng W11-G2-01; không chứa giá trị gốc của field nhạy cảm (test).
- **W12-R-01 · Replay runner và so sánh differential**
  - Làm: chạy bundle nháp trên corpus, trả FP/FN theo route; cùng S so sánh Strata với Coraza + CRS trên cùng traffic.
  - Xong khi: báo cáo replay cho một bản nháp; danh sách khác biệt với Coraza có ticket.
- **W12-S-01 · Sửa lỗi bộ nhập từ differential**
  - Xong khi: mọi khác biệt do bộ nhập đã sửa hoặc ghi lý do.
- **W12-G1-01 · Hoàn thiện fallback tại node**
  - Xong khi: test tự động cho các ngưỡng; cờ force-shadow tự gỡ chỉ khi có lệnh từ control plane.
- **W12-G2-01 · Giám sát canary toàn cụm**
  - Thư mục: `control-plane/fleet/`
  - Làm: so sánh nhóm canary với nhóm shadow (5xx upstream, p99, tỉ lệ chặn); vượt ngưỡng thì gửi `ForceShadow` và dừng rollout.
  - Xong khi: giả lập policy chặn nhầm hàng loạt → toàn cụm về shadow trong dưới 1 phút.
- **W12-F-01 · Diff giữa các version**
  - Xong khi: chọn 2 version → xem diff theo từng khối policy.
- **Vận hành**: lên 5% sau tối thiểu 24 giờ ở 1% nếu đạt điều kiện.

* **W12-R-02 · Tắt rule khẩn cấp trong engine**
  - Thư mục: `engine/`, `engine/ffi/strata.h`
  - Làm: thêm hàm FFI `strata_engine_disable_rules` (thay đổi ABI dạng thêm mới, tăng minor) để bỏ qua danh sách Rule ID mà không nạp lại bundle.
  - Xong khi: rule bị tắt không còn khớp; danh sách rỗng → hành vi như cũ; benchmark không đổi.
* **W12-G1-02 · Lệnh tắt / bật rule**
  - Thư mục: `proto/`, `agent/`
  - Làm: `Command DisableRules` / `EnableRules` trong `fleet.proto`; agent ghi danh sách vào control file.
  - Xong khi: lệnh tới toàn bộ node trong dưới 10 giây.
* **W12-N-02 · Áp dụng danh sách rule bị tắt**
  - Thư mục: `connectors/nginx/src/`
  - Xong khi: agent ghi danh sách → mọi worker áp dụng trong tối đa 1 giây.
  - Cần trước: W12-R-02, W12-G1-02.
* **W12-G2-02 · API tắt rule khẩn cấp**
  - Làm: `POST /v1/rules/{rule_id}:emergencyDisable` và `:enable` theo connector group; bắt buộc nhập lý do; ghi audit.
  - Xong khi: chỉ vai trò từ `operator` trở lên gọi được (có test); audit ghi đủ người, lý do, phạm vi.

**Demo**: hệ thống tự về shadow khi policy chặn nhầm, không cần người can thiệp.

### Tuần 13 · Replay và luồng duyệt

- **W13-G2-01 · Replay service**
  - Thư mục: `control-plane/replay/`
  - Làm: API `:replay` dạng long-running operation; lưu kết quả theo bản nháp.
  - Xong khi: tạo bản nháp → replay tự chạy → kết quả xem được qua API.
  - Cần trước: W12-R-01.
- **W13-G2-02 · Luồng duyệt 4 mắt**
  - Thư mục: `control-plane/policy/`
  - Làm: `:submit`, `:approve`; người tạo không tự duyệt.
  - Xong khi: test người tạo tự duyệt bị từ chối; deploy khi chưa duyệt bị từ chối.
- **W13-F-01 · Hàng chờ duyệt**
  - Xong khi: hiển thị bản nháp chờ duyệt kèm kết quả replay và diff; duyệt/từ chối được.
- **W13-N-01 · Sửa lỗi từ canary**
  - Xong khi: mọi lỗi canary mức cao đã đóng.
- **W13-G1-01 · Nâng cấp agent không gián đoạn**
  - Xong khi: nâng cấp gói agent trên node đang có tải → không mất sự kiện, không đổi bundle ngoài ý muốn.
- **W13-S-01 · Rule bù khoảng trống**
  - Xong khi: rule riêng cho phần CRS và nguồn nhập chưa phủ, cho các ca bypass từ fuzz; phát hành pack v0.2.
- **Vận hành**: quan sát 5% đủ 48 giờ, lên 25% cuối tuần nếu đạt.

* **W13-R-02 · Đo chi phí từng rule**
  - Thư mục: `engine/`
  - Làm: lấy mẫu thời gian xử lý theo Rule ID (mặc định 1% request), đưa vào metrics và sự kiện.
  - Xong khi: chi phí đo lường dưới 2% thời gian engine.

**Demo**: một thay đổi policy đi đủ chuỗi nháp → replay → duyệt → deploy.

### Tuần 14 · Exception từ Block ID và game day

- **W14-G2-01 · Exception và đánh dấu FP**
  - Làm: `POST /v1/exceptions:fromBlockId`; hạn dùng exception; `:markFalsePositive`.
  - Xong khi: exception sinh từ Block ID có phạm vi hẹp nhất (route + field + Rule ID) và bắt buộc hạn dùng.
- **W14-F-01 · Nút xử lý trên chi tiết sự kiện**
  - Xong khi: 3 nút Đánh dấu FP, Tạo exception (điền sẵn), Chặn IP/identity hoạt động; exception đi qua replay và duyệt.
- **W14-R-01 · Exception, override, cost unit trong compiler**
  - Xong khi: exception và override biên dịch đúng thứ tự ưu tiên (exception trước override); policy vượt cost bị từ chối.
- **W14-S-01 · Quy trình virtual patch**
  - Xong khi: diễn tập một CVE nghiêm trọng → gói signature ở staging trong dưới 24 giờ; runbook lưu ở `docs/runbook/virtual-patch.md`.
- **W14-Q-01 · Game day**
  - Xong khi: tắt control plane, tắt agent, làm hỏng bundle, tiêm panic, ngắt mạng trên staging; biên bản so sánh hành vi thật với thiết kế; lỗi tìm được có ticket.
- **Vận hành**: quan sát 25% đủ 72 giờ.

* **W14-G2-02 · Sức khỏe rule**
  - Thư mục: `control-plane/`
  - Làm: tổng hợp theo Rule ID (số lần khớp, số FP được báo, chi phí trung bình); rule có FP tăng đột biến tự quay về staging (chỉ ghi log) và báo người duyệt; API `GET /v1/rules/{rule_id}/health`.
  - Xong khi: giả lập FP tăng đột biến → rule về staging trong dưới 5 phút.
  - Cần trước: W13-R-02.

**Demo**: helpdesk xử lý một ca chặn nhầm từ Block ID tới exception được duyệt trong dưới 15 phút.

### Tuần 15 · Enforce 100%

- **W15-G2-01 · Audit, role binding, service account**
  - Xong khi: `GET /v1/audit` ghi đủ người, kênh, trước/sau; service account token có phạm vi và hạn dùng.
- **W15-F-01 · Hoàn thiện policy editor và trang Audit v0**
  - Xong khi: editor đủ 9 khối policy; trang Audit lọc theo người, thời gian, đối tượng.
- **W15-N-01 · Chốt tài liệu cấu hình**
  - Xong khi: bảng directive (gồm `strata_breaker*`) và README của module khớp code.
- **W15-R-01 · Tối ưu tokenizer theo FP thực tế**
  - Xong khi: FP của tokenizer trên traffic thật giảm theo báo cáo của S.
- **W15-S-01 · Red team nhỏ**
  - Xong khi: bypass tìm được đã vá; phát hành pack v0.3; đạt chỉ tiêu Gate B.
- **Vận hành**: người duyệt xác nhận trên UI, lên 100% cho route thí điểm.

* **W15-Q-01 · Benchmark chống bypass**
  - Xong khi: chạy GoTestWAF (sau khi kiểm tra giấy phép) và bộ biến thể của W09-S-02 trên staging; kết quả lưu ở `docs/reports/`; bypass mức cao chuyển cho W15-S-01.

**Demo**: route thí điểm enforce 100%, dashboard không có cảnh báo đỏ.

### Tuần 16 · Ổn định enforce

- **W16-S-01 · Báo cáo chất lượng sau enforce**
  - Xong khi: FP trên 1 triệu request, rule chưa từng khớp, rule tốn chi phí nhất; quy trình cập nhật khi CRS ra bản mới.
- **W16-G2-01 · Chuẩn bị GeoIP**
  - Xong khi: Event ingest nạp `.mmdb`; ClickHouse có cột `country_iso`, `city`, `lat`, `lon`, `asn`, `as_org`.
- **W16-ALL-01 · Retrospective và cập nhật thiết kế**
  - Xong khi: tài liệu thiết kế cập nhật theo những gì học được khi chạy thật.
- **Quyết định**: location nhạy cảm nào chuyển sang `strata_fail_mode closed` sau Gate B.

**Demo · Gate B**: xem mục Đường găng, phụ thuộc & gate.

## Giai đoạn C · Tuần 17–22: hoàn thiện v1

Mục tiêu: SOC có bản đồ GeoIP và dashboard dùng hằng ngày; engine có thêm độ phủ (semantic, CRS PL2, OpenAPI); sẵn sàng phát hành v1. `CLAUDE.md` theo khối: **C1** = tuần 17–19, **C2** = tuần 20–22.

### Tuần 17 · GeoIP và nền bản đồ

- **W17-G2-01 · Gắn GeoIP và bảng tổng hợp**
  - Thư mục: `control-plane/ingest/`
  - Làm: tra `.mmdb` khi ingest; materialized view theo phút (quốc gia, ASN, action, loại tấn công) và theo 5 phút (geohash độ chính xác 4); job cập nhật GeoIP hằng tuần.
  - Xong khi: sự kiện mới có đủ cột vị trí; job cập nhật lưu phiên bản `.mmdb` vào MinIO.
  - Đọc: nginx-module.md › Bản đồ GeoIP › Pipeline.
- **W17-F-01 · Nền bản đồ tự host**
  - Thư mục: `ui/`
  - Làm: MapLibre GL JS + file PMTiles do API server phục vụ.
  - Xong khi: bản đồ chạy trong mạng không có internet; **nguồn tile đã kiểm tra thể hiện đúng chủ quyền Hoàng Sa, Trường Sa** (biên bản kiểm tra lưu ở `docs/decisions/map-tiles.md`).
- **W17-R-01 · Mở rộng semantic detector, CRS PL2**
  - Làm: semantic detector CMDi và template injection; hỗ trợ CRS PL2 và plugin exclusion cùng S.
  - Xong khi: test go-ftw ở PL2 pass tối thiểu 95%.
- **W17-S-01 · CRS PL2 và plugin exclusion**
  - Xong khi: route chịu được PL2 chạy ở shadow; plugin exclusion (WordPress, Drupal…) nhập được.
- **W17-N-01 · Tối ưu và ring buffer (nếu đã quyết định)**
  - Xong khi: theo `docs/decisions/ring-buffer.md`: hoặc ring buffer `/dev/shm` có test, hoặc ghi rõ để v1.1.
- **W17-Q-01 · Test tải truy vấn tổng hợp**
  - Xong khi: truy vấn 24 giờ dưới 1 giây, 30 ngày dưới 3 giây trên dữ liệu giả lập 30 ngày.

**Demo**: bản đồ nền hiển thị trong mạng nội bộ.

### Tuần 18 · API thống kê và lớp bản đồ

- **W18-G2-01 · StatsService**
  - Làm: `GET /v1/stats/geo`, `GET /v1/stats/timeline`, cập nhật trực tiếp qua SSE (`/v1/stats/geo:watch`).
  - Xong khi: test API theo `groupBy=country|city|asn`; SSE đẩy thay đổi trong tối đa 5 giây.
- **W18-F-01 · Lớp bản đồ và panel**
  - Làm: lớp quốc gia (thang log), lớp thành phố (vòng tròn theo ô lưới, gom cụm), bộ lọc chip, panel top quốc gia / ASN / loại tấn công, dòng thời gian.
  - Xong khi: hiển thị dữ liệu thật 24 giờ; đổi bộ lọc → mọi panel cập nhật cùng lúc.
  - Đọc: nginx-module.md › Bản đồ GeoIP › Hiển thị.
- **W18-R-01 · Phủ thêm rule CRS**
  - Xong khi: tỉ lệ rule CRS nhập tự động tăng so với tuần 8 (báo cáo importer).

* **W18-G2-02 · Danh sách IP của bot tốt**
  - Thư mục: `control-plane/`
  - Làm: job lấy dải IP công bố của các crawler lớn (Google, Bing…), đóng vào bundle.
  - Xong khi: cập nhật hằng ngày; mỗi phiên bản lưu trên MinIO.
* **W18-R-02 · Xác minh bot tốt**
  - Thư mục: `engine/`
  - Làm: request tự nhận là crawler lớn qua User-Agent nhưng IP không thuộc dải công bố → violation điểm cao.
  - Xong khi: Googlebot giả từ IP lạ bị gắn violation; Googlebot từ dải công bố không bị (có test).
  - Cần trước: W18-G2-02.
* **W18-S-01 · Pack bot**
  - Xong khi: signature bot xấu và mẫu brute force có test; rule xác minh bot tốt bật mặc định.

**Demo**: bản đồ dữ liệu thật 24 giờ, truy vấn dưới 1 giây.

### Tuần 19 · Drill-down và rule geo/ASN

- **W19-F-01 · Drill-down và hành động nhanh**
  - Xong khi: bấm quốc gia hoặc ASN → lọc toàn trang và bảng sự kiện → mở decision trace; nút Tạo rule chặn geo/ASN tạo bản nháp.
- **W19-R-01 · Rule geo/ASN trong engine**
  - Làm: compiler đóng `.mmdb` vào bundle; engine tra vị trí tại node.
  - Xong khi: rule chặn theo quốc gia và ASN có test; kích thước bundle tăng được ghi lại.
- **W19-G2-01 · Rule geo/ASN trong policy**
  - Xong khi: tạo, sửa, deploy rule geo/ASN qua API.
- **W19-G1-01 · GitOps sync (phần 1)**
  - Thư mục: `gitops-sync/`
  - Xong khi: import YAML → bản nháp chờ duyệt; export policy ra Git.

**Demo**: từ bản đồ tới rule chặn ASN được duyệt và deploy trong dưới 10 phút.

### Tuần 20 · Dashboard và GitOps

- **W20-F-01 · Trang Tổng quan đầy đủ**
  - Xong khi: request, tỉ lệ chặn, top rule, top route, latency engine, node lỗi, rollout đang chạy; tự làm mới, có nút tạm dừng.
- **W20-G1-01 · GitOps sync (phần 2)**
  - Xong khi: export định kỳ; khóa policy theo kênh (UI / API / GitOps) để tránh ghi đè, có test.
- **W20-G2-01 · Tối ưu truy vấn thống kê**
  - Xong khi: 24 giờ dưới 1 giây, 30 ngày dưới 3 giây trên dữ liệu thật.
- **W20-R-01 · Tinh chỉnh semantic detector**
  - Xong khi: FP của semantic detector trên corpus replay giảm theo báo cáo của S.
- **W20-S-01 · Template policy cho API có OpenAPI**
  - Xong khi: template `api` có test.

**Demo**: SOC dùng thử dashboard và bản đồ trong một ca trực.

### Tuần 21 · OpenAPI, danh mục rule, kiểm thử bảo mật

- **W21-R-01 · Positive model v0**
  - Làm: enforce theo OpenAPI (endpoint, method, field không khai báo).
  - Xong khi: request tới endpoint/method/field ngoài schema bị violation tương ứng (có test).
- **W21-G2-01 · API schema**
  - Xong khi: tải OpenAPI, kiểm tra hợp lệ, biên dịch vào bundle qua API.
- **W21-F-01 · Trang Rule & signature, Exception, Schema**
  - Xong khi: danh mục rule theo dải ID, trạng thái staging và chỉ số sức khỏe (số lần khớp, FP, chi phí); nút tắt rule khẩn cấp; exception có cảnh báo sắp hết hạn; tải và xem schema.
- **W21-S-01 · Red team đầy đủ**
  - Xong khi: báo cáo red team trên staging; bypass mức cao đã vá; phát hành pack v0.9.
- **W21-Q-01 · Regression toàn bộ**
  - Xong khi: chạy lại toàn bộ test, fuzz, soak; không còn lỗi mức cao.

**Demo**: báo cáo red team và trạng thái xử lý.

### Tuần 22 · Phát hành v1

- **W22-ALL-01 · Release candidate**
  - Xong khi: tag `v1.0.0`; gói signature v1.0 kèm file NOTICE; tài liệu nâng cấp và migration; runbook vận hành bản cuối.
- **W22-S-01 · Hướng dẫn viết rule và lịch phát hành**
  - Xong khi: `docs/rules/authoring.md`; lịch phát hành gói signature hằng tuần.
- **Vận hành**: đào tạo SOC và helpdesk quy trình xử lý theo Block ID; thống nhất SLA hỗ trợ.
- **W22-ALL-02 · Retrospective và kế hoạch tiếp theo**
  - Xong khi: chọn connector thứ hai (Kong hoặc Envoy) và có kế hoạch sơ bộ.

**Demo · Gate C**: xem mục Đường găng, phụ thuộc & gate.

## Đường găng, phụ thuộc & gate

**Đường găng** (trễ ở bước nào thì mốc enforce trễ theo):

1. PoC Hyperscan + mmap (tuần 2) → định dạng bundle zero-copy (tuần 4–5).
2. Compiler + `strata_engine_map` (tuần 4–5) → hot reload (tuần 5) → shadow (tuần 10).
3. Định dạng rule + corpus (tuần 3–4) → gói signature v0 (tuần 5–9) → shadow có ý nghĩa (tuần 10). Thiếu luồng này thì shadow chỉ đo được lớp protocol.
4. Event ingest + ClickHouse (tuần 6) → tra Block ID trên UI (tuần 6–7) → shadow có thể vận hành.
5. Circuit breaker + fallback hai tầng (tuần 11–12) → được phép lên canary 5% trở lên.
6. Replay + luồng duyệt (tuần 13) và gói signature đạt chỉ tiêu Gate B → enforce 100%.

**Phụ thuộc giữa các luồng**

| Việc cần | Phụ thuộc vào | Cách giảm chờ |
| --- | --- | --- |
| Module nạp bundle thật (N, tuần 5) | Compiler + định dạng bundle (R, tuần 4) | N dùng bundle mẫu sinh tay trong lúc chờ |
| Agent nhận bundle (G1, tuần 5) | Fleet `BundleAvailable` (G2, tuần 5) | Thống nhất `fleet.proto` ngay tuần 3 |
| UI Sự kiện (F, tuần 6) | Event API (G2, tuần 6) | F làm với API giả lập từ tuần 5 theo OpenAPI |
| Replay (R + G2, tuần 12–13) | Lấy mẫu traffic từ module (N, tuần 12) | Tuần 11 dùng corpus tổng hợp |
| Bản đồ (F, tuần 18) | StatsService + GeoIP (G2, tuần 17–18) | F dựng bản đồ nền tuần 17 với dữ liệu giả |

**Tiêu chí gate**

| Gate | Thời điểm | Điều kiện đạt | Nếu chưa đạt |
| --- | --- | --- | --- |
| A · Shadow | Cuối tuần 10 | 5 mục tiêu của module đạt (p99 dưới 1 ms, throughput giảm tối đa 10%, hot reload không rớt request, 72 giờ fuzz không crash, conformance 100%); sự kiện về ClickHouse; UI tra được Block ID; runbook đã diễn tập; gói signature v0 đạt chỉ tiêu Gate A của luồng S | Giữ shadow, không bật canary; lùi giai đoạn B tương ứng |
| B · Enforce | Cuối tuần 16 | Route thí điểm enforce 100% ít nhất 2 tuần không fallback; FP dưới ngưỡng thống nhất; game day đạt; helpdesk xử lý được ca chặn nhầm qua Block ID; chỉ tiêu chất lượng Gate B của luồng S đạt | Quay về bậc canary trước; giai đoạn C vẫn làm được vì không chặn enforce |
| C · v1 | Cuối tuần 22 | SOC dùng bản đồ và dashboard trong ca trực; không còn lỗi pentest mức cao; tài liệu vận hành và đào tạo hoàn tất | Phát hành v1 không kèm phần chưa đạt (ví dụ GitOps), ghi vào v1.1 |

**Vùng đệm**: tuần 16 và tuần 22 đều có phần ổn định / phát hành, dùng được làm vùng đệm khoảng 1 tuần mỗi giai đoạn. Nếu thiếu nhân sự, giữ nguyên A–B, lùi C (bản đồ, dashboard, GitOps, OpenAPI) mà không ảnh hưởng enforce.

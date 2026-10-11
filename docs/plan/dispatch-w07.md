# Giao việc tuần 7 cho Antigravity

Soạn 11/10/2026 từ `docs/plan/plan.md` (tuần 7) và **hiện trạng code trên `main`** sau đợt gộp nhánh. Thay cho phần tuần 7 của `docs/plan/dispatch.md`: phần đó viết trước khi đối chiếu code, nên giao lại việc đã xong (transformation đợt 2, backoff, gia hạn chứng chỉ, `:pause/:resume/:abort`), thiếu phần Rust của sự kiện, và dẫn tới mục 6a/6b chưa có trong AGENTS.md (nay đã thêm).

Phân vai tuần 7: **Antigravity làm toàn bộ**; Claude Code review kế hoạch (L3) và review nhánh (L2, L3) theo AGENTS.md mục 6b.

## 1. Quyết định của PO

PO duyệt cả 6 đề xuất ngày 11/10/2026. Q1 đã thay đổi: repo nay ở `github.com/hieunyit/strata` (private), nên dùng quy trình PR của AGENTS.md mục 6a thay cho nhánh cục bộ.

| # | Quyết định | Đề xuất | Ảnh hưởng |
| --- | --- | --- | --- |
| Q1 | Quy trình nhánh và review | **Đã có remote**: nhánh trong `../strata-ag`, báo cáo `docs/reports/<mã>.md`, push và mở PR bằng `gh pr create`; review bằng `gh pr diff`; merge khi APPROVE và CI xanh | Mọi nhiệm vụ |
| Q2 | Layout cờ force-shadow trong control file | Offset 324 `u32` cờ (bit 0: mọi policy); 328 `u32` số policy bị ép (0..32); 336 `u8[32][56]` tên policy (đệm NUL). Ghi dưới seqlock như các trường khác; worker áp dụng ở lần đọc control file kế tiếp (≤ 1 s). Hết hạn (`duration_seconds`) do agent xóa cờ | W07-N-01 (đọc), W07-G1-01 (ghi). Đổi interface chung: `docs/design/control-file.md` |
| Q3 | Hyperscan streaming cho CPU budget | Section HYPERSCAN mới, magic `SHS2`, DB biên dịch `HS_MODE_STREAM`; engine đọc cả `SHS1` (bundle cũ, quét một lần) và `SHS2` (quét khối 8 KB, kiểm đồng hồ giữa các khối). Compiler ghi `SHS2` | W07-R-01. Đổi định dạng bundle (thêm, giữ tương thích) |
| Q4 | W07-S-01: virtual patch dải 700000 | PO cho biết stack của route thí điểm; chưa có thì bỏ phần này khỏi tuần 7, ghi ⛔ | W07-S-01 |
| Q5 | W07-S-01: "sự kiện của rule Sigma hiển thị tác giả" | Tuần 7 chỉ giữ `author` trong rule IR; hiển thị trên UI cần API danh mục rule (W21) | Dòng "Xong khi" của W07-S-01 |
| Q6 | W07-Q-01: CodeQL | Repo private: code scanning của GitHub cần GitHub Advanced Security. Chạy clang-tidy trong `make` và CI; CodeQL CLI chạy trong job CI hoặc chạy tay, lưu kết quả (không upload SARIF nếu không có GHAS) | W07-Q-01 |

Prompt bên dưới viết theo các quyết định trên.

## 2. Thứ tự và phụ thuộc

Antigravity làm **một nhiệm vụ một lúc**. Thứ tự đề xuất:

1. **W07-R-02** (L2) · operator còn thiếu. Nhỏ, không phụ thuộc.
2. **W07-R-03** (L3) · mã hóa sự kiện. Cần trước cho phần sự kiện của N-01.
3. **W07-R-01** (L3) · CPU budget, cô lập lỗi. Cần Q3.
4. **W07-N-01** (L3) · fail mode, event sink, metrics, cờ force-shadow. Cần R-03, R-01, Q2.
5. **W07-G1-01** (L3) · Command ForceShadow / chẩn đoán, test toxiproxy. Cần N-01 (worker đọc cờ).
6. **W07-G2-01** (L3) · signer KMS, cost unit. Độc lập.
7. **W07-S-01** (L2), **W07-F-01** (L1), **W07-Q-01** (L1) · độc lập, xen vào khi chờ review.

Trước khi giao: cập nhật mục 0 của AGENTS.md cho tuần 7 bằng prompt "Sáng thứ 2" trong `docs/plan/dispatch.md` (công cụ: Antigravity, thêm dòng W07-R-03).

## 3. Phần mở đầu chung (dán đầu mọi prompt)

```
Bạn là agent Antigravity trong dự án Strata. Đọc AGENTS.md (toàn bộ, đặc biệt mục 5, 6, 6a, 9, 10),
docs/plan/dispatch-w07.md mục 1 (các quyết định của PO) và mục của nhiệm vụ dưới đây.
Làm trong worktree ../strata-ag (git fetch origin; git worktree add ../strata-ag -b <NHÁNH> origin/main nếu chưa có).
Quy trình: Bước 1 xác nhận nhiệm vụ thuộc tuần 7 và "Cần trước" đã merge vào main (git log origin/main).
Bước 2 viết Implementation Plan gồm: file sẽ sửa/tạo; thiết kế (cấu trúc dữ liệu, luồng, interface);
bất biến cần giữ; ca biên và đường lỗi; rủi ro bảo mật; danh sách test (tên test, chứng minh điều gì, gồm test âm);
lệnh kiểm chứng; dependency mới (nếu có, kèm lý do). Rồi DỪNG, chờ tôi trả lời "duyệt".
Bước 3 (sau "duyệt"): làm đúng kế hoạch; lệch kế hoạch thì dừng và hỏi. Chạy đủ lệnh kiểm chứng, tự review theo mục 6a,
đổi dòng nhiệm vụ ở mục 0 AGENTS.md thành ✅ Done, viết báo cáo docs/reports/<mã-chữ-thường>.md theo mục 9
(kèm SHA commit cuối và mức review), commit, push, mở PR bằng gh pr create --base main (nội dung = báo cáo), rồi DỪNG. Không merge.
```

## 4. Prompt từng nhiệm vụ

### W07-R-02 · Operator đợt 2 · Review L2 · Cần trước: —

```
<phần mở đầu chung>  NHÁNH = W07-R-02-operators

Nhiệm vụ W07-R-02 · Operator đợt 2 (engine/, cộng tools/strata-import-crs/ để nhập rule dùng các operator này).

Hiện trạng (đừng làm lại):
- 16 transformation đợt 1–2 + length đã xong, khớp 229 vector Coraza (engine/tests/transform_vectors.rs, vectors trong engine/tests/vectors/coraza/, Coraza v3.8.1).
- Toán tử so sánh số (eq..le) đã có, chạy trên giá trị đã biến đổi.
- IR (docs/spec/ir.schema.json) và bảng mã rules::OPERATORS đã có validate_byte_range, validate_url_encoding,
  validate_utf8_encoding, ip_match; engine chưa chạy chúng: eval::supported() không liệt kê, rule dùng chúng bị bỏ qua
  (strata-rules test SKIP rule 800001 "engine lacks operator ip_match").

Làm:
1. engine/src/eval.rs (hoặc module mới engine/src/operators.rs): 4 operator, ngữ nghĩa theo Coraza v3.8.1:
   - validate_byte_range "9,10,13,32-126": khớp khi giá trị (đã biến đổi) có byte NGOÀI dải. Chuỗi dải phân tích lúc nạp bundle,
     lỗi cú pháp thì compiler từ chối (strata-compile), không panic lúc chạy.
   - validate_url_encoding: khớp khi có % không theo sau bởi 2 chữ số hex.
   - validate_utf8_encoding: khớp khi UTF-8 không hợp lệ (gồm overlong, surrogate, > U+10FFFF).
   - ip_match: danh sách IPv4/IPv6 và CIDR; so trên giá trị đã biến đổi (thường là remote_addr). Không DNS.
     Danh sách phân tích MỘT lần lúc nạp bundle thành dải đã sắp xếp, tra bằng tìm kiếm nhị phân (danh sách có thể vài nghìn mục).
     Giá trị không phải IP thì không khớp (negate theo quy tắc chung: mỗi giá trị).
2. Đưa 4 operator vào eval::supported() để strata-eval --capabilities liệt kê.
3. Test vector: vendor test của Coraza v3.8.1 cho 4 operator (internal/operators/testdata hoặc test Go tương ứng),
   ghi commit nguồn và LICENSE vào engine/tests/vectors/coraza/, chạy trong một file test mới; test không gọi mạng.
4. tools/strata-import-crs: ánh xạ @validateByteRange, @validateUrlEncoding, @validateUtf8Encoding, @ipMatch; make crs-import,
   ghi số rule nhập thêm vào báo cáo.
5. Fuzz: thêm validate_byte_range/ip_match vào target body_eval hoặc target mới, chạy engine/fuzz/run.sh 600 <target>.

Xong khi:
- 100% vector Coraza của 4 operator pass (ghi số vector).
- rules/samples/800001 không còn SKIP: deploy/dev/run.sh make test-rules pass.
- make crs-import không làm hỏng: make test-crs-ftw vẫn ≥ 90% mỗi nhóm, git diff rules/crs chỉ gồm rule mới nhập.
- cargo clippy --workspace --all-targets --all-features -- -D warnings sạch; cargo test --workspace pass.

Không được: đổi mã operator đã có trong bundle; thêm dependency mạng; dùng regex backtracking.
Mức review: L2.
```

### W07-R-03 · Mã hóa sự kiện trong libstrata · Review L3 · Cần trước: —

```
<phần mở đầu chung>  NHÁNH = W07-R-03-event-encoding

Nhiệm vụ W07-R-03 · Mã hóa sự kiện trong libstrata (engine/; được sửa comment của strata_tx_event trong strata.h qua cbindgen).
Đọc: docs/design/nginx-module.md › "Trang chặn, Block ID & sự kiện"; proto/strata/event/v1/event.proto;
agent/internal/eventsock/eventsock.go (bên nhận: một Event mỗi datagram, ≤ 8 KB, thiếu Block ID thì bị bỏ).

Hiện trạng: strata_tx_event (engine/ffi/src/ffi.rs) là stub trả 0. ABI không đổi: hàm đã có chữ ký
size_t strata_tx_event(const strata_tx_t *tx, uint8_t *dst, size_t cap).

Làm:
1. engine/src/event.rs: encoder protobuf viết tay (không thêm prost vào libstrata; nếu muốn dùng crate thì nêu trong kế hoạch),
   các trường của Event theo event.proto. Dữ liệu lấy từ Tx: block_id, thời gian, node_id, policy, bundle_version, client_ip,
   method, host, path, status, action, điểm theo layer, rule_ids, matches.
2. Khi nào có sự kiện: request bị chặn; shadow đáng lẽ chặn (Event ID EVT-); lỗi engine, vượt budget, bundle lỗi (fail mode, có Event ID).
   Request cho qua không khớp rule nào: trả 0.
3. Giới hạn: tổng ≤ 8 KB. Đoạn input trong matches tối đa 128 byte mỗi đoạn, tối đa 16 match; vượt 8 KB thì bớt matches trước,
   rồi cắt path. Hành vi theo chữ ký: trả kích thước đầy đủ, không ghi gì khi lớn hơn cap.
4. Test chéo ngôn ngữ: test Rust ghi các sự kiện mẫu ra testdata golden (ví dụ engine/tests/golden/events/*.bin);
   test Go trong agent/internal/eventsock giải mã đúng từng file và kiểm từng trường. Đổi encoder mà không cập nhật golden thì test fail.
5. Fuzz: target mới event_encode (Tx với input tùy ý → strata_tx_event với cap tùy ý): không panic, không ghi quá cap,
   kết quả giải mã được (kiểm bằng parser protobuf tối thiểu trong test).
6. Cập nhật comment của strata_tx_event ("The stub never produces events" không còn đúng); make check-header phải pass.

Xong khi:
- Golden: mọi file decode đúng ở phía Go (GOTOOLCHAIN=auto go test ./agent/internal/eventsock/...).
- Request sạch → 0 byte; bị chặn, shadow, lỗi engine → có sự kiện, Block ID đúng tiền tố STR-/EVT-.
- Sự kiện lớn nhất có thể (input thù địch) ≤ 8 KB; đoạn input bị cắt đúng giới hạn (test).
- deploy/dev/run.sh make test (Rust, header, fixtures, ABI, nginx 1.30.5) và fuzz 600 giây target mới không lỗi.

Không được: log hay đưa vào sự kiện header Authorization, Cookie, giá trị tham số ngoài đoạn khớp; đổi chữ ký ABI.
Mức review: L3.
```

### W07-R-01 · CPU budget hợp tác và cô lập lỗi · Review L3 · Cần trước: — (cần quyết định Q3)

```
<phần mở đầu chung>  NHÁNH = W07-R-01-cpu-budget

Nhiệm vụ W07-R-01 · CPU budget hợp tác và cô lập lỗi (engine/, engine/compiler/, engine/ffi/; được đổi định dạng section
HYPERSCAN theo quyết định Q3 và cập nhật docs/design/control-file.md phần bundle).
Đọc: docs/design/nginx-module.md › "Hiệu năng, tài nguyên & fail mode", "Circuit breaker cấp worker" (chế độ giảm cấp).

Hiện trạng:
- strata_tx_new nhận cpu_budget_us nhưng bỏ qua (ffi.rs: let _ = cpu_budget_us). STRATA_E_BUDGET đã có trong strata.h.
- Mọi hàm extern "C" đã bọc catch_unwind qua guard()/with_tx() trong ffi.rs: kiểm lại từng hàm, thêm test cho hàm còn thiếu.
- Tx đo thời gian (add_time, strata_tx_time_us). Feature test-hooks có trigger panic có chủ ý.
- Những phần chạy cả giá trị một lần, chưa kiểm đồng hồ: quét Hyperscan (block mode, section SHS1), transformation,
  regex fallback (crate regex cho pattern Hyperscan từ chối), libinjection (detect_sqli/xss), parser multipart/JSON/XML.

Làm:
1. Budget trong Tx: hạn chót = lúc bắt đầu lời gọi đầu tiên + cpu_budget_us (0 = không giới hạn). Khi vượt: lời gọi hiện tại và mọi
   lời gọi sau trả STRATA_E_BUDGET, verdict mang Event ID, quyết định để connector theo fail mode. Đồng hồ: Instant (đo chi phí;
   nếu muốn CLOCK_MONOTONIC_COARSE thì phần unsafe chỉ ở engine/ffi).
2. Điểm kiểm đồng hồ:
   - Hyperscan: DB stream mode (Q3, section SHS2), quét khối 8 KB, kiểm giữa các khối; giữ đọc được SHS1.
     Scratch/stream state cấp phát một lần mỗi worker hoặc mỗi Engine, không cấp phát lớn trên đường đi request.
   - Transformation: chuỗi transformation trên giá trị dài kiểm đồng hồ theo khối (hoặc giới hạn độ dài giá trị được inspect,
     nêu rõ lựa chọn và lý do trong kế hoạch).
   - Parser multipart/JSON/XML và libinjection: kiểm sau mỗi N phần tử/token.
   - Regex fallback (crate regex) không ngắt được giữa chừng: đo thời gian xấu nhất trên 1 MB cho 4 rule CRS dùng nó
     (932230, 932235, 932250, 932260), đề xuất cách chặn (giới hạn độ dài giá trị cho các rule này hoặc quét theo cửa sổ).
3. Chế độ giảm cấp: API trong engine chỉ chạy kiểm tra protocol dựng sẵn và rule ip_match (rate limit chưa có: để hook, ghi rõ).
   Chưa cần cờ ABI (W11 thêm).
4. Benchmark: bộ payload bệnh lý 1 MB: JSON lồng sâu, XML nhiều thuộc tính, multipart nhiều phần, chuỗi html entity dài,
   chuỗi cho detect_sqli, chuỗi cho 4 rule regex fallback, giá trị dài với CRS đầy đủ (rules/crs). Với budget 1 ms, đo phần vượt
   (thời gian thực − budget) 100 lần mỗi payload; báo cáo p50/p99/max. Lưu kết quả vào docs/reports/w07-cpu-budget.md.
5. Panic: test qua C ABI (engine/ffi/tests) tiêm panic ở mỗi hàm FFI có thể panic → STRATA_E_INTERNAL, process sống, tx sau dùng được.

Xong khi:
- Phần vượt budget max < 100 µs trên mọi payload bệnh lý 1 MB (bảng số đo thật).
- Panic tiêm ở mọi hàm FFI → STRATA_E_INTERNAL, không sập (test).
- Bundle SHS1 cũ vẫn nạp và cho cùng kết quả (test với fixture cũ); make test-crs-ftw không đổi kết quả.
- deploy/dev/run.sh make test, nginx-asan + test-nginx-asan trên 1.30.5 và 1.31.6, fuzz 600 giây mọi target sạch.

Không được: unsafe ngoài engine/ffi; giảm phát hiện (go-ftw, corpus report phải giữ nguyên hoặc tốt hơn).
Mức review: L3.
```

### W07-N-01 · Fail mode, event sink, metrics, RST_STREAM · Review L3 · Cần trước: W07-R-03, W07-R-01 (quyết định Q2)

```
<phần mở đầu chung>  NHÁNH = W07-N-01-fail-mode

Nhiệm vụ W07-N-01 · Fail mode, event sink, metrics, RST_STREAM (connectors/nginx/src/, connectors/nginx/t/;
được đọc thêm phần force-shadow của control file theo Q2 và cập nhật docs/design/control-file.md).
Đọc: nginx-module.md › "Hiệu năng, tài nguyên & fail mode" (bảng Fail mode), "Trang chặn, Block ID & sự kiện › Giao diện gửi sự kiện",
"Vòng đời request"; docs/design/control-file.md (control file và **file metrics**: layout STRMET1 đã được agent đọc).

Hiện trạng:
- Directive đã có và parse: strata_fail_mode, strata_cpu_budget, strata_event_socket (unix:, mặc định unix:/run/strata/events.sock).
- ctx->fail_closed đã tính; phần bundle thiếu/lỗi ghi log "follow strata_fail_mode".
- Bên nhận đã có: agent/internal/eventsock (unixgram, Event protobuf, ≤ 8 KB) và agent/internal/shmmetrics (đọc file STRMET1).
  agent/internal/bundles chờ file metrics để báo ACTIVE (manager.go: "the module writes it from W07-N-01").
- strata_tx_event (W07-R-03) trả sự kiện đã mã hóa: C chỉ copy byte ra socket, không tự dựng protobuf.

Làm:
1. Ma trận fail mode đúng bảng thiết kế cho 4 sự cố: không có bundle / bundle lỗi; engine trả lỗi hoặc panic (STRATA_E_INTERNAL);
   vượt strata_cpu_budget (STRATA_E_BUDGET); event socket đầy hoặc agent chết. open: cho qua + metric/sự kiện; closed: 503 kèm Event ID
   (trừ sự cố 4: không ảnh hưởng request ở cả hai mode). Truyền strata_cpu_budget vào strata_tx_new.
2. strata_event_sink_t: init(worker_id), send(buf,len) không chặn (OK/DROPPED), close(). Bản Unix datagram: socket mở trong
   init_process, sendto MSG_DONTWAIT; EAGAIN/ENOENT/ECONNREFUSED → DROPPED + counter 9. Buffer sự kiện 8 KB cấp một lần mỗi worker.
3. File metrics đúng layout STRMET1 (control-file.md): master tạo file (tạm → ftruncate → header → rename), worker ghi slot của mình
   bằng lệnh ghi 64 bit; bộ đếm 0..20 đúng chỉ số. Đường dẫn: directive mới strata_metrics_file (mặc định cạnh control file) —
   nêu trong kế hoạch.
4. Cờ force-shadow (Q2): đọc cùng lần đọc control file; policy bị ép → STRATA_TXF_FORCE_SHADOW (đã có trong strata.h).
5. strata_tx_free idempotent ở mọi đường (cleanup handler, redirect, lỗi). Internal redirect không inspect lại, không đếm metric 2 lần.
6. Giữ request sống khi có task thread pool (r->main->blocked, r->aio) như thiết kế.
7. HTTP/2: client RST_STREAM giữa lúc gửi body → không rò (ASan), không dùng tx sau khi free.

Test (Test::Nginx, t/060-fail-mode.t, t/061-events.t, t/062-metrics.t...):
- 4 sự cố × 2 fail mode = 8 ca, mỗi ca kiểm status, $strata_action/$strata_block_id, bộ đếm metrics 7/8.
- Sự cố engine: bundle test có rule kích hoạt panic (feature test-hooks) hoặc fixture bundle hỏng.
- Budget: strata_cpu_budget nhỏ + payload nặng (dùng bộ payload của W07-R-01).
- Event: một socket datagram giả trong test nhận và giải mã (hoặc dùng strata-emit/agent eventsock trong lab); socket không tồn tại → DROPPED.
- Metrics: đọc file bằng agent/internal/shmmetrics (test Go) hoặc script trong test; kiểm số request theo action.
- HTTP/2 RST: dùng raw-frame như các test HTTP/2 hiện có, chạy dưới ASan.
- Redirect: error_page/internal redirect → một lần inspect, một lần đếm.

Xong khi:
- 8 ca fail mode pass trên 1.30.5 và 1.31.6; RST_STREAM không rò dưới ASan; redirect không inspect/đếm 2 lần.
- Lab: deploy/lab smoke.sh pass với agent đọc file metrics thật (ACTIVE báo theo metrics, không theo ActiveDelay);
  một request bị chặn trên lab hiện trên UI qua đường thật (thay strata-emit) — đây là phần còn thiếu của W06-F-01.
- Lệnh: deploy/dev/run.sh make test NGINX_VERSION=1.30.5 và 1.31.6; make nginx-asan + make test-nginx-asan cả 2 bản;
  make nginx + make test-nginx-valgrind 1.30.5; phần C dưới 2.500 dòng code thực (CLAUDE.md).

Không được: parse input trong C; I/O chặn hay khóa trên đường đi request; đổi strata.h.
Mức review: L3.
```

### W07-G1-01 · Lệnh ForceShadow và chẩn đoán · Review L3 · Cần trước: W07-N-01 (quyết định Q2)

```
<phần mở đầu chung>  NHÁNH = W07-G1-01-agent-commands

Nhiệm vụ W07-G1-01 · Độ bền agent: lệnh ForceShadow, thu chẩn đoán, test mất mạng (agent/, control-plane/fleet/, control-plane/admin/,
proto/ chỉ khi kế hoạch chứng minh cần).
Đọc: nginx-module.md › "Giao thức gRPC agent ↔ control plane", "Fallback" (ForceShadow); proto/strata/fleet/v1/fleet.proto
(Command, ForceShadow{policy_id, route, duration_seconds}, CollectDiagnostics, CommandResult).

Hiện trạng (đừng làm lại):
- Kết nối lại có backoff lũy thừa + jitter (agent/internal/control/control.go, BackoffMin/Max).
- Gia hạn chứng chỉ khi còn 1/3 thời hạn, thử lại có jitter (renewLoop; identity.RenewAt).
- Agent nhận ControlMessage_Command nhưng chưa xử lý ("Commands come with W12"); control plane chưa gửi Command.

Làm:
1. Control plane: API admin gửi ForceShadow (policy, connector group hoặc node, thời hạn) và CollectDiagnostics; RBAC
   (quyền deploy policy) + audit; Command đi qua luồng Connect đang mở (presence AttachControl/Notify) tới node trực tuyến.
2. Agent: ForceShadow → ghi cờ vào control file theo Q2 (seqlock, như ghi bundle), xóa khi hết duration_seconds (kể cả sau khi agent khởi động lại:
   lưu hạn chót), trả CommandResult. route khác rỗng → CommandResult lỗi "route not supported" (chưa có route trong control file).
   CollectDiagnostics → CommandResult kèm thông tin không nhạy cảm (phiên bản, bundle đang chạy, counters) — không gửi khóa, file cấu hình.
3. Test toxiproxy: tests/e2e (docker) chặn mạng agent ↔ control plane 5 phút (cho phép rút ngắn bằng biến môi trường trong CI, nhưng chạy đủ 5 phút
   một lần và ghi output) → agent tự nối lại, trạng thái node về online.
4. Test chứng chỉ hạn ngắn (ví dụ 3 phút): gia hạn xảy ra khi còn ~1/3, không mất kết nối.

Xong khi:
- Cắt mạng 5 phút → tự nối lại (output thật).
- Chứng chỉ gia hạn đúng thời điểm (test).
- ForceShadow từ API → request đáng lẽ bị chặn trên NGINX lab chuyển sang EVT- trong ≤ 5 giây (đo từ lúc gọi API); hết hạn thì trở lại chặn.
- GOTOOLCHAIN=auto go test -race ./... trong agent/, control-plane/, tests/e2e; golangci-lint sạch; lab smoke pass.

Bảo mật: chỉ control plane đã xác thực mTLS gửi được Command; node bị thu hồi không nhận; CommandResult từ agent là dữ liệu không tin cậy.
Mức review: L3 (nhạy cảm bảo mật).
```

### W07-G2-01 · Signer KMS và cost unit · Review L3 · Cần trước: —

```
<phần mở đầu chung>  NHÁNH = W07-G2-01-kms-signer

Nhiệm vụ W07-G2-01 · Signer KMS, cost unit (control-plane/policy/, control-plane/cmd/, engine/compiler/ cho đường ký ngoài,
deploy/lab cho Vault dev mode).

Hiện trạng:
- Không có thư mục control-plane/compiler/: compiler là control-plane/policy/compiler.go, gọi strata-compile với --key <file seed Ed25519>.
- API rollout :pause / :resume / :abort đã có (control-plane/admin/rollout.go, W05-G2-01), có test: chỉ kiểm lại, không làm lại.

Làm:
1. Ký ngoài: strata-compile thêm chế độ xuất bundle chưa ký (hoặc xuất phần cần ký) và lệnh gắn chữ ký 64 byte cuối;
   định dạng bundle không đổi (chữ ký Ed25519 trên toàn bộ byte phía trước). Control plane ký qua Vault transit (khóa ed25519,
   cấu hình bằng biến môi trường), khóa không bao giờ rời Vault; chế độ file seed giữ cho lab/dev, chọn bằng cấu hình.
   Public key lấy từ Vault để kiểm lại chữ ký trước khi lưu bundle.
2. Cost unit: compiler tính chi phí mỗi rule (số pattern Hyperscan, số target, transformation, operator đắt như detect_*, regex fallback);
   policy vượt ngân sách → 400 kèm tên 3 rule tốn nhất. Công thức và ngân sách mặc định ghi trong báo cáo.
3. Lab: Vault dev mode trong deploy/lab, khóa tạo khi khởi động lab.

Xong khi:
- Test chứng minh khóa không rời KMS: đường ký không đọc seed; không có khóa trong file, log, test fixture (grep trong báo cáo).
- Bundle ký bằng Vault được agent và NGINX chấp nhận (lab-chain.sh pass với signer Vault).
- Policy vượt cost → 400 với tên rule (test).
- GOTOOLCHAIN=auto go test -race ./... và golangci-lint; cargo test cho thay đổi compiler.

Mức review: L3 (nhạy cảm bảo mật).
```

### W07-S-01 · Nhập Sigma, ET Open, danh sách bot · Review L2 · Cần trước: — (quyết định Q4, Q5)

```
<phần mở đầu chung>  NHÁNH = W07-S-01-import-sigma-et

Nhiệm vụ W07-S-01 · Nhập Sigma, ET Open, danh sách bot (tools/strata-import-sigma/, tools/strata-import-et/, rules/, corpus/sources.yaml, NOTICE).
Đọc: plan.md › Luồng S › Nguồn luật và cách dùng; rules/README.md; tools/strata-import-crs (cách làm mẫu: nguồn ghim bằng commit/sha,
lý do cho mọi rule bỏ ra, report, make target, CI kiểm file sinh ra là mới nhất); rules/reviews/2026-10-11-protocol-and-crs.md.

Hiện trạng: rules/samples có 1 mẫu cho mỗi nguồn (400100 web shell, 500100 scanner UA). Engine chạy được: rx, pm, contains, begins/ends_with,
streq, số, detect_*, (ip_match sau W07-R-02); target trong strata-eval --capabilities.

Làm:
1. Sigma rules/web (DRL 1.1) → dải 400000; ET Open chỉ SID 2000000–2099999 (BSD) và chỉ rule HTTP (http_uri, http_header, http_user_agent...)
   → dải 400000 (chia dải con, ghi trong README); crawler-user-agents → dải 500000. Mỗi nguồn ghim phiên bản (commit + sha256).
2. Mọi rule có author, license, upstream_id, upstream_version; rule không chuyển được ghi lý do trong docs/<nguồn>-import-report.md.
3. Importer ET từ chối SID ngoài 2000000–2099999 (test âm).
4. Mỗi rule nhập: mẫu khớp/không khớp lấy từ nguồn nếu có; không có thì sinh mẫu từ pattern và đánh dấu.
5. FP: strata-rules report trên corpus benign — mỗi bộ nhập thêm không làm FP benign tăng; rule gây FP thì bỏ kèm lý do.
6. Virtual patch dải 700000: chỉ làm nếu PO đã cho stack route thí điểm (Q4); nếu chưa, ghi ⛔ trong báo cáo.

Xong khi: như plan (author, license, upstream_id; ET từ chối SID ngoài dải có test); số rule nhập theo nguồn trong báo cáo;
make lint-rules, make test-rules pass; FP benign không tăng. (Hiển thị tác giả trên UI: Q5, không thuộc tuần 7.)
Mức review: L2. Rule nhập cần lượt duyệt luồng S như rules/reviews/.
```

### W07-F-01 · Trang Fleet · Review L1 · Cần trước: —

```
<phần mở đầu chung>  NHÁNH = W07-F-01-fleet-page

Nhiệm vụ W07-F-01 · Trang Fleet (ui/).
Đọc: nginx-module.md › "Giao diện quản trị"; ui/src/pages/FleetPage.tsx; ui/tests/events.spec.ts (cách mock API, signedIn);
OpenAPI control-plane (ui/src/api/generated).

Hiện trạng: FleetPage hiện node (online/offline/revoked) và group từ API (W04-F-01). Chưa có phiên bản proxy/module/bundle theo node
và trạng thái rollout theo node.

Làm: nhóm theo connector group; mỗi node: hostname, phiên bản NGINX, module, bundle đang chạy, trạng thái bundle
(DOWNLOADING/VERIFIED/ACTIVE/FAILED) cập nhật trực tiếp (polling hoặc stream nếu API có; không tự đặt URL ngoài client sinh từ OpenAPI);
rollout đang chạy: đợt, node theo trạng thái. Thiếu trường nào trong API thì dừng và đề xuất (đổi OpenAPI là interface chung).
i18n vi/en; viewer chỉ xem.

Xong khi: deploy một policy trên lab → thấy từng node chuyển trạng thái trên UI (ghi màn hình hoặc ảnh chụp từng bước);
Playwright: mock chuyển trạng thái VERIFIED → ACTIVE, FAILED; npm run lint, npm test, npm run build, npx playwright test pass.
Mức review: L1.
```

### W07-Q-01 · Phân tích tĩnh cho C · Review L1 · Cần trước: — (quyết định Q6)

```
<phần mở đầu chung>  NHÁNH = W07-Q-01-static-analysis

Nhiệm vụ W07-Q-01 · Phân tích tĩnh cho C (Makefile, .github/workflows/ci.yml, deploy/dev/Dockerfile nếu cần cài clang-tidy).

Làm: đích make clang-tidy cho connectors/nginx/src (compile_commands từ build NGINX của make nginx), cấu hình .clang-tidy
(nhóm bugprone, cert, clang-analyzer, security; tắt từng check gây nhiễu kèm lý do); job CI chạy đích này. CodeQL (Q6): workflow
.github/workflows/codeql.yml sẵn sàng cho khi có GitHub; trước đó chạy CodeQL CLI một lần trong image dev, lưu tóm tắt vào báo cáo.

Xong khi: deploy/dev/run.sh make clang-tidy chạy được, không còn cảnh báo mức cao (cảnh báo nào cũng có ticket trong báo cáo,
không tắt để cho qua); job CI có trong ci.yml; kết quả CodeQL CLI trong báo cáo.
Mức review: L1.
```

## 5. Prompt cho Claude Code (review)

**Review kế hoạch** (L3: R-01, R-03, N-01, G1-01, G2-01)
```
Đọc AGENTS.md mục 5, 6, 6a, 6b, docs/plan/dispatch-w07.md mục 1 và mục <MÃ>. Đối chiếu Implementation Plan dưới đây với hiện trạng code
trên main (được đọc code để kiểm "hiện trạng", không viết code):
<dán kế hoạch>
Trả về tối đa 10 mục [Cao|TB|Thấp] vấn đề → yêu cầu sửa. Dòng cuối: OK hoặc SỬA KẾ HOẠCH.
```

**Review nhánh** (L2, L3)
```
Review PR <số> của <MÃ> theo AGENTS.md mục 6b, mức <L2|L3>.
Đọc nội dung PR (báo cáo), gh pr diff <số>, gh pr checks <số>. L3: checkout nhánh, chạy lại kiểm chứng (sanitizer, -race, prove 2 bản NGINX, fuzz ngắn).
Lỗi Cao ở L3 sửa được trong khoảng 30 dòng thì tự sửa (commit "review: ..." vào nhánh của PR), còn lại ghi yêu cầu sửa cho Antigravity.
Đăng kết quả bằng gh pr review. APPROVE và CI xanh thì merge (gh pr merge --squash hoặc --rebase theo quy ước) và xóa nhánh.
```

**Sửa theo review** (Antigravity), **Review lại**, **Claude Code nhận làm**: dùng như mục 0 của `docs/plan/dispatch.md`.

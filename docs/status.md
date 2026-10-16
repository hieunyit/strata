# Trạng thái thật của tính năng

Đối chiếu lại: 16/10/2026. Baseline main là `991c4bb7a662765d038606a3ceb3a284cef2e270`; bảng tuần dưới đây có bằng chứng lịch sử, không phải trạng thái deployment hiện thời. Các bản sửa đang review nằm trong [remediation tracker](reports/remediation-tracker.md), có base/PR riêng và chưa merge. Không suy ra một tính năng đã có trên main từ file trong nhánh prototype hoặc từ một PR khác.

Con trỏ tuần trong AGENTS.md vẫn là tuần 8, trong khi có bảng mở sớm tuần 11–13; PO quản lý con trỏ này. Tài liệu này không tự nâng tuần hoặc đánh dấu nhiệm vụ tương lai đã hoàn thành.

Ký hiệu:

- **Có**: có implementation và bằng chứng test/báo cáo được dẫn. Không đồng nghĩa đã triển khai trên route thật hoặc đạt mọi SLO; xem phạm vi SHA/lab của từng báo cáo.
- **Một phần**: làm được một phần; cột Ghi chú nói phần nào còn thiếu.
- **Thiết kế**: mới có trong tài liệu thiết kế hoặc kế hoạch, chưa có code.

Bảng này được kiểm lại trong mỗi lần review tuần. Một dòng chỉ được ghi "Có" khi trỏ tới
được test hoặc báo cáo.

## 1. Danh mục tính năng (`docs/design/strata-overview.md`, mục "Danh mục tính năng")

| Tính năng | Phase | Trạng thái | Bằng chứng / ghi chú |
| --- | --- | --- | --- |
| HTTP compliance | 0 | **Có** | 40 rule protocol (`rules/protocol`, 0 FP trên corpus benign), detector `engine/src/detectors/protocol`; `make test-rules`, `connectors/nginx/t/005-protocol.t`. Bật/tắt từng check: theo rule ID trong gói, chưa có công tắc theo policy |
| Evasion techniques | 0 | **Một phần** | Transform CRS (`urlDecodeUni`, `normalizePath`, `utf8toUnicode`…), rule 100113/100114, go-ftw CRS 95,9% (`docs/reports/w08-s-01.md`). Biến thể lách được: 11% trên gói v0, encode hai lần lách 86% CMDi (`docs/mutation-report.md`, #34) |
| Allowed methods | 0 | **Một phần** | Rule 100101–100103 (method ngoài tập chuẩn, TRACE/TRACK, CONNECT). Chưa có danh sách method theo policy hoặc theo URL |
| IP lists, do-nothing path | 0 | **Một phần** | Operator `ip_match` (W07-R-02, `engine/src/operators.rs`) dùng được trong rule riêng. Chưa có danh sách allow/deny theo policy, chưa có path bỏ qua inspect (dùng `strata off` theo location NGINX) |
| XFF trusted headers | 0 | **Một phần** | Module dùng `$remote_addr`, nên để lấy IP thật thì dùng `ngx_http_realip_module` của NGINX (`set_real_ip_from`). Control plane có `-trusted-proxies` cho đăng nhập (PR #50). Chưa có cấu hình riêng trong policy |
| Block page, Block ID | 0 | **Có** | `connectors/nginx/t/030-block.t`, `docs/reports/w06-response-path.md`, tra Block ID qua API/UI < 1 s (`docs/reports/w09-g2-01.md`) |
| URL, parameter, header, cookie entities | 1 | **Thiết kế** | Chỉ có giới hạn độ dài trong rule protocol (100107, 100109) |
| JSON / XML content profile | 1 | **Một phần** | Parser JSON/XML có giới hạn độ sâu và số phần tử (`engine/src/json.rs`, `xml.rs`), kích thước body theo `strata_request_body_limit`. Chưa có profile theo policy |
| OpenAPI enforcement | 1 | **Thiết kế** | — |
| Filetypes | 1 | **Thiết kế** | — |
| Override rules, exceptions | 1 | **Thiết kế** | Exception từ Block ID ở W14-* |
| Custom rules (biểu thức) | 1 | **Có** | Rule riêng theo JSON Schema IR (`rules/samples`, `rules/schema`), `make test-rules` |
| Attack signatures + signature sets | 2 | **Có** | Gói 0.0.1: 9.054 rule (CRS 4.25.2 PL1, ET Open, Sigma, bot, rule riêng), FP 0,60%, recall ≥ 70% (`docs/reports/w09-s-01.md`). Chọn theo server technology: chưa có. Tách gói core (202 rule) / signature (8.852 rule): `strata-rules release --pack`, policy `signatures: off\|shadow\|enforce`, mặc định shadow (RV-S-01, `engine/compiler/tests/signature_pack.rs`). Ngưỡng lên gói core: chờ PO |
| Time-based signature staging | 2 | **Một phần** | Mỗi gói mới chạy 7 ngày trên staging (`docs/reports/w09-s-01.md` §5). Chưa có cơ chế theo từng rule ("rule mới chỉ ghi log N ngày") |
| Semantic detectors | 2 | **Một phần** | SQLi và XSS: port libinjection (`engine/src/detectors/injection`, `make libinjection-diff`). CMDi, path traversal: qua rule CRS, không phải detector ngữ nghĩa. SSRF, template injection: chưa có |
| Response: allowed codes, response signatures | 2 | **Có** | Rule 600001 (mã trả về ngoài danh sách, cố định trong v0), lỗi DB trong response; `t/050-response.t`, `t/051-response-layer.t`, `docs/reports/w06-response-path.md`. Danh sách mã theo policy: chưa có |
| Data guard | 2 | **Một phần** | Che CCCD, JWT trong response và trong snippet sự kiện (`engine/src/detectors/response`). PAN và pattern che dữ liệu theo policy đã có trong main (`control-plane/policy/spec.go`, `engine/src/detectors/response/pan.rs`, `engine/src/event.rs`); không đồng nghĩa xác minh chữ ký JWT |
| Cookie integrity | 2 | **Thiết kế** | — |
| JWT protection | 2 | **Thiết kế** | Hiện chỉ phát hiện và che JWT trong response; chưa kiểm thuật toán, chữ ký, claim |
| GraphQL protection | 3 | **Thiết kế** | — |
| gRPC protection | 3 | **Thiết kế** | `nginx-module.md`, mục "Traffic gRPC qua NGINX"; module chưa tách message gRPC |
| Brute force | 3 | **Thiết kế** | Chưa có rate limit nào (RV-R-03, tuần 14) |
| Bot signatures + fingerprint | 3 | **Một phần** | 1.454 rule User-Agent từ crawler-user-agents (`rules/bots`). Chưa có JA4 hoặc fingerprint HTTP/2 (RV-N-02), chưa có challenge (RV-R-04), chưa xác minh bot tốt (W18) |
| Geolocation, IP intelligence | 3 | **Thiết kế** | W17–W19 |
| Threat campaigns | 3 | **Thiết kế** | Rule ET Open có CVE nhưng không có feed chiến dịch |

## 2. Nền tảng

| Năng lực | Trạng thái | Bằng chứng / ghi chú |
| --- | --- | --- |
| Module NGINX: request, body (đồng bộ/bất đồng bộ), response, HTTP/2, HTTP/3 | **Có** | Test::Nginx 553 test trên NGINX 1.30.5 và 1.31.6, ASan cả hai bản (`docs/reports/w08-n-01.md`, `docs/reports/w10-n-01.md`) |
| Hot reload bundle, không rớt request | **Có** | `t/004-reload.t`; bằng chứng soak trong `docs/reports/w09-q-02.md` là của lượt/phiên bản được ghi tại đó. Không lấy lịch dự kiến 14/10 làm bằng chứng một tiến trình hiện còn chạy hoặc đã hoàn tất |
| Fail mode open/closed, CPU budget hợp tác | **Có** | `t/060-fail-mode-events.t`, `docs/reports/w07-cpu-budget.md`. Mặc định hiện là 10 ms; số cũ 2 ms ở `docs/reports/w10-g2-01.md` §4 là lịch sử. Body lớn vẫn PARTIAL ở 10 ms (`reports/h2-current-pack.md`, PR #134); không đổi chính sách chỉ để đạt số đo |
| Cô lập lỗi engine (`catch_unwind`) | **Một phần** | Mọi hàm `extern "C"` bọc `catch_unwind`: panic thành lỗi engine, worker sống (`engine/ffi/tests/panic_isolation.rs`). **Không** bắt được abort, OOM, stack overflow hay lỗi bộ nhớ trong code `unsafe` (`engine/ffi/`) và trong khoảng 2.600 dòng C. Breaker cấp worker: có (W11-N-01, `t/090-breaker.t`), chế độ giảm cấp chỉ lớp protocol và `ip_match` |
| Sự kiện (socket → agent → control plane → ClickHouse) | **Có** | `tests/e2e/lab-chain.sh`, smoke. Sự kiện shadow chỉ về ClickHouse từ PR #55 (#47). Từ RV-G2-01 (#68) và #57: `would_block` tách shadow (lẽ ra chặn) với `pass` (rule khớp dưới ngưỡng); module cũ vẫn ghi mọi sự kiện `EVT-` có rule là shadow |
| Agent: enroll, mTLS, gia hạn chứng chỉ, bundle, spool, ForceShadow | **Có** | `agent/` test, `tests/e2e/agent_resilience_test.go`, `docs/reports/w07-g1-01.md`, `w08-g2-01.md` (toxiproxy) |
| Rollout theo đợt, abort, node mới nhận bundle của fleet | **Có** | `tests/e2e/rollout_test.go` (`TestRolloutToRealAgents`, `TestNewNodeGetsTheFleetBundle`) |
| Circuit breaker cấp worker | **Có** | `connectors/nginx/t/090-breaker.t`, `docs/reports/w11-report.md`. Chuyển trạng thái chưa phát sự kiện qua event socket (chỉ `error.log`, metrics) |
| Canary theo % request | **Một phần** | Hash nhóm và tỉ lệ trong bundle (`engine/src/canary.rs`), `canary_percent` trong API policy và UI (W12-G2-01), bộ đếm theo nhóm trong metrics file (`t/110-canary-metrics.t`). Chưa bật trên route nào (1% rồi 5% là việc vận hành) |
| Fallback tại node | **Có** | `agent/internal/fallback` (`TestNodeFallsBackWithinSixSeconds`: 4,5 s; `TestThresholdEdges`). Tính cho cả node, ép shadow mọi policy; giữ cho tới khi control plane gỡ (W12-G1-01, `TestFallbackHoldOnlyEndsOnClearAll`) |
| Tắt rule khẩn cấp (kill switch) | **Có** | W12-R-02/G1-02/N-02/G2-02: `POST /v1/rules/{id}:emergencyDisable` theo connector group → mọi node; 1.000 agent nhận trong 31 ms (`TestKillSwitchReaches1000Agents`), worker áp trong 1 s (`t/100-kill-switch.t`). Chưa có nút trên UI |
| Fallback toàn cụm (canary) | **Có** | W12-G2-01 `control-plane/fleet/canary.go`: giả lập chặn nhầm 40% → ngắt sau 10 s (`TestMassFalsePositiveTripsWithinAMinute`), ForceShadow tới mọi node (`TestHeartbeatsTripAndForceShadowReachesTheNodes`). Chỉ ép shadow policy canary; chưa diễn tập trên lab |
| Control plane: policy, deploy, ký (Vault Transit), RBAC, audit | **Có** | `make test-go`; `docs/reports/w07-g2-01.md`; tải Fleet 1.000 agent (`docs/reports/w08-g1-01.md`) |
| Đăng nhập cục bộ (không cần IdP) | **Có** | PR #50: `control-plane/localauth` (argon2id, khóa tài khoản, giới hạn theo IP, audit), `TestThrottlingPerClientBehindAProxy` |
| Web UI: sự kiện, decision trace, Fleet, Tổng quan, người dùng | **Có** | `ui/` vitest 46, Playwright 15 (`docs/reports/w10-f-01.md`); số shadow trên Tổng quan đúng từ #47 |
| Giám sát: dashboard, cảnh báo | **Có** | `make test-alerts` (18 cảnh báo có unit test), `tests/e2e/lab-alerts.sh` (`docs/reports/w10-q-01.md`); FP shadow từ ClickHouse (`docs/reports/w10-s-01.md`) |
| Gói deb/rpm, image, cài 1 lệnh | **Có** | `deploy/packaging/test/test-install.sh` (Ubuntu 24.04, Debian 12, Rocky 9), `test-image.sh` (`docs/reports/w10-n-01.md`). Mới có x86_64 và NGINX OSS; chưa ký gói, chưa SBOM |
| Runbook đã diễn tập | **Có** | `tests/e2e/runbook-drill.sh` trên lab và staging (`docs/reports/w10-n-01.md`) |
| Replay | **Một phần** | Định dạng mẫu 1 (`docs/spec/replay-sample.md`, **chưa được pháp chế duyệt**), ẩn danh trong libstrata = Go (`engine/tests/anon_vectors.rs`), lấy mẫu tại connector với khóa HMAC mỗi group (W12-N-01, `t/120-replay-sample.t`; **mặc định tắt**, cần `-replay-sampling-approved`), `strata-replay compare` + báo cáo bản nháp (W12-R-01, `docs/reports/w12/r01-replay-signatures.md`). service (W13-G2-01): mỗi version mới tự replay so với bundle đang chạy, trên mẫu traffic 7 ngày và corpus, kết quả qua `GET /v1/operations/{id}` và `…/versions/{v}/replay` |
| Differential với Coraza + CRS 4.25.2 | **Có** | `make coraza-diff` (`tools/coraza-diff`, `docs/reports/w12/r01-coraza-diff.md`): mọi khác biệt có lý do, 0 ticket |
| Policy editor | **Một phần** | Form + YAML, lưu bản nháp (`ui/src/__tests__/PolicyEditor.test.tsx`, `ui/tests/policy-editor.spec.ts`); diff hai phiên bản theo khối (W12-F-01, `PolicyDiff.test.tsx`, `ui/tests/policy-diff.spec.ts`). Chưa có luồng duyệt (W13) |
| Luồng duyệt policy | **Một phần** | API (W13-G2-02): `:submit`, `:approve`, `:reject`, người soạn/gửi không tự duyệt (theo `sub`, có CHECK trong DB), duyệt cần replay DONE (PO 16/10), deploy chỉ lấy bản đã duyệt, hàng chờ `…/-/versions?state=SUBMITTED` (`tests/e2e/four_eyes_test.go`). Chưa có màn hình hàng chờ (W13-F-01) |
| GitOps, OpenAPI công khai, bản đồ GeoIP | **Thiết kế** | W19–W21 |
| Connector khác NGINX (Apache, HAProxy, Envoy, Kong) | **Thiết kế** | Chỉ có NGINX; connector khác sau v1 |
| Chế độ Lite cho cụm nhỏ | **Thiết kế** | RV-G1-01 (tuần 19, cần PO) |

## 3. Những điều cần nói đúng

- **Fuzz**: không có "72 giờ fuzz mỗi PR". Fuzz chạy riêng. Lần dài nhất: FFI dưới ASan
  khoảng 9 giờ 50 phút, khoảng 122 triệu lần chạy, 0 crash (W08-R-01); lần đó dừng vì máy
  khởi động lại. PO quyết ngày 13/10/2026: 30 phút đến 1 giờ là đủ cho Gate A.
- **Route thí điểm là giả lập**: `pilot-verify` và `pilot-upload` trên staging và prod-sim,
  với lưu lượng do `deploy/staging/pilot-traffic.sh` sinh ra. Prod-sim không phải
  production. Số FP hiện có không phải số trên traffic thật (RV-Q-03 trước Gate B).
- **Hiệu năng**: mục tiêu của tài liệu (overhead p99 < 1 ms, throughput giảm ≤ 10%) chưa
  đạt. Phase 0–1 throughput giảm 46% (đo trên WSL2; số trên Linux ở
  `docs/reports/w09-q-01.md` §7). Gói đầy đủ: JSON nhỏ 1,6–2,7 ms, upload vài chục KB
  khoảng 20 ms trên staging. Đang làm: RV-R-01 (#27, #28).
- **Request không được kiểm**: khi vượt budget thì request đi theo fail mode (mặc định là
  cho qua). RV-N-01: sự kiện có cờ `inspection`; tỉ lệ request không được kiểm đủ **theo
  policy** trên trang Tổng quan, mẫu số từ bộ đếm của libstrata (bảng ClickHouse
  `policy_requests`, `nginx-module.md` › Sự kiện); theo route chỉ có số tuyệt đối. Có số
  từ bản module và agent có RV-N-01 (staging sau 20/10).

## 4. Phân biệt main, prototype và bản sửa đang review

- Main baseline nêu trên có API replay/four-eyes; UI approval queue ở nhánh remote `W13-G2-02-replay-gate` có merge #115 không chứng minh main có UI đó. Chưa đóng W13-F-01 chỉ từ nhánh khác.
- `RV-R-03-ratelimit` là prototype; chưa có đường request/shared-memory theo node, chưa có benchmark proxy đạt <2%. Không quảng bá brute-force protection đã hoạt động.
- `W14-G2-01-exceptions-api` và `W14-G2-02-rule-health` là prototype; RAM exception/health không phải policy artifact/runtime hoặc durable quarantine. H3/M1 đã có replacement PR #122/#123, không nhập nguyên prototype để lấy endpoint.
- H4 có bản sửa dispatch local `codex/h4-health-route`, SHA `3f2e4e7`; chưa nhập health prototype vào main và chưa chứng minh pipeline tự về staging. M4 vẫn chưa hoàn tất.
- M5 snapshot/proof/gate/API đang ở các PR #124/#126/#128–#130. “Replay DONE” cũ trên main không có cùng bảo đảm provenance với chuỗi PR này. Dùng report của đúng SHA để đánh giá.
- Rule header 300011–300013 là candidate trong PR #133/#136: Header SQLi 8/8, XSS 54/56, benign 47/47 trên tập đã chọn; chưa phát hành pack production, cần review nội dung và chi phí.
- H5 PR #127 sửa cache integrity, resume test và C line budget; archive ET Open nguyên bản còn thiếu. Không ghi pipeline Rules tái lập thành công khi chưa có artifact đúng checksum.
- Benchmark/HTTP trong remediation có hash executable/bundle và đơn vị rõ. `engine_serial_rps` không phải TPS NGINX; 1052,62 ms tương đương khoảng 1,053 giây. Campaign redteam cũ và game day chưa được xác nhận lại bởi các phép thử paired HTTP mới.

Không có bằng chứng rollout staging/production mới trong đợt remediation này. Theo yêu cầu người dùng, chạy kiểm chứng local, không chờ hosted CI; trạng thái CI cũ không được ghi thành PASS. Các điều kiện vận hành/Gate còn thiếu giữ nguyên.


Cập nhật remediation 17/10 (PR nháp, chưa merge/triển khai): #145–#151/#154/#155 nối exception chính xác từ policy/API vào compiler/bundle/engine, có PostgreSQL audit/idempotency và cùng replay/four-eyes/deploy. Probe thật 15 cặp/30 HTTP attempts kiểm trước/sau/thu hồi/hết TTL; object storage, event input và auth principal là test boundary, không phải chứng cứ ingest/Fleet/production. #153 giữ các thiết lập ngoài form UI và hiển thị trong diff; form tạo exception và hàng duyệt UI chưa được đưa vào stack này. Xem [tracker](reports/remediation-tracker.md).

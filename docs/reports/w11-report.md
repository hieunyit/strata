# Báo cáo tuần 11 (mở sớm) · Circuit breaker, canary, fallback, replay, policy editor

Ngày: 14/10/2026 · Nhánh: `claude/peaceful-pasteur-efxre2` · Người làm: Claude Code (phiên cloud)
Kế hoạch và quyết định PO: `docs/plan/w11-plan.md`

PO duyệt mở sớm khối B1 (13/10): làm các nhiệm vụ tuần 11 không phụ thuộc Gate A. Báo cáo Gate A,
RV-N-01, RV-Q-01 và review tuần 10 do phiên khác làm.

Môi trường: container cloud 4 nhân, không Docker, không lab, không staging. NGINX 1.30.5 và 1.31.6
build từ mã nguồn (GitHub, vì nginx.org bị proxy chặn), MinIO build từ mã nguồn Go. Không chạy
benchmark của module.

## 1. Tóm tắt

| Mã | Trạng thái | Xong khi → kết quả |
| --- | --- | --- |
| W11-R-01 | ✅ | Cùng client luôn cùng nhóm canary (test); replay 1 triệu request trong **2 phút 12 giây** với gói đầy đủ 9.054 rule, 4 luồng (container cloud, không phải lab) |
| W11-N-01 | ✅ | Tiêm panic hàng loạt → breaker mở ngay khi đủ 20 request trong cửa sổ 1 s của test (test đòi < 10 s), chạy giảm cấp; half-open tự đóng khi hết lỗi; mở lại nhân đôi thời gian; payload vượt budget không mở breaker (`t/090-breaker.t`) |
| W11-G1-01 | ✅ | Tỉ lệ chặn tăng gấp 4 → node về shadow sau **4,5 s** (yêu cầu ≤ 6 s), không cần control plane (`TestNodeFallsBackWithinSixSeconds`, chu kỳ thật 5 s) |
| W11-G2-01 | ✅ phần code; ⛔ phần duyệt | Định dạng mẫu đã ẩn danh (chỉ field nhạy cảm, quyết định PO 14/10), lưu và đọc lại được qua MinIO thật. **Chưa được pháp chế duyệt** (việc của người) |
| RV-S-01 | ✅ | `strata-rules release --pack core|signature` sinh 2 gói (202 + 8.852 rule); policy chọn `signatures: off|shadow|enforce`; test: policy mặc định không có rule signature nào chặn ở enforce |
| W11-F-01 | ✅ | Form và YAML song song, đồng bộ hai chiều; lưu thành phiên bản nháp (`DRAFT`) bằng PATCH kèm etag |

Không làm: W11-S-01 (cần ≥ 1 tuần shadow), RV-G2-01 (cần RV-R-01), bật canary (vận hành).

## 2. Từng nhiệm vụ

### W11-R-01 · Nhóm canary và lõi replay

- `engine/src/canary.rs`: bucket = FNV-1a 64 trên `tên policy ‖ 0xff ‖ khóa`, trộn splitmix64, mod
  10.000. Khóa là identity, không có thì địa chỉ client. Giá trị ghim trong test (kiểm chéo bằng một
  bản Python độc lập) để control plane tính lại được (W12-G2-01).
- Bundle: `u16` canary (basis point) ở byte 59–60 của bảng policy, chỉ với mode enforce, 1..9.999.
  `canary_percent` trong `policies.schema.json` (0,01–99,99). Engine chọn enforce hoặc shadow lúc
  `set_policy`. **Libstrata cũ từ chối bundle có canary**: nâng module trước (như `block_alone`).
- Test: cùng client luôn cùng kết quả; 1%/5% trên 200.000 khóa đúng tỉ lệ; nhóm 1% nằm trong nhóm 5%;
  identity thắng địa chỉ; hai policy chia nhóm độc lập.
- Lõi replay: crate mới `engine/replay` (`strata-replay run|gen`), dùng crate `parquet` 60 (quyết
  định PO 13/10: libstrata không thêm dependency). Một luồng đọc đẩy lô 512 mẫu qua hàng đợi có giới
  hạn tới N luồng engine; bộ nhớ không tăng theo số mẫu. Báo cáo theo route: action bây giờ, thay đổi
  so với lúc lấy mẫu, số bị chặn mới (nghi FP), không còn bị chặn (nghi FN), số mẫu theo rule.
- Đo 1 triệu request (`strata-replay gen` từ corpus benign + tấn công, gói đầy đủ):

  | | Giá trị |
  | --- | --- |
  | Thời gian | 132,4 s (7.552 request/s, 4 luồng) |
  | Bị chặn mới / mẫu benign | 2.808 / ≈ 467.000 (0,6%, khớp FP 0,60% của gói 0.0.1) |
  | Mẫu tấn công không bị chặn | ≈ 26% (khớp recall ≈ 74%) |

  Container cloud 4 nhân, không phải lab; trên lab 16 vCPU sẽ nhanh hơn.

### W11-N-01 · Circuit breaker cấp worker

- ABI 1.2 (chỉ thêm): cờ `STRATA_TXF_DEGRADED` trong `strata_conn_t.flags`. libstrata đã có chế độ
  giảm cấp nội bộ (chỉ lớp protocol và rule toàn `ip_match`); giờ mở qua FFI, test hook panic không
  chạy ở chế độ này. Rate limit chưa có (RV-R-03).
- `connectors/nginx/src/ngx_http_strata_breaker.c`: Closed / Open / Half-open theo thiết kế (2% trong
  10 s, tối thiểu 200 request; mở 30 s, nhân đôi tới 5 phút; half-open 1/20 request qua engine đầy đủ,
  dưới 0,5% lỗi thì đóng). Chỉ tính `STRATA_E_INTERNAL`, `E_INVALID`, `E_STATE`; không tính budget,
  bundle, incomplete. `strata_breaker_action reject` trả 503 kèm Event ID.
- Directive: `strata_breaker`, `strata_breaker_threshold <tỉ lệ>% <cửa sổ> <tối thiểu> [open=<time>]`
  (http), `strata_breaker_action degrade|reject` (mọi cấp).
- Metrics file: bộ đếm 21 trạng thái, 22 số lần mở, 23 số request giảm cấp. Agent xuất
  `strata_breaker_state{worker}`, `strata_breaker_opens_total`, `strata_degraded_requests_total`.
  Cảnh báo `StrataBreakerOpen` (warning) và `StrataBreakerOpenManyWorkers` (critical), panel dashboard,
  mục runbook "Circuit breaker mở".
- Phần C: 2.832 / 3.000 dòng thực.
- **Khác thiết kế** (ghi trong `nginx-module.md`): directive ngưỡng ở mức http; thêm `open=`; cửa sổ
  cố định; chuyển trạng thái chưa phát sự kiện qua event socket (chỉ ghi `error.log` và metrics).

### W11-G1-01 · Fallback tại node

- `agent/internal/fallback`: mỗi 5 s lấy hiệu bộ đếm của cả node. Mức nền "lẽ ra chặn" = (block + log)
  / request, học bằng trung bình động (khởi động 12 khoảng). Ngắt khi tỉ lệ chặn > 3 × mức nền (mức nền
  tối thiểu 0,5%), hoặc lỗi engine hay vượt budget tăng 3 lần; cần ≥ 100 request mỗi khoảng và có chặn
  thật. Ép shadow **mọi policy** (quyết định PO 13/10) trong `--fallback-hold` (1 giờ), qua cùng
  `force-shadow.json` với lệnh `ForceShadow`.
- Flag `--fallback` (mặc định bật), `--fallback-factor`, `--fallback-hold`. Metric
  `strata_agent_fallback_triggers_total{reason}`, cảnh báo `StrataNodeFallback`, runbook "Node tự về
  shadow".
- **Rủi ro**: một đợt tấn công thật làm tỉ lệ chặn tăng cũng đưa node về shadow trong 1 giờ. Tầng 2
  (W12-G2-01) so canary với shadow nên không bị ảnh hưởng. Hiện mọi node đều shadow nên tầng 1 không
  có tác dụng cho tới khi bật canary.

### W11-G2-01 · Định dạng traffic mẫu cho replay

- Đặc tả `docs/spec/replay-sample.md`: Parquet, 15 cột, metadata `strata.replay.format=1` và id khóa.
  Lưu tại `replay/v1/<policy>/<yyyy>/<mm>/<dd>/<node>-<ts>-<seq>.parquet`.
- Quyết định PO 14/10: chỉ **field nhạy cảm** thành token `~h:<16 hex HMAC>:<lớp><độ dài>`: header
  xác thực, cookie, IP; tham số theo tên (password, token, otp, cccd, phone, email, name...); giá trị
  theo dạng (JWT, email, số điện thoại VN, CCCD 12 số, số thẻ có Luhn); nội dung file multipart; địa
  chỉ client. Payload tấn công và cách mã hóa (double encoding) được giữ.
- `control-plane/replay` (Go, thêm dependency `parquet-go` 0.25.1); vector chung
  `docs/spec/examples/replay-anon-v1.json`; test "không lọt giá trị nhạy cảm"; lưu và đọc lại qua
  **MinIO thật** (`TestStoreInMinIO`, MinIO build từ mã nguồn).
- Còn lại: **pháp chế duyệt định dạng** trước khi lấy mẫu traffic thật; W12-N-01 viết lại phần ẩn danh
  trong libstrata, phải khớp đúng vector.

### RV-S-01 · Tách gói core và signature

- Rule mang cờ "gói signature" (bit 2 byte cờ bản ghi `RULES`) khi `metadata.source` là `sigma`,
  `et-open`, `crawler-user-agents`. Policy có `signatures: off|shadow|enforce` (byte 61 bảng policy).
  Mặc định **shadow**: rule chạy và được báo (Event ID `EVT-`, action log), điểm tính riêng, không bao
  giờ chặn, kể cả ở policy enforce.
- `strata-rules release --pack core|signature`: gói core 202 rule (CRS 148, strata 52, organization 2),
  gói signature 8.852 rule (ET Open 7.377, crawler-user-agents 1.454, Sigma 21).
- Bộ đo chất lượng (`test-rules`, `test-signatures`, chỉ tiêu Gate A) dùng `signatures: enforce`: kết
  quả không đổi, xanh. Fixture NGINX đặt `signatures: enforce` cho `example-api` để giữ ý nghĩa test.
- **Thay đổi hành vi**: bundle build từ code mới, policy không ghi `signatures` thì rule signature
  không còn chặn. Hiện các policy staging/thí điểm đều shadow nên không ảnh hưởng. **Libstrata cũ từ
  chối bundle có bit 2**: nâng module trước. Còn chờ PO: ngưỡng FP production và N ngày shadow để rule
  lên gói core (`review-response.md` 6.x).

### W11-F-01 · Policy editor phần 1

- `ui/src/components/policy/PolicyEditor.tsx`, `ui/src/lib/policyYaml.ts`: form (mode, oversize, lớp
  response) và YAML (tên trường theo `policies.schema.json`) song song. YAML lỗi thì báo dòng, form giữ
  bản hợp lệ cuối, nút lưu tắt. Bộ đọc YAML tự viết cho đúng cấu trúc policy (không thêm thư viện).
- Lưu = PATCH với etag → phiên bản mới ở trạng thái `DRAFT`; 409 thì báo có người sửa trước. Nút sửa
  chỉ hiện với operator và admin (API vẫn kiểm quyền). Chuỗi tiếng Anh và tiếng Việt.
- Ảnh: `docs/reports/w11/f01-policy-editor.png` (dữ liệu giả lập Playwright).
- Chưa có trong editor: `canary_percent` và `signatures` (API policy chưa có hai trường này, theo quyết
  định PO 13/10).

## 3. Kiểm chứng

| Lệnh | Kết quả |
| --- | --- |
| `cargo fmt --check`, `cargo clippy --workspace --all-targets --all-features -D warnings` | sạch |
| `cargo test --workspace --all-features` | 286 test, 0 lỗi |
| Test::Nginx 1.30.5 và 1.31.6 (`prove -r t/`, user thường) | 570/570 mỗi bản |
| `make check-header`, `check-fixtures`, `check-c-lines` | xanh; 2.832 / 3.000 dòng C |
| `go vet` + `go test` agent, control-plane, tools/strata-rules | xanh (trừ `TestAgentMetrics`, dưới) |
| `make test-rules` (gồm `test-signatures`, chỉ tiêu Gate A) | xanh |
| `make test-alerts` | SUCCESS, 46 metric xuất ra |
| UI `tsc`, `vitest` (56 test), Playwright (16 test, có trình sửa policy) | xanh |
| `TestStoreInMinIO` (MinIO thật) | xanh |

## 4. Vấn đề có sẵn, không thuộc phiên này

- `make abi-test`: 2 CHECK sau panic lỗi trên cả `origin/main` (`abi_test.c:313, 315`).
- `TestAgentMetrics` chập chờn: lỗi 3/12 lần trên `origin/main` (đọc gauge spool trước khi ack về).
- `t/060-fail-mode-events.t` lỗi phần sự kiện khi chạy dưới root (worker `nobody` không gửi được tới
  socket của root); dưới user thường thì xanh.
- #44 (`credited_time_does_not_count` chập chờn): bản sửa của nhánh `issue-28-hs-groups` được
  cherry-pick vào nhánh này (không đổi gì khi nhánh kia merge).

## 5. Cần người làm

1. Cập nhật `CLAUDE.md` (mục "Phạm vi hiện tại") và `AGENTS.md` (con trỏ tuần, bảng tuần 11): phiên
   này không được sửa file chỉ dẫn của agent; nội dung đề xuất ở `docs/plan/w11-plan.md`.
2. Pháp chế duyệt `docs/spec/replay-sample.md`.
3. PO: ngưỡng FP production và số ngày shadow cho RV-S-01; khi nào thêm `canary_percent` và
   `signatures` vào API policy và editor.
4. Kiểm trên lab (phiên này không có lab): breaker và fallback với agent thật, Grafana panel mới.

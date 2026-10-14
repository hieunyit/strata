# Báo cáo tuần 12 (mở sớm) · Tắt rule khẩn cấp, fallback, canary toàn cụm, replay

Ngày: 14/10/2026 · Nhánh: `claude/peaceful-pasteur-efxre2` (PR #61) · Người làm: Claude Code (phiên cloud)
Kế hoạch: `docs/plan/w12-plan.md`

Môi trường như tuần 11: container cloud 4 nhân, không Docker, lab hay staging. NGINX 1.30.5 và
1.31.6 build từ mã nguồn. Không chạy benchmark của module; benchmark engine của W12-R-02 chạy ghim
1 nhân (dưới).

## 1. Tóm tắt

| Mã | Trạng thái | Xong khi → kết quả |
| --- | --- | --- |
| W12-R-02 | ✅ | Rule bị tắt không còn khớp; danh sách rỗng → như cũ (test engine, FFI, compiler); benchmark không đổi (6 lần xen kẽ, ghim 1 nhân, trung vị như nhau) |
| W12-G1-02 | ✅ | Lệnh tới **1.000 agent**, chậm nhất **31 ms** (yêu cầu < 10 s, `TestKillSwitchReaches1000Agents`) |
| W12-N-02 | ✅ | Agent ghi danh sách → mọi worker áp trong **0,06 s** (yêu cầu ≤ 1 s, `t/100-kill-switch.t`), kể cả sau reload và khi worker mới khởi động |
| W12-G2-02 | ✅ | Chỉ `operator` trở lên gọi được (viewer 403, có test); lý do bắt buộc; audit ghi người, lý do, group (`TestEmergencyDisableRule_REST`, `TestDisabledRulesInPostgres`) |
| W12-G1-01 | ✅ | Test biên cho mọi ngưỡng (`TestThresholdEdges`); cờ của fallback chỉ gỡ bằng lệnh từ control plane (`TestFallbackHoldOnlyEndsOnClearAll`, `TestWatcherHoldsUntilCleared`) |
| W12-F-01 | ✅ | Chọn 2 version → diff theo khối Chung và Lớp response (vitest + Playwright, ảnh `docs/reports/w12/f01-policy-diff.png`) |
| W12-G2-01 | ✅ | Giả lập 20 node, bundle chặn nhầm 40%: ngắt **10 s** sau khi bundle lên (yêu cầu < 1 phút, `TestMassFalsePositiveTripsWithinAMinute`); `ForceShadow` tới mọi node **0,1 s** sau heartbeat xấu (`TestHeartbeatsTripAndForceShadowReachesTheNodes`) |
| W12-N-01 | ✅ (mặc định tắt) | Mẫu đúng định dạng W11-G2-01 (vector của spec + corpus differential 400 ca, Rust = Go từng byte); field nhạy cảm không còn giá trị gốc (`t/120-replay-sample.t`, `TestNoSensitiveValueLeaks`). Bật cần cờ `-replay-sampling-approved` sau khi pháp chế duyệt |
| W12-R-01 | ✅ | Báo cáo replay cho một bản nháp (`docs/reports/w12/r01-replay-signatures.md`); danh sách khác biệt với Coraza (`docs/reports/w12/r01-coraza-diff.md`): mọi khác biệt có lý do, **0 ticket** |

Làm theo thứ tự PO giao; các quyết định của PO ghi ở `docs/plan/w12-plan.md`.

## 2. Từng nhiệm vụ

### Tắt rule khẩn cấp (W12-R-02, W12-G1-02, W12-N-02, W12-G2-02)

Luồng: `POST /v1/rules/{rule_id}:emergencyDisable` → bảng `disabled_rules` (trạng thái mong muốn
của group) + lệnh `DisableRules` cho từng node → agent lưu `disabled-rules.json` và ghi khối
disabled-rules của control file → worker NGINX đọc trong tick 1 giây → `strata_engine_disable_rules`.

- **Engine (ABI 1.3, chỉ thêm)**: danh sách gắn với engine (`RwLock<Arc<[u32]>>`, tối đa 4.096),
  mỗi transaction chụp danh sách lúc bắt đầu, nên request đang chạy không đổi giữa chừng. Rule bị tắt
  không khớp ở cả shadow. Bundle mới là engine mới: connector áp lại.
- **Control file**: khối ở offset 2128, tối đa 480 Rule ID, ghi tại chỗ dưới seqlock
  (`docs/design/control-file.md`). Module cũ không đọc khối này: trên node chưa nâng module, lệnh
  vẫn báo thành công nhưng rule **không** tắt. Nâng module trước khi dựa vào kill switch.
- **Fleet**: `DisableRules{rule_ids, replace}`, `EnableRules{rule_ids, all}` trong `fleet.proto`;
  migration 0009 thêm cột `rule_ids` cho `node_commands`.
- **Worker** (`ngx_http_strata_bundle.c`, +48 dòng, C 2.880/3.000): chép danh sách trong cửa sổ
  seqlock, áp khi danh sách đổi hoặc engine đổi. Lỗi tìm được khi viết test: sau đổi bundle và khi
  worker mới khởi động, các request tới tick kế tiếp chạy engine mới chưa có danh sách; đã sửa (áp
  ngay trong `load_done` và `init_process`), `t/100` có subtest reload.
- **API**: `:emergencyDisable`, `:enable`, `GET /v1/rules:disabled`; quyền mới `rules:disable`
  (operator, approver, admin). Node kết nối lại nhận cả danh sách của group (`DisableRules` thay thế,
  id `sync-<node>`, không lưu thành lệnh), nên node offline lúc tắt vẫn bắt kịp. Migration 0010.
- Giám sát: metric `strata_agent_disabled_rules`, cảnh báo `StrataRulesDisabled` (info); runbook
  mục "Tắt rule khẩn cấp".
- Chưa có nút trên UI (không nằm trong nhiệm vụ nào của tuần 12).

### W12-G1-01 · Hoàn thiện fallback tại node

- Trước đây fallback ép shadow 1 giờ (`--fallback-hold`) rồi tự gỡ. Nay cờ không có hạn: lưu ở
  `fallback` trong `force-shadow.json` (giữ qua restart agent), chỉ `ForceShadow{clear}` cho mọi
  policy (`POST /v1/nodes:clearForceShadow`, `policy_id` rỗng) gỡ được. Lệnh `forceShadow` hết hạn
  hay gỡ một policy không gỡ cờ. Bỏ flag `--fallback-hold` (không file deploy nào dùng).
- Metric `strata_agent_fallback_active`; cảnh báo `StrataNodeFallbackHeld` (warning) khi giữ quá
  1 giờ; diagnostics có `force_shadow.fallback` (lý do, thời điểm).
- Test biên: hệ số (mặc định 3 và 2), sàn (0,5% và 2%), số request tối thiểu (100 và 500), lỗi
  engine, budget, khởi động (1, 12, 30 khoảng).

### W12-F-01 · Diff giữa các version

- Nút "So sánh phiên bản" trên trang Policy khi có ≥ 2 phiên bản (mọi vai trò đọc được policy).
  Mặc định so phiên bản mới nhất với phiên bản trước; chọn tự do hai bên.
- Theo khối của `policies.schema.json`: Chung (mode, oversize) và Lớp response
  (allowed_codes_check, db_errors, data_guard). Mọi trường đều hiện, trường đổi được tô; data_guard
  hiện phần thêm/bớt. Giá trị mặc định API bỏ trống và thứ tự danh sách không tính là khác.
- Diff tính trên UI từ `listPolicyVersions` (đã có spec của mọi phiên bản). **Chưa thêm** API
  `:diff?from=&to=` trong bảng API của `nginx-module.md`: sẽ cần khi CLI hoặc GitOps dùng.

### W12-G2-01 · Giám sát canary toàn cụm

Quyết định PO: bộ đếm theo nhóm + cờ canary; tỉ lệ chặn so với mức nền học được; ngắt thì ép shadow
policy canary, giữ tới khi gỡ.

- **Engine (ABI 1.4, chỉ thêm)**: cờ verdict `STRATA_VF_CANARY`, `STRATA_VF_CANARY_SHADOW`; trường
  17 `CanaryGroup` trong sự kiện protobuf.
- **Module**: bộ đếm theo nhóm (canary / còn lại) ở log phase trong metrics file, counter 24..49
  (slot 448 byte, 50 counter, thêm vào cuối): request, bị chặn, chỉ ghi log, 5xx upstream, 9 bucket
  độ trễ (5..1.000 ms, +Inf).
- **Agent**: `strata_canary_*` trên Prometheus, bộ đếm gửi trong Heartbeat.
- **Control plane** (`fleet/canary.go`): cửa sổ 1 phút, tính mỗi 5 s, cần ≥ 200 request mỗi nhóm.
  Ngắt khi: 5xx canary hơn nhóm còn lại 1 điểm % và gấp 2; p99 gấp 1,5 và hơn 50 ms; tỉ lệ chặn
  > 3 lần mức nền (EWMA 1 giờ, khởi động 12 lần tính) và > 1%. Khi ngắt: `ForceShadow` 24 giờ cho
  policy canary, gia hạn mỗi 12 giờ tới khi gỡ; dừng rollout; bảng `canary_trips` (migration 0011);
  cảnh báo `StrataCanaryFallback`; runbook "Canary về shadow".
- API policy có `canary_percent`; UI: trường trong policy editor và trong diff.

### W12-N-01 · Lấy mẫu traffic tại connector

Quyết định PO: khóa HMAC riêng mỗi connector group.

- **Ẩn danh trong libstrata** (`engine/src/anon.rs`): bản chép từng byte của bộ ghi Go (escape URL,
  `mime.ParseMediaType`, multipart, JSON độ sâu 64). Kiểm bằng vector của spec và corpus
  differential 400 ca do Go sinh (`engine/tests/fixtures/anon-corpus-v1.json`).
- **ABI 1.5 (chỉ thêm)**: `strata_engine_set_replay`, `strata_tx_sample`. Datagram `\xffSR1` +
  `ReplaySample` protobuf, tối đa 8 KB (body giữ tối đa 4 KB, giảm một nửa tới khi vừa).
- **Module**: khối replay của control file ở offset 4056 (tỉ lệ, id khóa); khóa ở file riêng
  `replay.key` trong thư mục bundle (mode 0640), worker đọc trong tick rồi xóa khỏi bộ nhớ đệm.
  Mẫu gửi qua event socket trước `tx_free`. Test `t/110-canary-metrics.t`, `t/120-replay-sample.t`.
- **Agent**: lệnh `SetReplaySampling` (Command field 6), không lưu cài đặt ra đĩa: sau restart giữ
  nguyên file cho tới khi control plane gửi lại khi kết nối. Mẫu đi trong `EventBatch.samples`.
- **Control plane**: bảng `replay_sampling` (migration 0012), `POST /v1/groups/{group_id}:setReplaySampling`
  (quyền `replay:configure`, chỉ admin). Khóa không bao giờ ghi vào `node_commands` hay audit log.
  Collector ghi Parquet theo (policy, node, khóa), có cột `canary`.
- **Mặc định tắt**: tỉ lệ > 0 bị từ chối trừ khi server chạy với `-replay-sampling-approved`, chỉ
  bật sau khi pháp chế duyệt định dạng (`docs/spec/replay-sample.md`). Runbook "Lấy mẫu replay".
- Dòng C: **2.999 / 3.000** (mục 5).

### W12-R-01 · Runner replay đầy đủ, differential Coraza

- `strata-replay compare`: so bản nháp với bundle đang chạy theo route; liệt kê request mới bị chặn
  (ứng viên FP) và mới được cho qua (ứng viên FN), tách theo hành động ghi lúc lấy mẫu. Báo cáo cho
  bản nháp "gói signature enforce": `docs/reports/w12/r01-replay-signatures.md` (FN 603 → 355,
  248 request mới bị chặn đều là tấn công, FP benign giữ 12/2.000).
- `tools/coraza-diff` (module Go riêng, `coraza/v3` v3.8.1 chỉ ở đó; `make coraza-diff`): gói core
  qua `strata-eval` và Coraza + CRS 4.25.2 PL1, cùng cấu hình bộ nhập của Strata (`allowed_methods`
  có PUT/PATCH/DELETE) và body processor JSON/XML của `coraza.conf-recommended`. Hai phép so:
  - verdict trên 4.281 request của corpus: tấn công khớp 100%; 155 request benign Coraza chặn mà
    Strata không, **đều do tinh chỉnh có chủ đích** của W09-S-01 (930120 "program files/", 942100
    điều kiện thêm sau libinjection);
  - theo rule trên 4.779 test go-ftw: 293 khác biệt, phân loại: Coraza sai so với test 122 (121 là
    test thuộc tính XML `XML://@*` mà Coraza 3.8.1 không xét), Strata chặn trước khi tới rule 85
    (Coraza cũng chặn; CRS chặn ở cuối phase 2), đã biết trong `docs/crs-ftw-report.md` 46, rule
    chưa nhập 40 (943110, 921250, 920190).
- Kết quả: **không có ticket** cho W12-S-01. Bản đầu của công cụ báo 494 khác biệt; 339 trong số đó
  do cấu hình so sánh (phương thức cho phép, JSON bị đọc như urlencoded, rule 9000xx/920539 không
  phải phát hiện), đã sửa trong công cụ chứ không phải trong bộ nhập.
- CRS lấy bằng `git clone` tag v4.25.2 (commit b9818c37): tải tarball trong `crs.lock` bị proxy trả
  403 nên `fetch-crs.sh` không kiểm được sha256; `make coraza-diff CORAZA_CRS=<thư mục>` dùng cây có
  sẵn. Gói `coraza-coreruleset` của Go chỉ có tới 4.25.0 nên không dùng.

## 3. Kiểm chứng

| Lệnh | Kết quả |
| --- | --- |
| `cargo fmt --check`, `cargo clippy --workspace --all-targets --all-features -D warnings` | sạch |
| `cargo test --workspace --all-features` | 301 test, 0 lỗi |
| Test::Nginx 1.30.5 và 1.31.6 (`prove -r t/`, user thường) | 587/587 mỗi bản |
| `make check-header`, `check-fixtures`, `check-c-lines` | xanh; **2.999 / 3.000** dòng C |
| `make abi-test` | 2 CHECK sau panic lỗi như trên `main` (mục 4); các CHECK mới (ABI 1.3–1.5) xanh |
| `go vet`, `golangci-lint`, `go test -race` agent, control-plane (test PostgreSQL chạy trên PostgreSQL 16 thật), tools/strata-rules, tools/coraza-diff, tools/strata-import-crs | xanh (`TestCommittedConversionIsCurrent` chạy với `STRATA_CRS_DIR` trỏ tới bản git clone: ra đúng `corpus/crs-ftw` đã commit) |
| `make check-proto` | xanh |
| `make test-alerts` | SUCCESS, 57 metric xuất ra |
| UI `tsc`, `vitest` (63 test), Playwright (17 test) | xanh |
| `make coraza-diff CORAZA_CRS=…` | 4.281 request, 155 khác biệt; 4.779 test go-ftw, 293 khác biệt; 0 ticket |

**CI trên GitHub không chạy**: từ ít nhất 01:37 UTC 14/10, mọi run (cả `main`) kết thúc lỗi sau
khoảng 3 giây, không có log (404). Đây là runner không khởi động job, không phải lỗi code; người có
quyền repo cần kiểm Actions (giới hạn chi tiêu, billing, runner).

## 4. Vấn đề có sẵn

- `make abi-test`: 2 CHECK sau panic lỗi cả trên `main` (`abi_test.c:330, 332` sau khi thêm dòng).
- `TestAgentMetrics` chập chờn (tuần 11 ghi 3/12): **đã sửa** (chờ ack trước khi đọc gauge); 10/10
  lần xanh.
- `TestRenewSupersedesTheOldCertificate` (từ W07) chập chờn khi máy tải nặng: server đóng stream của
  chứng chỉ cũ trước khi test gửi Hello, `Send` trả `io.EOF`. **Đã sửa** helper `connect` (lỗi thật
  đọc ở `Recv`); 80/80 lần xanh dưới tải.
- Cleanup của `TestKillSwitchCommandsInPostgres` không chạy (đóng pool trước khi migrate về 0), để
  lại dữ liệu cho lần sau: đã sửa trong cả hai test PostgreSQL.

## 5. Cần người làm

1. Kiểm GitHub Actions (mục 3).
2. **Pháp chế duyệt** định dạng mẫu replay (`docs/spec/replay-sample.md`) trước khi chạy server với
   `-replay-sampling-approved`; tới lúc đó lấy mẫu tắt ở mọi group.
3. **PO quyết** ngân sách dòng C: còn **1 dòng** (2.999 / 3.000). Tuần 13+ cần nâng giới hạn hoặc
   chuyển logic của connector (đọc control file, metrics) sang libstrata.
4. Cập nhật `CLAUDE.md`, `AGENTS.md` sang tuần 12 (phiên agent không được sửa).
5. Trên lab: tắt rule khẩn cấp và canary về shadow đầu-cuối với agent thật; cảnh báo mới
   (`StrataRulesDisabled`, `StrataNodeFallbackHeld`, `StrataCanaryFallback`) trong vmalert.
6. Trên máy tải được GitHub: `fetch-crs.sh` (tarball kiểm sha256 theo `crs.lock`) rồi chạy lại
   `make coraza-diff`. Bản git clone đã cho đúng `corpus/crs-ftw` đã commit, nên khả năng khác là
   thấp, nhưng sha256 của bản phát hành chưa được kiểm trong phiên này.

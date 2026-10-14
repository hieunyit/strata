# Báo cáo tuần 12 (mở sớm) · Tắt rule khẩn cấp, fallback tại node, diff policy

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

Chưa làm: W12-G2-01, W12-R-01, W12-N-01 (chờ PO, mục 5).

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
  migration 0008 thêm cột `rule_ids` cho `node_commands`.
- **Worker** (`ngx_http_strata_bundle.c`, +48 dòng, C 2.880/3.000): chép danh sách trong cửa sổ
  seqlock, áp khi danh sách đổi hoặc engine đổi. Lỗi tìm được khi viết test: sau đổi bundle và khi
  worker mới khởi động, các request tới tick kế tiếp chạy engine mới chưa có danh sách; đã sửa (áp
  ngay trong `load_done` và `init_process`), `t/100` có subtest reload.
- **API**: `:emergencyDisable`, `:enable`, `GET /v1/rules:disabled`; quyền mới `rules:disable`
  (operator, approver, admin). Node kết nối lại nhận cả danh sách của group (`DisableRules` thay thế,
  id `sync-<node>`, không lưu thành lệnh), nên node offline lúc tắt vẫn bắt kịp. Migration 0009.
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

## 3. Kiểm chứng

| Lệnh | Kết quả |
| --- | --- |
| `cargo fmt --check`, `cargo clippy --workspace --all-targets --all-features -D warnings` | sạch |
| `cargo test --workspace --all-features` | 289 test, 0 lỗi |
| Test::Nginx 1.30.5 và 1.31.6 (`prove -r t/`, user thường) | 576/576 mỗi bản |
| `make check-header`, `check-fixtures`, `check-c-lines` | xanh; 2.880 / 3.000 dòng C |
| `make abi-test` | 2 CHECK sau panic lỗi như trên `main` (mục 4); các CHECK mới của `strata_engine_disable_rules` xanh |
| `go vet`, `golangci-lint`, `go test` agent, control-plane (có PostgreSQL 16 thật), tools/strata-rules | xanh |
| `make check-proto` | xanh |
| `make test-alerts` | SUCCESS, 48 metric xuất ra |
| UI `tsc`, `vitest` (60 test), Playwright (17 test) | xanh |

**CI trên GitHub không chạy**: từ ít nhất 01:37 UTC 14/10, mọi run (cả `main`) kết thúc lỗi sau
khoảng 3 giây, không có log (404). Đây là runner không khởi động job, không phải lỗi code; người có
quyền repo cần kiểm Actions (giới hạn chi tiêu, billing, runner).

## 4. Vấn đề có sẵn

- `make abi-test`: 2 CHECK sau panic lỗi cả trên `main` (`abi_test.c:330, 332` sau khi thêm dòng).
- `TestAgentMetrics` chập chờn (tuần 11 ghi 3/12): **đã sửa** (chờ ack trước khi đọc gauge); 10/10
  lần xanh.
- Cleanup của `TestKillSwitchCommandsInPostgres` không chạy (đóng pool trước khi migrate về 0), để
  lại dữ liệu cho lần sau: đã sửa trong cả hai test PostgreSQL.

## 5. Cần người làm

1. Kiểm GitHub Actions (mục 3).
2. **PO quyết** cách control plane biết request nào thuộc nhóm canary, trước W12-G2-01 (so canary
   với shadow về 5xx upstream, p99, tỉ lệ chặn). 5xx và p99 cần mọi request, không chỉ request có
   sự kiện, nên cần bộ đếm theo nhóm trong metrics file (thêm vào layout) hoặc một nguồn khác.
   W12-R-01 và W12-N-01 cũng dùng cách đánh dấu này.
3. Cập nhật `CLAUDE.md`, `AGENTS.md` sang tuần 12 (phiên agent không được sửa).
4. Trên lab: tắt rule khẩn cấp đầu-cuối với agent thật; cảnh báo mới trong vmalert.

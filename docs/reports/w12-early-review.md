# Review tuần 12 mở sớm (PR #61, phần sau `77a1c20`) trên server lab

Nhánh tích hợp: `w12-integrate`, gồm 27 commit tuần 12 của PR #61 (`0ef333f..b440f77`,
`claude/peaceful-pasteur-efxre2`) cherry-pick lên `main` 30e976c (đã có RV-G2-01 #68, #57 #70,
#65 #72, hs-block #54), cộng các bản sửa dưới đây. Công cụ: Claude Code (phiên strata-59, theo
yêu cầu PO ngày 14/10, worktree `~/strata-w12`, nhân 6–10).

Phiên cloud viết phần này **trước khi** RV-G2-01, #57 và #65 vào main, và không rebase. Phần
lớn công việc review là ghép hai luồng.

## 1. Kết luận

**APPROVE, merge kèm các bản sửa trong nhánh tích hợp.** Kill switch (W12-R-02, G1-02, N-02,
G2-02), fallback giữ tới khi control plane gỡ (W12-G1-01), diff policy (W12-F-01), canary toàn
cụm (W12-G2-01), lấy mẫu replay (W12-N-01, mặc định tắt) và W12-R-01 có code và test.

Không chặn merge, nhưng **phải xử lý trước khi bật canary**: #74 (tầng 2 của fallback bị kích
hoạt được từ bên ngoài). **Phải xử lý trước khi lấy mẫu traffic thật**: #75 (mẫu replay bỏ qua
privacy của policy), cùng lúc với việc pháp chế duyệt (W11-G2-01).

## 2. Phát hiện

| # | Mức | Phát hiện | Xử lý |
| --- | --- | --- | --- |
| 1 | Cao | **Trùng số migration**: tuần 12 đánh 0008–0011, trong khi RV-G2-01 đã lấy 0008 (`secrets`). Loader (`control-plane/db/migrate.go`) gộp file theo số, nên một trong hai migration 0008 bị bỏ qua mà không báo lỗi (`test-go` vẫn xanh) | Dời sang 0009–0012; loader báo lỗi khi một số có 2 tên (`TestLoadRejectsTwoMigrationsWithOneNumber`) |
| 2 | Cao | **Trùng số field proto**: `event.proto` `canary = 17` trùng `user_agent` (RV-G2-01 17–21); `PolicySpec.canary_percent = 4` trùng `max_snippet_size` (4), `privacy` (5) | `canary = 22` (test byte của tag sửa theo `0xb0 0x01`), `canary_percent = 6`; sinh lại code (`make check-proto` sạch) |
| 3 | Cao (trước canary) | Tầng 2 của fallback (`control-plane/fleet/canary.go`) so tỉ lệ chặn của nhóm canary với mức học trong 1 giờ: không giới hạn theo nguồn, không so với nhóm shadow trong cùng cửa sổ. Gửi dồn payload từ vài địa chỉ rơi vào nhóm canary sẽ ép mọi policy canary của group về shadow 24 giờ, tự gia hạn | #74, kèm đề xuất (giới hạn theo nguồn như #65, kiểm định Poisson). Không policy nào có `canary_percent` |
| 4 | TB (trước replay thật) | Anonymizer replay (Rust và Go) không dùng `privacy.sensitive_fields` / `mask_patterns` của policy (P-01 §1): field khai nhạy cảm vẫn vào Parquet ở dạng rõ | #75 (đổi đặc tả, PO quyết). Lấy mẫu mặc định tắt, cần cờ `-replay-sampling-approved` |
| 5 | TB | Ghép với #65: commit fallback "giữ tới khi gỡ" viết trên bản trước #65. `TestThresholdEdges` và `TestWatcherHoldsUntilCleared` giả định ngưỡng tỉ lệ cố định và đếm chặn từ metrics, nên hỏng sau #65 (kiểm định Poisson, chặn đếm từ sự kiện theo nguồn) | Giữ logic #65; test dùng 10.000 request mỗi khoảng và đưa sự kiện từ nhiều địa chỉ. Cảnh báo `StrataNodeFallback` mô tả cả hai thay đổi |
| 6 | Thấp | `TestNodeFallsBackWithinSixSeconds` có race: đọc `Triggers()` ngay khi control file đã ghi, trước khi watcher tăng bộ đếm | Test chờ tối đa 1 s; chạy 3/3 lần PASS |
| 7 | Thấp | `engine/Cargo.toml` khai `sha2` hai lần (RV-G2-01 và W12-N-01): `cargo metadata` lỗi; một test của RV-G2-01 thiếu field `canary`; `runbook_url` của `StrataNodeErrorsJump` lạc khi ghép `alerts.yml` | Sửa trong nhánh |
| 8 | Thấp | Engine đọc 2 `RwLock` (`disabled`, `replay`) ở đầu mỗi transaction. Không tranh chấp (chỉ timer của chính worker ghi), mỗi lần đọc là một thao tác atomic. Quy tắc "không khóa trên request" của CLAUDE.md viết cho C | Không sửa; nếu muốn bỏ hẳn thì dùng `arc-swap` (thêm crate, PO quyết) |
| 9 | Thông tin | C connector 2.999 / 3.000 dòng thực: tuần sau không còn chỗ | Logic mới phải nằm trong libstrata; nếu cần nâng trần thì PO quyết |
| 10 | Thông tin | Metrics file: slot 256 → 448 byte, 24 → 50 bộ đếm. Reader lấy kích thước slot và số bộ đếm từ header, bộ đếm canary tùy chọn: agent cũ đọc được module mới và ngược lại | Không cần sửa |

Đã kiểm thêm, không có vấn đề: offset control file (2128, 2136, 4056, 4064) khớp giữa C, agent
và `control-file.md`; file `replay.key` chỉ đọc trong timer (không trên request), khóa xóa khỏi
stack sau khi dùng; API kill switch và replay có quyền RBAC riêng (`rules:disable`,
`replay:configure`) và audit.

## 3. Đã chạy (14/10, nhân 6–10)

| Kiểm | Kết quả |
| --- | --- |
| `make check-c-lines`, `check-proto` | PASS (2.999 / 3.000 dòng thực) |
| `make test` 1.30.5 (fmt, clippy, cargo test, header, fixtures, ABI, Test::Nginx) | PASS, 20 file, 587 test (có `t/100-kill-switch`, `t/110-canary-metrics`, `t/120-replay-sample`) |
| `make test` 1.31.6 | Lượt đầy đủ: 2 ca hỏng (`t/002` TEST 4, `t/040` TEST 3: request đầu bị `error` / không có rule). Chạy riêng 2 file 3 lần: 2 PASS, 1 hỏng ở ca khác (`t/002` TEST 15). Load máy khoảng 12 (soak, staging, lab): cùng họ chập chờn đã ghi ở review tuần 10/11 (#49), không sửa |
| `make nginx-asan` + `test-nginx-asan` 1.30.5 | PASS, không có báo cáo sanitizer |
| `make test-go` (race, golangci-lint; agent, control plane, e2e build, rules) | PASS |
| `make clang-tidy` | sạch |
| `make test-alerts` | PASS (sau bản sửa: `runbook_url` của `StrataNodeErrorsJump` bị lạc khi ghép) |
| `make test-rules`, `test-signatures`, `test-conformance` 1.30.5 | PASS |
| `prefilter_differential` (`--ignored`, release) | PASS |
| `build/ui.sh` (lint, vitest 65, build, Playwright 17) + `generate:api` | PASS; type sinh lại trùng với file đã ghép tay |

Chưa chạy lab end to end cho nhánh này: lab `strata-lab` của phiên strata-w10-bc dựng từ
`~/strata-w10`; dựng lại cần báo trước phiên đó.

## 4. Sau khi merge

| Việc | Ai |
| --- | --- |
| #74 trước khi bật canary (B1, sau Gate A) | PO quyết đề xuất, rồi phiên control plane |
| #75 trước khi gửi định dạng mẫu cho pháp chế | PO quyết |
| PR #61 | Đóng (đã tích hợp hết qua #66 và PR này), xóa nhánh `claude/peaceful-pasteur-efxre2` |

# H1 · Fallback khi bảng nguồn đầy

Nhiệm vụ: H1 trong action plan được PO giao thực hiện ngày 16/10/2026; sửa tiếp W11-G1-01/W12-G2-01 (#65/#74).
Nhánh: `codex/h1-fallback-source-saturation`, từ `origin/main` tại `991c4bb`.

Đã làm:
- Bỏ bộ đếm overflow không giới hạn; giữ tối đa MaxSources địa chỉ và đánh dấu cửa sổ bão hòa khi có nguồn mới vượt giới hạn.
- Agent không ép shadow theo block-rate hoặc học baseline từ cửa sổ bão hòa; `--fallback-on-errors` không biến tràn bảng thành lý do ép shadow. Tín hiệu engine/budget độc lập vẫn theo cấu hình.
- Control plane bỏ quyết định block-rate và học baseline cho tới khi mọi bucket bão hòa hết cửa sổ. 5xx/latency vẫn được đánh giá.
- Xuất metric agent `fallback_alerts_total{reason="source_limit"}` và control plane `canary_source_saturations_total`; thêm alert `StrataFallbackSourcesSaturated`, test và runbook. Tên metric đầy đủ có prefix `strata_agent_` / `strata_cp_`.

Xong khi:
- [x] Test hồi quy fail trước sửa: `go test -race ./internal/fallback -run TestSourceOverflow -v` ép shadow node; `go test -race ./fleet -run TestCanarySourceOverflow -v` gửi ForceShadow cả 2 node và dừng rollout.
- [x] Sau sửa: 5 test mới kiểm overflow, IPv6 /64, cập nhật đồng thời, reset cửa sổ, không học baseline thiếu, khôi phục sau cửa sổ và tín hiệu lỗi độc lập đều PASS.
- [x] `go vet ./...`, `go test -race ./...`, `golangci-lint run ./...` trong cả `agent/` và `control-plane/` PASS: 29 package test thành công, lint `0 issues.` ở mỗi module.
- [x] `deploy/dev/run.sh make test-alerts` PASS: vmalert `SUCCESS`; 4 dashboard, 59 metric kiểm được, `OK`. Alert overflow không bị phân loại thành engine-error alert và tự hết sau khoảng quan sát.
- [x] `git diff --check` PASS. Sau chỉnh cuối, chạy lại fallback, fleet, metrics, server compile, vet/lint của phần bị ảnh hưởng: PASS.

Bằng chứng tiêu biểu (dev image có sẵn, giới hạn CPU 6–10):
```
ok github.com/strata/strata/agent/internal/agent 11.296s
ok github.com/strata/strata/agent/internal/fallback 16.908s
ok github.com/strata/strata/control-plane/fleet 32.022s
ok github.com/strata/strata/control-plane/metrics 1.305s
0 issues.
SUCCESS
check-dashboards: 4 dashboards, 59 exported metrics, OK
```

Tự review: (1) điều kiện có test/output; (2) không thêm I/O chưa xử lý hay endpoint ghi; (3) map vẫn có giới hạn, chỉ thêm cờ bão hòa; (4) không log IP/token, không giảm enforcement từ số đếm thiếu; (5) phạm vi agent/Fleet, metric/alert, test/runbook/báo cáo liên quan; (6) vet, race và lint sạch. Test overflow cũ đổi kỳ vọng vì hành vi tính mỗi request ngoài map chính là lỗi; không xóa hay tắt test.

Rủi ro / giới hạn: khi liên tục vượt MaxSources, tự fallback theo block-rate và học baseline tạm ngừng; operator cần theo alert để xử lý FP thật. Enforcement hiện có và các hold đã mở không bị gỡ. Không chứng minh được chống mọi botnet khi bộ đếm còn đầy đủ. Chỉ kiểm thử cục bộ/simulation, không deploy staging/production; test DB ngoài môi trường mặc định có thể skip. Không đổi ABI/proto/schema/bundle hay thêm dependency. Các bảng nhiệm vụ cũ đã Done và con trỏ tuần không thuộc bản sửa H1 này. PR cần review và CI trước merge.

# Review tuần 9 (W09)

Nhánh: `w09-review`
Công cụ: Claude Code
Phạm vi: bảy nhiệm vụ W09 (PR #30–#38). Review chạy lại mọi dòng "Xong khi" của
`docs/plan/plan.md` trên server mới, đọc code và báo cáo của từng nhiệm vụ, rồi sửa
những chỗ chưa đạt hoặc chỉ đạt về hình thức. Máy: VM Xeon E5-2696 v4 2,2 GHz,
16 vCPU, Linux 6.8. Trước đây là laptop WSL2 i7.

## 1. Kết luận

Năm nhiệm vụ đạt "Xong khi": Q-01, R-01 (có ticket cho phần thiếu), G2-01, F-01,
S-02. Hai nhiệm vụ còn chờ thời gian:

- **Q-02**: soak 24 giờ chạy lại trên server mới, verdict khoảng 14/10 10:35 UTC.
- **S-01**: mốc staging 7 ngày tính lại từ 13/10 11:18 UTC.

Chuyển sang server mới làm lộ ra hai lỗi thật mà laptop nhanh che mất. **Cả hai đã sửa
và merge trước khi viết báo cáo này**:

- **R-01 tạo ra lỗi cold-start**: regex compile ở lần dùng đầu bị tính vào CPU budget.
  Sau mỗi lần nạp gói signature, request đầu của mỗi worker đi fail mode. Trên staging,
  probe Log4Shell đầu tiên được cho qua. Sửa ở PR #42.
- **Control plane hủy deploy gói 9.054 rule**: compile mất 16 giây, REST cắt ở 10 giây.
  Sửa ở PR #40.

Ngoài ra review tìm thấy:

- ba chỗ chỉ đạt về hình thức:
  - G2-01 không đo qua API;
  - S-01 không có gate tự động cho chỉ tiêu Gate A, và thiếu tag;
  - S-02 chưa chạy hằng đêm lần nào;
- một lỗi CI: `rust-check` đỏ trên `main`;
- một test chỉ đúng trên CPU nhanh;
- hai phát hiện về event socket khi đo trên Linux thật.

Tất cả đã sửa hoặc đã có ticket.

## 2. Phát hiện và cách sửa

| # | Nhiệm vụ | Phát hiện | Sửa |
| --- | --- | --- | --- |
| 1 | R-01 | Regex dự phòng compile ở lần dùng đầu (`OnceLock`) và thời gian đó tính vào CPU budget. Request đầu sau khi nạp gói đầy đủ mất 35–86 ms và đi fail mode. Trên staging rc.3, probe Log4Shell đầu tiên nhận 200 (`engine error 4`, fail-open) | PR #42: `TxBudget::credit` bỏ thời gian compile khỏi lượt gọi (cả deadline lẫn phần cộng dồn); `FallbackRegex::compiled_timed`. Test `first_use_regex_compile_is_not_charged_to_the_request` đi đúng đường FFI, và đỏ khi bỏ `credit`. Compile hết lúc nạp tốn 1,3 s và +118 MB mỗi worker, nên loại. Staging rc.4: cả hai node chặn Log4Shell ngay lần đầu |
| 2 | S-01 / G2 | `POST /v1/policies/{id}:deploy` compile gói 9.054 rule mất 16 s trên Xeon. Context của REST và deadline đọc/ghi 10 s làm compiler bị kill, client nhận "Empty reply" | PR #40: route deploy có `DeployTimeout` 3 phút (context và deadline của kết nối, qua `http.ResponseController`), các route khác giữ 10 s. Test có ca âm; bỏ phần sửa thì test đỏ với `EOF` |
| 3 | Q-01 / CI | `make rust-check` đỏ trên `main`: `cargo fmt` cho `strata-bench.rs` | PR #42 |
| 4 | N (W08) | `t/003` TEST 1 đặt budget 1 ms, fail closed: dưới ASan trên nhân 2,2 GHz nhận 503 ở cả hai bản NGINX | PR #42: 5s/1s. Block này kiểm directive; `t/060` vẫn kiểm hành vi budget |
| 5 | G2-01 | Plan ghi "đo qua API của control plane". Báo cáo lại đo qua `ClickHouseStore`. `tests/perf/clickhouse.sh` còn cần Go trên host | `TestClickHouseAPIPerf`: server HTTP thật, đủ handler REST, auth, JSON, trên ClickHouse 20 triệu dòng. Script chạy test trong image dev; `PERF_CPUS` để ghim CPU. Kết quả ở mục 3 |
| 6 | S-01 | Chỉ tiêu Gate A (FP < 1%, recall ≥ 70%) chỉ được đọc bằng mắt. `--max-fp` đếm request khớp **bất kỳ** rule, theo số tuyệt đối; dùng `--max-fp 1` thì gói v0 trượt | `strata-rules report --max-fp-block-pct`, `--min-recall-block` (SQLi/XSS/CMDi/LFI ở ngưỡng chặn; loại tấn công vắng trong corpus cũng tính là trượt). `make test-signatures` chạy với 1% / 70%. Unit test có ca âm. Thử nâng lên 80% thì fail đúng ở SQLi và XSS |
| 7 | S-01 | Plan ghi tag `signatures-v0.0.1`, nhưng tag chưa có | Tag tại 263fba3, commit merge của S-01. Rule không đổi từ đó tới `main` |
| 8 | S-02 | "Chạy hằng đêm trong CI": GitHub Actions hết phút nên `nightly.yml` chưa chạy lần nào | `deploy/nightly/nightly.sh` + `install-cron.sh`: cron 19:00 UTC, `make mutate` trên `origin/main` trong worktree riêng. Đã cài cron. Lần chạy thử: 11,0% lách, khớp W09-S-01 |
| 9 | Q-01 / R-01 | Đo lại trên Linux thật, mỗi worker một nhân riêng. Throughput phase 0–1 vẫn −40% → **#27 không phải do WSL2**. Trên nhân 2,2 GHz, body lớn đi fail-open cả với bundle phase 0–1 (82 lần với 64 KB, 432 lần với 1 MB), và gói đầy đủ có GET p99 2,76 ms, vượt budget 2 ms | Số đo ở `w09-q-01.md` mục 7, `w09-r-01.md` mục 7, `docs/reports/w09/linux/`. Comment vào #27 và #28 |
| 10 | Q-01 | Event socket trên Linux: network namespace mới (container) có `max_dgram_qlen` = **10**. Đặt 8.192 rồi mà 50.000 sự kiện/giây vẫn bỏ 5,2%, vì đầu nhận của agent chỉ đọc được khoảng 47.000/s trên nhân 2,2 GHz | `docs/decisions/ring-buffer.md` mục "Đo lại": tăng tốc phía nhận của agent trước, ring buffer chỉ khi vẫn bỏ hơn 0,1%. Sysctl phải đặt cả trong container. Comment vào #29 (W10-N-01 làm sysctl) |
| 11 | S-01 | Gói build lại trên server mới: IR `rules.json` trùng từng byte, bundle `.sbn` thì khác sha256 (Hyperscan compile theo CPU) | Ghi trong `w09-s-01.md` mục 5: nội dung gói được xác định bằng IR + manifest đã ký |
| 12 | Q-02 | Chuyển máy: dữ liệu lab/staging chỉ có trong volume, `migrate.sh` chưa được test | PR #39: `test-migrate.sh` 19/19. Theo PO, lab và staging trên server mới được dựng lại từ đầu, không giữ dữ liệu cũ |

Không phải lỗi:

- `t/002` TEST 9 trên 1.31.6 đỏ một lần khi máy đang build song song: nhận 200 thay vì
  403 với body chunked bị tách. Chạy lại 6 lần đều pass. Nhiều khả năng request vượt
  budget 2 ms vì CPU bị chiếm. Ghi lại để theo dõi.
- Lần deploy staging rc.3 có smoke pass nhưng kiểm Log4Shell thất bại. Đó chính là
  lỗi số 1.

## 3. Chạy lại "Xong khi" (sau sửa)

| Nhiệm vụ | Điều kiện | Kết quả |
| --- | --- | --- |
| Q-01 | Báo cáo p50/p99 và throughput (nhỏ, 64 KB, 1 MB, HTTP/2) so với NGINX không module; event socket ~50.000/s; quyết định ring buffer | `make bench` 1.30.5 và 1.31.6 trên Linux, mỗi worker một nhân (`w09-q-01.md` mục 7); `make bench-events` với qlen 10 và 8.192; quyết định được cập nhật. Shellcheck các script bench: sạch |
| R-01 | p99 < 1 ms và throughput giảm ≤ 10%, hoặc ticket | GET phase 0–1: p50 +186/+196 µs; p99 +1,16 ms (1.30.5) / +0,90 ms (1.31.6), dao động quanh ngưỡng trên máy chung. Throughput −43%/−40% → #27. Form 64 KB → #28. Cả hai ticket đã có số mới. Lỗi cold-start đã sửa (PR #42) |
| Q-02 | 24 giờ + 1.000 lần đổi bundle không tăng bộ nhớ/fd; staging chỉ từ tag | Staging: `test-deploy.sh` từ chối nhánh, commit, tag sai dạng, tag không tồn tại, tag chưa push. Đã deploy rc.2, rc.3, rc.4 từ tag (`w09-s-01.md` mục 5). `soak-check.py --self-test` ok. **Soak chạy lại** từ 13/10 10:33 UTC (container `strata-soak-24h`, CPU 11–13, binary có bản sửa cold-start); tới 13/10 13:00 UTC đã đổi 100 lần, bundle hỏng bị từ chối. Verdict ghi vào `w09-q-02.md` mục 3 khi xong |
| G2-01 | TTL áp dụng; tra Block ID < 1 s; tìm kiếm 24 giờ < 2 s | Qua REST API, 20 triệu dòng: `GET /v1/events/{id}` p99 **59 ms**; `POST /v1/events:search` 24 giờ p99 lớn nhất **717 ms**. `TestClickHouseTTL` PASS |
| F-01 | Field vi phạm được tô; tác giả với rule Sigma | `build/ui.sh`: lint, vitest 26/26, build, Playwright 12/12. Snippet chính là đoạn đã khớp nên được tô cả khối; field trong path dùng `<mark>` (như báo cáo W09-F-01) |
| S-02 | Báo cáo tỉ lệ lách theo loại tấn công; chạy hằng đêm | Cron trên server lab (`deploy/nightly`), lần chạy thử: 25.740 biến thể, 11,0% lách (#34). `nightly.yml` giữ nguyên cho lúc CI có phút |
| S-01 | Gói v0; staging 7 ngày; review 2 người; chỉ tiêu Gate A | `make test-signatures` giờ gác FP < 1% và recall ≥ 70%: PASS (FP 0,60%; SQLi 76,3%, XSS 75,2%, CMDi 94,2%, LFI 92,7%). `verify --pub` gói build lại: OK. Tag `signatures-v0.0.1`. Staging rc.4 + gói 0.0.1 từ 13/10 11:18 UTC, VictoriaMetrics thấy `strata_bundle_version` = 7 trên cả hai agent. **Hết 7 ngày vào 20/10 11:18 UTC** |

## 4. Bộ kiểm tra đầy đủ

Chạy trong image dev, sau PR #42 (engine) và trên nhánh này:

| Bước | Kết quả |
| --- | --- |
| `check-c-lines` | 2.516 / 3.000 dòng thực |
| `rust-check` (fmt + clippy -D warnings), `cargo test --workspace` | PASS |
| `make test` 1.30.5 / 1.31.6 | PASS, 16 file, 551 test (một lần chập chờn ở mục 2) |
| `test-nginx-asan` 1.30.5 (3 lần) / 1.31.6 | PASS, không có báo cáo sanitizer |
| `clang-tidy` 1.30.5 / 1.31.6 | sạch |
| `test-conformance`, `test-rules`, `test-crs-ftw`, `test-signatures` | PASS |
| `prefilter_differential` (`--ignored`, release) | PASS, 0 khác |
| `make test-go` (sau các thay đổi Go của nhánh này) | PASS, golangci-lint 0 issue |
| UI (`build/ui.sh`) | PASS |
| shellcheck (`deploy/nightly`, `deploy/migrate`, `tests/perf/clickhouse.sh`, script bench và staging) | sạch ở mức warning |

## 5. Việc còn mở

- Verdict soak 24 giờ, khoảng 14/10 10:35 UTC → `w09-q-02.md` mục 3, dòng AGENTS.
- Staging 7 ngày của gói 0.0.1, tới 20/10 11:18 UTC → `w09-s-01.md`, dòng AGENTS.
- #27 throughput, #28 body lớn: ảnh hưởng hai tiêu chí hiệu năng của Gate A. Thêm rủi
  ro mới: gói đầy đủ có p99 vượt budget 2 ms trên CPU chậm.
- #29: sysctl trong container, tăng tốc phía nhận của agent, đo lại.
- #34 biến thể lách, #36 cost unit: không đổi.
- Staging chưa bàn giao cho phiên W10. Bàn giao bằng memory `w09-review.md` sau khi
  PR này merge.

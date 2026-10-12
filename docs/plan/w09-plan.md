# Kế hoạch chi tiết tuần 9 · Benchmark, soak, staging

Nguồn: `docs/plan/plan.md`, mục "Tuần 9". Lập ngày 13/10/2026, sau khi review W08
(`docs/reports/w08-review.md`, PR #25) đã merge.
Người làm: Claude Code, mọi luồng. PO đã giao quyền tự quyết kỹ thuật; chỉ hỏi khi
cần dữ liệu mà chỉ PO có.

Mỗi nhiệm vụ làm theo cùng một quy trình:

- một nhánh, đặt tên theo mã;
- chạy đủ dòng "Xong khi" bằng output thật;
- viết báo cáo `docs/reports/w09-*.md`;
- đổi dòng tương ứng trong AGENTS.md;
- PR, merge sau khi đã kiểm trên máy (GitHub Actions hết phút).

## 0. Ràng buộc của môi trường đo

- Máy: WSL2, 8 nhân, 7,6 GB RAM. Fuzz 72 giờ (`strata-fuzz-72h`) chiếm 1 nhân đến
  khoảng 15/10 22:45 (giờ VN).
- Mọi phép đo dùng cùng một cách:
  - nginx 2 worker ghim vào nhân 2–3 (`worker_cpu_affinity`);
  - client (`wrk`, `h2load`) ghim vào nhân 4–7;
  - backend là một `server` khác trong cùng nginx, `strata off`, ghim chung nhân với
    nginx.
- Kết quả là **so sánh tương đối** giữa có và không có module, trên cùng máy và cùng
  cấu hình. Số tuyệt đối không đại diện cho production; báo cáo phải ghi rõ điều này.
- Mỗi phép đo chạy 3 lần, lấy trung vị.
- Bundle đo là gói signature đầy đủ (`strata-rules release`, khoảng 9.000 rule), policy
  `example-api` ở enforce. Không dùng bundle test nhỏ, vì nó làm số đẹp giả.

## 1. Thứ tự

| # | Mã | Vì sao ở vị trí này |
| --- | --- | --- |
| 1 | W09-Q-01 Benchmark | Cho số liệu mà R-01 cần |
| 2 | W09-R-01 Điểm nóng hiệu năng | Sửa theo số liệu của Q-01, đo lại bằng chính script Q-01 |
| 3 | W09-Q-02 Soak + staging | Soak 24 giờ chạy trên code đã tối ưu, ở nền, trong lúc làm các việc sau. Staging cần có trước S-01 |
| 4 | W09-G2-01 ClickHouse | Độc lập; cần nhiều dữ liệu giả, nên làm khi soak đang chạy nhẹ |
| 5 | W09-F-01 Decision trace | Cần trường `author` từ API (G2) |
| 6 | W09-S-02 Bộ sinh biến thể | Cho số "lách được" mà S-01 dùng để quyết định rule nào vào gói v0 |
| 7 | W09-S-01 Gói signature v0 | Cần staging (Q-02), số đo chất lượng (S-02), và người review thứ hai |

## 2. Từng nhiệm vụ

### W09-Q-01 · Benchmark

**Xong khi.** Có báo cáo p50/p99 và throughput (request nhỏ, 64 KB, 1 MB, HTTP/2) so
với NGINX không bật module; đo chi phí event socket ở khoảng 50.000 sự kiện/giây; ghi
quyết định ring buffer vào `docs/decisions/ring-buffer.md`.

**Làm.**

1. Thêm `nghttp2-client` (`h2load`) vào `deploy/dev/Dockerfile`; `wrk` đã có sẵn.
2. Viết `connectors/nginx/scripts/bench.sh <nginx-version> <scenario> <mode>`:
   - scenario:
     - `small`: GET có query;
     - `64k`, `1m`: POST body urlencoded;
     - `h2`: GET qua HTTP/2, TLS.
   - mode:
     - `off`: không `load_module`;
     - `on`: module + bundle đầy đủ;
     - `on-events`: `on` + event socket, với một rule `log` khớp mọi request.
   - Mỗi lần chạy:
     - 10 giây warm-up, 30 giây đo;
     - `wrk --latency` cho p50/p99, rps;
     - `h2load` cho HTTP/2;
     - xuất một dòng JSON.
   - Script gộp `bench-report.sh` ghi bảng Markdown với hai cột so sánh: Δp99 (µs) và
     Δthroughput (%).
3. Đo event socket:
   - cho tải ở khoảng 50.000 req/s, mọi request đều sinh sự kiện;
   - đầu nhận là agent thật (`strata-agent`, có ingest giả) và một bộ đọc tối giản
     làm mốc;
   - đo:
     - CPU của worker khi bật và khi tắt sự kiện;
     - số sự kiện rơi (`C_DROPPED` trong metrics file);
     - p99 khi bật và khi tắt sự kiện.
4. `docs/decisions/ring-buffer.md`: chọn giữ datagram Unix socket hoặc chuyển sang
   ring buffer bộ nhớ chung, dựa trên số đo của bước 3:
   - chi phí `sendto` trên mỗi sự kiện;
   - tỉ lệ rơi khi agent chậm;
   - độ phức tạp của mỗi lựa chọn.
5. `make bench` (cả ma trận) và `make bench-events`.

**Kiểm:**

- `make bench NGINX_VERSION=1.30.5` và `1.31.6`;
- shellcheck cho script;
- báo cáo `docs/reports/w09-q-01.md` có bảng so với 5 mục tiêu của module (Demo
  tuần 9).

### W09-R-01 · Xử lý điểm nóng hiệu năng

**Xong khi.** Đạt p99 dưới 1 ms và throughput giảm tối đa 10%, hoặc có ticket cụ thể
cho phần còn thiếu.

**Làm.**

1. Tìm điểm nóng:
   - đo thời gian theo giai đoạn: `strata-eval --profile` hoặc bench `criterion` trong
     `engine/benches/` cho `request_line`, `headers`, `body` 64 KB và 1 MB, với
     bundle đầy đủ;
   - lấy flamegraph bằng `perf` (nếu WSL2 cho phép), không thì `pprof-rs`, trên
     `strata-eval`.
2. Sửa theo thứ tự lợi ích/rủi ro. Các nghi vấn cần đo trước khi sửa:
   - cấp phát lặp lại cho mỗi request (`Vec` của target, chuẩn hóa);
   - quét Hyperscan nhiều lần trên cùng một field;
   - chuẩn hóa body 1 MB làm nhiều lượt;
   - copy body chunk ở FFI.
3. Mỗi thay đổi kèm một bench trước/sau, và không đổi verdict:
   - conformance;
   - `test-rules`;
   - go-ftw giữ 95,9%;
   - FP benign không đổi.
4. Chạy lại `make bench`. Phần nào còn trượt mục tiêu thì mở `gh issue` với số đo,
   điểm nóng và hướng sửa.

**Kiểm:**

- `cargo test`, `clippy`, `test-nginx` và ASan cả hai bản, conformance, crs-ftw;
- bảng trước/sau trong `docs/reports/w09-r-01.md`.

### W09-Q-02 · Soak và dựng staging

**Xong khi.** Chạy 24 giờ + 1.000 lần đổi bundle, bộ nhớ và file descriptor không tăng
liên tục; staging dựng xong, chỉ deploy từ bản đã tag.

**Làm.**

1. Soak, `connectors/nginx/scripts/soak.sh`, chạy trong container riêng
   `strata-soak-24h`:
   - tải đều khoảng 300 req/s, trộn request sạch, request bị chặn, body 64 KB,
     HTTP/2 và client ngắt giữa chừng;
   - đổi bundle mỗi 86 giây, xen kẽ hai bundle thật và có một lần bundle hỏng mỗi
     100 lần, tổng cộng ≥ 1.000 lần trong 24 giờ;
   - mỗi phút ghi RSS, PSS và số fd của master, các worker và agent vào CSV;
   - `soak-check.py` phân tích CSV:
     - bỏ 1 giờ đầu (warm-up);
     - hồi quy tuyến tính trên 23 giờ còn lại;
     - đạt khi độ dốc của RSS < 1 MB/giờ trên mỗi worker, và số fd ở cuối bằng số fd
       ở đầu (±2).
   - Test âm cho bộ kiểm tra: một CSV có rò rỉ giả phải bị đánh trượt.
2. Staging, `deploy/staging/`:
   - compose riêng (project `strata-staging`, cổng khác lab), dùng lại image của lab;
   - `deploy/staging/deploy.sh <tag>`:
     - chỉ nhận tag dạng `v*` có trên `origin`;
     - checkout tag vào worktree tạm và build image từ đó;
     - gắn label `org.opencontainers.image.version=<tag>`;
     - ghi bản đã deploy vào `deploy/staging/.state/deployed`;
     - từ chối khi nhận commit chưa tag hoặc working tree bẩn.
   - Test: deploy một commit chưa tag phải bị từ chối; deploy tag `v0.9.0-rc.1`
     phải chạy được `smoke.sh` trên staging.
   - Staging chạy trên máy này, có thể chuyển sang host khác bằng `DOCKER_HOST`. Host
     staging thật là dữ liệu PO (xem mục 3).

**Kiểm:**

- `soak-check.py` trên CSV 24 giờ thật;
- deploy tag lên staging, smoke pass;
- báo cáo `docs/reports/w09-q-02.md`, có đồ thị RSS/fd dạng SVG.

### W09-G2-01 · ClickHouse cho vận hành

**Xong khi.** TTL lưu trữ áp dụng; tra Block ID dưới 1 giây; truy vấn tìm kiếm 24 giờ
dưới 2 giây.

**Làm.**

1. TTL:
   - đọc từ cấu hình control plane (`-events-ttl-days`, mặc định 90);
   - migration `ALTER TABLE ... MODIFY TTL` khi giá trị đổi;
   - test e2e với TTL rất ngắn (`INTERVAL 1 MINUTE` qua cờ test) và
     `OPTIMIZE ... FINAL`: bản ghi quá hạn biến mất.
2. Dữ liệu tải: `tools/strata-loadgen events` sinh 10 triệu sự kiện cho 24 giờ (khoảng
   115/s) vào ClickHouse của lab, phân phối Rule ID, IP và path giống thật.
3. Đo qua **API của control plane**, không phải SQL trần:
   - tra Block ID: `GET /v1/events/{block_id}`, p99 trên 200 Block ID ngẫu nhiên;
   - tìm kiếm 24 giờ: lọc theo policy, action, Rule ID, IP, tiền tố path, phân trang;
     p99 trên 50 truy vấn.
4. Chậm thì sửa schema có migration:
   - `ORDER BY (block_id, timestamp)` không phục vụ được lọc theo thời gian. Cách sửa
     có thể: projection theo `(timestamp, policy_id)`, hoặc bảng phụ;
   - quyết định ghi trong báo cáo.

**Kiểm:**

- `go test -race ./control-plane/...`;
- `tests/perf/clickhouse.sh` in p50/p99;
- báo cáo `docs/reports/w09-g2-01.md`.

### W09-F-01 · Decision trace dễ đọc

**Xong khi.** Field vi phạm được tô sáng; hiển thị tác giả với rule từ Sigma.

**Làm.**

1. Tô sáng:
   - trong `DecisionTraceModal`, field vi phạm (ví dụ `args:id`, `header:User-Agent`)
     được tô trong phần request;
   - đoạn khớp trong snippet được tô (`<mark>`). Snippet vẫn qua `maskSnippet` cho
     viewer: chỉ tô phần còn hiển thị, không lộ phần đã che.
   - Nếu sự kiện chưa có vị trí khớp thì tô cả field; ghi lại điều này.
2. Tác giả:
   - API rule (`GET /v1/rules/{id}`, hoặc trường `rule_meta` trong chi tiết sự kiện)
     trả `metadata.author`, `source`, `license`;
   - UI hiển thị "Tác giả: …" khi `source = sigma`.
   - Đây là thay đổi OpenAPI theo hướng chỉ thêm (additive). PO đã giao quyền tự
     quyết; lý do ghi trong báo cáo.

**Kiểm:**

- lint, unit, build, Playwright;
- `go test` cho API;
- báo cáo `docs/reports/w09-f-01.md` kèm ảnh chụp.

### W09-S-02 · Bộ sinh biến thể payload

**Xong khi.** Có báo cáo tỉ lệ biến thể lách được theo từng loại tấn công; chạy hằng
đêm trong CI.

**Làm.**

1. Viết `tools/strata-mutate` (Go), đọc `corpus/attack`. Các phép biến đổi:
   - encode URL hai lần;
   - đổi hoa thường;
   - chèn comment SQL `/**/`;
   - khoảng trắng lạ (tab, `%0b`, `%a0`);
   - Unicode NFC và NFD;
   - tách tham số (HPP);
   - kết hợp hai phép.
2. Mỗi biến thể chạy qua engine với gói đầy đủ (runner của `strata-rules`). "Lách
   được" nghĩa là payload gốc bị chặn còn biến thể thì không. Thống kê theo
   `attack_type` và theo phép biến đổi.
3. Workflow `.github/workflows/nightly.yml` (cron). Kết quả là artifact cộng
   `docs/mutation-report.md`.

**Kiểm:**

- `go test` của bộ biến đổi (mỗi phép một test, có test âm);
- chạy thật trên corpus;
- báo cáo `docs/reports/w09-s-02.md`.

### W09-S-01 · Phát hành gói signature v0

**Xong khi.** Gói v0 = CRS PL1 + nguồn nhập + rule riêng; tự vào staging 7 ngày; mọi
rule đã qua review 2 người; đạt chỉ tiêu Gate A ở mục Chỉ tiêu chất lượng.

**Làm.**

1. Đo chỉ tiêu Gate A trên gói đầy đủ:
   - FP benign ở ngưỡng chặn < 1%;
   - recall SQLi/XSS/CMDi/LFI ≥ 70%;
   - 100% rule có mẫu test.
   Rule thiếu mẫu (bots, ET) thì sinh mẫu `match` từ chính pattern, như đã làm cho
   bots.
2. Review:
   - `rules/reviews/2026-10-xx-signatures-v0.md` liệt kê theo nhóm, có số đo. Rule
     `block_alone` được duyệt từng rule;
   - Claude Code là người duyệt thứ nhất, theo tiền lệ PO giao;
   - người duyệt thứ hai phải là người thật (PO hoặc SecOps): comment trên PR, vì hai
     bên dùng chung tài khoản GitHub nên không dùng `--approve`.
3. Phát hành:
   - tag `signatures-v0.0.1`;
   - `strata-rules release` + `strata-rules verify`, ký qua Vault Transit;
   - control plane của staging nhận gói, và ngày bắt đầu ghi vào báo cáo.
   Mốc 7 ngày kết thúc sau tuần 9: nhiệm vụ ở trạng thái "chờ 7 ngày" cho đến khi
   staging chạy đủ 7 ngày không có FP mới.

**Kiểm:**

- `strata-rules report --max-fp` theo ngưỡng 1%;
- `strata-rules verify` gói đã phát hành;
- staging nhận bundle (metrics `C_BUNDLE`).

## 3. Cần PO (không chặn việc khác)

1. **Người duyệt thứ hai** cho gói v0 (W09-S-01): ai, và duyệt qua comment PR có được
   không?
2. **Staging thật**: có host hoặc VM nào không? Nếu không có, staging chạy trên máy
   này bằng compose và được ghi rõ như vậy (W09-Q-02).

## 4. Rủi ro

- Số đo trên WSL2 có thể dao động lớn. Cách giảm: ghim nhân, chạy 3 lần, báo trung vị
  và dải min–max. Nếu không đạt mục tiêu chỉ vì nhiễu môi trường, báo cáo ghi rõ và
  đề xuất đo lại trên VM Linux thật.
- Soak 24 giờ và fuzz 72 giờ chạy cùng lúc trên 8 nhân. Soak chỉ cần tải nhẹ, nên
  vẫn chấp nhận được.

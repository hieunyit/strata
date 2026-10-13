# Kế hoạch chi tiết tuần 10 · Đóng gói và shadow · Gate A

Nguồn: `docs/plan/plan.md`, mục "Tuần 10" và "Đường găng, phụ thuộc & gate". Lập ngày
13/10/2026, khi mọi PR của tuần 9 đã merge (#30–#40) nhưng còn ba việc tuần 9 chưa
khép (soak 24 giờ, staging 7 ngày của gói 0.0.1, review tuần 9).
Người làm: Claude Code, mọi luồng, trong worktree `~/strata-w10`. PO đã giao quyền tự
quyết kỹ thuật; chỉ hỏi khi cần dữ liệu mà chỉ PO có.

Mỗi nhiệm vụ làm theo cùng một quy trình:

- `git fetch && git rebase origin/main` trước khi bắt đầu và trước khi merge;
- một nhánh, đặt tên theo mã;
- chạy đủ dòng "Xong khi" bằng output thật;
- viết báo cáo `docs/reports/w10-*.md`;
- đổi dòng tương ứng trong AGENTS.md (mục tuần 10);
- PR, merge sau khi đã kiểm trên máy (GitHub Actions hết phút).

## 0. Ràng buộc của môi trường

- Máy: VM Xeon E5-2696 v4, 16 vCPU, 31 GB RAM (`hieuny-claude`). Chia nhân:

  | Nhân | Dùng cho |
  | --- | --- |
  | 0–5 | hệ thống, phiên review tuần 9 (`~/strata`, nhánh `w09-review`) |
  | 6–10 | build và test của tuần 10 (`STRATA_DEV_DOCKER_ARGS="--cpuset-cpus=6-10"`) |
  | 11–13 | soak 24 giờ (`strata-soak-24h`, tới khoảng 14/10 10:34 UTC) |
  | 14–15 | staging (`strata-staging`) |

- **Không chạy benchmark** trong phiên này (soak đang chạy, máy chia với phiên review).
  Mọi mục tiêu hiệu năng của Gate A giữ nguyên số đo của W09 và các ticket #27, #28.
- **Staging thuộc phiên review** cho tới khi memory `w09-review.md` có dòng
  "staging handed over to W10". Trước đó: không deploy staging, không đụng soak, không
  tạo tag `v0.9.0-rc.*`. Thử nghiệm cần stack đầy đủ thì dùng lab (project
  `strata-lab`, cổng 1xxxx).
- Sau khi nhận staging: chỉ deploy tag `v0.10.0-rc.*`, luôn kèm
  `--signatures build/signatures/v0.0.1`, mỗi lần deploy ghi một dòng vào
  `docs/reports/w09-s-01.md` (mốc 7 ngày của gói).
- Code dùng chung (engine, compiler, control plane, agent) có xung đột với bản sửa của
  phiên review thì chờ bản sửa đó merge rồi mới làm tiếp.

## 1. Gate A: trạng thái từng tiêu chí

Tiêu chí lấy từ `plan.md` (bảng "Tiêu chí gate", dòng A, và "Chỉ tiêu chất lượng" của
luồng S). Trạng thái tại ngày lập kế hoạch:

| # | Tiêu chí | Trạng thái | Bằng chứng / việc còn lại |
| --- | --- | --- | --- |
| A1 | Overhead p99 dưới 1 ms (request < 64 KB) | **Đạt một phần** | Phase 0–1: GET +53 µs (W09-R-01). Form 64 KB nhiều trường +1,34 ms → #28. Gói đầy đủ (ấm, Xeon): GET p50 1,0 ms, p99 1,7 ms (ghi chép review W09). Không đo lại trong tuần này |
| A2 | Throughput giảm tối đa 10% | **Chưa đạt** | −46% với phase 0–1 (W09-R-01, đo trên WSL2) → #27. Chưa đo lại trên Linux thật |
| A3 | Hot reload không rớt request | **Đạt** (chờ soak) | W05 (reload dưới tải), W08-N-01 (hot reload dưới tải trong Test::Nginx). Soak 24 giờ + 1.000 lần đổi bundle đang chạy, verdict khoảng 14/10 10:34 UTC |
| A4 | 72 giờ fuzz không crash | **Đạt theo quyết định của PO** | PO quyết ngày 13/10/2026: chỉ cần 30 phút đến 1 giờ fuzz thay cho 72 giờ. Đã có: FFI ASan khoảng 9 giờ 50 phút, khoảng 122 triệu lần chạy, 0 crash (W08-R-01, dừng do máy khởi động lại chứ không phải crash) |
| A5 | Conformance 100% | **Đạt** | W08-Q-01: corpus v1 qua engine và qua NGINX, 100% |
| A6 | Sự kiện về ClickHouse | **Đạt** (lab, staging) | W06, W09-G2-01. Với route thí điểm: W10-G2-01 |
| A7 | UI tra được Block ID | **Đạt** | W06-F-01, W09-G2-01 (tra Block ID < 1 s qua API) |
| A8 | Runbook đã diễn tập | **Chưa** | W10-N-01, diễn tập trên staging sau khi nhận staging |
| A9 | Gói signature v0 đạt chỉ tiêu Gate A của luồng S | **Đạt chỉ tiêu, chờ 7 ngày staging** | FP 0,60%, recall SQLi 76,3% / XSS 75,2% / CMDi 94,2% / LFI 92,7%, 9.054/9.054 rule có mẫu (W09-S-01). Mốc 7 ngày phải tính lại từ lần deploy sau bản sửa cold-start (xem mục 4) |

Kết luận dự kiến cuối tuần 10: **Gate A chưa đạt trọn** vì A1 (một phần), A2 và mốc
7 ngày của A9. Theo cột "Nếu chưa đạt" của plan: giữ shadow, không bật canary. Shadow
vẫn chạy được vì không chặn request; chi phí CPU của shadow và việc body lớn đi
fail-open (không được kiểm) phải được ghi rõ trong báo cáo Gate A. Quyết định chấp nhận
Gate A có ngoại lệ là của PO (mục 3).

## 2. Thứ tự

| # | Mã | Vì sao ở vị trí này |
| --- | --- | --- |
| 1 | W10-Q-01 Giám sát | Độc lập, làm được ngay trên lab. Shadow trên route thí điểm cần cảnh báo trước khi bật, và runbook (N-01) dẫn tới các dashboard và cảnh báo này |
| 2 | W10-N-01 Gói cài và runbook (+ #29) | Gói và runbook làm trên lab và container sạch. Phần diễn tập trên staging chờ nhận staging. #29 (sysctl, socket đã `connect()`) đi cùng gói cài |
| 3 | W10-G1-01 Triển khai control plane cho route thí điểm | Cần staging. Thêm 2 route thí điểm giả lập và node của chúng |
| 4 | W10-G2-01 Policy shadow cho route thí điểm | Cần node của route thí điểm (G1-01) |
| 5 | W10-S-01 Theo dõi FP trong shadow | Cần sự kiện shadow từ route thí điểm (G2-01) |
| 6 | W10-F-01 Trang Tổng quan v0 | Cần dữ liệu thật trong ClickHouse (G2-01) và truy vấn thống kê (S-01 dùng chung) |
| 7 | Báo cáo Gate A, review tuần 10 | Sau khi mọi nhiệm vụ trên có trạng thái cuối |

Nếu tới lúc làm G1-01 mà staging vẫn chưa được bàn giao, làm F-01 và phần truy vấn của
S-01 trên lab trước (dữ liệu shadow của lab), rồi quay lại G1-01.

## 3. Từng nhiệm vụ

### W10-Q-01 · Giám sát

**Xong khi.** Có dashboard Grafana và cảnh báo trên VictoriaMetrics cho module, agent,
control plane.

**Làm.**

1. Control plane xuất `/metrics` (Prometheus, cổng riêng chỉ cho scrape):
   - request REST theo route và mã trả về, độ trễ;
   - số node theo trạng thái (online, stale, ForceShadow), rollout đang chạy;
   - ingest: batch nhận, sự kiện ghi ClickHouse, lỗi ghi, độ trễ ghi;
   - compile và ký bundle: thời gian, lỗi.
   Dùng `prometheus/client_golang`, cùng bản với agent. Đây là dependency mới của
   module `control-plane`, ghi trong báo cáo.
2. Agent: metric `strata_agent_unix_max_dgram_qlen` (đọc `/proc/sys/net/unix/max_dgram_qlen`
   lúc khởi động) và cảnh báo log khi < 8.192 (phần agent của #29).
3. vmalert trong lab và staging, luật ở `deploy/lab/vm/alerts.yml`, mỗi luật có
   `runbook_url` trỏ vào `docs/runbook/`:
   - module: fail mode/budget vượt theo tỉ lệ, worker chạy bundle khác bản mong muốn,
     sự kiện bị bỏ > 0,1%, không có metrics từ node;
   - agent: mất kết nối control plane, spool gần đầy, chứng chỉ sắp hết hạn,
     ForceShadow đang bật, `max_dgram_qlen` thấp;
   - control plane: down, lỗi ghi ClickHouse, rollout kẹt, lỗi ký bundle.
4. Dashboard: tách `strata-node.json` thành module + agent, thêm `strata-control-plane.json`;
   dashboard nằm ở `deploy/grafana/dashboards/` cho cả lab, staging và gói cài.
5. Unit test cho luật cảnh báo bằng `vmalert-tool unittest` (có ca âm: luật không bắn
   khi chỉ số dưới ngưỡng).

**Kiểm:**

- `make test-go`; `make test-alerts` (mới, chạy `vmalert-tool` trong container);
- lab: `smoke.sh` kiểm Grafana nạp đủ dashboard và mỗi panel có dữ liệu; dừng một agent
  thì cảnh báo `StrataAgentDown` chuyển sang firing, bật lại thì hết;
- báo cáo `docs/reports/w10-q-01.md` kèm ảnh chụp dashboard.

### W10-N-01 · Gói cài và runbook

**Xong khi.** Gói deb/rpm `nginx-module-strata` theo từng phiên bản NGINX và gói
`strata-agent` cài được trên VM sạch bằng 1 lệnh; có image container; runbook tắt
module, ép shadow, rollback bundle đã diễn tập trên staging.

**Làm.**

1. `deploy/packaging/`:
   - build bằng `nfpm` trong image dev (dependency mới của image dev, ghi trong báo cáo);
   - `nginx-module-strata_<nginx-ver>+<strata-ver>`: `Depends: nginx (= <nginx-ver>-*)`
     theo cách đặt tên của gói nginx.org, để trình quản lý gói chặn cài lệch phiên bản;
     cài `.so` vào `/usr/lib/nginx/modules/`, file `load_module` mẫu, khóa công khai
     bundle;
   - `strata-agent`: binary, unit systemd, user `strata`, thư mục `/var/lib/strata`,
     `/run/strata`, `/etc/sysctl.d/90-strata.conf` (`net.unix.max_dgram_qlen = 8192`,
     #29);
   - ma trận v0: NGINX 1.30.5 và 1.31.6 × deb (Ubuntu 24.04, Debian 12) và rpm (Rocky 9),
     x86_64. aarch64, Alpine, NGINX Plus, OpenResty để sau, ghi trong báo cáo;
   - `make packages` và `deploy/packaging/install.sh` (1 lệnh: thêm gói từ thư mục cục
     bộ hoặc URL, cài, bật dịch vụ).
2. Test cài trên "VM sạch": container sạch của từng hệ điều hành (systemd làm init), cài
   nginx từ repo nginx.org đúng phiên bản, chạy 1 lệnh cài, kiểm `nginx -t`, agent chạy,
   sysctl đã áp. Ca âm: gói module cho 1.30.5 phải bị từ chối khi máy có nginx 1.31.6.
   Không có VM thật trên máy này; container sạch là thay thế, ghi trong báo cáo.
3. Image container `strata-nginx:<nginx-ver>` (NGINX + module + agent, supervisor đơn
   giản) dùng lại runtime của lab.
4. #29 phần module: gửi sự kiện qua socket đã `connect()`, nối lại khi agent khởi động
   lại (`ECONNREFUSED`/`ENOTCONN` → đóng, đánh dấu, thử lại ở lần gửi sau với giới hạn
   tần suất). Test::Nginx: agent khởi động lại giữa chừng, sự kiện sau đó vẫn tới. Số đo
   trước/sau cần benchmark, để lại cho #29.
5. `docs/runbook/`: tắt module (`strata off` + reload, hoặc gỡ `load_module`), ép shadow
   (`POST /v1/nodes:forceShadow`, `clearForceShadow`), rollback bundle (deploy lại
   version cũ), đặt sysctl, đọc dashboard và cảnh báo. Mỗi bước có lệnh, kết quả mong đợi
   và cách kiểm.
6. Diễn tập runbook trên staging (sau khi nhận staging), ghi giờ, lệnh và output vào
   báo cáo; mỗi lần deploy ghi vào `w09-s-01.md`.

**Kiểm:**

- C: `make test` cả 1.30.5 và 1.31.6, `test-nginx-asan` cả hai bản, `clang-tidy`,
  `check-c-lines` (≤ 3.000);
- Go: `make test-go`; shellcheck cho script;
- test cài trên 3 hệ điều hành; báo cáo `docs/reports/w10-n-01.md`.

### W10-G1-01 · Triển khai control plane cho route thí điểm

**Xong khi.** Control plane chạy trên staging và môi trường production cho route thí
điểm; node của 2 route thí điểm đã enroll.

**Làm.**

1. Chưa có dữ liệu route thí điểm và môi trường production từ PO (mục 4). Làm bằng
   **2 route giả lập trên staging**:
   - `pilot-verify` (`POST /v1/verify` trên `api.example.test`, JSON) và `pilot-upload`
     (`POST /v1/upload`, multipart);
   - mỗi route một node NGINX riêng (staging hiện có 2 node lab dùng chung route);
     node mới enroll bằng token, nhãn `route=pilot-verify|pilot-upload`;
   - backend giả lập trả JSON, có OpenAPI để sinh lưu lượng benign
     (`tools/strata-loadgen`), chạy đều suốt mốc shadow.
2. "Production" giả lập: một project Compose thứ ba (`strata-prod-sim`) dựng từ cùng tag
   bằng `deploy/staging/deploy.sh --env prod-sim`, chỉ để kiểm quy trình triển khai
   trên một môi trường khác staging. Báo cáo ghi rõ đây không phải production.
3. Mọi deploy từ tag `v0.10.0-rc.*`, kèm `--signatures build/signatures/v0.0.1`.

**Kiểm:** `smoke.sh` và `tests/e2e/lab-chain.sh` trên staging; `GET /v1/nodes` cho
thấy 2 node thí điểm online; báo cáo `docs/reports/w10-g1-01.md`.

### W10-G2-01 · Policy shadow cho route thí điểm

**Xong khi.** Policy của 2 route thí điểm ở chế độ shadow; sự kiện có Event ID về
ClickHouse.

**Làm.**

1. Policy `pilot-verify`, `pilot-upload`: `mode: shadow`, gói 0.0.1, fail mode `open`.
2. Lưu lượng: benign từ loadgen + một ít payload tấn công từ corpus (để có sự kiện
   `EVT-`); kiểm request không bị chặn (200 từ backend) dù vượt ngưỡng.
3. Kiểm đầu-cuối: sự kiện có `event_id` dạng `EVT-…`, `mode=shadow`, đúng policy, tra
   được qua `GET /v1/events/{id}` và trên UI.
4. Test âm: route thí điểm không bao giờ trả trang chặn khi ở shadow, kể cả với rule
   `block_alone`.

**Kiểm:** e2e `tests/e2e/pilot-shadow.sh`; `make test-go` nếu đụng control plane;
báo cáo `docs/reports/w10-g2-01.md`.

### W10-S-01 · Theo dõi FP trong shadow

**Xong khi.** Bảng FP theo Rule ID cập nhật hằng ngày (truy vấn ClickHouse hoặc
dashboard).

**Làm.**

1. Định nghĩa "nghi FP" cho shadow: sự kiện shadow trên route thí điểm, trừ những sự
   kiện từ nguồn tấn công đã biết (IP của bộ sinh tấn công trong lab/staging; ở
   production là danh sách do SecOps duy trì) → đếm theo Rule ID, theo ngày.
2. Bảng tổng hợp hằng ngày trong ClickHouse (materialized view hoặc bảng `fp_daily` ghi
   bởi job), có migration; panel Grafana (datasource ClickHouse) và lệnh
   `strata-rules fp-report --since 24h` in bảng Markdown.
3. Báo cáo ngày được ghi vào `docs/reports/w10-s-01.md` cho tới hết mốc shadow.

**Kiểm:** test Go cho truy vấn (dữ liệu giả có FP và có tấn công, ca âm: sự kiện
enforce và sự kiện từ IP tấn công không được tính); báo cáo có ít nhất 2 ngày số liệu.

### W10-F-01 · Trang Tổng quan v0

**Xong khi.** Request bị chặn theo giờ, top rule, top route từ dữ liệu thật.

**Làm.**

1. API `GET /v1/stats/overview?from&to&policy` (OpenAPI, **chỉ thêm**): số bị chặn (và
   shadow lẽ ra chặn) theo giờ, top 10 Rule ID, top 10 route (policy + path tiền tố),
   từ ClickHouse. Kiểm RBAC (viewer đọc được, không lộ IP). Lý do đổi OpenAPI: plan
   không có "Làm" cho nhiệm vụ này nhưng "dữ liệu thật" cần một API; thay đổi chỉ thêm,
   ghi vào báo cáo và `docs/design/nginx-module.md` mục API.
2. UI `OverviewPage`: biểu đồ cột theo giờ, hai bảng top, chọn khoảng thời gian; i18n
   vi/en; client sinh từ OpenAPI.

**Kiểm:** `make test-go`; `build/ui.sh` (lint, vitest, build, Playwright với lab);
ảnh chụp trên dữ liệu staging; báo cáo `docs/reports/w10-f-01.md`.

## 4. Việc tuần 9 còn mở (phụ thuộc, không giả định đã xong)

| Việc | Chủ | Ảnh hưởng tới tuần 10 |
| --- | --- | --- |
| Soak 24 giờ (`strata-soak-24h`, run `build/soak/24h-rc3`) | Phiên review | Tiêu chí A3. Verdict khoảng 14/10 10:34 UTC |
| Review tuần 9 (nhánh `w09-review`), gồm bản sửa cold-start (`TxBudget::credit`) | Phiên review | Bản sửa cần có trong tag `v0.10.0-rc.*` đầu tiên. Đụng engine, nên R/N của tuần 10 rebase sau khi bản sửa merge |
| Staging 7 ngày của gói 0.0.1 | Tôi, sau khi nhận staging | Lần deploy rc.3 (13/10 09:10 UTC) để lọt Log4Shell lúc cold-start, nên mốc 7 ngày tính lại từ lần deploy đầu tiên có bản sửa. Nếu deploy 15/10 thì hết mốc khoảng 22/10, **sau tuần 10** |
| #27 throughput, #28 body lớn | Chưa có chủ | A1, A2. Cần benchmark để làm và đo; phiên này không chạy benchmark (mục 5, câu 3) |
| #29 sysctl, socket đã `connect()`, đo lại trên Linux | W10-N-01 (code), W10-Q-01 (metric agent) | Phần đo lại cần benchmark, để mở |
| #34 biến thể lách được | Luồng S, tuần sau (W15-Q-01) | Không chặn Gate A (chỉ tiêu Gate A tính trên corpus gốc) |
| #36 cost unit | Chưa có chủ | Staging chạy `-cost-budget=2000000`. Môi trường prod-sim dùng cùng giá trị, ghi trong G1-01 |

## 5. Cần PO (không chặn việc khác)

1. **Route thí điểm thật** (W10-G1-01, W10-G2-01): host, path, OpenAPI hoặc mô tả API,
   lưu lượng trung bình, phiên bản NGINX và hệ điều hành của node. Chưa có thì tuần này
   chạy 2 route giả lập trên staging và báo cáo ghi rõ.
2. **Môi trường production cho control plane**: host hoặc VM, PostgreSQL, ClickHouse,
   KMS (Vault Transit hay KMS khác, và KMS đó có nhận payload ký cỡ 13 MB không; nếu
   không thì định dạng bundle phải chuyển sang ký digest), IdP (Keycloak hay IdP sẵn có).
   Chưa có thì dùng project `strata-prod-sim` trên máy này.
3. **Mục tiêu hiệu năng của Gate A** (#27, #28): (a) chấp nhận Gate A với ngoại lệ hiệu
   năng, vì shadow không chặn request, và đưa #27/#28 thành điều kiện trước canary
   (tuần 11); hoặc (b) mở cửa sổ benchmark (ví dụ sau khi soak xong 14/10) để làm tiếp
   trong tuần 10.
4. **Kênh nhận cảnh báo** (W10-Q-01): email, Slack hay webhook nào. Chưa có thì cảnh
   báo chỉ hiện trong vmalert/Grafana, với receiver webhook ghi log làm chỗ nối.
5. **Danh sách nguồn tấn công đã biết** để loại khỏi bảng FP (W10-S-01) khi có lưu
   lượng thật (dải IP quét nội bộ, pentest).

## 6. Rủi ro

- **Gate A không khép trọn trong tuần 10**: A2 chưa đạt, A1 đạt một phần, và mốc 7 ngày
  của gói rơi sau tuần 10. Cách giảm: báo cáo Gate A tách rõ phần đạt, phần chờ thời
  gian, phần cần quyết định của PO; không bật canary khi chưa đạt.
- **Phụ thuộc phiên review**: staging, soak và bản sửa engine nằm ở phiên kia. Cách
  giảm: làm Q-01, N-01 (phần gói) và F-01 trên lab trước; mọi việc staging dồn sau khi
  bàn giao.
- **Shadow với gói đầy đủ tốn CPU**: GET ấm p99 1,7 ms, body lớn đi fail-open. Shadow
  không chặn request nhưng vẫn cộng độ trễ. Route thí điểm giả lập không đo được ảnh
  hưởng thật; ghi trong báo cáo Gate A.
- **Gói cài chỉ thử trên container sạch**, không phải VM thật (systemd trong container
  khác VM ở sysctl và cgroup). Cách giảm: kiểm riêng phần sysctl bằng
  `--sysctl`/`--privileged`, và ghi lại bước cần kiểm trên VM thật.
- **Tài nguyên dùng chung**: build trên 5 nhân (6–10), staging 2 nhân (14–15). Thêm
  prod-sim và 2 node thí điểm làm tăng RAM khoảng 3–4 GB; kiểm `free` trước khi dựng.

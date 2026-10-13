# Kế hoạch khắc phục sau đánh giá bên ngoài (14/10/2026)

Lập ngày 14/10/2026, giữa tuần 10 (Gate A). Nguồn: bài đánh giá bên ngoài về Strata
(5 nhược điểm: hiệu năng, log thiếu ngữ cảnh, hạ tầng cồng kềnh, chống bot, duy trì
9.000 rule) và phần đối chiếu bài đó với repo tại `dd45b9b`.

**PO duyệt 14/10/2026** mục 6.1–6.5; các nhiệm vụ `RV-*` đã vào `plan.md` ở tuần ghi
trong từng đợt (mã giữ nguyên). Mục 6.6 (route thật) còn chờ PO. Việc đã có trong plan
hoặc đã được PO duyệt từ trước thì ghi rõ, không lập lại nhiệm vụ.

## 1. Đối chiếu bài đánh giá với repo

| Nhận định | Đúng / sai | Bằng chứng | Xử lý |
| --- | --- | --- | --- |
| Throughput −46%, form 64 KB +1,34 ms | Đúng | `docs/reports/w09-r-01.md` §5, #27, #28 | RV-R-01 |
| Gói đầy đủ cho body lớn đi fail-open | **Bài bỏ sót**, nặng hơn latency | #28, #49 (request đầu sau reload) | RV-R-01, RV-N-01 |
| Sự kiện thiếu User-Agent, Referer, header; snippet 128 B | Đúng | `proto/strata/event/v1/event.proto` | RV-G2-01 (P-01 §1, §1b đã duyệt) |
| Chỉ có NGINX | Đúng | `connectors/*` khác chỉ có 1 file | RV-Q-01 (ghi rõ trạng thái), giữ W22-ALL-02 |
| Replay mới là khung, chưa học schema | Đúng | Replay ở W11–W13; học schema không có trong plan | RV-Q-01 |
| Rate limit cơ bản | **Sai, thực tế còn kém hơn**: chưa có rate limit | P-01 §3 chờ duyệt | RV-R-03 |
| Chống bot chỉ có danh sách UA tĩnh | Đúng | `rules/` bot import; JA4 chỉ có trong `strata-overview.md` | RV-R-04, RV-N-02 |
| Hạ tầng nặng cho SME | Đúng với bản hiện tại | Module + agent + control plane + Postgres + ClickHouse + UI | RV-G1-01 (chế độ Lite, cần PO) |
| 9.000 rule khó duy trì | Đúng; FP 0,60% chưa đủ cho production | W09-S-01 | RV-S-01, RV-S-02 |
| Fuzz 72 giờ mỗi PR | **Sai** | Fuzz chạy riêng; PO 13/10 hạ yêu cầu xuống 30–60 phút; đã có 9 giờ 50 phút FFI ASan, 0 crash | RV-Q-01 (ghi đúng số) |
| Rust nên không sập worker | **Nói quá** | Còn ~3.000 dòng C và `unsafe` ở `engine/ffi/`; `catch_unwind` không bắt abort/OOM | RV-Q-01; breaker W11-N-01 |
| Chưa chạy traffic thật | Đúng | Route thí điểm W10 đang là giả lập | RV-Q-03 (điều kiện Gate B) |

## 2. Đợt 0 · Tuần 10–11: trước và ngay sau báo cáo Gate A

- **RV-R-01 · Đóng #27/#28 (đang làm, nhánh `issue-28-hs-groups`)**
  - Thư mục: `engine/`, `tools/` (compiler)
  - Làm: bundle section kind 8 (Hyperscan block mode, một DB cho mỗi nhóm scan) sau cờ compiler; đo trước/sau trên nhân 0–5, Linux thật (không phải WSL2 như số −46%).
  - Xong khi: báo cáo trước/sau cho 3 số: throughput phase 0–1, p99 form 64 KB / 1.700 trường, tỉ lệ fail-open của gói đầy đủ với body 64 KB và 1 MB. Chưa đạt mục tiêu (≤ 10%, < 1 ms, 0 fail-open với body ≤ 64 KB) thì ticket có hướng làm tiếp, và Gate A ghi ngoại lệ.
  - Đã có trong: quyết định PO 14/10 mục 1.
- **RV-N-01 · Fail-open phải nhìn thấy được**
  - Thư mục: `engine/`, `deploy/monitoring/`, `ui/`
  - Hiện có: `strata_budget_exceeded_total` + cảnh báo vmalert (W10-Q-01), biến `strata_tx_request_body_skipped`.
  - Làm: sự kiện có cờ `inspection = partial | skipped` khi vượt budget hoặc bỏ qua body; tỉ lệ request không được kiểm đủ theo route trên trang Tổng quan; dòng riêng trong báo cáo Gate A.
  - Xong khi: test tạo body vượt budget → sự kiện có cờ, ClickHouse đếm được theo route, ô trên Tổng quan hiện đúng số.
  - Interface: thêm field vào `event.proto` (thêm mới, tương thích ngược). Gộp với thay đổi proto của RV-G2-01 để chỉ đổi proto một lần.
- **RV-G2-01 · Ngữ cảnh điều tra trong sự kiện (P-01 §1, §1b, đã duyệt)**
  - Thư mục: `engine/`, `proto/`, `control-plane/`, `ui/`
  - Làm: `user_agent`, `referer` (cắt 512 B, cột riêng); header tên + giá trị, tối đa ~32 header / 2 KB, giá trị `Authorization`, `Cookie`, `X-Api-Key`… thành `[MASKED]`; `max_snippet_size` admin chọn (128 B mặc định, 2–4 KB); mở rộng masking trong `engine/src/event.rs` (CCCD, JWT) trước khi ghi; migration ClickHouse; UI chi tiết sự kiện hiện các field mới.
  - Xong khi: test masking cho từng loại; tra Block ID trên UI thấy UA, Referer, header đã che; đo lại hiệu năng sau thay đổi (PO yêu cầu) và so với RV-R-01.
  - Cần trước: RV-R-01.
- **RV-Q-01 · Trạng thái thật của tính năng**
  - Thư mục: `docs/`, `README.md`
  - Làm: `docs/status.md`, bảng mỗi tính năng trong `strata-overview.md` với một trong ba trạng thái **Có (đã test) / Một phần / Mới là thiết kế**, kèm link báo cáo hoặc test. README dẫn tới bảng này, không liệt kê tính năng chưa có như đã có. Báo cáo Gate A dùng đúng số: fuzz 9 giờ 50 phút (theo quyết định PO), giới hạn của `catch_unwind`, route thí điểm là giả lập.
  - Xong khi: mọi dòng "Có" trỏ tới test hoặc báo cáo; review tuần 10 kiểm bảng này.

## 3. Đợt 1 · Tuần 11–13: song song khối B1

- **RV-S-01 · Tách gói rule theo mức tin cậy**
  - Thư mục: `rules/`, `tools/`
  - Làm: gói **core** (CRS PL1 + protocol + virtual patch) là mặc định; gói **signature** (Sigma, ET Open, 9.054 rule) bật theo route, mặc định chỉ shadow. Rule chỉ lên gói core khi đủ N ngày shadow trên traffic thật mà FP theo Rule ID dưới ngưỡng.
  - Xong khi: `strata-rules release` sinh được 2 gói; policy chọn được gói theo route; test policy mặc định không có rule signature ở chế độ enforce.
  - Cần PO: ngưỡng FP production (đề xuất < 0,05% request theo route, thay cho 0,60% trên corpus) và N (đề xuất 14 ngày).
- **RV-S-02 · Quy trình nuôi rule**
  - Thư mục: `tools/`, `control-plane/`, `docs/rules/`
  - Làm: dựa trên bảng FP theo Rule ID (W10-S-01): rule vượt ngưỡng FP trong shadow tự bị đánh dấu "cần xem" và đề xuất exception có hạn; rule không khớp lần nào trong 90 ngày bị đánh dấu "già"; mỗi rule có người chịu trách nhiệm và ngày xem lại; nhập lại CRS/Sigma/ET theo lịch, chạy `make test-crs-ftw` + corpus benign trước khi phát hành.
  - Xong khi: báo cáo hằng tuần tự sinh (rule cần xem, rule già, thay đổi upstream); gộp vào lịch phát hành của W22-S-01 (đưa sớm lên tuần 13).
- **RV-Q-03 · Traffic thật trước Gate B**
  - Làm: thay 2 route thí điểm giả lập bằng route thật, chạy shadow ít nhất 14 ngày; thu corpus benign từ traffic thật đã ẩn danh (đã có trong W11-S-01); differential với Coraza + CRS trên cùng traffic (W12-R-01).
  - Xong khi: thêm vào Gate B: "≥ 14 ngày shadow trên traffic thật, FP theo route dưới ngưỡng RV-S-01, tỉ lệ request không được kiểm đủ (RV-N-01) dưới ngưỡng".
  - Cần PO: chọn route thật và dữ liệu.

## 4. Đợt 2 · Tuần 14–16: khối B2

- **RV-R-03 · Rate limit tầng 1, theo node (P-01 §3, chờ duyệt)**
  - Thư mục: `engine/`, `connectors/nginx/src/`
  - Làm: theo P-01 §3 tầng 1: bộ đếm trong shared memory, key theo IP / identity / route, action `rate_limit` trong policy (đã có trong mô hình policy của `strata-overview.md`).
  - Xong khi: test brute-force trên route login giả lập bị chặn đúng ngưỡng; không khóa, không I/O trên đường đi request; benchmark không giảm quá 2%.
  - Tầng 2 (toàn cụm, trễ vài giây) để sang giai đoạn C.

## 5. Đợt 3 · Tuần 17–20: khối C

Giai đoạn C thêm việc thì phải bớt việc: đề xuất chuyển GitOps (W20) sang v1.1, như cột
"Nếu chưa đạt" của Gate C đã cho phép.

- **RV-N-02 · Fingerprint TLS JA4 trong NGINX**
  - Thư mục: `connectors/nginx/src/`, `engine/`
  - Làm: lấy ClientHello thô qua callback ClientHello của OpenSSL, chỉ chuyển con trỏ + độ dài sang libstrata; libstrata tính JA4 (không parse trong C). JA4 vào sự kiện và dùng được làm key rate limit / điều kiện rule.
  - Xong khi: JA4 khớp vector tham chiếu của FoxIO cho curl, Chrome, Python requests; tăng số dòng C nằm trong giới hạn 3.000 (`make check-c-lines`).
  - Không làm: fingerprint HTTP/2 (SETTINGS/WINDOW_UPDATE) trên NGINX vì NGINX không đưa các frame này ra module; xem lại khi có connector Envoy.
- **RV-R-04 · Challenge và rate theo identity**
  - Thư mục: `engine/`, `connectors/nginx/src/`
  - Làm: action `challenge`: trang JS challenge, cookie ký HMAC có hạn, libstrata kiểm cookie; ngưỡng `challenge` / `block` theo route (đã có trong thiết kế); rate theo identity cho route đăng nhập (credential stuffing); rate limit tầng 2 (P-01 §3).
  - Xong khi: test client không chạy JS bị challenge, trình duyệt headless qua được rồi bị rate limit theo identity; cookie giả hoặc hết hạn bị từ chối.
- **RV-G1-01 · Chế độ Lite cho cụm nhỏ (cần PO, đổi thiết kế)**
  - Thư mục: `agent/`, `deploy/packaging/`, `docs/design/`
  - Làm: `strata-agent --standalone`: nhận bundle đã ký từ thư mục hoặc URL, ghi control file, đọc metrics, ghi sự kiện ra file JSON Lines / syslog (dùng đường xuất SIEM của P-01 §2). Không cần control plane, Postgres, ClickHouse, UI. Một lệnh cài: gói module + agent + gói rule core.
  - Xong khi: VM sạch, cài 1 lệnh, chặn được request SQLi mẫu trong dưới 5 phút; cập nhật rule bằng `strata-rules` + hot reload, không `nginx -s reload`.
  - Cần trước: PO duyệt; cập nhật `nginx-module.md` (chế độ triển khai) và P-01 §2.

## 6. Quyết định của PO

| # | Câu hỏi | Quyết định 14/10/2026 |
| --- | --- | --- |
| 1 | Đưa `RV-*` vào `plan.md` theo các đợt trên | Duyệt. RV-R-01, RV-N-01, RV-Q-01 → tuần 10; RV-G2-01, RV-S-01 → tuần 11; RV-S-02, RV-Q-03 → tuần 13; RV-R-03 → tuần 14; RV-N-02 → tuần 17; RV-R-04 → tuần 18; RV-G1-01 → tuần 19 |
| 2 | Ngưỡng FP production, số ngày shadow | Duyệt: dưới 0,05% request theo route, 14 ngày; thêm vào chỉ tiêu luồng S và Gate B |
| 3 | P-01 §3 rate limit | Duyệt (cả tầng 1 và tầng 2) |
| 4 | Chế độ Lite vào v1 | Duyệt; nginx-module.md cập nhật trong RV-G1-01, trước khi code |
| 5 | Chống bot vào giai đoạn C, GitOps sang v1.1 | Duyệt; W19-G1-01, W20-G1-01 bỏ khỏi v1 |
| 6 | Route thật cho RV-Q-03 | **Chờ PO.** Route thật phải shadow 14 ngày trước canary: bắt đầu đầu tuần 11 thì canary sớm nhất tuần 13, Gate B lùi theo |

## 7. Không làm theo bài đánh giá

- Không chạy fuzz 72 giờ trong mỗi PR: không khả thi và PO đã quyết số giờ.
- Không thêm connector khác trước Gate B: giữ W22-ALL-02 (chọn connector thứ hai sau v1).
- Học schema từ traffic: giữ là thiết kế, ghi "Mới là thiết kế" trong `docs/status.md`, không lập nhiệm vụ trong v1.

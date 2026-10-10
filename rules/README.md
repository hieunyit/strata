# rules

Rule của Strata và rule nhập từ nguồn ngoài (docs/plan/plan.md › Luồng S).

- `schema/rule.schema.json`: định dạng **một rule một file**: `rule` là rule IR
  mà compiler đọc (`docs/spec/ir.schema.json`), `tests.match` / `tests.no_match`
  là request rule phải khớp / không được khớp (mỗi loại ít nhất một).
  Rule nào cũng có `metadata.source` và `metadata.license`; rule nhập từ
  CRS, Sigma, ET, crawler-user-agents thêm `upstream_id`, `upstream_version`,
  `author`. Tên file bắt đầu bằng Rule ID: `800001-admin-path-....yaml`.
- `samples/`: rule mẫu của các nguồn khác CRS (Strata, Sigma, crawler-user-agents, tổ chức).
- `protocol/`: pack protocol của Strata (W05-S-01), 40 rule dải 100101–100140,
  layer `protocol`: method, phiên bản HTTP, dạng request target, giới hạn độ
  dài và số lượng (transformation `length` + toán tử số), encoding lạ, Host,
  `Upgrade: h2c`, header hop-by-hop, `Proxy` (httpoxy), body nén... Bổ sung
  cho các kiểm tra dựng sẵn trong engine (100001–100020) và nhóm 920/921 của
  CRS, không lặp lại chúng. Mỗi rule có mẫu khớp/không khớp; `make test-rules`
  đòi pack này khớp **0** request benign (`report --max-fp 0`).
- Bộ rule do importer sinh (ví dụ `crs/`) là tài liệu IR nhiều rule
  (`ir_version`, `ruleset`, `rules`); test của chúng là go-ftw của upstream.

## CRS (`crs/`)

`make crs-import` sinh `crs/*.yaml` từ CRS 4.25.2 (khóa trong
`tools/strata-import-crs/crs.lock`), chỉ paranoia level 1; rule không nhập
được kèm lý do ở `docs/crs-import-report.md`. Điểm anomaly nhân 20 (ngưỡng
CRS 5 = ngưỡng Strata 100). `make test-crs-ftw` chạy go-ftw của CRS qua
libstrata (mỗi rule biên dịch riêng) và đòi mỗi nhóm injection
(930, 931, 932, 933, 941, 942, 944) đạt tối thiểu 90% số test của rule PL1;
kết quả ở `docs/crs-ftw-report.md`.

Khác biệt đã biết với CRS chạy trên ModSecurity:

- `request_body` luôn là body thô, kể cả body XML/JSON/multipart (ModSecurity
  chỉ có `REQUEST_BODY` với body form): tên phần tử, tên thuộc tính XML lọt vào
  944100/944110/944120 (24 test `no_match` của 944 thất bại vì thế). Giữ như
  vậy để rule của tổ chức trên `request_body` không bị mù với API XML/JSON.
- Request có byte NUL (`%00`) bị kiểm tra protocol dựng sẵn 100013 chặn trước
  khi rule CRS ở giai đoạn body chạy (930100-3, 930120-1..3, 933170-5).
- Trên corpus benign, 930120 (`C:/Program Files` trong lfi-os-files.data) và
  942100 (libinjection coi `50% off -- today only` là SQLi, đúng như thư viện
  C gốc) khớp; đó là hành vi của CRS PL1, xử lý bằng exclusion của policy.

Kiểm tra (chạy trong CI):

```bash
make lint-rules        # = cd tools/strata-rules && go run . lint --repo ../..
make test-rules        # mẫu match / no_match qua libstrata, rồi báo cáo FP/recall trên corpus/
```

`strata-rules test` biên dịch mọi rule file thành bundle và chạy từng mẫu qua
libstrata (`strata-eval`, đúng thứ tự gọi của connector NGINX): FAIL khi mẫu
`match` không khớp hoặc mẫu `no_match` khớp; SKIP kèm lý do khi rule dùng
operator, transformation hay target mà engine chưa đánh giá.

`strata-rules lint` báo lỗi khi file sai schema (thiếu `license`, thiếu
thông tin upstream, Rule ID sai dải của nguồn), trùng Rule ID, tên file không
khớp ID, regex không phải RE2 (thời gian tuyến tính), giấy phép không được
đóng gói (chỉ Apache-2.0, MIT, BSD-2/3-Clause, DRL-1.1), hoặc thiếu mẫu test.

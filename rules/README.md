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
  khi rule CRS ở giai đoạn body chạy (920270-1..3, 920270-8, 930100-3, 930120-1..3, 933170-5).
- Trên corpus benign, 930120 (`C:/Program Files` trong lfi-os-files.data) và
  942100 (libinjection coi `50% off -- today only` là SQLi, đúng như thư viện
  C gốc) khớp; đó là hành vi của CRS PL1, xử lý bằng exclusion của policy.

## Sigma, ET Open, crawler-user-agents (`sigma/`, `et-open/`, `bots/`)

`make signatures-import` sinh ba pack từ nguồn ghim trong
`tools/strata-import-signatures/sources.lock` (commit hoặc phiên bản + sha256;
`fetch.sh` tải và kiểm hash). Mỗi pack có `*.yaml` (ruleset IR), `ids.txt`
(Rule ID của từng rule upstream, giữ qua các lần nhập: ID không dùng lại) và
`tests/*.jsonl` (request `match`/`no_match`, chạy bằng `make test-signatures`:
mỗi rule biên dịch riêng, phải đạt 100%). Rule không chuyển được, kèm lý do:
`docs/sigma-import-report.md`, `docs/et-open-import-report.md`,
`docs/bots-import-report.md`. Rule upstream bị bỏ sau khi kiểm corpus benign
nằm trong `tools/strata-import-signatures/exclude.txt` (có lý do).

| Dải Rule ID | Nguồn | Giấy phép | Ghi chú |
| --- | --- | --- | --- |
| 400100 | mẫu Sigma | DRL-1.1 | `samples/` |
| 400200–449999 | SigmaHQ `rules/web` | DRL-1.1 | chỉ log webserver; log proxy chỉ khi rule chỉ xét User-Agent; log lỗi của server bỏ |
| 450000–499999 | ET Open, **chỉ SID 2000000–2099999** | BSD-3-Clause | phần BSD của ET Open; importer từ chối SID khác (có test). Chỉ rule HTTP `to_server` của `web_server`, `web_specific_apps`, `exploit`, `scan` |
| 500100 | mẫu crawler-user-agents | MIT | `samples/` |
| 500200–509999 | crawler-user-agents | MIT | mỗi pattern một rule trên User-Agent, **điểm 0**, label `bot`: nhận diện, không chặn |
| 700000–799999 | virtual patch (`virtual-patches/`) | Apache-2.0 | Strata viết, một rule một file, có mẫu; xem dưới |

**Bộ ET khuyến nghị** (quyết định 12/10/2026): `et-open/web_server.yaml`, `scan.yaml`, `exploit.yaml` (khoảng 20.500 cost unit, cộng CRS PL1 khoảng 14.900, tổng khoảng 35.400, dưới ngân sách mặc định 50.000). `web_specific_apps.yaml` (82.681) chỉ bật cho policy bảo vệ đúng các ứng dụng đó. Không nâng ngân sách mặc định để chứa cả pack: cost unit đo chi phí CPU mỗi request.

**Virtual patch (`virtual-patches/`, 700001–700010)**: chặn khai thác các CVE web bị dùng rộng: Log4Shell, Spring4Shell, Struts2 OGNL (Content-Type), Confluence OGNL trong path, PHPUnit `eval-stdin.php`, Drupalgeddon 2, Laravel Ignition, Apache path traversal mã hóa hai lần, Citrix `/vpns/`, Exchange ProxyShell. Mỗi rule bám đúng dấu hiệu của khai thác, điểm 100 (chặn ngay) và `accuracy: high`. Rule có mẫu `match`/`no_match` và khớp 0 request benign (`make test-rules`). `metadata.systems` ghi stack liên quan; khi PO cho biết stack của route thí điểm (Q4), thêm patch theo cùng mẫu.

Điểm: Sigma critical 100, high 60, medium 40, low 20 (informational không nhập).
ET: `signature_severity` Critical 80, Major 60, Minor 30, Informational 10,
chia đôi khi `confidence Low`; một rule ET không tự chặn vì bản dịch có thể
rộng hơn Suricata (`distance`/`within` giữa các content bị bỏ; báo cáo đếm số
rule như vậy). Cost unit (W07-G2-01): Sigma 112, bots 2 906, ET `scan` 649,
`web_server` 5 078, `exploit` 14 780, `web_specific_apps` 82 681: cả pack ET
(103 188, bundle 15,9 MB) vượt ngân sách mặc định 50 000; policy chọn tệp ET
theo stack của mình.

Khác biệt với nguồn: Sigma so khớp không phân biệt hoa thường (transformation
`lowercase`); keywords (giá trị không có field) được tìm trong request target
thô, cả dạng thô và đã URL-decode; filter trên response (`sc-status`) bị bỏ vì
rule chạy trước khi có response. `http.uri` của Suricata là `uri_raw` +
`url_decode` (giữ `//`, không chuẩn hóa path); `+` trong content của URI khớp
cả `+` và dấu cách.

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

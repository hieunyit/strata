# rules

Rule của Strata và rule nhập từ nguồn ngoài (docs/plan/plan.md › Luồng S).

- `schema/rule.schema.json`: định dạng **một rule một file**: `rule` là rule IR
  mà compiler đọc (`docs/spec/ir.schema.json`), `tests.match` / `tests.no_match`
  là request rule phải khớp / không được khớp (mỗi loại ít nhất một).
  Rule nào cũng có `metadata.source` và `metadata.license`; rule nhập từ
  CRS, Sigma, ET, crawler-user-agents thêm `upstream_id`, `upstream_version`,
  `author`. Tên file bắt đầu bằng Rule ID: `800001-admin-path-....yaml`.
- `samples/`: 10 rule mẫu, mỗi dải nguồn một ví dụ.
- Bộ rule do importer sinh (ví dụ `crs/`) là tài liệu IR nhiều rule
  (`ir_version`, `ruleset`, `rules`); test của chúng là go-ftw của upstream.

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

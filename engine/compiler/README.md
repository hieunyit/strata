# strata-compiler — compiler bundle v0 (W04-R-01)

`strata-compile` nhận rule IR (`docs/spec/ir.schema.json`, viết bằng JSON hoặc YAML, cùng một mô hình dữ liệu) và file policies (`docs/spec/policies.schema.json`), ký Ed25519 và ghi bundle theo `docs/design/control-file.md`.

```bash
target/release/strata-compile --rules engine/compiler/examples/rules.yaml \
  --policies engine/compiler/examples/policies.yaml \
  --key connectors/nginx/t/fixtures/test.key --version 1 --out bundle-1.sbn
```

Chưa có: section Hyperscan (W05-R-01), cost unit (W07-G2-01), đánh giá rule trong engine; metadata rule (nguồn, giấy phép, tác giả) chỉ được kiểm theo schema, chưa đóng vào bundle.

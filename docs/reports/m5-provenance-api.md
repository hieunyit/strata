Nhiệm vụ: M5 · đọc bằng chứng replay qua API

Thêm trường proto tương thích ngược cho input/artifact/sample hashes, approved_replay_id và bundle input_digest; nối mapping REST/gRPC, sinh lại Go/OpenAPI/TypeScript. `docs/spec/replay-provenance.md` mô tả semantics và giới hạn. Không thêm URL thủ công cho UI, không đổi quyền đọc ví dụ nhạy cảm.

Kiểm chứng local:
```
make proto
# buf lint, cả hai buf generate: PASS
go test -race ./admin
ok github.com/strata/strata/control-plane/admin 6.066s
# API E2E trên PostgreSQL + MinIO riêng
--- PASS: TestPolicyDraftReplay (10.83s)
ok github.com/strata/strata/tests/e2e 11.992s
npm run generate:api && npm run lint
> tsc --noEmit
```
E2E xác nhận viewer nhận hashes đầy đủ qua HTTP, vẫn không nhận request examples; giữ các kiểm tra gate/binding/publish của phần trước. UI client types có trường mới; chưa thêm widget UI. Không chờ hosted CI theo yêu cầu PO.

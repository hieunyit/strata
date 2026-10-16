Nhiệm vụ: M2 · hợp đồng API exception draft
Nhánh: codex/m2-exception-contract; base: codex/m2-exception-api.

OpenAPI khai báo request/response và lỗi cho POST /v1/exceptions:fromBlockId; nêu rõ scope lấy từ event, TTL bắt buộc, exact field, request_id/etag, replay/four-eyes/deploy và việc từ chối alias mơ hồ. Sinh TS schema và thêm phương thức apiClient dùng các kiểu từ OpenAPI. Chưa thêm UI form trong PR này.

npm run generate:api; npm run lint; npm test → 8 files / 66 tests PASS; npm run build PASS (15.50s). Chạy Node 24.21.0 trong container, node_modules read-only và riêng cache .vite trên tmpfs; không sửa/tắt test. Chỉ spec/client/generated/docs, không dependency hoặc thay đổi policy xử lý. Test API PostgreSQL nằm ở base #150; kiểm thử chuỗi với compiler/replay thật là bước tiếp theo. Không merge/deploy, không chờ hosted CI.

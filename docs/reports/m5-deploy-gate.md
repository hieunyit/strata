Nhiệm vụ: M5 · deploy từ đúng đầu vào đã replay và duyệt (phần 4)

Hành vi: khi replay được cấu hình, deploy giữ bundle lock toàn cụm, chụp đầu vào compiler, rồi kiểm operation đã bind vào approval của từng policy/version. Phải DONE, đúng policy/version, có mẫu thực (>0), digest trùng toàn bộ tập policy/rule/compiler/config và baseline version/SHA. Sau đó chỉ compile từ snapshot đó. Thay file gốc sau kiểm không thay byte được compile. Từ chối trước upload/record/rollout; API trả FailedPrecondition với lý do. Lưu input_digest cùng bundle.

Bằng chứng local:
```
# PostgreSQL 17.11 riêng, -race
TestApprovalBindsReplayInPostgres PASS
TestReplayGateUsesApprovedOperation: 10 cases PASS
# go test -race ./policy ./admin ./replay ./cmd/server
ok github.com/strata/strata/control-plane/policy 1.371s
ok github.com/strata/strata/control-plane/replay 3.703s
# golangci-lint run
0 issues.
# E2E PostgreSQL + MinIO riêng, API auth/four eyes, compiler/replay subprocess giả lập
--- PASS: TestPolicyDraftReplay (10.69s)
PASS
ok github.com/strata/strata/tests/e2e 11.847s
```
E2E nối Prepare/Gate như server thật: replay → approve → đổi rule → deploy bị từ chối; replay mới DONE sau approval vẫn không deploy được; không có bundle được record; khôi phục đúng đầu vào được duyệt thì deploy thành công và digest giữ trong PostgreSQL. Test policy thay file rule sau khi gate kiểm: compile vẫn dùng snapshot cũ; khi gate từ chối không có object hay bundle. Đây là kiểm integrity/workflow, không dùng subprocess giả lập để tuyên bố chất lượng detection.

Tự review: không thêm dependency; I/O có context; migration và audit cùng nghiệp vụ; giữ 4 mắt theo subject; guard bật trong production wiring khi `-replay` được cấu hình. Không chờ hosted CI theo yêu cầu PO.

Vận hành:
- Approval cũ chưa có proof không được tự gán lại. Tạo version mới (có thể cùng spec), replay rồi submit/approve lại khi bật gate.
- Đổi rules/compiler/config/baseline hoặc tập policy cần replay và approval mới. Gate kiểm mọi policy trong bundle; chuẩn bị các draft xong, duyệt và refresh bản có digest cũ trước deploy. Không có đường bỏ qua gate để dùng replay mới chưa được duyệt.
- Digest cam kết file compiler/IR/config; runtime/shared libraries cần pin ở image. Chưa có ràng buộc digest image engine của từng node. Provenance hiện lưu ở kết quả operation trong DB; bổ sung mapping proto/UI là công việc hiển thị kế tiếp.
- Baseline là bundle được publish mới nhất, theo hành vi sẵn có; không tuyên bố mọi node đã activate cùng version. Bundle bytes có version/timestamp/signature riêng nên deploy SHA khác replay SHA; tính tương đương ở đây là cùng đầu vào đã snapshot.

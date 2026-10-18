Nhiệm vụ: M5 · bản chụp đầu vào compile (phần 1)

Thay đổi: `Compiler.Prepare` tạo bản chụp riêng của executable, các file rule theo đúng thứ tự, block page, policy (deep copy) và identity HMAC key. Digest SHA-256 cam kết nội dung cùng cost budget/support contact; signing key và số phiên bản bundle không thuộc digest vì replay dùng khóa riêng. `Prepared.Build/ReplayBuild` compile từ đúng bản chụp; `Close` dọn file. Giới hạn tổng file 512 MiB, kiểm context trong lúc copy; không dependency mới.

Bằng chứng local:
```
go test -race ./policy -run TestCompilerSnapshot -v
--- PASS: TestCompilerSnapshotUsesHashedBytes (0.07s)
--- PASS: TestCompilerSnapshotRejectsInvalidInputs (0.02s)
PASS
ok github.com/strata/strata/control-plane/policy 1.189s
golangci-lint run ./policy
0 issues.
```
Test thay đổi lần lượt rule, block page, policy mode, sensitive_fields, identity key, budget, support contact và executable: mỗi lần đổi digest. Sau khi mọi file gốc bị thay, Prepared vẫn thực thi compiler cũ và dùng rule/policy/block page cũ. Test âm: missing/directory/513 MiB/cancel; kiểm dọn snapshot.

Giới hạn: phần này chưa nối runner/deployer; PR tiếp theo lưu provenance và từ chối deploy không khớp. Digest cam kết file đầu vào, không thay thế việc pin image/runtime và shared libraries của compiler. Không đổi chính sách CPU budget, không chờ hosted CI.

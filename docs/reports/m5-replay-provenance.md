Nhiệm vụ: M5 · ghi provenance của replay (phần 2)

Runner dùng `Compiler.Prepare` trong cấu hình server thật; draft được compile từ snapshot. Kết quả operation lưu digest đầu vào, SHA-256 bundle draft/baseline, executable replay và từng file mẫu/corpus thực sự được so sánh. Corpus và executable được chụp riêng có giới hạn (1 GiB/256 MiB), copy/hash có context; không ghi dữ liệu mẫu hay khóa vào provenance.

Kiểm chứng local:
```
go test -race ./replay
ok github.com/strata/strata/control-plane/replay 3.864s
golangci-lint run ./replay ./cmd/server
0 issues.
```
`TestReplayRecordsPreparedInputs` chạy compiler/replay executable giả lập qua subprocess thật, kiểm digest artifact/corpus, rồi đổi rule và chứng minh digest đầu vào + artifact thay đổi. Các test replay cũ vẫn pass. Chưa dùng phép thử này thay cho replay engine thật.

Giới hạn: provenance hiện lưu trong JSON kết quả operation ở PostgreSQL; mapping proto/UI hiện chỉ trả các thống kê sẵn có. PR kế tiếp ràng buộc approval/deploy với operation này. Baseline chưa từng deploy vẫn dùng nhánh bootstrap hiện có, không phải traffic sản xuất. Không chờ hosted CI theo yêu cầu PO.

Nhiệm vụ: M5 · giữ parser và baseline đầu tiên trong snapshot

TestRealReplay nay dùng Compiler.Prepare như production, kiểm đủ input/draft/baseline/replay/corpus digests. Compiler thật phát hiện file YAML bị copy thành rules-N không có đuôi rồi bị parse JSON. Snapshot giữ .yaml/.yml; loại khác dùng .json đúng default compiler. Manifest format 2 ràng buộc thứ tự parser với input_digest: cùng bytes đổi JSON↔YAML phải replay/duyệt lại; YAML/YML cùng parser cho cùng digest.

Baseline đầu tiên khi chưa có bundle cũng build bằng executable/rules đã chụp, không quay lại Compiler.Build trên source có thể đã đổi. Regression sửa source sau Prepare, ép đường Build cũ báo lỗi: fail trước sửa, pass sau; baseline/draft đều có digest bytes chuẩn bị ban đầu. Baseline đang deploy vẫn dùng artifact thật và chữ ký hiện có. ReplayBuildPolicies chỉ dùng cho baseline tổng hợp ban đầu, không thay deployment policy selection.

Kiểm chứng local:
```
go test -v -race ./policy ./replay: PASS
TestCompilerSnapshotPreservesRuleParser: PASS
TestFirstReplayBaselineUsesPreparedCompilerInputs: PASS
TestRealReplay (compiler/replay binary build cùng source): PASS (75.21s)
4300 corpus samples: 1700 newly blocked by 61 rules in 7232 ms
baseline sai chữ ký: bundle refused (5): bad bundle signature
golangci-lint run (toàn control plane): 0 issues
```

Tổ hợp remediation a196e7f trước bản bổ sung này đã chạy Rust workspace all-features: 377 pass, 0 fail, 9 ignored; clippy workspace sạch; agent/control-plane race pass. Lint CP lần tích hợp đầu gặp gofmt khi test mới đang bổ sung, đã chạy lại sau gofmt và sạch như trên. Hai E2E ở tests/e2e thực thi: TestPolicyDraftReplay PASS 13.27s (API/PG/MinIO thật, compiler fixture), TestRolloutToRealAgents PASS 68.52s (agent process thật, signature failure/abort/resume). TestRealReplay nằm trong control-plane/replay, đã chạy riêng có opt-in binary; không coi regex không khớp trong package e2e là test đã chạy.

PR base là nhánh codex/remediation-integration chứa các PR đã tách riêng, chưa merge main. Không chờ hosted CI, không vận hành staging/production. Bằng chứng tập trung trong m5-snapshot-formats/; full log ở build/remediation-integration-* và build/m5-snapshot-final.log. Replay format 1 chưa có parser binding cần chạy/duyệt lại; không attest shared libraries/runtime image.

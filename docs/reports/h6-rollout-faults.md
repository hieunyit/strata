# H6 — Sai chữ ký và kill/restart giữa download

Ngày 2026-10-17. Nhánh evidence `codex/h6-rollout-fault-evidence`; test thực thi trên `95b48ee`. Không sửa test/assertion/deadline trong lượt này.

```sh
STRATA_DEV_DOCKER_ARGS='--network host --cpuset-cpus=12-13 --group-add 988 -v /usr/bin/docker:/usr/bin/docker:ro -v /var/run/docker.sock:/var/run/docker.sock -v /home/hellc/strata/build/go:/src/build/go' deploy/dev/run.sh sh -ec 'cd tests/e2e; go test -race -count=1 -timeout 8m -v -run "^TestRolloutToRealAgents$" .'
```

GID 988 là group của Docker socket trên host lúc chạy; môi trường khác lấy bằng `stat -c '%g' /var/run/docker.sock`. Lượt đầu thiếu Docker CLI trong image nên FAIL trước khi tạo fixture; lượt ghi dưới bind mount CLI host và socket, không cài dependency hay tắt xác thực.

Kết quả thật:

- Ba agent process enroll/mTLS tới Fleet, PostgreSQL 17.11 và MinIO riêng. Bundle 1 chạy ba wave; control file các node đổi tại +0, +2,057 s, +4,123 s.
- Node đầu dùng pubkey khác: bundle 2 bị từ chối **signature does not verify**, rollout dừng; cả ba giữ version 1. Sau abort/reconnect, node không tự nhận lại bundle đã abort.
- Bundle fixture 64 MiB: pause sau **1.048.576 byte**, kill -9 agent, control file vẫn version 1. Restart tiếp tục từ offset đó, tải/verify thành công; cả ba có bundle 3 đúng kích thước/chữ ký và control file version 3.

```text
--- PASS: TestRolloutToRealAgents (69.11s)
PASS
ok .../tests/e2e 70.612s
```

Log và hash source ở [evidence](evidence/h6-rollout-faults/). Resource do harness tự tạo/cleanup, không dùng staging/production, không chờ CI. Không chạy test lossless restart cũ khi nó còn có thể adopt/truncate ClickHouse dùng chung; đang tách fixture cho test đó.

**Phạm vi:** compiler/bundle là fixture của rollout, event store MockEventStore; không phải full rule pack/replay provenance/KMS. Pubkey sai kiểm signature rejection, không thay thế mọi ca bit-flip/corrupt bundle. ACTIVE ở harness dựa control file, không có worker NGINX thực. Đây là agent process bị kill, không phải process control plane. Không cộng kết quả này với các test độc lập để tuyên bố đủ game day năm fault dưới traffic NGINX liên tục; CP stop, panic và chain metrics/HTTP vẫn còn việc. Không kiểm chứng mọi crash đều không mất event.

H6 · control plane process restart với NGINX thật · 18/10/2026 (UTC+7)
Nhánh `codex/h6-control-plane-process-restart`, base `codex/h7-browser-oracle` (`504f7b0`). Bổ sung acceptance lab, chưa hoàn tất game day.

Test mới chạy **entrypoint control-plane `cmd/server` thành process riêng**, `SIGKILL` và khởi động binary mới trên cùng REST/Fleet addresses, PostgreSQL và ClickHouse. Agent thật enroll qua API/mTLS, giữ nguyên PID/spool; NGINX hai worker dùng bundle một rule SQLi đã ký, cài sẵn để tách kiểm chứng phục hồi khỏi deploy/replay. Không dùng MockEventStore, producer có retry, proxy cắt mạng hay in-process gRPC restart thay cho process chết.

| Kiểm chứng | NGINX 1.30.5 | NGINX 1.31.6 |
|---|---:|---:|
| Block ID được xác nhận riêng trong ClickHouse | 120/120 | 120/120 |
| Row vật lý lúc kiểm tra | 120 | 120 |
| Gián đoạn từ process chết tới REST trở lại | 2,447 s | 2,500 s |
| Thời gian đợi xả sau đợt gửi cuối | 2,438 s | xem result.json |
| Bundle/control file sau phục hồi | Giữ nguyên | Giữ nguyên |

Mỗi lượt gửi 20 attack trước lỗi, 80 lúc CP chết, 20 sau khi lên lại; thêm một benign mỗi giai đoạn. Benign luôn 200/allow và đến origin, attack luôn 403/block/700011. Khi CP chết, ClickHouse và watermark PostgreSQL không tiến, ACK agent không tiến, spool có batch chưa ACK. Sau khởi động lại, agent tự kết nối, spool về 0, không invalid/truncated/drop, watermark tăng và từng Block ID có đúng node, version 1, action block và rule 700011. Chữ ký và hash bundle còn nguyên. Raw socket metric đếm cả policy-counter datagram, không được dùng làm số event chính xác; tính đầy đủ dựa trên 120 ID từ HTTP và dữ liệu ClickHouse.

Đã sửa/thêm: `tests/e2e/control_plane_restart_test.go`; helper ClickHouse trả config cho child process nhưng giữ API cũ và nguyên test sentinel cách ly. Credential chỉ đi qua environment riêng của process test, không kế thừa cấu hình STRATA/Vault bên ngoài và không export vào evidence. Không đổi code production, dependency, interface, policy hay test cũ.

Lệnh chạy thực: dev image `--network host`, Docker CLI/socket và group 988, cpuset 6–10; mount cache Go và private Rust target như [chain M4](m4-real-activation-chain.md). Đặt `STRATA_TEST_COMPILER=/src/target/release/strata-compile`, `STRATA_TEST_NGINX`/`STRATA_TEST_NGINX_MODULE` vào `build/nginx-<version>-asan/objs`, và `STRATA_CP_RESTART_EVIDENCE_DIR` là thư mục mới, rồi:

```bash
go -C tests/e2e test -race -count=1 -timeout 6m -v -run '^TestControlPlaneProcessRestartWithRealNginx$' .
go -C tests/e2e test -race -count=1 -timeout 2m -run '^TestLosslessFixtureIgnoresLegacyAddresses$' .
cd tests/e2e && golangci-lint run ./...
```

Kết quả: **PASS 37,446 s / 37,103 s**, isolation test **PASS 11,048 s**, lint **0 issues**. Parent, CP và agent đều build/chạy `-race`; hai NGINX là ASan/UBSan, không report, LSan tắt. [Output, result và hash](evidence/h6-control-plane-process-restart/) giữ bằng chứng từng lượt; log trong Git chỉ bỏ khoảng trắng cuối dòng, bản gốc còn ở `build/`. Fixture ban đầu sai header IR/mode/healthcheck được sửa theo contract hiện có; giả định socket datagram = event được thay bằng kiểm tra đủ ID, không giảm yêu cầu 120 event.

Giới hạn: một node, một rule, tốc độ thấp tuần tự; không đo tải đồng thời/full pack. Đợt đầu đã ACK hết trước kill; không tiêm crash vào khoảng giữa commit ClickHouse và watermark PostgreSQL, nên 120 row lần này không chứng minh physical exactly-once cho mọi crash. Bundle cài sẵn không phải bằng chứng deploy qua gate; chain replay/4 mắt đã có riêng ở M4. Ca này không thay thế outage 5 phút trước, lỗi panic/corrupt hay diễn tập staging của người vận hành.

Tự review: có lệnh/output cho từng khẳng định; input và output/query đều bounded, exact Block ID được đối chiếu; cleanup process/container do test sở hữu; không credential thật, không thay kiểm tra TLS/chữ ký/RBAC; lint/race đạt. Không chờ hosted CI, không merge/deploy, giữ game day mở cho phạm vi còn thiếu.

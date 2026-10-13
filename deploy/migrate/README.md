# Chuyển lab và staging sang máy khác

Copy repo thôi thì không đủ. Dữ liệu nằm trong Docker volume, mật khẩu nằm trong `.state`, staging chạy từ cây build riêng (`build/staging/<tag>`, đã đổi cổng, có gói signature, có bản sửa giới hạn Vault làm tay trên rc.1), còn khóa release của gói signature nằm ở `~/.strata/keys`. `migrate.sh` gom tất cả những thứ đó.

```bash
deploy/migrate/migrate.sh export /path/to/strata-migrate    # máy cũ
rsync -a /path/to/strata-migrate newhost:/path/to/           # kênh mã hóa
git clone <repo> && git checkout <repo_commit trong manifest> # máy mới
deploy/migrate/migrate.sh import /path/to/strata-migrate     # máy mới, từ gốc repo
```

**Export** dừng từng project trong lúc đọc volume, rồi chạy lại project nào đang chạy. Các volume được chuyển:

- Chuyển: Postgres (control plane, Keycloak), MinIO (bundle), Vault (`vault-data`, `vault-keys`, `vault-signer`: phải đi cùng nhau), `state` (CA, node CA), `identity-node-*`, `bundles*`, Grafana.
- Không chuyển: `run-*`, `shm-*` (socket, tmpfs).
- Chỉ chuyển khi có `--with-events`: `clickhouse`, `victoriametrics`, `spool-*`. Mặc định sự kiện và metrics bắt đầu lại từ trống, ClickHouse tạo lại schema khi khởi động.

Image `strata-*` được lưu kèm. Thêm `--all-images` để lưu mọi image, khi máy mới không kéo được image từ registry. Thư mục export chứa mật khẩu, khóa CA và unseal key của Vault: chuyển qua kênh mã hóa và xóa sau khi xong.

**Import** kiểm `SHA256SUMS` trước. Nó từ chối nếu volume, `.state`, cây staging hoặc khóa đã có sẵn, rồi nạp image, tạo volume giữ nguyên nhãn Compose, chủ sở hữu và quyền. Sau đó nó chạy lại các project đang chạy lúc export (`--up-all` để chạy cả project đang dừng, `--no-up` để không chạy) và chạy `smoke.sh` của từng project.

Lưu ý:

- Chứng chỉ của agent có hạn 24 giờ: import trong vòng 24 giờ sau export, nếu không agent phải enroll lại.
- Cổng chỉ bind vào 127.0.0.1 và issuer OIDC là `127.0.0.1:<cổng>`. Muốn truy cập từ máy khác thì phải đổi cấu hình; script không đổi.
- Máy mới nên cùng kiến trúc (x86_64), vì bundle chứa Hyperscan DB đã biên dịch.

Test: `deploy/migrate/test-migrate.sh` (cần Docker, dùng project giả `strata-migtest`).

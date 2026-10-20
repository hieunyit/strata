# Review đợt A · Compact

Ngày: 21/10/2026. Baseline: `origin/main` tại `2dcc5ff` (sau CP-A06, PR #294).
Nhánh: `codex/cp-a-review`. Phạm vi: kiểm A, sửa lỗi tìm thấy trước khi xét B; không làm B03.

Người dùng xác nhận trong chat: **giữ PostgreSQL** theo `compact-ops-plan.md`, không chuyển
SQLite theo bản đề xuất cũ. Không sửa worktree đang dùng của người khác; review ở worktree riêng.

## Kết luận

**CẦN SỬA trước khi xác nhận A đủ.** Hai lỗi đã tái hiện và sửa trong PR này. Có mã và báo cáo
cho toàn bộ CP-A01, A02, A03, A05–A09; không có A04 vì quyết định giữ PostgreSQL.
Không coi bảng đánh dấu xong là bằng chứng đầy đủ cho mọi tiêu chí Compact Stable.

| Mục | Đối chiếu |
| --- | --- |
| A01 | Có kiểm kê/bất biến và RAM idle. Báo cáo thừa nhận dùng lại số đo ingest/query, chưa có bộ đo Compact đầy đủ; test deploy đồng thời được bổ sung ở A03 |
| A02 | Có YAML, kiểm cấu hình, xuất giá trị hiệu lực và che secret; test `config` chạy lại |
| A03 | Có lease, readiness, deploy tuần tự với timeout; lỗi giành lease theo PID namespace được sửa bên dưới. Giữ thiết kế deploy dưới khóa theo báo cáo A03 |
| A05 | Có init/recover, local mặc định, hash Argon2id và quản lý session; test `setup`, `localauth`, `cmd/server` chạy lại |
| A06 | Có overlay Keycloak, role mapping/clock skew, guard tắt local; test `auth` chạy lại. E2E browser/Keycloak trong báo cáo A06 chưa được chạy lại trong review này |
| A07 | Có filesystem qua `os.Root`, artifact bất biến, prune giữ bản cần dùng, file signer; test `policy`/`store` được kiểm lại trong gate control plane |
| A08 | Có UI embed, routing/security header và ClickHouse degraded; test `webui`, `api`, `ingest` được kiểm lại. Không build lại UI vì không đổi frontend |
| A09 | Có backup mã hóa, manifest, sàn version, compose/installer và restore drill trước đây; lỗi xóa metadata khi restore thất bại được sửa bên dưới |

## 1. Lỗi lease · Cao

`deadHere` coi holder đã chết nếu cùng hostname và PID trùng với PID hiện tại, hoặc không tìm
thấy PID. Container có thể dùng cùng hostname nhưng PID namespace khác, nên cả hai điều kiện
đều không chứng minh holder thực tế đã chết. `TakeOverLease` cho ghi đè lease chưa hết hạn.

Test mới trên PostgreSQL thật trước sửa:

```text
--- FAIL: TestLeaseDoesNotStealAcrossPIDNamespaces
    unexpired holder was not respected: <nil>
```

Sửa: bỏ suy đoán hostname/PID và API takeover sớm; PostgreSQL chỉ cho lấy lease khi đã hết hạn
hoặc được nhả. Test giữ nguyên holder/fencing khi deadline của người chờ hết, rồi cho hết hạn
và xác nhận takeover tăng fencing. Dừng sạch vẫn nhả ngay; crash có thể chờ khoảng 30 giây.
Test cũ kỳ vọng takeover tức thì được thay bằng test cho hợp đồng an toàn này; không bỏ test
keeper gia hạn, phát hiện mất lease hay nhả sạch.

## 2. Lỗi restore · Cao

`runRestore` commit `DROP SCHEMA ...; CREATE SCHEMA ...` trước khi gọi `pg_restore`.
Thiếu executable, dump lỗi hoặc SQL restore lỗi có thể làm mất metadata cũ.

Test mới trước sửa:

```text
--- FAIL: TestRestoreFailurePreservesDatabase
    failed restore destroyed metadata: max version 0,
    error ERROR: relation "bundles" does not exist (SQLSTATE 42P01)
```

Sửa: xuất dump thành SQL trong thư mục tạm 0700, file 0600; sau khi xuất thành công mới chạy
`psql --no-psqlrc --single-transaction --set=ON_ERROR_STOP=1` với reset schema và SQL dump.
Lỗi SQL rollback cả reset; thiếu công cụ không đụng DB. Mật khẩu DB vẫn qua `PGPASSFILE`.
`psql` đã có trong `postgresql-client-17` của image Compact, không thêm dependency Go.

Test giữ bundle version 11 sau lỗi executable; thêm xung đột schema để ép lỗi thực thi SQL
sau reset và xác nhận version 11 vẫn còn. Test round-trip restore cũ vẫn kiểm floor, node,
rollout và phục hồi khóa/artifact.

Giới hạn: transaction trên bảo vệ reset và nạp dump. Migration tiếp theo, chỉnh trạng thái sau
restore và cài file không nằm chung transaction; phải giữ control plane dừng nếu bước sau lỗi.
Cần thêm dung lượng tạm cho SQL đã xuất. Không tuyên bố toàn bộ quy trình restore nguyên tử.

## 3. Kiểm chứng

Môi trường riêng: PostgreSQL 17.11 và ClickHouse 25.8.33, network `strata-compact-review`,
image dev Go 1.26.9 + PostgreSQL client 17, CPU 6–10. Không dùng DSN hay credential thật.
Go chạy `-p 1` để tránh các package test migrate xuống 0 trên cùng DB (lỗi test dùng chung
schema được ghi trong báo cáo A06). Database của regression restore/lease tách riêng.

Regression sau sửa:

```text
--- PASS: TestBackupRestoreInPostgres (57.15s)
--- PASS: TestRestoreFailurePreservesDatabase (23.96s)
--- PASS: TestLeaseDoesNotStealAcrossPIDNamespaces (0.81s)
PASS
ok  github.com/strata/strata/control-plane/cmd/server 83.725s
```

Lint: `golangci-lint run ./...` trong control-plane → exit 0, `0 issues.`

E2E chọn theo phạm vi: `go test -race -count=1 -timeout 8m -run
'Test(FourEyes|MigrationsUpDownOnEmptyDatabase|PolicyEditAndDeploy)$' ./...`:

```text
ok  github.com/strata/strata/tests/e2e 28.121s
?   github.com/strata/strata/tests/e2e/fakecompile [no test files]
```

Gate toàn control plane: `go test -p 1 -race ./...` với PostgreSQL/ClickHouse thật →
exit 0, 19 package có test PASS. Trích output:

```text
ok  github.com/strata/strata/control-plane/cmd/server 94.112s
ok  github.com/strata/strata/control-plane/ingest 27.499s
ok  github.com/strata/strata/control-plane/policy 3.268s
```

Các ca cần compiler/native fixture chưa cấu hình vẫn tuân theo cơ chế skip có sẵn; kết quả
trên không thay nghiệm thu image Compact/browser/native hoặc fault matrix ở §4.
Log cục bộ: `build/review/control-plane-tests.log`, `build/review/e2e-tests.log` (gitignore).

## 4. Chưa đủ bằng chứng Compact Stable

- Bộ đo Compact đầy đủ theo A01: ingest/query/compile/replay, thời gian cài, retention/đĩa.
  Không chạy benchmark trong phiên này theo ràng buộc của `CLAUDE.md`.
- Fault matrix chưa được chứng minh đầy đủ bằng báo cáo: disk full thật, mất PostgreSQL,
  kill giữa build/replay/rollout; test gần đầy của A07 không thay bài diễn tập đầy đĩa thật.
- Nâng PostgreSQL major chưa diễn tập (A09 ghi rõ). Đây là hạn chế vận hành, không phải
  yêu cầu đổi major trong PR sửa lỗi này.
- Chưa chạy lại toàn bộ Compact browser/OIDC/drill bằng image build từ SHA review.
- Lease hiện vẫn không fence từng mutation khi tiến trình treo quá TTL (rủi ro đã ghi A03).

Vì A còn lỗi và thiếu bằng chứng Stable, phiên này ưu tiên sửa A, chưa triển khai
B01/B02/B04/B05. B03 được loại khỏi phạm vi đúng yêu cầu. Không merge hoặc deploy.

## 5. Tự review

1. Điều kiện nghiệm thu: có regression fail trước/pass sau; các khoảng trống Stable ghi ở §4.
2. Đường lỗi: lỗi render/psql được trả về; không xóa DB trước bước có thể lỗi; transaction SQL
   rollback khi gặp lỗi. Các bước sau restore vẫn có giới hạn như §2.
3. Giới hạn: acquire bị chặn bởi context và thời gian chờ hiện có; render/restore bị giới hạn
   bởi context lệnh (6 giờ), SQL dùng file tạm thay vì nạp cả dump vào RAM.
4. Bảo mật: file SQL 0600 trong thư mục 0700; PGPASSFILE giữ nguyên; không sửa quyền/RBAC.
5. Phạm vi: chỉ control-plane lease/backup, test và tài liệu liên quan; không đổi proto,
   OpenAPI, bundle format, frontend hoặc data plane.
6. Lint: `golangci-lint run ./...` → `0 issues.`; `git diff --check` sạch. Không chạy lại Rust,
   C, UI hoặc các Go module không đổi; e2e chọn ba luồng liên quan, không gọi đó là full e2e.

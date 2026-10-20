# Báo cáo CP-A07 · Artifact trên filesystem và file signer mặc định

Ngày: 20/10/2026. Người làm: Claude Code (strata-59). Kế hoạch: `docs/plan/compact-ops-plan.md`
§4 A07.

## 1. Làm gì

| Phần | Ở đâu |
| --- | --- |
| Adapter `policy.FS` (`Put`, `Get`, `Open` có offset, `List`, `Delete`, `FreeBytes`) trên `os.Root`; interface chung `policy.ObjectStore` cho S3 và FS | `control-plane/policy/fsobjects.go` |
| Cờ `-objects-dir` (khóa `bundles.storage.local.path`), loại trừ `-s3-endpoint`; `init` không có `-s3-endpoint` thì ghi `storage.local.path: objects` | `cmd/server/main.go`, `config/config.go`, `setup/setup.go` |
| Deploy: bỏ qua số bản đã có file mà chưa có bản ghi (`policy.FreeVersion`); từ chối trước khi build khi thư mục còn dưới 256 MiB | `policy/deploy.go` |
| Dọn artifact: `policy.Pruner` (bundle theo danh sách giữ từ DB `store.KeptBundles`, mẫu replay theo ngày), GeoIP giữ phiên bản mới và phiên bản vừa thay (`policy.PruneGeoIP`, hook `GeoIPUpdater.PruneOld`); cờ `-objects-keep-bundles` (10), `-objects-sample-days` (7), `-objects-prune-interval` (1h) | `policy/prune.go`, `store/artifacts.go`, `ingest/geoip_update.go` |
| Mẫu replay: khóa đã bị lần chạy trước chiếm (bộ đếm `seq` bắt đầu lại sau restart) thì lấy số kế tiếp | `replay/store.go` |
| `S3.Delete` | `policy/objects.go` |
| e2e chạy trên filesystem mặc định (rollout tới agent thật, four eyes, replay, staging tự động); `STRATA_E2E_OBJECTS=s3` chạy lại trên MinIO; `TestPolicyEditAndDeploy` luôn dùng MinIO | `tests/e2e` |

Ký bundle bằng file đã là mặc định (`-bundle-signer=file`, CP-A05 sinh khóa); A07 không đổi phần
này, chỉ kiểm lại bằng e2e (ký bằng file, không Vault).

## 2. Quyết định khi làm

- **Bất biến, nhưng không cho deploy kẹt.** Kế hoạch đặt bundle là khóa bất biến. Nếu `Put` xong
  mà ghi DB lỗi, lần deploy sau lấy lại đúng số bản đó với nội dung khác (GeoIP hay dải crawler
  mới) và bị từ chối mãi. `FreeVersion` nhảy qua số đã có file, lấy số sau file lớn nhất: không
  ghi đè (giữ bất biến) và cũng che trường hợp DB khôi phục lùi sau artifact (A09) ở mức không
  dùng lại số bản node có thể đã cài. Số bản có thể có khoảng trống; node chỉ cần tăng dần.
  Staging writer (M4) bắt buộc `source + 1` nên không nhảy được: gặp file mồ côi đúng số đó thì
  báo lỗi, lần deploy thường kế tiếp nhảy qua.
- **Manifest GeoIP và `goodbots/<version>.json` ghi đè được** (thêm vào danh sách khóa con trỏ
  `policy.DefaultMutableKeys`). Chúng mang thời điểm tải; một phiên bản tải lại sau phiên bản khác
  (A, B, A) sẽ ghi lại nội dung khác và, nếu bất biến, làm cập nhật hỏng mãi. MMDB vẫn bất biến
  (phiên bản là hash nội dung).
- **Ghi bất biến bằng `link`**, không `rename`: `link` thất bại khi khóa đã có, nên hai người ghi
  cùng lúc không thể đè nhau (test `TestFSConcurrentPuts`). Khóa con trỏ dùng `rename`.
- **Ký tự khóa `[A-Za-z0-9._-]`** thay vì `[a-z0-9._-]` như kế hoạch ghi: id node trong khóa mẫu
  replay có chữ hoa (`replay.nodePattern`). Đoạn rỗng, `.`, `..`, tối đa 16 đoạn, 255 byte mỗi
  đoạn; tiền tố `.strata-tmp-` dành cho file đang ghi.
- **Dọn chỉ chạy với `-objects-dir`**: object store dùng lifecycle rule như trước
  (`docs/spec/replay-sample.md`). Không bao giờ xóa file trên số bản lớn nhất đã ghi trong DB
  (upload chưa kịp ghi DB, hoặc DB khôi phục lùi). Bản ghi trong bảng `bundles` của bundle đã dọn
  vẫn còn (lịch sử); rollback trong Strata là deploy bản mới, không phát lại bundle cũ.
- **Không đưa dung lượng đĩa vào `/readyz`**: control plane gần đầy đĩa vẫn phục vụ được; deploy
  bị từ chối có lỗi rõ. Cảnh báo dung lượng thuộc B05 (trang Sức khỏe, `strata doctor`).

## 3. Lỗi và lỗ hổng đã chặn

| Rủi ro (kế hoạch A07) | Chặn bằng | Test |
| --- | --- | --- |
| Policy tên `..` ghi file ra ngoài thư mục replay | `policy.ValidName` (CP-SEC-02) + kiểm khóa từng đoạn + `os.Root` | `TestFSRefusesEscapes`, `TestStoreKeysAndChecks` |
| Symlink trong thư mục dẫn ra ngoài | `os.Root` từ chối; `List` bỏ qua symlink | `TestFSRefusesEscapes`, `TestFSPutGetOpenList` |
| Crash giữa ghi file và ghi DB: file mồ côi, hoặc file dở | File tạm + `fsync` + `link`/`rename` + `fsync` thư mục, rồi mới ghi DB; mồ côi bị nhảy qua và dọn | `TestDeployOnFilesystemAfterAnUnrecordedUpload`, `TestFreeVersionSkipsStoredBundles` |
| Đầy đĩa giữa lúc ghi bundle | Kiểm ≥ 256 MiB trống trước khi build | `TestDeployRefusedWhenTheDirectoryIsNearlyFull` |
| Mẫu replay đọc được bởi user khác | Thư mục 0700, file 0600 | `TestFSPutGetOpenList` |
| Dọn nhầm bundle node còn cần | Danh sách giữ từ DB (N mới nhất, active và desired của mọi node, rollout RUNNING/PAUSED, staging chưa rollout); đọc số bản lớn nhất trước danh sách giữ | `TestKeptBundlesInPostgres`, `TestPrunerKeepsWhatTheDatabaseNeeds` |
| Con trỏ GeoIP đọc giữa lúc ghi, hoặc trỏ tới bản đã dọn | `rename` nguyên tử; dọn GeoIP chạy trong updater sau khi con trỏ đã đổi, giữ bản mới và bản vừa thay | `TestPruneGeoIPKeepsThePointerAndTwoVersions`, `TestGeoIPUpdateWithFilesystemObjects` |
| Bất biến cho mọi khóa làm hỏng cập nhật GeoIP | Danh sách khóa ghi đè tường minh | `TestFSImmutableAndPointers`, `TestGeoIPUpdateWithFilesystemObjects`, `TestUpdateWithFilesystemObjects` |
| Endpoint tải artifact cho người không đủ quyền | Không thêm endpoint; bundle chỉ qua Fleet mTLS | — |
| Hai control plane ghi cùng thư mục | Lease CP-A03; cảnh báo lúc khởi động nếu thư mục trên NFS | — |
| Mẫu replay mất sau restart (khóa trùng) | Lấy số kế tiếp khi khóa đã có nội dung khác | `TestStoreOnFilesystem` |

## 4. Kiểm

- `make test-go` phần control-plane (vet, `go test -race` kể cả test PostgreSQL với
  `STRATA_TEST_POSTGRES_DSN`, golangci-lint 0 issues): xanh.
- `make e2e-go` hai lần: trên MinIO (exit 0, 689 s) và trên filesystem, mặc định mới (exit 0,
  646 s; vet và golangci-lint 0 issues). Trên filesystem: `TestRolloutToRealAgents` (rollout theo
  wave tới 3 agent thật, node kiểm chữ ký bằng khóa khác từ chối bundle và rollout dừng, abort,
  kill -9 giữa lúc ghi bundle 64 MB rồi tải tiếp), `TestBundleRolloutSurvivesNetworkFaults`,
  `TestNewNodeGetsTheFleetBundle`, `TestFourEyes`, `TestPolicyDraftReplay`; ký bằng file, không
  Vault. Bốn test cần NGINX thật bị SKIP như trên MinIO.
- Lab (20/10, control plane bản này, override thay `-s3-*` bằng `-objects-dir=/objects`, MinIO
  **dừng** trong suốt lúc kiểm): chép 62 bundle từ MinIO sang volume (đường chuyển từ MinIO sang
  filesystem, `mc mirror`); lúc khởi động bộ dọn xóa 48 bundle, giữ 14 (10 mới nhất và bundle
  node đang chạy). Duyệt lại 30 policy (replay gate, như các lần lab trước); `lab-chain` pass
  (bundle 63, 64 qua Fleet tới 2 node NGINX, rollout 17 s); `runbook-drill` pass (ép shadow, deploy
  hỏng rồi rollback bằng bundle 66, tắt/bật module). File 0600, thư mục 0700, chủ `strata`, không
  còn file tạm. Vault vẫn ký trong lab (khóa node tin là khóa Vault); ký bằng file đã kiểm ở e2e.
- Ghi chú: lab trước khi kiểm đang khởi động lại liên tục (94 lần): image schema 26, DB đã ở 27
  (CP-A03). Sau khi kiểm, lab được dựng lại từ `origin/main`.

## 5. Còn lại

- Cảnh báo dung lượng thư mục artifact trên trang Sức khỏe và `strata doctor`: B05.
- Backup/restore thư mục artifact cùng PostgreSQL, và nâng sàn số bản bundle sau khi khôi phục:
  A09.
- Compose Compact không MinIO, không Vault: A09.

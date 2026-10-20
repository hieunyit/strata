# Báo cáo CP-A01 · Kiểm kê và đo nền

Ngày: 20/10/2026. Người làm: Claude Code (strata-59). Main tại `df59b23` (sau #270, #271, #273,
#274). Kế hoạch: `docs/plan/compact-ops-plan.md`.

**Xong khi** (plan): mỗi dữ liệu có owner, nơi lưu, chính sách phục hồi; mỗi bất biến có ít nhất
một test. **Đạt một phần**: bất biến "deploy đồng thời không trùng version" chưa có test (mục 2,
giao cho CP-A03); đo tải ingest/truy vấn dùng số đã có từ báo cáo trước, không chạy lại (mục 3).

## 1. Danh mục dữ liệu

### 1.1 PostgreSQL (28 bảng, migration 0001–0026)

Mọi bảng nằm trong một database; backup bằng `pg_dump` (CP-A09). Cột "Phục hồi" ghi điều cần
lưu ý khi restore.

| Bảng | Nội dung | Owner (package) | Phục hồi |
| --- | --- | --- | --- |
| `connector_groups`, `nodes`, `enrollment_tokens` | Group, node đã enroll (chứng chỉ, trạng thái), token dùng một lần | store, fleet | Node enroll sau thời điểm backup phải enroll lại |
| `policies`, `policy_versions` | Policy và mọi version: spec, trạng thái bốn mắt, subject, replay đã gắn | store, admin | Bất biến bốn mắt có CHECK trong DB |
| `bundles` | Bundle đã ghi: version, sha256, khóa object, `contents`, `input_digest`, `rules_digest` | store, policy | **Sau restore, version bundle tiếp theo phải lớn hơn mọi version node đang chạy** (CP-A09) |
| `rollouts`, `rollout_nodes` | Rollout theo đợt, trạng thái từng node | store, fleet | Rollout đang chạy khi backup cần đánh dấu lại |
| `node_commands` | Lệnh tới node (force shadow, diagnostics, kill switch, replay sync) | store, fleet | Lệnh hết hạn bỏ qua |
| `disabled_rules` | Kill switch theo group | store | Trạng thái mong muốn, đẩy lại khi node kết nối |
| `canary_trips` | Lần canary fallback | store | |
| `replay_sampling` | Tỉ lệ lấy mẫu và **khóa HMAC ẩn danh** mỗi group (bytea rõ) | store | Có khóa: dump DB phải được mã hóa |
| `secrets` | Khóa định danh HMAC của cài đặt (bytea rõ) | policy, replay | Có khóa: dump DB phải được mã hóa |
| `operations` | Hàng đợi replay (long-running operation), kết quả | store, replay | Operation RUNNING lúc backup bị đánh FAILED khi chạy lại |
| `ingest_sequences` | Số thứ tự đã nhận theo node (chống trùng sự kiện) | store, ingest | Restore cũ hơn ClickHouse: có thể nhận trùng một số lô; ClickHouse đọc `FINAL` |
| `event_annotations`, `event_annotation_requests` | Báo FP theo Block ID, khóa chống trùng request | store | |
| `policy_edit_requests` | Khóa chống trùng cho bản nháp từ sự kiện (exception) | store | |
| `rule_annotation_context`, `rule_staging_actions` | Ngữ cảnh rule health; M4 staging theo rule | store | |
| `machine_accounts`, `machine_tokens`, `machine_requests` | Service account, token (chỉ hash), khóa chống trùng | store | |
| `local_users`, `local_sessions` | Tài khoản cục bộ (argon2id), session (chỉ SHA-256) | localauth | Session cũ còn hiệu lực sau restore tới khi hết hạn |
| `audit_log` | Audit, có `subject` từ 0024 | store, api, localauth | Không gọi là chống sửa |
| `role_bindings`, `service_accounts` | Có từ 0001, **không code nào đọc hay ghi** (service account dùng `machine_accounts`; chữ `service_accounts` trong code chỉ là tên tài nguyên trong audit và JSON) | — | Dọn hoặc dùng ở CP-A05 |

### 1.2 ClickHouse

| Bảng | Nội dung | Phục hồi |
| --- | --- | --- |
| `events` | Sự kiện (Block ID, trace, geo, cost) | Mất ClickHouse = mất lịch sử sự kiện, không mất cấu hình; TTL cấu hình được |
| `node_seq` | Watermark ingest phía ClickHouse (M6) | Đi cùng `ingest_sequences` |
| `policy_requests` | Số request theo policy (RV-N-01) | |
| `events_perf_*`, `events_ttl_test` | Chỉ trong test | — |

Schema: `ingest/schema.sql` chạy khi tạo volume, phần sau dùng `Ensure*` lúc khởi động. CP-A08
gom thành migration có số thứ tự.

### 1.3 File và object

| Dữ liệu | Nơi lưu hiện nay | Phục hồi |
| --- | --- | --- |
| Bundle (bất biến) | Object storage `bundles/<version>/…` | Backup cùng DB; không xóa bundle active, desired, N gần nhất |
| Mẫu replay (traffic đã ẩn danh) | Object storage `replay/v1/<policy>/…` | Theo số ngày giữ; dữ liệu nhạy cảm |
| GeoIP MMDB theo phiên bản + con trỏ `geoip/latest.json` (ghi đè) | Object storage | Tải lại được từ nguồn; con trỏ là khóa ghi đè duy nhất hiện có |
| Dải IP crawler (goodbots) | Object storage | Tải lại được |
| M4 staging (bundle dẫn xuất) | Object storage + `bundles` | Như bundle |
| Khóa ký bundle | Lab/staging: Vault transit (`vault-data`); dev: file seed | **Mất khóa = node không nhận bundle mới**; backup bắt buộc (CP-A07, A09) |
| Public key bundle | `/bundles/bundle.pub`, phân phối cho node | |
| PKI: CA, chứng chỉ control plane, CA của node (`/state/pki/*`) | Volume `state` | Mất CA node = enroll lại mọi node |
| Khóa ký replay nháp | RAM, sinh mỗi lần khởi động | Không cần phục hồi |

### 1.4 Trạng thái chỉ nằm trong RAM của control plane

| Trạng thái | Package | Mất khi restart | Hệ quả cho Compact |
| --- | --- | --- | --- |
| Presence: stream `Connect` của từng node | fleet | Có; node kết nối lại | Chỉ bản giữ lease phục vụ Fleet (CP-A03) |
| Canary monitor: mẫu theo node, nhóm, nguồn | fleet | Có; tích lũy lại | Như trên |
| Bộ ghi request theo policy (hiệu giữa heartbeat) | fleet | Mất một khoảng | Như trên |
| Chống trùng ingest (cache) | ingest | Đọc lại từ `ingest_sequences` | |
| Collector mẫu replay (đệm tới 1.000 dòng / 5 phút) | replay | **Mẫu chưa ghi bị mất** (đã ghi trong code) | Chấp nhận, best effort |
| Cache GeoIP, goodbots | ingest, goodbots | Nạp lại từ object storage | |
| Proxy tin cậy (phân giải lại mỗi 30 s) | localauth | Phân giải lại | |
| Staging worker (tick) | rulehealth | Chạy lại tick sau | |

Ingest chỉ ack cho agent **sau** khi lô đã ghi (`IngestService.ProcessBatch` qua `WithIngestBatch`),
nên không có sự kiện nào chỉ nằm trong RAM của control plane; phần chờ nằm ở spool của agent.

## 2. Bất biến và test đang giữ

| Bất biến | Test | Ghi chú |
| --- | --- | --- |
| Sửa policy bằng etag cũ thất bại | e2e `TestPolicyEditAndDeploy` | |
| Bốn mắt theo subject, CHECK trong DB | `TestFourEyes`, `TestFourEyesInPostgres` | |
| Định danh local/OIDC/service account tách biệt | `TestVerifier_SubjectNamespace`, `TestOIDCSubjectNamespaceMigration` | CP-SEC-01 |
| Duyệt cần replay DONE, gắn đúng replay đã xem | `TestApproveNeedsADoneReplay`, `TestApproveReplayPinRESTInPostgres` | |
| Deploy chỉ lấy bản đã duyệt; chốt replay chỉ kiểm cái thay đổi | `TestFourEyes`, `TestReplayGateUsesApprovedOperation`, `TestReplayGateChecksOnlyWhatChanged` | CP-FIX-01 |
| Enrollment token dùng một lần, có hạn | `TestEnroll_TokenOnceAndNotExpired`, `TestFleetEnrollConnectRevoke` | |
| `request_id` không tạo trùng | `TestPolicyDraftAndReplayAtomicInPostgres`, `TestMachineConcurrentTokenRetryCommitsOnce`, `TestStagingRecordAtomicRetryAndPersistence`, test annotation | |
| Audit commit/rollback cùng thay đổi | test annotation, machine credential, staging (atomic retry) | Chưa có test chung cho mọi đường ghi |
| Tên policy an toàn cho đường dẫn | `TestValidName`, `TestStoreKeysAndChecks` | CP-SEC-02 |
| **Deploy đồng thời không trùng version, không giữ khóa khi build** | **Chưa có** | CP-A03 thêm test cùng lúc sửa `WithBundleLock` |

## 3. Đo nền

Đo trên lab (`strata-lab`, main `90b06a0` + #271, CPU 6–10), `docker stats --no-stream` lúc idle,
20/10/2026. Một lần chụp, CPU tức thời dao động; dùng số RAM để so.

| Dịch vụ | RAM idle | Trong Compact |
| --- | --- | --- |
| ClickHouse | 670 MiB | Giữ |
| PostgreSQL | 43 MiB | Giữ |
| Control plane | 20 MiB | Giữ (UI nhúng thêm vài MiB) |
| **Tổng phần giữ** | **≈ 733 MiB** | |
| Keycloak | 729 MiB | Tùy chọn |
| VictoriaMetrics | 210 MiB | Tùy chọn |
| Grafana | 134 MiB | Tùy chọn |
| MinIO | 70 MiB | Tùy chọn |
| Vault | 36 MiB | Tùy chọn |
| UI (nginx) | 14 MiB | Bỏ (nhúng) |
| vmalert | 11 MiB | Tùy chọn |
| **Tổng phần thành tùy chọn** | **≈ 1.204 MiB** | |
| Data plane: 2 NGINX + 2 agent | 35 MiB | Không đổi |

Dung lượng volume sau nhiều ngày dùng lab: ClickHouse 1,14 GB, Grafana 133 MB, PostgreSQL 82 MB,
spool node tới 1,2 MB, MinIO 3,5 MB (bundle lab nhỏ vì dùng `rules.yaml` ví dụ).

Số đã có từ báo cáo trước, không chạy lại (CLAUDE.md: phiên này không chạy benchmark):

- Replay: corpus 4.281 mẫu khoảng 370 ms với rule lab; 1 triệu mẫu 182,7–213,5 s (W11);
  compile gói CRS PL1 khoảng 35 s một lần (`TestRealReplay`).
- Tra Block ID trên 20 triệu dòng: p99 96 ms; 8 tìm kiếm dưới 2 s (`m6-annotated-read-benchmark.md`).
- Ingest qua restart control plane: 120/120 Block ID, spool tăng rồi về 0
  (`h6-control-plane-process-restart.md`).

Nhận xét cho các bước sau:

1. Bỏ Keycloak khỏi mặc định là phần tiết kiệm lớn nhất (729 MiB), sau ClickHouse.
2. ClickHouse idle 670 MiB là phần lớn nhất còn lại; CP-A08/A09 nên có cấu hình bộ nhớ cho máy
   nhỏ (`max_server_memory_usage`, cache) và ghi giới hạn đo được.
3. Cài từ đầu và đĩa sau 7 ngày chưa đo được trên compose Compact (chưa có); đo ở CP-A09.

## 4. Mâu thuẫn tài liệu còn lại

| Chỗ | Mâu thuẫn | Đề xuất |
| --- | --- | --- |
| `AGENTS.md` §0 | Con trỏ "Tuần hiện tại: 8", cập nhật 12/10 | PO đổi; bảng CP và các tracker là nguồn trạng thái |
| `docs/plan/plan.md` | Lộ trình 22 tuần không có kế hoạch Compact | Đã thêm dòng trỏ tới `compact-ops-plan.md` (PR này) |
| `nginx-module.md` bảng control plane | Ghi Message bus (NATS), PostgreSQL HA bằng Patroni | Đã có ghi chú Compact (#267); giữ bảng cho bản nhiều control plane |
| `role_bindings`, `service_accounts` | Bảng có từ 0001, không code dùng; RBAC lấy vai trò từ token | CP-A05 quyết: dùng cho tài khoản cục bộ hoặc xóa |

## 5. Việc chuyển cho các bước sau

- CP-A03: test deploy đồng thời; sửa `WithBundleLock`; lease một control plane (presence, canary,
  bộ đếm theo policy nằm trong RAM).
- CP-A05: quyết `role_bindings`/`service_accounts`.
- CP-A07: khóa con trỏ duy nhất hiện có là `geoip/latest.json`.
- CP-A08: migration ClickHouse có số thứ tự; cấu hình bộ nhớ ClickHouse cho máy nhỏ.
- CP-A09: dump PostgreSQL chứa khóa (`secrets`, `replay_sampling`) nên gói backup luôn mã hóa;
  version bundle không đi lùi sau restore.

# Control file và định dạng bundle v1 (đặc tả byte)

Bổ sung chi tiết cho mục "Bundle & hot reload" của `nginx-module.md`; tài liệu đó không cố định layout byte. Mọi số nguyên là little-endian.

## Control file (`strata_control_file`, mặc định `/run/strata/control`)

File đúng 4.096 byte, nằm trên tmpfs. Chỉ `strata-agent` được ghi; mỗi worker NGINX mmap file này (`PROT_READ`, `MAP_SHARED`) một lần lúc khởi động và từ đó chỉ đọc bộ nhớ.

| Offset | Kiểu | Trường |
| --- | --- | --- |
| 0 | `u8[8]` | magic `STRCTL1\0` |
| 8 | `u32` | phiên bản layout = 1 |
| 12 | `u32` | dự phòng, 0 |
| 16 | `u64` | **generation** (seqlock: lẻ = đang ghi, chẵn = ổn định) |
| 24 | `u64` | phiên bản bundle (thông tin; phiên bản có hiệu lực là trong header bundle đã ký) |
| 32 | `u8[32]` | sha256 của file bundle (agent kiểm; worker không kiểm, worker kiểm chữ ký) |
| 64 | `u16` | độ dài tên file, 1..255 |
| 66 | `u8[256]` | tên file bundle trong `strata_bundle_dir`, chỉ gồm `[A-Za-z0-9._-]`, không phải `.` hay `..` |
| 322 | `u16` | dự phòng, đệm 0 |
| 324 | `u32` | **cờ force-shadow** (bit 0: `1 << 0` = mọi policy bị ép shadow) |
| 328 | `u32` | số policy bị ép shadow (`num_policies`, 0..32) |
| 332 | `u32` | đệm căn lề 8 byte, 0 |
| 336 | `u8[32][56]` | danh sách tên policy bị ép shadow (mỗi tên tối đa 55 byte `[a-z0-9._-]`, đệm NUL) |
| 2128 | `u32` | số rule bị tắt khẩn cấp (`n`, 0..480; W12-G1-02) |
| 2132 | `u32` | dự phòng, 0 |
| 2136 | `u32[480]` | Rule ID bị tắt, `n` mục đầu có nghĩa |
| 4056 | `u32` | tỉ lệ lấy mẫu replay, basis point 0..10.000 (0 = tắt; W12-N-01) |
| 4060 | `u32` | dự phòng, 0 |
| 4064 | `u8[16]` | id khóa ẩn danh của mẫu (`[A-Za-z0-9._-]`, đệm NUL) |
| 4080 | — | dự phòng, 0 (16 byte) |

**Agent ghi (seqlock)**, luôn **tại chỗ** trên cùng inode:

1. Ghi generation = G+1 (lẻ).
2. Ghi các trường còn lại.
3. Ghi generation = G+2 (chẵn).

Không bao giờ thay control file bằng `rename`: worker đang map inode cũ và sẽ không thấy bản mới. Tạo file lần đầu (generation chẵn) rồi chỉ cập nhật tại chỗ.

Ba loại ghi, cùng seqlock, nối tiếp nhau trong agent: **đổi bundle** chỉ ghi offset 0..15 và 24..321 (khối force-shadow giữ nguyên); **force-shadow** chỉ ghi offset 324..2127; **tắt rule** (W12-G1-02) chỉ ghi offset 2128..4055; **lấy mẫu replay** (W12-N-01) chỉ ghi offset 4056..4079. Agent giữ danh sách rule bị tắt trong `disabled-rules.json` của `--bundle-dir` (qua được agent khởi động lại); rule chỉ bật lại khi có lệnh `EnableRules`. Agent giữ hạn chót force-shadow trong `force-shadow.json` của `--bundle-dir` (qua được agent khởi động lại, không kéo dài hạn), và mỗi giây ghi lại khối nếu khác với các hạn còn chạy: khi hạn qua, và khi control file được tạo sau lệnh (chưa có bundle lúc nhận lệnh).

**Khóa của mẫu replay** (W12-N-01) không nằm trong control file (không đủ chỗ): agent ghi `replay.key` trong `strata_bundle_dir` (ghi file tạm rồi `rename`, quyền 0640 như bundle) **trước** khi ghi khối 4056: `"SRK1"`, id khóa (16 byte, đệm NUL), khóa 32 byte. Worker chỉ đọc file này khi khối đổi hoặc engine đổi (timer, không trên request), kiểm id trong file khớp id trong control file, đưa khóa cho libstrata (`strata_engine_set_replay`) rồi xóa khỏi stack; không khớp thì tắt lấy mẫu và ghi cảnh báo. Tỉ lệ 0 thì agent xóa `replay.key`. Agent không lưu cài đặt này: control plane gửi lại khi node kết nối; trước đó, sau khi agent khởi động lại, file giữ nguyên.

**Worker đọc**: đọc generation g1; nếu lẻ thì bỏ qua lượt này; copy các trường; đọc lại generation g2; chỉ dùng khi g1 == g2. Generation chẵn khác lần trước → nạp bundle mới.

## Bundle v1 (`bundle-<version>.sbn` trong `strata_bundle_dir`)

| Offset | Nội dung |
| --- | --- |
| 0 | header 64 byte: magic `STRBNDL\0`, `u16` format = 1, `u16` flags (bit 0: ROLLBACK), `u32` số policy, `u64` version, `u64` created_at (ms), `u64` offset section, `u64` độ dài section, 16 byte dự phòng = 0 |
| 64 | bảng policy: mỗi policy 64 byte = tên 56 byte (`[a-z0-9._-]`, 1..55 ký tự, đệm NUL) + `u8` mode (0 = shadow, 1 = enforce) + `u8` oversize (0 = pass, 1 = block: body request lớn hơn phần connector inspect, Rule 100020) + `u8` response (cờ lớp response: bit 0 allowed codes, bit 1 lỗi DB, bit 2 data guard CCCD, bit 3 data guard JWT, bit 4 data guard số thẻ thanh toán (PAN, P-01 §1; libstrata trước đó từ chối bundle có bit này); bit khác phải = 0; bundle cũ có byte này = 0 nghĩa là tắt hết) + `u16` canary (W11-R-01: phần client bị enforce, tính theo basis point 1..9.999; 0 = không canary, mọi request theo mode; khác 0 chỉ khi mode = enforce) + `u8` signatures (RV-S-01, gói signature của policy: 0 = shadow, mặc định và là giá trị của mọi bundle cũ, 1 = off, 2 = enforce; khác phải từ chối) + `u8` sự kiện (byte 62, RV-G2-01: bit 0–1 độ dài tối đa đoạn input trong sự kiện `max_snippet_size`, 0 = 128 byte, 1 = 2 KB, 2 = 4 KB; bit 2 = policy có cài đặt privacy trong section 9; bit 3 = `fail_on_findings: block` (#98: hết CPU budget khi request đã có finding thì fail closed; libstrata trước đó từ chối bundle có bit này); bit 4 = policy có exception trong section 10 (engine trước M2 từ chối bit này); bit 5 = policy có staging từng rule trong section 11 (engine trước M4 từ chối bit này); bit khác và giá trị 3 của bit 0–1 phải từ chối; libstrata trước đó từ chối byte này khác 0, nên nâng module trên mọi node trước) + `u8` max_args (byte 63, #28: số tham số policy kiểm, query rồi body, tính theo bội số 4, 1..255 = 4..1.020; 0 = mặc định của engine 1.024, giá trị của mọi bundle cũ; request nhiều hơn đi theo oversize, Rule 100021; libstrata trước đó từ chối byte này khác 0) |
| bội số 4.096 | thư mục section: `u32` số section, `u32` 0, rồi mỗi mục `u32` kind, `u32` 0, `u64` offset, `u64` độ dài; sau đó từng section ở offset bội số 4.096, tăng dần, không chồng lấn |
| cuối − 64 | chữ ký Ed25519 trên toàn bộ byte phía trước |

Kind của section (kind lạ bị bỏ qua nhưng vẫn kiểm biên): 1 `RULES`, 2 `CONDITIONS`, 3 `TARGETS`, 4 `LISTS`, 5 `STRINGS`, 6 `BLOCK_PAGE` (template HTML mặc định + support contact), 7 `HYPERSCAN` (database regex tiền biên dịch), 8 `HYPERSCAN_BLOCK` (bản block mode của section 7, tùy chọn, #27), 9 `PRIVACY` (cài đặt privacy của policy, P-01 §1), 10 `EXCEPTIONS` (exception có scope chính xác và hạn dùng, bắt buộc bit 4/byte 62 ở mỗi policy liên quan), 11 `STAGING` (overlay log-only từng managed request rule, bắt buộc bit 5/byte 62). Layout byte từng bản ghi nằm ở đầu `engine/src/rules.rs`. Byte cờ của bản ghi `RULES`: bit 0 = điều kiện OR, bit 1 = `block_alone` (W08-R-02, trước đó dự phòng), bit 2 = gói signature (RV-S-01: compiler đặt cho rule có `metadata.source` là `sigma`, `et-open`, `crawler-user-agents`), bit khác phải = 0. Rule gói signature trong policy `signatures: shadow` vẫn chạy và được báo (Event ID `EVT-`, action `log`), nhưng điểm của chúng tính riêng và không bao giờ chặn; `off` bỏ qua chúng; `enforce` coi như rule thường. Libstrata trước RV-S-01 từ chối bundle có bit 2: nâng module trước. Libstrata trước W08 từ chối bundle có bit 1, nên **nâng module trên mọi node trước** khi deploy bundle có rule `block_alone`. Tương tự, libstrata trước W11-R-01 từ chối bundle có canary khác 0 (byte dự phòng khác 0): nâng module trên mọi node trước khi deploy policy có `canary_percent`. Rollout tự dừng ở node đầu tiên còn bản cũ (FAILED "bad bundle layout"), các node khác giữ bundle đang chạy; mã của layer, stage, variable, transformation, operator theo đúng thứ tự enum trong `docs/spec/ir.schema.json`. Bundle do `strata-compile` tạo (`engine/compiler`).

**W17-R-01, operator SSTI:** `detect_ssti` được nối cuối danh mục operator ở mã 18;
18 mã cũ (0–17) giữ nguyên. Operator không có `value`, hỗ trợ transform/negate như
`detect_sqli` và dùng cùng giới hạn input/budget của evaluator. Bundle chứa operator
mới bị engine cũ từ chối lúc nạp; nâng module trước khi phát bundle đó. Không tự
bật rule trong policy. Không thêm section hoặc thay layout bản ghi.


### Section 11 `STAGING` (M4)

Codec `SSG1`: magic 4 byte, số entry `u32`, rồi cặp `(policy_index u32, rule_id u32)`, little-endian, tăng dần theo policy/rule. Tối đa 4.096 entry toàn bundle, 16/policy, không trùng; không có cấu hình thì không có section. Tập policy có entry phải khớp chính xác bit 5/byte 62; thiếu section/flag, dữ liệu vượt giới hạn hoặc Rule ID không trỏ duy nhất tới managed request rule có điểm 0..1000 thì từ chối (bỏ điểm âm có thể tăng mức chặn). Engine cũ từ chối bit bắt buộc, không âm thầm enforce rule đã staging. Không đổi C ABI.

Staging giữ detection, match và event log; chỉ loại điểm và `block_alone` của rule được chọn khỏi quyết định enforce ở đúng policy. Rule khác và protocol/data guard không bị giảm cấp. `would_block` vẫn phản ánh tổng điểm giả định nếu chưa staging. Staged-only finding không kích hoạt `fail_on_findings`; finding enforce còn lại vẫn theo policy cũ. Overlay là dữ liệu bất biến của bundle ký, không tự hết hạn hoặc tự bật lại rule. Codec/runtime chưa tự cấp quyền phát hành: writer phải kiểm opt-in đã replay/duyệt, phiên bản và input digest; Compiler nhận `staged_rules` trong input policy JSON/YAML và đặt bit bắt buộc; public policy API không nhận trường effective này. Adapter/automatic writer được nối ở các bước sau.

### Section 10 `EXCEPTIONS` (M2)

Codec `SEX1` được mô tả ở [policy-exceptions.md](../spec/policy-exceptions.md). Tối đa 4.096 entry/bundle, 128/policy. Mỗi entry mang policy index, managed Rule ID, method, Host, canonical path, field và Unix expiry. Tập policy có entry phải đúng bằng tập bật bit 4/byte 62; thiếu flag/section, Rule ID ngoài managed, scope không hợp lệ hoặc dữ liệu vượt giới hạn đều bị từ chối. Engine cũ từ chối bit bắt buộc; cần nâng mọi engine trước khi dùng exception. Không đổi C ABI.

Exception chỉ bỏ value của đúng field trước khi evaluate đúng managed rule, không bỏ toàn rule hoặc route. Scope cần một Host duy nhất; header/Host không phân biệt ASCII case, argument name/path phân biệt case. Alias do decoder tạo được quy về field gốc; tên argument thật có đuôi `|base64` là field khác. Thời gian 0/không biết hoặc đã tới expiry không kích hoạt exception; expiry áp dụng khi engine vẫn giữ bundle.

Policy version giữ metadata ID/reason/source Block ID; chúng không vào section runtime. `POST /v1/exceptions:fromBlockId` chỉ tạo DRAFT và xếp replay atomic với audit/request_id. Method/Host/path/policy lấy từ event; client chọn rõ managed Rule ID và field không mơ hồ, TTL 60 giây..30 ngày. Submit/approve/deploy dùng luồng policy và proof replay hiện có; không có approve RAM riêng. Thu hồi bằng version mới loại entry khỏi `PolicySpec.exceptions`, rồi replay/duyệt/deploy; bản thu hồi còn nháp không làm thay đổi node đang chạy.

### Section 9 `PRIVACY` (P-01 §1)

Cài đặt `privacy` của các policy: tên field không bao giờ giữ snippet (thêm vào danh sách có sẵn) và pattern bị che bằng `*` trong snippet, giá trị header, User-Agent, Referer (sau các mặc che có sẵn: CCCD, JWT, số thẻ).

- `u32` số mục, `u32` số chuỗi, 32 byte khóa identity (toàn 0 = không có khóa); mỗi mục 24 byte: `u32` chỉ số policy, `u32` chuỗi đầu và `u32` số chuỗi của `sensitive_fields`, `u32` chuỗi đầu và `u32` số chuỗi của `mask_patterns`, `u32` cờ (bit 0: `identity: hmac`; bit khác phải = 0; có bit 0 mà khóa toàn 0 thì từ chối bundle); mỗi chuỗi 8 byte: `u32` offset, `u32` độ dài trong blob theo sau; rồi blob (UTF-8).
- Giới hạn: tối đa 64 tên (1–64 ký tự in được, không khoảng trắng) và 16 pattern (1–256 byte, crate `regex`, thời gian tuyến tính, giới hạn kích thước sau compile 1 MB, không khớp chuỗi rỗng) mỗi policy. Engine kiểm lại toàn bộ lúc nạp và compile pattern một lần.
- Tập policy có bit privacy trong bảng policy phải đúng bằng tập policy có mục trong section; sai thì từ chối bundle.
- `identity: hmac`: engine thay identity của sự kiện bằng `hmac:` + hex 16 byte đầu của HMAC-SHA256(khóa, identity), trước khi encode; giá trị gốc không rời node. Khóa là **của cài đặt**, giống nhau ở mọi bundle, nên cùng một client luôn ra cùng một giá trị qua các lần deploy (tra cứu, thống kê vẫn được). Nguồn khóa: biến `STRATA_IDENTITY_HMAC_KEY` của control plane (64 hex, từ secret manager), nếu không có thì control plane sinh một lần và giữ trong PostgreSQL (bảng `secrets`, migration 0008); `strata-compile --identity-key <file>`. Khóa chỉ nằm trong bundle (node, MinIO), không bao giờ tới ClickHouse, API hay UI. Ai đọc được bucket bundle hoặc file bundle thì có khóa và có thể dò identity từ các giá trị đoán trước (email, số điện thoại): `identity: hmac` bảo vệ trước người xem sự kiện, không trước người quản trị hạ tầng; quyền đọc bucket phải giới hạn như quyền với khóa ký. Đổi khóa đổi mọi giá trị: làm có chủ đích, ghi vào báo cáo vận hành.

### Section 7 `HYPERSCAN` (`SHS1` và `SHS2`)

Section `HYPERSCAN` chứa database Hyperscan đã biên dịch và bảng ánh xạ pattern ID về condition index.

- **Header 56 byte**:
  - `u8[4]`: magic `SHS1` (chế độ block) hoặc `SHS2` (chế độ stream `HS_MODE_STREAM`). `strata-compile` mặc định sinh `SHS2`. Engine tương thích ngược và đọc cả `SHS1` lẫn `SHS2`.
  - `u32`: số lượng pattern (`n_patterns` / số mục trong `cond_index`).
  - `u8[32]`: chuỗi phiên bản Hyperscan / Chimera (đệm NUL, so khớp với `strata_hs::version()`).
  - `u32`: `db_off` (offset của ảnh database trong section, bắt buộc là bội số của 4.096 byte).
  - `u32`: `db_len` (độ dài ảnh database tính bằng byte).
  - `u8[8]`: dự phòng, đệm 0.
- **Bảng `cond_index`**: mảng `n_patterns` phần tử `u32`, từ offset 56 tới `56 + n_patterns * 4`.
- **Đệm căn lề**: các byte 0 từ cuối bảng `cond_index` tới `db_off`.
- **Ảnh database Hyperscan**: từ offset `db_off` tới `db_off + db_len`, được ánh xạ trực tiếp và kiểm tra tính hợp lệ bằng `hs_validate_database` mà không cần cấp phát thêm bộ nhớ.

### Section 8 `HYPERSCAN_BLOCK` (tùy chọn, #27)

Cùng layout với section 7, nhưng chỉ nhận magic `SHS1` (block mode). Section chứa **đúng các pattern của section 7**, biên dịch ở block mode: cùng `n_patterns`, cùng chuỗi phiên bản Hyperscan, và bảng `cond_index` giống từng byte với bảng của section 7. Ảnh database nằm ở `db_off` riêng của section 8.

- **Sinh ra**: mặc định (PO 14/10/2026), bởi `strata-compile` và vì vậy cả `strata-rules release` lẫn control plane; `strata-compile --no-hs-block` (hoặc `strata-rules release --hs-block=false`) bỏ section. Với gói signature đầy đủ, bundle tăng từ 12,8 MB lên 21,7 MB. Giới hạn: control plane ký qua Vault bundle tối đa 24 MiB (`MaxVaultMessage`, vì Vault nhận request tối đa 32 MiB và bundle đi dạng base64), còn dư khoảng 3,5 MB; gói lớn hơn thì phải nâng `max_request_size` của Vault cùng giới hạn đó, hoặc dùng `--no-hs-block`.
- **Engine đọc** (từ bản có section này): giá trị đã transform dài tối đa `BLOCK_SCAN_MAX` = 2.048 byte được scan bằng database của section 8; giá trị dài hơn vẫn scan bằng database stream của section 7, theo từng đoạn và kiểm budget giữa các đoạn. Kết quả hai database cho cùng một giá trị là như nhau. Block mode bỏ được chi phí reset stream và xử lý cuối dữ liệu, vốn lớn hơn chính lần scan với giá trị ngắn. Hai database dùng chung scratch của mỗi thread.
- **Kiểm lúc nạp**: section 8 chỉ hợp lệ khi có section 7 ở stream mode (`SHS2`), cùng phiên bản và cùng `cond_index`. Ảnh database được kiểm CRC như section 7. Sai bất kỳ điều nào thì **từ chối bundle** (bundle đã ký mà không khớp nghĩa là compiler lỗi).
- **Tương thích**: engine cũ bỏ qua kind 8 và chạy với section 7 như trước, nên không cần nâng module trước khi deploy bundle có section này. Bundle không có section 8 thì engine mới chạy như cũ.


libstrata kiểm chữ ký **trước** rồi mới đọc layout, và kiểm biên mọi trường (mọi bản ghi rule, điều kiện, target, list) kể cả khi chữ ký đúng, một lần lúc nạp; sau đó đọc tại chỗ, không copy. Mode của policy là dữ liệu đã ký: `strata_engine_policy` đọc nó tại chỗ trong vùng mmap. Location đặt `strata_request_body_mode stream` mà policy là enforce thì `nginx -t` (và `nginx -s reload`) lỗi; nếu policy chuyển sang enforce qua hot reload, worker ghi cảnh báo và location vẫn chạy shadow. File bundle đã công bố không bao giờ được sửa tại chỗ (xem `docs/poc/hyperscan-mmap.md`): agent ghi file tạm → `fsync` → `rename` sang tên mới theo phiên bản, rồi mới cập nhật control file; xóa bundle cũ chỉ bằng `unlink`.

## Xoay khóa ký bundle

Node tin **một hoặc hai** public key Ed25519: file `strata_bundle_pubkey` của NGINX và `bundle.pub` của agent dài 32 hoặc 64 byte (hai khóa nối nhau). Bundle được nhận khi chữ ký đúng với một trong các khóa đó. Kiểm tra chạy trong thread pool, nên khóa thứ hai chỉ tốn thêm một lần kiểm khi khóa đầu không khớp.

Khóa mới được phát tới node **ngoài băng** (config management, như bản cài agent), không qua control plane. Nếu control plane đẩy được danh sách khóa tin cậy, thì ai chiếm control plane cũng tự cài khóa của mình được, và việc giữ khóa trong KMS không còn ý nghĩa.

Quy trình (Vault transit, khóa `strata-bundles` đang ở phiên bản N):

1. Ghim phiên bản đang ký: control plane chạy với `-vault-transit-key-version=N`.
2. `vault write -f transit/keys/strata-bundles/rotate` tạo phiên bản N+1. Lấy public key của nó: `vault read -format=json transit/keys/strata-bundles`, trường `keys["N+1"].public_key` (base64 → 32 byte).
3. Phát `bundle.pub` = khóa N ‖ khóa N+1 (64 byte) tới mọi node (NGINX `nginx -s reload`, khởi động lại agent), và cho control plane (`-bundle-pubkey`, để node enroll sau đó cũng nhận cả hai).
4. Kiểm: `POST /v1/nodes/{id}:collectDiagnostics` của từng node, `bundle.trusted_keys` (sha256 rút gọn) phải có khóa N+1.
5. Chuyển ký: `-vault-transit-key-version=N+1`, khởi động lại control plane, deploy; rollout ACTIVE trên mọi node.
6. Bỏ khóa cũ: `bundle.pub` = khóa N+1 (32 byte) trên node và control plane; sau đó có thể đặt `min_encryption_version` của khóa trong Vault.

Một node chưa nhận khóa mới ở bước 3 sẽ từ chối bundle ở bước 5. Rollout dừng ở node đó (FAILED, "signature does not verify") và các node khác giữ bundle cũ.

## Quy tắc nạp trong worker

- Timer mỗi `strata_bundle_check` (cộng jitter ngẫu nhiên tới 25%) chỉ đọc generation trong bộ nhớ.
- Generation đổi → gửi việc sang thread pool `default`: `open`, `fstat`, `mmap(PROT_READ, MAP_SHARED)`, `madvise(MADV_WILLNEED)`, `strata_engine_map` (kiểm chữ ký), so phiên bản. Mỗi worker chỉ có tối đa một việc nạp đang chạy. Bên trong libstrata, `strata_engine_map` dựng engine trên **một luồng nạp riêng** của tiến trình (`engine/ffi/src/loader.rs`), không trên luồng thread pool gọi nó. Lý do: mỗi luồng có arena malloc riêng, và gói đầy đủ để lại khoảng 18 MB trong arena của mỗi luồng từng nạp nó (soak 14/10/2026, `docs/reports/w09-q-02.md` §3).
- Từ chối khi: chữ ký hoặc layout sai, hoặc version **nhỏ hơn hoặc bằng** bản đang chạy mà bundle không có cờ ROLLBACK. Bản bị từ chối được `munmap` ngay trong thread; worker giữ engine cũ và không thử lại cho tới khi generation đổi.
- Đổi engine trong event loop. Request đang chạy giữ tham chiếu tới bundle cũ; bundle cũ được `strata_engine_release` + `munmap` (trong thread pool) khi tham chiếu cuối được trả.
- Control file chưa có lúc worker khởi động: worker thử mở lại ở mỗi chu kỳ timer (trong thread pool) và chạy theo `strata_fail_mode` cho tới khi có bundle.
- Master đọc control file khi đọc cấu hình và mmap bundle hiện hành; worker thừa hưởng qua `fork`. Chữ ký sai → `nginx -t` lỗi; chưa có control file hoặc bundle → cảnh báo, chạy theo fail mode.

## Metrics file (mặc định `/run/strata/metrics`)

Bổ sung cho đoạn "Metrics" của mục "Trang chặn, Block ID & sự kiện" trong `nginx-module.md`. `strata-agent` không attach được vào shared memory zone của NGINX (zone tạo bằng anonymous mmap), nên bộ đếm nằm trong một file trên tmpfs mà module tạo và agent chỉ đọc. Phần module ghi file thuộc W07-N-01; W06-G1-01 cài đặt phía agent theo layout này.

**Header 64 byte**

| Offset | Kiểu | Trường |
| --- | --- | --- |
| 0 | `u8[8]` | magic `STRMET1\0` |
| 8 | `u32` | phiên bản layout = 1 |
| 12 | `u32` | số slot = số worker, 1..1.024 |
| 16 | `u32` | kích thước slot (byte), bội số của 64, ≥ 8 × số bộ đếm |
| 20 | `u32` | số bộ đếm mỗi slot, ≥ 21 (module từ W11-N-01 ghi 24, từ W12-G2-01 ghi 50 trong slot 448 byte) |
| 24 | `u64` | thời điểm tạo file (ms); đổi khi file được tạo lại |
| 32 | `u8[16]` | phiên bản NGINX (`NGINX_VERSION`, đệm NUL), W07-F-01 |
| 48 | `u8[12]` | phiên bản module (đệm NUL) |
| 60 | `u32` | `STRATA_ABI_VERSION` của module |

Agent gửi ba trường phiên bản trong `Hello` (`Connector.proxy_version`, `module_version`, `abi_version`) và mở lại luồng khi chúng đổi (NGINX khởi động sau agent, hoặc được nâng cấp). File của module cũ có 0 ở đó: agent báo rỗng.

Slot của worker `i` (`ngx_worker`) nằm ở offset `64 + i × kích thước slot`. Kích thước file đúng bằng `64 + số slot × kích thước slot`, tối đa 16 MB. Mỗi bộ đếm là `u64` căn 8 byte. **Chỉ worker sở hữu slot ghi slot đó**, bằng một lệnh ghi 64 bit, nên không cần khóa; agent đọc từng bộ đếm bằng atomic load. Worker được respawn dùng lại slot cũ và đếm tiếp.

| Chỉ số | Bộ đếm |
| --- | --- |
| 0 | pid của worker (0 = slot chưa dùng) |
| 1 | phiên bản bundle đang chạy (gauge) |
| 2..5 | số request theo action: allow, log, challenge, block |
| 6 | byte body đã inspect |
| 7, 8 | số lần áp fail mode: open (cho qua), closed (503) |
| 9 | số sự kiện bị bỏ vì event socket đầy (`strata_events_dropped`) |
| 10 | số lần vượt CPU budget (`strata_budget_exceeded`) |
| 11 | tổng thời gian engine (ns) |
| 12..20 | histogram thời gian engine, mỗi bucket đếm riêng (không cộng dồn), cận trên: 50 µs, 100 µs, 200 µs, 500 µs, 1 ms, 2 ms, 5 ms, 10 ms, +Inf |
| 21 | trạng thái circuit breaker của worker (gauge): 0 closed, 1 open, 2 half-open (W11-N-01) |
| 22 | số lần breaker mở |
| 23 | số request chạy chế độ giảm cấp |
| 24..36 | nhóm **canary** (policy có `canary_percent`, client trong nhóm: enforce; cờ verdict `STRATA_VF_CANARY`), W12-G2-01: 24 request, 25 bị chặn, 26 ghi log, 27 upstream trả 5xx (trạng thái của upstream cuối), 28..36 histogram thời gian request (từ lúc đọc request tới khi xong, ms), mỗi bucket đếm riêng, cận trên 5, 10, 25, 50, 100, 250, 500, 1000, +Inf |
| 37..49 | nhóm **shadow** của policy canary (client ngoài nhóm, `STRATA_VF_CANARY_SHADOW`), cùng thứ tự như 24..36 |

Bộ đếm mới chỉ được thêm vào cuối slot (tăng số bộ đếm, không đổi phiên bản layout); agent bỏ qua bộ đếm nó không biết.

**Tạo file**: master tạo file khi đọc cấu hình: ghi file tạm, `ftruncate`, ghi header, `rename` sang tên chính thức, rồi mmap `MAP_SHARED`. Worker thừa hưởng vùng map qua `fork`. Khi reload, master tạo file mới theo cùng cách. Worker cũ vẫn ghi vào inode cũ cho tới khi thoát, và bộ đếm bắt đầu lại từ 0; Prometheus coi đó là counter reset. Khác với control file, ở đây được dùng `rename`, vì agent mở lại file theo đường dẫn ở mỗi lần scrape.

**Agent đọc**: mỗi lần scrape, agent mở file, `fstat`, kiểm magic, phiên bản, số slot, kích thước slot, số bộ đếm và kích thước file, rồi mmap `PROT_READ` và cộng các slot có pid khác 0. File sai layout được coi là không có dữ liệu (`strata_metrics_file_up 0`); agent không bao giờ tin các giá trị trong file là đúng định dạng.

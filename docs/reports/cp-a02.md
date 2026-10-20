# Báo cáo CP-A02 · Một file cấu hình

Ngày: 20/10/2026. Người làm: Claude Code (strata-59). Kế hoạch: `docs/plan/compact-ops-plan.md`
§4 A02.

## 1. Cách làm

Không viết lại phần đọc cấu hình: 57 cờ của control plane vẫn là nơi duy nhất parse và kiểm giá
trị. File YAML chỉ là một nguồn đặt các cờ đó.

| Phần | Ở đâu |
| --- | --- |
| Cấu trúc file `version: 1` theo nhóm `server`, `database`, `auth`, `events`, `bundles`, `replay`, `rollouts`, `geoip`, `good_bots`; mỗi khóa có tag `flag` hoặc `env` | `control-plane/config/config.go` |
| Mẫu có chú thích | `control-plane/config/example.yaml` |
| `-config` / `STRATA_CONFIG`; `config validate`, `config show` | `control-plane/cmd/server/main.go` |

Thứ tự ưu tiên: cờ truyền tường minh (`flag.Visit`) > biến môi trường (secret) > file > mặc định.

## 2. Quyết định khi làm

- **Secret chỉ đọc từ file.** Không có khóa nào chứa giá trị secret; khóa `*_file` nạp nội dung
  file vào đúng biến môi trường mà code đã đọc. File secret: không symlink (`O_NOFOLLOW`), không
  cho nhóm/người khác đọc, tối đa 64 KiB, không rỗng; bỏ một dấu xuống dòng cuối.
- **Ngoài phạm vi giai đoạn này:** đổi cấu hình khi đang chạy (mọi khóa cần restart), và khóa cho
  backend chưa có (`bundles.storage.local`, `auth.local` mặc định bật): CP-A05, A07 thêm.

## 3. Lỗi và lỗ hổng đã chặn (theo kế hoạch)

| Rủi ro | Chặn bằng |
| --- | --- |
| Khóa gõ sai bị bỏ qua | Decoder `KnownFields`; test |
| Cờ mới quên khóa | `TestKeysCoverTheFlags` đọc `main.go`, đối chiếu `Keys()` |
| Lộ secret qua `config show`, log, thông báo lỗi | Secret không bao giờ là giá trị cờ; `Effective` chỉ in `<redacted>` và nguồn; thông báo lỗi chỉ có đường dẫn; test kiểm không có chuỗi secret |
| File secret đọc được bởi người khác, symlink | Kiểm quyền và `O_NOFOLLOW`; test |
| Duration không đơn vị (`30` = 30 ns) | Kiểu `Duration` từ chối số trần; test |
| Đường dẫn tương đối hiểu khác nhau giữa systemd và tay | Tính từ thư mục của file; test |
| Tổ hợp backend sai | `signer.type` vault kèm `key_file`, `in_memory` kèm ClickHouse: từ chối |

## 4. Test

| Test | Kết quả |
| --- | --- |
| `TestKeysCoverTheFlags`: mọi khóa trỏ tới cờ có thật, mọi cờ (trừ `-config`) có khóa | PASS |
| `TestExampleLoadsAndApplies`: mẫu nạp được; cờ tường minh giữ; đường dẫn tuyệt đối hóa; danh sách nối dấu phẩy; nguồn đúng; `Effective` không lộ secret | PASS |
| `TestRefusals`: thiếu/sai version, khóa lạ, duration trần hoặc sai, signer sai, tổ hợp sai, secret viết thẳng | PASS |
| `TestSecretFiles`: nạp vào môi trường; quyền 644, rỗng, symlink, không tồn tại bị từ chối mà không lộ nội dung; biến đã đặt thắng | PASS |
| Thử tay: `config validate` báo file secret thiếu và duration trần, mã thoát 1 | Đúng |

Cổng kiểm đầy đủ và lab: chạy chung với CP-A03 (nhánh này nối tiếp nó), ghi ở `cp-a03.md` §5.

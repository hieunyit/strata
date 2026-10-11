# W05-S-01 · W06-S-01 · Nhập CRS, pack protocol, go-ftw qua libstrata

11/10/2026 · Claude Code (đợt gộp nhánh, mọi nhiệm vụ do Claude Code làm) · Review: L2 (công cụ), L3 cho phần engine và IR

Chạy lại (trong dev image, `deploy/dev/run.sh <lệnh>`):

- `make crs-import` → `rules/crs/*.yaml`, `docs/crs-import-report.md`
- `make test-rules` → mẫu của rule file, báo cáo FP/recall, pack protocol 0 FP
- `make test-crs-ftw` → `docs/crs-ftw-report.md`, lỗi nếu một nhóm injection dưới 90%
- `cargo test --workspace`, `make test` và `make test-nginx-asan` trên 1.30.5 và 1.31.6

## Kết luận theo dòng "Xong khi"

| Nhiệm vụ | Tiêu chí | Kết quả |
| --- | --- | --- |
| W05-S-01 | Báo cáo tỉ lệ rule CRS nhập tự động | **Đạt**: `docs/crs-import-report.md`; 136 / 392 rule của CRS 4.25.2; của 159 rule phát hiện PL1, 136 nhập được (86%); mỗi rule bỏ ra có lý do |
| W05-S-01 | Mỗi rule protocol có mẫu khớp/không khớp | **Đạt**: 40 rule `rules/protocol/100101–100140`, `strata-rules test` pass hết |
| W05-S-01 | FP bằng 0 trên corpus benign | **Đạt** cho pack protocol (0 / 2.000, kiểm trong `make test-rules`). Rule CRS PL1 khớp 8,35% request benign (930120, 942100), xem "Khác biệt đã biết" |
| W06-S-01 | go-ftw của nhóm 930, 931, 932, 933, 941, 942, 944 pass tối thiểu 90% | **Đạt**: 94,2 / 100 / 100 / 99,7 / 99,6 / 100 / 96,0% số test của rule PL1 (`docs/crs-ftw-report.md`) |
| W06-S-01 | Danh sách rule chưa nhập được kèm lý do | **Đạt**: `docs/crs-import-report.md` |

Cách đo go-ftw: test của CRS (`corpus/crs-ftw`, 4.778 / 4.950 test chuyển được; phần còn lại ở `docs/crs-ftw-unconverted.md`) chạy qua `strata-eval`, đúng thứ tự gọi của connector. Mỗi rule biên dịch riêng (engine dừng đánh giá khi đã chặn, còn go-ftw tìm rule trong log của CRS đầy đủ). Mẫu số là mọi test của rule PL1 trong nhóm; test của rule không nhập được hoặc engine chưa chạy được tính là thất bại. Test của rule PL2+ không tính (PL2 là W17).

## Đã sửa trong engine trên đường đi

| Vấn đề | Sửa |
| --- | --- |
| `negate` áp sau khi gộp mọi giá trị: header vắng mặt + `!@rx` thì khớp, nên CRS 920170 chặn mọi request benign (100% FP) | Phủ định theo từng giá trị như ModSecurity; target không có giá trị không bao giờ khớp; IR ghi rõ |
| Toán tử số bỏ qua transformation | So trên giá trị đã biến đổi; thêm transformation `length` |
| Regex Hyperscan không nhận (932230, 932235, 932250, 932260 quá lớn) | Compiler để ngoài DB, engine chạy bằng crate `regex` (thời gian tuyến tính), cùng nghĩa với Hyperscan (byte, `\x{bc}` là byte) |
| Rule chain dùng `MATCHED_VARS` | Target `matched_vars`: giá trị (đã biến đổi) mà điều kiện trước khớp |
| Body multipart, JSON, XML không được đọc | Parser lặp, có giới hạn: multipart → `args_post`, `files`, `files_names`; JSON → `args` (`json.a.0`); XML → `xml`, `xml_attributes` (không mở rộng DTD) |
| `multiMatch` | `multi_match` trên điều kiện, ghi vào trường dự trữ của bản ghi điều kiện (bundle cũ giữ nghĩa) |

Thay đổi interface chung, đều là **thêm vào cuối** (mã cũ giữ nghĩa, bundle cũ chạy như trước): IR thêm target `matched_vars`, `request_line`, `query_string`, `xml`, `xml_attributes`; transformation `length`; trường `multi_match`; mô tả ngữ nghĩa `negate`. Định dạng bundle: `reserved u32` của bản ghi điều kiện thành `flags u32` (bit 0 `multi_match`). Định dạng test của rule file: thêm `protocol`, request target dạng tuyệt đối và `*`. `strata.h` không đổi.

## Khác biệt đã biết với CRS trên ModSecurity

- `request_body` luôn là body thô kể cả với XML/JSON/multipart, nên 24 test `no_match` của 944 (tên phần tử, thuộc tính XML) thất bại. Giữ để rule của tổ chức trên `request_body` không bị mù với API XML/JSON.
- Request có `%00` bị kiểm tra dựng sẵn 100013 chặn trước khi rule CRS giai đoạn body chạy (5 test).
- 941180-7: `document.cookie` trong `REQUEST_FILENAME` khớp, upstream mong không khớp.
- FP của CRS PL1 trên corpus benign: 930120 với `C:/Program Files`, 942100 với `50% off -- today only` (thư viện libinjection C gốc cho cùng kết quả, `make libinjection-diff`). Xử lý bằng exclusion của policy.

## Duyệt và kiểm chứng thêm (11/10, chiều)

- Duyệt rule: `rules/reviews/2026-10-11-protocol-and-crs.md`. Sửa 7 rule protocol; sửa importer để rule điều khiển `skip:N` của CRS (920539 tắt 920540 với body JSON) thành điều kiện, qua target mới `body_processor`; runner go-ftw thêm Content-Length như go-ftw (nhóm 920 hết test thất bại).
- Fuzz 1 giờ hai target mới (`engine/fuzz/run.sh 3600 bodies body_eval`): 0 crash; `bodies` 56,6 triệu lần, `body_eval` 3,83 triệu lần; RSS đỉnh 33–36 MB.
- Valgrind 1.30.5 và 1.31.6: 0 báo cáo (xem `w06-response-layer-tokenizer.md`). Test::Nginx và ASan + UBSan pass trên cả hai bản với engine mới.
- Lab dựng lại với engine mới: `lab-smoke`, `e2e-lab` (deploy → rollout → chặn trong 4–5 giây) và `e2e-go` đều pass.

## Còn lại
- Recall trên corpus tấn công (`make test-rules`): command-injection 95%, path-traversal 86%, SQLi 72%, XSS 53% số payload có rule khớp; phần thiếu chủ yếu thuộc PL2+ (W17).

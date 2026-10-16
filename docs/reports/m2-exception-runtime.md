Nhiệm vụ: M2 · runtime exception theo field

Engine đọc EXCEPTIONS kind 10, policy bit 4/byte 62 bắt buộc; từ chối thiếu flag/section, policy mismatch và Rule ID không tồn tại/ngoài managed. Scope cần Host duy nhất, method/path chính xác, đúng policy và chưa hết hạn. Chỉ bỏ value của field thuộc đúng Rule ID trước khi evaluate; không bỏ cả rule. Argument name giữ case, header không phân biệt ASCII case. Chỉ alias do decoder tạo mới được quy về tên gốc; parameter thật có đuôi |base64 không bị nhầm. Lọc value kiểm budget hợp tác như đường hiện có. Không đổi mặc định body/budget/fail mode/oversize/max_args.

C ABI giữ nguyên. Test C ABI mới map bundle ký thật, chạy 8 transaction cho exception argument/header, case header và payload ở field khác: 1 test PASS, 0 fail. Shared fixture không mock engine hay detector. Clippy workspace all-targets/all-features sạch; bộ workspace đã chạy và bộ kiểm chứng HTTP/sanitizer có báo cáo riêng ở bước validation tiếp theo. Không thêm dependency hoặc unsafe ngoài test FFI.

Compiler YAML/JSON và API chưa tạo được artifact exception; đây là hỗ trợ runtime trước khi nối phần đó. Chưa kích hoạt exception từ UI/control plane. Scope/expiry/compatibility và phép thử HTTP bổ sung nằm trong bước validation kế tiếp; M2 chưa hoàn tất toàn luồng. Spec cập nhật ở docs/spec/policy-exceptions.md. Không merge/deploy, không chờ hosted CI.

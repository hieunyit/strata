M5 / UI review · Đề xuất gắn quyết định duyệt với replay đã xem
Trạng thái: người dùng đã duyệt ngày 18/10/2026 (UTC+7): thêm optional `expected_replay_id` theo đề xuất. PR client này chưa sửa proto/OpenAPI/backend; contract được triển khai ở PR kế tiếp.

Hiện `ApprovePolicyRequest` chỉ nhận policy ID, version và comment (`proto/strata/admin/v1/policy.proto`). `policyAdmin.decide` lấy replay DONE mới nhất rồi lưu ID đó vào approval. API đã gắn approval với một replay bền vững, nhưng không biết người duyệt vừa xem replay nào. Nếu UI hiển thị A, một lần chạy B hoàn tất trước khi POST approve tới, API có thể duyệt và gắn B trong khi người dùng đang nhìn A. Không thể loại TOCTOU này chỉ bằng thêm một GET trước POST.

Đề xuất tương thích ngược:

- Thêm `string expected_replay_id = 4` vào `ApprovePolicyRequest`, mô tả và sinh lại OpenAPI/client. Không đổi bundle, C ABI, quyền hay default policy.
- UI luôn gửi ID của report DONE đang hiển thị; không có report hợp lệ thì không cho duyệt. Không fallback sang approve không ID khi server từ chối.
- API từ chối nếu expected ID không phải replay DONE mới nhất của đúng policy/version. Kiểm tra lại ở transaction quyết định, trong lúc giữ lock version, để không có race trước commit. Tận dụng `Audit.ReplayOperation` và `approved_replay_id` hiện có, không cần thêm bảng.
- Serialize queue replay và quyết định trên cùng version hoặc chứng minh khóa FK hiện có bảo đảm điểm tuyến tính; test concurrency phải kiểm chứng. Không chỉ so sánh ID ngoài transaction.
- Caller cũ không gửi field vẫn dùng contract cũ; UI mới luôn pin. Sau approval, replay mới chạy thêm không tự thay `approved_replay_id`, không tự thu hồi/bật lại enforcement.

Test phải có: xem A rồi B chạy xong → yêu cầu pin A bị từ chối và không state/audit mới; pin B → approval trỏ đúng B; sai policy/version, PENDING/FAILED/nonexistent bị từ chối; concurrent queue/approve không duyệt replay khác; bốn mắt/RBAC và deploy gate cũ giữ nguyên; caller cũ được kiểm tương thích. Chạy Go -race với PostgreSQL, lint, buf lint/generate và UI type/test/build.

File dự kiến: proto admin policy, generated Go/gateway/OpenAPI/TypeScript, admin policy handler, Store decision/operation lock, test API/PG/client và báo cáo. Thay đổi được tách khỏi phần UI đọc queue/replay để review; không merge/deploy hay chạy hosted CI. Dự kiến thêm một PR API/transaction và một PR UI sử dụng contract, khoảng 1–2 phiên làm việc cùng kiểm chứng; không cần dịch vụ mới.

Lý do đã xin xác nhận: AGENTS.md mục 5 giới hạn đổi interface chung khi nhiệm vụ ghi rõ. Đề xuất này thêm trường proto/OpenAPI ngoài phần giao diện; người dùng đã xác nhận phạm vi trên, không cần hỏi lại khi triển khai đúng đề xuất.

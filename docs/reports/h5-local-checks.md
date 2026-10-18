Nhiệm vụ: H5 · sửa kiểm tra và khả năng chạy cục bộ

Thay đổi:
- Test rollout chặn object bundle 3 sau đúng 1 MiB trước khi kill agent. Khi restart phải thực sự fetch từ offset này; giữ nguyên kiểm chữ ký, wave order và trạng thái control file. Không tăng timeout để che race loopback tải hết file.
- `signatures-import` dừng ngay khi fetch lỗi, không chạy importer với `--src` rỗng. Regression test FAIL trên Makefile cũ, PASS trên bản sửa.
- Fetch giữ archive theo SHA-256, kiểm hash mỗi lần, giải nén lại từ archive đã kiểm. Cache offline qua `STRATA_SIGNATURE_CACHE`; cache sai bị từ chối kể cả có `.verified`. Stdout chỉ dành cho đường dẫn kết quả.
- CI cache archive theo hash sources.lock và chạy test integrity/failure propagation. Không kích hoạt hosted CI trong lần làm này.
- CI gọi `make check-c-lines` (ngân sách 4.000 đã có trong Makefile/CLAUDE.md), bỏ giá trị 3.000 bị lệch. Không xóa hay tắt test.

Bằng chứng cục bộ:
```
python3 tools/strata-import-signatures/test-fetch.py
Ran 5 tests in 0.602s
OK
make check-c-lines
C connector: 3002 real lines, budget 4000
go test -race -run TestRolloutToRealAgents -count=1 -v
--- PASS: TestRolloutToRealAgents (66.10s)
PASS
ok github.com/strata/strata/tests/e2e 67.571s
```
E2E dùng PostgreSQL/MinIO riêng do test tạo, agent thật, mTLS và signature như test cũ. Chạy trong dev image có mount Docker CLI/socket và network host để tới các port lab loopback; không chạm container staging/prod/lab dùng chung. `build/h5-make-red.log` chứng minh Makefile cũ vẫn gọi importer khi fetch lỗi. Bash syntax và diff whitespace sạch.

Chưa hoàn tất đối với nguồn ET lịch sử: cache mới không khôi phục được archive gốc đã bị xóa và upstream đã đổi nội dung. Cache miss của hash ET cũ vẫn từ chối đúng checksum. Cần lấy archive đúng hash từ mirror/backup, hoặc cập nhật nguồn và duyệt diff rule trong PR riêng. Không tự bỏ kiểm hash hay nâng nguồn để giả báo CI xanh. Chưa chạy lại toàn bộ pipeline phát hành; không chờ hosted CI theo yêu cầu PO.

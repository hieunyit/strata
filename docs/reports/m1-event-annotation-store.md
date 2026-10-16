Nhiệm vụ: M1 · lưu annotation false positive (phần PostgreSQL)

Thay đổi: migration 0016 và store annotation riêng, không tạo bản sao sự kiện ClickHouse. Annotation lưu reason, actor/subject, UTC time, etag. Audit cùng transaction; sửa cần etag; request_id theo subject giữ response để retry vẫn idempotent kể cả sau lần sửa khác. Search đọc tối đa 200 annotation trong một query. Không thêm dependency.

Kiểm chứng trên PostgreSQL 17.11 lab riêng:
```
go test -race ./store -run TestEventAnnotationsInPostgres -v
--- PASS: TestEventAnnotationsInPostgres (0.50s)
PASS
ok github.com/strata/strata/control-plane/store 1.593s
```
Test bao gồm: đọc lại qua Store mới; retry; request_id dùng khác nội dung; etag thiếu/cũ; audit before/after; audit lỗi rollback; 12 ghi đồng thời chỉ một thành công; reason rỗng/quá dài; page quá giới hạn. Không tắt test có sẵn. Lint chạy trong cùng lệnh, output `build/m1-storage.log`.

Giới hạn: đây là lớp lưu trữ; PR kế tiếp nối endpoint và overlay GET/search. Annotation/request records giữ bền vững, chưa có chính sách TTL; cần chốt retention theo yêu cầu lưu vết. Không đổi chính sách CPU budget. Không đợi hosted CI theo chỉ dẫn PO.

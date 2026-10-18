# M4 — Snapshot rule của sự kiện FP trong PostgreSQL

Ngày 2026-10-17. Nhánh `codex/m4-fp-rule-context`, base `d49c822` (PR #169). Phần nền dữ liệu, chưa bật health/quarantine tự động.

## Thay đổi

Khi đánh dấu FP, API lấy policy, timestamp và các rule từ `GetEvent`; đưa snapshot nội bộ vào cùng transaction lưu annotation/audit/request_id. Client không được đưa `event_context` vào JSON. Migration 0019 lưu tối đa 64 rule/event, dedupe ID và bỏ ID 0 của prefilter. Audit chứa snapshot nguồn; `Audit.RuleContext` không nhận qua JSON.

`RuleFalsePositiveEvents` đọc SQL theo Rule ID, policy tùy chọn và cửa sổ nửa mở tối đa 24 giờ. Mỗi sự kiện chỉ được đếm một lần, dù danh sách rule có ID lặp; join annotation hiện có. Không đưa luồng event vào slice RAM và không gọi callback/thay đổi trạng thái khi đọc. Query dùng index rule/policy/time.

`PruneRuleAnnotationContext` xóa tối đa 1.000 snapshot cũ/lượt, index `(event_at,block_id)` và `FOR UPDATE SKIP LOCKED`. Annotation, audit và request-id record vẫn được giữ độc lập. Worker định kỳ chưa được nối trong PR này; có hàm dọn hữu hạn không có nghĩa retention đã tự chạy.

## Kiểm chứng thật

Test API trước khi nối snapshot vào annotation: **FAIL**, rule 942100/policy default-api có count **0**, yêu cầu **1**. Sau sửa, cùng test PASS: snapshot lấy từ server, tồn tại khi tạo store mới; retry vẫn giữ snapshot gốc ngay cả khi upstream duplicate đổi rule claims; client tự gửi context nhận 400.

Test PostgreSQL mới còn kiểm:

- Hạ schema xuống 18, ghi annotation cũ, lên migration mới: annotation cũ còn nguyên. Không backfill rule không có nguồn.
- Dedupe ID, ID UInt32 lớn nhất, policy khác, biên cuối loại trừ; retry không đổi snapshot; etag edit cập nhật snapshot.
- Audit lỗi rollback metadata; dọn từng lô 1 dòng, giữ annotation; từ chối rule 0, window quá 24 giờ, context quá 64 rule và batch retention quá 1.000.

Lượt chọn test thực với PostgreSQL 17.11, `-race` (trước khi thêm assertion migration 18→19 và SKIP LOCKED): API **2,472 s**, store **2,418 s**, mọi test PASS. Lượt full trên mã cuối bao gồm cả migration/retention mới:

```text
go test -race -count=1 ./...
ok .../api   8.756s
ok .../db    1.061s
ok .../fleet 30.040s
ok .../store 9.253s
(mọi package PASS)
golangci-lint run
0 issues.
```

CPU 6–13, không `-short`, không sửa test/load deadline, không chờ CI. Log [evidence](evidence/m4-fp-rule-context/) có red, chọn test và full. Mỗi test dùng database tạm riêng, không đụng staging/production hoặc DB lab dùng chung.

## Giới hạn

Số đếm là **sự kiện được người vận hành đánh dấu FP có chứa rule**, không chứng minh riêng rule đó gây chặn nhầm khi sự kiện chứa nhiều rule. Không dùng số này tự hạ rule, không coi dữ liệu thiếu snapshot là FP=0 có độ tin cậy đầy đủ. Không thay request/response công khai của annotation; RBAC, etag, idempotency và audit cũ vẫn có test PASS.

M4 còn aggregation match/cost có phạm vi, endpoint health chỉ đọc, retention worker/evaluator/outbox, và lệnh chỉ ghi log thật ở engine. Prototype health RAM chưa nhập vào main. Chưa đặt ngưỡng tự quarantine production. Không thay hai quyết định “chỉ đo” của body CPU/rate saturation.

# Virtual patch: chuẩn bị, replay, duyệt và triển khai trên lab

Áp dụng cho API hiện tại. Thực hiện trên lab độc lập; việc vận hành staging/production do người có trách nhiệm thực hiện theo runbook của môi trường đó. Mốc 24 giờ là mục tiêu ứng phó, không phải kết quả diễn tập đã đạt.

## 1. Xác định bản vá và bằng chứng

Ghi ticket/CVE, phiên bản ứng dụng bị ảnh hưởng, backend parser, route/method/header/field chứa payload và oracle chứng minh tác động trên ứng dụng lab. HTTP 200 đơn thuần không chứng minh khai thác thành công. Ghi cả request tấn công và các request hợp lệ gần giống nó.

Rule có ID 700000–799999, một file theo `rules/schema/rule.schema.json`: top-level `rule` và `tests`; layer `managed`; severity chữ thường; `metadata.source` thuộc enum trong IR, có license/author/owner/review_by. Không dùng layer `virtual-patch` hay source `strata-security` vì schema không hỗ trợ chúng.

[Fixture 700011](examples/700011-example-vpatch.yaml) chỉ khớp canary header của lab, không phải bản vá cho một CVE. Fixture ở ngoài `rules/`, không tự được đóng vào pack đang sử dụng. Khi viết bản vá thật, thay matcher và mẫu bằng vector cụ thể, kiểm ID không trùng, rồi người luồng S review từng rule theo AGENTS.md.

## 2. Kiểm syntax và hành vi rule

Từ repo root, trong dev image:

```bash
deploy/dev/run.sh make rules-tools
deploy/dev/run.sh sh -ec 'cd tools/strata-rules; go run . lint --repo ../.. ../../docs/runbook/examples'
deploy/dev/run.sh sh -ec 'cd tools/strata-rules; go run . test --repo ../.. ../../docs/runbook/examples'
```

Đối với rule thật, thay thư mục fixture bằng thư mục chứa bản vá. `test` nhận đường dẫn positional, không có cờ `--rule`. Lưu output số pass/fail/skipped; skipped không phải pass. Thêm benign corpus của ứng dụng, chạy `report --repo ../.. --rules <rules-dir> --corpus <corpus-dir>` và regression toàn pack. `corpus benign` là lệnh sinh corpus, không phải phép chứng minh 0 FP; không có cờ `corpus --benign`.

## 3. Đóng gói, cost và đầu vào compiler

Ví dụ đóng **fixture lab** bằng khóa test có sẵn:

```bash
deploy/dev/run.sh sh -ec 'cd tools/strata-rules; go run . release --repo ../.. --rules ../../docs/runbook/examples --version lab-example --bundle-version 1 --key ../../connectors/nginx/t/fixtures/test.key --out ../../build/virtual-patch-example'
deploy/dev/run.sh sh -ec 'cd tools/strata-rules; go run . verify --pub ../../connectors/nginx/t/fixtures/bundle.pub ../../build/virtual-patch-example'
```

Đọc `cost.json` và manifest trong `build/virtual-patch-example`. Đây chỉ là package một rule, không thay thế full pack. Không coi cost unit là microsecond hay tự áp ngưỡng 500. Đo bundle đầy đủ với cấu hình `-cost-budget` thực tế; nếu không đạt thì giữ chặn phát hành và xử lý chi phí. `strata-pattern-cost` nhận các subcommand `prepare/time/minus/...` với IR/corpus, không nhận trực tiếp một file authoring YAML như một phép kiểm cost.

Control plane lab compile từ danh sách file của `-rules` (compose lab hiện dùng `/opt/strata/rules.yaml`). Người vận hành phải đưa IR mới vào artifact đó bằng quy trình build lab; chỉ thêm YAML vào Git hoặc gọi `:deploy` không tự thay file rule trong image. Ghi SHA của IR/compiler/image/bundle, policy version và cấu hình trước khi replay. Sau khi thay đầu vào, replay lại; gate provenance từ chối dùng kết quả cũ.

## 4. Replay trước khi approve và deploy

Các biến `CP`, `POLICY`, `VERSION` trỏ đến lab/version cần duyệt; token đến từ phiên đăng nhập lab của hai subject khác nhau. Không ghi token vào repo hoặc output báo cáo. Lấy version từ API, không suy đoán luôn là 2.

```bash
# Submit version cụ thể. Endpoint không có /versions/{n}:submit.
curl -fsS -X POST "$CP/v1/policies/$POLICY:submit" \
  -H "Authorization: Bearer $OPERATOR_TOKEN" -H 'Content-Type: application/json' \
  -d "{\"version\":$VERSION}"

# Replay version đó; field sample_size không tồn tại.
curl -fsS -X POST "$CP/v1/policies/$POLICY:replay" \
  -H "Authorization: Bearer $OPERATOR_TOKEN" -H 'Content-Type: application/json' \
  -d "{\"version\":$VERSION}"

# Dùng operation.id từ response; đọc đến DONE hoặc FAILED.
curl -fsS "$CP/v1/operations/$OPERATION_ID" \
  -H "Authorization: Bearer $APPROVER_TOKEN"
```

Người duyệt xem riêng traffic/corpus, newly_blocked/newly_allowed, rule/route bị ảnh hưởng và số mẫu. FAILED, 0 mẫu hoặc thiếu dữ liệu đại diện không đủ căn cứ phát hành. Kiểm benign FP và attack theo oracle ứng dụng; không lấy tỷ lệ tổng để che một route bị hỏng. Với gate provenance, operation/digest được bind tại approval; replay mới sau approval không tự được duyệt thay operation cũ.

```bash
# Người duyệt khác subject của drafter/submitter.
curl -fsS -X POST "$CP/v1/policies/$POLICY:approve" \
  -H "Authorization: Bearer $APPROVER_TOKEN" -H 'Content-Type: application/json' \
  -d "{\"version\":$VERSION,\"comment\":\"Reviewed lab replay and application regression\"}"

# Chỉ sau approval: compile, ký, verify, lưu và khởi động rollout.
curl -fsS -X POST "$CP/v1/policies/$POLICY:deploy" \
  -H "Authorization: Bearer $OPERATOR_TOKEN" -H 'Content-Type: application/json' -d '{}'
```

Nếu rules/compiler/baseline/tập policy thay đổi, tạo version mới, replay và duyệt lại đúng digest. Với nhiều policy trong bundle, tất cả phải có bằng chứng phù hợp với tập đầu vào được deploy. Không cập nhật riêng IR sau bước replay rồi dùng approval cũ.

## 5. Quan sát và rollback khẩn cấp

Theo `rollout_id`, node phải ACTIVE ở bundle đúng SHA; gửi ca tấn công/benign qua NGINX lab và tra Event ID. Đối chiếu `inspection`, `would_block`, fail mode và error: 400/503 không tự đồng nghĩa signature TP. Chỉ ghi SLA/kết quả khi có timestamp và output thật của lượt diễn tập.

Nếu rule gây sự cố, emergency kill switch nhận **rule_id ở path**, group_id trong body:

```bash
curl -fsS -X POST "$CP/v1/rules/700011:emergencyDisable" \
  -H "Authorization: Bearer $OPERATOR_TOKEN" -H 'Content-Type: application/json' \
  -d '{"group_id":"example-edge","reason":"Lab rollback exercise"}'

# Sau khi xác nhận sửa và duyệt phục hồi:
curl -fsS -X POST "$CP/v1/rules/700011:enable" \
  -H "Authorization: Bearer $OPERATOR_TOKEN" -H 'Content-Type: application/json' \
  -d '{"group_id":"example-edge","reason":"Reviewed recovery"}'
```

Kill switch vô hiệu rule; không gọi nó là chuyển staging chỉ ghi log. Kiểm command được agent/worker áp dụng, audit và request thực sau thao tác. Không dùng endpoint `/groups/.../rules/...:disable` vì API không có.

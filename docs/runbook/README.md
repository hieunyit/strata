# Runbook Strata

Runbook cho người trực vận hành Strata (module NGINX, `strata-agent`, control plane).
Mỗi cảnh báo trong `deploy/monitoring/alerts.yml` có `runbook_url` trỏ vào một mục
dưới đây.

- Dashboard (Grafana, thư mục "Strata"): **Strata module**, **Strata agent**,
  **Strata control plane**.
- Cảnh báo: vmalert (lab `127.0.0.1:18880`, staging `127.0.0.1:28880`), danh sách
  cảnh báo trong Grafana, và chuỗi `ALERTS{alertstate="firing"}` trong VictoriaMetrics.
- Cài node: `docs/runbook/install.md`.
- Các thao tác can thiệp (tắt module, ép shadow, rollback bundle) có lệnh và kết quả
  mong đợi ở các mục cùng tên. `tests/e2e/runbook-drill.sh [lab|staging]` chạy đúng các
  lệnh đó và đo thời gian; biên bản diễn tập nằm trong `docs/reports/w10-n-01.md`.

Quy ước trong lệnh: `$CP` là URL REST của control plane, `$TOKEN` là access token của
một người có vai trò `operator` (ép shadow) hoặc `admin` (deploy).

## Module không gửi metrics

Cảnh báo `StrataModuleMetricsMissing`: agent không đọc được file metrics của NGINX
trong 5 phút.

1. `systemctl status nginx` (hoặc container NGINX): NGINX có chạy không?
2. `nginx -T | grep -E 'load_module|strata_metrics_file'`: module có được nạp không, và
   đường dẫn có trùng `--metrics-file` của agent không?
3. Log lỗi của NGINX: tìm `strata:`.

Request vẫn đi qua NGINX như bình thường. Chỉ mất phần quan sát và (nếu module không
được nạp) phần kiểm tra.

## Fail mode tăng

Cảnh báo `StrataFailModeHigh`, `StrataBudgetExceeded`: trên 1% request đi theo fail
mode hoặc vượt CPU budget.

1. Dashboard **Strata module**, panel "Fail mode and CPU budget": loại nào tăng
   (`open`, `closed`, vượt budget)?
2. Vượt budget là chính → xem panel "Body inspected" và "Engine time". Body lớn với gói
   đầy đủ đi fail-open là giới hạn đã biết (#28). Nếu có dấu hiệu tấn công làm chậm, tra
   sự kiện vượt budget trên trang Sự kiện.
3. `closed` trả 503 cho người dùng: nếu kéo dài, **ép shadow** cho policy đó trong lúc
   điều tra.

## Circuit breaker mở

Cảnh báo `StrataBreakerOpen` (một worker), `StrataBreakerOpenManyWorkers` (từ 2 worker
trên cùng node, nghiêm trọng): lỗi nội bộ của engine (panic) vượt 2% trong 10 giây, worker
chạy **chế độ giảm cấp**: chỉ lớp protocol và rule `ip_match`, không có rule đầy đủ.
Location đặt `strata_breaker_action reject` trả 503 kèm Event ID.

1. Dashboard **Strata module**, panel "Circuit breaker per worker": worker nào, open (1)
   hay half-open (2). Breaker tự thử lại: mở 30 giây, half-open 10 giây với 5% request
   qua engine đầy đủ; mở lại liên tiếp thì thời gian nhân đôi, tối đa 5 phút.
2. `error.log` của NGINX: `strata: circuit breaker open, N internal errors in M requests`
   và các dòng `strata: engine error 3` (panic) trước đó, kèm Event ID. Tra Event ID trên
   trang Sự kiện để thấy request gây lỗi.
3. Nhiều worker cùng mở ngay sau một lần deploy: **rollback bundle** (mục dưới). Không
   liên quan tới deploy: báo nhóm libstrata kèm Event ID; trong lúc chờ, giảm cấp vẫn chặn
   request mơ hồ, nên chỉ **tắt module** khi chính chế độ giảm cấp cũng lỗi (fail mode
   tăng, mục trên).
4. Request vượt CPU budget **không** làm breaker mở (cố ý); budget tăng thì xem mục
   "Fail mode tăng".

## Sự kiện bị bỏ

Cảnh báo `StrataEventsDropped`: trên 0,1% sự kiện bị bỏ ở event socket.

1. Kiểm **sysctl** (mục dưới) trên node.
2. Dashboard **Strata agent**: agent có theo kịp không (events received, spool)?

## Sysctl

Cảnh báo `StrataDgramQueueTooShort`. Hàng đợi datagram Unix mặc định (512) làm NGINX bỏ
sự kiện ngay cả ở tải vừa phải (`docs/decisions/ring-buffer.md`). Gói `strata-agent` cài
`/etc/sysctl.d/90-strata.conf`.

```bash
sysctl net.unix.max_dgram_qlen            # mong đợi: 8192
sysctl -w net.unix.max_dgram_qlen=8192    # áp ngay
systemctl restart strata-agent            # socket mới nhận giá trị mới
```

Trong container, giá trị này thuộc network namespace của container agent
(`sysctls:` trong Compose, `securityContext.sysctls` trong Kubernetes).

## Agent không chạy

Cảnh báo `StrataAgentDown`. NGINX giữ bundle đang chạy và vẫn kiểm request. Trong lúc
agent dừng: không nhận bundle mới, không nhận lệnh ép shadow, sự kiện bị bỏ ở socket.

```bash
systemctl status strata-agent
journalctl -u strata-agent --since -15min
```

## Agent mất kết nối

Cảnh báo `StrataAgentDisconnected`, `StrataAgentCertExpiring`, `StrataNodesOffline`,
`StrataAgentSpoolDropping`.

1. Log agent: `control stream ended` kèm lý do.
   - `PermissionDenied` / `Unauthenticated`: node đã bị thu hồi hoặc chứng chỉ hết hạn;
     enroll lại bằng token mới.
   - Lỗi mạng: kiểm đường tới cổng FleetService (mTLS) của control plane.
2. Chứng chỉ node sống 24 giờ, được gia hạn khi còn 8 giờ. Còn dưới 4 giờ nghĩa là gia
   hạn đã lỗi 4 giờ liền.
3. Sự kiện nằm trong spool trong lúc mất kết nối. Spool đầy thì sự kiện cũ nhất bị bỏ.

## Ép shadow

Đưa một node (hoặc một policy trên node) về shadow trong tối đa 24 giờ, không cần
deploy. Dùng khi chặn nhầm hàng loạt.

```bash
curl -fsS -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"node_id":"<node>","policy_id":"example-api","duration_seconds":3600}' "$CP/v1/nodes:forceShadow"
curl -fsS -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"node_id":"<node>","policy_id":"example-api"}' "$CP/v1/nodes:clearForceShadow"
```

Cảnh báo `StrataForceShadowActive` (mức info) nhắc rằng node đang bị giữ ở shadow.

## Tắt rule khẩn cấp

Một Rule ID chặn nhầm hàng loạt: tắt nó trên mọi node của một connector group trong vài
giây, không deploy lại policy (W12). Các rule khác vẫn chặn, nên đây là lựa chọn đầu tiên
khi đã biết rule nào sai; chưa biết thì **ép shadow**.

```bash
curl -fsS -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"group_id":"<group>","reason":"FP trên /search, ticket #123"}' "$CP/v1/rules/942100:emergencyDisable"
curl -fsS -H "Authorization: Bearer $TOKEN" "$CP/v1/rules:disabled?group_id=<group>"
curl -fsS -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"group_id":"<group>","reason":"rule sửa trong gói 0.0.2"}' "$CP/v1/rules/942100:enable"
```

- Cần vai trò `operator` trở lên; lý do (1..500 ký tự) bắt buộc và nằm trong audit cùng
  người gọi và group.
- Node offline lúc tắt nhận danh sách khi kết nối lại. Agent giữ danh sách qua restart
  (`disabled-rules.json` trong `--bundle-dir`), worker NGINX áp trong 1 giây (log `strata: N rules disabled by the
  kill switch`); một group tắt tối đa 480 rule.
- Rule bị tắt không khớp cả ở shadow, nên không có sự kiện của nó cho tới khi bật lại.
- Cảnh báo `StrataRulesDisabled` (mức info) nhắc rằng còn rule đang tắt. Kiểm một node:
  `POST /v1/nodes/{id}:collectDiagnostics`, kết quả có `disabled_rules`; metric
  `strata_agent_disabled_rules`.

## Node tự về shadow

Cảnh báo `StrataNodeFallback`: agent tự ép **mọi policy** của node về shadow (tầng 1 của
fallback tự động), lý do ở nhãn `reason`:

- `block_rate`: node chặn hơn 3 lần mức "lẽ ra chặn" học được (trung bình động mỗi 5
  giây, khởi động 1 phút);
- `engine_errors`: request đi fail mode (lỗi engine) tăng hơn 3 lần (tối thiểu 1,5%);
- `budget`: request vượt CPU budget tăng hơn 3 lần (tối thiểu 1,5%).

Node giữ shadow **cho tới khi control plane gỡ** (W12-G1-01): không có hạn, restart agent
vẫn giữ (`force-shadow.json`). Giữ quá 1 giờ thì có cảnh báo `StrataNodeFallbackHeld`.
Kiểm: metric `strata_agent_fallback_active`, hoặc `collectDiagnostics` (`force_shadow.fallback`
có lý do và thời điểm). Việc cần làm:

1. Trang Sự kiện, lọc node và 15 phút trước cảnh báo: Rule ID nào tăng? Nhiều IP khác
   nhau trên một rule mới deploy thường là chặn nhầm; ít IP với payload tấn công rõ là
   đợt tấn công thật (khi đó shadow để lọt tấn công: cân nhắc gỡ sớm).
2. Chặn nhầm: **rollback bundle** hoặc tắt rule (mục Tắt rule khẩn cấp), rồi gỡ. Tấn công
   thật: gỡ ngay khi đã chắc. Gỡ bằng `clearForceShadow` (mục Ép shadow) với `policy_id` để
   trống; gỡ một policy hay lệnh `forceShadow` hết hạn không gỡ được fallback.
3. Tắt hẳn tầng này trên một node: `strata-agent --fallback=false`.

## Tắt module

Dùng khi nghi module gây lỗi cho request (không phải chặn nhầm: chặn nhầm thì **ép
shadow**, vì shadow vẫn ghi sự kiện).

1. Nhanh, giữ module trong bộ nhớ: đổi **mọi** `strata on;` thành `strata off;`, rồi
   `nginx -t && systemctl reload nginx`. Thêm một dòng `strata off;` ở khối `http` là
   **không đủ**: location có `strata on;` vẫn được ưu tiên.

   ```bash
   grep -rl 'strata on;' /etc/nginx | xargs sed -i 's/strata on;/strata off;  # strata disabled/'
   nginx -t && systemctl reload nginx
   ```

   Request không còn được kiểm, không có header `X-Strata-Block-Id`. Bật lại bằng lệnh
   ngược (`s/strata off;  # strata disabled/strata on;/`) rồi reload.
2. Gỡ hẳn khỏi NGINX: bỏ dòng `load_module modules/ngx_http_strata_module.so;` và file
   `/etc/nginx/conf.d/strata.conf`, bỏ mọi `strata*` trong cấu hình, rồi `nginx -t` và
   **restart** (reload không gỡ được module đã nạp).

Sau khi bật lại, kiểm bằng một request thử bị chặn (403 kèm Block ID).

Lưu ý (#49): với gói signature đầy đủ, request đầu tiên trên mỗi worker mới (sau reload
hoặc đổi bundle) có thể vượt CPU budget và đi theo `strata_fail_mode`. Gửi vài request
thử sau reload, và đừng kết luận từ request đầu tiên.

## Rollback bundle

Cảnh báo `StrataWorkersOnOldBundle`, `StrataRolloutStuck`, hoặc một deploy làm chặn
nhầm.

Node không tự nhận bundle cũ hơn bản đang chạy (chữ ký và số version chặn việc đó).
Vì vậy rollback là **deploy lại nội dung policy cũ** thành một bundle mới:

1. Rollout đang chạy dở thì dừng nó: `POST $CP/v1/rollouts/{id}:abort` (node chưa nhận
   bundle mới thì không nhận nữa).
2. Tìm phiên bản policy tốt trước đó:
   `GET $CP/v1/policies/{id}/versions`, rồi `GET $CP/v1/policies/{id}/versions/{v}`.
3. Ghi lại spec đó lên policy, kèm etag hiện tại:
   `PATCH $CP/v1/policies/{id}` với `{"etag":"<etag>","spec":<spec của v>}`.
4. `POST $CP/v1/policies/{id}:deploy`, rồi theo dõi `GET $CP/v1/rollouts/{rollout_id}`
   tới `DONE`.
5. Kiểm: request thử cho kết quả như trước sự cố. Panel "Bundle version per worker"
   cho thấy mọi worker đã sang bundle mới.

Trong lúc chờ rollout: **ép shadow** những node đang chặn nhầm.

## Control plane

Cảnh báo `StrataControlPlaneDown`, `StrataControlPlaneDatabaseDown`,
`StrataIngestStoreErrors`, `StrataDeployFailed`, `StrataAPIErrors`.

Khi control plane dừng, node tiếp tục chạy bundle hiện tại; sự kiện chờ trong spool của
agent. Không deploy, không enroll được.

1. Log control plane: `[FATAL]`, `[ERROR]`.
2. `StrataControlPlaneDatabaseDown`: PostgreSQL.
3. `StrataIngestStoreErrors`: ClickHouse. Agent tự gửi lại khi ClickHouse trở lại.
4. `StrataDeployFailed`: lỗi compile, vượt cost budget (#36), ký (KMS) hoặc lưu (S3);
   chi tiết nằm trong câu trả lời của `:deploy` và trong log.

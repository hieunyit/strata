# Runbook Strata

Runbook cho người trực vận hành Strata (module NGINX, `strata-agent`, control plane).
Mỗi cảnh báo trong `deploy/monitoring/alerts.yml` có `runbook_url` trỏ vào một mục
dưới đây.

- Dashboard (Grafana, thư mục "Strata"): **Strata module**, **Strata agent**,
  **Strata control plane**.
- Cảnh báo: vmalert (lab `127.0.0.1:18880`, staging `127.0.0.1:28880`), danh sách
  cảnh báo trong Grafana, và chuỗi `ALERTS{alertstate="firing"}` trong VictoriaMetrics.
- Các thao tác can thiệp (tắt module, ép shadow, rollback bundle) có lệnh và kết quả
  mong đợi đầy đủ ở các mục cùng tên. Chúng được diễn tập trên staging trong
  W10-N-01; biên bản nằm trong `docs/reports/w10-n-01.md`.

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

## Rollback bundle

Cảnh báo `StrataWorkersOnOldBundle`, `StrataRolloutStuck`. Quy trình rollback đầy đủ:
W10-N-01.

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

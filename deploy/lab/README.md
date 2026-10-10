# Strata lab

Dựng trên một máy (Docker + Compose v2): 2 node NGINX có `ngx_http_strata_module` (1.30.5 stable, 1.31.6 mainline), mỗi node kèm một `strata-agent`; control plane (REST và FleetService `PushEvents`); ClickHouse, PostgreSQL, Keycloak, MinIO; Web UI; VictoriaMetrics và Grafana. Chỉ dùng cho lab: không trỏ vào staging hay production.

```bash
make lab-up      # build trong image dev, sinh mật khẩu + PKI + khóa ký bundle, chạy và chờ healthy
make lab-smoke   # kiểm tra từng thành phần, chặn trên cả 2 NGINX, đường đi sự kiện, metrics
make lab-status
make lab-down    # dừng, giữ dữ liệu
make lab-clean   # xóa cả volume và deploy/lab/.state
```

| Dịch vụ | Địa chỉ (chỉ 127.0.0.1) |
| --- | --- |
| NGINX 1.30.5 (node-1) | http://127.0.0.1:18080, header `Host: api.example.test` |
| NGINX 1.31.6 (node-2) | http://127.0.0.1:18081 |
| Web UI | http://127.0.0.1:18088 |
| Control plane REST (admin + event API) | http://127.0.0.1:18090, cần token |
| Control plane admin gRPC (không TLS, chỉ lab) | 127.0.0.1:18091 |
| Grafana (dashboard "Strata node") | http://127.0.0.1:13000, user `admin` |
| VictoriaMetrics | http://127.0.0.1:18428 |
| Keycloak (realm `strata`) | http://127.0.0.1:18180, user `admin` |
| MinIO API / console | http://127.0.0.1:19000 / :19001, user `strata` |
| ClickHouse HTTP | http://127.0.0.1:18123, user `strata` |

Mật khẩu nằm trong `deploy/lab/.state/env`, gồm cả 4 user lab `lab-viewer`, `lab-operator`, `lab-approver`, `lab-admin` (mỗi user một vai trò) và secret của client `strata-lab-cli` (tạo ngẫu nhiên lần đầu, không commit). CA của lab, node CA và khóa ký bundle nằm trong volume `state`, do `lab-init` tạo một lần. `fleet-init` (sau khi control plane chạy) đăng nhập bằng `lab-admin`, tạo connector group `lab` và một enrollment token cho mỗi agent; agent `enroll` ở lần chạy đầu (khóa riêng trong volume `identity-node-N`, chứng chỉ 24 giờ, tự gia hạn) rồi `run --identity-dir`. `GET /v1/nodes` cho thấy hai node online.

Thử tay:

```bash
. deploy/lab/.state/env
TOKEN=$(curl -fsS http://127.0.0.1:18180/realms/strata/protocol/openid-connect/token \
  -d grant_type=password -d client_id=strata-lab-cli -d client_secret=$LAB_CLI_SECRET \
  -d username=lab-operator --data-urlencode password=$LAB_OPERATOR_PASSWORD | jq -r .access_token)
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:18090/v1/version
curl -i -H 'Host: api.example.test' 'http://127.0.0.1:18080/files/%2e%2e/etc/passwd'
docker compose -f deploy/lab/compose.yaml exec agent-1 strata-emit -n 5
```

`strata-emit` gửi sự kiện thử vào event socket thay cho worker; module NGINX chỉ gửi sự kiện và ghi file metrics từ W07-N-01, nên trước đó `strata_metrics_file_up` là 0 và Grafana chỉ có các metric `strata_agent_*`.

Mọi route `/v1/` của control plane cần access token của realm `strata` (`aud` = `strata-api`); token phát cho `127.0.0.1:18180`, control plane đọc metadata qua `keycloak:8080` (`-oidc-discovery-url`).

Chưa có: agent tải bundle từ control plane (bundle v1 do `lab-init` ký sẵn).

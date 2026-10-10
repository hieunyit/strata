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
| Control plane REST | http://127.0.0.1:18090 |
| Grafana (dashboard "Strata node") | http://127.0.0.1:13000, user `admin` |
| VictoriaMetrics | http://127.0.0.1:18428 |
| Keycloak (realm `strata`) | http://127.0.0.1:18180, user `admin` |
| MinIO API / console | http://127.0.0.1:19000 / :19001, user `strata` |
| ClickHouse HTTP | http://127.0.0.1:18123, user `strata` |

Mật khẩu nằm trong `deploy/lab/.state/env` (tạo ngẫu nhiên lần đầu, không commit). CA của lab, chứng chỉ node (`spiffe://strata/node/node-{1,2}`) và khóa ký bundle nằm trong volume `state`, do `lab-init` tạo một lần.

Thử tay:

```bash
curl -i -H 'Host: api.example.test' 'http://127.0.0.1:18080/files/%2e%2e/etc/passwd'
docker compose -f deploy/lab/compose.yaml exec agent-1 strata-emit -n 5
```

`strata-emit` gửi sự kiện thử vào event socket thay cho worker; module NGINX chỉ gửi sự kiện và ghi file metrics từ W07-N-01, nên trước đó `strata_metrics_file_up` là 0 và Grafana chỉ có các metric `strata_agent_*`.

Chưa có: đăng nhập UI qua Keycloak (realm và client `strata-ui` đã có), agent tải bundle từ control plane (bundle v1 do `lab-init` ký sẵn).

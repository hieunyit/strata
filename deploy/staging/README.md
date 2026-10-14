# Strata staging

Staging chạy trên chính máy lab, theo quyết định của PO ngày 13/10/2026. Nó là stack
lab của **một bản đã gắn tag**, chạy dưới project Compose `strata-staging`, song song
với lab. Chỉ bản đã tag mới deploy được. Chuyển sang host khác thì đặt `DOCKER_HOST`.

```bash
git tag -a v0.9.0-rc.1 -m "..." && git push origin v0.9.0-rc.1
deploy/staging/deploy.sh v0.9.0-rc.1      # kiểm tag, build từ tag, chạy, smoke test
deploy/staging/deploy.sh --status         # bản đang chạy (tag, commit, thời điểm)
deploy/staging/test-deploy.sh             # các trường hợp phải bị từ chối
```

`deploy.sh` từ chối:

- tên nhánh, mã commit, hoặc tag không có dạng `v<major>.<minor>.<patch>[-<pre>]`;
- tag chưa có trên `origin`;
- tag trên `origin` trỏ tới commit khác với tag ở máy này.

Mã nguồn được lấy bằng `git archive <tag>`: chỉ có những gì nằm trong tag, không lấy
working tree. Toàn bộ build chạy từ mã nguồn đó, trong
`build/staging/<tag>` (`deploy/lab/build.sh` trong image dev).

| Dịch vụ | Lab | Staging |
| --- | --- | --- |
| NGINX 1.30.5 / 1.31.6 | 18080 / 18081 | 28080 / 28081 |
| Web UI | 18088 | 28088 |
| Control plane REST / admin gRPC | 18090 / 18091 | 28090 / 28091 |
| Keycloak | 18180 | 28180 |
| Grafana / VictoriaMetrics | 13000 / 18428 | 23000 / 28428 |
| MinIO / ClickHouse HTTP | 19000 / 18123 | 29000 / 28123 |

Cổng chỉ bind vào 127.0.0.1. Image mang tên `strata-staging-runtime:<tag>` và
`strata-staging-ui:<tag>`.

Mật khẩu (`.state/env`) và bản đang chạy (`.state/deployed`) nằm trong
`deploy/staging/.state`, không commit. Dữ liệu nằm trong các volume `strata-staging_*`.
Cả hai được giữ lại qua các lần deploy.

Gỡ staging:

```bash
docker compose -p strata-staging down -v && rm -rf deploy/staging/.state
```

## prod-sim và route thí điểm (W10-G1-01)

Khi PO chưa có môi trường production và route thí điểm thật, có thêm hai thứ chạy trên
máy này:

- **prod-sim**: một môi trường thứ ba, deploy y như staging từ một tag. Mục đích là kiểm
  quy trình triển khai trên một môi trường khác staging. Đây **không phải production**.

  ```bash
  deploy/staging/deploy.sh --env prod-sim --signatures build/signatures/v0.0.1 v0.10.0-rc.1
  ```

  Project `strata-prodsim`, cổng 3xxxx (NGINX 38080/38081, control plane 38090,
  Keycloak 38180, Grafana 33000), state trong `deploy/staging/.state-prod-sim`.

- **2 route thí điểm giả lập** trên mỗi môi trường: `pilot-verify`
  (`POST /v1/verify`, JSON) và `pilot-upload` (`POST /v1/upload`, multipart). Mỗi route là
  một node riêng: image node của gói (`deploy/packaging/image`), build từ mã nguồn của
  chính tag đã deploy, enroll vào group `pilot`, đứng trước một backend giả lập.

  ```bash
  deploy/staging/pilot.sh [--env prod-sim] up        # dựng hoặc dựng lại node, enroll lần đầu
  deploy/staging/pilot.sh [--env prod-sim] status
  deploy/staging/pilot.sh [--env prod-sim] --inspect up   # bật kiểm tra (policy pilot-*, W10-G2-01); được nhớ
  deploy/staging/pilot.sh [--env prod-sim] --no-inspect up  # tắt kiểm tra
  deploy/staging/pilot-traffic.sh [--env prod-sim] up|status|sources|down   # lưu lượng giả lập
  ```

  Cổng: 28480 (verify) và 28481 (upload); prod-sim dùng 38480 và 38481. Từ 14/10,
  `deploy.sh` tự chạy `pilot.sh up` (khi môi trường đã có route thí điểm), ngay sau smoke
  và **trước** khi rollout bundle mới. Lý do: node thí điểm chạy module cũ sẽ từ chối bundle
  mà nó không biết, và rollout dừng ở đó (prod-sim, `v0.11.0-rc.1`). Bước này cũng dựng lại
  job `strata-agent-pilot` trong `scrape.yml`. Trạng thái `--inspect` được giữ. Trước khi chạy `fp-report`,
  chạy `pilot-traffic.sh sources`: IP của container tấn công có thể đổi khi container
  được tạo lại.

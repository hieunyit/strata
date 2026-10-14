# Strata WAF

Strata là WAF mã nguồn mở (Apache-2.0):

- lõi detection `libstrata` viết bằng Rust, xuất C ABI;
- connector cho proxy có sẵn; hiện tại **chỉ có NGINX** (`connectors/nginx`);
- `strata-agent` chạy cạnh proxy;
- control plane (Go) và Web UI quản trị.

**Trạng thái thật của từng tính năng**: [`docs/status.md`](docs/status.md) (Có / Một phần
/ Thiết kế, kèm test hoặc báo cáo). Tài liệu thiết kế mô tả đích đến, không phải những gì
đã chạy được.

| Tài liệu | Nội dung |
| --- | --- |
| [`docs/design/nginx-module.md`](docs/design/nginx-module.md) | Thiết kế module NGINX, FFI, bundle, agent, control plane, API |
| [`docs/design/strata-overview.md`](docs/design/strata-overview.md) | Thiết kế tổng thể, danh mục tính năng |
| [`docs/plan/plan.md`](docs/plan/plan.md) | Kế hoạch tuần 3–22, gate |
| [`docs/runbook/`](docs/runbook/) | Cài node, vận hành, xử lý cảnh báo |
| [`docs/reports/`](docs/reports/) | Báo cáo từng nhiệm vụ, số đo |
| [`AGENTS.md`](AGENTS.md), [`CLAUDE.md`](CLAUDE.md) | Quy tắc cho agent làm việc trong repo |

Bắt đầu nhanh (lab trên một máy, cần Docker):

```bash
deploy/dev/run.sh deploy/lab/build.sh
deploy/lab/init-env.sh
docker compose -f deploy/lab/compose.yaml --env-file deploy/lab/.state/env up -d --wait
deploy/lab/smoke.sh
```

Cài một node thật: [`docs/runbook/install.md`](docs/runbook/install.md).

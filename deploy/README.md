# deploy

- `compact/`: Strata Compact, control plane trên một máy bằng 3 dịch vụ (CP-A09): build image, cài, backup/restore, overlay Keycloak.
- `packaging/`: gói deb/rpm của module NGINX và agent, image node.
- `lab/`: lab đầy đủ (Keycloak, MinIO, Vault, giám sát, 2 node NGINX) cho phát triển và kiểm thử.
- `staging/`: staging và prod-sim, chỉ deploy từ tag.
- `dev/`: image build/test dùng chung cho local và CI.
- `monitoring/`: dashboard Grafana và cảnh báo vmalert.

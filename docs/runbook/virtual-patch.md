# Runbook Diễn tập và Triển khai Virtual Patch khẩn cấp (W14-S-01)

Tài liệu hướng dẫn quy trình ứng phó và phát hành Virtual Patch khẩn cấp khi phát hiện lỗ hổng bảo mật nghiêm trọng (CVE 0-day hoặc 1-day có PoC khai thác công khai).

> **Mục tiêu vận hành (SLA)**: Phát hành signature virtual patch lên môi trường **Staging** trong vòng **< 24 giờ** kể từ khi tiếp nhận thông tin CVE.

---

## 1. Tiếp nhận và Phân loại CVE (Triage & Classification)

- **Kênh tiếp nhận**: NVD, CISA KEV (Known Exploited Vulnerabilities), GitHub Security Advisories, CERT-VN, hoặc báo cáo nội bộ.
- **Tiêu chí đánh giá mức độ khẩn cấp**:
  - **Critical (P0)**: CVSS $\ge$ 9.0, Remote Code Execution (RCE) / Auth Bypass, có PoC công khai hoặc bằng chứng đang bị khai thác thực tế (In-the-wild).
  - **High (P1)**: CVSS 7.0 – 8.9, SQLi, LFI/RFI, SSRF ảnh hưởng trực tiếp đến dữ liệu nhạy cảm.
  - **Medium/Low (P2/P3)**: Lỗ hổng cần quyền xác thực cao hoặc điều kiện môi trường phức tạp $\rightarrow$ xử lý theo lịch cập nhật định kỳ.

```bash
# Ghi nhận CVE ticket
cve_id="CVE-2026-XXXX"
cvss="9.8"
affected_component="Spring Boot / Apache Struts / Log4j / WordPress"
```

---

## 2. Đánh giá Phạm vi Ảnh hưởng (Blast Radius Assessment)

1. Xác định các hệ thống và route đang sử dụng công nghệ bị ảnh hưởng:
   - Truy vấn danh mục asset hoặc đối chiếu header/path trong traffic ClickHouse.
2. Xác định các vector tấn công:
   - Request Header (ví dụ: `User-Agent`, `X-Api-Version`, `Cookie`).
   - Query Parameter hoặc Form/JSON Body.
   - HTTP Method hoặc URI Path đặc thù.

---

## 3. Xây dựng Signature (Virtual Patch Authoring)

- **Vị trí lưu trữ**: `rules/virtual-patches/<cve-id>.yaml`.
- **Dải Rule ID**: **700000 – 799999** (dành riêng cho Virtual Patches theo thiết kế Strata).
- **Cấu trúc Rule**: Tuân thủ nghiêm ngặt `docs/spec/ir.schema.json`.

```yaml
# Ví dụ mẫu: rules/virtual-patches/700011-cve-2026-xxxx.yaml
rules:
  - id: 700011
    name: "Virtual Patch: CVE-2026-XXXX RCE via Malicious Header"
    layer: virtual-patch
    stage: request_headers
    severity: CRITICAL
    score: 10
    action_mode: block_alone
    metadata:
      source: strata-security
      author: "Strata SecOps Team"
      cve: "CVE-2026-XXXX"
      created_at: "2026-10-16"
      review_by: "2026-11-16"
    match:
      all:
        - targets:
            - var: request_headers
              key: "X-Exploit-Payload"
          transforms:
            - lowercase
            - url_decode
          operator:
            type: rx
            value: "(?:\\$\\{jndi|getRuntime|exec\\()"
```

---

## 4. Kiểm thử Khai thác (PoC) và Request Hợp lệ

Mỗi signature phải có bộ kiểm thử song hành:
1. **True Positive (Exploit Payload)**: Phải bị chặn 100%.
2. **True Negative (Benign Traffic)**: Không được khớp với các giá trị hợp lệ.

```bash
# Kiểm tra cú pháp và test case của rule
deploy/dev/run.sh bash -c "cd tools/strata-rules && go run . test --rule rules/virtual-patches/700011-cve-2026-xxxx.yaml"
```

---

## 5. Regression Test và Đánh giá False Positive

- Chạy kiểm thử trên toàn bộ corpus benign (hơn 10,000 mẫu hợp lệ):
```bash
# Đảm bảo 0 False Positive trên corpus chuẩn
deploy/dev/run.sh bash -c "cd tools/strata-rules && go run . corpus --benign"
```
- Chạy kiểm thử go-ftw / CRS regression suite:
```bash
deploy/dev/run.sh bash -c "make test-rules"
```

---

## 6. Kiểm tra Cost Unit và Hiệu năng

- Kiểm tra tổng chi phí (cost units) của rule mới:
```bash
deploy/dev/run.sh bash -c "cargo run -p strata-compiler --bin strata-pattern-cost -- rules/virtual-patches/700011-cve-2026-xxxx.yaml"
```
- **Tiêu chuẩn**:
  - Không sử dụng regex có độ phức tạp hàm mũ ($O(2^n)$).
  - Rule mới không làm tăng quá 500 cost units.
  - Tổng chi phí bundle phải nhỏ hơn `DefaultCostBudget` (50,000 units).

---

## 7. Review và Phê duyệt (4-Eyes Workflow)

- **Người tạo (Drafter)**: Kỹ sư SecOps tạo Pull Request và submit draft policy/rule.
- **Người duyệt (Approver)**: Security Lead hoặc DevSecOps cấp cao kiểm tra:
  - Tính chính xác của regex/pattern.
  - Kết quả test âm tính và dương tính.
  - Không tự duyệt chính bản nháp của mình (chính sách 4 mắt bắt buộc).

```bash
# Submit bản nháp policy có virtual patch
curl -X POST http://control-plane:8080/v1/policies/pilot-verify/versions/2:submit \
  -H "Authorization: Bearer $OPERATOR_TOKEN"

# Approver phê duyệt
curl -X POST http://control-plane:8080/v1/policies/pilot-verify/versions/2:approve \
  -H "Authorization: Bearer $APPROVER_TOKEN" \
  -d '{"comment": "Duyệt virtual patch CVE-2026-XXXX sau khi test benign 0 FP"}'
```

---

## 8. Kiểm tra Tính toàn vẹn và Chữ ký Bundle

Khi build bundle chứa rule mới:
- Control plane tự động ký số bằng Ed25519 (KMS / Vault).
- Kiểm tra chữ ký và version trước khi upload lên S3/MinIO:
```bash
# Kiểm tra xác thực bundle
deploy/dev/run.sh bash -c "cd control-plane && go test -v -run TestDeploy ./policy/..."
```

---

## 9. Triển khai Staging

- Triển khai bundle mới lên cụm Staging:
```bash
curl -X POST http://control-plane:8080/v1/policies/pilot-verify:deploy \
  -H "Authorization: Bearer $OPERATOR_TOKEN"
```
- Xác minh NGINX worker trên Staging tải bundle mới mà không mất kết nối (`error.log` ghi nhận `bundle version X mapped`).

---

## 10. Replay và Xác minh (Traffic Replay Verification)

- Chạy Replay Service với corpus traffic thực tế:
```bash
curl -X POST http://control-plane:8080/v1/policies/pilot-verify:replay \
  -H "Authorization: Bearer $OPERATOR_TOKEN" \
  -d '{"sample_size": 5000}'
```
- Phân tích kết quả:
  - Tỷ lệ `would_block` trên lưu lượng bình thường phải bằng **0%**.
  - Các request mô phỏng tấn công CVE phải hiển thị `blocked`.

---

## 11. Giám sát, Rollback và Báo cáo

### Giám sát 24/7 sau triển khai:
- Theo dõi Dashboard Grafana:
  - Tỷ lệ lỗi 5xx $\le 0.01\%$.
  - Tỷ lệ chặn bất thường (Block surge $> 3\times$ baseline).
  - Cảnh báo Rule Health (`GET /v1/rules/700011/health`).

### Quy trình Rollback khẩn cấp:
Nếu phát hiện False Positive nghiêm trọng ảnh hưởng nghiệp vụ:
1. **Cách 1 - Tự cách ly (Auto-Quarantine)**: Rule Health Monitor tự động chuyển rule về log-only nếu FP surge.
2. **Cách 2 - Emergency Disable (Kill-switch)**:
```bash
curl -X POST http://control-plane:8080/v1/groups/edge/rules/700011:disable \
  -H "Authorization: Bearer $OPERATOR_TOKEN" \
  -d '{"reason": "Tạm dừng khẩn cấp do nghi ngờ FP luồng thanh toán"}'
```
3. **Cách 3 - Rollback Bundle**: Triển khai lại phiên bản bundle đã duyệt trước đó.

### Báo cáo sau sự cố:
- Tổng kết thời gian phản ứng từ lúc nhận CVE $\rightarrow$ Staging (ghi nhận SLA).
- Lập kế hoạch cho nhà phát triển vá mã nguồn gốc (upstream patch), sau đó gỡ bỏ virtual patch khi ứng dụng đã cập nhật.

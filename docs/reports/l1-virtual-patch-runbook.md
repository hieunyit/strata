Nhiệm vụ: L1 · sửa runbook virtual patch

Viết lại runbook của prototype W14-S-01 theo API/CLI thực: schema rule và metadata đúng, CLI positional `test`, replay có version trước approve/deploy, endpoint submit/approve đúng, emergencyDisable/enable đúng, bỏ field sample_size. Nêu rõ artifact `-rules` của control plane cần được build lại; thêm cách đọc cost/provenance và giới hạn của oracle HTTP.

Fixture canary 700011 nằm ngoài `rules/`, không đại diện CVE và không tự vào pack. Kiểm chứng bằng compiler/engine thật:
```
strata-rules lint: 1 files, 0 problems
PASS 700011 (3 requests)
strata-rules test: 1 rules: 1 pass, 0 fail, 0 skipped (engine lacks a feature)
strata-rules release: lab-example (1 rules) -> ../../build/virtual-patch-example
strata-rules verify: lab-example (1 rules) OK
```
Cost report của fixture: total 2. `make rules-tools` build binary trước các lệnh trên. Không lấy unit rule test làm bằng chứng full-pack FP hay diễn tập staging <24 giờ. HTTP submit/replay/approve/deploy đã được kiểm qua E2E trong các PR M5; kill switch giữ endpoint khai trong proto Fleet. Không vận hành staging/production, không chờ hosted CI.

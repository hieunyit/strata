Nhiệm vụ: H4 · route health che lệnh emergencyDisable/emergencyEnable

Sửa trên prototype local W14-G2-02-rule-health (5109fb2), chưa nhập prototype vào main. Đổi broad prefix /v1/rules/ thành đúng GET /v1/rules/{rule_id}/health; các action Fleet và đường dẫn khác tới admin gateway như trước. Giữ auth middleware và principal; gateway vẫn chịu trách nhiệm RBAC/audit của lệnh ghi. Health từ chối ID 0/âm/tràn uint32/không phải số.

Test mới fail trước sửa: 4 đường dẫn bị 404, gateway calls=0. Sau sửa:
```
go test -race ./api -count=1
ok github.com/strata/strata/control-plane/api 3.481s
golangci-lint run ./api/...: exit 0
```
Test chứng minh dispatch đúng cho hai action, health không tới gateway, thiếu token không tới gateway, ID sai bị từ chối. Đây không thay thế E2E Fleet/audit đã có; test dùng gateway stub để cô lập lỗi router. Log trước/sau trong h4-health-route/.

Chưa giải quyết M4: monitor vẫn RAM, GET vẫn evaluate/mutate, callback dưới lock, danh sách sự kiện không giới hạn, chưa có pipeline quarantine ra runtime. Nhánh này sửa lỗi dispatch đã tái hiện; chưa phát hành/publish prototype có các thiếu sót đó thành tính năng production. Sẽ tích hợp route này cùng bản M4 hoàn chỉnh; không tuyên bố health/quarantine đã hoạt động.

# Báo cáo CP-A03 · Gia cố PostgreSQL

Ngày: 20/10/2026. Người làm: Claude Code (strata-59). Kế hoạch: `docs/plan/compact-ops-plan.md`
§4 A03.

## 1. Làm gì

| Phần | Ở đâu |
| --- | --- |
| Lease một control plane: bảng `control_plane_lease` (migration 0027), giành, gia hạn, nhả, giành lại khi holder đã chết | `control-plane/store/lease.go`, `control-plane/cmd/server/lease.go` |
| Cờ `-single-control-plane` (mặc định bật), `-lease-ttl` (30 s) | `cmd/server/main.go` |
| `GET /readyz`: `postgres`, `lease`, `clickhouse`; 503 khi PostgreSQL hoặc lease không ổn | `api/server.go`, `cmd/server/main.go` |
| Deploy chờ khóa có giới hạn (`Store.BundleLockWait`, 2 phút) → 409 | `store/policy.go`, `admin/policy.go` |

## 2. Thiết kế đã điều chỉnh so với kế hoạch

Kế hoạch ghi "deploy không giữ lock khi build" (đặt chỗ → build → xác nhận). Khi làm, tôi giữ
deploy tuần tự dưới khóa: chốt replay (CP-FIX-01) so với bundle đang chạy, khóa bảo đảm bundle đó
không đổi tới lúc deploy ghi xong. Tách ba bước chỉ biến việc chờ thành lỗi khi xác nhận, thêm
trạng thái BUILDING và đụng tới M4 staging, cũng ghi bundle dưới cùng khóa. Vấn đề thật là chờ
không giới hạn; nay giới hạn và báo rõ. Khóa phiên đã có cơ chế hủy kết nối khi không chắc còn giữ
khóa (có từ trước).

## 3. Lease: hành vi

- Khởi động: giành lease. Nếu bản khác đang giữ: chờ tối đa `ttl + 10 s` để nó hết hạn, rồi dừng
  với thông báo nêu holder.
- Khởi động lại sau sự cố trên cùng máy: holder là `host/pid/ngẫu nhiên`; cùng host và PID trùng
  của mình (container, cả hai là PID 1) hoặc PID không còn tồn tại → giành ngay, fencing tăng.
  Một control plane khác còn sống trên cùng máy vẫn phải chờ.
- Đang chạy: gia hạn mỗi `ttl/3`. Mất lease (bị giành) hoặc không gia hạn được trong `2/3 ttl` →
  thoát (compose/systemd chạy lại).
- Dừng sạch: nhả lease, bản sau giành ngay.
- Rollout, lệnh node, hàng đợi replay đều đọc từ PostgreSQL nên chạy tiếp sau khởi động lại.

Rủi ro còn lại: tiến trình bị treo lâu hơn ttl mà không chết thì có lúc hai bản cùng chạy cho tới
lần gia hạn kế tiếp của bản cũ (nó sẽ thoát). Fencing chưa được gắn vào từng thao tác ghi.

## 4. Test

| Test | Kết quả |
| --- | --- |
| `TestControlPlaneLeaseInPostgres`: giành, giữ, bị chặn, giành sau khi hết hạn (fencing tăng), bản cũ không gia hạn được, nhả | PASS |
| `TestConcurrentDeploysSerializedInPostgres`: 4 deploy đồng thời → tuần tự, version 1–4; chờ quá hạn → `ErrBundleBusy`; khóa tự do lại sau đó | PASS |
| `TestLeaseKeeperInPostgres`: gia hạn qua ttl, bản khác bị chặn, dừng sạch nhả lease, bản mất lease thì thoát | PASS |
| `TestLeaseTakeOverAfterCrashHere`: PID của mình, PID không tồn tại → chết; PID cha, host khác, holder hỏng → không; giành ngay trong PostgreSQL | PASS |
| `TestReadyz`: không token, chỉ trạng thái, 503 khi mất lease | PASS |

Cổng kiểm đầy đủ và lab: mục 5.

## 5. Cổng kiểm và lab

Điền khi chạy xong.

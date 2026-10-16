# Kế hoạch Triển khai Chi tiết Tuần 14 (Week 14 Implementation Plan)

- **Trạng thái**: Đang triển khai (In Progress)
- **Kỳ làm việc**: Tuần 14 · Khối B2
- **Mục tiêu**: Hoàn thiện toàn diện 8 tasks của Tuần 14 với đầy đủ kiểm thử, mã nguồn, UI, và runbook.

---

## 1. Bảng theo dõi tiến độ tổng thể

| Task ID | Nhiệm vụ | Trạng thái | Nhánh thực hiện | File thay đổi | Tests Run | Kết quả | Blockers |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **W14-G2-01** | Exception từ Block ID & :markFalsePositive | 🔄 IN PROGRESS | `W14-G2-01-exceptions-api` | `control-plane/api/*`, `control-plane/store/*` | Unit, Integration | Chờ chạy | Không |
| **W14-F-01** | 3 Nút thao tác trên Chi tiết sự kiện | ⏳ QUEUED | `W14-F-01-event-actions` | `ui/src/pages/*`, `ui/src/api/*` | Vitest UI | Chờ chạy | Phụ thuộc G2-01 |
| **W14-R-01** | Compiler: Exception trước Override | ⏳ QUEUED | `W14-R-01-exceptions` | `engine/compiler/*`, `control-plane/policy/*` | Cargo test, Go test | Chờ chạy | Không |
| **W14-G2-02** | Sức khỏe Rule & Tự cách ly | ⏳ QUEUED | `W14-G2-02-rule-health` | `control-plane/api/*`, `tools/strata-rules/*` | Go test | Chờ chạy | Không |
| **RV-R-03** | NGINX Rate Limiting tầng 1 (P-01 §3) | ⏳ QUEUED | `RV-R-03-ratelimit` | `connectors/nginx/src/*` | Make test, bench | Chờ chạy | Không |
| **W14-S-01** | Virtual Patch Runbook & Tooling | ⏳ QUEUED | `W14-S-01-virtual-patch` | `docs/runbook/virtual-patch.md`, tools | Drill test | Chờ chạy | Không |
| **W14-Q-01** | Game Day Chaos Testing | ⏳ QUEUED | `W14-Q-01-game-day` | `docs/runbook/game-day.md`, `tests/chaos/*` | Chaos script | Chờ chạy | Không |
| **Canary 25%** | Quan sát 72h & Dashboard | ⏳ QUEUED | `main` | `docs/runbook/canary-25.md` | Audit & metrics | Chờ chạy | Gate A blocker |

---

## 2. Thiết kế chi tiết cho Task 1 (W14-G2-01)

### Mô hình dữ liệu Exception
```go
type Exception struct {
    ID          string     `json:"id"`           // exp-[0-9a-f]{16}
    BlockID     string     `json:"block_id"`     // Block ID gốc tạo ra exception
    PolicyID    string     `json:"policy_id"`    // Policy hẹp nhất
    RuleID      uint32     `json:"rule_id"`      // Rule bị chặn nhầm
    Field       string     `json:"field"`        // Field cụ thể (ví dụ "query.q", "body.password")
    Reason      string     `json:"reason"`       // Lý do tạo exception
    State       string     `json:"state"`        // DRAFT, SUBMITTED, APPROVED, EXPIRED, REVOKED
    CreatedBy   string     `json:"created_by"`   // Người tạo
    ApprovedBy  string     `json:"approved_by"`  // Người duyệt (bắt buộc != CreatedBy)
    CreatedAt   time.Time  `json:"created_at"`   
    ExpiresAt   time.Time  `json:"expires_at"`   // Bắt buộc có hạn dùng (max 30 ngày)
}
```

### Các Endpoint triển khai:
1. `POST /v1/events/{block_id}:markFalsePositive`
   - Đánh dấu sự kiện trong store là FP.
   - Ghi audit trail.
2. `POST /v1/exceptions:fromBlockId`
   - Tra cứu sự kiện từ Block ID.
   - Trích xuất: PolicyID, RuleID từ vi phạm, Field từ vi phạm.
   - Xác thực TTL: `ttl_seconds > 0` và $\le$ 30 ngày.
   - Lưu exception ở trạng thái `SUBMITTED` (chờ duyệt).
   - Ghi audit trail.
3. `GET /v1/exceptions`
   - Liệt kê các exception, hỗ trợ lọc theo policy, rule_id, state.
4. `POST /v1/exceptions/{id}:approve`
   - Kiểm tra 4-Eyes: Caller khác `CreatedBy`.
   - Chuyển trạng thái sang `APPROVED`.
5. `DELETE /v1/exceptions/{id}`
   - Thu hồi exception.

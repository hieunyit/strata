# Prompt giao việc tuần 6–22

Đặt file ở `docs/plan/dispatch.md`.

**Phân vai:** Antigravity viết toàn bộ code, test, rule, tài liệu. Claude Code chỉ review và sửa ở những chỗ rủi ro cao, nên tốn rất ít token. Ngoại lệ: W06-N-01 đang làm dở thì để Claude Code làm nốt.

**Thiết lập Antigravity (một lần):** chế độ **Planning** (không dùng Fast), model mạnh nhất đang có, terminal ở chế độ hỏi trước với lệnh ngoài danh sách cho phép. Worktree `../strata-ag` cho Antigravity, `../strata-cc` cho Claude Code. Mỗi agent làm một nhiệm vụ một lúc.

**Mức review** (ghi ở tiêu đề từng nhiệm vụ):

| Mức | Áp dụng cho | Ai review |
| --- | --- | --- |
| L1 | UI, test e2e, deploy, CI, tài liệu, nội dung rule | CI + Antigravity tự review; rule do người luồng S duyệt. Không gọi Claude Code |
| L2 | Go control plane, agent, gitops-sync, công cụ, Rust detector | Claude Code review PR (một lượt, chỉ đọc diff) |
| L3 | C module NGINX, FFI, bundle/ký, auth/RBAC/audit, fallback, interface chung | Claude Code review **kế hoạch** trước khi duyệt và review PR kỹ, chạy sanitizer |

**Luồng một nhiệm vụ**

1. Dán prompt của nhiệm vụ vào Antigravity → nó tạo Implementation Plan rồi dừng.
2. L3: dán prompt **"Review kế hoạch"** vào Claude Code kèm kế hoạch → sửa kế hoạch nếu cần → trả lời Antigravity **"duyệt"**. L1/L2: tự đọc rồi trả lời **"duyệt"**.
3. Antigravity làm, tự review, mở PR rồi dừng.
4. L2/L3: dán prompt **"Review PR"** vào Claude Code. Kết quả có 3 dạng:
   - `APPROVE` → merge.
   - `CẦN SỬA` → dán prompt **"Sửa theo review"** vào Antigravity, rồi dùng **"Review lại"** cho Claude Code (chỉ đọc phần mới).
   - Claude Code đã tự sửa lỗi Cao nhỏ ở L3 → Claude Code commit vào nhánh rồi `APPROVE`.
5. Quá 2 vòng sửa mà vẫn còn lỗi Cao → dùng **"Claude Code nhận làm"**.

Chỉ giao một nhiệm vụ khi mọi mã ở dòng "Cần trước" đã merge. Dòng ghi **Người** là việc vận hành, không giao cho agent.

---

## 0. Prompt dùng chung

**Review kế hoạch** · Claude Code · chỉ L3
```
Đọc AGENTS.md mục 3, 6, 6b và mục <MÃ> trong docs/plan/plan.md (chỉ mục đó, cùng các mục thiết kế ghi ở dòng "Đọc").
Không đọc code, không viết code. Dưới đây là Implementation Plan của Antigravity cho <MÃ>:
<dán kế hoạch>
Kiểm tra: đúng thiết kế; đủ bất biến, ca biên, đường lỗi; rủi ro bảo mật; test đủ để chứng minh "Xong khi" (gồm test âm, sanitizer/-race);
không đổi interface chung ngoài phạm vi; không thêm dependency chưa nêu.
Trả về tối đa 10 mục, mỗi mục một dòng: [Cao|TB|Thấp] vấn đề → yêu cầu sửa cụ thể. Dòng cuối: OK hoặc SỬA KẾ HOẠCH.
```

**Review PR** · Claude Code · L2 và L3
```
Review PR <link> của nhiệm vụ <MÃ> theo AGENTS.md mục 6b. Mức review: <L2|L3>.
Chỉ đọc: báo cáo trong PR, gh pr diff <số>, mục <MÃ> trong docs/plan/plan.md; mở file khác chỉ khi diff không đủ để kết luận.
L2: không chạy lại toàn bộ test; chỉ kiểm bằng chứng trong báo cáo và đọc diff.
L3: chạy thêm các lệnh kiểm chứng của mức L3 ở mục 6b (sanitizer, -race, prove, fuzz ngắn) trên nhánh của PR.
Lỗi Cao ở L3 sửa được trong khoảng 30 dòng thì tự sửa: commit "review: <mô tả>" vào nhánh của PR, chạy lại test liên quan.
Lỗi còn lại không sửa, ghi thành yêu cầu sửa cụ thể cho Antigravity.
Trả về theo mẫu ở mục 6b. Không viết lại phần đã đúng, không tóm tắt PR.
```

**Sửa theo review** · Antigravity
```
Đọc AGENTS.md mục 6a. Claude Code đã review PR <link> của <MÃ>:
<dán kết quả review>
Sửa mọi mục Cao và TB, mục Thấp nếu không mở rộng phạm vi. Mỗi lỗi kèm test chứng minh đã sửa (test fail trước, pass sau).
Không sửa ngoài phạm vi review. Chạy lại đủ "Xong khi" và lint/test khu vực, chạy lại checklist tự review.
Push lên cùng nhánh, cập nhật báo cáo mục 9: bảng "mục review → commit → test", SHA commit cuối. Rồi DỪNG.
```

**Review lại** · Claude Code
```
Review lại PR <link> của <MÃ>. Lần trước review tới SHA <sha cũ>. Chỉ đọc git diff <sha cũ>..<sha mới> và bảng "mục review → commit → test" trong báo cáo.
Đối chiếu từng mục đã yêu cầu: đã sửa / chưa sửa / sửa sai. Chỉ báo lỗi mới nếu nằm trong phần vừa đổi. Trả về theo mẫu mục 6b.
```

**Claude Code nhận làm** · khi Antigravity sửa quá 2 vòng vẫn còn lỗi Cao
```
Đọc AGENTS.md. Nhiệm vụ <MÃ> do Antigravity làm trên nhánh <nhánh>, sau 2 vòng review vẫn còn lỗi Cao:
<dán review gần nhất>
Checkout nhánh, sửa đúng các lỗi này, giữ phần đã đúng. Nêu kế hoạch ngắn rồi DỪNG, chờ "duyệt".
Sau khi duyệt: sửa, chạy đủ "Xong khi" và lint/test khu vực, push, báo cáo theo mục 9.
```

**Tiếp tục nhiệm vụ đang dở** · công cụ đang làm nhiệm vụ đó
```
Đọc AGENTS.md. Nhiệm vụ <MÃ> đang làm dở trên nhánh <MÃ>-*.
Checkout nhánh, đối chiếu từng điều kiện "Xong khi" trong docs/plan/plan.md: đạt / chưa đạt / chưa kiểm.
Nêu kế hoạch cho phần còn thiếu rồi DỪNG, chờ tôi duyệt. Sau khi duyệt: làm hết, chạy đủ "Xong khi",
đổi dòng nhiệm vụ ở mục 0 thành ✅ Done trong PR, báo cáo theo mục 9.
```

**Sáng thứ 2 · cập nhật mục 0 cho tuần mới** · Antigravity
```
Tôi là PO, yêu cầu cập nhật mục 0 của AGENTS.md cho tuần <N>.
Đổi "Tuần hiện tại" thành <N>, đổi khối và ngày cập nhật. Tạo bảng nhiệm vụ tuần <N> lấy từ docs/plan/dispatch.md
(Mã, Nhiệm vụ, Công cụ, Review, Cần trước, Trạng thái = ⏳). Giữ lại nhiệm vụ tuần trước chưa ✅ Done.
Cập nhật cột Trạng thái của bảng lộ trình. Chỉ sửa mục 0. Mở PR "plan: week <N>".
```

---

## Tuần 6 · Đường đi response và sự kiện

### W06-N-01 · Claude Code · Cần trước: — · đang làm dở (giữ Claude Code làm nốt, không đổi công cụ giữa chừng)
Dùng prompt "Tiếp tục nhiệm vụ đang dở" ở mục 0 với mã `W06-N-01`.

### W06-R-01 · Antigravity · Review L3 · Cần trước: —
```
Bạn là agent Antigravity trong dự án Strata. Đọc AGENTS.md (đặc biệt mục 0, 3, 4, 6) và mục W06-R-01 trong docs/plan/plan.md.

Nhiệm vụ W06-R-01 · Lớp response và tokenizer.
- Thư mục: engine/src/detectors/
- Việc: (a) lớp response: kiểm allowed response codes, chữ ký lỗi DB, che số CCCD và JWT trong response, trả buffer đã che qua API rewritten; (b) port tokenizer SQLi/XSS kiểu libinjection sang Rust.
- Xong khi: 15 case response pass; tokenizer khớp tối thiểu 99% bộ test gốc của libinjection (đưa test vector vào repo); fuzz 1 giờ không panic.
- Đọc: nginx-module.md › Ranh giới FFI; Xử lý body › Response body.
- Lưu ý: không unsafe ngoài engine/ffi/; ghi nguồn và giấy phép của libinjection trong NOTICE.

Bước 1: xác nhận nhiệm vụ thuộc phần Antigravity và tuần hiện tại, "Cần trước" đã merge.
Bước 2: tạo Implementation Plan (module, file, test, lệnh kiểm chứng) rồi DỪNG, chờ tôi duyệt.
Bước 3 (sau khi duyệt): tạo nhánh W06-R-01-response-tokenizer từ main, làm, chạy đủ "Xong khi" và lint/test Rust,
đổi dòng W06-R-01 ở mục 0 AGENTS.md thành ✅ Done trong PR, báo cáo theo mục 9.
Chuẩn bắt buộc: mục 6a AGENTS.md (test viết trước code, tự review theo checklist, bằng chứng là output thật). Mức review: L3 (khu vực rủi ro cao).
Implementation Plan phải có thêm: bất biến cần giữ, ca biên và đường lỗi, rủi ro bảo mật, danh sách test (gồm test âm và chạy sanitizer / -race).
Kế hoạch sẽ được Claude Code review trước khi tôi duyệt; chỉ bắt đầu code khi tôi trả lời "duyệt".
Sau khi mở PR (báo cáo mục 9, ghi "Review: L3" và SHA commit cuối): DỪNG, chờ Claude Code review. Không tự merge.
```

### W06-G1-01 · Antigravity · Review L2 · Cần trước: —
```
Bạn là agent Antigravity trong dự án Strata. Đọc AGENTS.md và mục W06-G1-01 trong docs/plan/plan.md.

Nhiệm vụ W06-G1-01 · Sự kiện từ worker tới control plane.
- Thư mục: agent/
- Việc: nhận sự kiện protobuf từ event socket của worker; gửi lên control plane qua PushEvents với spool đĩa 2 GB, seq tăng dần và ack; exporter Prometheus đọc bộ đếm từ shared memory.
- Xong khi: tắt control plane 10 phút rồi bật lại → không mất sự kiện; lô trùng seq bị bỏ; metrics hiện trên Grafana lab.
- Đọc: nginx-module.md › Trang chặn, Block ID & sự kiện; Giao thức gRPC agent ↔ control plane › Độ tin cậy.
- Lưu ý: không sửa fleet.proto ngoài phần PushEvents đã có; cần đổi thì dừng và đề xuất.

Bước 1: xác nhận phần Antigravity, tuần hiện tại, "Cần trước" đã merge.
Bước 2: tạo Implementation Plan rồi DỪNG, chờ tôi duyệt.
Bước 3 (sau khi duyệt): nhánh W06-G1-01-push-events, làm, chạy đủ "Xong khi" + go test + golangci-lint,
cập nhật mục 0 thành ✅ Done trong PR, báo cáo theo mục 9.
Chuẩn bắt buộc: mục 6a AGENTS.md (test viết trước code, tự review theo checklist, bằng chứng là output thật). Mức review: L2.
Implementation Plan phải có thêm: bất biến cần giữ, ca biên và đường lỗi, danh sách test (gồm test âm).
Sau khi mở PR (báo cáo mục 9, ghi "Review: L2" và SHA commit cuối): DỪNG, chờ Claude Code review. Không tự merge.
```

### W06-G2-01 · Antigravity · Review L2 · Cần trước: —
```
Bạn là agent Antigravity trong dự án Strata. Đọc AGENTS.md và mục W06-G2-01 trong docs/plan/plan.md.

Nhiệm vụ W06-G2-01 · Event ingest và API sự kiện.
- Thư mục: control-plane/ingest/, control-plane/api/
- Việc: service ingest nhận sự kiện từ Fleet, chống trùng theo seq, kiểm schema, ghi theo lô vào ClickHouse bảng events v1; endpoint GET /v1/events/{block_id} và POST /v1/events:search.
- Xong khi: chịu 10.000 sự kiện/giây trên lab không tồn đọng; tra Block ID dưới 1 giây trên 10 triệu dòng (có script sinh dữ liệu).
- Đọc: nginx-module.md › Control plane; API quản trị.
- Lưu ý: không sửa proto, không động vào control-plane/fleet/; endpoint phải kiểm quyền RBAC bằng middleware có sẵn.

Bước 1: xác nhận phần Antigravity, tuần hiện tại, "Cần trước" đã merge.
Bước 2: tạo artifact Implementation Plan (schema bảng, luồng ingest, endpoint, test, lệnh kiểm chứng) rồi DỪNG, chờ tôi duyệt.
Bước 3 (sau khi duyệt): nhánh W06-G2-01-event-ingest, làm, chạy đủ "Xong khi" + go test + golangci-lint,
cập nhật mục 0 thành ✅ Done trong PR, báo cáo theo mục 9.
Chuẩn bắt buộc: mục 6a AGENTS.md (test viết trước code, tự review theo checklist, bằng chứng là output thật). Mức review: L2.
Implementation Plan phải có thêm: bất biến cần giữ, ca biên và đường lỗi, danh sách test (gồm test âm).
Sau khi mở PR (báo cáo mục 9, ghi "Review: L2" và SHA commit cuối): DỪNG, chờ Claude Code review. Không tự merge.
```

### W06-F-01 · Antigravity · Review L2 · Cần trước: W06-G2-01
```
Bạn là agent Antigravity trong dự án Strata. Đọc AGENTS.md và mục W06-F-01 trong docs/plan/plan.md.

Nhiệm vụ W06-F-01 · Trang Sự kiện nối API thật.
- Thư mục: ui/
- Việc: thay dữ liệu mock của trang Sự kiện bằng client sinh từ OpenAPI; trang chi tiết hiển thị decision trace (điểm từng lớp, Rule ID, vị trí, đoạn input đã che).
- Xong khi: gửi một request bị chặn tới NGINX lab, tra Block ID trên UI ra đúng sự kiện; test Playwright pass.
- Đọc: nginx-module.md › Giao diện quản trị (Sự kiện, Chi tiết sự kiện).
- Lưu ý: vai trò viewer không thấy IP đầy đủ và đoạn input; mọi chuỗi qua i18n.

Bước 1: xác nhận phần Antigravity, tuần hiện tại, W06-G2-01 đã merge.
Bước 2: tạo Implementation Plan rồi DỪNG, chờ tôi duyệt.
Bước 3 (sau khi duyệt): nhánh W06-F-01-events-api, làm, chạy npm lint/test/build và Playwright,
mở trình duyệt tới UI lab thực hiện kịch bản "Xong khi", đính kèm ảnh chụp hoặc bản ghi trình duyệt,
cập nhật mục 0 thành ✅ Done trong PR, báo cáo theo mục 9.
Chuẩn bắt buộc: mục 6a AGENTS.md (test viết trước code, tự review theo checklist, bằng chứng là output thật). Mức review: L2.
Implementation Plan phải có thêm: bất biến cần giữ, ca biên và đường lỗi, danh sách test (gồm test âm).
Sau khi mở PR (báo cáo mục 9, ghi "Review: L2" và SHA commit cuối): DỪNG, chờ Claude Code review. Không tự merge.
```

### W06-S-01 · Antigravity · Review L2 · Cần trước: W06-R-01
```
Bạn là agent Antigravity trong dự án Strata. Đọc AGENTS.md, mục Luồng S › Bộ nhập CRS và mục W06-S-01 trong docs/plan/plan.md.

Nhiệm vụ W06-S-01 · Nhập nhóm injection của CRS.
- Thư mục: tools/strata-import-crs/, rules/crs/
- Việc: nhập nhóm rule CRS 930, 931, 932, 933, 941, 942, 944; ánh xạ @detectSQLi / @detectXSS sang tokenizer của libstrata; ánh xạ anomaly scoring của CRS sang điểm của Strata.
- Xong khi: test go-ftw của các nhóm này pass tối thiểu 90%; có danh sách rule chưa nhập được kèm lý do.
- Lưu ý: mỗi rule có source, upstream_id, upstream_version, license (Apache-2.0), author, action_mode; không sửa rules/schema/.

Bước 1: xác nhận phần Antigravity, tuần hiện tại, W06-R-01 đã merge.
Bước 2: tạo Implementation Plan rồi DỪNG, chờ tôi duyệt.
Bước 3 (sau khi duyệt): nhánh W06-S-01-crs-injection, làm, chạy strata-rules lint/test và go-ftw,
cập nhật mục 0 thành ✅ Done trong PR, báo cáo theo mục 9 kèm bảng tỉ lệ pass theo nhóm.
Chuẩn bắt buộc: mục 6a AGENTS.md (test viết trước code, tự review theo checklist, bằng chứng là output thật). Mức review: L2.
Implementation Plan phải có thêm: bất biến cần giữ, ca biên và đường lỗi, danh sách test (gồm test âm).
Sau khi mở PR (báo cáo mục 9, ghi "Review: L2" và SHA commit cuối): DỪNG, chờ Claude Code review. Không tự merge.
```

### W06-Q-01 · Antigravity · Review L1 · Cần trước: W06-G1-01, W06-G2-01
```
Bạn là agent Antigravity trong dự án Strata. Đọc AGENTS.md và mục W06-Q-01 trong docs/plan/plan.md.

Nhiệm vụ W06-Q-01 · Kiểm tra mất sự kiện.
- Thư mục: tests/e2e/
- Việc: script tạo tải chặn liên tục lên NGINX lab, khởi động lại strata-agent giữa chừng, so sánh số sự kiện gửi đi với số dòng trong ClickHouse.
- Xong khi: số sự kiện gửi bằng số sự kiện nhận; script chạy được bằng một lệnh make.
- Lưu ý: chỉ chạy trên lab.

Bước 1: xác nhận phần Antigravity, tuần hiện tại, W06-G1-01 và W06-G2-01 đã merge.
Bước 2: tạo Implementation Plan rồi DỪNG, chờ tôi duyệt.
Bước 3 (sau khi duyệt): nhánh W06-Q-01-event-loss, làm, chạy script, đính kèm output,
cập nhật mục 0 thành ✅ Done trong PR, báo cáo theo mục 9.
Chuẩn bắt buộc: mục 6a AGENTS.md (test viết trước code, tự review theo checklist, bằng chứng là output thật). Mức review: L1 (không cần Claude Code; CI và tự review là đủ).
```

---

## Tuần 7 · Fail mode, CPU budget, độ bền

### W07-N-01 · Antigravity · Review L3 · Cần trước: W06-N-01
```
Bạn là agent Antigravity trong dự án Strata. Đọc AGENTS.md và mục W07-N-01 trong docs/plan/plan.md.

Nhiệm vụ W07-N-01 · Fail mode, event sink, RST_STREAM.
- Thư mục: connectors/nginx/src/, connectors/nginx/t/
- Việc: ma trận fail mode open/closed; truyền strata_cpu_budget; interface strata_event_sink_t (bản Unix socket); bộ đếm metrics trong shared memory; strata_tx_free idempotent; giữ request sống khi có task thread pool (r->main->blocked, r->aio).
- Xong khi: test 4 loại sự cố × 2 fail mode pass; stream HTTP/2 bị RST giữa lúc gửi body không leak (ASan); internal redirect không inspect lại, không đếm metric 2 lần.
- Đọc: nginx-module.md › Hiệu năng, tài nguyên & fail mode; Trang chặn, Block ID & sự kiện › Giao diện gửi sự kiện; Vòng đời request.
- Lưu ý: strata_event_sink_t nằm trong connector, không đổi strata.h.

Bước 1: xác nhận phần Antigravity, tuần hiện tại, "Cần trước" đã merge.
Bước 2: tạo Implementation Plan rồi DỪNG, chờ tôi duyệt.
Bước 3 (sau khi duyệt): nhánh W07-N-01-fail-mode, làm, chạy prove trên cả 2 bản NGINX và build ASan,
cập nhật mục 0 thành ✅ Done trong PR, báo cáo theo mục 9.
Chuẩn bắt buộc: mục 6a AGENTS.md (test viết trước code, tự review theo checklist, bằng chứng là output thật). Mức review: L3 (khu vực rủi ro cao).
Implementation Plan phải có thêm: bất biến cần giữ, ca biên và đường lỗi, rủi ro bảo mật, danh sách test (gồm test âm và chạy sanitizer / -race).
Kế hoạch sẽ được Claude Code review trước khi tôi duyệt; chỉ bắt đầu code khi tôi trả lời "duyệt".
Sau khi mở PR (báo cáo mục 9, ghi "Review: L3" và SHA commit cuối): DỪNG, chờ Claude Code review. Không tự merge.
```

### W07-R-01 · Antigravity · Review L3 · Cần trước: —
```
Bạn là agent Antigravity trong dự án Strata. Đọc AGENTS.md và mục W07-R-01 trong docs/plan/plan.md.

Nhiệm vụ W07-R-01 · CPU budget hợp tác và cô lập lỗi.
- Thư mục: engine/
- Việc: Hyperscan quét theo khối 8 KB (chế độ streaming), kiểm đồng hồ giữa các khối; parser kiểm đồng hồ sau mỗi N token; trả STRATA_E_BUDGET; catch_unwind cho mọi hàm FFI; tách module tối thiểu (protocol, IP list, rate limit) cho chế độ giảm cấp.
- Xong khi: payload bệnh lý 1 MB → phần vượt budget dưới 100 µs (có benchmark); panic được tiêm → trả STRATA_E_INTERNAL, process không sập.
- Đọc: nginx-module.md › Hiệu năng, tài nguyên & fail mode; Circuit breaker cấp worker (phần chế độ giảm cấp).

Bước 1: xác nhận phần Antigravity, tuần hiện tại.
Bước 2: tạo Implementation Plan rồi DỪNG, chờ tôi duyệt.
Bước 3 (sau khi duyệt): nhánh W07-R-01-cpu-budget, làm, chạy cargo test/clippy/bench,
cập nhật mục 0 thành ✅ Done trong PR, báo cáo theo mục 9.
Chuẩn bắt buộc: mục 6a AGENTS.md (test viết trước code, tự review theo checklist, bằng chứng là output thật). Mức review: L3 (khu vực rủi ro cao).
Implementation Plan phải có thêm: bất biến cần giữ, ca biên và đường lỗi, rủi ro bảo mật, danh sách test (gồm test âm và chạy sanitizer / -race).
Kế hoạch sẽ được Claude Code review trước khi tôi duyệt; chỉ bắt đầu code khi tôi trả lời "duyệt".
Sau khi mở PR (báo cáo mục 9, ghi "Review: L3" và SHA commit cuối): DỪNG, chờ Claude Code review. Không tự merge.
```

### W07-R-02 · Antigravity · Review L2 · Cần trước: —
```
Bạn là agent Antigravity trong dự án Strata. Đọc AGENTS.md, mục Luồng S › Bộ nhập CRS và mục W07-R-02 trong docs/plan/plan.md.

Nhiệm vụ W07-R-02 · Transformation và operator đợt 2.
- Thư mục: engine/
- Việc: transformation jsDecode, cssDecode, cmdLine, utf8toUnicode, base64Decode; operator @validateByteRange, @validateUrlEncoding, @validateUtf8Encoding, @ipMatch, so sánh số.
- Xong khi: khớp 100% test vector so với Coraza.
- Lưu ý: test vector nằm trong repo, test không gọi mạng.

Bước 1: xác nhận phần Antigravity, tuần hiện tại.
Bước 2: tạo Implementation Plan rồi DỪNG, chờ tôi duyệt.
Bước 3 (sau khi duyệt): nhánh W07-R-02-transforms-2, làm, chạy cargo test/clippy,
cập nhật mục 0 thành ✅ Done trong PR, báo cáo theo mục 9.
Chuẩn bắt buộc: mục 6a AGENTS.md (test viết trước code, tự review theo checklist, bằng chứng là output thật). Mức review: L2.
Implementation Plan phải có thêm: bất biến cần giữ, ca biên và đường lỗi, danh sách test (gồm test âm).
Sau khi mở PR (báo cáo mục 9, ghi "Review: L2" và SHA commit cuối): DỪNG, chờ Claude Code review. Không tự merge.
```

### W07-G1-01 · Antigravity · Review L3 · Cần trước: W06-G1-01
```
Bạn là agent Antigravity trong dự án Strata. Đọc AGENTS.md và mục W07-G1-01 trong docs/plan/plan.md.

Nhiệm vụ W07-G1-01 · Độ bền agent.  (Nhiệm vụ nhạy cảm bảo mật: PR cần 2 người review.)
- Thư mục: agent/
- Việc: kết nối lại với backoff lũy thừa 1–60 s có jitter; gia hạn chứng chỉ khi còn 1/3 thời hạn; xử lý Command (ForceShadow, thu chẩn đoán).
- Xong khi: cắt mạng 5 phút bằng toxiproxy → tự nối lại; chứng chỉ gia hạn đúng thời điểm (test với chứng chỉ hạn ngắn); ForceShadow áp dụng trên node trong tối đa 5 giây.
- Đọc: nginx-module.md › Giao thức gRPC agent ↔ control plane.

Bước 1: xác nhận phần Antigravity, tuần hiện tại, "Cần trước" đã merge.
Bước 2: kế hoạch kèm danh sách rủi ro bảo mật và cách test từng rủi ro, rồi DỪNG, chờ tôi duyệt.
Bước 3 (sau khi duyệt): nhánh W07-G1-01-agent-resilience, làm, chạy go test/golangci-lint và test toxiproxy,
cập nhật mục 0 thành ✅ Done trong PR, báo cáo theo mục 9.
Chuẩn bắt buộc: mục 6a AGENTS.md (test viết trước code, tự review theo checklist, bằng chứng là output thật). Mức review: L3 (khu vực rủi ro cao).
Implementation Plan phải có thêm: bất biến cần giữ, ca biên và đường lỗi, rủi ro bảo mật, danh sách test (gồm test âm và chạy sanitizer / -race).
Kế hoạch sẽ được Claude Code review trước khi tôi duyệt; chỉ bắt đầu code khi tôi trả lời "duyệt".
Sau khi mở PR (báo cáo mục 9, ghi "Review: L3" và SHA commit cuối): DỪNG, chờ Claude Code review. Không tự merge.
```

### W07-G2-01 · Antigravity · Review L3 · Cần trước: —
```
Bạn là agent Antigravity trong dự án Strata. Đọc AGENTS.md và mục W07-G2-01 trong docs/plan/plan.md.

Nhiệm vụ W07-G2-01 · Signer KMS, cost unit, điều khiển rollout.  (Nhạy cảm bảo mật: PR cần 2 người review.)
- Thư mục: control-plane/compiler/, control-plane/fleet/
- Việc: ký bundle bằng KMS (Vault transit hoặc HSM, cấu hình qua biến môi trường); compiler tính cost unit, từ chối policy vượt ngân sách kèm tên rule tốn nhất; API rollout :pause, :resume, :abort.
- Xong khi: khóa ký không rời KMS; policy vượt cost bị từ chối 400 với tên rule; 3 thao tác rollout có test.
- Lưu ý: không ghi khóa ra file, log hay test; dùng Vault dev mode trên lab.

Bước 1: xác nhận phần Antigravity, tuần hiện tại.
Bước 2: kế hoạch kèm rủi ro bảo mật và cách test, rồi DỪNG, chờ tôi duyệt.
Bước 3 (sau khi duyệt): nhánh W07-G2-01-kms-signer, làm, chạy go test/golangci-lint,
cập nhật mục 0 thành ✅ Done trong PR, báo cáo theo mục 9.
Chuẩn bắt buộc: mục 6a AGENTS.md (test viết trước code, tự review theo checklist, bằng chứng là output thật). Mức review: L3 (khu vực rủi ro cao).
Implementation Plan phải có thêm: bất biến cần giữ, ca biên và đường lỗi, rủi ro bảo mật, danh sách test (gồm test âm và chạy sanitizer / -race).
Kế hoạch sẽ được Claude Code review trước khi tôi duyệt; chỉ bắt đầu code khi tôi trả lời "duyệt".
Sau khi mở PR (báo cáo mục 9, ghi "Review: L3" và SHA commit cuối): DỪNG, chờ Claude Code review. Không tự merge.
```

### W07-S-01 · Antigravity · Review L2 · Cần trước: —
```
Bạn là agent Antigravity trong dự án Strata. Đọc AGENTS.md, mục Luồng S › Nguồn luật và cách dùng, và mục W07-S-01 trong docs/plan/plan.md.

Nhiệm vụ W07-S-01 · Nhập Sigma, ET Open, danh sách bot.
- Thư mục: tools/strata-import-sigma/, tools/strata-import-et/, rules/
- Việc: nhập Sigma rules/web và ET Open vào dải Rule ID 400000; danh sách bot từ crawler-user-agents vào dải 500000; virtual patch dải 700000 cho stack của route thí điểm.
- Xong khi: mọi rule nhập có author, license, upstream_id; importer ET từ chối SID ngoài 2000000–2099999 (có test); rule Sigma giữ trường author để UI hiển thị.
- Lưu ý: chỉ lấy rule ET dùng nội dung HTTP; Sigma giấy phép DRL 1.1, ET Open dải BSD; ghi vào NOTICE.

Bước 1: xác nhận phần Antigravity, tuần hiện tại.
Bước 2: tạo Implementation Plan rồi DỪNG, chờ tôi duyệt.
Bước 3 (sau khi duyệt): nhánh W07-S-01-import-sigma-et, làm, chạy go test và strata-rules lint/test,
cập nhật mục 0 thành ✅ Done trong PR, báo cáo theo mục 9 kèm số rule nhập theo nguồn.
Chuẩn bắt buộc: mục 6a AGENTS.md (test viết trước code, tự review theo checklist, bằng chứng là output thật). Mức review: L2.
Implementation Plan phải có thêm: bất biến cần giữ, ca biên và đường lỗi, danh sách test (gồm test âm).
Sau khi mở PR (báo cáo mục 9, ghi "Review: L2" và SHA commit cuối): DỪNG, chờ Claude Code review. Không tự merge.
```

### W07-F-01 · Antigravity · Review L1 · Cần trước: —
```
Bạn là agent Antigravity trong dự án Strata. Đọc AGENTS.md và mục W07-F-01 trong docs/plan/plan.md.

Nhiệm vụ W07-F-01 · Trang Fleet.
- Thư mục: ui/
- Việc: hiển thị connector group, node, phiên bản proxy/module/bundle, trạng thái rollout VERIFIED → ACTIVE cập nhật trực tiếp.
- Xong khi: deploy một policy trên lab → thấy từng node chuyển trạng thái trên UI; test Playwright pass.
- Đọc: nginx-module.md › Giao diện quản trị (Fleet).

Bước 1: xác nhận phần Antigravity, tuần hiện tại.
Bước 2: tạo Implementation Plan rồi DỪNG, chờ tôi duyệt.
Bước 3 (sau khi duyệt): nhánh W07-F-01-fleet-page, làm, chạy npm lint/test/build và Playwright,
thực hiện kịch bản "Xong khi" trên trình duyệt lab, đính kèm ảnh chụp hoặc bản ghi,
cập nhật mục 0 thành ✅ Done trong PR, báo cáo theo mục 9.
Chuẩn bắt buộc: mục 6a AGENTS.md (test viết trước code, tự review theo checklist, bằng chứng là output thật). Mức review: L1 (không cần Claude Code; CI và tự review là đủ).
```

### W07-Q-01 · Antigravity · Review L1 · Cần trước: —
```
Bạn là agent Antigravity trong dự án Strata. Đọc AGENTS.md và mục W07-Q-01 trong docs/plan/plan.md.

Nhiệm vụ W07-Q-01 · Phân tích tĩnh cho C.
- Thư mục: cấu hình CI
- Việc: thêm clang-tidy và CodeQL cho connectors/nginx/ vào CI.
- Xong khi: chạy mỗi PR; báo cáo không có cảnh báo mức cao (nếu có thì tạo ticket, không tắt cảnh báo).

Bước 1: xác nhận phần Antigravity, tuần hiện tại.
Bước 2: tạo Implementation Plan rồi DỪNG, chờ tôi duyệt.
Bước 3 (sau khi duyệt): nhánh W07-Q-01-static-analysis, làm, chạy thử trên một PR,
cập nhật mục 0 thành ✅ Done trong PR, báo cáo theo mục 9.
Chuẩn bắt buộc: mục 6a AGENTS.md (test viết trước code, tự review theo checklist, bằng chứng là output thật). Mức review: L1 (không cần Claude Code; CI và tự review là đủ).
```

---

## Tuần 8 · Kiểm thử (1), mức tin cậy rule

### W08-N-01 · Antigravity · Review L2 · Cần trước: W07-N-01
```
Bạn là agent Antigravity trong dự án Strata. Đọc AGENTS.md và mục W08-N-01 trong docs/plan/plan.md.

Nhiệm vụ W08-N-01 · Bộ Test::Nginx đầy đủ.
- Thư mục: connectors/nginx/t/
- Việc: bổ sung test HTTP/2, HTTP/3, subrequest, internal redirect, client ngắt giữa chừng, hot reload dưới tải.
- Xong khi: toàn bộ pass trên cả 2 bản NGINX trong ma trận CI.
- Lưu ý: không sửa code module trừ khi test lộ lỗi; lỗi lộ ra thì ghi ticket và hỏi trước khi sửa.

Bước 1: xác nhận phần Antigravity, tuần hiện tại, "Cần trước" đã merge.
Bước 2: liệt kê các case sẽ viết rồi DỪNG, chờ tôi duyệt.
Bước 3 (sau khi duyệt): nhánh W08-N-01-test-nginx, làm, chạy prove trên cả 2 bản,
cập nhật mục 0 thành ✅ Done trong PR, báo cáo theo mục 9.
Chuẩn bắt buộc: mục 6a AGENTS.md (test viết trước code, tự review theo checklist, bằng chứng là output thật). Mức review: L2.
Implementation Plan phải có thêm: bất biến cần giữ, ca biên và đường lỗi, danh sách test (gồm test âm).
Sau khi mở PR (báo cáo mục 9, ghi "Review: L2" và SHA commit cuối): DỪNG, chờ Claude Code review. Không tự merge.
```

### W08-R-01 · Antigravity · Review L2 · Cần trước: —
```
Bạn là agent Antigravity trong dự án Strata. Đọc AGENTS.md và mục W08-R-01 trong docs/plan/plan.md.

Nhiệm vụ W08-R-01 · Fuzz và differential.
- Thư mục: engine/fuzz/, conformance/
- Việc: target libFuzzer cho lớp FFI; harness differential so sánh cách parse với profile go-net-http và spring; script khởi chạy fuzz ASan 72 giờ trên máy lab riêng.
- Xong khi: fuzz chạy được; tài liệu cách khởi chạy và nơi lưu crash; mọi crash tìm được có ticket.

Bước 1: xác nhận phần Antigravity, tuần hiện tại.
Bước 2: tạo Implementation Plan rồi DỪNG, chờ tôi duyệt.
Bước 3 (sau khi duyệt): nhánh W08-R-01-fuzz, làm, chạy fuzz thử 30 phút,
cập nhật mục 0 thành ✅ Done trong PR, báo cáo theo mục 9.
Chuẩn bắt buộc: mục 6a AGENTS.md (test viết trước code, tự review theo checklist, bằng chứng là output thật). Mức review: L2.
Implementation Plan phải có thêm: bất biến cần giữ, ca biên và đường lỗi, danh sách test (gồm test âm).
Sau khi mở PR (báo cáo mục 9, ghi "Review: L2" và SHA commit cuối): DỪNG, chờ Claude Code review. Không tự merge.
```

### W08-R-02 · Antigravity · Review L3 · Cần trước: —
```
Bạn là agent Antigravity trong dự án Strata. Đọc AGENTS.md, mục Luồng S › Tính năng cho rule trong v1 và mục W08-R-02 trong docs/plan/plan.md.

Nhiệm vụ W08-R-02 · Mức tin cậy của rule.
- Thư mục: engine/, rules/schema/  (nhiệm vụ này ĐƯỢC PHÉP sửa rules/schema/)
- Việc: thêm trường action_mode: block_alone | score vào JSON Schema rule; engine: rule block_alone chặn ngay khi khớp, rule score chỉ cộng điểm.
- Xong khi: test cho cả hai mức; linter báo lỗi rule thiếu action_mode.
- Lưu ý: PR cần duyệt của người luồng S vì đổi schema.

Bước 1: xác nhận phần Antigravity, tuần hiện tại.
Bước 2: tạo Implementation Plan rồi DỪNG, chờ tôi duyệt.
Bước 3 (sau khi duyệt): nhánh W08-R-02-action-mode, làm, chạy cargo test và strata-rules lint,
cập nhật mục 0 thành ✅ Done trong PR, báo cáo theo mục 9.
Chuẩn bắt buộc: mục 6a AGENTS.md (test viết trước code, tự review theo checklist, bằng chứng là output thật). Mức review: L3 (khu vực rủi ro cao).
Implementation Plan phải có thêm: bất biến cần giữ, ca biên và đường lỗi, rủi ro bảo mật, danh sách test (gồm test âm và chạy sanitizer / -race).
Kế hoạch sẽ được Claude Code review trước khi tôi duyệt; chỉ bắt đầu code khi tôi trả lời "duyệt".
Sau khi mở PR (báo cáo mục 9, ghi "Review: L3" và SHA commit cuối): DỪNG, chờ Claude Code review. Không tự merge.
```

### W08-G1-01 · Antigravity · Review L2 · Cần trước: —
```
Bạn là agent Antigravity trong dự án Strata. Đọc AGENTS.md và mục W08-G1-01 trong docs/plan/plan.md.

Nhiệm vụ W08-G1-01 · Test tải Fleet.
- Thư mục: control-plane/fleet/, tests/load/
- Việc: công cụ giả lập 1.000 agent kết nối Connect; đo thời gian BundleAvailable tới đủ 1.000 agent.
- Xong khi: 1.000 agent ổn định; BundleAvailable tới đủ trong dưới 10 giây; báo cáo lưu ở docs/reports/.
- Lưu ý: chỉ chạy trên lab.

Bước 1: xác nhận phần Antigravity, tuần hiện tại.
Bước 2: tạo Implementation Plan rồi DỪNG, chờ tôi duyệt.
Bước 3 (sau khi duyệt): nhánh W08-G1-01-fleet-load, làm, chạy test tải,
cập nhật mục 0 thành ✅ Done trong PR, báo cáo theo mục 9.
Chuẩn bắt buộc: mục 6a AGENTS.md (test viết trước code, tự review theo checklist, bằng chứng là output thật). Mức review: L2.
Implementation Plan phải có thêm: bất biến cần giữ, ca biên và đường lỗi, danh sách test (gồm test âm).
Sau khi mở PR (báo cáo mục 9, ghi "Review: L2" và SHA commit cuối): DỪNG, chờ Claude Code review. Không tự merge.
```

### W08-S-01 · Antigravity · Review L2 · Cần trước: W06-S-01, W07-S-01
```
Bạn là agent Antigravity trong dự án Strata. Đọc AGENTS.md, mục Luồng S › Chỉ tiêu chất lượng và mục W08-S-01 trong docs/plan/plan.md.

Nhiệm vụ W08-S-01 · Chất lượng v0 và pipeline phát hành.
- Thư mục: rules/, tools/strata-rules/
- Việc: chạy toàn bộ test go-ftw của CRS; báo cáo FP/recall theo loại tấn công; lệnh strata-rules release tạo gói signature có version, chữ ký, changelog, file NOTICE.
- Xong khi: go-ftw pass tối thiểu 95%; báo cáo chất lượng lưu ở docs/reports/; gói tạo được trên lab.
- Lưu ý: khóa ký lấy từ biến môi trường, không ghi vào repo.

Bước 1: xác nhận phần Antigravity, tuần hiện tại, "Cần trước" đã merge.
Bước 2: tạo Implementation Plan rồi DỪNG, chờ tôi duyệt.
Bước 3 (sau khi duyệt): nhánh W08-S-01-quality-release, làm, chạy go-ftw và strata-rules,
cập nhật mục 0 thành ✅ Done trong PR, báo cáo theo mục 9.
Chuẩn bắt buộc: mục 6a AGENTS.md (test viết trước code, tự review theo checklist, bằng chứng là output thật). Mức review: L2.
Implementation Plan phải có thêm: bất biến cần giữ, ca biên và đường lỗi, danh sách test (gồm test âm).
Sau khi mở PR (báo cáo mục 9, ghi "Review: L2" và SHA commit cuối): DỪNG, chờ Claude Code review. Không tự merge.
```

### W08-S-02 · Antigravity · Review L1 · Cần trước: W08-R-02
```
Bạn là agent Antigravity trong dự án Strata. Đọc AGENTS.md và mục W08-S-02 trong docs/plan/plan.md.

Nhiệm vụ W08-S-02 · Gán mức tin cậy cho rule.
- Thư mục: rules/
- Việc: gán action_mode cho mọi rule. Chỉ virtual patch, rule protocol mơ hồ và rule độ chính xác cao được gán block_alone; còn lại là score.
- Xong khi: strata-rules lint pass; danh sách rule block_alone kèm lý do nằm trong mô tả PR.
- Lưu ý: PR cần review của SecOps trước khi merge.

Bước 1: xác nhận phần Antigravity, tuần hiện tại, W08-R-02 đã merge.
Bước 2: tạo Implementation Plan (tiêu chí gán) rồi DỪNG, chờ tôi duyệt.
Bước 3 (sau khi duyệt): nhánh W08-S-02-action-mode, làm, chạy strata-rules lint/test,
cập nhật mục 0 thành ✅ Done trong PR, báo cáo theo mục 9.
Chuẩn bắt buộc: mục 6a AGENTS.md (test viết trước code, tự review theo checklist, bằng chứng là output thật). Mức review: L1 (không cần Claude Code; CI và tự review là đủ).
```

### W08-G2-01 · Antigravity · Review L2 · Cần trước: —
```
Bạn là agent Antigravity trong dự án Strata. Đọc AGENTS.md và mục W08-G2-01 trong docs/plan/plan.md.

Nhiệm vụ W08-G2-01 · Test tích hợp khi mạng lỗi.
- Thư mục: tests/e2e/
- Việc: dùng toxiproxy gây trễ, mất gói, ngắt kết nối giữa agent và control plane trong lúc deploy và gửi sự kiện.
- Xong khi: không mất sự kiện, không có bundle hỏng; kết quả lưu ở docs/reports/.
- Lưu ý: chỉ chạy trên lab.

Bước 1: xác nhận phần Antigravity, tuần hiện tại.
Bước 2: tạo Implementation Plan rồi DỪNG, chờ tôi duyệt.
Bước 3 (sau khi duyệt): nhánh W08-G2-01-network-faults, làm, chạy test,
cập nhật mục 0 thành ✅ Done trong PR, báo cáo theo mục 9.
Chuẩn bắt buộc: mục 6a AGENTS.md (test viết trước code, tự review theo checklist, bằng chứng là output thật). Mức review: L2.
Implementation Plan phải có thêm: bất biến cần giữ, ca biên và đường lỗi, danh sách test (gồm test âm).
Sau khi mở PR (báo cáo mục 9, ghi "Review: L2" và SHA commit cuối): DỪNG, chờ Claude Code review. Không tự merge.
```

### W08-F-01 · Antigravity · Review L1 · Cần trước: —
```
Bạn là agent Antigravity trong dự án Strata. Đọc AGENTS.md và mục W08-F-01 trong docs/plan/plan.md.

Nhiệm vụ W08-F-01 · Phân quyền trên UI và xuất CSV.
- Thư mục: ui/
- Việc: ẩn nút theo vai trò; vai trò viewer không thấy IP đầy đủ và đoạn input; mọi bảng xuất được CSV.
- Xong khi: kiểm với cả 4 vai trò (viewer, operator, approver, admin) trên lab; test Playwright cho từng vai trò.

Bước 1: xác nhận phần Antigravity, tuần hiện tại.
Bước 2: tạo Implementation Plan rồi DỪNG, chờ tôi duyệt.
Bước 3 (sau khi duyệt): nhánh W08-F-01-rbac-ui, làm, chạy npm lint/test/build và Playwright,
đăng nhập lần lượt 4 vai trò trên lab, đính kèm ảnh chụp, cập nhật mục 0 thành ✅ Done trong PR, báo cáo theo mục 9.
Chuẩn bắt buộc: mục 6a AGENTS.md (test viết trước code, tự review theo checklist, bằng chứng là output thật). Mức review: L1 (không cần Claude Code; CI và tự review là đủ).
```

### W08-Q-01 · Antigravity · Review L1 · Cần trước: W08-R-01
```
Bạn là agent Antigravity trong dự án Strata. Đọc AGENTS.md và mục W08-Q-01 trong docs/plan/plan.md.

Nhiệm vụ W08-Q-01 · Conformance trong CI.
- Thư mục: cấu hình CI, conformance/
- Việc: chạy corpus conformance v1 trên mỗi PR thay đổi engine/ hoặc connectors/.
- Xong khi: job conformance chạy và chặn PR khi kết quả lệch.

Bước 1: xác nhận phần Antigravity, tuần hiện tại, W08-R-01 đã merge.
Bước 2: tạo Implementation Plan rồi DỪNG, chờ tôi duyệt.
Bước 3 (sau khi duyệt): nhánh W08-Q-01-conformance-ci, làm, chạy thử trên một PR,
cập nhật mục 0 thành ✅ Done trong PR, báo cáo theo mục 9.
Chuẩn bắt buộc: mục 6a AGENTS.md (test viết trước code, tự review theo checklist, bằng chứng là output thật). Mức review: L1 (không cần Claude Code; CI và tự review là đủ).
```

---

## Tuần 9 · Benchmark, soak, staging, gói signature v0

### W09-Q-01 · Antigravity · Review L1 · Cần trước: —
```
Bạn là agent Antigravity trong dự án Strata. Đọc AGENTS.md, nginx-module.md › Hiệu năng, tài nguyên & fail mode, và mục W09-Q-01 trong docs/plan/plan.md.

Nhiệm vụ W09-Q-01 · Benchmark.
- Thư mục: tests/bench/, docs/reports/, docs/decisions/
- Việc: đo p50/p99 và throughput (request nhỏ, 64 KB, 1 MB, HTTP/2) so với NGINX không bật module, bằng wrk2/k6; đo chi phí event socket ở khoảng 50.000 sự kiện/giây.
- Xong khi: báo cáo ở docs/reports/benchmark-w09.md; đề xuất quyết định ring buffer ở docs/decisions/ring-buffer.md (để PO duyệt).

Bước 1: xác nhận phần Antigravity, tuần hiện tại.
Bước 2: tạo Implementation Plan rồi DỪNG, chờ tôi duyệt.
Bước 3 (sau khi duyệt): nhánh W09-Q-01-benchmark, làm, chạy benchmark,
cập nhật mục 0 thành ✅ Done trong PR, báo cáo theo mục 9.
Chuẩn bắt buộc: mục 6a AGENTS.md (test viết trước code, tự review theo checklist, bằng chứng là output thật). Mức review: L1 (không cần Claude Code; CI và tự review là đủ).
```

### W09-Q-02 · Antigravity · Review L1 · Cần trước: —
```
Bạn là agent Antigravity trong dự án Strata. Đọc AGENTS.md và mục W09-Q-02 trong docs/plan/plan.md.

Nhiệm vụ W09-Q-02 · Soak và dựng staging.
- Thư mục: deploy/staging/, tests/soak/
- Việc: soak 24 giờ kèm 1.000 lần đổi bundle; theo dõi bộ nhớ và file descriptor; viết cấu hình dựng staging chỉ deploy từ bản đã tag.
- Xong khi: bộ nhớ và file descriptor không tăng liên tục (đồ thị trong báo cáo); cấu hình staging chạy thử được trên lab (người deploy staging thật).
- Lưu ý: không dùng thông tin đăng nhập production.

Bước 1: xác nhận phần Antigravity, tuần hiện tại.
Bước 2: tạo Implementation Plan rồi DỪNG, chờ tôi duyệt.
Bước 3 (sau khi duyệt): nhánh W09-Q-02-soak-staging, làm, chạy soak,
cập nhật mục 0 thành ✅ Done trong PR, báo cáo theo mục 9.
Chuẩn bắt buộc: mục 6a AGENTS.md (test viết trước code, tự review theo checklist, bằng chứng là output thật). Mức review: L1 (không cần Claude Code; CI và tự review là đủ).
```

### W09-R-01 · Antigravity · Review L3 · Cần trước: W09-Q-01
```
Bạn là agent Antigravity trong dự án Strata. Đọc AGENTS.md, docs/reports/benchmark-w09.md và mục W09-R-01 trong docs/plan/plan.md.

Nhiệm vụ W09-R-01 · Xử lý điểm nóng hiệu năng.
- Thư mục: engine/, connectors/nginx/src/
- Việc: chỉ tối ưu các điểm nóng có trong báo cáo benchmark.
- Xong khi: p99 dưới 1 ms và throughput giảm tối đa 10%, hoặc ticket cụ thể cho phần còn thiếu.

Bước 1: xác nhận phần Antigravity, tuần hiện tại, W09-Q-01 đã merge.
Bước 2: trình bày điểm nóng và cách tối ưu rồi DỪNG, chờ tôi duyệt.
Bước 3 (sau khi duyệt): nhánh W09-R-01-perf, làm, chạy lại benchmark, đính kèm số liệu trước/sau,
cập nhật mục 0 thành ✅ Done trong PR, báo cáo theo mục 9.
Chuẩn bắt buộc: mục 6a AGENTS.md (test viết trước code, tự review theo checklist, bằng chứng là output thật). Mức review: L3 (khu vực rủi ro cao).
Implementation Plan phải có thêm: bất biến cần giữ, ca biên và đường lỗi, rủi ro bảo mật, danh sách test (gồm test âm và chạy sanitizer / -race).
Kế hoạch sẽ được Claude Code review trước khi tôi duyệt; chỉ bắt đầu code khi tôi trả lời "duyệt".
Sau khi mở PR (báo cáo mục 9, ghi "Review: L3" và SHA commit cuối): DỪNG, chờ Claude Code review. Không tự merge.
```

### W09-S-01 · Antigravity · Review L2 · Cần trước: W08-S-01, W08-S-02
```
Bạn là agent Antigravity trong dự án Strata. Đọc AGENTS.md, mục Luồng S và mục W09-S-01 trong docs/plan/plan.md.

Nhiệm vụ W09-S-01 · Phát hành gói signature v0.
- Thư mục: rules/, tools/strata-rules/
- Việc: đóng gói v0 = CRS PL1 + nguồn nhập + rule riêng; staging 7 ngày tự động cho signature mới; quy trình review rule 2 người trong CI.
- Xong khi: gói v0 ký, có changelog và NOTICE; đạt chỉ tiêu Gate A ở mục Chỉ tiêu chất lượng.
- Lưu ý: khóa ký do người cung cấp qua biến môi trường.

Bước 1: xác nhận phần Antigravity, tuần hiện tại, "Cần trước" đã merge.
Bước 2: tạo Implementation Plan rồi DỪNG, chờ tôi duyệt.
Bước 3 (sau khi duyệt): nhánh W09-S-01-signature-v0, làm, chạy strata-rules test,
cập nhật mục 0 thành ✅ Done trong PR, báo cáo theo mục 9 kèm bảng chỉ tiêu.
Chuẩn bắt buộc: mục 6a AGENTS.md (test viết trước code, tự review theo checklist, bằng chứng là output thật). Mức review: L2.
Implementation Plan phải có thêm: bất biến cần giữ, ca biên và đường lỗi, danh sách test (gồm test âm).
Sau khi mở PR (báo cáo mục 9, ghi "Review: L2" và SHA commit cuối): DỪNG, chờ Claude Code review. Không tự merge.
```

### W09-S-02 · Antigravity · Review L2 · Cần trước: —
```
Bạn là agent Antigravity trong dự án Strata. Đọc AGENTS.md và mục W09-S-02 trong docs/plan/plan.md.

Nhiệm vụ W09-S-02 · Bộ sinh biến thể payload.
- Thư mục: tools/strata-mutate/
- Việc: sinh biến thể từ corpus attack: encoding kép, đổi hoa thường, chèn comment SQL, khoảng trắng lạ, Unicode NFC/NFD, tách tham số; chạy qua engine và báo tỉ lệ lách theo loại tấn công.
- Xong khi: báo cáo theo loại tấn công; job hằng đêm trong CI.

Bước 1: xác nhận phần Antigravity, tuần hiện tại.
Bước 2: tạo Implementation Plan rồi DỪNG, chờ tôi duyệt.
Bước 3 (sau khi duyệt): nhánh W09-S-02-mutate, làm, chạy thử,
cập nhật mục 0 thành ✅ Done trong PR, báo cáo theo mục 9.
Chuẩn bắt buộc: mục 6a AGENTS.md (test viết trước code, tự review theo checklist, bằng chứng là output thật). Mức review: L2.
Implementation Plan phải có thêm: bất biến cần giữ, ca biên và đường lỗi, danh sách test (gồm test âm).
Sau khi mở PR (báo cáo mục 9, ghi "Review: L2" và SHA commit cuối): DỪNG, chờ Claude Code review. Không tự merge.
```

### W09-G2-01 · Antigravity · Review L2 · Cần trước: W06-G2-01
```
Bạn là agent Antigravity trong dự án Strata. Đọc AGENTS.md và mục W09-G2-01 trong docs/plan/plan.md.

Nhiệm vụ W09-G2-01 · ClickHouse cho vận hành.
- Thư mục: control-plane/ingest/, control-plane/api/
- Việc: TTL lưu trữ; tối ưu truy vấn.
- Xong khi: tra Block ID dưới 1 giây; tìm kiếm 24 giờ dưới 2 giây trên dữ liệu thử.

Bước 1: xác nhận phần Antigravity, tuần hiện tại.
Bước 2: tạo Implementation Plan rồi DỪNG, chờ tôi duyệt.
Bước 3 (sau khi duyệt): nhánh W09-G2-01-clickhouse-ops, làm, đo trước/sau,
cập nhật mục 0 thành ✅ Done trong PR, báo cáo theo mục 9.
Chuẩn bắt buộc: mục 6a AGENTS.md (test viết trước code, tự review theo checklist, bằng chứng là output thật). Mức review: L2.
Implementation Plan phải có thêm: bất biến cần giữ, ca biên và đường lỗi, danh sách test (gồm test âm).
Sau khi mở PR (báo cáo mục 9, ghi "Review: L2" và SHA commit cuối): DỪNG, chờ Claude Code review. Không tự merge.
```

### W09-F-01 · Antigravity · Review L1 · Cần trước: W07-S-01
```
Bạn là agent Antigravity trong dự án Strata. Đọc AGENTS.md và mục W09-F-01 trong docs/plan/plan.md.

Nhiệm vụ W09-F-01 · Decision trace dễ đọc.
- Thư mục: ui/
- Việc: tô sáng field vi phạm; hiển thị tác giả với rule từ Sigma.
- Xong khi: kịch bản trên lab: request khớp rule Sigma → trang chi tiết có tên tác giả và field được tô sáng; Playwright pass.

Bước 1: xác nhận phần Antigravity, tuần hiện tại, "Cần trước" đã merge.
Bước 2: tạo Implementation Plan rồi DỪNG, chờ tôi duyệt.
Bước 3 (sau khi duyệt): nhánh W09-F-01-trace-ux, làm, chạy npm lint/test/build và Playwright,
đính kèm ảnh chụp trên lab, cập nhật mục 0 thành ✅ Done trong PR, báo cáo theo mục 9.
Chuẩn bắt buộc: mục 6a AGENTS.md (test viết trước code, tự review theo checklist, bằng chứng là output thật). Mức review: L1 (không cần Claude Code; CI và tự review là đủ).
```

---

## Tuần 10 · Đóng gói và shadow · Gate A

### W10-N-01 · Antigravity · Review L2 · Cần trước: W08-N-01
```
Bạn là agent Antigravity trong dự án Strata. Đọc AGENTS.md và mục W10-N-01 trong docs/plan/plan.md.

Nhiệm vụ W10-N-01 · Gói cài và runbook.
- Thư mục: deploy/packaging/, docs/runbook/  (nhiệm vụ này ĐƯỢC PHÉP sửa hai thư mục này)
- Việc: gói deb/rpm nginx-module-strata cho từng phiên bản NGINX, gói strata-agent, image container; runbook tắt module, ép shadow, rollback bundle.
- Xong khi: cài trên VM sạch bằng 1 lệnh; runbook có các bước kiểm chứng sau mỗi thao tác.

Bước 1: xác nhận phần Antigravity, tuần hiện tại, "Cần trước" đã merge.
Bước 2: tạo Implementation Plan rồi DỪNG, chờ tôi duyệt.
Bước 3 (sau khi duyệt): nhánh W10-N-01-packaging, làm, cài thử trên VM lab,
cập nhật mục 0 thành ✅ Done trong PR, báo cáo theo mục 9.
Chuẩn bắt buộc: mục 6a AGENTS.md (test viết trước code, tự review theo checklist, bằng chứng là output thật). Mức review: L2.
Implementation Plan phải có thêm: bất biến cần giữ, ca biên và đường lỗi, danh sách test (gồm test âm).
Sau khi mở PR (báo cáo mục 9, ghi "Review: L2" và SHA commit cuối): DỪNG, chờ Claude Code review. Không tự merge.
```

### W10-G1-01 · **Người** (Antigravity soạn)
```
Bạn là agent Antigravity trong dự án Strata. Đọc AGENTS.md và mục W10-G1-01 trong docs/plan/plan.md.
Soạn (không thực hiện) manifest/Helm và runbook triển khai control plane cho staging và môi trường route thí điểm,
gồm bước enroll node. Không chứa secret thật. Mở PR để người duyệt rồi tự triển khai.
```

### W10-G2-01 · **Người** (Antigravity soạn)
```
Bạn là agent Antigravity trong dự án Strata. Đọc AGENTS.md và mục W10-G2-01 trong docs/plan/plan.md.
Soạn file YAML policy ở chế độ shadow cho 2 route thí điểm dựa trên template api. Không deploy.
Mở PR để người duyệt rồi deploy qua luồng duyệt.
```

### W10-S-01 · Antigravity · Review L1 · Cần trước: W10-G2-01 (đã deploy)
```
Bạn là agent Antigravity trong dự án Strata. Đọc AGENTS.md và mục W10-S-01 trong docs/plan/plan.md.

Nhiệm vụ W10-S-01 · Theo dõi FP trong shadow.
- Thư mục: control-plane/api/ (truy vấn), hoặc dashboard trong deploy/
- Việc: truy vấn hoặc dashboard liệt kê Event ID theo Rule ID mỗi ngày.
- Xong khi: bảng FP theo Rule ID cập nhật hằng ngày.
- Lưu ý: chỉ đọc dữ liệu; không sửa rule.

Bước 1: xác nhận phần Antigravity, tuần hiện tại.
Bước 2: tạo Implementation Plan rồi DỪNG, chờ tôi duyệt.
Bước 3 (sau khi duyệt): nhánh W10-S-01-fp-tracking, làm,
cập nhật mục 0 thành ✅ Done trong PR, báo cáo theo mục 9.
Chuẩn bắt buộc: mục 6a AGENTS.md (test viết trước code, tự review theo checklist, bằng chứng là output thật). Mức review: L1 (không cần Claude Code; CI và tự review là đủ).
```

### W10-Q-01 · Antigravity · Review L1 · Cần trước: —
```
Bạn là agent Antigravity trong dự án Strata. Đọc AGENTS.md và mục W10-Q-01 trong docs/plan/plan.md.

Nhiệm vụ W10-Q-01 · Giám sát.
- Thư mục: deploy/monitoring/
- Việc: dashboard Grafana và cảnh báo VictoriaMetrics cho module, agent, control plane (request theo action, latency engine, fail mode, breaker, bundle version, sự kiện bị bỏ).
- Xong khi: dashboard import được trên lab; mỗi cảnh báo có runbook liên kết.

Bước 1: xác nhận phần Antigravity, tuần hiện tại.
Bước 2: tạo Implementation Plan rồi DỪNG, chờ tôi duyệt.
Bước 3 (sau khi duyệt): nhánh W10-Q-01-monitoring, làm, đính kèm ảnh dashboard trên lab,
cập nhật mục 0 thành ✅ Done trong PR, báo cáo theo mục 9.
Chuẩn bắt buộc: mục 6a AGENTS.md (test viết trước code, tự review theo checklist, bằng chứng là output thật). Mức review: L1 (không cần Claude Code; CI và tự review là đủ).
```

### W10-F-01 · Antigravity · Review L1 · Cần trước: —
```
Bạn là agent Antigravity trong dự án Strata. Đọc AGENTS.md và mục W10-F-01 trong docs/plan/plan.md.

Nhiệm vụ W10-F-01 · Trang Tổng quan v0.
- Thư mục: ui/
- Việc: request bị chặn theo giờ, top rule, top route từ dữ liệu thật.
- Xong khi: hiển thị đúng dữ liệu lab; Playwright pass.

Bước 1: xác nhận phần Antigravity, tuần hiện tại.
Bước 2: tạo Implementation Plan rồi DỪNG, chờ tôi duyệt.
Bước 3 (sau khi duyệt): nhánh W10-F-01-overview, làm, chạy npm lint/test/build và Playwright,
đính kèm ảnh chụp trên lab, cập nhật mục 0 thành ✅ Done trong PR, báo cáo theo mục 9.
Chuẩn bắt buộc: mục 6a AGENTS.md (test viết trước code, tự review theo checklist, bằng chứng là output thật). Mức review: L1 (không cần Claude Code; CI và tự review là đủ).
```

**Gate A** · Người.

---

## Tuần 11 · Circuit breaker, canary 1%

### W11-N-01 · Antigravity · Review L3 · Cần trước: W07-N-01, W07-R-01
```
Bạn là agent Antigravity trong dự án Strata. Đọc AGENTS.md, nginx-module.md › Circuit breaker cấp worker, và mục W11-N-01 trong docs/plan/plan.md.

Nhiệm vụ W11-N-01 · Circuit breaker cấp worker.  (Nhạy cảm bảo mật: PR cần 2 người review.)
- Thư mục: connectors/nginx/src/, connectors/nginx/t/
- Việc: trạng thái Closed / Open / Half-open; directive strata_breaker, strata_breaker_threshold, strata_breaker_action degrade | reject; chỉ tính lỗi nội bộ của engine, KHÔNG tính vượt budget.
- Xong khi: tiêm panic hàng loạt → breaker mở trong 10 giây và chạy giảm cấp; half-open tự đóng khi hết lỗi; payload nặng vượt budget không làm breaker mở (có test).

Bước 1: xác nhận phần Antigravity, tuần hiện tại, "Cần trước" đã merge.
Bước 2: kế hoạch kèm rủi ro bị lợi dụng để mở breaker và cách test, rồi DỪNG, chờ tôi duyệt.
Bước 3 (sau khi duyệt): nhánh W11-N-01-breaker, làm, chạy prove trên 2 bản NGINX,
cập nhật mục 0 thành ✅ Done trong PR, báo cáo theo mục 9.
Chuẩn bắt buộc: mục 6a AGENTS.md (test viết trước code, tự review theo checklist, bằng chứng là output thật). Mức review: L3 (khu vực rủi ro cao).
Implementation Plan phải có thêm: bất biến cần giữ, ca biên và đường lỗi, rủi ro bảo mật, danh sách test (gồm test âm và chạy sanitizer / -race).
Kế hoạch sẽ được Claude Code review trước khi tôi duyệt; chỉ bắt đầu code khi tôi trả lời "duyệt".
Sau khi mở PR (báo cáo mục 9, ghi "Review: L3" và SHA commit cuối): DỪNG, chờ Claude Code review. Không tự merge.
```

### W11-R-01 · Antigravity · Review L2 · Cần trước: —
```
Bạn là agent Antigravity trong dự án Strata. Đọc AGENTS.md, nginx-module.md › Bật enforce theo canary, và mục W11-R-01 trong docs/plan/plan.md.

Nhiệm vụ W11-R-01 · Chọn nhóm canary và lõi replay.
- Thư mục: engine/
- Việc: hash ổn định (identity hoặc IP, tên policy) để chọn nhóm canary; lõi replay chạy engine trên request đã lưu dạng Parquet.
- Xong khi: cùng client luôn rơi vào cùng nhóm (test); replay 1 triệu request dưới 10 phút trên lab.

Bước 1: xác nhận phần Antigravity, tuần hiện tại.
Bước 2: tạo Implementation Plan rồi DỪNG, chờ tôi duyệt.
Bước 3 (sau khi duyệt): nhánh W11-R-01-canary-replay, làm, chạy cargo test và đo replay,
cập nhật mục 0 thành ✅ Done trong PR, báo cáo theo mục 9.
Chuẩn bắt buộc: mục 6a AGENTS.md (test viết trước code, tự review theo checklist, bằng chứng là output thật). Mức review: L2.
Implementation Plan phải có thêm: bất biến cần giữ, ca biên và đường lỗi, danh sách test (gồm test âm).
Sau khi mở PR (báo cáo mục 9, ghi "Review: L2" và SHA commit cuối): DỪNG, chờ Claude Code review. Không tự merge.
```

### W11-G1-01 · Antigravity · Review L3 · Cần trước: W07-G1-01
```
Bạn là agent Antigravity trong dự án Strata. Đọc AGENTS.md, nginx-module.md › Bật enforce theo canary › Tự fallback hai tầng, và mục W11-G1-01 trong docs/plan/plan.md.

Nhiệm vụ W11-G1-01 · Tự fallback tại node.
- Thư mục: agent/
- Việc: đọc metrics shared memory mỗi 5 giây; tỉ lệ chặn của policy vượt ngưỡng (mặc định gấp 3 mức shadow) hoặc lỗi engine/budget tăng đột biến → ghi cờ force-shadow cho policy vào control file.
- Xong khi: giả lập tỉ lệ chặn tăng gấp 3 → policy về shadow trong tối đa 6 giây, không cần control plane.

Bước 1: xác nhận phần Antigravity, tuần hiện tại, "Cần trước" đã merge.
Bước 2: tạo Implementation Plan rồi DỪNG, chờ tôi duyệt.
Bước 3 (sau khi duyệt): nhánh W11-G1-01-local-fallback, làm, chạy go test,
cập nhật mục 0 thành ✅ Done trong PR, báo cáo theo mục 9.
Chuẩn bắt buộc: mục 6a AGENTS.md (test viết trước code, tự review theo checklist, bằng chứng là output thật). Mức review: L3 (khu vực rủi ro cao).
Implementation Plan phải có thêm: bất biến cần giữ, ca biên và đường lỗi, rủi ro bảo mật, danh sách test (gồm test âm và chạy sanitizer / -race).
Kế hoạch sẽ được Claude Code review trước khi tôi duyệt; chỉ bắt đầu code khi tôi trả lời "duyệt".
Sau khi mở PR (báo cáo mục 9, ghi "Review: L3" và SHA commit cuối): DỪNG, chờ Claude Code review. Không tự merge.
```

### W11-G2-01 · Antigravity · Review L2 · Cần trước: —
```
Bạn là agent Antigravity trong dự án Strata. Đọc AGENTS.md và mục W11-G2-01 trong docs/plan/plan.md.

Nhiệm vụ W11-G2-01 · Định dạng traffic mẫu cho replay.
- Thư mục: control-plane/replay/
- Việc: định dạng Parquet lưu request đã ẩn danh (chỉ cấu trúc + hash, không giá trị gốc của field nhạy cảm); lưu vào MinIO.
- Xong khi: định dạng có tài liệu ở docs/spec/replay-format.md; ghi/đọc được từ MinIO.
- Lưu ý: định dạng phải được pháp chế duyệt trước khi merge.

Bước 1: xác nhận phần Antigravity, tuần hiện tại.
Bước 2: tạo Implementation Plan rồi DỪNG, chờ tôi duyệt.
Bước 3 (sau khi duyệt): nhánh W11-G2-01-replay-format, làm, chạy go test,
cập nhật mục 0 thành ✅ Done trong PR, báo cáo theo mục 9.
Chuẩn bắt buộc: mục 6a AGENTS.md (test viết trước code, tự review theo checklist, bằng chứng là output thật). Mức review: L2.
Implementation Plan phải có thêm: bất biến cần giữ, ca biên và đường lỗi, danh sách test (gồm test âm).
Sau khi mở PR (báo cáo mục 9, ghi "Review: L2" và SHA commit cuối): DỪNG, chờ Claude Code review. Không tự merge.
```

### W11-S-01 · Antigravity · Review L1 · Cần trước: W10-S-01 (sau ít nhất 5 ngày shadow)
```
Bạn là agent Antigravity trong dự án Strata. Đọc AGENTS.md và mục W11-S-01 trong docs/plan/plan.md.

Nhiệm vụ W11-S-01 · Xử lý FP sau tuần shadow.
- Thư mục: rules/, corpus/
- Việc: với mỗi Rule ID có FP trong shadow, đề xuất chỉnh rule hoặc exception; bổ sung corpus benign từ traffic thật đã ẩn danh; phát hành pack v0.1.
- Xong khi: mọi Rule ID có FP đều có xử lý; strata-rules test pass; pack v0.1 tạo được.
- Lưu ý: chỉ đọc sự kiện shadow; mọi thay đổi rule đi qua PR bình thường.

Bước 1: xác nhận phần Antigravity, tuần hiện tại.
Bước 2: tạo Implementation Plan (danh sách Rule ID và cách xử lý) rồi DỪNG, chờ tôi duyệt.
Bước 3 (sau khi duyệt): nhánh W11-S-01-shadow-fp, làm, chạy strata-rules lint/test,
cập nhật mục 0 thành ✅ Done trong PR, báo cáo theo mục 9.
Chuẩn bắt buộc: mục 6a AGENTS.md (test viết trước code, tự review theo checklist, bằng chứng là output thật). Mức review: L1 (không cần Claude Code; CI và tự review là đủ).
```

### W11-F-01 · Antigravity · Review L1 · Cần trước: —
```
Bạn là agent Antigravity trong dự án Strata. Đọc AGENTS.md, strata-overview.md › Mô hình policy & rule, và mục W11-F-01 trong docs/plan/plan.md.

Nhiệm vụ W11-F-01 · Policy editor (phần 1).
- Thư mục: ui/
- Việc: sửa policy dạng form và YAML song song, hai dạng đồng bộ; lưu thành bản nháp.
- Xong khi: sửa ở form → YAML đổi theo và ngược lại; lưu bản nháp qua API; Playwright pass.

Bước 1: xác nhận phần Antigravity, tuần hiện tại.
Bước 2: tạo Implementation Plan rồi DỪNG, chờ tôi duyệt.
Bước 3 (sau khi duyệt): nhánh W11-F-01-policy-editor, làm, chạy npm lint/test/build và Playwright,
đính kèm ảnh chụp trên lab, cập nhật mục 0 thành ✅ Done trong PR, báo cáo theo mục 9.
Chuẩn bắt buộc: mục 6a AGENTS.md (test viết trước code, tự review theo checklist, bằng chứng là output thật). Mức review: L1 (không cần Claude Code; CI và tự review là đủ).
```

**Canary 1%** · Người, sau khi W11-S-01 merge.

---

## Tuần 12 · Canary 5%, fallback toàn cụm, tắt rule khẩn cấp

### W12-R-02 · Antigravity · Review L3 · Cần trước: —
```
Bạn là agent Antigravity trong dự án Strata. Đọc AGENTS.md, nginx-module.md › Ranh giới FFI, và mục W12-R-02 trong docs/plan/plan.md.

Nhiệm vụ W12-R-02 · Tắt rule khẩn cấp trong engine.
- Thư mục: engine/, engine/ffi/strata.h  (nhiệm vụ này ĐƯỢC PHÉP THÊM hàm vào strata.h)
- Việc: thêm hàm strata_engine_disable_rules để bỏ qua danh sách Rule ID mà không nạp lại bundle; tăng minor ABI, không sửa hàm cũ; cập nhật mục Ranh giới FFI trong docs/design/nginx-module.md.
- Xong khi: rule bị tắt không còn khớp; danh sách rỗng → hành vi như cũ; benchmark không đổi.

Bước 1: xác nhận phần Antigravity, tuần hiện tại.
Bước 2: trình bày chữ ký hàm và kế hoạch rồi DỪNG, chờ tôi duyệt.
Bước 3 (sau khi duyệt): nhánh W12-R-02-disable-rules, làm, chạy cargo test/bench, gắn nhãn interface-change cho PR,
cập nhật mục 0 thành ✅ Done trong PR, báo cáo theo mục 9.
Chuẩn bắt buộc: mục 6a AGENTS.md (test viết trước code, tự review theo checklist, bằng chứng là output thật). Mức review: L3 (khu vực rủi ro cao).
Implementation Plan phải có thêm: bất biến cần giữ, ca biên và đường lỗi, rủi ro bảo mật, danh sách test (gồm test âm và chạy sanitizer / -race).
Kế hoạch sẽ được Claude Code review trước khi tôi duyệt; chỉ bắt đầu code khi tôi trả lời "duyệt".
Sau khi mở PR (báo cáo mục 9, ghi "Review: L3" và SHA commit cuối): DỪNG, chờ Claude Code review. Không tự merge.
```

### W12-G1-02 · Antigravity · Review L3 · Cần trước: —
```
Bạn là agent Antigravity trong dự án Strata. Đọc AGENTS.md và mục W12-G1-02 trong docs/plan/plan.md.

Nhiệm vụ W12-G1-02 · Lệnh tắt / bật rule.
- Thư mục: proto/, agent/  (nhiệm vụ này ĐƯỢC PHÉP thêm vào fleet.proto)
- Việc: thêm Command DisableRules / EnableRules vào fleet.proto; agent ghi danh sách vào control file theo seqlock.
- Xong khi: lệnh tới toàn bộ node trong dưới 10 giây (test trên lab); buf lint pass.
- Lưu ý: PR cần duyệt của G2; gắn nhãn interface-change.

Bước 1: xác nhận phần Antigravity, tuần hiện tại.
Bước 2: trình bày thay đổi proto rồi DỪNG, chờ tôi duyệt.
Bước 3 (sau khi duyệt): nhánh W12-G1-02-disable-command, làm, chạy buf lint/generate và go test,
cập nhật mục 0 thành ✅ Done trong PR, báo cáo theo mục 9.
Chuẩn bắt buộc: mục 6a AGENTS.md (test viết trước code, tự review theo checklist, bằng chứng là output thật). Mức review: L3 (khu vực rủi ro cao).
Implementation Plan phải có thêm: bất biến cần giữ, ca biên và đường lỗi, rủi ro bảo mật, danh sách test (gồm test âm và chạy sanitizer / -race).
Kế hoạch sẽ được Claude Code review trước khi tôi duyệt; chỉ bắt đầu code khi tôi trả lời "duyệt".
Sau khi mở PR (báo cáo mục 9, ghi "Review: L3" và SHA commit cuối): DỪNG, chờ Claude Code review. Không tự merge.
```

### W12-N-02 · Antigravity · Review L3 · Cần trước: W12-R-02, W12-G1-02
```
Bạn là agent Antigravity trong dự án Strata. Đọc AGENTS.md và mục W12-N-02 trong docs/plan/plan.md.

Nhiệm vụ W12-N-02 · Áp dụng danh sách rule bị tắt.
- Thư mục: connectors/nginx/src/, connectors/nginx/t/
- Việc: đọc danh sách rule bị tắt từ control file và gọi strata_engine_disable_rules.
- Xong khi: agent ghi danh sách → mọi worker áp dụng trong tối đa 1 giây.

Bước 1: xác nhận phần Antigravity, tuần hiện tại, "Cần trước" đã merge.
Bước 2: tạo Implementation Plan rồi DỪNG, chờ tôi duyệt.
Bước 3 (sau khi duyệt): nhánh W12-N-02-apply-disabled, làm, chạy prove,
cập nhật mục 0 thành ✅ Done trong PR, báo cáo theo mục 9.
Chuẩn bắt buộc: mục 6a AGENTS.md (test viết trước code, tự review theo checklist, bằng chứng là output thật). Mức review: L3 (khu vực rủi ro cao).
Implementation Plan phải có thêm: bất biến cần giữ, ca biên và đường lỗi, rủi ro bảo mật, danh sách test (gồm test âm và chạy sanitizer / -race).
Kế hoạch sẽ được Claude Code review trước khi tôi duyệt; chỉ bắt đầu code khi tôi trả lời "duyệt".
Sau khi mở PR (báo cáo mục 9, ghi "Review: L3" và SHA commit cuối): DỪNG, chờ Claude Code review. Không tự merge.
```

### W12-N-01 · Antigravity · Review L3 · Cần trước: W11-G2-01
```
Bạn là agent Antigravity trong dự án Strata. Đọc AGENTS.md, docs/spec/replay-format.md và mục W12-N-01 trong docs/plan/plan.md.

Nhiệm vụ W12-N-01 · Lấy mẫu traffic cho replay.
- Thư mục: connectors/nginx/src/, engine/
- Việc: qua event sink, lấy mẫu mặc định 1% request, ẩn danh ngay tại connector theo đúng định dạng replay.
- Xong khi: mẫu đúng định dạng; test chứng minh không lưu giá trị gốc của field nhạy cảm.

Bước 1: xác nhận phần Antigravity, tuần hiện tại, "Cần trước" đã merge.
Bước 2: tạo Implementation Plan rồi DỪNG, chờ tôi duyệt.
Bước 3 (sau khi duyệt): nhánh W12-N-01-replay-sampling, làm, chạy prove và cargo test,
cập nhật mục 0 thành ✅ Done trong PR, báo cáo theo mục 9.
Chuẩn bắt buộc: mục 6a AGENTS.md (test viết trước code, tự review theo checklist, bằng chứng là output thật). Mức review: L3 (khu vực rủi ro cao).
Implementation Plan phải có thêm: bất biến cần giữ, ca biên và đường lỗi, rủi ro bảo mật, danh sách test (gồm test âm và chạy sanitizer / -race).
Kế hoạch sẽ được Claude Code review trước khi tôi duyệt; chỉ bắt đầu code khi tôi trả lời "duyệt".
Sau khi mở PR (báo cáo mục 9, ghi "Review: L3" và SHA commit cuối): DỪNG, chờ Claude Code review. Không tự merge.
```

### W12-R-01 · Antigravity · Review L2 · Cần trước: W11-R-01
```
Bạn là agent Antigravity trong dự án Strata. Đọc AGENTS.md và mục W12-R-01 trong docs/plan/plan.md.

Nhiệm vụ W12-R-01 · Replay runner và so sánh differential.
- Thư mục: engine/, conformance/
- Việc: chạy bundle nháp trên corpus, trả FP/FN theo route; harness so sánh Strata với Coraza + CRS trên cùng traffic.
- Xong khi: báo cáo replay cho một bản nháp; danh sách khác biệt với Coraza có ticket.

Bước 1: xác nhận phần Antigravity, tuần hiện tại, "Cần trước" đã merge.
Bước 2: tạo Implementation Plan rồi DỪNG, chờ tôi duyệt.
Bước 3 (sau khi duyệt): nhánh W12-R-01-replay-runner, làm, chạy thử,
cập nhật mục 0 thành ✅ Done trong PR, báo cáo theo mục 9.
Chuẩn bắt buộc: mục 6a AGENTS.md (test viết trước code, tự review theo checklist, bằng chứng là output thật). Mức review: L2.
Implementation Plan phải có thêm: bất biến cần giữ, ca biên và đường lỗi, danh sách test (gồm test âm).
Sau khi mở PR (báo cáo mục 9, ghi "Review: L2" và SHA commit cuối): DỪNG, chờ Claude Code review. Không tự merge.
```

### W12-G1-01 · Antigravity · Review L3 · Cần trước: W11-G1-01
```
Bạn là agent Antigravity trong dự án Strata. Đọc AGENTS.md và mục W12-G1-01 trong docs/plan/plan.md.

Nhiệm vụ W12-G1-01 · Hoàn thiện fallback tại node.
- Thư mục: agent/
- Việc: test tự động cho mọi ngưỡng; cờ force-shadow chỉ được gỡ khi có lệnh từ control plane.
- Xong khi: test pass; tài liệu ngưỡng trong README của agent.

Bước 1: xác nhận phần Antigravity, tuần hiện tại, "Cần trước" đã merge.
Bước 2: tạo Implementation Plan rồi DỪNG, chờ tôi duyệt.
Bước 3 (sau khi duyệt): nhánh W12-G1-01-fallback-final, làm, chạy go test,
cập nhật mục 0 thành ✅ Done trong PR, báo cáo theo mục 9.
Chuẩn bắt buộc: mục 6a AGENTS.md (test viết trước code, tự review theo checklist, bằng chứng là output thật). Mức review: L3 (khu vực rủi ro cao).
Implementation Plan phải có thêm: bất biến cần giữ, ca biên và đường lỗi, rủi ro bảo mật, danh sách test (gồm test âm và chạy sanitizer / -race).
Kế hoạch sẽ được Claude Code review trước khi tôi duyệt; chỉ bắt đầu code khi tôi trả lời "duyệt".
Sau khi mở PR (báo cáo mục 9, ghi "Review: L3" và SHA commit cuối): DỪNG, chờ Claude Code review. Không tự merge.
```

### W12-G2-01 · Antigravity · Review L3 · Cần trước: —
```
Bạn là agent Antigravity trong dự án Strata. Đọc AGENTS.md, nginx-module.md › Bật enforce theo canary, và mục W12-G2-01 trong docs/plan/plan.md.

Nhiệm vụ W12-G2-01 · Giám sát canary toàn cụm.
- Thư mục: control-plane/fleet/
- Việc: so sánh nhóm canary với nhóm shadow (5xx upstream, p99, tỉ lệ chặn); vượt ngưỡng → gửi ForceShadow tới mọi node của group, dừng rollout, báo người duyệt.
- Xong khi: giả lập policy chặn nhầm hàng loạt trên lab → toàn cụm về shadow trong dưới 1 phút.

Bước 1: xác nhận phần Antigravity, tuần hiện tại.
Bước 2: tạo Implementation Plan rồi DỪNG, chờ tôi duyệt.
Bước 3 (sau khi duyệt): nhánh W12-G2-01-canary-monitor, làm, chạy go test và kịch bản lab,
cập nhật mục 0 thành ✅ Done trong PR, báo cáo theo mục 9.
Chuẩn bắt buộc: mục 6a AGENTS.md (test viết trước code, tự review theo checklist, bằng chứng là output thật). Mức review: L3 (khu vực rủi ro cao).
Implementation Plan phải có thêm: bất biến cần giữ, ca biên và đường lỗi, rủi ro bảo mật, danh sách test (gồm test âm và chạy sanitizer / -race).
Kế hoạch sẽ được Claude Code review trước khi tôi duyệt; chỉ bắt đầu code khi tôi trả lời "duyệt".
Sau khi mở PR (báo cáo mục 9, ghi "Review: L3" và SHA commit cuối): DỪNG, chờ Claude Code review. Không tự merge.
```

### W12-G2-02 · Antigravity · Review L3 · Cần trước: W12-G1-02
```
Bạn là agent Antigravity trong dự án Strata. Đọc AGENTS.md và mục W12-G2-02 trong docs/plan/plan.md.

Nhiệm vụ W12-G2-02 · API tắt rule khẩn cấp.  (Nhạy cảm bảo mật: PR cần 2 người review.)
- Thư mục: control-plane/api/, control-plane/rules/
- Việc: POST /v1/rules/{rule_id}:emergencyDisable và :enable theo connector group; bắt buộc lý do; ghi audit; gửi Command DisableRules / EnableRules qua Fleet.
- Xong khi: chỉ vai trò từ operator trở lên gọi được (test); audit ghi đủ người, lý do, phạm vi.
- Lưu ý: dùng middleware RBAC và audit có sẵn, không tự viết lại.

Bước 1: xác nhận phần Antigravity, tuần hiện tại, W12-G1-02 đã merge.
Bước 2: tạo Implementation Plan kèm rủi ro bảo mật và cách test, rồi DỪNG, chờ tôi duyệt.
Bước 3 (sau khi duyệt): nhánh W12-G2-02-emergency-disable, làm, chạy go test/golangci-lint,
cập nhật mục 0 thành ✅ Done trong PR, báo cáo theo mục 9.
Chuẩn bắt buộc: mục 6a AGENTS.md (test viết trước code, tự review theo checklist, bằng chứng là output thật). Mức review: L3 (khu vực rủi ro cao).
Implementation Plan phải có thêm: bất biến cần giữ, ca biên và đường lỗi, rủi ro bảo mật, danh sách test (gồm test âm và chạy sanitizer / -race).
Kế hoạch sẽ được Claude Code review trước khi tôi duyệt; chỉ bắt đầu code khi tôi trả lời "duyệt".
Sau khi mở PR (báo cáo mục 9, ghi "Review: L3" và SHA commit cuối): DỪNG, chờ Claude Code review. Không tự merge.
```

### W12-S-01 · Antigravity · Review L2 · Cần trước: W12-R-01
```
Bạn là agent Antigravity trong dự án Strata. Đọc AGENTS.md và mục W12-S-01 trong docs/plan/plan.md.

Nhiệm vụ W12-S-01 · Sửa lỗi bộ nhập từ differential.
- Thư mục: tools/strata-import-crs/, rules/crs/
- Việc: với mỗi khác biệt Strata vs Coraza do bộ nhập gây ra, sửa importer hoặc ghi lý do.
- Xong khi: mọi ticket khác biệt đã đóng hoặc có lý do; go-ftw không giảm.

Bước 1: xác nhận phần Antigravity, tuần hiện tại, W12-R-01 đã merge.
Bước 2: tạo Implementation Plan rồi DỪNG, chờ tôi duyệt.
Bước 3 (sau khi duyệt): nhánh W12-S-01-importer-fixes, làm, chạy go test và go-ftw,
cập nhật mục 0 thành ✅ Done trong PR, báo cáo theo mục 9.
Chuẩn bắt buộc: mục 6a AGENTS.md (test viết trước code, tự review theo checklist, bằng chứng là output thật). Mức review: L2.
Implementation Plan phải có thêm: bất biến cần giữ, ca biên và đường lỗi, danh sách test (gồm test âm).
Sau khi mở PR (báo cáo mục 9, ghi "Review: L2" và SHA commit cuối): DỪNG, chờ Claude Code review. Không tự merge.
```

### W12-F-01 · Antigravity · Review L1 · Cần trước: W11-F-01
```
Bạn là agent Antigravity trong dự án Strata. Đọc AGENTS.md và mục W12-F-01 trong docs/plan/plan.md.

Nhiệm vụ W12-F-01 · Diff giữa các version.
- Thư mục: ui/
- Việc: chọn 2 version policy → xem diff theo từng khối.
- Xong khi: diff đúng trên dữ liệu lab; Playwright pass.

Bước 1: xác nhận phần Antigravity, tuần hiện tại, W11-F-01 đã merge.
Bước 2: tạo Implementation Plan rồi DỪNG, chờ tôi duyệt.
Bước 3 (sau khi duyệt): nhánh W12-F-01-policy-diff, làm, chạy npm lint/test/build và Playwright,
đính kèm ảnh chụp trên lab, cập nhật mục 0 thành ✅ Done trong PR, báo cáo theo mục 9.
Chuẩn bắt buộc: mục 6a AGENTS.md (test viết trước code, tự review theo checklist, bằng chứng là output thật). Mức review: L1 (không cần Claude Code; CI và tự review là đủ).
```

**Canary 5%** · Người, khi đạt điều kiện bậc 1.

---

## Tuần 13 · Replay và luồng duyệt

### W13-N-01 · Antigravity · Review L3 · Cần trước: —
```
Bạn là agent Antigravity trong dự án Strata. Đọc AGENTS.md và mục W13-N-01 trong docs/plan/plan.md.

Nhiệm vụ W13-N-01 · Sửa lỗi từ canary.
- Thư mục: connectors/nginx/
- Việc: tự thu thập lỗi của module phát sinh trong canary rồi sửa. Nguồn cần tự đọc:
  (1) issue trên repo có nhãn canary hoặc module-nginx đang mở (gh issue list);
  (2) báo cáo canary đã có trong docs/reports/ (canary-*.md) và log CI của các lần chạy e2e gần nhất;
  (3) dựng lại kịch bản canary trên lab (make lab-up, replay traffic mẫu, bật 1% → 5% → 25%), đọc error log NGINX,
      log strata-agent, metrics strata_breaker_state, strata_budget_exceeded, fail mode, lỗi engine;
  (4) sự kiện có action = error trên control plane của lab (POST /v1/events:search).
- Xong khi: có danh sách lỗi đã phân loại cao / trung bình / thấp kèm bằng chứng; mọi lỗi mức cao đã sửa, mỗi lỗi có test hồi quy.
  Nếu không tìm thấy lỗi nào: báo cáo các nguồn đã kiểm, kết luận "không có lỗi", đánh dấu nhiệm vụ ✅ Done.
- Lưu ý: chỉ làm trên lab. Không kết nối staging hay production; nếu nghi có lỗi chỉ thấy được ở staging, ghi vào báo cáo kèm lệnh để người kiểm tra, không tự chạy.

Bước 1: xác nhận phần Antigravity, tuần hiện tại.
Bước 2: thu thập từ 4 nguồn trên, trình bày danh sách lỗi và kế hoạch sửa từng lỗi mức cao, rồi DỪNG, chờ tôi duyệt.
Bước 3 (sau khi duyệt): nhánh W13-N-01-canary-fixes, làm, chạy prove trên 2 bản NGINX,
cập nhật mục 0 thành ✅ Done trong PR, báo cáo theo mục 9 kèm danh sách lỗi.
Chuẩn bắt buộc: mục 6a AGENTS.md (test viết trước code, tự review theo checklist, bằng chứng là output thật). Mức review: L3 (khu vực rủi ro cao).
Implementation Plan phải có thêm: bất biến cần giữ, ca biên và đường lỗi, rủi ro bảo mật, danh sách test (gồm test âm và chạy sanitizer / -race).
Kế hoạch sẽ được Claude Code review trước khi tôi duyệt; chỉ bắt đầu code khi tôi trả lời "duyệt".
Sau khi mở PR (báo cáo mục 9, ghi "Review: L3" và SHA commit cuối): DỪNG, chờ Claude Code review. Không tự merge.
```

### W13-R-02 · Antigravity · Review L2 · Cần trước: —
```
Bạn là agent Antigravity trong dự án Strata. Đọc AGENTS.md và mục W13-R-02 trong docs/plan/plan.md.

Nhiệm vụ W13-R-02 · Đo chi phí từng rule.
- Thư mục: engine/
- Việc: lấy mẫu thời gian xử lý theo Rule ID (mặc định 1% request), đưa vào metrics và sự kiện.
- Xong khi: chi phí đo lường dưới 2% thời gian engine (benchmark trước/sau).

Bước 1: xác nhận phần Antigravity, tuần hiện tại.
Bước 2: tạo Implementation Plan rồi DỪNG, chờ tôi duyệt.
Bước 3 (sau khi duyệt): nhánh W13-R-02-rule-cost, làm, chạy cargo test/bench,
cập nhật mục 0 thành ✅ Done trong PR, báo cáo theo mục 9.
Chuẩn bắt buộc: mục 6a AGENTS.md (test viết trước code, tự review theo checklist, bằng chứng là output thật). Mức review: L2.
Implementation Plan phải có thêm: bất biến cần giữ, ca biên và đường lỗi, danh sách test (gồm test âm).
Sau khi mở PR (báo cáo mục 9, ghi "Review: L2" và SHA commit cuối): DỪNG, chờ Claude Code review. Không tự merge.
```

### W13-G1-01 · Antigravity · Review L3 · Cần trước: —
```
Bạn là agent Antigravity trong dự án Strata. Đọc AGENTS.md và mục W13-G1-01 trong docs/plan/plan.md.

Nhiệm vụ W13-G1-01 · Nâng cấp agent không gián đoạn.
- Thư mục: agent/, deploy/packaging/  (được phép sửa phần gói của agent)
- Việc: nâng cấp gói agent trên node đang có tải mà không mất sự kiện và không đổi bundle ngoài ý muốn.
- Xong khi: test nâng cấp trên lab có tải: số sự kiện gửi = nhận; phiên bản bundle không đổi.

Bước 1: xác nhận phần Antigravity, tuần hiện tại.
Bước 2: tạo Implementation Plan rồi DỪNG, chờ tôi duyệt.
Bước 3 (sau khi duyệt): nhánh W13-G1-01-agent-upgrade, làm, chạy test lab,
cập nhật mục 0 thành ✅ Done trong PR, báo cáo theo mục 9.
Chuẩn bắt buộc: mục 6a AGENTS.md (test viết trước code, tự review theo checklist, bằng chứng là output thật). Mức review: L3 (khu vực rủi ro cao).
Implementation Plan phải có thêm: bất biến cần giữ, ca biên và đường lỗi, rủi ro bảo mật, danh sách test (gồm test âm và chạy sanitizer / -race).
Kế hoạch sẽ được Claude Code review trước khi tôi duyệt; chỉ bắt đầu code khi tôi trả lời "duyệt".
Sau khi mở PR (báo cáo mục 9, ghi "Review: L3" và SHA commit cuối): DỪNG, chờ Claude Code review. Không tự merge.
```

### W13-G2-01 · Antigravity · Review L2 · Cần trước: W12-R-01, W11-G2-01
```
Bạn là agent Antigravity trong dự án Strata. Đọc AGENTS.md, nginx-module.md › API quản trị (long-running operation), và mục W13-G2-01 trong docs/plan/plan.md.

Nhiệm vụ W13-G2-01 · Replay service.
- Thư mục: control-plane/replay/, control-plane/api/
- Việc: API :replay dạng long-running operation, gọi replay runner, lưu kết quả theo bản nháp.
- Xong khi: tạo bản nháp → replay tự chạy → kết quả xem được qua API (test).

Bước 1: xác nhận phần Antigravity, tuần hiện tại, "Cần trước" đã merge.
Bước 2: tạo Implementation Plan rồi DỪNG, chờ tôi duyệt.
Bước 3 (sau khi duyệt): nhánh W13-G2-01-replay-service, làm, chạy go test/golangci-lint,
cập nhật mục 0 thành ✅ Done trong PR, báo cáo theo mục 9.
Chuẩn bắt buộc: mục 6a AGENTS.md (test viết trước code, tự review theo checklist, bằng chứng là output thật). Mức review: L2.
Implementation Plan phải có thêm: bất biến cần giữ, ca biên và đường lỗi, danh sách test (gồm test âm).
Sau khi mở PR (báo cáo mục 9, ghi "Review: L2" và SHA commit cuối): DỪNG, chờ Claude Code review. Không tự merge.
```

### W13-G2-02 · Antigravity · Review L2 · Cần trước: —
```
Bạn là agent Antigravity trong dự án Strata. Đọc AGENTS.md và mục W13-G2-02 trong docs/plan/plan.md.

Nhiệm vụ W13-G2-02 · Luồng duyệt 4 mắt.  (Nhạy cảm bảo mật: PR cần 2 người review.)
- Thư mục: control-plane/policy/
- Việc: :submit, :approve; người tạo bản nháp không tự duyệt được; deploy khi chưa duyệt bị từ chối.
- Xong khi: test cho cả hai quy tắc trên; audit ghi người tạo và người duyệt.

Bước 1: xác nhận phần Antigravity, tuần hiện tại.
Bước 2: tạo Implementation Plan kèm rủi ro bỏ qua bước duyệt và cách test, rồi DỪNG, chờ tôi duyệt.
Bước 3 (sau khi duyệt): nhánh W13-G2-02-four-eyes, làm, chạy go test/golangci-lint,
cập nhật mục 0 thành ✅ Done trong PR, báo cáo theo mục 9.
Chuẩn bắt buộc: mục 6a AGENTS.md (test viết trước code, tự review theo checklist, bằng chứng là output thật). Mức review: L2.
Implementation Plan phải có thêm: bất biến cần giữ, ca biên và đường lỗi, danh sách test (gồm test âm).
Sau khi mở PR (báo cáo mục 9, ghi "Review: L2" và SHA commit cuối): DỪNG, chờ Claude Code review. Không tự merge.
```

### W13-F-01 · Antigravity · Review L1 · Cần trước: W13-G2-01, W13-G2-02
```
Bạn là agent Antigravity trong dự án Strata. Đọc AGENTS.md và mục W13-F-01 trong docs/plan/plan.md.

Nhiệm vụ W13-F-01 · Hàng chờ duyệt.
- Thư mục: ui/
- Việc: danh sách bản nháp chờ duyệt kèm kết quả replay (FP/FN theo route) và diff; nút duyệt / từ chối.
- Xong khi: kịch bản trên lab với 2 tài khoản: người tạo không thấy nút duyệt bản của mình, người duyệt duyệt được; Playwright pass.

Bước 1: xác nhận phần Antigravity, tuần hiện tại, "Cần trước" đã merge.
Bước 2: tạo Implementation Plan rồi DỪNG, chờ tôi duyệt.
Bước 3 (sau khi duyệt): nhánh W13-F-01-approval-queue, làm, chạy npm lint/test/build và Playwright,
đính kèm ảnh chụp trên lab, cập nhật mục 0 thành ✅ Done trong PR, báo cáo theo mục 9.
Chuẩn bắt buộc: mục 6a AGENTS.md (test viết trước code, tự review theo checklist, bằng chứng là output thật). Mức review: L1 (không cần Claude Code; CI và tự review là đủ).
```

### W13-S-01 · Antigravity · Review L1 · Cần trước: —
```
Bạn là agent Antigravity trong dự án Strata. Đọc AGENTS.md và mục W13-S-01 trong docs/plan/plan.md.

Nhiệm vụ W13-S-01 · Rule bù khoảng trống.
- Thư mục: rules/
- Việc: viết rule riêng cho phần CRS và nguồn nhập chưa phủ (theo báo cáo differential và bộ biến thể W09-S-02), cho các ca bypass từ fuzz; phát hành pack v0.2.
- Xong khi: mỗi rule mới có mẫu khớp/không khớp; recall tăng so với v0.1, FP không tăng.

Bước 1: xác nhận phần Antigravity, tuần hiện tại.
Bước 2: tạo Implementation Plan (danh sách khoảng trống) rồi DỪNG, chờ tôi duyệt.
Bước 3 (sau khi duyệt): nhánh W13-S-01-gap-rules, làm, chạy strata-rules lint/test,
cập nhật mục 0 thành ✅ Done trong PR, báo cáo theo mục 9 kèm số liệu trước/sau.
Chuẩn bắt buộc: mục 6a AGENTS.md (test viết trước code, tự review theo checklist, bằng chứng là output thật). Mức review: L1 (không cần Claude Code; CI và tự review là đủ).
```

**Canary 25%** · Người, khi đạt điều kiện bậc 2.

---

## Tuần 14 · Exception từ Block ID, sức khỏe rule, game day

### W14-R-01 · Antigravity · Review L3 · Cần trước: —
```
Bạn là agent Antigravity trong dự án Strata. Đọc AGENTS.md, strata-overview.md › Mô hình policy & rule, và mục W14-R-01 trong docs/plan/plan.md.

Nhiệm vụ W14-R-01 · Exception, override, cost unit trong compiler.
- Thư mục: engine/compiler/
- Việc: biên dịch exception và override đúng thứ tự ưu tiên (exception trước override); áp ngân sách cost unit khi lưu policy.
- Xong khi: test thứ tự ưu tiên; policy vượt cost bị từ chối.

Bước 1: xác nhận phần Antigravity, tuần hiện tại.
Bước 2: tạo Implementation Plan rồi DỪNG, chờ tôi duyệt.
Bước 3 (sau khi duyệt): nhánh W14-R-01-exceptions, làm, chạy cargo test,
cập nhật mục 0 thành ✅ Done trong PR, báo cáo theo mục 9.
Chuẩn bắt buộc: mục 6a AGENTS.md (test viết trước code, tự review theo checklist, bằng chứng là output thật). Mức review: L3 (khu vực rủi ro cao).
Implementation Plan phải có thêm: bất biến cần giữ, ca biên và đường lỗi, rủi ro bảo mật, danh sách test (gồm test âm và chạy sanitizer / -race).
Kế hoạch sẽ được Claude Code review trước khi tôi duyệt; chỉ bắt đầu code khi tôi trả lời "duyệt".
Sau khi mở PR (báo cáo mục 9, ghi "Review: L3" và SHA commit cuối): DỪNG, chờ Claude Code review. Không tự merge.
```

### W14-G2-01 · Antigravity · Review L2 · Cần trước: —
```
Bạn là agent Antigravity trong dự án Strata. Đọc AGENTS.md, nginx-module.md › API quản trị, và mục W14-G2-01 trong docs/plan/plan.md.

Nhiệm vụ W14-G2-01 · Exception và đánh dấu FP.
- Thư mục: control-plane/policy/, control-plane/api/
- Việc: POST /v1/exceptions:fromBlockId sinh exception phạm vi hẹp nhất (route + field + Rule ID) dưới dạng bản nháp; bắt buộc hạn dùng; :markFalsePositive.
- Xong khi: test sinh exception từ một Block ID thật trên lab; exception thiếu hạn dùng bị từ chối.

Bước 1: xác nhận phần Antigravity, tuần hiện tại.
Bước 2: tạo Implementation Plan rồi DỪNG, chờ tôi duyệt.
Bước 3 (sau khi duyệt): nhánh W14-G2-01-exceptions-api, làm, chạy go test/golangci-lint,
cập nhật mục 0 thành ✅ Done trong PR, báo cáo theo mục 9.
Chuẩn bắt buộc: mục 6a AGENTS.md (test viết trước code, tự review theo checklist, bằng chứng là output thật). Mức review: L2.
Implementation Plan phải có thêm: bất biến cần giữ, ca biên và đường lỗi, danh sách test (gồm test âm).
Sau khi mở PR (báo cáo mục 9, ghi "Review: L2" và SHA commit cuối): DỪNG, chờ Claude Code review. Không tự merge.
```

### W14-G2-02 · Antigravity · Review L2 · Cần trước: W13-R-02
```
Bạn là agent Antigravity trong dự án Strata. Đọc AGENTS.md và mục W14-G2-02 trong docs/plan/plan.md.

Nhiệm vụ W14-G2-02 · Sức khỏe rule.
- Thư mục: control-plane/rules/, control-plane/api/
- Việc: tổng hợp theo Rule ID (số lần khớp, số FP được báo, chi phí trung bình); rule có FP tăng đột biến tự quay về staging và báo người duyệt; GET /v1/rules/{rule_id}/health.
- Xong khi: giả lập FP tăng đột biến → rule về staging trong dưới 5 phút (test).

Bước 1: xác nhận phần Antigravity, tuần hiện tại, W13-R-02 đã merge.
Bước 2: tạo Implementation Plan rồi DỪNG, chờ tôi duyệt.
Bước 3 (sau khi duyệt): nhánh W14-G2-02-rule-health, làm, chạy go test,
cập nhật mục 0 thành ✅ Done trong PR, báo cáo theo mục 9.
Chuẩn bắt buộc: mục 6a AGENTS.md (test viết trước code, tự review theo checklist, bằng chứng là output thật). Mức review: L2.
Implementation Plan phải có thêm: bất biến cần giữ, ca biên và đường lỗi, danh sách test (gồm test âm).
Sau khi mở PR (báo cáo mục 9, ghi "Review: L2" và SHA commit cuối): DỪNG, chờ Claude Code review. Không tự merge.
```

### W14-F-01 · Antigravity · Review L1 · Cần trước: W14-G2-01
```
Bạn là agent Antigravity trong dự án Strata. Đọc AGENTS.md, nginx-module.md › Giao diện quản trị, và mục W14-F-01 trong docs/plan/plan.md.

Nhiệm vụ W14-F-01 · Nút xử lý trên chi tiết sự kiện.
- Thư mục: ui/
- Việc: 3 nút Đánh dấu FP, Tạo exception (form điền sẵn phạm vi hẹp nhất), Chặn IP/identity; exception đi qua replay và duyệt.
- Xong khi: kịch bản trên lab từ Block ID tới exception chờ duyệt; Playwright pass.

Bước 1: xác nhận phần Antigravity, tuần hiện tại, W14-G2-01 đã merge.
Bước 2: tạo Implementation Plan rồi DỪNG, chờ tôi duyệt.
Bước 3 (sau khi duyệt): nhánh W14-F-01-event-actions, làm, chạy npm lint/test/build và Playwright,
đính kèm bản ghi trình duyệt trên lab, cập nhật mục 0 thành ✅ Done trong PR, báo cáo theo mục 9.
Chuẩn bắt buộc: mục 6a AGENTS.md (test viết trước code, tự review theo checklist, bằng chứng là output thật). Mức review: L1 (không cần Claude Code; CI và tự review là đủ).
```

### W14-S-01 · Antigravity · Review L2 · Cần trước: —
```
Bạn là agent Antigravity trong dự án Strata. Đọc AGENTS.md và mục W14-S-01 trong docs/plan/plan.md.

Nhiệm vụ W14-S-01 · Quy trình virtual patch.
- Thư mục: docs/runbook/, tools/strata-rules/
- Việc: runbook và công cụ hỗ trợ đi từ một CVE nghiêm trọng tới gói signature ở staging trong dưới 24 giờ.
- Xong khi: docs/runbook/virtual-patch.md; diễn tập một CVE mẫu trên lab (gói ở trạng thái staging), ghi thời gian từng bước.
- Lưu ý: không đẩy gói lên production.

Bước 1: xác nhận phần Antigravity, tuần hiện tại.
Bước 2: tạo Implementation Plan rồi DỪNG, chờ tôi duyệt.
Bước 3 (sau khi duyệt): nhánh W14-S-01-virtual-patch, làm, diễn tập,
cập nhật mục 0 thành ✅ Done trong PR, báo cáo theo mục 9.
Chuẩn bắt buộc: mục 6a AGENTS.md (test viết trước code, tự review theo checklist, bằng chứng là output thật). Mức review: L2.
Implementation Plan phải có thêm: bất biến cần giữ, ca biên và đường lỗi, danh sách test (gồm test âm).
Sau khi mở PR (báo cáo mục 9, ghi "Review: L2" và SHA commit cuối): DỪNG, chờ Claude Code review. Không tự merge.
```

### W14-Q-01 · **Người** (Antigravity soạn)
```
Bạn là agent Antigravity trong dự án Strata. Đọc AGENTS.md và mục W14-Q-01 trong docs/plan/plan.md.
Soạn kịch bản game day ở docs/runbook/game-day.md (tắt control plane, tắt agent, làm hỏng bundle, tiêm panic, ngắt mạng):
mỗi tình huống có bước thực hiện, kết quả kỳ vọng theo thiết kế, ô ghi kết quả thật. Không tự chạy ngoài lab.
```

---

## Tuần 15 · Enforce 100%

### W15-G2-01 · Antigravity · Review L3 · Cần trước: —
```
Bạn là agent Antigravity trong dự án Strata. Đọc AGENTS.md, nginx-module.md › API quản trị › Xác thực và phân quyền, và mục W15-G2-01 trong docs/plan/plan.md.

Nhiệm vụ W15-G2-01 · Audit, role binding, service account.  (Nhạy cảm bảo mật: PR cần 2 người review.)
- Thư mục: control-plane/auth/, control-plane/audit/
- Việc: GET /v1/audit (người, kênh, trước/sau); API role binding theo connector group; service account token có phạm vi và hạn dùng.
- Xong khi: test phạm vi token; token hết hạn bị từ chối; audit ghi đủ.

Bước 1: xác nhận phần Antigravity, tuần hiện tại.
Bước 2: kế hoạch kèm rủi ro bảo mật và cách test, rồi DỪNG, chờ tôi duyệt.
Bước 3 (sau khi duyệt): nhánh W15-G2-01-audit-sa, làm, chạy go test/golangci-lint,
cập nhật mục 0 thành ✅ Done trong PR, báo cáo theo mục 9.
Chuẩn bắt buộc: mục 6a AGENTS.md (test viết trước code, tự review theo checklist, bằng chứng là output thật). Mức review: L3 (khu vực rủi ro cao).
Implementation Plan phải có thêm: bất biến cần giữ, ca biên và đường lỗi, rủi ro bảo mật, danh sách test (gồm test âm và chạy sanitizer / -race).
Kế hoạch sẽ được Claude Code review trước khi tôi duyệt; chỉ bắt đầu code khi tôi trả lời "duyệt".
Sau khi mở PR (báo cáo mục 9, ghi "Review: L3" và SHA commit cuối): DỪNG, chờ Claude Code review. Không tự merge.
```

### W15-N-01 · Antigravity · Review L1 · Cần trước: W11-N-01
```
Bạn là agent Antigravity trong dự án Strata. Đọc AGENTS.md và mục W15-N-01 trong docs/plan/plan.md.
Nhiệm vụ W15-N-01 · Chốt tài liệu cấu hình. Thư mục: connectors/nginx/README.md, docs/design/nginx-module.md (được phép sửa bảng directive).
Việc: bảng directive (gồm strata_breaker*) và README khớp với code thật.
Xong khi: mọi directive trong code có trong tài liệu và ngược lại (script so sánh).
Bước 1: xác nhận. Bước 2: liệt kê chỗ lệch rồi DỪNG, chờ tôi duyệt. Bước 3: nhánh W15-N-01-docs, sửa, cập nhật mục 0, báo cáo theo mục 9.
Chuẩn bắt buộc: mục 6a AGENTS.md (test viết trước code, tự review theo checklist, bằng chứng là output thật). Mức review: L1 (không cần Claude Code; CI và tự review là đủ).
```

### W15-R-01 · Antigravity · Review L2 · Cần trước: W14-G2-01
```
Bạn là agent Antigravity trong dự án Strata. Đọc AGENTS.md và mục W15-R-01 trong docs/plan/plan.md.

Nhiệm vụ W15-R-01 · Tối ưu tokenizer theo FP thực tế.
- Thư mục: engine/src/detectors/, corpus/fp/ (được phép thêm mẫu FP đã ẩn danh)
- Việc: tự thu thập mẫu FP của tokenizer SQLi/XSS rồi giảm FP. Nguồn cần tự đọc:
  (1) sự kiện được đánh dấu false positive trên control plane của lab (POST /v1/events:search với false_positive = true);
  (2) exception đã duyệt cho các Rule ID thuộc tokenizer SQLi/XSS (GET /v1/exceptions trên lab) và các file exception trong repo;
  (3) replay trên corpus benign (corpus/benign/, gồm traffic mẫu đã ẩn danh): request benign bị tokenizer khớp.
  Lưu mẫu vào corpus/fp/ ở dạng đã ẩn danh (chỉ giữ cấu trúc payload, bỏ giá trị định danh).
- Xong khi: FP trên tập mẫu giảm, recall trên corpus attack không giảm (báo cáo trước/sau).
  Nếu có dưới 20 mẫu FP thật: dùng thêm FP từ replay trên corpus benign và ghi rõ trong báo cáo.

Bước 1: xác nhận phần Antigravity, tuần hiện tại, W14-G2-01 đã merge.
Bước 2: thu thập mẫu, trình bày nhóm FP và cách xử lý rồi DỪNG, chờ tôi duyệt.
Bước 3 (sau khi duyệt): nhánh W15-R-01-tokenizer-fp, làm, chạy cargo test và strata-rules test,
cập nhật mục 0 thành ✅ Done trong PR, báo cáo theo mục 9 kèm số liệu trước/sau.
Chuẩn bắt buộc: mục 6a AGENTS.md (test viết trước code, tự review theo checklist, bằng chứng là output thật). Mức review: L2.
Implementation Plan phải có thêm: bất biến cần giữ, ca biên và đường lỗi, danh sách test (gồm test âm).
Sau khi mở PR (báo cáo mục 9, ghi "Review: L2" và SHA commit cuối): DỪNG, chờ Claude Code review. Không tự merge.
```

### W15-F-01 · Antigravity · Review L1 · Cần trước: W15-G2-01
```
Bạn là agent Antigravity trong dự án Strata. Đọc AGENTS.md và mục W15-F-01 trong docs/plan/plan.md.

Nhiệm vụ W15-F-01 · Hoàn thiện policy editor và trang Audit v0.
- Thư mục: ui/
- Việc: editor đủ 9 khối policy; trang Audit lọc theo người, thời gian, đối tượng.
- Xong khi: sửa đủ 9 khối trên lab; audit hiện đúng thay đổi vừa làm; Playwright pass.

Bước 1: xác nhận phần Antigravity, tuần hiện tại, W15-G2-01 đã merge.
Bước 2: tạo Implementation Plan rồi DỪNG, chờ tôi duyệt.
Bước 3 (sau khi duyệt): nhánh W15-F-01-editor-audit, làm, chạy npm lint/test/build và Playwright,
đính kèm ảnh chụp trên lab, cập nhật mục 0 thành ✅ Done trong PR, báo cáo theo mục 9.
Chuẩn bắt buộc: mục 6a AGENTS.md (test viết trước code, tự review theo checklist, bằng chứng là output thật). Mức review: L1 (không cần Claude Code; CI và tự review là đủ).
```

### W15-S-01 · Antigravity · Review L1 · Cần trước: W15-Q-01
```
Bạn là agent Antigravity trong dự án Strata. Đọc AGENTS.md và mục W15-S-01 trong docs/plan/plan.md.
Nhiệm vụ W15-S-01 · Tự kiểm thử và vá bypass (1). Thư mục: rules/.
Việc: đọc docs/reports/bypass-w15.md (kết quả GoTestWAF và strata-mutate của W15-Q-01), chạy thêm strata-mutate với corpus mới nhất,
xếp bypass theo mức cao / trung bình / thấp, viết hoặc chỉnh rule cho bypass mức cao; phát hành pack v0.3.
Xong khi: mọi bypass mức cao đã vá; đạt chỉ tiêu Gate B ở mục Chỉ tiêu chất lượng.
Bước 1: xác nhận. Bước 2: Implementation Plan rồi DỪNG, chờ tôi duyệt. Bước 3: nhánh W15-S-01-bypass-fixes, làm, chạy strata-rules lint/test và strata-mutate, cập nhật mục 0, báo cáo theo mục 9.
Chuẩn bắt buộc: mục 6a AGENTS.md (test viết trước code, tự review theo checklist, bằng chứng là output thật). Mức review: L1 (không cần Claude Code; CI và tự review là đủ).
```

### W15-Q-01 · Antigravity · Review L1 · Cần trước: W09-S-02
```
Bạn là agent Antigravity trong dự án Strata. Đọc AGENTS.md và mục W15-Q-01 trong docs/plan/plan.md.

Nhiệm vụ W15-Q-01 · Benchmark chống bypass.
- Thư mục: tests/bypass/, docs/reports/
- Việc: chạy GoTestWAF (kiểm tra giấy phép trước, ghi vào báo cáo) và bộ biến thể strata-mutate trên lab (dựng từ bản đã tag).
- Xong khi: báo cáo ở docs/reports/bypass-w15.md; danh sách bypass mức cao chuyển cho W15-S-01.
- Lưu ý: chỉ chạy trên lab, không kết nối staging hay production.

Bước 1: xác nhận phần Antigravity, tuần hiện tại.
Bước 2: tạo Implementation Plan rồi DỪNG, chờ tôi duyệt.
Bước 3 (sau khi duyệt): nhánh W15-Q-01-bypass-bench, làm,
cập nhật mục 0 thành ✅ Done trong PR, báo cáo theo mục 9.
Chuẩn bắt buộc: mục 6a AGENTS.md (test viết trước code, tự review theo checklist, bằng chứng là output thật). Mức review: L1 (không cần Claude Code; CI và tự review là đủ).
```

**Enforce 100%** · Người, khi đạt điều kiện bậc 3.

---

## Tuần 16 · Ổn định enforce · Gate B

### W16-S-01 · Antigravity · Review L2 · Cần trước: —
```
Bạn là agent Antigravity trong dự án Strata. Đọc AGENTS.md và mục W16-S-01 trong docs/plan/plan.md.
Nhiệm vụ W16-S-01 · Báo cáo chất lượng sau enforce. Thư mục: docs/reports/, tools/strata-rules/.
Việc: báo cáo FP trên 1 triệu request, rule chưa từng khớp, rule tốn chi phí nhất (dùng API sức khỏe rule); quy trình cập nhật khi CRS ra bản mới.
Xong khi: docs/reports/quality-w16.md và docs/runbook/crs-update.md.
Bước 1: xác nhận. Bước 2: Implementation Plan rồi DỪNG, chờ tôi duyệt. Bước 3: nhánh W16-S-01-quality-report, làm, cập nhật mục 0, báo cáo theo mục 9.
Chuẩn bắt buộc: mục 6a AGENTS.md (test viết trước code, tự review theo checklist, bằng chứng là output thật). Mức review: L2.
Implementation Plan phải có thêm: bất biến cần giữ, ca biên và đường lỗi, danh sách test (gồm test âm).
Sau khi mở PR (báo cáo mục 9, ghi "Review: L2" và SHA commit cuối): DỪNG, chờ Claude Code review. Không tự merge.
```

### W16-G2-01 · Antigravity · Review L2 · Cần trước: —
```
Bạn là agent Antigravity trong dự án Strata. Đọc AGENTS.md, nginx-module.md › Bản đồ GeoIP, và mục W16-G2-01 trong docs/plan/plan.md.

Nhiệm vụ W16-G2-01 · Chuẩn bị GeoIP.
- Thư mục: control-plane/ingest/
- Việc: Event ingest nạp file .mmdb; ClickHouse thêm cột country_iso, city, lat, lon, accuracy_km, asn, as_org, geoip_version.
- Xong khi: sự kiện mới có đủ cột (test với file .mmdb mẫu).
- Lưu ý: không đưa file .mmdb có giấy phép hạn chế vào repo; đường dẫn qua cấu hình.

Bước 1: xác nhận phần Antigravity, tuần hiện tại.
Bước 2: tạo Implementation Plan rồi DỪNG, chờ tôi duyệt.
Bước 3 (sau khi duyệt): nhánh W16-G2-01-geoip-prep, làm, chạy go test,
cập nhật mục 0 thành ✅ Done trong PR, báo cáo theo mục 9.
Chuẩn bắt buộc: mục 6a AGENTS.md (test viết trước code, tự review theo checklist, bằng chứng là output thật). Mức review: L2.
Implementation Plan phải có thêm: bất biến cần giữ, ca biên và đường lỗi, danh sách test (gồm test âm).
Sau khi mở PR (báo cáo mục 9, ghi "Review: L2" và SHA commit cuối): DỪNG, chờ Claude Code review. Không tự merge.
```

**W16-ALL-01 · Gate B** · Người.

---

## Tuần 17 · GeoIP, nền bản đồ, CRS PL2

### W17-R-01 · Antigravity · Review L2 · Cần trước: —
```
Bạn là agent Antigravity trong dự án Strata. Đọc AGENTS.md và mục W17-R-01 trong docs/plan/plan.md.

Nhiệm vụ W17-R-01 · Mở rộng semantic detector, CRS PL2.
- Thư mục: engine/
- Việc: semantic detector CMDi và template injection; hỗ trợ operator/action còn thiếu cho CRS PL2 và plugin exclusion.
- Xong khi: test go-ftw ở PL2 pass tối thiểu 95%.

Bước 1: xác nhận phần Antigravity, tuần hiện tại.
Bước 2: tạo Implementation Plan rồi DỪNG, chờ tôi duyệt.
Bước 3 (sau khi duyệt): nhánh W17-R-01-semantic-pl2, làm, chạy cargo test và go-ftw,
cập nhật mục 0 thành ✅ Done trong PR, báo cáo theo mục 9.
Chuẩn bắt buộc: mục 6a AGENTS.md (test viết trước code, tự review theo checklist, bằng chứng là output thật). Mức review: L2.
Implementation Plan phải có thêm: bất biến cần giữ, ca biên và đường lỗi, danh sách test (gồm test âm).
Sau khi mở PR (báo cáo mục 9, ghi "Review: L2" và SHA commit cuối): DỪNG, chờ Claude Code review. Không tự merge.
```

### W17-N-01 · Antigravity · Review L3 · Cần trước: W09-Q-01
```
Bạn là agent Antigravity trong dự án Strata. Đọc AGENTS.md, docs/decisions/ring-buffer.md và mục W17-N-01 trong docs/plan/plan.md.
Nhiệm vụ W17-N-01 · Ring buffer (nếu đã quyết định) và tối ưu. Thư mục: connectors/nginx/src/, agent/ (phần đọc ring).
Việc: nếu quyết định là đưa vào v1 → cài ring SPSC theo worker trong /dev/shm sau interface strata_event_sink_t; nếu không → chỉ ghi chú v1.1 và dừng.
Xong khi: benchmark sự kiện trước/sau; agent kiểm từng record.
Bước 1: đọc quyết định và báo tôi. Bước 2: kế hoạch rồi DỪNG, chờ tôi duyệt. Bước 3: nhánh W17-N-01-ring-buffer, làm, cập nhật mục 0, báo cáo theo mục 9.
Chuẩn bắt buộc: mục 6a AGENTS.md (test viết trước code, tự review theo checklist, bằng chứng là output thật). Mức review: L3 (khu vực rủi ro cao).
Implementation Plan phải có thêm: bất biến cần giữ, ca biên và đường lỗi, rủi ro bảo mật, danh sách test (gồm test âm và chạy sanitizer / -race).
Kế hoạch sẽ được Claude Code review trước khi tôi duyệt; chỉ bắt đầu code khi tôi trả lời "duyệt".
Sau khi mở PR (báo cáo mục 9, ghi "Review: L3" và SHA commit cuối): DỪNG, chờ Claude Code review. Không tự merge.
```

### W17-G2-01 · Antigravity · Review L2 · Cần trước: W16-G2-01
```
Bạn là agent Antigravity trong dự án Strata. Đọc AGENTS.md, nginx-module.md › Bản đồ GeoIP › Pipeline, và mục W17-G2-01 trong docs/plan/plan.md.

Nhiệm vụ W17-G2-01 · Gắn GeoIP và bảng tổng hợp.
- Thư mục: control-plane/ingest/
- Việc: materialized view theo phút (quốc gia, ASN, action, loại tấn công) và theo 5 phút (geohash độ chính xác 4); job cập nhật GeoIP hằng tuần, lưu phiên bản vào MinIO.
- Xong khi: view có dữ liệu trên lab; job chạy được.

Bước 1: xác nhận phần Antigravity, tuần hiện tại, W16-G2-01 đã merge.
Bước 2: tạo Implementation Plan rồi DỪNG, chờ tôi duyệt.
Bước 3 (sau khi duyệt): nhánh W17-G2-01-geoip-views, làm, chạy go test,
cập nhật mục 0 thành ✅ Done trong PR, báo cáo theo mục 9.
Chuẩn bắt buộc: mục 6a AGENTS.md (test viết trước code, tự review theo checklist, bằng chứng là output thật). Mức review: L2.
Implementation Plan phải có thêm: bất biến cần giữ, ca biên và đường lỗi, danh sách test (gồm test âm).
Sau khi mở PR (báo cáo mục 9, ghi "Review: L2" và SHA commit cuối): DỪNG, chờ Claude Code review. Không tự merge.
```

### W17-F-01 · Antigravity · Review L1 · Cần trước: —
```
Bạn là agent Antigravity trong dự án Strata. Đọc AGENTS.md, nginx-module.md › Bản đồ GeoIP › Hiển thị, và mục W17-F-01 trong docs/plan/plan.md.

Nhiệm vụ W17-F-01 · Nền bản đồ tự host.
- Thư mục: ui/
- Việc: MapLibre GL JS + file PMTiles do API server phục vụ; không dùng dịch vụ bản đồ bên ngoài.
- Xong khi: bản đồ chạy trong mạng không có internet trên lab; ghi nguồn tile vào docs/decisions/map-tiles.md.
- Lưu ý BẮT BUỘC: bản đồ phải thể hiện đúng chủ quyền của Việt Nam với Hoàng Sa và Trường Sa. Chụp ảnh khu vực Biển Đông đính kèm PR để người kiểm tra trước khi merge.

Bước 1: xác nhận phần Antigravity, tuần hiện tại.
Bước 2: tạo Implementation Plan rồi DỪNG, chờ tôi duyệt.
Bước 3 (sau khi duyệt): nhánh W17-F-01-basemap, làm, chạy npm lint/test/build,
đính kèm ảnh chụp, cập nhật mục 0 thành ✅ Done trong PR, báo cáo theo mục 9.
Chuẩn bắt buộc: mục 6a AGENTS.md (test viết trước code, tự review theo checklist, bằng chứng là output thật). Mức review: L1 (không cần Claude Code; CI và tự review là đủ).
```

### W17-S-01 · Antigravity · Review L2 · Cần trước: W17-R-01
```
Bạn là agent Antigravity trong dự án Strata. Đọc AGENTS.md và mục W17-S-01 trong docs/plan/plan.md.
Nhiệm vụ W17-S-01 · CRS PL2 và plugin exclusion. Thư mục: tools/strata-import-crs/, rules/crs/.
Việc: nhập rule PL2 và plugin exclusion (WordPress, Drupal…) của CRS.
Xong khi: route chịu được PL2 chạy shadow; go-ftw PL2 pass tối thiểu 95%.
Bước 1: xác nhận. Bước 2: Implementation Plan rồi DỪNG, chờ tôi duyệt. Bước 3: nhánh W17-S-01-crs-pl2, làm, chạy go-ftw, cập nhật mục 0, báo cáo theo mục 9.
Chuẩn bắt buộc: mục 6a AGENTS.md (test viết trước code, tự review theo checklist, bằng chứng là output thật). Mức review: L2.
Implementation Plan phải có thêm: bất biến cần giữ, ca biên và đường lỗi, danh sách test (gồm test âm).
Sau khi mở PR (báo cáo mục 9, ghi "Review: L2" và SHA commit cuối): DỪNG, chờ Claude Code review. Không tự merge.
```

### W17-Q-01 · Antigravity · Review L1 · Cần trước: W17-G2-01
```
Bạn là agent Antigravity trong dự án Strata. Đọc AGENTS.md và mục W17-Q-01 trong docs/plan/plan.md.
Nhiệm vụ W17-Q-01 · Test tải truy vấn tổng hợp. Thư mục: tests/load/, docs/reports/.
Việc: sinh dữ liệu giả lập 30 ngày, đo truy vấn tổng hợp.
Xong khi: 24 giờ dưới 1 giây, 30 ngày dưới 3 giây; báo cáo docs/reports/stats-load-w17.md.
Bước 1: xác nhận. Bước 2: Implementation Plan rồi DỪNG, chờ tôi duyệt. Bước 3: nhánh W17-Q-01-stats-load, làm, cập nhật mục 0, báo cáo theo mục 9.
Chuẩn bắt buộc: mục 6a AGENTS.md (test viết trước code, tự review theo checklist, bằng chứng là output thật). Mức review: L1 (không cần Claude Code; CI và tự review là đủ).
```

---

## Tuần 18 · API thống kê, lớp bản đồ, xác minh bot tốt

### W18-R-01 · Antigravity · Review L2 · Cần trước: W17-S-01
```
Bạn là agent Antigravity trong dự án Strata. Đọc AGENTS.md và mục W18-R-01 trong docs/plan/plan.md.
Nhiệm vụ W18-R-01 · Phủ thêm rule CRS. Thư mục: engine/.
Việc: cài operator/transformation/action còn thiếu theo báo cáo importer để tăng tỉ lệ rule CRS nhập tự động.
Xong khi: tỉ lệ nhập tự động tăng so với tuần 8 (báo cáo importer trước/sau).
Bước 1: xác nhận. Bước 2: kế hoạch rồi DỪNG, chờ tôi duyệt. Bước 3: nhánh W18-R-01-crs-coverage, làm, chạy cargo test và go-ftw, cập nhật mục 0, báo cáo theo mục 9.
Chuẩn bắt buộc: mục 6a AGENTS.md (test viết trước code, tự review theo checklist, bằng chứng là output thật). Mức review: L2.
Implementation Plan phải có thêm: bất biến cần giữ, ca biên và đường lỗi, danh sách test (gồm test âm).
Sau khi mở PR (báo cáo mục 9, ghi "Review: L2" và SHA commit cuối): DỪNG, chờ Claude Code review. Không tự merge.
```

### W18-R-02 · Antigravity · Review L2 · Cần trước: W18-G2-02
```
Bạn là agent Antigravity trong dự án Strata. Đọc AGENTS.md, mục Luồng S › Tính năng cho rule trong v1, và mục W18-R-02 trong docs/plan/plan.md.

Nhiệm vụ W18-R-02 · Xác minh bot tốt.
- Thư mục: engine/
- Việc: request tự nhận là crawler lớn qua User-Agent nhưng IP không thuộc dải công bố trong bundle → violation điểm cao.
- Xong khi: Googlebot giả từ IP lạ bị gắn violation; Googlebot từ dải công bố không bị (test).

Bước 1: xác nhận phần Antigravity, tuần hiện tại, W18-G2-02 đã merge.
Bước 2: tạo Implementation Plan rồi DỪNG, chờ tôi duyệt.
Bước 3 (sau khi duyệt): nhánh W18-R-02-goodbot-verify, làm, chạy cargo test,
cập nhật mục 0 thành ✅ Done trong PR, báo cáo theo mục 9.
Chuẩn bắt buộc: mục 6a AGENTS.md (test viết trước code, tự review theo checklist, bằng chứng là output thật). Mức review: L2.
Implementation Plan phải có thêm: bất biến cần giữ, ca biên và đường lỗi, danh sách test (gồm test âm).
Sau khi mở PR (báo cáo mục 9, ghi "Review: L2" và SHA commit cuối): DỪNG, chờ Claude Code review. Không tự merge.
```

### W18-G2-01 · Antigravity · Review L2 · Cần trước: W17-G2-01
```
Bạn là agent Antigravity trong dự án Strata. Đọc AGENTS.md, nginx-module.md › Bản đồ GeoIP › API cho bản đồ, và mục W18-G2-01 trong docs/plan/plan.md.

Nhiệm vụ W18-G2-01 · StatsService.
- Thư mục: control-plane/stats/, control-plane/api/
- Việc: GET /v1/stats/geo (groupBy=country|city|asn), GET /v1/stats/timeline, SSE /v1/stats/geo:watch.
- Xong khi: test API theo 3 kiểu groupBy; SSE đẩy thay đổi trong tối đa 5 giây.

Bước 1: xác nhận phần Antigravity, tuần hiện tại, W17-G2-01 đã merge.
Bước 2: tạo Implementation Plan rồi DỪNG, chờ tôi duyệt.
Bước 3 (sau khi duyệt): nhánh W18-G2-01-stats-service, làm, chạy go test/golangci-lint,
cập nhật mục 0 thành ✅ Done trong PR, báo cáo theo mục 9.
Chuẩn bắt buộc: mục 6a AGENTS.md (test viết trước code, tự review theo checklist, bằng chứng là output thật). Mức review: L2.
Implementation Plan phải có thêm: bất biến cần giữ, ca biên và đường lỗi, danh sách test (gồm test âm).
Sau khi mở PR (báo cáo mục 9, ghi "Review: L2" và SHA commit cuối): DỪNG, chờ Claude Code review. Không tự merge.
```

### W18-G2-02 · Antigravity · Review L2 · Cần trước: —
```
Bạn là agent Antigravity trong dự án Strata. Đọc AGENTS.md và mục W18-G2-02 trong docs/plan/plan.md.
Nhiệm vụ W18-G2-02 · Danh sách IP của bot tốt. Thư mục: control-plane/.
Việc: job hằng ngày lấy dải IP công bố chính thức của các crawler lớn (Google, Bing…), lưu phiên bản vào MinIO, đóng vào bundle.
Xong khi: job chạy trên lab; bundle chứa danh sách; nguồn từng danh sách ghi trong README.
Lưu ý: chỉ dùng nguồn công bố chính thức của từng crawler.
Bước 1: xác nhận. Bước 2: Implementation Plan rồi DỪNG, chờ tôi duyệt. Bước 3: nhánh W18-G2-02-goodbot-ranges, làm, chạy go test, cập nhật mục 0, báo cáo theo mục 9.
Chuẩn bắt buộc: mục 6a AGENTS.md (test viết trước code, tự review theo checklist, bằng chứng là output thật). Mức review: L2.
Implementation Plan phải có thêm: bất biến cần giữ, ca biên và đường lỗi, danh sách test (gồm test âm).
Sau khi mở PR (báo cáo mục 9, ghi "Review: L2" và SHA commit cuối): DỪNG, chờ Claude Code review. Không tự merge.
```

### W18-F-01 · Antigravity · Review L1 · Cần trước: W18-G2-01, W17-F-01
```
Bạn là agent Antigravity trong dự án Strata. Đọc AGENTS.md, nginx-module.md › Bản đồ GeoIP › Hiển thị, và mục W18-F-01 trong docs/plan/plan.md.

Nhiệm vụ W18-F-01 · Lớp bản đồ và panel.
- Thư mục: ui/
- Việc: lớp quốc gia (thang log), lớp thành phố (vòng tròn theo ô lưới, gom cụm), bộ lọc chip, panel top quốc gia / ASN / loại tấn công, dòng thời gian.
- Xong khi: dữ liệu thật 24 giờ trên lab; đổi bộ lọc → mọi panel cập nhật cùng lúc; Playwright pass.

Bước 1: xác nhận phần Antigravity, tuần hiện tại, "Cần trước" đã merge.
Bước 2: tạo Implementation Plan rồi DỪNG, chờ tôi duyệt.
Bước 3 (sau khi duyệt): nhánh W18-F-01-map-layers, làm, chạy npm lint/test/build và Playwright,
đính kèm bản ghi trình duyệt trên lab, cập nhật mục 0 thành ✅ Done trong PR, báo cáo theo mục 9.
Chuẩn bắt buộc: mục 6a AGENTS.md (test viết trước code, tự review theo checklist, bằng chứng là output thật). Mức review: L1 (không cần Claude Code; CI và tự review là đủ).
```

### W18-S-01 · Antigravity · Review L1 · Cần trước: W18-R-02
```
Bạn là agent Antigravity trong dự án Strata. Đọc AGENTS.md và mục W18-S-01 trong docs/plan/plan.md.
Nhiệm vụ W18-S-01 · Pack bot. Thư mục: rules/.
Việc: signature bot xấu, mẫu brute force; bật mặc định rule xác minh bot tốt.
Xong khi: mọi rule có test; strata-rules test pass.
Bước 1: xác nhận. Bước 2: Implementation Plan rồi DỪNG, chờ tôi duyệt. Bước 3: nhánh W18-S-01-bot-pack, làm, cập nhật mục 0, báo cáo theo mục 9.
Chuẩn bắt buộc: mục 6a AGENTS.md (test viết trước code, tự review theo checklist, bằng chứng là output thật). Mức review: L1 (không cần Claude Code; CI và tự review là đủ).
```

---

## Tuần 19 · Drill-down, rule geo/ASN, GitOps (1)

### W19-R-01 · Antigravity · Review L3 · Cần trước: —
```
Bạn là agent Antigravity trong dự án Strata. Đọc AGENTS.md và mục W19-R-01 trong docs/plan/plan.md.

Nhiệm vụ W19-R-01 · Rule geo/ASN trong engine.
- Thư mục: engine/, engine/compiler/
- Việc: compiler đóng .mmdb vào bundle (section riêng); engine tra quốc gia và ASN tại node.
- Xong khi: rule chặn theo quốc gia và ASN có test; ghi lại kích thước bundle tăng thêm.

Bước 1: xác nhận phần Antigravity, tuần hiện tại.
Bước 2: tạo Implementation Plan rồi DỪNG, chờ tôi duyệt.
Bước 3 (sau khi duyệt): nhánh W19-R-01-geo-rules, làm, chạy cargo test,
cập nhật mục 0 thành ✅ Done trong PR, báo cáo theo mục 9.
Chuẩn bắt buộc: mục 6a AGENTS.md (test viết trước code, tự review theo checklist, bằng chứng là output thật). Mức review: L3 (khu vực rủi ro cao).
Implementation Plan phải có thêm: bất biến cần giữ, ca biên và đường lỗi, rủi ro bảo mật, danh sách test (gồm test âm và chạy sanitizer / -race).
Kế hoạch sẽ được Claude Code review trước khi tôi duyệt; chỉ bắt đầu code khi tôi trả lời "duyệt".
Sau khi mở PR (báo cáo mục 9, ghi "Review: L3" và SHA commit cuối): DỪNG, chờ Claude Code review. Không tự merge.
```

### W19-G2-01 · Antigravity · Review L2 · Cần trước: W19-R-01
```
Bạn là agent Antigravity trong dự án Strata. Đọc AGENTS.md và mục W19-G2-01 trong docs/plan/plan.md.
Nhiệm vụ W19-G2-01 · Rule geo/ASN trong policy. Thư mục: control-plane/policy/, control-plane/api/.
Việc: tạo, sửa, deploy rule geo/ASN qua API.
Xong khi: test API; deploy lên lab chặn được request theo quốc gia (giả lập IP).
Bước 1: xác nhận. Bước 2: Implementation Plan rồi DỪNG, chờ tôi duyệt. Bước 3: nhánh W19-G2-01-geo-policy, làm, chạy go test, cập nhật mục 0, báo cáo theo mục 9.
Chuẩn bắt buộc: mục 6a AGENTS.md (test viết trước code, tự review theo checklist, bằng chứng là output thật). Mức review: L2.
Implementation Plan phải có thêm: bất biến cần giữ, ca biên và đường lỗi, danh sách test (gồm test âm).
Sau khi mở PR (báo cáo mục 9, ghi "Review: L2" và SHA commit cuối): DỪNG, chờ Claude Code review. Không tự merge.
```

### W19-F-01 · Antigravity · Review L1 · Cần trước: W18-F-01
```
Bạn là agent Antigravity trong dự án Strata. Đọc AGENTS.md và mục W19-F-01 trong docs/plan/plan.md.

Nhiệm vụ W19-F-01 · Drill-down và hành động nhanh.
- Thư mục: ui/
- Việc: bấm quốc gia hoặc ASN → lọc toàn trang và bảng sự kiện → mở decision trace; nút Tạo rule chặn geo/ASN tạo bản nháp.
- Xong khi: kịch bản trên lab từ bản đồ tới bản nháp rule chờ duyệt; Playwright pass.

Bước 1: xác nhận phần Antigravity, tuần hiện tại, W18-F-01 đã merge.
Bước 2: tạo Implementation Plan rồi DỪNG, chờ tôi duyệt.
Bước 3 (sau khi duyệt): nhánh W19-F-01-map-drilldown, làm, chạy npm lint/test/build và Playwright,
đính kèm bản ghi trình duyệt trên lab, cập nhật mục 0 thành ✅ Done trong PR, báo cáo theo mục 9.
Chuẩn bắt buộc: mục 6a AGENTS.md (test viết trước code, tự review theo checklist, bằng chứng là output thật). Mức review: L1 (không cần Claude Code; CI và tự review là đủ).
```

### W19-G1-01 · Antigravity · Review L2 · Cần trước: —
```
Bạn là agent Antigravity trong dự án Strata. Đọc AGENTS.md, nginx-module.md › Control plane (các kênh thay đổi cấu hình), và mục W19-G1-01 trong docs/plan/plan.md.

Nhiệm vụ W19-G1-01 · GitOps sync (phần 1).
- Thư mục: gitops-sync/
- Việc: import YAML từ Git thành bản nháp chờ duyệt qua API; export policy ra Git.
- Xong khi: test import → bản nháp; export → file YAML đúng định dạng.
- Lưu ý: import KHÔNG BAO GIỜ deploy thẳng, luôn qua luồng duyệt.

Bước 1: xác nhận phần Antigravity, tuần hiện tại.
Bước 2: tạo Implementation Plan rồi DỪNG, chờ tôi duyệt.
Bước 3 (sau khi duyệt): nhánh W19-G1-01-gitops-sync, làm, chạy go test,
cập nhật mục 0 thành ✅ Done trong PR, báo cáo theo mục 9.
Chuẩn bắt buộc: mục 6a AGENTS.md (test viết trước code, tự review theo checklist, bằng chứng là output thật). Mức review: L2.
Implementation Plan phải có thêm: bất biến cần giữ, ca biên và đường lỗi, danh sách test (gồm test âm).
Sau khi mở PR (báo cáo mục 9, ghi "Review: L2" và SHA commit cuối): DỪNG, chờ Claude Code review. Không tự merge.
```

---

## Tuần 20 · Dashboard, GitOps (2)

### W20-R-01 · Antigravity · Review L2 · Cần trước: W17-R-01
```
Bạn là agent Antigravity trong dự án Strata. Đọc AGENTS.md và mục W20-R-01 trong docs/plan/plan.md.

Nhiệm vụ W20-R-01 · Tinh chỉnh semantic detector.
- Thư mục: engine/src/detectors/, corpus/fp/
- Việc: tự thu thập FP của semantic detector (SQLi, XSS, CMDi, template injection) rồi giảm FP. Nguồn cần tự đọc:
  (1) sự kiện được đánh dấu false positive và exception đã duyệt cho các Rule ID của semantic detector (API control plane của lab, file exception trong repo);
  (2) GET /v1/rules/{rule_id}/health trên lab để chọn rule có FP cao nhất;
  (3) replay bundle hiện tại trên corpus benign và traffic mẫu đã ẩn danh trong MinIO của lab.
  Lưu mẫu vào corpus/fp/ ở dạng đã ẩn danh.
- Xong khi: FP giảm, recall trên corpus attack và bộ biến thể strata-mutate không giảm (báo cáo trước/sau).

Bước 1: xác nhận phần Antigravity, tuần hiện tại, W17-R-01 đã merge.
Bước 2: thu thập, trình bày nhóm FP và cách xử lý rồi DỪNG, chờ tôi duyệt.
Bước 3 (sau khi duyệt): nhánh W20-R-01-semantic-tuning, làm, chạy cargo test, strata-rules test và strata-mutate,
cập nhật mục 0 thành ✅ Done trong PR, báo cáo theo mục 9 kèm số liệu trước/sau.
Chuẩn bắt buộc: mục 6a AGENTS.md (test viết trước code, tự review theo checklist, bằng chứng là output thật). Mức review: L2.
Implementation Plan phải có thêm: bất biến cần giữ, ca biên và đường lỗi, danh sách test (gồm test âm).
Sau khi mở PR (báo cáo mục 9, ghi "Review: L2" và SHA commit cuối): DỪNG, chờ Claude Code review. Không tự merge.
```

### W20-F-01 · Antigravity · Review L1 · Cần trước: W18-G2-01
```
Bạn là agent Antigravity trong dự án Strata. Đọc AGENTS.md, nginx-module.md › Giao diện quản trị (Tổng quan), và mục W20-F-01 trong docs/plan/plan.md.

Nhiệm vụ W20-F-01 · Trang Tổng quan đầy đủ.
- Thư mục: ui/
- Việc: request, tỉ lệ chặn, top rule, top route, latency engine, node lỗi, rollout đang chạy; tự làm mới, có nút tạm dừng.
- Xong khi: dữ liệu thật trên lab; Playwright pass.

Bước 1: xác nhận phần Antigravity, tuần hiện tại.
Bước 2: tạo Implementation Plan rồi DỪNG, chờ tôi duyệt.
Bước 3 (sau khi duyệt): nhánh W20-F-01-overview-full, làm, chạy npm lint/test/build và Playwright,
đính kèm ảnh chụp trên lab, cập nhật mục 0 thành ✅ Done trong PR, báo cáo theo mục 9.
Chuẩn bắt buộc: mục 6a AGENTS.md (test viết trước code, tự review theo checklist, bằng chứng là output thật). Mức review: L1 (không cần Claude Code; CI và tự review là đủ).
```

### W20-G1-01 · Antigravity · Review L2 · Cần trước: W19-G1-01
```
Bạn là agent Antigravity trong dự án Strata. Đọc AGENTS.md và mục W20-G1-01 trong docs/plan/plan.md.
Nhiệm vụ W20-G1-01 · GitOps sync (phần 2). Thư mục: gitops-sync/, control-plane/policy/ (phần khóa theo kênh).
Việc: export định kỳ; khóa policy theo kênh (UI / API / GitOps) để tránh ghi đè.
Xong khi: test khóa theo kênh: sửa từ kênh bị khóa bị từ chối.
Bước 1: xác nhận. Bước 2: Implementation Plan rồi DỪNG, chờ tôi duyệt. Bước 3: nhánh W20-G1-01-gitops-lock, làm, chạy go test, cập nhật mục 0, báo cáo theo mục 9.
Chuẩn bắt buộc: mục 6a AGENTS.md (test viết trước code, tự review theo checklist, bằng chứng là output thật). Mức review: L2.
Implementation Plan phải có thêm: bất biến cần giữ, ca biên và đường lỗi, danh sách test (gồm test âm).
Sau khi mở PR (báo cáo mục 9, ghi "Review: L2" và SHA commit cuối): DỪNG, chờ Claude Code review. Không tự merge.
```

### W20-G2-01 · Antigravity · Review L2 · Cần trước: W17-Q-01
```
Bạn là agent Antigravity trong dự án Strata. Đọc AGENTS.md, docs/reports/stats-load-w17.md và mục W20-G2-01 trong docs/plan/plan.md.
Nhiệm vụ W20-G2-01 · Tối ưu truy vấn thống kê. Thư mục: control-plane/stats/, control-plane/ingest/.
Xong khi: 24 giờ dưới 1 giây, 30 ngày dưới 3 giây trên dữ liệu thật; số liệu trước/sau.
Bước 1: xác nhận. Bước 2: Implementation Plan rồi DỪNG, chờ tôi duyệt. Bước 3: nhánh W20-G2-01-stats-perf, làm, đo, cập nhật mục 0, báo cáo theo mục 9.
Chuẩn bắt buộc: mục 6a AGENTS.md (test viết trước code, tự review theo checklist, bằng chứng là output thật). Mức review: L2.
Implementation Plan phải có thêm: bất biến cần giữ, ca biên và đường lỗi, danh sách test (gồm test âm).
Sau khi mở PR (báo cáo mục 9, ghi "Review: L2" và SHA commit cuối): DỪNG, chờ Claude Code review. Không tự merge.
```

### W20-S-01 · Antigravity · Review L1 · Cần trước: —
```
Bạn là agent Antigravity trong dự án Strata. Đọc AGENTS.md, strata-overview.md › Mô hình policy & rule, và mục W20-S-01 trong docs/plan/plan.md.
Nhiệm vụ W20-S-01 · Template policy cho API có OpenAPI. Thư mục: rules/templates/.
Việc: template api dùng positive model; có test.
Xong khi: template biên dịch được, test pass.
Bước 1: xác nhận. Bước 2: Implementation Plan rồi DỪNG, chờ tôi duyệt. Bước 3: nhánh W20-S-01-api-template, làm, cập nhật mục 0, báo cáo theo mục 9.
Chuẩn bắt buộc: mục 6a AGENTS.md (test viết trước code, tự review theo checklist, bằng chứng là output thật). Mức review: L1 (không cần Claude Code; CI và tự review là đủ).
```

---

## Tuần 21 · OpenAPI, danh mục rule, tự kiểm thử bypass

### W21-R-01 · Antigravity · Review L2 · Cần trước: —
```
Bạn là agent Antigravity trong dự án Strata. Đọc AGENTS.md, strata-overview.md › Pipeline detection (positive model), và mục W21-R-01 trong docs/plan/plan.md.

Nhiệm vụ W21-R-01 · Positive model v0.
- Thư mục: engine/, engine/compiler/
- Việc: enforce theo OpenAPI: endpoint, method, field không khai báo → violation dải 200000.
- Xong khi: test cho từng loại vi phạm.

Bước 1: xác nhận phần Antigravity, tuần hiện tại.
Bước 2: tạo Implementation Plan rồi DỪNG, chờ tôi duyệt.
Bước 3 (sau khi duyệt): nhánh W21-R-01-positive-model, làm, chạy cargo test,
cập nhật mục 0 thành ✅ Done trong PR, báo cáo theo mục 9.
Chuẩn bắt buộc: mục 6a AGENTS.md (test viết trước code, tự review theo checklist, bằng chứng là output thật). Mức review: L2.
Implementation Plan phải có thêm: bất biến cần giữ, ca biên và đường lỗi, danh sách test (gồm test âm).
Sau khi mở PR (báo cáo mục 9, ghi "Review: L2" và SHA commit cuối): DỪNG, chờ Claude Code review. Không tự merge.
```

### W21-G2-01 · Antigravity · Review L2 · Cần trước: W21-R-01
```
Bạn là agent Antigravity trong dự án Strata. Đọc AGENTS.md và mục W21-G2-01 trong docs/plan/plan.md.
Nhiệm vụ W21-G2-01 · API schema. Thư mục: control-plane/policy/, control-plane/api/.
Việc: POST /v1/schemas (OpenAPI), :validate, biên dịch vào bundle.
Xong khi: tải một OpenAPI mẫu → kiểm hợp lệ → deploy → request ngoài schema bị violation trên lab.
Bước 1: xác nhận. Bước 2: Implementation Plan rồi DỪNG, chờ tôi duyệt. Bước 3: nhánh W21-G2-01-schema-api, làm, chạy go test, cập nhật mục 0, báo cáo theo mục 9.
Chuẩn bắt buộc: mục 6a AGENTS.md (test viết trước code, tự review theo checklist, bằng chứng là output thật). Mức review: L2.
Implementation Plan phải có thêm: bất biến cần giữ, ca biên và đường lỗi, danh sách test (gồm test âm).
Sau khi mở PR (báo cáo mục 9, ghi "Review: L2" và SHA commit cuối): DỪNG, chờ Claude Code review. Không tự merge.
```

### W21-F-01 · Antigravity · Review L1 · Cần trước: W14-G2-02, W12-G2-02
```
Bạn là agent Antigravity trong dự án Strata. Đọc AGENTS.md và mục W21-F-01 trong docs/plan/plan.md.

Nhiệm vụ W21-F-01 · Trang Rule & signature, Exception, Schema.
- Thư mục: ui/
- Việc: danh mục rule theo dải ID, trạng thái staging, chỉ số sức khỏe (số lần khớp, FP, chi phí) và nút tắt khẩn cấp (bắt buộc nhập lý do); trang Exception có cảnh báo sắp hết hạn; trang tải và xem Schema.
- Xong khi: kịch bản trên lab cho cả 3 trang; tắt khẩn cấp một rule và thấy hiệu lực trên NGINX lab; Playwright pass.

Bước 1: xác nhận phần Antigravity, tuần hiện tại, "Cần trước" đã merge.
Bước 2: tạo Implementation Plan rồi DỪNG, chờ tôi duyệt.
Bước 3 (sau khi duyệt): nhánh W21-F-01-rules-pages, làm, chạy npm lint/test/build và Playwright,
đính kèm bản ghi trình duyệt trên lab, cập nhật mục 0 thành ✅ Done trong PR, báo cáo theo mục 9.
Chuẩn bắt buộc: mục 6a AGENTS.md (test viết trước code, tự review theo checklist, bằng chứng là output thật). Mức review: L1 (không cần Claude Code; CI và tự review là đủ).
```

### W21-S-01 · Antigravity · Review L1 · Cần trước: W15-S-01
```
Bạn là agent Antigravity trong dự án Strata. Đọc AGENTS.md, mục Luồng S và mục W21-S-01 trong docs/plan/plan.md.

Nhiệm vụ W21-S-01 · Tự kiểm thử và vá bypass (2).
- Thư mục: rules/, tests/bypass/, docs/reports/
- Việc: tự tìm bypass trên lab (dựng từ bản đã tag) rồi vá. Nguồn cần tự chạy:
  (1) GoTestWAF và strata-mutate với corpus mới nhất (gồm biến thể encoding, Unicode, tách tham số);
  (2) toàn bộ corpus attack (PayloadsAllTheThings, SecLists) và test go-ftw ở PL1, PL2;
  (3) so sánh differential với Coraza + CRS: payload Coraza chặn mà Strata cho qua;
  (4) các bypass cũ trong docs/reports/bypass-w15.md để kiểm tra không tái phát.
  Xếp bypass theo mức cao / trung bình / thấp; viết hoặc chỉnh rule cho bypass mức cao; phát hành pack v0.9.
- Xong khi: docs/reports/bypass-w21.md; mọi bypass mức cao đã vá; FP trên corpus benign không tăng.
- Lưu ý: chỉ chạy trên lab, không kết nối staging hay production.

Bước 1: xác nhận phần Antigravity, tuần hiện tại, W15-S-01 đã merge.
Bước 2: chạy 4 nguồn trên, tạo Implementation Plan gồm danh sách bypass và cách vá từng bypass mức cao, rồi DỪNG, chờ tôi duyệt.
Bước 3 (sau khi duyệt): nhánh W21-S-01-bypass-fixes, làm, chạy strata-rules test, strata-mutate và go-ftw,
cập nhật mục 0 thành ✅ Done trong PR, báo cáo theo mục 9 kèm số liệu trước/sau.
Chuẩn bắt buộc: mục 6a AGENTS.md (test viết trước code, tự review theo checklist, bằng chứng là output thật). Mức review: L1 (không cần Claude Code; CI và tự review là đủ).
```

### W21-Q-01 · Antigravity · Review L1 · Cần trước: —
```
Bạn là agent Antigravity trong dự án Strata. Đọc AGENTS.md và mục W21-Q-01 trong docs/plan/plan.md.
Nhiệm vụ W21-Q-01 · Regression toàn bộ. Thư mục: tests/, docs/reports/.
Việc: chạy lại toàn bộ test, fuzz, soak trên lab (dựng từ bản đã tag); tổng hợp kết quả.
Xong khi: docs/reports/regression-w21.md; mọi lỗi mức cao có ticket.
Bước 1: xác nhận. Bước 2: Implementation Plan rồi DỪNG, chờ tôi duyệt. Bước 3: nhánh W21-Q-01-regression, chạy, cập nhật mục 0, báo cáo theo mục 9.
Chuẩn bắt buộc: mục 6a AGENTS.md (test viết trước code, tự review theo checklist, bằng chứng là output thật). Mức review: L1 (không cần Claude Code; CI và tự review là đủ).
```

---

## Tuần 22 · Phát hành v1 · Gate C

### W22-S-01 · Antigravity · Review L1 · Cần trước: W21-S-01
```
Bạn là agent Antigravity trong dự án Strata. Đọc AGENTS.md và mục W22-S-01 trong docs/plan/plan.md.
Nhiệm vụ W22-S-01 · Hướng dẫn viết rule và lịch phát hành. Thư mục: docs/rules/, rules/.
Việc: docs/rules/authoring.md (định dạng, dải ID, action_mode, test bắt buộc, quy trình review); lịch phát hành gói signature hằng tuần; chuẩn bị gói signature v1.0 kèm NOTICE.
Xong khi: tài liệu được luồng S duyệt; gói v1.0 tạo được.
Bước 1: xác nhận. Bước 2: Implementation Plan rồi DỪNG, chờ tôi duyệt. Bước 3: nhánh W22-S-01-rule-docs, làm, cập nhật mục 0, báo cáo theo mục 9.
Chuẩn bắt buộc: mục 6a AGENTS.md (test viết trước code, tự review theo checklist, bằng chứng là output thật). Mức review: L1 (không cần Claude Code; CI và tự review là đủ).
```

### W22-ALL-01 · **Người** (Antigravity soạn tài liệu, 2 phiên)
Antigravity (phiên 1):
```
Bạn là agent Antigravity trong dự án Strata. Đọc AGENTS.md. Soạn phần changelog và tài liệu nâng cấp/migration cho engine, module NGINX và agent
từ lịch sử merge kể từ tuần 3. Ghi vào docs/release/v1.0-engine.md. Không tag phát hành. Mở PR để người duyệt.
```
Antigravity (phiên 2):
```
Bạn là agent Antigravity trong dự án Strata. Đọc AGENTS.md. Soạn phần changelog và tài liệu nâng cấp/migration cho control plane, UI và gói signature
từ lịch sử merge kể từ tuần 3. Ghi vào docs/release/v1.0-platform.md. Không tag phát hành. Mở PR để người duyệt.
```

**W22-ALL-02 · Gate C** · Người.
# Kế Hoạch Chi Tiết Nâng Cấp Giao Diện Web UI Strata WAF
## Tối Ưu Hóa An Toàn Thông Tin, Khả Năng Kiểm Toán & Công Thái Học SOC

> **Phiên bản:** 1.0  
> **Tài liệu nền tảng:** Tổng hợp từ 2 lượt đánh giá chuyên sâu (UI/UX Ergonomics & Information Security / SOC Review)  
> **Phạm vi tác động:** `ui/src/` (React 18, TypeScript, Tailwind CSS, i18n, Vitest) và các endpoint bổ trợ tại `control-plane/`  
> **Tiêu chuẩn áp dụng:** PCI-DSS v4.0 (Req 8.3.6), OWASP ASVS v4.0.3, SOC 2 Type II (Audit Trail & Non-repudiation), WCAG 2.1 AA (Trợ năng & Chống mù màu)

---

## 1. Mục Tiêu Chiến Lược & Chỉ Số Đo Lường (KPIs)

Bản kế hoạch này chuyển hóa toàn bộ các phát hiện và phê bình kỹ thuật thành hành động thực thi cụ thể nhằm giải quyết triệt để 3 bài toán lớn:

1. **Bảo Mật & Tuân Thủ (Security & Compliance):** Triệt tiêu rủi ro chiếm đoạt phiên làm việc khi người vận hành rời vị trí; ngăn ngừa sai sót thảm họa từ các thao tác cấu hình phá hủy; minh bạch hóa toàn bộ vết kiểm toán (Audit Trail) trên giao diện.
2. **Hiệu Suất Tác Nghiệp Sự Cố (Incident Response Velocity):** Rút ngắn thời gian từ lúc phát hiện cảnh báo đến khi phân tích xong nguyên nhân gốc rễ (Mean-Time-To-Triage - MTTT < 30 giây); hỗ trợ trích xuất nhanh lệnh tái hiện cURL; không làm mất dấu vết/bộ lọc khi di chuyển giữa các trang.
3. **Công Thái Học & Trải Nghiệm Trung Thực (Ergonomics & Honesty):** Loại bỏ hoàn toàn các thông báo trạng thái gây hiểu lầm (Dishonest Polling); tối ưu hóa thao tác bằng bàn phím (Keyboard-first SOC); triệt tiêu hiện tượng giật giao diện (CLS = 0) và đảm bảo chuẩn hiển thị cho người khiếm sắc.

---

## 2. Ma Trận Phân Bổ Hạng Mục & File Ảnh Hưởng

| Hạng mục | Mức độ | Nhóm vấn đề | File cần tạo mới / chỉnh sửa | Thời gian dự kiến |
| :--- | :---: | :--- | :--- | :---: |
| **P0-1: Inactivity Idle Timeout** | **P0** | Bảo mật / PCI-DSS | `ui/src/hooks/useIdleTimeout.ts` (mới)<br>`ui/src/context/AuthContext.tsx`<br>`ui/src/components/layout/IdleTimeoutModal.tsx` (mới) | 1 ngày |
| **P0-2: Destructive Action Safeguard** | **P0** | An toàn vận hành | `ui/src/components/ui/DestructiveConfirmModal.tsx` (mới)<br>`ui/src/pages/FleetPage.tsx`<br>`ui/src/components/policy/PolicyEditor.tsx` | 1 ngày |
| **P0-3: Audit Trail UI** | **P0** | Kiểm toán & Giải trình | `ui/src/pages/AuditPage.tsx` (mới)<br>`ui/src/api/client.ts`<br>`ui/src/router.ts`<br>`ui/src/components/layout/AppShell.tsx` | 1.5 ngày |
| **P1-1: Smart Back & Filter State** | **P1** | UX Điều tra sự cố | `ui/src/pages/EventDetailPage.tsx`<br>`ui/src/pages/EventsPage.tsx`<br>`ui/src/router.ts` | 0.5 ngày |
| **P1-2: Intelligent Filter Bar** | **P1** | Tiện ích tìm kiếm | `ui/src/components/events/EventFilterBar.tsx`<br>`ui/src/api/client.ts` | 1 ngày |
| **P1-3: Honest Live Polling Indicator** | **P1** | Tính trung thực dữ liệu | `ui/src/pages/EventsPage.tsx`<br>`ui/src/usePolling.ts`<br>`ui/src/components/ui.tsx` | 0.5 ngày |
| **P1-4: Incident Response Tooling (cURL)** | **P1** | Phân tích thù địch | `ui/src/lib/curl.ts` (mới)<br>`ui/src/components/events/EventTrace.tsx`<br>`ui/src/components/events/TruncationWarning.tsx` (mới) | 1 ngày |
| **P2-1: Global Keyboard Shortcuts** | **P2** | Công thái học bàn phím | `ui/src/hooks/useKeyboardShortcuts.ts` (mới)<br>`ui/src/components/layout/AppShell.tsx`<br>`ui/src/components/layout/KeyboardHelpModal.tsx` (mới) | 0.5 ngày |
| **P2-2: Shimmer Skeleton Loaders** | **P2** | Ổn định hình ảnh (CLS) | `ui/src/components/ui/Skeleton.tsx` (mới)<br>`ui/src/components/events/EventsTable.tsx`<br>`ui/src/pages/OverviewPage.tsx` | 0.5 ngày |
| **P2-3: Accessible Verdict Badges** | **P2** | Trợ năng / WCAG | `ui/src/components/ui.tsx`<br>`ui/src/index.css` | 0.5 ngày |

---

## 3. Chi Tiết Kỹ Thuật Từng Giai Đoạn

### Giai Đoạn 1: Bảo Mật, Kiểm Toán & An Toàn Thao Tác (P0 - Security & Safety)

#### 1.1. Inactivity Idle Timeout & Tự Động Khóa Phiên (PCI-DSS v4.0 Req 8.3.6)
- **Vấn đề gốc:** Hiện tại token lưu ở `localStorage` hoặc session in-memory không có cơ chế phát hiện người dùng bất động. Khi analyst rời bàn làm việc trong phòng SOC, hệ thống vẫn duy trì quyền ghi.
- **Giải pháp kiến trúc:**
  - Tạo custom hook `ui/src/hooks/useIdleTimeout.ts` theo dõi các sự kiện DOM: `['mousedown', 'keydown', 'scroll', 'touchstart']` có gắn throttle (500ms).
  - Cấu hình chuẩn SOC: Thời gian rảnh tối đa **15 phút (900s)**.
  - Tại phút thứ 14 (840s): Kích hoạt `IdleTimeoutModal.tsx` hiển thị đếm ngược 60 giây kèm cảnh báo âm thanh/visual nhấp nháy nhẹ.
  - Nếu người dùng bấm "Tiếp tục làm việc" (Stay Logged In) $\rightarrow$ reset timer và gọi nhẹ `apiClient.me()` làm mới phiên.
  - Nếu hết 60s không phản hồi $\rightarrow$ xóa sạch token, kích hoạt `AuthContext.logout()`, chuyển hướng về `#/login` kèm thông báo: *"Phiên làm việc đã tự động kết thúc do không hoạt động trong 15 phút để bảo vệ an toàn."*
- **Tiêu chí nghiệm thu (Acceptance Criteria):**
  - Giả lập tua nhanh thời gian bằng Vitest fake timers: Sau 14 phút modal hiện ra; sau 15 phút token bị xóa và trang chuyển về login.
  - Phím bấm và di chuột bất kỳ trong 14 phút đầu reset timer về 0.

#### 1.2. Hộp Thoại Xác Nhận Thao Tác Phá Hủy (Destructive Action Safeguards)
- **Vấn đề gốc:** Nút "Revoke Node" tại `FleetPage.tsx` hay "Emergency Block IP" có thể bị bấm nhầm bằng 1 cú click chuột, gây cô lập node sản xuất hoặc chặn nhầm dải IP gateway.
- **Giải pháp kiến trúc:**
  - Xây dựng component `ui/src/components/ui/DestructiveConfirmModal.tsx`:
    - Nhận vào `targetName`, `actionType` ('revoke_node' | 'block_ip' | 'disable_rule'), `onConfirm`, `onClose`.
    - **Yêu cầu gõ xác nhận:** Bắt buộc người dùng phải gõ chính xác chuỗi định danh tài nguyên (ví dụ mã node `node-edge-hn-01` hoặc từ khóa `XÁC NHẬN` / `CONFIRM`).
    - **Trường nhập lý do bắt buộc (Audit Reason):** Tối thiểu 10 ký tự giải thích lý do thực hiện thao tác (lý do này sẽ được gửi kèm trong payload API để ghi vào `audit_log`).
    - Nút "Thực hiện" bị disabled hoàn toàn cho đến khi chuỗi nhập khớp 100% và lý do hợp lệ.
- **Tiêu chí nghiệm thu:**
  - Nút xác nhận chỉ sáng khi input trùng khớp.
  - Thao tác gửi kèm header/field `reason` đến API backend.

#### 1.3. Giao Diện Tra Cứu Nhật Ký Kiểm Toán (Audit Trail UI - `#/audit`)
- **Vấn đề gốc:** Backend đã có bảng PostgreSQL `audit_log` ghi nhận actor, action, timestamp, resource, diff before/after, nhưng UI hoàn toàn không có trang hiển thị. Operator không thể tự kiểm tra ai đã sửa đổi cấu hình.
- **Giải pháp kiến trúc:**
  - Bổ sung route `'audit'` vào `ui/src/router.ts` và menu điều hướng trên `AppShell.tsx` (chỉ hiển thị với user có role `admin` hoặc `operator`).
  - Thêm phương thức API `apiClient.listAuditLogs(params: AuditFilterParams)` trong `ui/src/api/client.ts`.
  - Tạo trang `ui/src/pages/AuditPage.tsx`:
    - Bộ lọc theo: Thời gian, Actor (username), Action (`local_users.*`, `policy.update`, `policy.deploy`, `node.revoke`, `rule.disable`), Resource.
    - Bảng hiển thị: Thời gian (relative + absolute), Actor, IP nguồn, Hành động, Tài nguyên đích.
    - Drawer/Modal xem chi tiết: Hiển thị JSON Diff dạng màu (xanh lá = added, đỏ = deleted) của hai trường `before` và `after`.
- **Tiêu chí nghiệm thu:**
  - User role `viewer` không thấy menu Audit và bị chặn truy cập nếu gõ trực tiếp `#/audit`.
  - Hiển thị đầy đủ lịch sử thay đổi cấu hình gần nhất.

---

### Giai Đoạn 2: Trải Nghiệm Cốt Lõi & Điều Tra Sự Cố (P1 - Core Usability & Incident Response)

#### 2.1. Bảo Lưu Bộ Lọc & Trạng Thái Điều Hướng (Smart Back Navigation)
- **Vấn đề gốc:** Tại `EventDetailPage.tsx:44`, nút quay lại hardcode `<a href={href({ page: 'events' })}>`. Khi analyst đang ở trang 4 của bộ lọc phức tạp (`action=block&policy_id=api-gateway&rule_id=942100`) bấm xem 1 sự kiện rồi bấm Back, toàn bộ query param và trang số 4 biến mất sạch, bắt đầu lại từ trang 1 rỗng.
- **Giải pháp kiến trúc:**
  - Chỉnh sửa `EventDetailPage.tsx`:
    - Kiểm tra `window.history.length > 1` và `document.referrer`.
    - Khi bấm Back: Sử dụng `window.history.back()`.
    - Fallback: Nếu người dùng truy cập trực tiếp bằng đường link được chia sẻ qua chat/email $\rightarrow$ fallback về `href({ page: 'events' })`.
  - Đồng bộ `EventsPage.tsx`:
    - Khi thay đổi `pageIndex`, cập nhật query URL hash (ví dụ: `#/events?page=4&action=block...`) thông qua `replaceQuery` thay vì chỉ lưu state cục bộ. Nhờ đó, khi `history.back()` hoạt động, bảng sự kiện phục hồi chính xác trang 4 và các bộ lọc đang chọn.
- **Tiêu chí nghiệm thu:**
  - Đang lọc sự kiện ở trang 2 $\rightarrow$ click vào 1 dòng sự kiện $\rightarrow$ bấm "Quay lại" $\rightarrow$ bảng sự kiện giữ nguyên các bộ lọc và vẫn ở trang 2.

#### 2.2. Thanh Lọc Thông Minh (Intelligent Filter Bar)
- **Vấn đề gốc:** `EventFilterBar.tsx` yêu cầu người dùng tự gõ tay mã `policy_id` và `node_id`. Gõ sai một ký tự sẽ ra kết quả rỗng. Trường `rule_id` chỉ cho nhập 1 số đơn lẻ.
- **Giải pháp kiến trúc:**
  - Chuyển ô `policy_id` thành Dropdown / Combobox: Tự động fetch danh sách từ `apiClient.listPolicies()` khi mount, hiển thị dạng `[ID] Tên Policy` kèm tùy chọn "Tất cả policy".
  - Chuyển ô `node_id` thành Dropdown: Lấy danh sách từ `apiClient.listNodes()`, hiển thị `[Hostname] (ID)`.
  - Nâng cấp ô `rule_id`:
    - Cho phép nhập danh sách phân tách bằng dấu phẩy (ví dụ: `942100, 941100, 930100`).
    - Bổ sung dropdown gợi ý nhanh nhóm tấn công: `SQL Injection (CRS 942xxx)`, `XSS (CRS 941xxx)`, `RCE (CRS 932xxx)`, `Protocol Violation (CRS 920xxx)`.
- **Tiêu chí nghiệm thu:**
  - Người dùng chọn được policy và node từ danh sách mà không cần gõ phím.
  - Nhập chuỗi nhiều rule ID được tách thành mảng đúng chuẩn khi gửi lên API `events:search`.

#### 2.3. Minh Bạch Hóa Trạng Thái Tự Động Làm Mới (Honest Live Polling)
- **Vấn đề gốc:** `EventsPage.tsx:81` có code `if (!live || pageIndex > 0) return;`. Khi chuyển sang trang 2+, hệ thống ngầm tắt timer refresh để chống trôi dòng, nhưng nút bấm trên UI vẫn hiển thị "Tạm dừng" kèm icon Play/Pause như thể đang chạy ngầm $\rightarrow$ Đánh lừa người vận hành.
- **Giải pháp kiến trúc:**
  - Tách bạch rõ 2 trạng thái: `liveEnabled` (mong muốn của người dùng) và `pollingActive` (trạng thái thực tế của engine).
  - Khi `pageIndex > 0`:
    - Nút Auto-refresh chuyển sang trạng thái disabled hoặc kèm nhãn phụ: `Tạm dừng (Trang 2+)`.
    - Hiển thị một Banner nhỏ phía trên bảng:  
      *⚠️ "Chế độ xem trực tiếp tạm dừng khi bạn xem các trang cũ để tránh xáo trộn dòng. [Bấm vào đây để về Trang 1 và tiếp tục theo dõi trực tiếp]."*
- **Tiêu chí nghiệm thu:**
  - Tại trang 1: Badge hiển thị chấm xanh nhấp nháy "Đang cập nhật trực tiếp (5s)".
  - Tại trang > 1: Badge chuyển sang màu xám "Tạm dừng cập nhật (Đang ở trang cũ)".

#### 2.4. Tiện Ích Tái Hiện Khai Thác (Incident Response Tooling - cURL & Truncation)
- **Vấn đề gốc:** Khi điều tra một cuộc tấn công tinh vi, analyst cần kiểm thử lại request đó qua terminal hoặc chuyển cho đội AppSec. Hiện tại phải copy từng trường thủ công (Host, Path, Header, Body). Ngoài ra, nếu body vượt quá giới hạn capture buffer (8KB), UI không cảnh báo khiến analyst phân tích trên payload thiếu.
- **Giải pháp kiến trúc:**
  - Tạo module `ui/src/lib/curl.ts`: Hàm `buildCurlFromEvent(event: Event): string`:
    - Dựng lệnh chuẩn bash/zsh:  
      `curl -i -X POST 'https://api.example.test/v1/login' \`  
      `  -H 'Host: api.example.test' \`  
      `  -H 'User-Agent: ...' \`  
      `  --data-raw '...'`
    - Tự động escape các ký tự đặc biệt (`'`, `"`, `\n`, shell variables).
  - Đặt nút **"Copy as cURL"** cạnh nút "Copy Block ID" trên `EventDetailPage.tsx`.
  - Cảnh báo cắt ngắn dữ liệu (`TruncationWarning.tsx`):
    - Nếu `event.raw_body_truncated === true` hoặc `event.input_snippet` đạt ngưỡng tối đa: Hiển thị icon cảnh báo màu cam cạnh snippet:  
      *⚠️ "Dữ liệu payload đã bị cắt ngắn do vượt quá giới hạn đệm bắt giữ của WAF (8KB). Chuỗi hiển thị bên dưới chỉ chứa phần đầu của request."*
- **Tiêu chí nghiệm thu:**
  - Click "Copy as cURL" sao chép thành công lệnh bash hợp lệ vào clipboard.
  - Test case kiểm tra chuỗi escape với các ký tự nguy hiểm (`$`, `\`, backticks).

---

### Giai Đoạn 3: Công Thái Học & Trợ Năng Giao Diện (P2 - Ergonomics & Accessibility)

#### 3.1. Hệ Thống Phím Tắt Toàn Cục (Keyboard Shortcuts)
- **Vấn đề gốc:** Analyst thao tác trong ca trực SOC liên tục chuyển đổi giữa chuột và phím, làm giảm tốc độ xử lý khi có hàng trăm cảnh báo dồn dập.
- **Giải pháp kiến trúc:**
  - Xây dựng custom hook `ui/src/hooks/useKeyboardShortcuts.ts`:
    - Phím `/`: Focus ngay lập tức vào ô tìm kiếm Block ID trên Header hoặc ô Filter IP.
    - Phím `j` / `k` (khi đang ở bảng sự kiện): Di chuyển con trỏ chọn dòng lên / xuống.
    - Phím `Enter` (khi dòng đang được chọn): Mở chi tiết sự kiện của dòng đó.
    - Phím `Escape`: Đóng bất kỳ Modal hoặc Drawer đang mở.
    - Phím `?`: Bật Modal trợ giúp danh sách phím tắt (`KeyboardHelpModal.tsx`).
  - Khóa phím tắt khi người dùng đang gõ trong các thẻ `<input>`, `<textarea>` hoặc modal đang mở.
- **Tiêu chí nghiệm thu:**
  - Bấm `/` con trỏ nhảy ngay vào ô tìm kiếm; bấm `Esc` thoát modal.

#### 3.2. Shimmer Skeleton Loaders (Triệt Tiêu Hiện Tượng Giật Giao Diện - CLS)
- **Vấn đề gốc:** Khi đổi trang hoặc đổi bộ lọc, các component bảng sự kiện và biểu đồ biến mất và thay thế bằng text "Loading...", làm chiều cao container co lại rồi giãn ra đột ngột gây nhức mắt (CLS > 0.25).
- **Giải pháp kiến trúc:**
  - Tạo `ui/src/components/ui/Skeleton.tsx` với hiệu ứng animation shimmer nhẹ nhàng nền xám tôn trọng Dark/Light mode.
  - `SkeletonTable.tsx`: Giữ nguyên chiều cao cố định của 10 dòng bảng kèm các ô chữ nhật giả lập các cột Status, Host, IP, Rule.
  - `SkeletonChart.tsx`: Giữ nguyên khung chiều cao 240px của biểu đồ đường khi đang tải dữ liệu `stats/overview`.
- **Tiêu chí nghiệm thu:**
  - Layout không bị co giật khi chuyển trạng thái tải dữ liệu; CLS đo bằng Lighthouse < 0.05.

#### 3.3. Trợ Năng Trực Quan Cho Người Khiếm Sắc (Colorblind Accessibility - WCAG 2.1 AA)
- **Vấn đề gốc:** Các huy hiệu phán quyết (`VerdictBadge`) và trạng thái node (`StateBadge`) hiện chỉ dựa vào màu sắc (Đỏ = Block, Vàng = Shadow, Xanh = Pass, Xám = Offline). Người khiếm sắc đỏ-xanh (Protanopia / Deuteranopia) rất khó phân biệt giữa Block và Shadow trong môi trường thiếu sáng.
- **Giải pháp kiến trúc:**
  - Cập nhật `VerdictBadge` trong `ui/src/components/ui.tsx`: Bổ sung ký hiệu hình học và icon đi kèm:
    - **BLOCK:** Kèm icon Khiên gạch chéo `ShieldX` + chữ in hoa đậm + viền nét liền đỏ.
    - **SHADOW:** Kèm icon Con mắt theo dõi `Eye` + chữ in hoa nghiêng + viền nét đứt vàng hổ phách.
    - **PASS:** Kèm icon Tích xanh `CheckCircle` + viền nét chấm xanh lục.
  - Cập nhật `dot` status trong `FleetPage.tsx`: Không dùng chấm tròn đơn thuần mà kết hợp ký hiệu (Dấu `●` Online, Dấu `✖` Revoked, Dấu `○` Offline).
- **Tiêu chí nghiệm thu:**
  - Khi xem ở chế độ đen trắng (Grayscale filter), người dùng vẫn nhận diện chính xác 100% phán quyết mà không cần nhìn màu.

---

## 4. Kế Hoạch Kiểm Thử Tự Động (Vitest Test Suite)

Mỗi tính năng mới bắt buộc phải đi kèm bộ kiểm thử tự động tại `ui/src/__tests__/`:

```
ui/src/__tests__/
├── IdleTimeout.test.tsx         # Giả lập 15m rảnh, hiển thị countdown, trigger logout
├── DestructiveModal.test.tsx    # Kiểm tra chặn bấm khi gõ sai chuỗi xác nhận
├── AuditPage.test.tsx           # Kiểm tra render bảng audit, RBAC check (chặn viewer)
├── NavigationBack.test.tsx      # Kiểm tra history.back() giữ nguyên page index & query
├── IntelligentFilters.test.tsx  # Kiểm tra dropdown policy/node và phân tách multi rule_id
├── HonestPolling.test.tsx       # Kiểm tra badge hiển thị đúng "Tạm dừng" khi pageIndex > 0
├── CurlGenerator.test.ts        # Unit test sinh lệnh cURL với payload phức tạp
└── KeyboardShortcuts.test.tsx   # Kiểm tra phím tắt '/', 'j/k', 'Esc'
```

Lệnh thực thi kiểm thử trong môi trường container:
```bash
docker run --rm -v $(pwd)/ui:/ui -w /ui node:24.21.0-bookworm-slim npm test
```

---

## 5. Lộ Trình Triển Khai (Sprint Roadmap)

```
[Sprint 1: Security & Compliance] (P0)
├── Ngày 1: useIdleTimeout + IdleTimeoutModal + Cập nhật AuthContext
├── Ngày 2: DestructiveConfirmModal + Tích hợp FleetPage & PolicyEditor
└── Ngày 3: Trang AuditPage + API client audit + Router hash '#/audit'

[Sprint 2: Investigation Workflow & Ergonomics] (P1 & P2)
├── Ngày 4: Smart Back Navigation (EventDetailPage) + Honest Live Polling
├── Ngày 5: Dropdown Filter Bar (Policy & Node select) + Multi Rule input
├── Ngày 6: Incident Tooling (Copy as cURL generator) + Truncation Warning
└── Ngày 7: Keyboard Shortcuts + Shimmer Skeletons + Colorblind Badges

[Sprint 3: Verification & Hardening]
├── Ngày 8: Viết toàn bộ Vitest test suites + Đo lường CLS & Accessibility
└── Ngày 9: E2E Smoke test trên Lab + Soát xét i18n Anh - Việt
```

---

## 6. Kết Luận & Cam Kết Kỹ Thuật

Bản kế hoạch này loại bỏ hoàn toàn các nhận định cảm tính, tập trung 100% vào mã nguồn thực tế và chuẩn hóa hệ thống quản trị Strata WAF theo đẳng cấp của các nền tảng bảo mật hàng đầu (Cloudflare, AWS WAF, Datadog). 

Toàn bộ các thay đổi đều tương thích ngược với API hiện tại, không gây breaking changes đối với data plane NGINX / Rust engine, và sẵn sàng cho việc triển khai mã nguồn ngay lập tức.

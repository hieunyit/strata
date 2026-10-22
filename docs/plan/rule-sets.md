# Bộ rule mặc định và tùy chỉnh rule theo policy (đề xuất)

Trạng thái: **PO duyệt 22/10/2026, đang làm** (RS-1, RS-2 xong). Người lập: Claude Code (strata-59).
Tham chiếu: `docs/design/strata-overview.md` › Mô hình policy & rule (khối *Template*,
*Signature sets*, *Overrides*); mô hình chỉnh policy của NGINX App Protect trong NGINX Instance
Manager (PO chọn 22/10/2026).

## 1. Mục tiêu

Người vận hành tạo policy từ một **bộ mặc định hợp lý**, rồi **chọn và sửa** như trong NIM:

1. Chọn template (Cơ bản, Nghiêm ngặt, API, Website).
2. Trong policy, xem các **bộ rule** (bộ chữ ký theo loại tấn công, các nhóm bot); mỗi bộ có
   một action: **Chặn**, **Chỉ ghi log**, **Tắt**.
3. Mở một bộ để thấy từng rule; **ghi đè từng rule** (bật/tắt, đổi action) khi cần.
4. Mọi thay đổi đi qua version, replay và duyệt bốn mắt như hiện nay.

PO 22/10/2026: policy mới **chỉ ghi log mọi bot**; người vận hành tự bật chặn từng nhóm.

## 2. Hiện trạng

| Có | Thiếu |
| --- | --- |
| Template `base`, `web`, `api` (W20-S-01) | Template dùng bộ rule; template Nghiêm ngặt |
| Gói signature (Sigma, ET Open, danh sách bot) bật **cả gói**: `signatures: off \| shadow \| enforce` | Chọn **theo nhóm** trong gói |
| Paranoia CRS 1–4, plugin CRS, geo rule, exception theo route + field + rule | Tắt/đổi action **một rule cho cả policy** (exception chỉ hẹp theo route) |
| `staged_rules`: tối đa 16 rule chỉ ghi log (nội bộ, auto-staging) | Ghi đè action không giới hạn 16, do người dùng chọn |
| Section `SCOPE` (W19): rule chỉ chạy cho policy được liệt kê, chế độ enforce/log, ≤ 65.536 mục | Chế độ **chặn** cho rule chỉ đánh dấu |
| Khoảng 1.450 rule bot (`rules/bots`), gắn tag: `ai-crawler`, `scanner`, `http-library`, `browser-automation`, `seo`, `advertising`, `search-engine`, `monitoring`, `feed-reader`, `social-preview`, `archiver`, `academic`; rule 500001 (bot giả danh máy tìm kiếm) | Rule bot đều **điểm 0** (chỉ đánh dấu): bật lên cũng **không chặn được** |
| Trang Rules & packs: danh mục rule (chỉ đọc) | Chỉnh rule từ giao diện |

## 3. Mô hình

### 3.1 Bộ rule (rule set)

Một bộ rule là **bộ lọc trên metadata rule** (không phải danh sách ID chép tay), nên rule mới của
gói tự vào đúng bộ khi gói cập nhật:

```yaml
name: bots-scanners
title: Bot quét lỗ hổng
kind: bot            # attack | bot | technology
match:
  sources: [crawler-user-agents, crs]   # metadata.source
  tags: [scanner]                       # metadata.tags (một trong)
  attack_types: []                      # metadata.attack_type (một trong)
  ids: [500001]                         # thêm rule cụ thể
default_action: log
```

**Bộ dựng sẵn**, có phiên bản và đi kèm phiên bản sản phẩm:

| Nhóm | Bộ | Lọc | Mặc định (template Cơ bản) |
| --- | --- | --- | --- |
| Tấn công | SQL injection, XSS, RCE/command injection, LFI/path traversal, RFI, PHP, Java, Session fixation, Protocol, Virtual patch CVE | `attack_type`, nguồn `crs`/`strata`/`virtual-patch` | như hiện nay (gói core chặn theo paranoia) |
| Tấn công (gói signature) | Sigma, ET Open | nguồn `sigma`, `et-open` | Chỉ ghi log (như `signatures: shadow`) |
| Bot · độc hại | Bot quét lỗ hổng | tag `scanner`, rule 913xxx | Chỉ ghi log |
| Bot · độc hại | Bot giả danh máy tìm kiếm | rule 500001 | Chỉ ghi log |
| Bot · tự động hóa | Thư viện HTTP | tag `http-library` | Chỉ ghi log |
| Bot · tự động hóa | Trình duyệt tự động | tag `browser-automation` | Chỉ ghi log |
| Bot · không tin cậy | AI crawler | tag `ai-crawler` | Chỉ ghi log |
| Bot · không tin cậy | SEO, quảng cáo | tag `seo`, `advertising` | Chỉ ghi log |
| Bot · tin cậy | Máy tìm kiếm, giám sát, feed, xem trước mạng xã hội, lưu trữ, học thuật | các tag còn lại | Chỉ ghi log (không nên chặn) |

**Bộ tự tạo**: người vận hành nhân bản một bộ dựng sẵn rồi sửa bộ lọc, hoặc tạo bộ chỉ gồm ID.

### 3.2 Policy

Thêm hai khối vào `Spec` (khối *Signature sets* và *Overrides* của thiết kế):

```yaml
rule_sets:                 # thứ tự có nghĩa: bộ sau ghi đè bộ trước cho rule thuộc cả hai
  - { set: attack-sqli, action: block }
  - { set: bots-scanners, action: block }
  - { set: bots-ai-crawlers, action: log }
rule_overrides:            # ưu tiên cao nhất; mỗi mục có lý do
  - { rule: 942100, action: log, reason: "FP trên /search, theo dõi" }
  - { rule: 500213, action: off, reason: "crawler nội bộ" }
```

Action: `block` (chặn ngay khi khớp, kể cả rule điểm 0), `log` (sự kiện có Event ID, không bao
giờ chặn), `off` (không chạy), `default` (hành vi gốc của rule: điểm + ngưỡng). Thứ tự hiệu lực:
**exception** (route + field) > **rule_overrides** > **rule_sets** (bộ sau thắng) > gốc.
Mức paranoia CRS vẫn áp trước: rule trên mức enforce chỉ chạy shadow, kể cả khi bộ chọn `block`.

Giới hạn: tối đa 32 bộ và 2.048 ghi đè mỗi policy. Compiler chỉ ghi vào bundle những rule mà
action hiệu lực **khác** hành vi gốc, nên bundle không phình theo số rule của gói.

### 3.3 Bundle và engine

Section mới **`OVERRIDE` (17)**, codec `SOV1`: `(policy_index u32, rule_id u32, action u8)` theo
thứ tự (policy, rule); action `0 off`, `1 log`, `2 block`; tối đa 65.536 mục. Engine:

- Khi một rule khớp, tra `(policy, rule)`: `off` bỏ qua; `log` đi đường giống `staged_rules` (sự
  kiện, không cộng điểm chặn); `block` đặt `block_alone`.
- Không có mục: như hiện nay.
- Node cũ không hiểu section 17 thì không nhận bundle có section này: kiểm tra tương thích của
  B02 (manifest liệt kê `section.17`) đã chặn deploy tới node đó, kèm lỗi rõ.

`staged_rules` và `SCOPE` giữ nguyên.

### 3.4 Compiler và control plane

- **Danh mục bộ dựng sẵn:** file trong repo (`rules/sets/*.yaml`), kiểm schema, đóng vào image.
  Bộ tự tạo lưu PostgreSQL (migration mới), có version và audit.
- **Compiler:** giải `rule_sets` + `rule_overrides` trên danh mục rule của bundle, cho ra danh
  sách mục `OVERRIDE`. Quá giới hạn hoặc tham chiếu rule/bộ không có thì từ chối khi lưu policy
  (lỗi có tên bộ/rule).
- **Template:** thêm `strict`. Mọi template đặt bot ở `log` (quyết định PO); `strict` chặn các bộ
  tấn công độ chính xác cao ở paranoia 2.
- **API:**
  - `GET /v1/rule-sets` (danh sách, số rule mỗi bộ theo gói hiện tại);
  - `GET /v1/rule-sets/{name}/rules` (phân trang, tìm);
  - CRUD bộ tự tạo;
  - `GET /v1/policies/{id}/effective-rules` (action hiệu lực từng rule, nguồn của action: gốc,
    bộ, ghi đè).
- **Replay:** thay đổi bộ/ghi đè là thay đổi spec, nên tự có replay. Báo cáo replay thêm "rule
  đổi action" để người duyệt thấy tác động.

### 3.5 Giao diện (kiểu NIM)

- **Trình sửa policy, tab "Bộ rule":**
  - nhóm Tấn công / Bot / Công nghệ;
  - mỗi bộ: nút gạt bật, chọn action, số rule, số sự kiện 24 giờ qua;
  - nút "Xem rule" mở danh sách rule của bộ (tìm theo ID/tên, lọc severity/paranoia), ghi đè
    từng rule kèm lý do.
- **Tab "Ghi đè":** mọi ghi đè của policy, sửa/xóa.
- **Trang Rules & packs:**
  - danh mục đầy đủ có tìm/lọc (thay ô gõ tự do bằng danh sách chọn), phân trang;
  - xem rule thuộc bộ nào, policy nào ghi đè nó;
  - "Thêm ghi đè vào policy…" tạo bản nháp.
- **Từ sự kiện:** trên trace một sự kiện, "Ghi đè rule này" (cho cả policy) bên cạnh "Tạo
  exception" (hẹp theo route).
- **Diff policy và trang duyệt:** hiện thay đổi bộ/ghi đè dễ đọc.

## 4. Chia việc

| Mã | Việc | Tầng |
| --- | --- | --- |
| RS-1 ✅ | Section `OVERRIDE` trong engine + test (khớp/không khớp, log không chặn, block với điểm 0, off), fuzz codec. Thêm byte header 48 `requires` (bit 0) để engine cũ **từ chối** bundle thay vì bỏ qua ghi đè (engine cũ bỏ qua kind lạ) | Rust |
| RS-2 ✅ | Compiler: `rule_sets`, `rule_overrides`, danh mục `rules/sets/catalog.yaml` (19 bộ dựng sẵn), giới hạn, schema policy. Control plane gửi bộ lọc đã mở rộng (không gửi tên bộ); compiler đọc metadata rule từ chính file IR `--rules` | Rust + spec |
| RS-3 | Control plane: spec, kiểm khi lưu, template `strict` + bot `log`, API bộ rule và effective-rules, bộ tự tạo (migration) | Go |
| RS-4 | UI: tab Bộ rule, Ghi đè, trang Rules & packs, nút từ sự kiện, diff/duyệt | React |
| RS-5 | Lab: bộ bot chặn thật (scanner) trên 2 node, rollback, node cũ bị chặn deploy; replay báo rule đổi action | e2e |

Mỗi việc một nhánh, gate cục bộ như kế hoạch Compact (§8a). RS-1 → RS-2 → RS-3 → RS-4 → RS-5.

## 5. Rủi ro

| Rủi ro | Giảm thiểu |
| --- | --- |
| Chặn nhầm bot tốt (Googlebot) | Bot mặc định chỉ ghi log; bộ "tin cậy" có cảnh báo khi chọn Chặn; 500001 kiểm dải IP đã công bố |
| Bộ lọc theo tag kéo theo rule ngoài ý muốn khi gói cập nhật | Diff gói (C02) hiện rule mới vào bộ; replay trước khi duyệt |
| Bundle phình | Chỉ ghi mục khác hành vi gốc; giới hạn 65.536 |
| Node cũ chạy bundle thiếu ghi đè (ghi đè `off` không có hiệu lực) | Kiểm tra tương thích B02 chặn deploy |
| Ghi đè rộng che mất tấn công | Bắt buộc lý do; hiện trong duyệt bốn mắt và audit; báo cáo replay |

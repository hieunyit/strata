# AGENTS.md — Strata WAF

Hướng dẫn chung cho mọi agent làm việc trong repo này: **Claude Code** và **Google Antigravity**. Đọc toàn bộ file này trước mỗi nhiệm vụ.

## 0. Tiến độ hiện tại

> **Tuần hiện tại: 6** · Khối `A2` (tuần 6–7) · Giai đoạn A (tới shadow, Gate A cuối tuần 10)
> Cập nhật lần cuối: 2026-10-10

**Quy tắc dùng mục này**

- Chỉ nhận nhiệm vụ của **tuần hiện tại**, hoặc nhiệm vụ của tuần trước còn trạng thái chưa xong. Không làm nhiệm vụ của tuần sau, kể cả khi được giao nhầm; nếu bị giao thì dừng và báo.
- Kiểm tra "Cần trước" bằng cả hai cách: trạng thái trong bảng dưới là `✅ Done`, **và** nhánh của nhiệm vụ đó đã merge vào `main`.
- Khi PR của nhiệm vụ sẵn sàng merge, agent sửa **đúng dòng của nhiệm vụ mình** trong bảng tuần hiện tại thành `✅ Done` ngay trong PR đó. Không sửa dòng của nhiệm vụ khác, không sửa con trỏ tuần.
- PO / tech lead đổi con trỏ "Tuần hiện tại" và chép bảng nhiệm vụ tuần mới vào mục này vào sáng thứ 2.

**Ký hiệu**: `✅ Done` · `🔄 Đang làm` · `⏳ Chưa bắt đầu` · `⛔ Bị chặn` (ghi lý do)

**Nhiệm vụ tuần 6**

| Mã | Nhiệm vụ | Công cụ | Cần trước | Trạng thái |
| --- | --- | --- | --- | --- |
| W06-N-01 | Response path (header/body filter, data guard, trước gzip) | Claude Code | — | ✅ Done |
| W06-R-01 | Lớp response + port tokenizer SQLi/XSS | Claude Code | — | ⏳ Chưa bắt đầu |
| W06-G1-01 | Sự kiện từ worker tới control plane (PushEvents, spool, metrics) | Claude Code | — | ✅ Done |
| W06-S-01 | Nhập nhóm injection của CRS | Antigravity | W06-R-01 | ⏳ Chưa bắt đầu |
| W06-G2-01 | Event ingest → ClickHouse + API sự kiện | Antigravity | — | ✅ Done |
| W06-F-01 | Trang Sự kiện nối API thật | Antigravity | W06-G2-01 | ✅ Done |
| W06-Q-01 | Kiểm tra mất sự kiện khi khởi động lại agent | Antigravity | W06-G1-01, W06-G2-01 | ⏳ Chưa bắt đầu |

**Các tuần đã qua**: tuần 3–5 coi là xong. Nhiệm vụ nào của tuần 3–5 chưa merge thì PO thêm vào bảng trên với trạng thái hiện tại.

**Lộ trình tuần 3–22** (chi tiết từng nhiệm vụ trong `docs/plan/plan.md`)

| Tuần | Chủ đề | Khối | Trạng thái |
| --- | --- | --- | --- |
| 3 | Đường đi request, khung các thành phần | A1 | ✅ Done |
| 4 | Mốc nối thông end-to-end | A1 | ✅ Done |
| 5 | Bundle và hot reload | A1 | ✅ Done |
| 6 | Đường đi response và sự kiện | A2 | 🔄 Đang làm |
| 7 | Fail mode, CPU budget, độ bền | A2 | ⏳ |
| 8 | Kiểm thử (1), mức tin cậy rule | A3 | ⏳ |
| 9 | Benchmark, soak, staging, gói signature v0 | A3 | ⏳ |
| 10 | Đóng gói và shadow · **Gate A** | A3 | ⏳ |
| 11 | Circuit breaker, canary 1% | B1 | ⏳ |
| 12 | Canary 5%, fallback toàn cụm, tắt rule khẩn cấp | B1 | ⏳ |
| 13 | Replay và luồng duyệt | B1 | ⏳ |
| 14 | Exception từ Block ID, sức khỏe rule, game day | B2 | ⏳ |
| 15 | Enforce 100% | B2 | ⏳ |
| 16 | Ổn định enforce · **Gate B** | B2 | ⏳ |
| 17 | GeoIP và nền bản đồ, CRS PL2 | C1 | ⏳ |
| 18 | API thống kê, lớp bản đồ, xác minh bot tốt | C1 | ⏳ |
| 19 | Drill-down, rule geo/ASN, GitOps (1) | C1 | ⏳ |
| 20 | Dashboard, GitOps (2) | C2 | ⏳ |
| 21 | OpenAPI, danh mục rule, red team | C2 | ⏳ |
| 22 | Phát hành v1 · **Gate C** | C2 | ⏳ |

## 1. Dự án

Strata là WAF mã nguồn mở (Apache-2.0):

- Lõi detection `libstrata` viết bằng Rust, xuất C ABI.
- Cắm vào proxy có sẵn qua connector; hiện tại chỉ làm connector NGINX.
- Agent `strata-agent` (Go) chạy cạnh proxy.
- Control plane (Go) và Web UI (React + TypeScript) để quản trị.

## 2. Tài liệu bắt buộc

| File | Vai trò |
| --- | --- |
| `docs/plan/plan.md` | **Nguồn nhiệm vụ.** Mỗi nhiệm vụ có mã `Wxx-L-yy`, các dòng Thư mục, Làm, Xong khi, Cần trước, Đọc |
| `docs/design/nginx-module.md` | Thiết kế chi tiết: module NGINX, FFI, bundle, agent, control plane, API, UI, GeoIP |
| `docs/design/strata-overview.md` | Thiết kế tổng thể: mô hình policy & rule, danh mục tính năng |

Khi code và tài liệu mâu thuẫn thì tài liệu đúng. Nếu thấy tài liệu sai hoặc thiếu, **dừng lại và báo**, không tự đổi thiết kế.

## 3. Phân công giữa hai công cụ

Mỗi nhiệm vụ chỉ do **một** công cụ làm. Nhận một mã nhiệm vụ không thuộc phần của mình thì từ chối và nói rõ nhiệm vụ đó thuộc công cụ nào.

| Luồng / phạm vi | Thư mục | Công cụ |
| --- | --- | --- |
| N · module NGINX (C) | `connectors/nginx/` | Claude Code |
| R · libstrata, compiler, FFI (Rust) | `engine/` | Claude Code |
| G1 · agent, Fleet service | `agent/`, `control-plane/fleet/`, `proto/` | Claude Code |
| G2 · xác thực, RBAC, audit, service account | `control-plane/auth/`, `control-plane/audit/` | Claude Code |
| G2 · policy, ingest, stats, replay, rules API | `control-plane/` (trừ `fleet/`, `auth/`, `audit/`) | Antigravity |
| F · Web UI | `ui/` | Antigravity |
| S · công cụ rule, importer, corpus, `strata-mutate` | `tools/`, `corpus/`, `rules/schema/` | Antigravity |
| S · nội dung rule | `rules/` (trừ `schema/`) | Antigravity viết, **người luồng S duyệt từng rule** |
| Q · lab, CI, e2e, dashboard | `deploy/`, `tests/e2e/`, cấu hình CI | Antigravity |
| GitOps sync | `gitops-sync/` | Antigravity |

Nhiệm vụ mang mã `ALL` hoặc dòng "Vận hành" là việc của người, agent chỉ hỗ trợ khi được yêu cầu cụ thể.

## 4. Quy trình mỗi nhiệm vụ

1. **Xác nhận mã nhiệm vụ** (ví dụ `W05-F-01`) và tìm đúng mục trong `docs/plan/plan.md`. Không có mã thì hỏi lại, không tự chọn việc.
2. **Kiểm tra tiến độ và "Cần trước"** theo mục 0: nhiệm vụ phải thuộc tuần hiện tại (hoặc tuần trước còn dở); nhiệm vụ phụ thuộc phải `✅ Done` và đã merge vào `main`. Không đạt thì dừng và báo.
3. **Đọc** đúng các mục ghi ở dòng "Đọc".
4. **Lập kế hoạch rồi chờ duyệt**: file sẽ tạo/sửa, hàm/endpoint/component sẽ thêm, test sẽ viết, lệnh kiểm chứng. Chưa được duyệt thì chưa viết code.
5. **Làm**: tạo nhánh `Wxx-L-yy-mo-ta-ngan` từ `main`, chỉ sửa trong thư mục của nhiệm vụ (cộng test và tài liệu liên quan), viết test cùng lúc với code.
6. **Kiểm chứng**: chạy **đủ** các lệnh ở dòng "Xong khi" và các lệnh lint/test của khu vực (mục 8). Chưa pass thì chưa xong.
7. **Cập nhật tiến độ**: trong cùng PR, đổi dòng của nhiệm vụ mình trong mục 0 thành `✅ Done`.
8. **Báo cáo** theo mẫu ở mục 9 rồi mở PR.

Mỗi phiên chỉ làm một mã nhiệm vụ. Không làm trước nhiệm vụ của tuần sau, kể cả khi thấy "tiện tay".

## 5. Phạm vi được sửa

- Chỉ sửa trong thư mục ghi ở nhiệm vụ, cộng file test và tài liệu của thành phần đó.
- **Interface chung** chỉ được đổi khi nhiệm vụ ghi rõ:
  - `engine/ffi/strata.h`
  - `proto/**/*.proto`
  - OpenAPI của control plane
  - định dạng bundle
  - JSON Schema của rule và IR (`rules/schema/`, `docs/spec/`)

  Cần đổi mà nhiệm vụ không ghi thì dừng và đề xuất thay đổi.
- Không sửa `docs/design/` và `docs/plan/` trừ khi được yêu cầu.
- Không thêm dependency mới khi chưa nêu trong kế hoạch ở bước 4.
- Không xóa hoặc tắt test đang có để CI xanh.

## 6. Quy tắc code

**C — `connectors/nginx/`**
- Không parse input trong C; chỉ lấy con trỏ + độ dài từ cấu trúc NGINX rồi chuyển cho libstrata.
- Kiểm tra độ dài trước mọi copy; không `strcpy`, `sprintf`; dùng `ngx_palloc` / `ngx_pcalloc`.
- Không I/O, không khóa, không cấp phát lớn trên đường đi của request.
- Đọc body theo đúng mẫu đồng bộ/bất đồng bộ trong thiết kế (cân bằng `r->main->count`).
- Build với `-Wall -Wextra -Werror`.

**Rust — `engine/`**
- Không `unsafe` ngoài `engine/ffi/`.
- Dữ liệu từ FFI chỉ mượn dạng `&[u8]` trong thời gian gọi; không đổi sang `String`/`Vec<u8>` trừ khi cần giữ.
- Mọi hàm `extern "C"` bọc `catch_unwind`.
- Chỉ dùng regex thời gian tuyến tính (Hyperscan, crate `regex`); parser dạng vòng lặp có giới hạn độ sâu.

**Go — `agent/`, `control-plane/`, `tools/`, `gitops-sync/`**
- `context.Context` cho mọi I/O; không goroutine không có cách dừng.
- Lỗi được bọc (`fmt.Errorf("...: %w", err)`), không nuốt lỗi.
- Mọi endpoint ghi đều kiểm quyền RBAC và ghi audit.
- Cập nhật dùng `etag`; tạo mới hỗ trợ `request_id`.

**TypeScript / React — `ui/`**
- Chỉ gọi API qua client sinh từ OpenAPI; không gọi thẳng database hay URL tự đặt.
- Ẩn nút theo quyền, nhưng không coi đó là kiểm soát bảo mật (API vẫn kiểm).
- Mọi chuỗi hiển thị qua i18n (tiếng Việt, tiếng Anh).
- Vai trò `viewer` không thấy IP đầy đủ và đoạn input.

**Rule — `rules/`**
- Mỗi rule một file YAML, đúng JSON Schema, có `source`, `license`, `author`, `action_mode`.
- Mỗi rule kèm mẫu phải khớp và mẫu không được khớp.
- Rule nhập từ bên ngoài giữ `upstream_id` và `upstream_version`; Rule ID theo đúng dải trong thiết kế.

**Chung**
- Tên ví dụ trong code, test, cấu hình mẫu dùng giá trị trung tính: `example-api`, `api.example.test`.
- Commit tiếng Anh dạng `area: change`, ví dụ `nginx: force body read in enforce`.
- PR tối đa khoảng 400 dòng thay đổi (không tính code sinh tự động); lớn hơn thì tách.

## 7. An toàn khi chạy lệnh

- Chỉ làm việc với **lab**. Không kết nối staging hay production, không dùng thông tin đăng nhập thật.
- Không ghi secret, token, khóa riêng vào code, rule, prompt, log hay file trong repo.
- Không chạy lệnh phá hủy ngoài thư mục làm việc (`rm -rf` ngoài repo, `git push --force` lên `main`, xóa database dùng chung).
- Trình duyệt (Antigravity) chỉ mở URL của lab và trang tài liệu công khai.
- Không tắt hay bỏ qua kiểm tra chữ ký, TLS, xác thực để test cho nhanh.

## 8. Lệnh thường dùng

```bash
# Lab
make lab-up            # dựng lab
make lab-down
make e2e               # test end-to-end

# Rust (engine/)
cargo build --release -p libstrata
cargo test -p libstrata
cargo clippy --all-targets -- -D warnings
cargo fmt --check

# Module NGINX (trong thư mục mã nguồn NGINX tương ứng)
./configure --with-compat --with-threads --with-http_v2_module \
  --add-dynamic-module=$REPO/connectors/nginx
make modules
prove -r $REPO/connectors/nginx/t/

# Go (agent/, control-plane/, tools/, gitops-sync/)
go test ./...
golangci-lint run
buf lint && buf generate    # khi sửa proto/

# UI (ui/)
npm ci
npm run lint
npm test
npm run build
npx playwright test         # test giao diện trên lab

# Rule (rules/, corpus/)
strata-rules lint rules/
strata-rules test rules/ --corpus corpus/
```

## 9. Mẫu báo cáo khi xong nhiệm vụ

```
Nhiệm vụ: Wxx-L-yy · <tên>
Nhánh / PR: <tên nhánh> / <link PR>

Đã làm:
- <thay đổi chính, theo file hoặc thành phần>

Xong khi (từng điều kiện):
- [x] <điều kiện 1> — <lệnh đã chạy> → <kết quả>
- [x] <điều kiện 2> — ...

Lint / test khu vực: <lệnh> → pass

Bằng chứng: <output test; với UI: ảnh chụp hoặc bản ghi trình duyệt trên lab>

Chưa làm / rủi ro / câu hỏi:
- <nếu có>
```

## 10. Khi nào phải dừng và hỏi

- Nhiệm vụ không có trong `docs/plan/plan.md`, thuộc công cụ còn lại, hoặc thuộc tuần sau tuần hiện tại (mục 0).
- Nhiệm vụ "Cần trước" chưa merge.
- Phải đổi interface chung, thêm dependency lớn, hoặc sửa ngoài thư mục được giao.
- Điều kiện "Xong khi" không thể kiểm chứng trên lab.
- Tài liệu thiết kế mâu thuẫn hoặc thiếu thông tin để làm đúng.
- Test có sẵn fail mà không liên quan tới nhiệm vụ.
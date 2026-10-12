# Duyệt rule luồng S · 12/10/2026

Người duyệt: Claude Code, theo yêu cầu của PO (đóng vai người luồng S, AGENTS.md mục 3).
Phạm vi: các pack do `make signatures-import` sinh (W07-S-01):
- `rules/sigma/`: 20 rule từ SigmaHQ `rules/web` 2026-10-06 (8a48134);
- `rules/et-open/`: 7.377 rule ET Open 11308, SID 2000000–2099999;
- `rules/bots/`: 1.453 pattern crawler-user-agents 2026-09-29 (9345a7a).

Cách duyệt:
- Đọc đủ 20 rule Sigma, đối chiếu với rule gốc: field map, điều kiện, điểm, rủi ro FP.
- Với ET, đọc mẫu ngẫu nhiên và mọi ca test fail trong quá trình làm (đều do bộ dịch hoặc bộ sinh mẫu, đã sửa, xem báo cáo W07-S-01).
- Chạy `strata-rules report` cho từng pack trên 2.000 request benign (`--max-fp 0`).
- Chạy `make test-signatures`: mỗi rule biên dịch riêng, chạy qua libstrata.

## Kết luận

- Sigma: **duyệt**, sau 2 chỗ sửa dưới đây. 0/2.000 request benign khớp.
- ET Open: **duyệt** cho cả 4 tệp, 0/2.000 request benign khớp, với hai điều kiện:
  - một rule ET không tự chặn (điểm tối đa 80);
  - policy chọn tệp theo stack của mình (cost unit: `web_specific_apps` một mình là 82.681, vượt ngân sách mặc định).
- crawler-user-agents: **duyệt** là pack nhận diện: điểm 0, label `bot`, không chặn. Bỏ 3 pattern khớp user agent trong corpus benign.

## Đã sửa khi duyệt

| Rule | Vấn đề | Sửa |
| --- | --- | --- |
| Sigma 5513deaf (SQL Injection Strings In URI) | `select .* ` và `=select ` khớp văn bản tự do (`q=SELECT+the+best+plan`): 63/2.000 request benign | Bỏ, lý do trong `tools/strata-import-signatures/exclude.txt` |
| Sigma `cs-uri-query` (mọi rule) | Nhiều rule Sigma dùng `cs-uri-query` cho cả URI: 400209 F5 iControl (`endswith /mgmt/tm/util/bash`) không bao giờ khớp nếu chỉ xét query | Map sang request target thô (path + query), thô và đã decode; các giá trị `=c:/windows`... vẫn khớp trong phần query |
| ET 2053468 (UNION SELECT in body) | Bỏ `distance` khiến `UNION` ... `SELECT` khớp ở bất cứ đâu trong body (`union station tickets. select the best plan`): 4/2.000 | Bỏ, lý do trong `exclude.txt` |

## Duyệt, kèm ghi chú vận hành

| Rule / nhóm | Ghi chú |
| --- | --- |
| Sigma User-Agent (400200–400208, 400216) | User-Agent của công cụ tấn công, malware, miner, PowerShell, rclone; 400208 (UA kết thúc bằng `=`) và 400201 (UA base64) điểm 40, không tự chặn |
| Sigma 400213 (`.git/` trong URI) | Đúng ý nghĩa; site phục vụ thư mục tên `.git` thì tắt rule |
| Sigma 400220 (ReGeorg) | POST không Referer và không User-Agent, kèm `cmd=...`: chặt, đúng như rule gốc |
| ET "loose" (3.115 rule) | Content tìm ở bất cứ đâu trong buffer (bỏ `distance`/`within`): rộng hơn Suricata, nên điểm ≤ 80. Không khớp request benign nào |
| ET `nocase` | Thành transformation `lowercase` và giá trị viết thường; `http.uri` thành `uri_raw` + `url_decode` (giữ `//`, `+` khớp cả dấu cách) |
| crawler-user-agents | Gồm cả bot tốt (Googlebot, Bingbot): điểm 0 nên không ảnh hưởng chặn; dùng cho policy và sự kiện |

## Điều kiện để giữ kết quả duyệt

- `make test-rules`: test của pack đạt 100%, mỗi pack khớp 0 request benign. CI có thêm bước kiểm `make signatures-import` không tạo diff.
- Nâng phiên bản nguồn (`sources.lock`) cần một lượt duyệt mới cho rule mới hoặc đổi. `exclude.txt` chỉ thêm kèm lý do và số request benign khớp.

## Bổ sung: virtual patch 700001–700010 (12/10/2026)

Rule Strata tự viết, không phải nhập. Từng rule được đối chiếu với payload khai thác công khai của CVE: mẫu `match` là payload thật, có biến thể mã hóa và che giấu (Log4Shell `${${lower:j}…}`, URL-encode); mẫu `no_match` là request hợp lệ gần với payload nhất (`$100 jndi`, `class=economy`, `#post render` trong giá trị, Exchange autodiscover thường). Kết quả: 0/2.000 request benign khớp; `make test-rules` 56/56 rule pass. Điểm 100 vì mỗi rule chỉ khớp đúng dấu hiệu khai thác. Duyệt.

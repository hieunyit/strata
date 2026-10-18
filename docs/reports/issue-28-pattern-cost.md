# #28: chi phí từng pattern Hyperscan, và rule 932340

Ngày: 15/10/2026 · Nhánh: `issue-28-pattern-cost` · Người làm: Claude Code. PO giao ngày 15/10/2026: "bỏ A, làm tiếp đo chi phí theo pattern". Compile trên CPU 6–10, đo trên CPU 2.

## 1. Kết luận

- Mỗi lần scan DB đầy đủ (12.751 pattern) tốn khoảng **5 µs**, dù giá trị chỉ dài trung bình 39 byte. Request có nhiều giá trị (body lớn) trả chi phí này cho mỗi giá trị.
- **CRS chiếm khoảng 80%** chi phí đó. ET Open (7.380 pattern) chỉ khoảng 4%; bots không đáng kể.
- Bỏ riêng từng rule CRS khỏi DB thì **132/137 rule nằm trong mức nhiễu** (±10%): chi phí rải trên nhiều rule. Hyperscan gộp các NFA lại với nhau, nên chi phí không cộng tuyến tính theo rule.
- **Ngoại lệ là 932340** ("Direct Unix Command Execution (No Arguments)"):
  - bỏ nó khỏi DB thì mỗi lần scan rẻ đi 33–37%;
  - cùng pattern đó chạy bằng regex crate (lazy DFA) chỉ tốn **107 ns** mỗi giá trị, so với **2.405 ns** khi đứng riêng trong Hyperscan.
- **Thay đổi trong nhánh này**: compiler đưa điều kiện `rx` của 932340 ra khỏi DB Hyperscan. Đây là cơ chế đã có cho pattern Hyperscan từ chối: điều kiện `rx` ngoài DB chạy bằng regex crate.
  - Không đổi định dạng bundle hay ABI; engine cũ vẫn đọc được bundle mới.
  - Đổi lại, rule 932340 không còn được prefilter gate và chạy regex trên mọi request.

## 2. Công cụ: `strata-pattern-cost`

`engine/compiler/src/bin/strata-pattern-cost.rs`. Bốn bước, để phần compile và phần đo chạy trên hai bộ CPU khác nhau:

| Bước | Làm gì |
| --- | --- |
| `prepare` | Pattern đúng như `compile` dựng (`hyperscan_patterns`: lower, gạt pattern bị từ chối), giá trị mẫu lấy từ corpus (path, query, form, lá JSON, header, cookie; tối đa 4.000 giá trị khác nhau), DB đầy đủ block-mode, mỗi pattern một DB |
| `time` | ns mỗi lần scan của DB đầy đủ và của từng pattern đứng riêng; xếp hạng (`rank.json`) |
| `minus` | DB đầy đủ trừ top K, trừ vài rule (`--drop`), trừ cả một nguồn (`--sources`), hoặc trừ từng rule của một nguồn (`--each-rule-of crs`) |
| `time-minus` | ns mỗi lần scan của từng DB trên. Mỗi phép đo kẹp giữa hai lần đo DB đầy đủ và so với trung bình hai lần đó, vì máy dao động nhiều hơn chênh lệch cần đo |
| `regex` | ns mỗi giá trị khi chạy pattern của một rule bằng regex crate, so với Hyperscan |

Bài học về đo: lượt đầu không kẹp (đo theo thứ tự) cho thấy "bỏ bất kỳ rule CRS nào cũng −28%" và vài rule "+97%". Đó là do máy trôi: CPU 2 dùng chung L3 với các tải khác. Sau khi kẹp, 132/137 rule về mức nhiễu.

## 3. Số đo

Trên 4.000 giá trị của corpus benign, trung bình 39 byte:

| DB | ns mỗi lần scan | |
| --- | ---: | ---: |
| Đầy đủ | 4.859 | |
| Bỏ 932340 | 3.266 | −33% |
| Bỏ top 10 (đứng riêng) | 2.877 | −41% |
| Bỏ 932340, 932250, 932260, 932370, 932380 | 2.836 | −42% |
| Bỏ top 1.000 | 946 | −80% |
| Bỏ ET Open | 4.652 | −4% |
| Bỏ CRS | 918 | −81% |
| Bỏ bots | 4.989 | +3% (nhiễu) |

Lượt bỏ từng rule CRS, có kẹp: 932340 −37%; mọi rule khác trong khoảng ±10%, trừ 4 rule (−8 đến −21%) mà chính DB đầy đủ lúc đó dao động 3,9–7,8 µs.

**Engine** (`strata-bench`, 1 nhân, gói đầy đủ, xen kẽ; verdict giống hệt ở mọi request):

| Request | main | 932340 ngoài Hyperscan | |
| --- | ---: | ---: | ---: |
| GET nhỏ (7 lượt, trung vị) | 606 µs | 527 µs | −13% |
| JSON nhỏ (7 lượt) | 646 µs | 589 µs | −9% |
| Attack (7 lượt) | 710 µs | 611 µs | −14% |
| JSON 64 KB (3 lượt) | 37,5 ms | 30,2 ms | −20% |
| Form 64 KB, 1.024 tham số (3 lượt) | 51,1 ms | 40,3 ms | −21% |
| Form 1 MB (3 lượt) | 200 ms | 165 ms | −18% |

Lượt 3 vòng đầu cho JSON nhỏ +102%. Đo lại 7 vòng thì là −9%: lượt kia là nhiễu (main cũng lên 957 µs trong cùng vòng).

Bundle: 20,99 MB → 20,93 MB. Cost unit +648 (regex ngoài Hyperscan có trọng số 25), xa ngân sách.

## 4. Còn lại cho #28

- Body 64 KB vẫn 30–40 ms trên một nhân với gói đầy đủ, vượt budget 10 ms. Phần lớn chi phí scan còn lại là CRS rải đều. Không có rule nào khác đáng đưa ra như 932340.
- Hướng tiếp theo cần PO quyết:
  - giới hạn `max_args` cho route API (#87, đã có);
  - gói CRS theo route: route API JSON không cần các nhóm PHP/Java/Windows;
  - chuyển thêm regex CRS sang regex crate theo số đo, nhưng mỗi rule chỉ lợi vài phần trăm và rule mất gate.
- W13-R-02 (chi phí từng rule lúc chạy): rule chạy bằng regex crate đo được theo rule; phần Hyperscan là chi phí chung, không chia được theo rule lúc chạy. Công cụ này cho phần đó, đo offline theo gói.

## 5. Đã thử thêm (16/10/2026): Hyperscan prefilter mode

Ý tưởng: compile pattern CRS với `HS_FLAG_PREFILTER` để Hyperscan dùng một automaton xấp xỉ, chỉ báo thừa, rẻ hơn; engine sẽ xác nhận lại bằng regex crate. Đo trước khi sửa engine (`strata-pattern-cost minus --prefilter-sources crs`, kẹp giữa hai lần đo DB đầy đủ, 2 lượt):

| DB | ns mỗi lần scan |
| --- | ---: |
| CRS ở prefilter mode | +1,6% / −1,3%: nhiễu |
| Bỏ 932340 (đối chứng) | −37% / −41% |

**Không có lợi**, nên không sửa engine. Cùng với §3 (mỗi rule CRS còn lại nằm trong nhiễu) và với #87 (DB tham số, không đề xuất), kết luận là lớp Hyperscan không còn chỗ tối ưu đáng kể. #28 với body 8–128 KB và gói đầy đủ cần một quyết định về hành vi, không phải tối ưu thêm (`docs/reports/issue-28-next.md`).

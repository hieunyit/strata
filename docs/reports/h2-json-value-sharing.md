H2 / RV-R-01 · Dùng chung biến đổi cho giá trị JSON lặp · 18/10/2026 (UTC+7)
Nhánh `codex/h2-json-value-sharing`, base `codex/h6-corrupted-artifact-chain` (`17c9711`).

Trước sửa, hai giá trị bằng nhau nhưng ở địa chỉ khác được cache kết quả Hyperscan theo bytes, nhưng vẫn chạy lại cây biến đổi. Body JSON dạng danh sách có nhiều description lặp trả chi phí này nhiều lần. `scan_values` nay gộp index theo **bytes bằng nhau hoàn toàn** khi có body JSON, hợp nhất nhu cầu các chuỗi biến đổi của chúng; vẫn giữ mọi địa chỉ → index cho lookup và mọi tên/target/exclude khi đánh giá điều kiện. Không gộp theo hash đơn thuần, không lowercase khóa. Map mượn bytes trong lần eval, dùng RandomState có seed sẵn từ engine, bỏ map trước khi tạo slot/biến đổi; không copy thêm body hoặc lấy OS randomness trên request path. Các định dạng khác giữ index theo địa chỉ. Không đổi rule, budget 10 ms, fail mode, oversize, max_args, ABI/schema hay dependency.

Thử nghiệm gộp mọi định dạng bị loại vì thêm việc trên form unique: prefilter Ir +2,31%, latency dao động/chậm hơn trong hai cặp đo. Bản cuối chỉ JSON: Ir form +0,261%, header +0,187%; không biến hai số này thành cam kết latency bằng nhau. Lợi ích phụ thuộc độ lặp; unique JSON và traffic thật chưa được benchmark riêng.

Kiểm chứng bản cuối:
- `cargo test --offline -p libstrata -p libstrata-ffi --all-features` → **270 PASS, 3 stress test có sẵn ignored**; `cargo test --offline --release -p strata-compiler --test repeated_values --test prefilter --test base64_args --test eval` → **44 PASS**. Test mới qua engine tham chiếu không prefilter và engine hiện tại, kiểm target/exclude, raw vs decoded/lowercase/multi_match, empty/NUL/độ dài khác, 80 field lặp và event giữ `ARGS_POST:json.include`. Lỗi lúc dựng fixture (score thấp chưa tạo event; header NUL bị protocol chặn trước body) được sửa trong test mới, log giữ riêng; không sửa/tắt test cũ và không gọi đó là regression đỏ của engine.
- `cargo clippy --offline -p libstrata -p libstrata-ffi -p strata-compiler --all-targets --all-features -- -D warnings`, `cargo fmt --all --check` → **PASS**.
- `cargo test --offline --release -p strata-compiler --test prefilter_differential -- --ignored --nocapture` → **11.590 request qua ba engine (reference/fast/block), 7.997 có rule khớp, 0 khác action/score/tập rule; PASS 374,54 s**. Lượt thử gộp mọi định dạng trước đó cũng 0 khác, giữ riêng, không thay bản cuối.
- Fresh `make nginx-asan NGINX_VERSION=V` **trước** `make test-nginx-asan NGINX_VERSION=V ASAN_LOGS=/src/build/NEW` → **595 test PASS mỗi bản**: 1.30.5 **159 s**, 1.31.6 **158 s**, không sanitizer report. 1.31.6 build sau khi source cuối được ghim; 1.30.5 chạy lại sau giới hạn JSON. H3 skipped vì không cấu hình binary riêng; LSan tắt, không gọi đây là kiểm H3/leak/fuzz dài/soak.

Dùng cùng candidate bundle 9.067 rule (v1 SHA `b9e6fafc4c5b7f4f401f6bac335a42d7cc565dbf48a544337b98dbb3e3fa1d0a`), test key và hai executable copy/hash riêng. Candidate vẫn có rule cần S review, không coi là pack đã phát hành. Callgrind chỉ collect trong `libstrata::eval::candidates`, không phải toàn engine: JSON64k 10 warm + 10 mẫu, **2.784.661.477 → 2.343.788.645 Ir (−15,832%)**; form/header 1 warm + 1 mẫu cho so sánh độ nhạy. Warning brk/mmap của Valgrind giữ trong log, command hoàn tất và có totals; không lấy latency dưới Valgrind làm số hiệu năng native.

Sau khi các job test/build của phiên đã kết thúc, chạy riêng từng workload thứ tự A/B/B/A, CPU6, cùng artifact, budget unlimited. Bảng là mean của hai trial mỗi phiên bản, **µs**; JSON/form mỗi trial 100 mẫu, small/header 1.000. Máy vẫn dùng chung, không phải proxy TPS hay SLO:

| Workload | Trước | Sau | Thay đổi |
|---|---:|---:|---:|
| small | 822,74 | 731,79 | −11,05% |
| headers | 1.066,85 | 877,62 | −17,74% |
| JSON 64 KiB | 30.482,93 | 28.728,47 | −5,76% |
| form 64 KiB | 39.222,08 | 41.095,22 | +4,78% |

Ngay đường form/header không dùng map cũng có chênh latency lớn hơn nhiều chênh Ir. Chưa có bằng chứng tách nguyên nhân scheduler/cache/host; không gán mọi chênh này cho code và không tuyên bố mọi workload nhanh hơn. Giữ raw cả lượt chạy cùng các job nặng (JSON mean −11,41%, header +29,75%) để thể hiện độ trôi, không chỉ chọn lượt đẹp.

Bốn lượt toàn bộ 14 workload unlimited giữ nguyên action/tập rule và số FULL/PARTIAL/error; quiet 16 trial cũng giữ nguyên. Form unlimited vẫn PARTIAL do max_args như baseline. **Ở 10 ms, cả chín ca body lớn vẫn PARTIAL** (30 mẫu/ca, 1 MiB 20), không block được payload đầu/cuối trong các ca đó. Chưa đạt #28, không đóng H2 hoặc suy ra #49/SLO proxy. Build/đo dùng `deploy/dev/run.sh`, private target/cache; binary trước/sau `strata-bench --bundle ... --pubkey ... --only WORKLOAD --iterations N --budget-us 0`; Callgrind `--collect-atstart=no --toggle-collect=libstrata::eval::candidates`. Có toolchain/image/source/bundle/binary hashes và [output thật](evidence/h2-json-value-sharing/), raw gzip lossless, validation assertions và từng trial.

Tự review: điều kiện có output; đường lỗi/budget giữ nguyên, equality đầy đủ kể cả NUL; map/buffer bị chặn bởi tập giá trị input có sẵn và chỉ sống trong eval; không unsafe/dependency/PII logging mới; chỉ engine/test/report, không interface/plan/tuần; clippy/fmt sạch. Bản sửa có lợi cho JSON lặp theo phép đo này; form/unique JSON/traffic thật, CPU budget lớn, soak và Gate A vẫn cần xử lý riêng. Chưa merge/deploy, không chờ hosted CI.

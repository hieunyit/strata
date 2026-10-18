H6 · Artifact hỏng qua MinIO/Fleet/agent/NGINX/ClickHouse · 18/10/2026 (UTC+7)
Nhánh `codex/h6-corrupted-artifact-chain`, base `codex/review-decision-details` (`db09c89`).

Test mới dùng helper control plane thật chạy trong process test (`-race`), PostgreSQL/MinIO/ClickHouse/CA/ports riêng, agent executable build `-race`, NGINX hai worker ASan/UBSan. Hai rule synthetic SQLi/XSS, không phải full pack. Mỗi version 1/2/3 đi qua API tạo/sửa bằng etag, replay Rust thật với corpus 4.300 mẫu, submit, duyệt người khác kèm expected_replay_id rồi deploy qua replay gate. Không đổi code production, dependency, interface, trust/TLS/signature check hay chính sách budget/fail mode.

Sau bundle1 enforce tốt, callback Publish của **fixture** làm hỏng một byte payload của object bundle2 shadow đã được deployer verify/upload/record, trước Fleet notify. Object trong MinIO có hash khác, cùng size 24.663 byte; SHA đã record/announce ở PostgreSQL giữ nguyên. Agent tải qua mTLS/FetchBundle thật, báo FAILED `sha256 does not match the announced one`, Fleet dừng rollout2. Không tạo bundle2 trên node, xóa partial; control file và bundle1 giữ nguyên SHA, chữ ký bundle1 còn hợp lệ. SQLi tiếp tục 403/block/700011: nếu shadow2 được kích hoạt sai, assertion này thất bại.

Sửa lại **object thuộc test** về bytes/SHA gốc để replay sau xác minh được baseline2. Không gọi resume: rollout2 vẫn FAILED và node vẫn bundle1 trong giai đoạn kiểm kế tiếp. Sau đó tạo policy3 enforce mới, replay/duyệt/deploy riêng, rollout3 DONE, chữ ký bundle3 hợp lệ. Lần ACTIVE phục hồi không dùng fallback thiếu worker metrics; agent nhận metrics thật của worker.

Bốn giai đoạn trước lỗi/sau từ chối/sau sửa object/sau deploy mới: mỗi giai đoạn 20 SQLi + 1 benign. Cả **80/80 native Block ID trên mỗi NGINX** được tra riêng trong CH, kiểm node/bundle/action/rule, không chỉ count tổng; 60 event mang bundle1, 20 mang bundle3. ACK cuối bằng last_seq, spool unacked=0; invalid/truncated/dropped event=0. Benign 200/allow tới origin. Không có event sản xuất hay event giả lập.

| Kiểm chứng cuối | NGINX 1.30.5 | NGINX 1.31.6 |
|---|---:|---:|
| Native IDs kiểm riêng trong CH | 80/80 | 80/80 |
| Rollout lỗi / phục hồi | FAILED / DONE | FAILED / DONE |
| ACK / last_seq | 4 / 4 | 4 / 4 |
| Go -race test / package | 38,54 / 39,856 s | 38,98 / 40,326 s |
| ASan/UBSan report (sau cleanup) | 0 | 0 |

Lệnh: trước **mỗi** lần native chạy `make nginx-asan NGINX_VERSION=<V>` trong dev/private target, rồi `STRATA_TEST_COMPILER=/src/target/release/strata-compile STRATA_TEST_REPLAY_BIN=/src/target/release/strata-replay STRATA_TEST_NGINX=/src/build/nginx-<V>-asan/objs/nginx STRATA_TEST_NGINX_MODULE=/src/build/nginx-<V>-asan/objs/ngx_http_strata_module.so STRATA_CORRUPT_EVIDENCE_DIR=/src/build/NEW go -C tests/e2e test -race -count=1 -timeout6m -v -run '^TestCorruptedArtifactKeepsNativeLastKnownGood$' .` Dev network host + Docker socket/CLI group988, private Go cache/Rust target như fixture H6 trước. `golangci-lint run ./...` tại tests/e2e → **0 issues**. Lượt đầu lint phát hiện assignment thừa trong test mới, đã sửa và chạy lại sạch; giữ output lỗi. Lượt native sơ bộ trước bổ sung metric cũng 80/80 PASS, không thay acceptance cuối.

[Bằng chứng](evidence/h6-corrupted-artifact-chain/) giữ source/binary hashes, JSON đầy đủ 80 IDs mỗi node, metric/checkpoint, rollout states/reason, status agent chọn lọc và native/build/test log. Raw nén gzip lossless, summary hai dòng. Không lưu token/password/private key. Test fixture sửa đúng object riêng sau upload, không mô phỏng checksum bằng mock. Trường hợp SHA khớp nhưng chữ ký không hợp lệ vẫn có test riêng #178/#206, không suy từ lỗi SHA này; không sửa hash để bỏ qua kiểm chứng.

Tự review: điều kiện có lệnh/output và từng native ID; lỗi API/storage/metrics/read được xử lý, timeout/batch/read bounded; fixture riêng, RBAC/4 mắt/replay gate/TLS không tắt; chỉ tests/e2e và báo cáo, không sửa tuần; lint sạch. LSan tắt theo runbook nên không claim kiểm leak. Đây là acceptance lab một node/serial/CP services trong process test, không phải CP-process crash (đã có #205/#216), tải đồng thời/đa node/soak hoặc diễn tập vận hành đầy đủ. Không merge/deploy hay chờ hosted CI.

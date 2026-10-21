# Compact · Merge về main

PO yêu cầu: “gộp hết về main cho tôi”, phạm vi 75 PR C và cẩm nang #321–#395.
Kết luận review tích hợp: **APPROVE theo cổng kiểm cục bộ Compact §8a**.
Toàn bộ 75 PR đã merged; không đóng PR để thay thế trạng thái merge.

- Main trước tích hợp: `ccf04bf7eaefb26ca969cd12ac33d917448e13bf`.
- Main sau tích hợp 75 PR: `84160a3ee6ec296ff10d57082512c9820cb99b16`.
- Cây Git kiểm thử/tích hợp: `3e3c0d611b0487df7bbe2b92438a4f30cfc6c960`.
- Tip được kiểm trước merge: `983a1bf24e18f3205fa999753b062ada390c3235`.
- Runtime source bằng bản C05 đã nghiệm thu: `e2ddd4067012ddfcd7444c61270ca3487988afa8`;
  khác biệt từ mốc đó đến tip chỉ là Markdown.

## Phạm vi

| Nhóm | PR | Kết quả |
| --- | --- | --- |
| C03 · Privacy, MFA, sessions, audit copies | #321–#335 | Merged |
| C01 · Investigation/evidence | #336–#351 | Merged |
| C02 · Rules/exceptions | #352–#365 | Merged |
| C04 · Incidents/reports | #366–#375 | Merged |
| C05 · Documentation discovery preview | #376–#388 | Merged; collection off |
| Cẩm nang cài đặt/cấu hình/triển khai | #389–#395 | Merged |

Đã kiểm 75 head SHA, ancestor/base liên tục, trạng thái review và conflict. Gộp từ
#395 về #321 vào các base của chuỗi, giữ merge commit và kiểm SHA cây Git sau **mỗi**
bước. Cây ở cả 75 bước giống tip đã kiểm; #321 cuối cùng đưa toàn bộ vào main trong
một cập nhật. Kiểm lại API `merged=true`, `merged_at` và ancestor trên main cho đủ 75 PR.
Không force-push, không xóa nhánh người dùng hoặc sửa workflow/branch protection.

## Kiểm chứng và giới hạn CI

Cổng kiểm cục bộ đã có bằng chứng trên chính runtime tree này:

- Control plane `go test -p 1 -race ./...`: exit 0, PG/CH thật; Go lint **0 issues**.
- UI **283 tests** và **4 tests** bị ảnh hưởng cuối; lint/build exit 0.
- Browser **28 tests** và lượt discovery cuối **1/1**; e2e chọn lọc **56.894s**, exit 0.
- Kiểm tài liệu: **9 YAML**, **33 Bash blocks**, **46 local links**, **63 entries**
  tương thích schema main A/B cũ; Compose Compact/Keycloak hợp lệ.

Chạy lại trong lượt merge, CPU 6–10:

```text
TestLosslessRestartUnderLoad PASS (18.76s)
ClickHouse received 2000 / 2000 events
zero loss and zero duplicates
ok github.com/strata/strata/tests/e2e 19.943s
Pinned signature fetch safety: Ran 5 tests; OK
```

GitHub Actions thực tế vẫn tự chạy trong repo, dù kế hoạch quy định dùng cổng kiểm
cục bộ thay CI GitHub. Trên tip `983a1bf` trước gộp, Go/UI/Rust/NGINX/sanitizer/CodeQL
pass, nhưng hai job CI đỏ, cũng tái hiện trên main trước tích hợp:

1. `e2e`: runner không start được image `clickhouse/clickhouse-server:25.8.33`, lỗi
   Docker `page not found` / `Unable to find image ... locally`. Regression tương ứng
   vừa chạy lại bằng fixture riêng, đủ 2.000 event, không mất/trùng.
2. `Rules`: ET Open URL mutable không còn bytes đúng hash trong `sources.lock`;
   fetch từ chối đúng thiết kế. Không thay hash/nguồn rule, không bỏ xác minh. Muốn
   importer CI chạy lại cần bản archive ghim từ mirror bất biến hoặc một lượt review
   cập nhật nguồn riêng.

Log đối chiếu: [e2e trên main cũ](https://github.com/hieunyit/strata/actions/runs/39563628948/job/119100536657),
[Rules trên main cũ](https://github.com/hieunyit/strata/actions/runs/39563628948/job/119100536693),
[e2e PR #321](https://github.com/hieunyit/strata/actions/runs/39560570855/job/119090554265),
[Rules PR #321](https://github.com/hieunyit/strata/actions/runs/39560570855/job/119090554086).
Các head PR trung gian còn có kết quả CI lịch sử của các lát code chưa tích hợp đủ;
không nhận chúng là xanh. Quyết định dựa trên toàn bộ tree tích hợp đã kiểm cục bộ,
không dựa vào việc chỉ nhìn trạng thái merged hoặc bỏ qua checksum.

Receipt/API audit và output lệnh lưu cục bộ ở `build/merge-all/` (gitignore).
Không chạy benchmark, không tác động shared lab/staging/production. Fixture ClickHouse
riêng của regression được dọn bởi test. Merge source không tự bật telemetry, không
cài collector, không thêm runtime OpenAPI enforcement; B03 vẫn chưa làm.

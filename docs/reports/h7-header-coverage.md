Nhiệm vụ: H7 / #108 · coverage custom header, phần tiếp

Bổ sung rule 300012: libinjection XSS, lời gọi JavaScript gián tiếp và javascript:setInterval/setTimeout/eval/Function trong header; normalize URL/HTML/JS/CSS và base64, multi_match giữ cả raw và từng bước. Rule 300013 nhận boolean SQL predicate AND/OR + JSON function + so sánh số, regex giới hạn phần đối số 256 ký tự. Tách rule vì schema match không cho nested all/any. Không sửa rule CRS sinh tự động hay chính sách budget/body. Các rule mới cần duyệt nội dung trước release.

Kiểm chứng:
```
strata-rules lint: 13 files, 0 problems
strata-rules test: 13 rules: 13 pass, 0 fail, 0 skipped
300012: 14 requests; 300013: 6 requests
full pack: 9067 rules evaluated, 0 skipped
3000 benign: 0 matched, 0 blocked
Gate corpus: CMDi 94.6%, LFI 97.4%, SQLi 76.8%, XSS 75.8% blocked
```

Chạy cùng script pinned GoTestWAF/NGINX của PR #133, 111 test Header: SQLi **8/8** bị chặn (baseline 1/8), XSS **54/56** (baseline 13/56), benign **47/47** đi qua, 0 unresolved/failed. Paired HTTP/SQLite: 5 attack bị signature chặn, 5 benign đi qua, hai SQLi đã tái hiện trước sửa không còn trả marker. Không coi HTTP 200 của XSS fixture là bằng chứng browser exploit.

Hai bypass XSS còn lại là một payload ở URL/Base64Flat: `\\"autof<x>ocus o<x>nfocus=alert<x>(1)//`. Chưa có oracle trình duyệt/chuỗi sanitizer chứng minh exploit trên ứng dụng thực. Không thêm chữ ký riêng chỉ để nâng điểm; giữ #108 mở cho giới hạn này và coverage header ứng dụng thực. Đây là cải thiện có bằng chứng cho fixture Header, không phải đảm bảo chặn mọi XSS/SQLi.

Đo chi phí với cùng binary 25a6e9e (workload headers mới: JWT/ETag/filter/prose/trace), budget 10ms, sampling mặc định, 1000 mẫu mỗi lượt A/B/B/A. Mean µs: 915.16/1288.20/1173.00/1114.62; candidate trung bình 1230.60 so baseline 1014.89, tăng khoảng **21.3%**. Cả 4000/4000 FULL, 0 errors/budget_errors/block. Host còn dịch vụ khác và độ trôi lớn, nên không suy ra tỷ lệ chính xác cho production. Chi phí tăng là rủi ro cần profile/tune trước rollout; không tuyên bố đạt SLO hiệu năng.

[Dữ liệu](h7-header-coverage/) giữ hash artifact, từng paired request, summary/bypass GoTestWAF, corpus và raw performance. Lệnh `tests/security/run-header-gotestwaf.sh BUNDLE build/OUT`; report đầy đủ ở build/h7-v4-final/headers.json. Không chờ hosted CI, không merge hay triển khai staging/production.

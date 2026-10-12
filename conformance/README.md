# conformance

Tests bắt buộc để các connector và các stack cho kết quả nhất quán.

## differential/ (W08-R-01)

So khung (framing) một request thô giữa hai profile và gắn cờ phân kỳ — nơi
sinh ra request smuggling khi WAF và origin hiểu khác nhau:

- `go-net-http`: parser thật của Go `net/http` (`http.ReadRequest`).
- `spring`: mô hình framing nghiêm ngặt theo RFC 7230 của một Servlet
  container (Tomcat/Coyote mà Spring Boot nhúng): từ chối khi có đồng thời
  `Content-Length` và `Transfer-Encoding`, hoặc `Content-Length` lặp mâu thuẫn.

```bash
cd conformance/differential
GOTOOLCHAIN=auto go test ./...      # benign đồng thuận, diverge-* bị gắn cờ
GOTOOLCHAIN=auto go run main.go corpus/   # JSON mỗi input + số ca phân kỳ
```

Mỗi ca `diverge-*` là ứng viên cho corpus conformance (W08-Q-01) và tương ứng
rule protocol mơ hồ của Strata (100126/100128/100139, `action_mode: block_alone`,
xem `rules/reviews/2026-10-12-action-mode.md`).

# conformance

Tests bắt buộc để các connector và các stack cho kết quả nhất quán.

## corpus/v1.jsonl (W08-Q-01)

Corpus conformance v1: mỗi dòng là một request kèm kỳ vọng `expect`
(`action` allow/block và tập `rules` khớp), tùy chọn `nginx.status` khi chính
NGINX từ chối request trước module (smuggling), `framed: true` khi gửi đúng
nguyên văn header/body. Hai runner dùng cùng corpus, cùng bundle test
(`connectors/nginx/t/fixtures`, biên dịch từ `engine/compiler/examples/rules.yaml`)
và policy `example-api`:

- `engine/compiler/tests/conformance.rs`: gọi engine như connector gọi (path đã
  chuẩn hóa như NGINX, client 127.0.0.1).
- `connectors/nginx/t/080-conformance.t`: gửi request thô qua NGINX; block → 403,
  allow → 200, `$strata_rules` phải đúng tập rule.

Placeholder `@ARGS<n>@` trong `uri` sinh `n` tham số `a<k>=1`.

```bash
make test-conformance    # corpus v1 qua engine và NGINX + differential go-net-http/spring
```

CI chạy `make test-conformance` mỗi PR chạm `engine/**`, `connectors/**` hoặc
`conformance/**` (`.github/workflows/ci.yml`, job `conformance`).

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

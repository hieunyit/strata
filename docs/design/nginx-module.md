# Strata — Thiết kế chi tiết module NGINX

Oct 10, 2026 · @hieuny

## Tóm tắt & phạm vi

`ngx_http_strata_module` là dynamic module của NGINX, nối vòng đời request vào lõi `libstrata` (Rust). Module là lớp C mỏng: không parse input, không giữ cấu hình bảo mật riêng, chỉ chuyển dữ liệu và thực thi quyết định. Đây là connector đầu tiên và là mẫu chuẩn cho Apache, HAProxy, Envoy, Kong.

**Mục tiêu đo được**

1. Overhead latency p99 dưới 1 ms với request dưới 64 KB khi bật đủ lớp phase 0–1.
2. Throughput giảm không quá 10% so với NGINX không bật module (request nhỏ, keep-alive).
3. Cập nhật bundle không cần `nginx -s reload`, không rớt request đang xử lý.
4. Không crash worker sau 72 giờ fuzz với ASan; panic trong Rust không kéo sập worker.
5. Quyết định giống hệt các connector khác trên bộ conformance.

**Trong phạm vi**

- HTTP/1.1, HTTP/2, HTTP/3 (khi NGINX build có QUIC); request header, request body, response header, response body.
- Chế độ shadow / enforce, fail-open / fail-closed theo location.
- Trang chặn HTML/JSON, Block ID, biến NGINX, gửi sự kiện cho `strata-agent`.
- Hot reload bundle có chữ ký.

**Ngoài phạm vi (giai đoạn này)**

- Inspect nội dung frame WebSocket sau khi upgrade (chỉ inspect handshake).
- Module `stream` (TCP/UDP).
- Tự kết nối control plane từ trong worker: việc này giao cho `strata-agent`.

**Phiên bản hỗ trợ**

| Nền tảng | Phiên bản | Ghi chú |
| --- | --- | --- |
| NGINX Open Source | Nhánh stable và mainline hiện hành | Build riêng cho từng bản vì dynamic module phải khớp phiên bản |
| NGINX Plus | Các release còn được F5 hỗ trợ | Build với `--with-compat` theo bản OSS tương ứng |
| OpenResty | Bản hiện hành | Kiểm tra cùng `lua-nginx-module` |
| Angie | Bản hiện hành | Ưu tiên thấp |

Danh sách phiên bản cụ thể chốt khi lập CI (xem mục Build & đóng gói).

## Kiến trúc module

Module gồm ba thành phần tách biệt: lớp C trong worker, `libstrata` link tĩnh vào cùng file `.so`, và tiến trình `strata-agent` chạy cạnh NGINX. Worker không bao giờ tự kết nối mạng.

&#91;embedded content: kiến trúc module NGINX · worker, agent, control plane\]

Agent nhận bundle đã ký từ control plane rồi ghi vào đĩa; worker đọc bundle theo chu kỳ, gửi sự kiện qua Unix socket và ghi bộ đếm vào shared memory để agent đọc.

| Thành phần | Trách nhiệm | Không làm |
| --- | --- | --- |
| `ngx_http_strata_module` (C) | Đăng ký directive, biến, phase handler, filter; quản lý context request; gửi response chặn; timer kiểm tra bundle | Parse input, quyết định bảo mật, kết nối mạng |
| `libstrata` (Rust) | Nạp và kiểm chữ ký bundle, parse, detect, chấm điểm, sinh Block ID, tạo sự kiện | Gọi ngược vào NGINX, I/O |
| `strata-agent` (Go) | mTLS với control plane, ghi bundle nguyên tử, gom sự kiện, xuất metrics Prometheus, báo trạng thái node | Nằm trên đường đi của request |

Nhờ tách agent, agent chết hoặc mất mạng không ảnh hưởng request: worker tiếp tục với bundle hiện có. Cấu trúc mã nguồn:

```
connectors/nginx/
├── config                  # khai báo module cho ./configure
├── src/
│   ├── ngx_http_strata_module.c   # directive, init, merge cấu hình
│   ├── ngx_http_strata_phase.c    # PREACCESS handler, đọc body
│   ├── ngx_http_strata_filter.c   # request body, header, body filter
│   ├── ngx_http_strata_block.c    # response chặn HTML/JSON
│   ├── ngx_http_strata_bundle.c   # timer, thread task, đổi engine
│   ├── ngx_http_strata_event.c    # event socket, metrics shm
│   └── ngx_http_strata_vars.c     # biến $strata_*
├── include/strata.h        # sinh từ libstrata bằng cbindgen
└── t/                      # test Test::Nginx
```

## Vòng đời request

Module đăng ký một handler ở PREACCESS, ba filter (request body, header, body) và một handler ở LOG; verdict phải có trước khi request đi lên upstream.

&#91;embedded content: vòng đời request · 6 điểm hook\]

Tại sao chọn PREACCESS mà không phải ACCESS: với `satisfy any`, NGINX bỏ qua các handler ACCESS còn lại khi một handler đã cho phép, nên WAF ở ACCESS có thể bị bỏ qua. PREACCESS chạy sau REWRITE (đã biết location cuối cùng) và trước mọi kiểm tra quyền truy cập.

| Điểm hook | Việc module làm | Kết quả trả cho NGINX |
| --- | --- | --- |
| PREACCESS handler | Tạo context và transaction, đăng ký pool cleanup, gửi request line + toàn bộ header. Nếu verdict cần body: gọi `ngx_http_read_client_request_body` | `NGX_DECLINED` (đi tiếp), `NGX_DONE` (chờ body), hoặc gửi response chặn |
| Request body filter | Đưa từng chunk vào libstrata; khi có `block` giữa chừng thì ngừng đọc body | Chuyển buffer sang filter kế tiếp |
| Post handler sau khi đọc body | Lấy verdict cuối cùng | Chạy tiếp phase hoặc gửi response chặn |
| Header filter | Gửi status + header response; quyết định có cần buffer response không | Gọi header filter kế tiếp |
| Body filter | Inspect hoặc thay buffer đã che; dừng inspect khi vượt giới hạn | Gọi body filter kế tiếp |
| LOG handler + pool cleanup | Hoàn tất sự kiện, ghi metrics; cleanup gọi `strata_tx_free` kể cả khi client ngắt | — |

**Mẫu đọc body: xử lý cả trường hợp đồng bộ và bất đồng bộ**

`ngx_http_read_client_request_body` tăng `r->main->count` khi bắt đầu, và gọi post-handler **ngay trong lời gọi** nếu body đã nằm hết trong preread buffer (trả `NGX_OK`), hoặc **sau này** khi đọc xong (trả `NGX_AGAIN`). Code phải xử lý cả hai, và phần count đã tăng phải được trả lại đúng một lần; thiếu là request treo. Khi đọc bất đồng bộ, NGINX có thể tự kết thúc request mà **không gọi post-handler** (ví dụ body chunked vượt `client_max_body_size` → 413, timeout đọc body), nên phần count phải được trả ngay khi nhận `NGX_AGAIN` bằng `ngx_http_finalize_request(r, NGX_DONE)`, giống module `mirror` của NGINX; post-handler chỉ trả count ở nhánh đồng bộ:

```c
/* PREACCESS handler */
if (ctx->body_state == BODY_DONE)    return strata_apply_verdict(r, ctx);
if (ctx->body_state == BODY_WAITING) return NGX_DONE;

rc = ngx_http_read_client_request_body(r, strata_body_read);
if (rc == NGX_ERROR || rc >= NGX_HTTP_SPECIAL_RESPONSE) return rc;

if (rc == NGX_AGAIN) {            /* body chưa đủ: chờ bất đồng bộ */
    ctx->body_state = BODY_WAITING;
    ngx_http_finalize_request(r, NGX_DONE);   /* trả count ngay */
    return NGX_DONE;
}
/* rc == NGX_OK: post-handler đã chạy đồng bộ ngay trong lời gọi trên */
return strata_apply_verdict(r, ctx);

/* post-handler */
static void strata_body_read(ngx_http_request_t *r)
{
    ngx_http_strata_ctx_t *ctx = strata_get_ctx(r);
    ngx_int_t waiting = (ctx->body_state == BODY_WAITING);

    if (!waiting) {
        r->main->count--;           /* đồng bộ: trả phần read_client_request_body đã tăng */
    }
    strata_finish_body(ctx);        /* gửi chunk cuối, lấy verdict */
    ctx->body_state = BODY_DONE;

    if (waiting) {                  /* bất đồng bộ: count đã trả lúc NGX_AGAIN */
        r->write_event_handler = ngx_http_core_run_phases;
        ngx_http_core_run_phases(r);   /* quay lại PREACCESS, đi nhánh BODY_DONE */
    }
}
```

Response chặn gửi từ PREACCESS (ngoài CONTENT phase) phải tự gọi `ngx_http_finalize_request(r, rc)` rồi trả `NGX_DONE`; trả `NGX_OK` sẽ làm phase engine chạy tiếp sang proxy.

Test bắt buộc cho phần này: body nằm hết trong preread buffer; `Content-Length: 0`; HTTP/2 có `END_STREAM` ngay trên frame HEADERS; body gửi từng byte một; client đóng kết nối khi đang chờ body; body vượt `client_max_body_size` (NGINX trả 413; với `Content-Length` lỗi xảy ra trước PREACCESS, với body chunked lỗi xảy ra trong lúc module đang đọc body và request phải được giải phóng); internal redirect sau khi đã đọc body.

**Stream bị hủy giữa chừng (RST\_STREAM ở HTTP/2, HTTP/3)**

- Pool cleanup luôn được gọi đúng một lần khi request bị giải phóng, kể cả khi stream bị reset; `strata_tx_free` gọi trong cleanup và idempotent.
- NGINX không hủy được task đang chạy trong thread pool. Với task gắn với request (inspect body lớn ở phase 2), module giữ request sống tới khi task xong: tăng `r->main->blocked` và đặt `r->aio = 1` trước khi gửi task; handler hoàn tất giảm lại rồi mới đi tiếp. Nếu kết nối đã lỗi (`r->connection->error`), kết quả task bị bỏ.
- Task nạp bundle thuộc về worker, không gắn với request nào, nên không bị ảnh hưởng khi stream bị hủy.

## Xử lý body

Request body được inspect theo luồng (streaming) qua request body filter, nhưng ở chế độ enforce thì body phải đọc xong và có verdict trước khi gửi lên upstream; response body chỉ được inspect đến một giới hạn byte.

**Request body**

- Module đăng ký vào chuỗi `ngx_http_top_request_body_filter`: mỗi chunk đến được đưa ngay vào `strata_tx_request_body_chunk`.
- **Enforce luôn đọc đủ body trước CONTENT phase**: ở PREACCESS, với location ở chế độ enforce và request có body, module tự gọi `ngx_http_read_client_request_body` và trả `NGX_DONE`. NGINX giữ body (bộ nhớ hoặc file tạm), và proxy chỉ chạy sau khi module có verdict. Vì body đã được đọc xong trước khi proxy bắt đầu, `proxy_request_buffering off` không còn tạo ra kẽ hở gửi chunk đầu lên upstream trước khi inspect xong.
- Directive `strata_request_body_mode buffer | stream` (mặc định `buffer`). `stream` chỉ dành cho location upload/streaming dài và chỉ chạy shadow: cấu hình `stream` cho location mà policy ở enforce làm `nginx -t` **báo lỗi**, không chỉ cảnh báo; nếu policy đổi sang enforce khi đang chạy, module ép location đó về shadow và ghi metric `strata_forced_shadow`.
- Giới hạn `strata_request_body_limit` (mặc định 1 MB). Body vượt giới hạn xử lý theo `oversize` của policy: template API mặc định `block`, template web mặc định `pass`; vì vậy location upload lớn cần đặt giới hạn riêng.
- Số tham số được kiểm (query rồi body: form, lá JSON, field multipart) tối đa `max_args` của policy, mặc định 1.024 (#28). Request có nhiều hơn cũng xử lý theo `oversize` (Rule 100021): `block` thì chặn; `pass` thì chỉ kiểm phần trong giới hạn và sự kiện ghi `inspection = PARTIAL`. Trước #28, tham số thứ 1.025 trở đi bị bỏ mà không có dấu hiệu nào.
- Body không parse được tới cuối (#97) thì báo rule protocol dựng sẵn **100022**, xử lý theo `oversize` của policy giống 100020 và 100021 (chặn ngay, hoặc ghi lại với `inspection = PARTIAL`). Các trường hợp: JSON hỏng, lồng sâu hơn 64 tầng hoặc còn dữ liệu sau văn bản; XML có thẻ, comment, CDATA hay khai báo không đóng; multipart không có delimiter, có part không kết thúc, hoặc có part bị bỏ (thiếu dòng trống sau header, thiếu `name`), kể cả khi boundary của header không khớp body. Trước #97, phần sau chỗ hỏng không được kiểm và không có gì báo. Body bị connector cắt ở giới hạn (100020) thì không báo thêm 100022. BOM UTF-8 ở đầu JSON không tính là hỏng. Multipart nhiều hơn 1.024 part thì báo 100021 (phần dư không được kiểm).
- **Ranh giới message**: body tới filter đã được NGINX bỏ framing chunked; libstrata inspect đúng nội dung NGINX sẽ gửi lên upstream (proxy tự đóng gói lại bằng framing của chính nó). Header framing thô (`Content-Length`, `Transfer-Encoding`, kể cả giá trị trùng hoặc dạng lạ như `chunked, identity`) được truyền riêng cho lớp protocol để chặn request mơ hồ. Chunked hỏng thì NGINX từ chối trước khi tới module.
- `multipart/form-data`: libstrata tự tách part; nội dung file nhị phân chỉ kiểm tra tên, kiểu, kích thước theo filetype.

**Response body**

- **Header filter**: kiểm tra mã trả về theo allowed codes, header lộ thông tin, cookie attribute. Nếu policy cần inspect response body, đặt `r->filter_need_in_memory = 1` để NGINX đọc body từ file vào bộ nhớ cho request này (sendfile tự tắt với request đó). Location trả file tĩnh lớn nên tắt `strata_response_inspect`.
- **Quy tắc buffer ở body filter**:
  - Không ghi đè buffer gốc. Khi che dữ liệu, module lấy buffer mới (từ danh sách free của module, hoặc cấp từ `r->pool`) với `temporary = 1`, copy dữ liệu đã che từ libstrata vào, rồi gọi `strata_buf_free`.
  - Giữ nguyên các cờ `last_buf`, `last_in_chain`, `flush`, `sync` của buffer gốc trên buffer mới; đánh dấu buffer gốc đã dùng hết (`b->pos = b->last`) để module phía trên giải phóng hoặc tái sử dụng đúng.
  - Dùng `ngx_chain_update_chains` với danh sách busy/free (cách `sub_filter` và `gunzip` làm) để bộ nhớ không tăng theo kích thước response.
  - Buffer cấp từ `r->pool` tồn tại tới khi request kết thúc hẳn (output đã gửi xong hoặc kết nối đóng), nên an toàn khi NGINX còn đang gửi dữ liệu ra socket.
  - Không bao giờ truyền buffer `in_file` vào libstrata. Nhờ `filter_need_in_memory` thì không còn gặp buffer loại này; nếu vẫn gặp, bỏ qua inspect phần đó và ghi metric.
  - Inspect tới `strata_response_body_limit`; phần còn lại truyền nguyên.
  - Data guard giữ lại đuôi mỗi chunk (độ dài giá trị dài nhất trừ 1 byte) để giá trị bị cắt giữa hai buffer vẫn bị che; tổng độ dài không đổi. Gặp buffer có cờ `flush` (SSE, `proxy_buffering off`), module gọi `strata_tx_response_body_flush` và gửi phần đang giữ cùng buffer đó, nên stream không bị chậm; giá trị bị cắt đúng tại điểm flush thì không được che.
  - Bộ nhớ: buffer gốc được trả ngay cho module phía trên, nên nguồn đọc tiếp trong khi bản copy còn chờ socket. Đỉnh bộ nhớ của một request vì vậy xấp xỉ min(`strata_response_body_limit`, kích thước body) và được trả khi request xong; không tăng dần qua các request. Mặc định 512 KB giữ mức này nhỏ; location đặt giới hạn lớn phải tính phần bộ nhớ này.
- **Ba chế độ khi phát hiện vấn đề**:
  - **Log**: ghi sự kiện, không đổi response.
  - **Che (data guard)**: thay ký tự bằng `*` cùng độ dài nên `Content-Length` không đổi.
  - **Chặn response**: chỉ làm được khi header chưa gửi, nên policy chặn response bắt buộc buffer response tới giới hạn trước khi gửi header.
- **Response nén**: body filter đặt trước `gzip` trong chuỗi filter (qua `ngx_module_order`) để thấy dữ liệu chưa nén. Upstream trả sẵn nội dung nén thì theo policy: bỏ `Accept-Encoding` khi gửi lên upstream cho location cần inspect, hoặc bỏ qua inspect và ghi metric.

**URI và query**

Module truyền cho libstrata cả ba giá trị: `r->unparsed_uri` (thô, đúng như client gửi), `r->uri` (NGINX đã giải mã `%XX`, gộp `//`, xử lý `.` và `..`), và `r->args`. Lý do: upstream có thể nhận URI thô (`proxy_pass` không kèm URI) hoặc URI đã normalize (`proxy_pass` có URI, hoặc sau `rewrite`).

- Rule về path chạy trên cả dạng thô, dạng NGINX normalize, và dạng libstrata normalize theo profile backend (ví dụ Tomcat/Spring bỏ matrix parameter `;jsessionid=…`, IIS coi `\` như `/`).
- Khác biệt bất thường giữa dạng thô và dạng normalize là violation riêng ở lớp protocol: encoding kép (`%252e`), `%2e%2e/`, `;` trong segment, null byte, ký tự điều khiển.

**Giao thức**

| Trường hợp | Cách xử lý |
| --- | --- |
| HTTP/2, HTTP/3 | Cùng API body của NGINX; header đã được NGINX giải nén HPACK/QPACK trước khi tới module |
| gRPC (`grpc_pass`) | Xem mục Traffic gRPC qua NGINX |
| WebSocket | Inspect handshake (URL, header, cookie, origin); sau `101 Switching Protocols` không inspect frame |
| Server-Sent Events, streaming dài | Không buffer response; chỉ inspect header và byte đầu tới giới hạn. Buffer `flush` xả phần data guard đang giữ (`strata_tx_response_body_flush`) |
| Subrequest (`auth_request`, SSI) | Nhận diện bằng `r != r->main`, bỏ qua; chỉ inspect request chính |
| Internal redirect (`error_page`, `try_files`, `rewrite … last`) | NGINX xóa module context khi redirect nhưng giữ nguyên request và pool. Module lưu trạng thái (đã inspect chưa, verdict, phase đã qua, đã đếm metric chưa) trong một struct gắn vào pool cleanup của request. Khi PREACCESS thấy context rỗng, module tìm struct này trong `r->pool->cleanup` và gắn lại. Nếu đã có verdict thì không inspect lại, không đếm metric lần hai; verdict và policy của lần đầu được giữ. Request mới luôn có pool mới nên không thể nhầm với request đã redirect |

## Traffic gRPC qua NGINX

Với `grpc_pass`, module tách từng message gRPC trong body, giải mã protobuf theo descriptor của service đã nạp trong bundle, và khi chặn thì trả lỗi đúng chuẩn gRPC (`grpc-status: 7`) kèm Block ID, vì client gRPC không đọc được trang 403 HTML.

**Nhận diện và parse**

- Nhận diện request gRPC qua `Content-Type: application/grpc` (kể cả `+proto`), HTTP/2, method `POST`; path có dạng `/<package>.<Service>/<Method>`.
- Body là chuỗi message có tiền tố 5 byte (1 byte cờ nén + 4 byte độ dài big-endian). libstrata ghép message có thể nằm vắt qua nhiều buffer NGINX.
- Message nén (`grpc-encoding: gzip`): giải nén có giới hạn kích thước và tỉ lệ nén để chống bom nén; vượt giới hạn là violation.
- Descriptor: người vận hành tải `FileDescriptorSet` (tạo bằng `protoc --include_imports --descriptor_set_out`) lên UI hoặc API; control plane biên dịch vào bundle và gắn với policy.

**Kiểm tra theo descriptor**

| Kiểm tra | Violation |
| --- | --- |
| Service hoặc method không có trong descriptor | `GRPC_UNKNOWN_METHOD` |
| Message không giải mã được theo kiểu khai báo | `GRPC_MALFORMED_MESSAGE` |
| Field không khai báo (unknown field) | `GRPC_UNKNOWN_FIELD` (bật/tắt theo method) |
| Message vượt kích thước, số message trong một stream vượt giới hạn, độ sâu lồng quá mức | `GRPC_SIZE_LIMIT`, `GRPC_STREAM_LIMIT`, `GRPC_DEPTH_LIMIT` |
| Giá trị `string` khớp signature hoặc semantic detector (SQLi, XSS, CMDi…) | `SIG_MATCH` / `SEMANTIC_*`, kèm đường dẫn field như `req.customer.name` |
| Giá trị `bytes` | Chỉ kiểm tra kích thước, không chạy signature văn bản |

Trong decision trace và sự kiện, vị trí vi phạm được ghi theo đường dẫn field protobuf, nên exception có thể nhắm đúng một field của một method.

**Chặn**

- Unary và server-streaming: request được inspect đủ trước khi lên upstream. Khi chặn, module trả response chỉ có header (Trailers-Only): HTTP 200, `content-type: application/grpc`, `grpc-status: 7` (PERMISSION\_DENIED), `grpc-message: blocked; block_id=STR-…`, và header `x-strata-block-id`.
- Client-streaming và bidi-streaming: từng message được inspect khi đến; nếu phát hiện vi phạm sau khi stream đã đi lên upstream, module hủy stream (RST\_STREAM) và ghi sự kiện. Client chỉ thấy lỗi `CANCELLED`, Block ID nằm trong log và event store.
- Fail-closed với gRPC trả `grpc-status: 14` (UNAVAILABLE) thay cho HTTP 503.

**Response gRPC**: inspect message trả về theo cùng descriptor (data guard che field nhạy cảm, ví dụ số CCCD trong `string`), có giới hạn byte như response HTTP. `grpc-status` từ upstream được ghi vào sự kiện.

**Ngoài phạm vi giai đoạn này**: gRPC-Web, gRPC transcoding JSON.

## Ranh giới FFI

Module chỉ gọi `libstrata` qua một C ABI nhỏ, ổn định, có version; mọi con trỏ đầu vào chỉ được mượn trong thời gian gọi hàm, và không panic nào được phép vượt qua ranh giới.

Cache worker (ABI 1.7, remediation #49): bundle map biên dịch sớm fallback regex của rule không có gate chọn lọc, gồm gate chỉ theo method. Connector gọi `strata_engine_prepare_thread` trên chính thread worker sau fork và trước khi publish bundle mới: cấp scratch/stream Hyperscan và prime cache regex cho đường thông dụng bằng input cố định hữu hạn. Không tạo transaction, không tăng traffic/rule-cost counters, không thay budget/fail mode. Không bảo đảm warm mọi pattern/input; fallback dưới gate theo dữ liệu vẫn lazy. Nếu chuẩn bị lỗi, module ghi warning và giữ cơ chế inspection/fail mode hiện có khi request đến. Hot activation có thêm thời gian chuẩn bị đồng bộ trên event loop, cần đo độ trễ activation và traffic dưới tải trước khi triển khai.

JA4 (ABI 1.8, RV-N-02): khi module bật, postconfiguration gắn message callback của OpenSSL (`SSL_CTX_set_msg_callback`) vào SSL context của mọi server; NGINX đã dùng ClientHello callback cho SNI nên không dùng được callback đó. Với ClientHello đầu tiên của kết nối, C chỉ chuyển con trỏ + độ dài thông điệp handshake cho `strata_ja4` (libstrata parse, có giới hạn, không cấp phát heap) và lưu 36 byte vào ex_data của SSL (pool của connection). Mỗi request gọi `strata_tx_set_ja4`: rule đọc qua target `tls_ja4`, sự kiện có field 24 `ja4`. Fingerprint bị từ chối không làm hỏng transaction. HTTP/3 qua lớp tương thích OpenSSL của NGINX: lớp đó đặt callback riêng cho từng kết nối QUIC nên không có JA4. Module phải build với `--with-http_ssl_module` (như bản nginx.org); trước RV-N-02 `build.sh` thiếu cờ này nên phần TLS của module không được biên dịch. JA4 dùng làm key rate limit để sau RV-R-03.

**API chính (`strata.h`)**

```c
/* Phiên bản ABI: module kiểm tra lúc init, lệch major thì từ chối nạp */
uint32_t strata_abi_version(void);

/* Engine: dựng trực tiếp trên vùng bundle đã mmap (chỉ đọc, dùng chung giữa
   các worker); libstrata không copy dữ liệu bundle */
strata_engine_t *strata_engine_map(const uint8_t *base, size_t len,
                                   const uint8_t *pubkey, strata_err_t *err);
void strata_engine_retain(strata_engine_t *e);
void strata_engine_release(strata_engine_t *e);   /* bản cuối: module munmap */

/* ABI 1.7: chuẩn bị cache trên thread worker, trước request/activate bundle */
strata_rc_t strata_engine_prepare_thread(const strata_engine_t *e);

/* ABI 1.8 (RV-N-02): JA4 của một ClientHello (thông điệp handshake), không cần
   engine; rồi gắn vào từng transaction trước strata_tx_request_headers */
strata_rc_t strata_ja4(const uint8_t *hello, size_t len, uint32_t flags,
                       uint8_t *out /* STRATA_JA4_LEN */);
strata_rc_t strata_tx_set_ja4(strata_tx_t *tx, strata_str_t ja4);

/* Transaction: một request, chỉ dùng trên một thread */
strata_tx_t *strata_tx_new(strata_engine_t *e, strata_str_t policy,
                           const strata_conn_t *conn,
                           uint64_t cpu_budget_us);

/* URI truyền đủ 3 dạng: thô, NGINX đã normalize, query */
strata_rc_t strata_tx_request_line(strata_tx_t *tx, strata_str_t method,
                                   strata_str_t raw_uri,   /* r->unparsed_uri */
                                   strata_str_t norm_uri,  /* r->uri */
                                   strata_str_t args,      /* r->args */
                                   strata_str_t proto);

/* Header thô theo đúng thứ tự và số lần xuất hiện (kể cả trùng lặp),
   lấy từ r->headers_in.headers */
strata_rc_t strata_tx_request_headers(strata_tx_t *tx,
                                      const strata_header_t *h, size_t n);
strata_rc_t strata_tx_request_body_chunk(strata_tx_t *tx, const uint8_t *p,
                                         size_t len, int last);
strata_rc_t strata_tx_response_headers(strata_tx_t *tx, uint16_t status,
                                       const strata_header_t *h, size_t n);
strata_rc_t strata_tx_response_body_chunk(strata_tx_t *tx, const uint8_t *p,
                                          size_t len, int last,
                                          strata_buf_t *rewritten);
/* ABI 1.1: gặp buffer flush (streaming), lấy ngay phần data guard đang giữ */
strata_rc_t strata_tx_response_body_flush(strata_tx_t *tx, strata_buf_t *out);
void strata_tx_verdict(const strata_tx_t *tx, strata_verdict_t *out);
size_t strata_tx_event(const strata_tx_t *tx, uint8_t *dst, size_t cap);
void strata_tx_free(strata_tx_t *tx);
void strata_buf_free(strata_buf_t *b);
```

**Kiểu dữ liệu zero-copy và quy tắc lifetime** (chốt ở tuần 2, sau đó chỉ đổi khi tăng major ABI)

```c
typedef struct { const uint8_t *ptr; size_t len; } strata_str_t;
typedef struct { strata_str_t key; strata_str_t val; } strata_str_pair_t;
typedef strata_str_pair_t strata_header_t;
```

- Mọi `strata_str_t` chỉ là dữ liệu mượn trong thời gian một lời gọi. Phía Rust map thành `&[u8]` bằng `std::slice::from_raw_parts`, không chuyển sang `String` hay `Vec<u8>`.
- Không giả định UTF-8, không giả định kết thúc bằng null; `ptr` được phép là NULL khi `len = 0`.
- So khớp tên header không phân biệt hoa thường bằng so sánh byte ASCII, không cấp phát.
- Rust chỉ copy dữ liệu cần giữ qua nhiều lời gọi, và chỉ trong hai trường hợp: đoạn input khớp rule để đưa vào sự kiện (128 byte mỗi match, hoặc 2–4 KB theo `max_snippet_size` của policy, đã che), header của request cho ngữ cảnh sự kiện (chỉ khi request đã có Event ID, hoặc bundle có rule ở stage body vốn đã giữ header), và một số ít header cần đối chiếu với response (ví dụ `Origin`, `Content-Type`). Phần copy nằm trong arena riêng của transaction, có giới hạn kích thước, giải phóng một lần ở `strata_tx_free`.
- `strata_tx_free` idempotent: libstrata bỏ qua con trỏ NULL, module đặt con trỏ trong context về NULL ngay sau khi gọi.
- Cả 5 connector dùng chung `strata.h` này; thay đổi ABI không tương thích sau tuần 2 phải tăng major và kèm lớp tương thích. Chỉ thêm hàm mới (không đổi hàm, kiểu đã có) thì tăng minor: 1.1 thêm `strata_tx_response_body_flush`, 1.2 thêm cờ `STRATA_TXF_DEGRADED` (W11-N-01), 1.3 thêm `strata_engine_disable_rules` (W12-R-02: danh sách Rule ID bị tắt khẩn cấp, gắn với engine, mỗi transaction chụp danh sách lúc bắt đầu; bundle mới thì connector áp lại), 1.4 thêm cờ verdict `STRATA_VF_CANARY` / `STRATA_VF_CANARY_SHADOW` (W12-G2-01: policy có canary enforce, client trong / ngoài nhóm canary; connector đếm hai nhóm; sự kiện có trường `canary` 22, vì 17–21 là của RV-G2-01). 1.5 thêm `strata_engine_set_replay` và `strata_tx_sample` (W12-N-01: lấy mẫu một tỉ lệ transaction cho replay, ẩn danh ngay trong libstrata bằng khóa HMAC của connector group, `engine/src/anon.rs`; mẫu là một datagram ≤ 8 KB trên event socket, mở đầu `\xffSR1`; body giữ tối đa 4 KB). 1.6 thêm cờ verdict `STRATA_VF_FAIL_CLOSED` (#98: hết CPU budget khi request đã có finding và policy đặt `fail_on_findings: block`; connector xử lý như fail mode closed).

`strata_verdict_t` gồm: action (`allow`, `log`, `challenge`, `block`), mã HTTP trả về, Block ID (24 byte), điểm tổng, tối đa 16 rule ID khớp, cờ `need_body` / `need_response`.

**Quy tắc bộ nhớ**

| Dữ liệu | Ai cấp phát | Ai giải phóng |
| --- | --- | --- |
| Header, URI, chunk body truyền vào | NGINX (pool request, buffer) | NGINX; libstrata copy phần cần giữ |
| `strata_tx_t` | libstrata | Module gọi `strata_tx_free` trong pool cleanup của request, kể cả khi client ngắt giữa chừng |
| Buffer response đã che (`rewritten`) | libstrata | Module copy sang buffer NGINX mới (`temporary = 1`, giữ cờ của buffer gốc) rồi gọi `strata_buf_free` ngay; libstrata không giữ con trỏ nào vào buffer NGINX |
| Vùng bundle mmap | Module (`mmap` trong thread pool) | Module `munmap` khi `strata_engine_release` trả về tham chiếu cuối |
| Engine | libstrata, có đếm tham chiếu | Request nào đang dùng engine thì giữ một tham chiếu; giải phóng khi tham chiếu cuối được trả |

**Lỗi và panic**

- Mọi hàm `extern "C"` bọc trong `catch_unwind`; panic trả `STRATA_E_INTERNAL` và đánh dấu transaction hỏng.
- Build Rust với `panic = "unwind"` để bắt được panic (không dùng `abort`).
- Module xử lý mọi mã lỗi theo `strata_fail_mode` của location. Ngoại lệ (#98, ABI 1.6): verdict có cờ `STRATA_VF_FAIL_CLOSED` thì module xử lý như fail mode closed (503 kèm Event ID, đếm vào fail closed). libstrata đặt cờ này khi hết CPU budget trên một request **đã có finding** (điểm > 0: rule khớp dưới ngưỡng; gói signature ở shadow và rule điểm 0 không tính), policy enforce, và policy đặt `fail_on_findings: block` (mặc định `pass`: theo fail mode như trước). Mục đích: đóng đường tránh có chủ đích, tức đặt giá trị tốn CPU ở đầu request để payload ở cuối được cho qua. Trước khi bật cho một policy, đo trong shadow tỉ lệ request "hết budget sau một finding" (`strata-rules lifecycle`, mục #98; cần module có cờ `inspection`, từ RV-G2-01).
- Không có callback từ Rust gọi ngược vào NGINX: tránh re-entrancy và phụ thuộc phiên bản NGINX.

**Liên kết**: `libstrata` build thành thư viện tĩnh (`.a`) và link thẳng vào `ngx_http_strata_module.so`, kèm Hyperscan tĩnh, để không phụ thuộc thư viện ngoài khi cài.

## Directive & biến

Directive chỉ quy định cách module gắn vào NGINX; nội dung bảo mật (rule, ngưỡng, exception) luôn nằm trong bundle từ control plane. Directive ở cấp con kế thừa và ghi đè cấp cha theo cơ chế merge chuẩn của NGINX.

| Directive | Ngữ cảnh | Mặc định | Ý nghĩa |
| --- | --- | --- | --- |
| `strata on \| off` | http, server, location | `off` | Bật module |
| `strata_control_file <path>` | http | `/run/strata/control` | Trang control (tmpfs) do `strata-agent` ghi; worker mmap để biết có bundle mới |
| `strata_bundle_dir <path>` | http | `/var/lib/strata/bundle` | Thư mục bundle; phải nằm trên đĩa local hoặc tmpfs, không dùng NFS/Ceph |
| `strata_bundle_pubkey <path>` | http | — (bắt buộc) | Khóa công khai kiểm tra chữ ký bundle |
| `strata_bundle_check <time>` | http | `1s` | Chu kỳ đọc số generation trong control file (chỉ đọc bộ nhớ, không syscall) |
| `strata_node_id <name>` | http | hostname | Tên node, dùng sinh Block ID và gắn sự kiện |
| `strata_policy <name>` | server, location | — | Policy trong bundle áp cho khối này |
| `strata_mode inherit \| shadow` | http, server, location | `inherit` | Theo policy, hoặc ép về shadow khi khẩn cấp; không thể ép lên enforce từ phía NGINX |
| `strata_fail_mode open \| closed` | http, server, location | `open` | Hành vi khi engine lỗi, quá budget hoặc chưa có bundle |
| `strata_request_body_mode buffer \| stream` | http, server, location | `buffer` | `buffer`: đọc đủ body trước khi lên upstream. `stream`: chỉ hợp lệ với shadow; đi cùng policy enforce thì `nginx -t` báo lỗi |
| `strata_request_body_limit <size>` | http, server, location | `1m` | Số byte request body tối đa được inspect |
| `strata_response_inspect on \| off` | http, server, location | `on` | Bật inspect response (bật thì NGINX đọc body file vào bộ nhớ cho request đó) |
| `strata_response_body_limit <size>` | http, server, location | `512k` | Số byte response body tối đa được inspect |
| `strata_identity <complex value>` | http, server, location | — | Định danh client cho rate limit / behavior, ví dụ `$http_x_client_id` |
| `strata_block_page <path>` | http, server, location | template từ bundle | Ghi đè cục bộ template trang chặn mặc định của control plane |
| `strata_event_socket <unix:path>` | http | `unix:/run/strata/events.sock` | Socket gửi sự kiện (protobuf) cho `strata-agent`. Gói cài đặt để systemd giữ socket này (`strata-agent.socket`, socket activation, W13-G1-01): socket sống qua mỗi lần agent khởi động lại, nên sự kiện được xếp hàng chứ không mất, và socket đã `connect()` của worker vẫn hợp lệ |
| `strata_cpu_budget <time>` | http, server, location | `10ms` | Thời gian CPU tối đa cho một request; vượt thì xử lý theo fail mode. Mặc định 2 ms tới 15/10/2026, nâng lên 10 ms theo quyết định PO (`docs/decisions/base64-args.md` §2) |
| `strata_breaker on\|off` | http | `on` | Circuit breaker cấp worker (mục Circuit breaker cấp worker) |
| `strata_breaker_threshold <tỉ lệ>% <cửa sổ> <tối thiểu> [open=<time>]` | http | `2% 10s 200 open=30s` | Ngưỡng mở breaker; `open=` là thời gian mở đầu tiên (tối đa 5 phút) |
| `strata_breaker_action degrade\|reject` | http, server, location | `degrade` | Khi breaker mở: chạy giảm cấp, hoặc trả 503 kèm Event ID |

IP client lấy từ `$remote_addr` sau module `realip`, nên cấu hình `set_real_ip_from` / `real_ip_header` như bình thường.

**Biến**

| Biến | Giá trị |
| --- | --- |
| `$strata_block_id` | Block ID nếu bị chặn, Event ID nếu shadow, rỗng nếu cho qua |
| `$strata_action` | `allow`, `log`, `challenge`, `block`, `error` |
| `$strata_score` | Điểm tổng |
| `$strata_rules` | Danh sách rule ID khớp, phân cách bằng dấu phẩy |
| `$strata_policy` | Policy đã áp dụng |
| `$strata_bundle_version` | Phiên bản bundle đang chạy |
| `$strata_time_us` | Thời gian xử lý của engine (micro giây) |
| `$strata_ja4` | JA4 (FoxIO) của kết nối TLS của client, 36 ký tự; rỗng nếu không TLS hoặc qua HTTP/3; có cả ở location `strata off` (RV-N-02) |

**Ví dụ cấu hình**

```nginx
load_module modules/ngx_http_strata_module.so;

http {
    strata_control_file  /run/strata/control;
    strata_bundle_dir    /var/lib/strata/bundle;
    strata_bundle_pubkey /etc/strata/bundle.pub;
    strata_node_id       web-01;

    set_real_ip_from 10.0.0.0/8;
    real_ip_header   X-Forwarded-For;

    log_format waf '$remote_addr "$request" $status '
                   'blk=$strata_block_id act=$strata_action '
                   'score=$strata_score rules=$strata_rules t=$strata_time_us';
    access_log /var/log/nginx/access.log waf;

    server {
        listen 443 ssl;
        server_name api.example.vn;
        strata on;
        strata_policy  ekyc-api;
        strata_identity $http_x_client_id;

        location /ekyc/upload/ {
            strata_request_body_limit 8m;
            proxy_pass http://ekyc;
        }
        location /static/ {
            strata off;
            root /srv/static;
        }
    }
}
```

## Bundle & hot reload

Agent chuẩn bị bundle và báo có bản mới qua một trang control dùng chung; worker mmap file bundle ở chế độ chỉ đọc nên mọi worker dùng chung một bản trong RAM vật lý. Event loop không phát sinh syscall I/O nào khi không có bundle mới, và không cần `nginx -s reload`.

**Định dạng bundle (zero-copy)**: header cố định (magic, phiên bản định dạng, phiên bản bundle tăng dần, thời điểm tạo, danh sách policy) + các section căn lề 4 KB + chữ ký Ed25519. Cây quyết định, bảng rule, schema dùng **offset thay cho con trỏ** (kiểu định dạng rkyv) nên dùng trực tiếp từ vùng mmap ở bất kỳ địa chỉ nào, không cần deserialize.

**Hyperscan cần PoC ở tuần 1–2**: phải xác nhận database Hyperscan (hoặc Vectorscan trên ARM) đã deserialize có dùng được trực tiếp từ vùng chỉ đọc mmap ở các địa chỉ khác nhau giữa các worker hay không. Nếu không được, riêng section Hyperscan được deserialize vào bộ nhớ riêng mỗi worker; phần còn lại vẫn dùng chung. Scratch của Hyperscan luôn riêng mỗi worker (nhỏ, cấp một lần).

**Control file**: `/run/strata/control` nằm trên tmpfs, dài 4 KB, chỉ agent được ghi. Nội dung: generation (u64), phiên bản bundle, tên file, sha256. Agent ghi theo kiểu seqlock (generation lẻ là đang ghi, chẵn là xong). Worker mmap file này lúc khởi động; timer chỉ đọc generation trong bộ nhớ, không gọi `stat()`.

**Luồng cập nhật**

1. `strata-agent` nhận bundle qua `FetchBundle`, kiểm sha256 và chữ ký, ghi `bundle-<version>.sbn` (file tạm → `fsync` → `rename`). Lúc khởi động, agent kiểm loại filesystem của thư mục bundle và từ chối chạy nếu đó là filesystem mạng.
2. Agent cập nhật control file theo seqlock, tăng generation.
3. Worker thấy generation đổi (timer `strata_bundle_check` + độ lệch ngẫu nhiên để các worker không nạp cùng lúc), gửi việc sang thread pool: `open`, `mmap(PROT_READ, MAP_SHARED)`, `madvise(MADV_WILLNEED)`, kiểm chữ ký trực tiếp trên vùng mmap, gọi `strata_engine_map`. Mọi syscall nằm trong thread pool, không nằm trong event loop.
4. Callback trong event loop đổi con trỏ engine của worker. Request mới dùng engine mới; engine cũ giữ bằng đếm tham chiếu và được `munmap` khi request cuối dùng nó kết thúc.
5. Worker báo phiên bản đang chạy qua event socket; agent báo `ACTIVE` lên control plane.

**Các trường hợp đặc biệt**

| Tình huống | Xử lý |
| --- | --- |
| Khởi động NGINX | Master mmap bundle hiện tại khi đọc cấu hình; worker thừa hưởng vùng mmap qua `fork`, dùng chung RAM ngay từ đầu. `nginx -t` báo lỗi nếu chữ ký sai, chỉ cảnh báo nếu chưa có bundle |
| Chưa có bundle | Worker chạy theo `strata_fail_mode` của từng location, ghi metric `strata_bundle_missing` |
| Bundle hỏng hoặc sai chữ ký | Giữ bundle cũ, ghi lỗi, báo về control plane |
| Phiên bản cũ hơn bản đang chạy | Từ chối, trừ khi header có cờ rollback được control plane ký |
| Agent chết | Control file không đổi; worker chạy tiếp với bundle hiện tại |
| NGINX build không có thread pool | Nạp đồng bộ trong event loop và ghi cảnh báo; các gói chính thức của nginx.org đều có thread pool |
| `nginx -s reload` | Vẫn hoạt động: master mới mmap lại bundle hiện tại |

**Ngân sách tài nguyên**: phần dùng chung của engine chỉ tốn RAM vật lý một lần cho cả máy (ví dụ engine 64 MB trên máy 128 worker vẫn khoảng 64 MB, thay vì khoảng 8 GB nếu mỗi worker giữ một bản). Bộ nhớ riêng mỗi worker chỉ gồm scratch Hyperscan và trạng thái transaction, mục tiêu dưới 8 MB (cộng phần Hyperscan nếu PoC buộc phải tách riêng). Trong lúc chuyển bản, máy giữ tối đa hai vùng mmap.

## Control plane

Control plane là nơi duy nhất giữ cấu hình: người dùng và công cụ đi qua API server; node chỉ kết nối tới Fleet service bằng chứng chỉ riêng. Mọi service đều không trạng thái, chạy nhiều bản sau load balancer.

&#91;embedded content: control plane · service, kho dữ liệu, kết nối\]

Khi một policy được deploy, compiler tạo và ký bundle, lưu vào object storage, rồi phát thông báo qua message bus; Fleet service đẩy `BundleAvailable` tới các agent đang kết nối. Sự kiện agent gửi lên đi qua Fleet sang Event ingest rồi vào ClickHouse.

| Thành phần | Trách nhiệm | Công nghệ đề xuất |
| --- | --- | --- |
| API server | gRPC + REST cho UI, CLI, CI, GitOps; xác thực, RBAC, audit | Go, grpc-gateway |
| Policy service | CRUD policy, rule, exception, schema; version, diff, quy tắc 4 mắt | Go |
| Compiler + signer | Biên dịch policy → bundle (dùng chính libstrata), tính cost unit, ký Ed25519; khóa riêng nằm trong KMS/HSM, không rời khỏi đó | Rust + Go |
| Replay service | Chạy bản nháp trên corpus traffic đã ẩn danh, báo FP/FN theo route | Rust (dùng chung engine) |
| Fleet service | Enrollment, cấp và gia hạn chứng chỉ, giữ stream `Connect`, điều phối rollout theo đợt, nhận sự kiện | Go, gRPC |
| Message bus | Thông báo bundle mới, lệnh khẩn cấp tới mọi bản Fleet | NATS hoặc PostgreSQL LISTEN/NOTIFY |
| Event ingest | Chống trùng theo `seq`, kiểm schema, ghi theo lô | Go |
| PostgreSQL | Policy, version, node, role binding, audit | HA bằng Patroni |
| Object storage | Bundle, corpus replay | Thư mục cục bộ (`-objects-dir`, Compact, CP-A07) hoặc S3 / MinIO |

*Bản Compact (PO 19/10/2026, `docs/plan/compact-ops-plan.md`):* mặc định chỉ chạy **một control **Lease (CP-A03):** control plane giữ lease trong bảng `control_plane_lease` (cờ `-single-control-plane`, mặc định bật; `-lease-ttl` 30 s, gia hạn mỗi 10 s); bản thứ hai chờ lease hết hạn rồi dừng; bản mất lease thì thoát; sau sự cố phải chờ lease hết hạn (mặc định tối đa khoảng 30 s); không suy đoán tiến trình đã chết từ hostname/PID vì container có PID namespace riêng. Deploy chạy tuần tự dưới khóa bundle, chờ tối đa 2 phút rồi trả 409. `GET /readyz` (không cần token): trạng thái `postgres`, `lease`, `clickhouse` (ok, error, degraded, disabled), 503 khi PostgreSQL hoặc lease không ổn; ClickHouse lỗi chỉ là `degraded`. **Cấu hình (CP-A02):** `-config <file>` (hoặc `STRATA_CONFIG`) nạp file YAML `version: 1` (mẫu: `control-plane/config/example.yaml`); mỗi khóa ứng với một cờ (`config.Keys()`, test bắt cờ mới thiếu khóa); cờ truyền tường minh thắng file; khóa lạ, duration không đơn vị, tổ hợp sai bị từ chối; đường dẫn tương đối tính từ thư mục của file. Secret không viết trong file: khóa `*_file` trỏ tới file (không symlink, không cho nhóm/người khác đọc) mà nội dung thành biến môi trường control plane vẫn đọc (`STRATA_POSTGRES_DSN`, `STRATA_CLICKHOUSE_PASSWORD`, `STRATA_S3_*`, `STRATA_IDENTITY_HMAC_KEY`, `STRATA_LOCAL_ADMIN_PASSWORD`), trừ khi biến đã đặt. `strata-control-plane config validate|show -config <file>` kiểm và in giá trị hiệu lực kèm nguồn (flag, env, file, default); secret chỉ hiện `<redacted>`. Mọi khóa giai đoạn này cần restart. **Artifact (CP-A07):** `-objects-dir <thư mục>` (khóa `bundles.storage.local.path`; `init` đặt `<data>/objects` khi không có `-s3-endpoint`; hai cờ loại trừ nhau) giữ bundle, mẫu replay, GeoIP và dải IP crawler dưới cùng khóa như S3. Mọi file mở qua `os.Root` (khóa hay symlink không thoát ra ngoài; khóa chỉ gồm đoạn `[A-Za-z0-9._-]`, không đoạn rỗng, `.`, `..`), thư mục 0700, file 0600; ghi nguyên tử (file tạm cùng thư mục, `fsync`, rồi `link` hoặc `rename`, `fsync` thư mục). Khóa **bất biến** (bundle, mẫu replay, MMDB): đã có nội dung khác thì `ErrObjectExists`, cùng nội dung thì thành công; chỉ các khóa trong `policy.DefaultMutableKeys` ghi đè được (`geoip/latest.json`, `geoip/*/manifest.json`, `goodbots/*.json`: con trỏ và manifest mang thời điểm tải). Deploy bỏ qua số bản đã có file mà chưa có bản ghi (upload của deploy lỗi, hoặc DB khôi phục lùi sau artifact) và lấy số sau file lớn nhất; deploy bị từ chối trước khi build khi thư mục còn dưới 256 MiB. Dọn mỗi giờ (`-objects-prune-interval`): giữ `-objects-keep-bundles` (10) bundle mới nhất, bundle mọi node đang chạy hoặc cần chạy, bundle của rollout RUNNING/PAUSED và của staging action chưa rollout (danh sách lấy từ DB, không theo tuổi file); không bao giờ xóa file trên số bản lớn nhất đã ghi; mẫu replay giữ `-objects-sample-days` (7) ngày; GeoIP giữ phiên bản mới và phiên bản vừa thay. Thư mục trên NFS bị cảnh báo lúc khởi động. Ký bundle mặc định bằng file (`-bundle-signer=file`), Vault là tùy chọn. **UI nhúng và ClickHouse (CP-A08):** control plane phục vụ Web UI build sẵn trong binary (`go:embed` của `control-plane/webui/dist`, `make control-plane-ui` chép `ui/dist` vào; binary không có UI chỉ phục vụ API) trên cùng origin với API (`-ui`, mặc định bật; CORS mặc định tắt). `/v1/`, `/healthz`, `/readyz` luôn là của API (đường API gõ sai là 404 JSON, không bao giờ `index.html`); file trong `assets/` (có hash) cache một năm `immutable`, còn lại `no-cache`; asset không có (của bản build khác) là 404. `/config.json` sinh từ cấu hình: `oidcAuthority` (= `-oidc-issuer`) và `oidcClientId` (`-ui-oidc-client-id`, mặc định `strata-ui`) chỉ khi bật OIDC. Mọi phản hồi có CSP (`script-src 'self'`, không script inline; `frame-ancestors 'none'`; nguồn ngoài duy nhất là origin của IdP), `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`; UI không đặt HTML thô (test quét mã nguồn). Schema ClickHouse là danh sách migration đánh số (`ingest/chmigrate.go`, ghi vào bảng `strata_schema_migrations`; `schema.sql` là migration 1; mỗi bước idempotent nên database cũ nhận lại mà không đổi), TTL vẫn là cấu hình áp mỗi lần khởi động; database của bản mới hơn thì không đụng. Control plane khởi động cả khi ClickHouse không chạy, migrate nền và thử lại (5 s, tăng dần tới 1 phút); `/readyz` báo `clickhouse: degraded` tới khi ping được và đã migrate. Truy vấn sự kiện/thống kê lỗi trả 503 `reason: EVENTS_UNAVAILABLE`; UI hiện "nguồn dữ liệu không sẵn sàng" và `—`, không bao giờ 0 sự kiện; đăng nhập, policy, deploy vẫn chạy. **Backup/restore (CP-A09):** `strata-control-plane backup -out <file>` ghi một tar mã hóa `age` (passphrase, scrypt; luôn mã hóa vì có khóa ký, CA, secret và bản dump chứa secret): `pg_dump -Fc` trước, rồi thư mục dữ liệu (khóa, PKI, secret, cấu hình), rồi artifact trên filesystem, cuối cùng manifest (SHA-256 từng file, phiên bản sản phẩm, migration PostgreSQL). Mật khẩu DSN chuyển cho `pg_dump`/`pg_restore` qua `PGPASSFILE` riêng 0600, không qua dòng lệnh. ClickHouse (lịch sử sự kiện) không nằm trong backup. `strata-control-plane restore -in <file>` từ chối khi lease còn hạn (control plane đang chạy), khi một file trong archive lệch manifest hoặc archive có đường dẫn lạ/symlink, khi schema của backup mới hơn bản build, khi file trong thư mục dữ liệu khác backup (trừ `-overwrite`); hỏi xác nhận (gõ RESTORE, hoặc `-yes`). Nó dùng `pg_restore` xuất SQL vào file tạm riêng 0600 rồi `psql --single-transaction` làm rỗng schema và nạp SQL trong cùng transaction (lỗi SQL rollback cả thao tác xóa), migrate lên, rồi trong một transaction: sàn số bundle (`bundle_version_floor`, migration 0028) = max của bản ghi và version node báo trong DB bị thay; bỏ `desired_bundle_version` của mọi node (không node nào bị kéo về bundle cũ; bản deploy kế tiếp mang cấu hình đã khôi phục); rollout RUNNING/PAUSED thành ABORTED, replay RUNNING thành FAILED, xóa lease; in danh sách node enroll sau thời điểm backup (phải enroll lại). Số bundle kế tiếp luôn lớn hơn mọi bản ghi, mọi version node báo (`nodes.bundle_version`) và sàn. **Đóng gói (CP-A09):** `deploy/compact` (image control plane có UI, compiler, replay, gói rule core và `pg_dump` 17; compose 3 dịch vụ PostgreSQL 17.11, ClickHouse 25.8.33 cấu hình cho máy nhỏ, control plane; overlay Keycloak; `install.sh`, `backup.sh`, `restore.sh`); hướng dẫn trong `deploy/compact/README.md`. **OIDC (CP-A06):** token có `iat`/`nbf` quá 2 phút trong tương lai bị từ chối; mỗi tài khoản OIDC vai trò admin đăng nhập thành công được ghi (`oidc_admin_sign_ins`, migration 0029); tắt local auth (khi OIDC bật và đang có tài khoản local) chỉ được khi đã có lần ghi đó, nếu không control plane dừng lúc khởi động.
plane** (UI nhúng trong binary) cùng **PostgreSQL** và **ClickHouse** đi kèm. Artifact lưu trên
**filesystem**, ký bundle bằng **file Ed25519**, xác thực bằng **tài khoản cục bộ**. OIDC
(Keycloak hoặc IdP khác), S3/MinIO, Vault transit, PostgreSQL ngoài có HA và giám sát
(Grafana, VictoriaMetrics) là tùy chọn. Message bus không có: trạng thái Fleet (presence,
canary, bộ đếm theo policy) nằm trong RAM của control plane đang giữ lease, nên chỉ một bản nhận
ghi; chạy nhiều control plane cùng lúc cần làm lại phần này và nằm ngoài kế hoạch Compact.

*Hiện trạng (W11-G2-01, W11-R-01):* mẫu traffic theo `docs/spec/replay-sample.md` (Parquet, định dạng 1): control plane ẩn danh hóa (`control-plane/replay`: chỉ field nhạy cảm thành HMAC có khóa, quyết định PO 14/10/2026) và lưu vào object storage dưới `replay/v1/<policy>/...`; lõi replay là crate `engine/replay` (`strata-replay run`), đọc các file đó và chạy từng request qua bundle trên nhiều luồng, báo theo route: action bây giờ so với lúc lấy mẫu, số bị chặn mới (nghi FP) và không còn bị chặn (nghi FN). Định dạng **chưa được pháp chế duyệt**.

*Replay service (W13-G2-01):* control plane chạy với `-replay=<strata-replay>` (cần cấu hình deploy: signer, `-bundle-pubkey`, `-objects-dir` hoặc `-s3-*`). Mỗi version mới của policy tự có một operation REPLAY (bảng PostgreSQL `operations`, migration 0013); runner trong control plane lấy lần lượt từng operation (`FOR UPDATE SKIP LOCKED`, nhiều control plane chia nhau hàng đợi; operation RUNNING quá 2 lần `-replay-timeout` là của control plane đã dừng và bị đánh FAILED). Mỗi lần chạy: build bundle mà deploy sẽ tạo nếu version này được áp dụng (các policy khác giữ version deploy sẽ lấy), ký bằng một khóa Ed25519 riêng của tiến trình (không bao giờ là khóa ký bundle cho node, nên bundle nháp không thể lên node); so với bundle đang có hiệu lực (bundle mới nhất, kiểm chữ ký bằng `-bundle-pubkey`; chưa có thì build từ các policy hiện tại) bằng `strata-replay compare --policy <tên>`, hai lượt tách riêng: mẫu traffic của policy trong 7 ngày (`replay/v1/<policy>/…`, ngày mới trước, tối đa 200 file và 1 GiB) và corpus benign + tấn công (`-replay-corpus`, file do `strata-replay gen` tạo lúc build). Kết quả (FP/FN ứng viên, rule, đường dẫn, ví dụ đã ẩn danh) lưu cùng operation; ví dụ chỉ trả cho người có quyền `events:read_sensitive`. Tên policy (`[a-z0-9._-]{1,55}`) **không được chỉ gồm dấu chấm** (CP-SEC-02, `policy.ValidName`): tên nằm trong khóa object `replay/v1/<policy>/…`, và `.` hay `..` sẽ thoát khỏi thư mục khi lưu trên filesystem; control plane từ chối khi tạo policy và khi ghi mẫu.
| ClickHouse | Sự kiện, tra theo Block ID, thống kê dashboard | Hoặc OpenSearch nếu tái sử dụng hạ tầng sẵn có |

**Ký bundle và cost unit (W07-G2-01)**: `strata-compile --unsigned` ghi phần cần ký (bundle trừ 64 byte cuối) và không đọc khóa; control plane gửi phần đó tới Vault transit (`-bundle-signer=vault`, khóa `ed25519` với `exportable=false`, `allow_plaintext_backup=false`, phiên bản khóa ghim lúc khởi động; token chỉ có quyền `transit/sign/<key>` và đọc `transit/keys/<key>`), gắn chữ ký vào cuối, kiểm lại bằng public key lấy từ Vault rồi mới lưu. Vault giới hạn request 32 MiB nên bundle tối đa 24 MiB. Chế độ `-bundle-signer=file` (seed Ed25519 trong file) chỉ cho lab cũ và phát triển. `--cost-report` cho cost unit từng rule: 1 + Σ điều kiện Σ target trọng số target × (1 + số transformation) × trọng số operator (× 2 nếu `multi_match`). Trọng số target: collection không chọn key (args, header, cookie, files, xml, matched_vars, response headers) 4, body request/response 8, còn lại (kể cả có key hoặc đếm) 1. Trọng số operator: `detect_sqli`/`detect_xss`/`detect_ssti`/`detect_cmdi` 10, regex chạy ngoài Hyperscan 25, `validate_*` và `ip_match` 2, còn lại 1. Bundle vượt `-cost-budget` (mặc định 50.000; CRS 4.25 PL1 nhập vào khoảng 14.900) bị từ chối với 400, kèm 3 rule tốn nhất.

**Mục tiêu vận hành**: 5.000 node mỗi cụm control plane; thông báo bundle tới toàn bộ node trong dưới 10 giây; control plane sập không ảnh hưởng traffic vì node chạy tiếp với bundle đã có.

## Giao thức gRPC agent ↔ control plane

`strata-agent` giữ một stream gRPC hai chiều dài hạn với control plane qua mTLS: control plane đẩy thông báo bundle và lệnh xuống, agent đẩy trạng thái lên; bundle tải qua RPC riêng theo chunk, sự kiện gửi qua client stream có xác nhận.

**Định nghĩa service (`strata/fleet/v1/fleet.proto`)**

```protobuf
syntax = "proto3";
package strata.fleet.v1;

service FleetService {
  // Lần đầu: đổi enrollment token lấy chứng chỉ client
  rpc Enroll(EnrollRequest) returns (EnrollResponse);
  rpc RenewCertificate(RenewRequest) returns (RenewResponse);

  // Kênh điều khiển dài hạn, hai chiều
  rpc Connect(stream AgentMessage) returns (stream ControlMessage);

  // Tải bundle theo chunk, tiếp tục được từ offset
  rpc FetchBundle(FetchBundleRequest) returns (stream BundleChunk);

  // Gửi sự kiện theo lô, control plane xác nhận theo seq
  rpc PushEvents(stream EventBatch) returns (stream EventAck);
}

message EnrollRequest {
  string token = 1;            // enrollment token dùng một lần
  bytes  csr = 2;              // CSR do agent tự sinh khóa
  NodeInfo node = 3;
}
message EnrollResponse {
  string node_id = 1;
  bytes  certificate = 2;      // hạn 24 giờ, tự gia hạn
  bytes  ca_bundle = 3;
  bytes  bundle_pubkey = 4;    // khóa công khai kiểm chữ ký bundle
}

message NodeInfo {
  string hostname = 1;
  string agent_version = 2;
  Connector connector = 3;
  map<string, string> labels = 4;
}
message Connector {
  string type = 1;             // nginx | apache | haproxy | envoy | kong
  string proxy_version = 2;    // ví dụ 1.28.x
  string module_version = 3;
  uint32 abi_version = 4;
}

message AgentMessage {
  oneof msg {
    Hello      hello = 1;      // gửi đầu tiên khi mở stream
    Heartbeat  heartbeat = 2;  // mỗi 15 giây
    BundleStatus bundle_status = 3;
    CommandResult command_result = 4;
  }
}
message Hello {
  NodeInfo node = 1;
  uint64 active_bundle_version = 2;
}
message Heartbeat {
  uint64 active_bundle_version = 1;
  repeated WorkerState workers = 2;  // phiên bản engine từng worker
  NodeCounters counters = 3;          // request, block, fail mode, dropped events
}
message BundleStatus {
  uint64 version = 1;
  enum State {               // buf lint: 0 là UNSPECIFIED, tên có tiền tố
    STATE_UNSPECIFIED = 0; STATE_DOWNLOADING = 1; STATE_VERIFIED = 2;
    STATE_ACTIVE = 3; STATE_FAILED = 4;
  }
  State  state = 2;
  string error = 3;
}

message ControlMessage {
  oneof msg {
    BundleAvailable bundle_available = 1;
    Command command = 2;
  }
}
message BundleAvailable {
  uint64 version = 1;
  bytes  sha256 = 2;
  uint64 size_bytes = 3;
  bool   rollback = 4;         // cho phép phiên bản thấp hơn bản đang chạy
}
message Command {
  string id = 1;
  oneof action {
    ForceShadow force_shadow = 2;   // ép shadow khẩn cấp cho policy/route
    CollectDiagnostics diagnostics = 3;
  }
}

message FetchBundleRequest { uint64 version = 1; uint64 offset = 2; }
message BundleChunk { uint64 offset = 1; bytes data = 2; }  // chunk 1 MB

message EventBatch {
  uint64 seq = 1;              // tăng dần theo node, dùng chống trùng
  repeated Event events = 2;
}
message EventAck { uint64 acked_seq = 1; }
```

`Event` dùng chung định dạng với event socket trong module (Block ID, thời gian, policy, phiên bản bundle, IP, identity, route, action, điểm từng lớp, rule ID, đoạn input đã che).

**Đăng ký node (enrollment)**

1. Admin tạo enrollment token trên UI, gắn với một connector group, dùng một lần, hết hạn sau 24 giờ.
2. Chạy `strata-agent enroll --server cp.example.vn:8443 --tls-ca ca.pem --token-file <file>` (hoặc `--token`, `STRATA_ENROLL_TOKEN`); agent tự sinh khóa P-256 riêng (file 0600, không rời node), gửi CSR. `--dry-run` chỉ sinh khóa và CSR. Bản đầy đủ của message phụ (`WorkerState`, `NodeCounters`, `CommandResult`, `ForceShadow`, `RenewRequest`) nằm trong `proto/strata/fleet/v1/fleet.proto`.
3. Control plane kiểm token, cấp chứng chỉ client có định danh node (`spiffe://strata/node/<node_id>`), hạn 24 giờ; agent tự gia hạn khi còn 1/3 thời hạn.
4. Thu hồi node trên UI: chứng chỉ bị đưa vào danh sách thu hồi, stream bị cắt ngay.

**Phân phối bundle**

1. Policy được duyệt và deploy → compiler tạo bundle, ký, lưu vào object storage.
2. Control plane gửi `BundleAvailable` tới các node thuộc connector group, theo đợt (ví dụ 1 node → 10% → 100%) nếu policy cấu hình rollout theo node.
3. Agent gọi `FetchBundle`, kiểm `sha256` và chữ ký, ghi file nguyên tử, báo `VERIFIED`.
4. Worker nạp xong, agent thấy qua event socket và báo `ACTIVE`; lỗi thì báo `FAILED` kèm lý do, control plane dừng đợt rollout. *Hiện trạng (W05-G1-01):* agent đọc phiên bản bundle của từng worker trong file metrics (`docs/design/control-file.md`); module chỉ ghi file đó từ W07-N-01, nên khi chưa có file agent báo `ACTIVE` sau 2 giây kể từ lúc cập nhật control file (worker đọc control file mỗi giây).
5. Node enroll sau một lần deploy nhận ngay bundle của **rollout gần nhất đã xong** (`DONE`) ở `Hello` đầu tiên; rollout đang chạy, tạm dừng, lỗi hoặc đã hủy thì không được giao cho node mới (W10-N-01: trước đó node mới không có bundle cho tới lần deploy sau).

**Độ tin cậy**

| Tình huống | Hành vi |
| --- | --- |
| Mất kết nối | Thử lại với backoff lũy thừa 1 s → 60 s có jitter; khi nối lại, `Hello` mang phiên bản đang chạy, control plane gửi lại phiên bản mong muốn |
| Tải bundle đứt giữa chừng | Gọi lại `FetchBundle` với `offset` đã nhận |
| Gửi sự kiện thất bại | Agent spool ra đĩa (giới hạn cấu hình được, mặc định 2 GB), gửi lại theo `seq`; control plane bỏ lô trùng seq |
| Spool đầy | Bỏ sự kiện cũ nhất, tăng counter, báo trong heartbeat |
| Control plane quá tải | Trả `RESOURCE_EXHAUSTED`; agent giảm tốc gửi sự kiện, request NGINX không bị ảnh hưởng |

**Bảo mật kênh**: TLS 1.3, mTLS bắt buộc, agent chỉ tin CA trong `ca_bundle`; node chỉ được tải bundle của connector group mình thuộc về; control plane giới hạn tốc độ theo node và kiểm schema mọi sự kiện nhận được.

## API quản trị (REST + gRPC)

Mọi thao tác trên Web UI đều đi qua cùng một API: định nghĩa một lần bằng protobuf (`strata.admin.v1`), phục vụ song song dạng gRPC và REST/JSON (qua grpc-gateway), sinh tài liệu OpenAPI và SDK Go/TypeScript từ cùng nguồn.

**Tài nguyên và endpoint chính**

| Tài nguyên | REST | Thao tác đặc biệt |
| --- | --- | --- |
| Policy | `GET/POST /v1/policies`, `GET/PATCH /v1/policies/{id}` | `:replay`, `:submit`, `:approve`, `:deploy`, `:rollback`. Replay (W13-G2-01): mỗi version mới tự xếp hàng một replay (`replay_operation` trong kết quả tạo/sửa); `POST /v1/policies/{id}:replay` (`version`, 0 = mới nhất; quyền `policies:write`) xếp thêm; `GET /v1/policies/{id}/versions/{v}/replay` trả replay mới nhất của version (`policies:read`). Duyệt 4 mắt (W13-G2-02): mỗi lần sửa là một version DRAFT; `POST …:submit` (`version`, 0 = mới nhất; `policies:write`) → SUBMITTED; `POST …:approve` (`version` bắt buộc, `comment` và `expected_replay_id` tùy chọn; UI gửi ID report DONE đã xem, ID cũ/sai version bị từ chối; backend kiểm lại replay mới nhất trong transaction giữ khóa version, việc xếp replay dùng cùng khóa; caller cũ bỏ ID vẫn tương thích) hoặc `POST …:reject` (`comment` bắt buộc), quyền `policies:approve`, người soạn hoặc gửi version không duyệt được (so theo `sub` của token, không theo tên hiển thị; DB cũng chặn bằng CHECK); khi control plane có replay (`-replay`), `:approve` chỉ nhận version có replay mới nhất DONE (quyết định PO 16/10/2026; replay chưa xong hoặc FAILED → FAILED_PRECONDITION, chạy lại bằng `:replay`), `:reject` không phải chờ → APPROVED / REJECTED; bundle lấy version → DEPLOYED. `:deploy` build **bản APPROVED/DEPLOYED mới nhất của mỗi policy** (bản nháp chưa duyệt không bao giờ lên node; policy chưa có bản duyệt nào không vào bundle) và bị từ chối (FAILED_PRECONDITION) khi bản mới nhất của chính policy đó chưa duyệt (quyết định PO 15/10/2026). Version có trước migration 0014 coi là DEPLOYED. **Chốt replay lúc deploy (M5, sửa ở CP-FIX-01, quyết định PO 20/10/2026): chỉ kiểm cái thay đổi.** Bundle ghi `rules_digest` (chỉ compiler và file rule, không gồm spec policy, staged rule hay khóa định danh; migration 0025). Policy đã có trong bundle đang chạy ở đúng version, với cùng `rules_digest`, được bỏ qua. Policy khác phải có replay gắn lúc duyệt, chạy với cùng `rules_digest`, so với một bundle mà policy đó đang ở version hiện có hiệu lực (bundle mới hơn do policy khác deploy không làm replay lỗi thời). Khi `rules_digest` đổi, hoặc bundle đang chạy có từ trước khi có digest này, mọi policy phải được lưu lại thành version mới, replay và duyệt. Replay cũ chỉ có digest toàn phần vẫn được nhận nếu khớp đúng như trước. Policy trả thêm `approved_version`, `deployed_version`; hàng chờ duyệt: `GET /v1/policies/-/versions?state=SUBMITTED` |
| Phiên bản policy | `GET /v1/policies/{id}/versions`, `GET …/versions/{v}` | `:diff?from=&to=` |
| Rule, signature | `GET /v1/rules`, `GET /v1/rules/{rule_id}`, `POST /v1/rules` (rule riêng dải 800000) | `:stage`, `:enable`, `:disable` theo policy/route; tắt khẩn cấp theo connector group (W12-G2-02): `POST /v1/rules/{rule_id}:emergencyDisable` và `:enable` (`group_id`, `reason` 1..500 ký tự bắt buộc; quyền `rules:disable` cho `operator` trở lên; audit ghi người, lý do, group), `GET /v1/rules:disabled?group_id=`. Danh sách là trạng thái mong muốn của group: node kết nối lại nhận `DisableRules` thay thế toàn bộ |
| Exception | `GET/POST /v1/exceptions`, `DELETE /v1/exceptions/{id}` | `POST /v1/exceptions:fromBlockId` |
| API schema, gRPC descriptor | `POST /v1/schemas` (OpenAPI hoặc `FileDescriptorSet`) | `:validate` |
| Sự kiện | `GET /v1/events/{block_id}`, `POST /v1/events:search` | `:markFalsePositive` |
| Connector group, node | `GET /v1/groups`, `GET /v1/nodes`, `DELETE /v1/nodes/{id}` (thu hồi) | `POST /v1/groups/{id}/enrollmentTokens` |
| Lấy mẫu replay | `GET /v1/groups/{group_id}/replaySampling` (không bao giờ trả khóa) | `POST /v1/groups/{group_id}:setReplaySampling` (`rate_percent` 0..100, `rotate_key`; quyền `replay:configure`, chỉ `admin`; > 0 cần `-replay-sampling-approved`; W12-N-01) |
| Lệnh tới node | `GET /v1/commands?node_id=`, `GET /v1/commands/{id}` | `POST /v1/nodes:forceShadow` (`node_id` hoặc `group_id`, `policy_id` rỗng = mọi policy, `duration_seconds` 1..86400; quyền `policies:deploy`), `POST /v1/nodes:clearForceShadow` (kết thúc trước hạn: `policy_id`, hoặc mọi force shadow khi rỗng; cùng quyền), `POST /v1/nodes/{id}:collectDiagnostics` (quyền `nodes:write`) |
| Bundle, rollout | `GET /v1/bundles`, `GET /v1/rollouts/{id}` | `:pause`, `:resume`, `:abort` |
| Người dùng, vai trò | `GET/POST /v1/roleBindings` | — |
| Audit | `GET /v1/audit` | — |
| Thống kê | `GET /v1/stats/overview?from=&to=&policy_id=&step=` (trang Tổng quan, W10-F-01: theo giờ/6 giờ/ngày, top rule, top route, top IP chỉ cho vai trò xem được IP đầy đủ; cửa sổ tối đa 31 ngày) | — |

**Ví dụ: tra một Block ID**

```bash
# REST
curl -H "Authorization: Bearer $TOKEN" \
  https://strata-cp.example.vn/v1/events/STR-8F3K-Q2VD-7XNM-A1PC

# gRPC
grpcurl -H "authorization: Bearer $TOKEN" \
  -d '{"block_id":"STR-8F3K-Q2VD-7XNM-A1PC"}' \
  strata-cp.example.vn:443 strata.admin.v1.EventService/GetEvent

# CLI
strata trace STR-8F3K-Q2VD-7XNM-A1PC
```

Kết quả gồm decision trace đầy đủ: policy và phiên bản bundle, connector và node, điểm từng lớp, rule ID khớp, vị trí (field HTTP hoặc đường dẫn field protobuf), đoạn input đã che.

**Xác thực và phân quyền**

- Người dùng: OIDC (Keycloak, Azure AD…) hoặc LDAP qua OIDC bridge; token ngắn hạn.
- Tài khoản cục bộ (cờ `-local-auth`, W10; **bật mặc định từ CP-A05**, tự tắt khi không có PostgreSQL trừ khi bật tường minh): tên đăng nhập và mật khẩu argon2id trong PostgreSQL, cho cài đặt nhỏ không có IdP; dùng thay hoặc cùng OIDC. Token phiên `stl_…` (DB chỉ giữ SHA-256, hết hạn sau 8 giờ), khóa tài khoản sau 5 lần sai, giới hạn theo IP, mọi thay đổi vào audit. API: `POST /v1/auth/login`, `/v1/auth/logout`, `/v1/auth/password`, `GET /v1/auth/methods`, `GET /v1/auth/me`, `GET/POST/PATCH/DELETE /v1/users`.
- Khởi tạo và khôi phục (CP-A05): `strata-control-plane init -data-dir <dir> [-name <tên Fleet>] [-admin-password-file f]` chạy migration, tạo khi chưa có: CA và chứng chỉ Fleet, CA của node, khóa ký bundle (file Ed25519; DB đã có bundle mà mất khóa thì dừng, không sinh khóa mới), file secret (DSN, mật khẩu ClickHouse), `config.yaml`, admin đầu tiên (mật khẩu hỏi trên terminal không echo hoặc từ file, không bao giờ từ cờ). Khóa thư mục bằng `flock`, ghi file bằng `O_EXCL`; chạy lại không ghi đè gì. `strata-control-plane admin recover -user <tên>` (trên máy control plane, cần DSN): đặt mật khẩu mới, bật và mở khóa tài khoản, xóa mọi session, audit `system:recover (<user>@<host>)`. Admin cuối cùng không bị xóa hay hạ quyền (có từ W10).
- Tự động hóa: service account với token có phạm vi (`policies:read`, `policies:deploy`, `events:read`…), có hạn dùng, thu hồi được.
- Định danh (CP-SEC-01): subject của người gọi luôn có không gian tên riêng: `local:<tên>` (tài khoản cục bộ), `sa:<id>` (service account), `oidc:<sub>` (token OIDC; token không có `sub` bị từ chối). Bốn mắt, audit và khóa chống trùng request so theo subject này, nên một IdP cấp `sub` dạng `local:admin` không trùng được với tài khoản cục bộ. Migration 0026 chuyển subject OIDC đã lưu sang dạng mới; `audit_log` giữ nguyên như đã ghi.
- RBAC theo vai trò `viewer`, `operator`, `approver`, `admin`, giới hạn theo connector group; người tạo bản nháp không tự duyệt được bản của mình (quy tắc 4 mắt, luôn bật, kể cả lab và staging: script dùng `lab-approver` để duyệt).
- Agent không dùng API này; agent chỉ được gọi `FleetService` bằng chứng chỉ node.

**Quy ước API**

- Đặt tên tài nguyên và phương thức theo Google API Improvement Proposals (AIP): `List`, `Get`, `Create`, `Update`, phương thức tùy chỉnh dạng `:verb`.
- Cập nhật dùng `etag` để tránh ghi đè lẫn nhau giữa UI, API và GitOps; lệch `etag` trả `409` / `ABORTED`.
- Tạo mới hỗ trợ `request_id` (idempotency) để gọi lại an toàn.
- Phân trang bằng `page_token`; lọc theo cú pháp AIP-160.
- Thao tác lâu (replay, deploy) trả về long-running operation, theo dõi qua `GET /v1/operations/{id}` (`state` PENDING → RUNNING → DONE/FAILED, `done`, `error`, kết quả). Hiện có replay (W13-G2-01); deploy vẫn trả kết quả ngay.
- Version API trong đường dẫn (`v1`); thay đổi phá vỡ chỉ ở `v2`, `v1` được giữ tối thiểu 12 tháng.
- Mọi lời gọi ghi được lưu vào audit kèm người gọi, kênh (UI, API, GitOps), trước/sau.

## Giao diện quản trị

Web UI là nơi làm việc chính của SOC, SRE và helpdesk. UI chỉ gọi API quản trị, không có đường riêng vào database; mọi nút bấm đều tương ứng một lời gọi API có audit.

**Công nghệ**: React + TypeScript, Vite, TanStack Query (cache, tự làm mới), client sinh từ OpenAPI, bản đồ MapLibre GL JS, biểu đồ Apache ECharts, giao diện sáng/tối, tiếng Anh (mặc định) và tiếng Việt (i18n), đăng nhập SSO qua OIDC hoặc tài khoản cục bộ. UI build tĩnh và được API server phục vụ, nên chạy được trong mạng nội bộ không có internet.

**Màn hình**

| Màn hình | Nội dung chính | Vai trò dùng |
| --- | --- | --- |
| Tổng quan | Request, tỉ lệ chặn, top rule, top route, latency engine, node lỗi, rollout đang chạy | Tất cả |
| Bản đồ tấn công | Bản đồ GeoIP theo quốc gia / thành phố / ASN, cập nhật trực tiếp, drill-down tới sự kiện | SOC, SRE |
| Sự kiện | Ô tìm Block ID luôn ở thanh trên cùng; lọc theo thời gian, IP, quốc gia, ASN, route, rule ID, action | Helpdesk, SOC |
| Chi tiết sự kiện (decision trace) | Điểm từng lớp, rule khớp, vị trí (field HTTP / field protobuf), đoạn input đã che; nút Đánh dấu FP, Tạo exception, Chặn IP/ASN | Helpdesk, SOC |
| Policy | Danh sách policy theo site/route; editor dạng form + YAML song song; diff giữa version; chạy replay; gửi duyệt; deploy theo chế độ shadow / canary / enforce | Operator, approver |
| Hàng chờ duyệt | Bản nháp chờ duyệt kèm kết quả replay (FP/FN theo route) và diff | Approver |
| Rule & signature | Danh mục theo dải ID, tag, loại tấn công; trạng thái staging; bật/tắt theo policy | Operator |
| Exception | Danh sách theo hạn dùng, số request đã khớp, người tạo; cảnh báo exception sắp hết hạn | Operator |
| Schema | Tải OpenAPI / gRPC descriptor, xem endpoint và method đã khai báo | Operator |
| Fleet | Connector group, node, phiên bản proxy/module/bundle, trạng thái kết nối, rollout theo đợt (tạm dừng / hủy); tạo enrollment token | SRE |
| Người dùng & quyền | Role binding theo connector group, service account | Admin |
| Audit | Ai đổi gì, lúc nào, qua kênh nào, trước/sau | Admin, kiểm toán |

**Luồng chính cần tối ưu**

1. **Helpdesk tra Block ID**: dán Block ID ở bất kỳ trang nào → mở chi tiết sự kiện trong dưới 5 giây.
2. **Xử lý false positive**: từ chi tiết sự kiện → Tạo exception (form điền sẵn phạm vi hẹp nhất) → replay tự chạy → gửi duyệt; tối đa 3 lần bấm trước bước duyệt.
3. **Phản ứng sự cố từ bản đồ**: thấy một quốc gia hoặc ASN tăng đột biến → bấm vào vùng → xem sự kiện → tạo rule chặn geo/ASN dạng bản nháp, có thể duyệt nhanh khi khẩn cấp.
4. **Rollout policy**: deploy → theo dõi trên Fleet từng node chuyển `VERIFIED` → `ACTIVE`, tỉ lệ chặn theo đợt; tự dừng nếu lỗi.

**Nguyên tắc giao diện**: UI ẩn nút theo quyền của người dùng nhưng API vẫn kiểm quyền lần nữa; không hiển thị IP đầy đủ và đoạn input cho vai trò `viewer`; mọi bảng xuất được CSV; các trang dashboard tự làm mới, có nút tạm dừng khi đang điều tra.

## Bản đồ GeoIP

Màn hình Bản đồ tấn công hiển thị sự kiện theo quốc gia, thành phố hoặc ASN, cập nhật trực tiếp và cho drill-down tới từng Block ID. Vị trí được gắn ở Event ingest (không phải trong worker NGINX), bản đồ nền tự host nên chạy được trong mạng không có internet.

&#91;embedded content: phác thảo màn hình Bản đồ tấn công\]

Bộ lọc trên cùng và cú bấm trên bản đồ áp dụng cho cả trang: bấm một quốc gia thì xếp hạng ASN, dòng thời gian và bảng sự kiện cùng thu hẹp về quốc gia đó.

**Nguồn dữ liệu GeoIP**

| Nguồn | Nội dung | Ghi chú |
| --- | --- | --- |
| MaxMind GeoIP2 City + ASN | Quốc gia, vùng, thành phố, tọa độ gần đúng kèm bán kính sai số, ASN | Bản trả phí, chính xác hơn; có thêm cơ sở dữ liệu IP ẩn danh (VPN, proxy) nếu mua |
| MaxMind GeoLite2 | Tương tự, độ chính xác thấp hơn | Miễn phí, cần tài khoản, license key và tuân thủ EULA |
| DB-IP Lite | Quốc gia, thành phố, ASN | Giấy phép CC BY 4.0, phải ghi nguồn trên UI |

Control plane tải cơ sở dữ liệu `.mmdb` theo lịch (mặc định hằng tuần), lưu phiên bản trong object storage. Khi có rule chặn theo geo/ASN, compiler lấy từ cơ sở dữ liệu này đúng các dải IP của quốc gia và ASN mà rule nhắc tới, đóng vào bundle (section `GEO`) để engine tra ngay tại node; không đóng nguyên `.mmdb` (PO duyệt 21/10/2026: bundle nhỏ, không vượt giới hạn ký của Vault). Chi tiết: `docs/design/control-file.md`, W19-R-01.

**Pipeline**

1. Event ingest nhận sự kiện, tra IP trong `.mmdb` đã nạp sẵn trong bộ nhớ, gắn: `country_iso`, `region`, `city`, `lat`, `lon`, `accuracy_km`, `asn`, `as_org`, phiên bản GeoIP.
2. Ghi vào ClickHouse bảng `events`; materialized view tổng hợp theo phút theo (site, policy, action, loại tấn công, quốc gia, ASN) và theo 5 phút theo ô lưới địa lý (geohash độ chính xác 4, khoảng 20–40 km) cho lớp thành phố.
3. Thời gian lưu: sự kiện gốc 90 ngày, bảng tổng hợp 13 tháng (cấu hình được).

*Hiện trạng (W17-G2-01):* bảng `events_geo_minute_v1` và `events_geo_grid_v1` (AggregatingMergeTree) do materialized view của bảng `events` ghi, theo phút (policy, action, loại tấn công, quốc gia, ASN) và theo 5 phút (geohash 4, policy, action, loại tấn công, quốc gia). Bảng `events` có thể giữ một sự kiện hai lần tới khi merge (batch gửi lại sau timeout hoặc crash), nên view lưu `uniqCombined64(block_id)` chứ không `count()`: chính xác với tập nhỏ, sai số khoảng 1% khi cộng dồn tập lớn; số chính xác vẫn lấy từ bảng `events`. Loại tấn công suy từ Rule ID đã khớp (`ingest.AttackTypeSQL`), vì engine chấm điểm theo layer, không theo loại tấn công. Chưa có "site": sự kiện chưa mang connector group. Metadata vị trí không có phiên bản GeoIP (dữ liệu cũ chưa xác minh) không vào bảng tổng hợp. `-geo-aggregates-months` (mặc định 13) đặt TTL; lần khởi động đầu, control plane backfill từ sự kiện đã lưu (chạy lại an toàn).

**API cho bản đồ** (thuộc `strata.admin.v1.StatsService`)

| Endpoint | Mục đích |
| --- | --- |
| `GET /v1/stats/geo?from=&to=&groupBy=country\|city\|asn&filter=` | Số liệu tổng hợp cho lớp bản đồ và xếp hạng |
| `GET /v1/stats/timeline?from=&to=&step=&filter=` | Dòng thời gian chồng theo action |
| `GET /v1/stats/geo:watch` (SSE) ↔ `rpc WatchGeo` (gRPC server stream) | Cập nhật trực tiếp mỗi 2–5 giây dạng phần thay đổi; trình duyệt dùng SSE nên không cần gRPC-Web |

*Hiện trạng (W20-G2-01):* Tổng quan và các bảng xếp hạng/dòng thời gian của bản đồ từ 6 giờ trở lên đọc bảng tổng hợp theo giờ (`stats_*_hour_v1`, migration ClickHouse 5): job mỗi 30 giây tính lại từ `events FINAL` các giờ vừa có sự kiện (theo `received_at`), nên mỗi sự kiện chỉ đếm một lần kể cả khi batch gửi lại; số sự kiện chính xác, client khác nhau là ước lượng, cửa sổ làm tròn theo giờ, trễ tối đa một chu kỳ (`approximate: true`). 20 triệu sự kiện: Tổng quan 24 giờ 0,41 giây, 30 ngày 0,87 giây ([báo cáo](../reports/w20-g2-01.md)).

*Hiện trạng (W19-F-01):* `POST /v1/events:search` nhận thêm `country`, `asn`, `attack_type`, đếm như bảng tổng hợp (chỉ vị trí đã xác minh; loại tấn công suy từ rule đã khớp); trang Bản đồ có bảng sự kiện cùng khoảng thời gian và bộ lọc với các bảng xếp hạng, bấm một dòng mở decision trace.

*Hiện trạng (W18-G2-01):* ba endpoint REST trong `control-plane/api` (như `/v1/stats/overview`), chưa có `StatsService`/`rpc WatchGeo` gRPC. Đọc bảng tổng hợp GeoIP, số là sự kiện khác nhau xấp xỉ (`approximate: true`). Bộ lọc chung: `policy_id`, `action`, `attack_type`, `country`, `asn`. `geo:watch`: cửa sổ trượt `window` (1m–168h, mặc định 1h), đọc lại mỗi `interval` (2–5 s), sự kiện `snapshot` rồi `delta` (dòng đổi + khóa bị bỏ), comment giữ kết nối mỗi 15 s; tối đa 15 phút mỗi stream và 32 stream mỗi control plane (503). Token chỉ qua header `Authorization` (main không nhận token trên query): trình duyệt đọc stream bằng `fetch`, không dùng `EventSource`. Đo trên ClickHouse: sự kiện mới tới stream sau ~2 s với `interval=2s`.

**Hiển thị**

- Bản đồ nền: MapLibre GL JS với vector tile tự host (một file PMTiles do API server phục vụ), không gọi dịch vụ bản đồ bên ngoài.
- **Ranh giới lãnh thổ**: bản đồ nền phải thể hiện đúng chủ quyền của Việt Nam đối với quần đảo Hoàng Sa và Trường Sa, và tuân thủ quy định hiển thị bản đồ của Việt Nam. Nguồn tile phải được kiểm tra ranh giới trước khi đưa vào bản phát hành.
- Lớp quốc gia: tô màu theo số request bị chặn (thang log). Lớp thành phố: vòng tròn theo ô lưới, kích thước theo số lượng, màu theo loại tấn công chính, tự gom cụm khi thu nhỏ. Lớp ASN: xếp hạng, bấm để tô các vị trí của ASN đó.
- Tùy chọn: đường cung từ nguồn tới site bị tấn công (địa điểm data center khai báo trong connector group).
- Hành động nhanh: chọn quốc gia hoặc ASN → Tạo rule chặn geo/ASN dạng bản nháp → replay → duyệt; xuất PNG/CSV.

**Độ chính xác và quyền riêng tư**

- Bản đồ chỉ hiển thị số liệu tổng hợp theo ô lưới, không đặt chấm tại tọa độ của từng IP; danh sách IP chỉ hiện khi drill-down và với vai trò từ `operator`.
- GeoIP sai với VPN, proxy, CDN và mạng di động: tooltip hiển thị bán kính sai số; IP thuộc dải ẩn danh được đánh dấu riêng nếu có cơ sở dữ liệu tương ứng.
- Node đứng sau CDN hoặc load balancer phải cấu hình `realip` đúng, nếu không bản đồ sẽ hiển thị vị trí của CDN.
- Mục tiêu hiệu năng: truy vấn 24 giờ dưới 1 giây, 30 ngày dưới 3 giây; độ trễ chế độ trực tiếp dưới 5 giây.

## Trang chặn, Block ID & sự kiện

Khi verdict là `block`, module tự gửi response chặn (không chuyển qua upstream), gắn Block ID vào body, header và biến log, rồi đẩy một sự kiện có cùng Block ID sang `strata-agent`.

**Response chặn**

- Mã trả về theo policy (mặc định 403; fail-closed dùng 503).
- Chọn dạng theo policy và header `Accept`: JSON cho API, HTML cho trình duyệt.
- Header luôn có: `X-Strata-Block-Id`, `Cache-Control: no-store`, `Content-Type` tương ứng; không có header lộ phiên bản.
- Body HTML lấy từ `strata_block_page`, đã nạp vào bộ nhớ lúc đọc cấu hình; chỉ thay các biến `{{block_id}}`, `{{time}}`, `{{support_contact}}`, không render dữ liệu từ request (tránh XSS phản xạ).
- Body JSON cố định: `{"error":"blocked","block_id":"STR-8F3K-Q2VD-7XNM-A1PC"}`.
- Nếu response đã bắt đầu gửi (chặn ở response body), module đóng kết nối và ghi sự kiện, vì không thể đổi status.

**Block ID**: do libstrata sinh, 80 bit = 42 bit thời gian (ms) + 10 bit lấy từ hash `strata_node_id` + 28 bit ngẫu nhiên, mã hóa Crockford base32 thành `STR-XXXX-XXXX-XXXX-XXXX`. Ở chế độ shadow, request đáng lẽ bị chặn có Event ID tiền tố `EVT-`. Nếu NGINX có `$request_id`, giá trị này được ghi kèm trong sự kiện để đối chiếu log.

**Sự kiện**

- Mỗi worker gửi sự kiện qua Unix datagram socket `strata_event_socket` ở chế độ non-blocking; socket đầy thì bỏ sự kiện và tăng counter `strata_events_dropped`, không bao giờ chặn worker.
- Nội dung: Block ID, thời gian, node, policy, phiên bản bundle, IP, identity, method, host, path, mã trả về, action, điểm từng lớp, rule ID, đoạn input đã normalize và che dữ liệu nhạy cảm (128 byte mỗi match mặc định, 2 hoặc 4 KB theo `max_snippet_size` của policy; P-01 §1b).
- Ngữ cảnh điều tra (RV-G2-01, P-01 §1): `user_agent` và `referer` (tối đa 512 byte, giá trị query nhạy cảm của Referer thành `[MASKED]`), các header khác (tối đa 32 header, 2 KB): header nhạy cảm (`Authorization`, `Cookie`, `X-Api-Key`…, cùng danh sách tên với snippet) chỉ giữ tên, giá trị thành `[MASKED]`; giá trị khác được che như snippet. Có header khi request đã có Event ID ở stage header, hoặc khi bundle có rule ở stage body (header vốn được giữ cho rule); sự kiện chỉ có ở stage response với bundle không có rule body thì không có header. `inspection` (RV-N-01): `FULL`, `PARTIAL` (hết budget CPU), `BODY_SKIPPED` (body không được kiểm hết). `would_block` (#57): request bị chặn, hoặc lẽ ra bị chặn khi ở shadow; false với finding dưới ngưỡng và lỗi engine. `rule_costs` (23, W13-R-02): chỉ có ở sự kiện của request được lấy mẫu đo chi phí (mặc định 1%); tối đa 8 rule tốn thời gian nhất của request đó, mỗi mục là `RuleCost {rule_id, samples, total_ns, max_ns}`; `rule_id` 0 là lượt scan Hyperscan của prefilter, phần mọi rule dùng chung, không chia được theo rule.
- Che luôn bật, không tắt được: CCCD, JWT, số thẻ thanh toán (13–19 chữ số, Luhn, chữ số đầu 2–6) trong snippet, giá trị header, User-Agent, Referer. Datagram vượt 8 KB thì bỏ header trước, rồi cắt snippet dài về 128 byte, rồi mới bỏ match.
- `strata-agent` gom theo lô, gửi tới event store; ghi tạm ra đĩa khi mất kết nối.
- Access log NGINX vẫn là nguồn dự phòng nhờ các biến `$strata_*`.
- **Các loại datagram trên event socket**: datagram là protobuf `Event`, trừ khi mở đầu bằng 4 byte có `0xff` (protobuf không bao giờ bắt đầu bằng byte này): `\xffSR1` + `ReplaySample` (W12-N-01, mẫu replay) và `\xffSC1` + `PolicyCounters` (RV-N-01, bộ đếm theo policy). Cả hai do libstrata tạo và trả qua `strata_tx_sample`, module chỉ gửi bytes, không biết định dạng. Agent không biết loại nào thì tăng bộ đếm `invalid` (`strata_agent_events_invalid_total`), không log từng datagram.
- **Request theo policy (RV-N-01)**: sự kiện chỉ có khi request có finding hoặc fail mode, nên không cho được mẫu số của tỉ lệ request không được kiểm đủ. libstrata giữ bộ đếm theo policy trong mỗi engine (`engine/src/counters.rs`): số request, và trong đó số không được kiểm đủ theo lý do (`partial`: hết budget CPU, `body_skipped`: body không được kiểm hết, `error`: lỗi engine khác; đều là fail mode quyết định), cộng số chạy giảm cấp do breaker. Mỗi transaction đếm một lần khi được giải phóng. Khoảng mỗi giây, nếu transaction không có mẫu replay và buffer của connector đủ 8 KB, `strata_tx_sample` trả datagram `\xffSC1` với các policy có request từ lần trước (policy rỗng: tên `strata_policy` bundle không có). Không thêm dòng C nào (lúc làm, giới hạn còn 3.000 dòng và đã dùng 2.999; PO nâng lên 4.000 sau đó cùng ngày). Mỗi worker gửi phần của mình; bộ đếm của engine cũ chưa kịp gửi khi đổi bundle bị mất (tối đa khoảng 1 giây). Agent cộng dồn từ lúc khởi động (`strata_policy_requests_total`, `strata_policy_not_inspected_total{reason}`, `strata_policy_degraded_total`) và gửi trong heartbeat (`NodeCounters.policies`, `agent_started_ms`); control plane lấy hiệu giữa hai heartbeat, ghi bảng ClickHouse `policy_requests` theo lô 10 giây; trang Tổng quan hiện số request và tỉ lệ không kiểm đủ theo policy (theo route chỉ có số tuyệt đối từ sự kiện). **Thứ tự nâng cấp: agent trước module**, vì agent cũ đếm datagram `\xffSC1` là invalid.
- **Chi phí từng rule (W13-R-02)**: libstrata lấy mẫu 1 transaction trên 100 (bộ đếm theo thread, không khóa, không I/O; `engine/src/rulecost.rs`). Transaction được lấy mẫu đo lượt scan của prefilter và thời gian đánh giá từng rule nó đi qua (gồm regex ngoài Hyperscan, libinjection), cộng vào mảng atomic theo rule của engine. Datagram `\xffSC1` mỗi giây mang thêm `rule_costs` (tối đa 64 rule, tốn nhất trước; phần còn lại gửi lần sau), `sampled_requests` và `sampled_engine_ns` (`PolicyCounters` 5–7). Sự kiện của request được lấy mẫu có `rule_costs` (23). Agent cộng dồn và xuất `strata_rule_cost_seconds_total{rule}`, `strata_rule_cost_samples_total{rule}`, `strata_rule_cost_max_seconds{rule}`, `strata_rule_cost_sampled_requests_total`, `strata_rule_cost_sampled_engine_seconds_total`. Nhãn `rule`: `prefilter` (scan chung), 50 Rule ID đầu tiên agent gặp (tốn nhất trước, giữ nhãn đến khi agent khởi động lại để bộ đếm không giảm), còn lại là `other`. Chi phí đo (`strata-bench --rule-cost-ab`, gói đầy đủ): ở 1% nằm trong nhiễu đo (−0,2% đến +0,6%); kể cả đo mọi request cũng dưới 2% (+1,3% đến +1,6% với request nhỏ). Phần Hyperscan chia theo pattern thì đo offline bằng `strata-pattern-cost` (#28). Không thêm dòng C. Agent cũ bỏ qua field mới; module không đổi.

**Giao diện gửi sự kiện (event sink)**: phần còn lại của module chỉ gọi một interface `strata_event_sink_t` gồm `init(worker_id)`, `send(buf, len)` không bao giờ chặn (trả `OK` hoặc `DROPPED`), và `close()`. Nhờ vậy, đổi cách vận chuyển không ảnh hưởng code ở phase handler hay filter.

| Bản cài đặt | Cách hoạt động | Khi nào dùng |
| --- | --- | --- |
| Unix datagram socket (v1) | Protobuf, mỗi datagram tối đa 8 KB, `sendto()` non-blocking | Mặc định trong v1 |
| Ring buffer shared memory (ứng viên) | Mỗi worker một ring SPSC trong file `/dev/shm/strata/events-<số worker>.ring` (agent không attach được vào shared memory zone của NGINX vì zone được tạo bằng anonymous mmap); record có độ dài và CRC; ring đầy thì bỏ sự kiện và tăng counter; agent coi nội dung ring là dữ liệu không tin cậy và kiểm từng record | Đưa vào v1 nếu benchmark tuần 8–9 cho thấy drop sự kiện vượt 0,1% hoặc `sendto()` chiếm hơn 5% CPU worker ở mức khoảng 50.000 sự kiện/giây mỗi node; nếu không thì để v1.1 |

**Metrics**: module ghi bộ đếm vào shared memory zone; `strata-agent` đọc và xuất định dạng Prometheus: số request theo action, thời gian engine (histogram), byte body đã inspect, số lần fail mode, phiên bản bundle, số sự kiện bị bỏ.

## Hiệu năng, tài nguyên & fail mode

Engine chạy đồng bộ trong event loop của worker, nên mọi lời gọi phải có thời gian chặn trên; khi vượt, module xử lý theo fail mode thay vì để worker bị treo.

**Nguyên tắc hiệu năng**

- Không I/O, không khóa, không cấp phát lớn trong đường đi của request; mọi I/O (bundle, control file, sự kiện) nằm ngoài luồng request hoặc trong thread pool.
- Header được truyền thành một mảng trong một lời gọi FFI, không gọi từng header.
- Body truyền theo buffer NGINX sẵn có, không copy thêm ở phía C.
- **CPU budget là cơ chế hợp tác, có chặn trên**: không thể ngắt một lời gọi FFI từ bên ngoài, nên libstrata tự kiểm tra đồng hồ tại các điểm cố định:
  - Hyperscan quét theo khối (mặc định 8 KB, dùng chế độ streaming của Hyperscan), kiểm đồng hồ giữa các khối; callback khi có match có thể trả giá trị khác 0 để dừng sớm.
  - Parser JSON, XML, protobuf, multipart viết dạng vòng lặp (không đệ quy), kiểm đồng hồ sau mỗi N token, có giới hạn độ sâu và số phần tử.
  - Đồng hồ đọc bằng `CLOCK_MONOTONIC_COARSE` để chi phí kiểm tra không đáng kể.

  Nhờ vậy, phần vượt budget tối đa chỉ bằng thời gian xử lý một khối (cỡ vài chục micro giây), không phải toàn bộ request.
- **Không có ReDoS từ regex**: Hyperscan và crate `regex` của Rust đều dùng automata, thời gian tuyến tính, không backtracking và không hỗ trợ backreference. Compiler từ chối rule cần tính năng không tuyến tính; rule CRS dùng backreference hoặc lookaround được viết lại hoặc chuyển thành detector riêng.
- **Theo dõi tấn công làm chậm**: nhiều request liên tiếp chạm budget là dấu hiệu tấn công; metric `strata_budget_exceeded` được agent cảnh báo, và policy có thể xử lý các request đó theo fail mode.
- Ngắt sớm: điểm đã vượt ngưỡng chặn thì bỏ qua các lớp còn lại.
- Phase 2: request body lớn (trên 256 KB) có thể chuyển sang thread pool để không chiếm event loop.

**Ngân sách mục tiêu**

| Chỉ số | Mục tiêu |
| --- | --- |
| Overhead p50 / p99, request dưới 64 KB | dưới 0,2 ms / dưới 1 ms |
| Giảm throughput, request nhỏ keep-alive | không quá 10% |
| RAM engine dùng chung (mmap) | bằng kích thước bundle, tính một lần cho cả máy |
| RAM riêng mỗi worker | dưới 8 MB (chưa tính Hyperscan nếu PoC buộc tách riêng) |
| Bộ nhớ mỗi transaction | dưới 16 KB + phần body đang giữ |
| Phần vượt CPU budget tối đa | dưới 100 µs |
| Thời gian nạp bundle (thread pool) | dưới 500 ms |

**Fail mode**

| Sự cố | `open` | `closed` |
| --- | --- | --- |
| Chưa có bundle, bundle không nạp được | Cho qua, ghi metric | Trả 503 kèm Event ID |
| Engine trả lỗi hoặc panic | Cho qua, ghi sự kiện lỗi | Trả 503 kèm Event ID |
| Vượt `strata_cpu_budget` | Cho qua, ghi sự kiện | Trả 503 kèm Event ID |
| Body vượt giới hạn inspect | Theo policy (`pass` hoặc `block`) | Theo policy |
| Event socket đầy hoặc agent chết | Không ảnh hưởng request, tăng counter | Không ảnh hưởng request, tăng counter |

Khuyến nghị: `open` cho site công khai lưu lượng lớn, `closed` cho API nhạy cảm như eKYC.

## Circuit breaker cấp worker

Mỗi worker tự theo dõi sức khỏe engine của mình; khi lỗi nội bộ vượt ngưỡng, worker chuyển sang chế độ giảm cấp (không bypass hoàn toàn) rồi tự thử lại. Breaker hoạt động trong worker, không cần agent hay control plane.

**Chỉ tính lỗi nội bộ**: panic (`STRATA_E_INTERNAL`), lỗi nạp hoặc kiểm bundle, lỗi FFI bất thường. **Không tính** `STRATA_E_BUDGET`: nếu tính, kẻ tấn công chỉ cần gửi đủ nhiều request nặng để tự mở breaker rồi tấn công trong lúc WAF bị giảm cấp. Request vượt budget vẫn xử lý riêng theo fail mode và được cộng điểm nghi vấn.

| Trạng thái | Hành vi | Chuyển tiếp |
| --- | --- | --- |
| Closed | Engine đầy đủ | Sang Open khi lỗi nội bộ vượt 2% trong cửa sổ 10 giây, với tối thiểu 200 request trong cửa sổ |
| Open | Chế độ giảm cấp (xem dưới) trong 30 giây; mở lại liên tiếp thì thời gian nhân đôi, tối đa 5 phút | Hết thời gian thì sang Half-open |
| Half-open | 5% request đi qua engine đầy đủ, phần còn lại vẫn giảm cấp | Trong 10 giây, lỗi dưới 0,5% thì về Closed; ngược lại quay lại Open |

**Chế độ giảm cấp**: vẫn chạy lớp protocol (chặn request mơ hồ), IP allow/deny list và rate limit. Các lớp này nằm trong một module tối thiểu của libstrata, tách khỏi engine đầy đủ và có `catch_unwind` riêng; nếu chính module này lỗi thì xử lý theo `strata_fail_mode`.

| Location | Khi breaker mở |
| --- | --- |
| `strata_fail_mode open` | Giảm cấp, request qua các kiểm tra tối thiểu thì đi tiếp |
| `strata_fail_mode closed` (ví dụ eKYC) | Mặc định giảm cấp; đặt `strata_breaker_action reject` nếu muốn trả 503 thay vì chạy giảm cấp |

Mỗi lần chuyển trạng thái phát một sự kiện và tăng metric `strata_breaker_state`; agent cảnh báo ngay, và cảnh báo mức nghiêm trọng nếu nhiều worker trên cùng node cùng mở. Directive: `strata_breaker on | off` (mặc định `on`), `strata_breaker_threshold 2% 10s 200`, `strata_breaker_action degrade | reject` (mặc định `degrade`).

*Hiện trạng (W11-N-01):* breaker nằm trong `ngx_http_strata_breaker.c`, trạng thái riêng từng worker (biến tĩnh, không khóa). Chế độ giảm cấp là cờ `STRATA_TXF_DEGRADED` của `strata_conn_t` (ABI 1.2, chỉ thêm): libstrata chỉ chạy lớp protocol và rule toàn điều kiện `ip_match`, trong cùng `catch_unwind` của từng lời gọi FFI. Chưa có rate limit (RV-R-03). Khác thiết kế: (1) `strata_breaker` và `strata_breaker_threshold` chỉ ở mức `http`, vì breaker là của worker, không của location; (2) `strata_breaker_threshold` nhận thêm `open=<time>` (mặc định 30 s) cho test và vận hành; (3) cửa sổ đếm lỗi là cửa sổ cố định (tumbling), không trượt; half-open lấy 1/20 request, kết thúc sau một cửa sổ; (4) lỗi được tính: `STRATA_E_INTERNAL`, `STRATA_E_INVALID`, `STRATA_E_STATE` (gồm transaction NULL); không tính `STRATA_E_BUDGET`, `STRATA_E_BUNDLE` (đã có fail mode), `STRATA_E_INCOMPLETE`; request chạy giảm cấp không được tính; (5) chuyển trạng thái chưa phát **sự kiện** qua event socket (sự kiện do libstrata mã hóa theo transaction): mỗi lần chuyển ghi `error.log` (`strata: circuit breaker open|half-open|closed`) và cập nhật metrics file (bộ đếm 21 trạng thái, 22 số lần mở, 23 số request giảm cấp; `docs/design/control-file.md`), agent xuất `strata_breaker_state{worker}`, `strata_breaker_opens_total`, `strata_degraded_requests_total`, cảnh báo `StrataBreakerOpen` và `StrataBreakerOpenManyWorkers` (nghiêm trọng).

## Bật enforce theo canary

Không chuyển thẳng từ shadow sang enforce: enforce tăng dần 1% → 5% → 25% → 100% request, mỗi bậc có thời gian quan sát tối thiểu, và có hai tầng tự quay về shadow khi có dấu hiệu sai.

**Chọn request vào nhóm canary**: hash ổn định của (identity hoặc IP, tên policy) so với tỉ lệ %. Cùng một client luôn rơi vào cùng một nhóm nên trải nghiệm không chập chờn. Request ngoài nhóm canary vẫn được inspect ở chế độ shadow (có Event ID), nên luôn có nhóm đối chứng.

*Hiện trạng (W11-R-01):* tỉ lệ canary là dữ liệu đã ký của policy: `canary_percent` trong `policies.schema.json` (0,01–99,99, chỉ với mode enforce), lưu thành `u16` basis point trong bảng policy của bundle (`docs/design/control-file.md`). libstrata chọn nhóm lúc `strata_tx_new` (`engine/src/canary.rs`): bucket = FNV-1a 64 trên `tên policy ‖ 0xff ‖ khóa`, trộn bằng splitmix64, mod 10.000; khóa là identity (`strata_identity`) nếu có, không thì địa chỉ client. Request có bucket nhỏ hơn tỉ lệ thì enforce, còn lại chạy shadow như policy shadow (`EVT-`, action `log`). Hàm hash cố định để control plane tính lại nhóm (W12-G2-01); tăng tỉ lệ thì nhóm cũ vẫn nằm trong nhóm mới. Hash không có khóa bí mật: client tự chọn identity có thể rơi vào phía shadow, chỉ hoãn việc bị chặn tới khi policy enforce 100%. Đổi tỉ lệ là deploy bundle mới; API policy và UI cho tỉ lệ chưa làm.

| Bậc | Tỉ lệ enforce | Quan sát tối thiểu | Điều kiện lên bậc |
| --- | --- | --- | --- |
| 1 | 1% | 24 giờ | Không có false positive được xác nhận mới; tỉ lệ chặn trong nhóm canary khớp với dự đoán từ shadow |
| 2 | 5% | 48 giờ | Như trên; 5xx upstream và p99 của nhóm canary không cao hơn nhóm shadow |
| 3 | 25% | 72 giờ | Như trên; helpdesk không có phiếu báo chặn nhầm chưa xử lý |
| 4 | 100% | — | Người duyệt xác nhận trên UI |

**Tự fallback hai tầng**

1. **Tại node, trong vài giây**: agent đọc metrics trong shared memory mỗi 5 giây. Nếu tỉ lệ chặn của một policy vượt ngưỡng (ví dụ gấp 3 lần mức đo được ở shadow) hoặc lỗi engine / budget tăng đột biến, agent ghi cờ force-shadow cho policy đó vào control file. Worker áp dụng ở lần đọc control file kế tiếp (tối đa 1 giây), không cần control plane.
2. **Toàn cụm, trong vài phút**: control plane so sánh nhóm canary với nhóm shadow về tỉ lệ 5xx upstream, p99 và tỉ lệ chặn, cộng với báo cáo false positive. Vượt ngưỡng thì gửi `Command ForceShadow` tới mọi node của connector group, dừng rollout và báo người duyệt.

5xx upstream tăng có thể không do WAF, nên fallback dựa trên **chênh lệch giữa hai nhóm** chứ không dựa trên con số tuyệt đối. Quay lại enforce sau fallback chỉ được làm bằng thao tác có duyệt trên UI.

*Hiện trạng (W11-G1-01, tầng 1):* `agent/internal/fallback`. Metrics file không có bộ đếm theo policy, nên agent tính cho **cả node** và ép shadow mọi policy (bit 0 của control file, qua cùng `force-shadow.json` với lệnh `ForceShadow`; quyết định PO 13/10/2026). Mỗi 5 giây, hiệu bộ đếm của mọi worker: tỉ lệ chặn so với mức "lẽ ra chặn" (block + log: khi shadow mọi request lẽ ra bị chặn đều là log) học bằng trung bình động; lỗi engine (fail mode) và vượt budget so với mức của chính chúng. Vượt `--fallback-factor` (3) lần mức nền (mức nền dưới 0,5% tính là 0,5%), trên khoảng có ít nhất 100 request, sau 12 khoảng khởi động: ép shadow, cảnh báo `StrataNodeFallback`. Chỉ ngắt khi node có chặn thật (block > 0): node đang shadow không bị ảnh hưởng.

*Sửa #65 (14/10/2026, Claude Code quyết theo ủy quyền của PO cho tuần 11):* fallback cũ có thể bị kích hoạt từ bên ngoài (gửi dồn payload bị chặn hoặc payload nặng, rồi tấn công khi node ở shadow), và bắn nhầm do dao động ngẫu nhiên khi lưu lượng thấp. Ba thay đổi:
- Số lần chặn của một khoảng chỉ tính tối đa 3 lần cho mỗi IP client (IPv6 gộp theo /64), lấy từ sự kiện agent nhận qua socket (`STR-`, action `BLOCK`). Không dùng identity, vì client có thể tự đặt.
- Một số đếm chỉ ngắt khi vừa vượt 3 lần mức nền, vừa khó xảy ra dưới mức nền: kiểm định Poisson một phía, p < 10⁻⁶. Mô phỏng một tuần ở 300 request mỗi 5 giây với 1% bị chặn: cách cũ bắn nhầm 705 lần, cách mới 0 lần.
- Lỗi engine và vượt budget mặc định **chỉ cảnh báo** (`StrataNodeErrorsJump`), không ép shadow, vì shadow không đổi fail mode (fail-open vẫn cho qua, fail-closed vẫn 503). `--fallback-on-errors` bật lại hành vi cũ. Điều này khác đoạn tầng 1 ở trên ("lỗi engine / budget tăng đột biến"); **PO xác nhận ngày 14/10/2026**.

Rủi ro còn lại: một đợt tấn công thật từ nhiều nguồn (botnet) vẫn đưa node về shadow. Tầng 2 (W12-G2-01) có cùng giảm thiểu (#74, dưới). *W12-G1-01:* cờ của fallback không có hạn (`fallback` trong `force-shadow.json`, giữ qua restart, metric `strata_agent_fallback_active`, cảnh báo `StrataNodeFallbackHeld` sau 1 giờ); chỉ `ForceShadow{clear}` cho mọi policy từ control plane (`POST /v1/nodes:clearForceShadow`, `policy_id` rỗng) gỡ được. Lệnh `forceShadow` hết hạn hay gỡ một policy không gỡ cờ này. Bỏ flag `--fallback-hold`. Ngưỡng có test biên (`TestThresholdEdges`).

*Hiện trạng (W12-G2-01, tầng 2):* `control-plane/fleet/canary.go`. Module đếm theo nhóm canary (cờ verdict `STRATA_VF_CANARY` / `STRATA_VF_CANARY_SHADOW`, bộ đếm 24..49 của metrics file: request, bị chặn, ghi log, upstream 5xx, histogram độ trễ request); agent gửi trong mỗi heartbeat (`NodeCounters.canary`, `canary_shadow`, 15 giây). Control plane cộng theo connector group trên cửa sổ 1 phút, mỗi nhóm ≥ 200 request (quyết định PO 14/10/2026): 5xx canary hơn shadow ≥ 1 điểm % và ≥ 2 lần; p99 canary ≥ 1,5 lần và +50 ms; tỉ lệ chặn canary > 3 lần mức "lẽ ra chặn" của các policy canary học trong 1 giờ (trung bình động, không tính cửa sổ đã ngắt; 12 lần đánh giá khởi động) và > 1%, và khó xảy ra dưới mức đó (kiểm định Poisson một phía, p < 10⁻⁶). *Sửa #74 (15/10/2026, PO giao):* số chặn và "lẽ ra chặn" không lấy từ heartbeat mà từ **sự kiện** node gửi lên (`PushEvents`: `STR-` + `BLOCK` phía canary, `EVT-` + `LOG` + `would_block` cả hai phía, theo trường `canary`), mỗi địa chỉ client (IPv6 gộp /64) tính tối đa 3 lần trong cửa sổ, **trên cả group**. Trước đó vài client gửi dồn payload bị chặn qua mọi node là ép được mọi policy canary của group về shadow 24 giờ (giới hạn theo từng node không đủ, vì một client đi qua load balancer chạm mọi node). Số request vẫn lấy từ heartbeat. Mất sự kiện trên đường (socket đầy) chỉ làm số chặn thấp đi. Giới hạn: control plane chỉ đếm sự kiện của node đã gửi heartbeat tới chính bản đó; với nhiều bản sau load balancer, luồng `PushEvents` và `Connect` của một node có thể tới hai bản khác nhau, làm số chặn thấp đi (bỏ sót, không ngắt nhầm). So chặn với mức nền chứ không với nhóm shadow vì hai nhóm chia client ngẫu nhiên: chặn nhầm làm cả hai cùng tăng. Ngắt thì ép shadow mọi policy có `canary_percent` (phiên bản hiện tại) trên mọi node của group (`ForceShadow` 24 giờ, gia hạn mỗi 12 giờ), dừng rollout đang chạy, audit, cảnh báo `StrataCanaryFallback`; giữ tới khi `clearForceShadow` trên group gỡ hết policy của lần ngắt (bảng `canary_trips`, mỗi group tối đa một lần ngắt mở, nên nhiều bản control plane không ngắt trùng). Mỗi bản control plane chỉ thấy node nối với nó; với nhiều bản, mỗi bản tự đánh giá trên phần node của mình. `canary_percent` có trong API policy (`PolicySpec.canary_percent`), chưa có trên UI.

## Bảo mật của module

Phần C được giữ nhỏ nhất có thể (tối đa 4.000 dòng code thực, không tính dòng trống và comment, `make check-c-lines`; nâng từ 2.000 sau W06-N-01, lên 2.500 rồi 3.000 ngày 12/10/2026, lên 4.000 ngày 15/10/2026) vì đó là phần duy nhất không memory-safe; mọi việc parse input không tin cậy nằm trong Rust.

- **Không parse trong C**: C chỉ lấy con trỏ và độ dài từ cấu trúc NGINX đã có, rồi chuyển cho libstrata.
- **Kiểm tra độ dài trước mọi copy**; chỉ dùng hàm có giới hạn kích thước (`ngx_cpymem` với độ dài đã kiểm, không `strcpy`/`sprintf`).
- **Trang chặn không phản chiếu input**: chỉ chèn Block ID, thời gian, thông tin liên hệ.
- **Chữ ký bundle** kiểm tra hai lần: ở agent và trong worker trước khi nạp; khóa công khai đọc từ file chỉ root ghi được.
- **Quyền file**: thư mục bundle chỉ cho user của agent ghi, user worker NGINX chỉ đọc; event socket chỉ cho nhóm NGINX ghi.
- **Không mở port, không gọi mạng** từ trong worker.
- **Không log dữ liệu nhạy cảm**: đoạn input trong sự kiện đã che theo data guard trước khi rời libstrata.
- **Build an toàn**: `-fstack-protector-strong`, `-D_FORTIFY_SOURCE=2`, RELRO, PIE; chạy CodeQL và clang-tidy trên phần C mỗi PR.

**Không có bypass bằng header**: module không hỗ trợ header bí mật hay token cho phép một request vượt WAF, vì khóa bị lộ hoặc lỗi trong phần kiểm token sẽ thành backdoor. Khi cần điều tra sự cố production, SRE dùng `ForceShadow` qua UI/API (áp dụng trong vài giây, request vẫn được inspect và ghi log), hoặc tạo exception debug cho IP bastion/VPN có hạn dùng ngắn, đi qua duyệt nhanh và audit.

## Kiểm thử

Mỗi PR phải qua các tầng unit, tích hợp và conformance; fuzz, hiệu năng và soak chạy thêm hằng đêm trên ma trận phiên bản NGINX.

| Tầng | Công cụ | Nội dung | Tiêu chí đạt |
| --- | --- | --- | --- |
| Unit (C) | cmocka hoặc harness riêng | Parse directive, merge cấu hình, sinh response chặn | 100% directive có test |
| Tích hợp | Test::Nginx (OpenResty) chạy NGINX thật | Từng phase, body streaming, HTTP/2, HTTP/3, internal redirect, subrequest, client ngắt giữa chừng, fail mode, hot reload khi đang có tải | Toàn bộ pass trên mọi phiên bản trong ma trận |
| Conformance | Corpus chung của Strata | Cùng request cho cùng verdict, rule ID và điểm như các connector khác | 100% khớp |
| Fuzz | libFuzzer trên lớp FFI; fuzz HTTP thô vào NGINX build ASan/UBSan | Header, body, chunked, multipart, HTTP/2 frame | 0 crash, 0 lỗi ASan sau 72 giờ |
| Rò rỉ bộ nhớ | Valgrind / ASan với `master_process off` | Chạy suite tích hợp | 0 leak |
| Hiệu năng | wrk2, k6; so với NGINX không bật module | Request nhỏ, body 64 KB, body 1 MB, HTTP/2 | Đạt ngân sách ở mục Hiệu năng |
| Soak | 24 giờ tải ổn định + 1.000 lần đổi bundle | Bộ nhớ, file descriptor, latency theo thời gian | Bộ nhớ không tăng liên tục, không rớt request |

## Build & đóng gói

Dynamic module của NGINX phải build đúng phiên bản NGINX sẽ nạp nó, nên CI build một artifact cho mỗi tổ hợp phiên bản NGINX × hệ điều hành × kiến trúc.

**Quy trình build**

1. Build `libstrata` thành thư viện tĩnh (`cargo build --release`, target theo kiến trúc), link tĩnh Hyperscan.
2. Tải mã nguồn NGINX đúng phiên bản, chạy `./configure --with-compat --add-dynamic-module=connectors/nginx` (thêm các cờ `--with-threads`, `--with-http_v2_module`, `--with-http_v3_module` cho khớp gói gốc).
3. `make modules` → `ngx_http_strata_module.so`.
4. Chạy suite tích hợp trên chính bản build đó.
5. Ký gói và ghi SBOM.

File `config` của module khai báo `ngx_module_type=HTTP_FILTER` cho phần filter và dùng `ngx_module_order` để đặt body filter trước `ngx_http_gzip_filter_module`.

**Ma trận ban đầu**

| Trục | Giá trị |
| --- | --- |
| NGINX | 2 bản OSS (stable + mainline hiện hành), NGINX Plus bản còn hỗ trợ, OpenResty bản hiện hành |
| Hệ điều hành | Ubuntu 22.04 / 24.04, Debian 12, RHEL/Rocky 8 / 9, Alpine (cho container) |
| Kiến trúc | x86\_64, aarch64 |

**Phân phối**

- Gói `nginx-module-strata` dạng deb/rpm, đặt tên và phụ thuộc theo đúng phiên bản `nginx` của nginx.org để trình quản lý gói chặn cài lệch phiên bản.
- Image container: NGINX + module + `strata-agent` (agent chạy cùng pod dạng sidecar hoặc cùng container với supervisor).
- `strata-agent` phân phối riêng (deb/rpm, image) vì dùng chung cho mọi connector.
- Script kiểm tra trước khi nâng NGINX: báo nếu chưa có module build cho phiên bản mới.

## Chế độ Lite (RV-G1-01)

`strata-agent run --standalone` nhận bundle đã ký từ file/thư mục hoặc URL,
xác minh bằng public key tin cậy tại node, cài bundle bất biến và cập nhật control
file cho worker hot reload. Không cần control plane hoặc database. Chu kỳ poll
và kiểm control của module quyết định độ trễ; không cam kết nạp tức thì.

Agent nhận Unix datagram và xuất JSON Lines/syslog; các sink trực tiếp có lỗi
được đếm, không thay thế hàng đợi lưu bền. Đọc counter tại `/run/strata/metrics`
và phục vụ `/metrics`. Đường dẫn bundle/control/socket phải khớp NGINX.

Gói agent có service/socket standalone riêng, xung đột với Fleet trên cùng node;
không tự bật mode này khi cài gói. Socket do systemd giữ qua restart agent; queue
có giới hạn. Mỗi tham số dùng biến EnvironmentFile riêng, không ghép shell args.
Một lệnh cài và bằng chứng SQLi dưới 5 phút trên VM sạch vẫn cần nghiệm thu
installer, bundle core đã ký và cấu hình route thật; test service không thay thế.

## Kế hoạch triển khai

Module NGINX mất khoảng 10 tuần để chạy shadow trên traffic thật, với 2 kỹ sư (1 C/NGINX, 1 Rust) làm song song với lõi libstrata; tuần 11–16 dành cho canary enforce.

&#91;embedded content: kế hoạch module 10 tuần · 6 mốc, 1 gate\]

Tuần 1–4 dùng libstrata dạng stub (luật đơn giản, cùng ABI) để không phụ thuộc tiến độ engine; từ tuần 5 thay bằng engine thật. Ước lượng thời gian là giả định, cần xác nhận khi chốt nhân sự.

### Lộ trình tổng thể: module, agent, control plane, UI

Lộ trình chia 3 giai đoạn trong 22 tuần. Phạm vi được cắt để giai đoạn đầu chỉ gồm những gì cần cho shadow; replay đầy đủ, bản đồ GeoIP và GitOps được lùi về sau khi đã enforce.

&#91;embedded content: lộ trình 22 tuần · 4 luồng việc, 3 mốc\]

| Giai đoạn | Phạm vi | Điều kiện kết thúc |
| --- | --- | --- |
| A · Tuần 1–10: shadow | Module NGINX đầy đủ; agent (enroll, bundle, sự kiện); control plane lõi (API, policy, compiler, fleet, ingest); UI tối thiểu (tra Block ID, sự kiện, fleet). Mốc phụ tuần 4: nối thông end-to-end với engine stub | 5 mục tiêu của module đạt; shadow trên 2 route eKYC; UI tra được Block ID |
| B · Tuần 11–16: enforce | Canary 1% → 5% → 25% → 100% với fallback hai tầng; replay MVP; policy editor, diff, duyệt | eKYC enforce 100% ít nhất 2 tuần không fallback; FP dưới ngưỡng |
| C · Tuần 17–22: hoàn thiện v1 | GeoIP + API thống kê, bản đồ và dashboard, GitOps sync tùy chọn | SOC dùng được bản đồ và dashboard; sẵn sàng làm connector thứ hai |

Phân công đề xuất: 1 kỹ sư C/NGINX, 1 Rust (libstrata, compiler, replay), 2 Go (agent, control plane), 1 frontend, cộng 1 QA/SRE bán thời gian cho kiểm thử và vận hành canary. Thời gian là ước lượng, cần xác nhận khi chốt nhân sự; nếu thiếu người thì giữ nguyên giai đoạn A–B và lùi giai đoạn C.

## Rủi ro & câu hỏi còn mở

| Rủi ro | Tác động | Giảm thiểu |
| --- | --- | --- |
| Hành vi request body khác nhau giữa các phiên bản NGINX (đặc biệt HTTP/2, HTTP/3) | Bỏ sót inspect body | Test tích hợp riêng cho từng giao thức trên mọi phiên bản trong ma trận |
| Thứ tự filter đụng module khác (gzip, sub\_filter, njs, Lua) | Inspect body đã biến đổi hoặc nén | Kiểm tra thứ tự filter lúc khởi động và ghi cảnh báo; test cùng OpenResty |
| Database Hyperscan không dùng chung được qua mmap | RAM tăng theo số worker cho phần Hyperscan | PoC tuần 1–2; nếu không được thì chỉ tách riêng section Hyperscan, phần còn lại vẫn dùng chung |
| Engine chạy đồng bộ chiếm event loop với body lớn | Tăng latency request khác trên cùng worker | CPU budget hợp tác, giới hạn body, chuyển sang thread pool ở phase 2 |
| Canary đánh giá sai vì 5xx do nguyên nhân khác | Fallback không cần thiết hoặc bỏ lỡ sự cố thật | So sánh nhóm canary với nhóm shadow thay vì dùng số tuyệt đối |
| Phạm vi control plane và UI lớn hơn nguồn lực | Trễ mốc enforce | Cắt phạm vi theo giai đoạn A/B/C; giai đoạn C lùi được mà không ảnh hưởng enforce |
| Gói phải theo kịp mỗi bản NGINX mới | Không nâng được NGINX khi chưa có module | CI tự build khi NGINX ra bản mới; theo dõi release feed |

**Quyết định đã chốt** (sau review ngày 10/10/2026):

| Câu hỏi | Quyết định | Lý do |
| --- | --- | --- |
| NGINX Plus ngay từ đầu hay sau? | Sau khi OSS ổn định (sau giai đoạn B) | Cần license và build riêng theo release Plus, làm chậm CI giai đoạn đầu |
| OpenResty và Kong | Hỗ trợ OpenResty như một bản NGINX thông thường; Kong làm connector riêng, không đi qua module NGINX | Tránh xung đột phase và filter với plugin Kong, nhất là buffer response |
| Định dạng sự kiện qua event socket | Protobuf, mỗi datagram tối đa 8 KB | Nhỏ và parse nhanh hơn JSON, giảm drop khi tải cao |
| `strata_fail_mode` mặc định | `open`; location API nhạy cảm (eKYC) đặt `closed` sau khi đã enforce 100% ổn định | Ưu tiên tính sẵn sàng khi mới đưa vào vận hành |
| Ai sở hữu trang chặn | Control plane giữ template mặc định trong bundle; `strata_block_page` cho phép SRE/SecOps ghi đè cục bộ | Thống nhất mặc định, vẫn tùy biến được theo dự án |
| Ring buffer shared memory cho sự kiện | v1 dùng socket sau interface `strata_event_sink_t`; ring vào v1 chỉ khi benchmark tuần 8–9 vượt ngưỡng, nếu không thì v1.1 | Lợi ích chỉ rõ khi bị tấn công dồn dập; có interface nên chuyển sau không tốn công |
| Circuit breaker | Có trong v1 (giai đoạn B), chỉ tính lỗi nội bộ, mở thì chạy giảm cấp | Cần trước khi enforce; không tính budget để kẻ tấn công không tự mở được |
| Emergency bypass header | Không làm | Rủi ro thành backdoor; đã có `ForceShadow` và exception debug theo IP |

Câu hỏi còn mở:

- [ ] Kết quả PoC mmap cho database Hyperscan / Vectorscan (tuần 2)
- [ ] Nguồn vector tile cho bản đồ đã kiểm tra đúng ranh giới lãnh thổ Việt Nam
- [ ] Xác nhận nhân sự cho giai đoạn A–B

## Phản hồi review kỹ thuật (10/10/2026)

Bảng dưới ghi nhận từng điểm của bản review, đánh giá và thay đổi tương ứng trong tài liệu này.

| Điểm review | Đánh giá | Thay đổi trong thiết kế |
| --- | --- | --- |
| Buffer response đã che có thể bị giải phóng sớm hoặc hỏng cờ | Đúng một phần. Buffer cấp từ `r->pool` tồn tại tới khi request kết thúc hẳn, nên không bị giải phóng khi NGINX còn gửi. Thiếu sót thật là việc giữ cờ buffer, quản lý busy/free chain và buffer nằm trong file | Bổ sung quy tắc buffer và `filter_need_in_memory` (mục Xử lý body) |
| Internal redirect gây inspect lặp, đếm metric hai lần | Cần mô tả rõ hơn. Tuy nhiên NGINX xóa toàn bộ module context khi internal redirect, nên không thể lưu cờ trong context như review đề xuất; trạng thái phải nằm trong pool cleanup | Mô tả cơ chế lưu trạng thái trong pool cleanup; phân biệt subrequest bằng `r != r->main` |
| RAM engine nhân theo số worker | Đúng | Bundle dạng zero-copy, mmap `MAP_SHARED` ngay từ đầu; PoC Hyperscan tuần 1–2 |
| Bypass khi `proxy_request_buffering off` | Đúng, chỉ cảnh báo là chưa đủ | Module tự đọc đủ body ở enforce; chế độ `stream` chỉ chạy shadow; `nginx -t` báo lỗi khi cấu hình sai |
| Lệch ranh giới message do chunked / Transfer-Encoding | Đúng, cần nói rõ libstrata nhận gì | libstrata inspect body đã bỏ framing (đúng thứ upstream nhận được) và nhận header framing thô cho lớp protocol |
| Bypass qua URL normalization | Đúng | Truyền cả URI thô, URI đã normalize và query; đổi chữ ký `strata_tx_request_line` |
| `stat()` trong event loop | Đúng về nguyên tắc: trên đĩa local `stat()` rất nhanh, nhưng có thể treo trên filesystem mạng | Control file mmap trên tmpfs; mọi syscall nạp bundle chạy trong thread pool; agent từ chối thư mục bundle trên filesystem mạng |
| CPU budget không ngắt được giữa chừng, nguy cơ ReDoS | Cần nói rõ cơ chế. Lưu ý Hyperscan và crate `regex` không backtracking nên không có ReDoS kiểu PCRE | Budget hợp tác: quét theo khối 8 KB, parser dạng vòng lặp có đếm token; phần vượt tối đa dưới 100 µs |
| Timeline 12 tuần quá gấp | Đồng ý | Giãn thành 22 tuần, 3 giai đoạn; lùi replay đầy đủ, GeoIP, GitOps |
| Thiếu giai đoạn canary enforce | Đồng ý | Thêm mục Bật enforce theo canary với fallback hai tầng |
| 5 câu hỏi còn mở | Đồng ý với cả 5 khuyến nghị | Ghi vào bảng Quyết định đã chốt |

### Review lần 2 (10/10/2026)

| Đề xuất | Đánh giá | Quyết định cho v1 |
| --- | --- | --- |
| Xử lý post-handler đọc body chạy đồng bộ và bất đồng bộ | Đúng; điểm dễ gây treo request nhất là cân bằng `r->main->count` | Đưa vào: mẫu code và danh sách test ở mục Vòng đời request. Sửa khi triển khai tuần 1–2: mẫu ban đầu (trả count trong post-handler ở cả hai nhánh) làm treo request khi NGINX tự báo lỗi lúc đọc body bất đồng bộ (413 với body chunked) vì post-handler không được gọi; chuyển sang trả count ngay khi `NGX_AGAIN` như module `mirror` |
| RST\_STREAM ở HTTP/2, HTTP/3 | Đúng một nửa: pool cleanup luôn chạy đúng một lần; NGINX không hủy được task đang chạy trong thread pool | Đưa vào: `strata_tx_free` idempotent; giữ request sống bằng `r->main->blocked` + `r->aio` khi có task |
| Tắt sendfile khi inspect response | Đã có từ bản trước qua `r->filter_need_in_memory`, là cơ chế chuẩn của NGINX; chỉ đặt `r->sendfile = 0` là chưa đủ | Giữ nguyên thiết kế |
| Header zero-copy (`strata_str_pair_t`) | Đồng ý | Đưa vào và chốt ABI ở tuần 2, kèm quy tắc lifetime |
| Ring buffer shared memory cho sự kiện | Tốt, cần ring theo từng worker trong `/dev/shm`, agent kiểm từng record | Interface trong v1; ring tùy kết quả benchmark |
| Circuit breaker cấp node | Tốt, nhưng nếu tính cả vượt budget thì kẻ tấn công tự mở được | Đưa vào với phiên bản đã điều chỉnh |
| Emergency bypass header | Không khuyến nghị: thực chất là backdoor | Không làm; dùng `ForceShadow` và exception debug |

### CP-B02 · Inventory và kiểm tương thích

Fleet Hello/Heartbeat mang NodeInfo với agent version, OS/architecture, ABI và danh sách
capability; input không được tin để cấp quyền. PostgreSQL giữ inventory và thời điểm nhận,
Fleet API/UI hiển thị desired/actual, drift và hạn chứng chỉ (sắp hết hạn trong 7 ngày).
Agent nhận `--module-manifest` (mặc định `/etc/strata/module-manifest.json` của gói module),
kiểm SHA-256 binary và đối chiếu module version/ABI từ metrics trước khi báo capability.
Thiếu manifest hoặc runtime không khớp nghĩa là chưa biết. Nâng module cần reload NGINX và
restart agent; manifest không phải bằng chứng rằng mọi worker đã bỏ binary cũ.

Requirements lấy từ section directory và policy metadata của bundle đã xác minh chữ ký,
lưu cùng bundle trong PostgreSQL, không đổi định dạng v1. Deploy/staging kiểm trước khi ghi;
rollout kiểm lại trước khi thay desired hoặc hủy rollout cũ; node thiếu capability không được
tải bundle qua FetchBundle, kể cả khi enroll/kết nối sau rollout. Inventory không thay kiểm
chữ ký/layout của engine. Bundle cũ chưa có requirements giữ đường tương thích cũ; không suy
ra capability cho agent cũ.

### Compact B01 · Applications and scope

PostgreSQL migration 0032 defines application ownership, environments, route links and
namespaced subject bindings. Explicit bindings replace token role authority, while machine
token scopes remain a ceiling; previously bound subjects never revert to legacy global
roles after revocation. Global operators configure ownership, global admins grant roles.
Shared policy mutation/approval requires rights on all owning environments. HTTP and gRPC
resolve and enforce scope, including event detail and scoped ClickHouse aggregations. SSE
refreshes authorization each poll. Application metadata hides unassigned environments.
Scoped request/engine counters are unavailable (`telemetry_scope=events_only`) because their
source has no route dimensions; the UI labels coverage unknown. The application page shows
configuration intent and timestamps, not a claim that workers activated that intent.

### Compact B04 · Release snapshot and rollback

Migration 0033 stores immutable releases (signed artifact metadata, approved replay IDs,
baseline, compiler/rule/input digests and canary configuration). Preparation keeps artifacts
under `releases/` without changing the deployed baseline. Independent subject review pins
hash and replay IDs. Publication atomically records the new bundle, rollout, node desired
versions and receipt. Rollback copies all historical sections into a new monotonic version
and signs with the current key, rather than recompiling old policy with new rules. Historical
or changed replay baselines require explicit acknowledgment of the current baseline.
Global roles manage these installation-wide artifacts; scoped users cannot disclose them.
Canary thresholds are YAML/flag settings, pinned at preparation; changes require new review.

### Compact B05 · Health and read-only doctor

Fleet Heartbeat optionally carries bounded AgentHealth spool counters; NodeCounters declares
whether worker metrics were actually observed. Migration 0034 persists this telemetry and its
receipt time. Authenticated `/v1/health` combines readiness, bounded ClickHouse observations,
node/certificate/drift, failed operations and filesystem diagnostics with explicit freshness
and unknown states. Application scope filters nodes/events and withholds whole-node traffic
counters. The UI ages observations even while its network request is pending.

`strata-control-plane doctor` reads existing schemas and never starts migrations/workers or
acquires a lease. Private support archives allowlist numeric configuration and diagnostic
fields, pseudonymize node IDs, omit raw logs/request data/credentials, and include checksums.
Remote database disk space and offline live-process telemetry remain unknown. Details and
exit codes are in `docs/runbook/doctor.md`.

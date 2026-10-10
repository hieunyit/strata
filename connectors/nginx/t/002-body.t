# Request body reading: the 7 mandatory cases from the design
# ("Vòng đời request"), each checking both the sync/async post-handler path
# and that r->main->count stays balanced (no hung request, no alert).

use FindBin;
use lib "$FindBin::Bin/lib";
use Test::Strata 'no_plan';

our $ID = qr/STR-[0-9A-HJKMNP-TV-Z]{4}(?:-[0-9A-HJKMNP-TV-Z]{4}){3}/;

our $Location = <<'_EOC_';
    location /t {
        strata on;
        add_header X-Action $strata_action always;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/backend/;
    }
_EOC_

add_block_preprocessor(sub {
    my $block = shift;

    if (!defined $block->config) {
        $block->set_value("config", $Location . $Test::Strata::Backend);
    }

    if (!defined $block->no_error_log) {
        $block->set_value("no_error_log", "[alert]\n[crit]\n[emerg]");
    }
});

# send one byte at a time
sub bytes { [ map { $_ } split //, shift ] }

run_tests();

__DATA__

=== TEST 1: body entirely in the preread buffer (sync post handler)
--- request
POST /t
a=1&b=2
--- response_body
backend uri=/backend/ len=7
--- error_log
strata: body read, sync



=== TEST 2: preread body containing the test string is blocked
--- request
POST /t
a=STRATA-TEST-BLOCK
--- error_code: 403
--- response_headers_like eval
"X-Strata-Block-Id: $::ID"
--- error_log
strata: body read, sync



=== TEST 3: Content-Length: 0
--- raw_request eval
"POST /t HTTP/1.1\r
Host: localhost\r
Content-Length: 0\r
Connection: close\r
\r
"
--- response_headers
X-Action: allow
--- response_body
backend uri=/backend/ len=0
--- error_log
strata: body read, sync



=== TEST 4: HTTP/2 with END_STREAM on HEADERS (no body at all)
--- http2
--- request
GET /t?h2
--- response_headers
X-Action: allow
--- response_body
backend uri=/backend/?h2 len=
--- error_log
strata: body read, sync



=== TEST 5: HTTP/2 blocked on URI, request with END_STREAM on HEADERS
--- http2
--- request
GET /t?STRATA-TEST-BLOCK
--- error_code: 403
--- response_headers_like eval
"x-strata-block-id: $::ID"



=== TEST 6: HTTP/2 request body is inspected
--- http2
--- request
POST /t
x=STRATA-TEST-BLOCK
--- error_code: 403
--- response_headers_like eval
"x-strata-block-id: $::ID"



=== TEST 7: body sent one byte at a time (async post handler), clean
--- raw_request eval
::bytes("POST /t HTTP/1.1\r
Host: localhost\r
Content-Length: 12\r
Connection: close\r
\r
hello=world!")
--- raw_request_middle_delay: 0.001
--- response_body
backend uri=/backend/ len=12
--- error_log
strata: body read, async



=== TEST 8: body sent one byte at a time, test string split across reads
--- raw_request eval
::bytes("POST /t HTTP/1.1\r
Host: localhost\r
Content-Length: 21\r
Connection: close\r
\r
xxSTRATA-TEST-BLOCKyy")
--- raw_request_middle_delay: 0.001
--- error_code: 403
--- response_headers_like eval
"X-Strata-Block-Id: $::ID"
--- error_log
strata: body read, async



=== TEST 9: chunked body sent in pieces (async), test string split across chunks
--- raw_request eval
["POST /t HTTP/1.1\r
Host: localhost\r
Transfer-Encoding: chunked\r
Connection: close\r
\r
9\r
xxSTRATA-\r
", "c\r
TEST-BLOCKyy\r
", "0\r
\r
"]
--- raw_request_middle_delay: 0.01
--- error_code: 403
--- error_log
strata: body read, async



=== TEST 10: client closes the connection while the body is awaited
--- raw_request eval
"POST /t HTTP/1.1\r
Host: localhost\r
Content-Length: 100\r
\r
only part of the body"
--- timeout: 0.3
--- abort
--- wait: 0.3
--- ignore_response
--- error_log
client prematurely closed connection
strata: tx freed



=== TEST 11: Content-Length over client_max_body_size: 413 before PREACCESS
--- config
    location /t {
        strata on;
        client_max_body_size 10;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/backend/;
    }
--- request
POST /t
this body is longer than ten bytes
--- error_code: 413
--- error_log
client intended to send too large body
--- no_error_log
strata: tx created
[alert]



=== TEST 12: chunked body over client_max_body_size: 413 while the module reads it
--- config
    location /t {
        strata on;
        client_max_body_size 10;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/backend/;
    }
--- raw_request eval
["POST /t HTTP/1.1\r
Host: localhost\r
Transfer-Encoding: chunked\r
Connection: close\r
\r
8\r
12345678\r
", "8\r
12345678\r
0\r
\r
"]
--- raw_request_middle_delay: 0.01
--- error_code: 413
--- wait: 0.2
--- error_log
client intended to send too large chunked body
strata: tx created
strata: tx freed
--- no_error_log
strata: body read
[alert]



=== TEST 13: internal redirect after the body was read: no second inspection
--- config
    location /t {
        strata on;
        add_header X-Action $strata_action always;
        try_files /nonexistent @fallback;
    }
    location @fallback {
        strata on;
        add_header X-Action $strata_action always;
        rewrite ^ /backend/ break;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT;
    }
--- request
POST /t
a=1&b=2
--- response_headers
X-Action: allow
--- response_body
backend uri=/backend/ len=7
--- grep_error_log eval: qr/strata: (?:tx created|context restored|body read|tx freed)/
--- grep_error_log_out
strata: tx created
strata: body read
strata: context restored
strata: tx freed



=== TEST 14: body over strata_request_body_limit is inspected only up to the limit
--- config
    location /t {
        strata on;
        strata_request_body_limit 8;
        add_header X-Action $strata_action always;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/backend/;
    }
--- request
POST /t
12345678STRATA-TEST-BLOCK
--- response_headers
X-Action: allow
--- response_body
backend uri=/backend/ len=25
--- error_log
strata: request body inspected:8 last:1



=== TEST 15: large body spooled to a temp file is still inspected (filter sees memory buffers)
--- config
    location /t {
        strata on;
        client_body_buffer_size 1k;
        add_header X-Action $strata_action always;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/backend/;
    }
--- request eval
"POST /t\n" . ("a" x 5000) . "STRATA-TEST-BLOCK" . ("b" x 5000)
--- error_code: 403
--- error_log
a client request body is buffered to a temporary file

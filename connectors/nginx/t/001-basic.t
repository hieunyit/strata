# Basic block / pass behaviour, block response, variables, modes.

use FindBin;
use lib "$FindBin::Bin/lib";
use Test::Strata 'no_plan';

our $ID = qr/[0-9A-HJKMNP-TV-Z]{4}(?:-[0-9A-HJKMNP-TV-Z]{4}){3}/;
our $BLOCK_ID = qr/^STR-$ID$/;
our $EVENT_ID = qr/^EVT-$ID$/;

run_tests();

__DATA__

=== TEST 1: clean request passes through
--- config
    location /t {
        strata on;
        add_header X-Action $strata_action always;
        add_header X-Block-Id $strata_block_id always;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/backend/;
    }
--- request
GET /t?q=hello
--- response_headers
X-Action: allow
X-Block-Id:
X-Strata-Block-Id:
--- response_body
backend uri=/backend/?q=hello len=
--- no_error_log
[error]



=== TEST 2: test string in query is blocked with an HTML page
--- config
    location /t {
        strata on;
        add_header X-Action $strata_action always;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/backend/;
    }
--- request
GET /t?q=STRATA-TEST-BLOCK
--- error_code: 403
--- response_headers_like eval
[
    "X-Strata-Block-Id: $::BLOCK_ID",
    "Cache-Control: no-store",
    "Content-Type: text/html; charset=utf-8",
    "X-Action: block",
    "Server: ",
]
--- response_body_like eval
qr{<p>Block ID: <code>STR-$::ID</code><br>Time: \d{4}-\d\d-\d\dT\d\d:\d\d:\d\d[+-]\d\d:\d\d</p>}
--- no_error_log
[error]



=== TEST 3: test string in the path is blocked
--- config
    location /t {
        strata on;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/backend/;
    }
--- request
GET /t/a/STRATA-TEST-BLOCK/b
--- error_code: 403
--- response_headers_like eval
"X-Strata-Block-Id: $::BLOCK_ID"



=== TEST 4: JSON block response for API clients
--- config
    location /t {
        strata on;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/backend/;
    }
--- request
GET /t?STRATA-TEST-BLOCK
--- more_headers
Accept: application/json
--- error_code: 403
--- response_headers_like eval
[
    "Content-Type: application/json",
    "X-Strata-Block-Id: $::BLOCK_ID",
]
--- response_body_like eval
qr/^\{"error":"blocked","block_id":"STR-$::ID"\}$/



=== TEST 5: test string in the body is blocked
--- config
    location /t {
        strata on;
        add_header X-Action $strata_action always;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/backend/;
    }
--- request
POST /t
name=STRATA-TEST-BLOCK&x=1
--- error_code: 403
--- response_headers_like eval
[
    "X-Strata-Block-Id: $::BLOCK_ID",
    "X-Action: block",
]



=== TEST 6: clean body passes and reaches the upstream
--- config
    location /t {
        strata on;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/backend/;
    }
--- request
POST /t
name=example&x=1
--- response_body
backend uri=/backend/ len=16



=== TEST 7: score, rules and policy variables
--- config
    location /t {
        strata on;
        strata_policy example-api;
        add_header X-Score $strata_score always;
        add_header X-Rules $strata_rules always;
        add_header X-Policy $strata_policy always;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/backend/;
    }
--- request
GET /t?STRATA-TEST-BLOCK
--- error_code: 403
--- response_headers
X-Score: 100
X-Rules: 899001
X-Policy: example-api



=== TEST 8: shadow mode logs with an Event ID and lets the request through
--- config
    location /t {
        strata on;
        strata_mode shadow;
        add_header X-Action $strata_action always;
        add_header X-Block-Id $strata_block_id always;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/backend/;
    }
--- request
GET /t?STRATA-TEST-BLOCK
--- response_headers_like eval
[
    "X-Action: log",
    "X-Block-Id: $::EVENT_ID",
    "X-Strata-Block-Id: ",
]
--- response_body
backend uri=/backend/?STRATA-TEST-BLOCK len=



=== TEST 9: strata off is not inspected
--- config
    strata on;
    location /t {
        strata off;
        add_header X-Action $strata_action always;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/backend/;
    }
--- request
GET /t?STRATA-TEST-BLOCK
--- response_headers
X-Action:
--- response_body
backend uri=/backend/?STRATA-TEST-BLOCK len=



=== TEST 10: subrequests are skipped, only the main request is inspected
--- config
    location /t {
        strata on;
        auth_request /auth/STRATA-TEST-BLOCK;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/backend/;
    }
    location /auth/ {
        internal;
        strata on;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/backend/;
    }
--- response_body
backend uri=/backend/ len=
--- grep_error_log eval: qr/strata: tx created/
--- grep_error_log_out
strata: tx created



=== TEST 11: custom block page, only known placeholders are replaced
--- config
    location /t {
        strata on;
        strata_block_page $TEST_NGINX_STRATA_FIXTURES/block.html;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/backend/;
    }
--- request
GET /t?STRATA-TEST-BLOCK
--- error_code: 403
--- response_body_like eval
qr{^<html><body>Blocked: STR-$::ID at \d{4}-\d\d-\d\dT[\d:+-]+ \{\{unknown\}\} </body></html>$}



=== TEST 12: HEAD gets the block status without a body
--- config
    location /t {
        strata on;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/backend/;
    }
--- request
HEAD /t?STRATA-TEST-BLOCK
--- error_code: 403
--- response_headers_like eval
"X-Strata-Block-Id: $::BLOCK_ID"
--- response_body



=== TEST 13: no bundle + fail open: pass, action "error", Event ID
--- http_config
    strata_control_file  $TEST_NGINX_STRATA_FIXTURES/empty/control;
    strata_bundle_dir    $TEST_NGINX_STRATA_FIXTURES/empty;
    strata_bundle_pubkey $TEST_NGINX_STRATA_FIXTURES/bundle.pub;
--- config
    location /t {
        strata on;
        add_header X-Action $strata_action always;
        add_header X-Block-Id $strata_block_id always;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/backend/;
    }
--- request
GET /t?STRATA-TEST-BLOCK
--- response_headers_like eval
[
    "X-Action: error",
    "X-Block-Id: $::EVENT_ID",
]
--- response_body
backend uri=/backend/?STRATA-TEST-BLOCK len=
--- error_log
requests follow



=== TEST 14: no bundle + fail closed: 503 with Event ID
--- http_config
    strata_control_file  $TEST_NGINX_STRATA_FIXTURES/empty/control;
    strata_bundle_dir    $TEST_NGINX_STRATA_FIXTURES/empty;
    strata_bundle_pubkey $TEST_NGINX_STRATA_FIXTURES/bundle.pub;
--- config
    location /t {
        strata on;
        strata_fail_mode closed;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/backend/;
    }
--- error_code: 503
--- response_headers_like eval
[
    "X-Strata-Block-Id: $::EVENT_ID",
    "Cache-Control: no-store",
]
--- response_body_like eval
qr/Block ID: <code>EVT-$::ID</
--- no_error_log
[error]



=== TEST 15: a panic in libstrata is contained, fail open lets the request through
--- config
    location /t {
        strata on;
        add_header X-Action $strata_action always;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/backend/;
    }
--- request
POST /t
STRATA-TEST-PANIC
--- response_headers
X-Action: error
--- response_body
backend uri=/backend/ len=17
--- error_log eval
qr/strata: engine error 3, event id EVT-$::ID, fail mode open/
--- no_error_log
[alert]
[emerg]



=== TEST 16: a panic with fail closed returns 503
--- config
    location /t {
        strata on;
        strata_fail_mode closed;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/backend/;
    }
--- request
POST /t
STRATA-TEST-PANIC
--- error_code: 503
--- error_log
strata: engine error 3
--- no_error_log
[alert]



=== TEST 17: blocked before the body is read, keepalive connection still usable
--- config
    location /t {
        strata on;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/backend/;
    }
--- pipelined_requests eval
["POST /t?STRATA-TEST-BLOCK\nsome body", "GET /t?ok"]
--- error_code eval
[403, 200]
--- response_body_like eval
[qr/Request blocked/, qr/^backend uri=\/backend\/\?ok len=$/]



=== TEST 18: stream body mode is shadow only; body findings reach the variables
--- config
    location /t {
        strata on;
        strata_request_body_mode stream;
        add_header X-Action $strata_action always;
        add_header X-Block-Id $strata_block_id always;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/backend/;
    }
--- request
POST /t
name=STRATA-TEST-BLOCK
--- response_headers_like eval
[
    "X-Action: log",
    "X-Block-Id: $::EVENT_ID",
    "X-Strata-Block-Id: ",
]
--- response_body
backend uri=/backend/ len=22
--- no_error_log
strata: body read



=== TEST 19: stream body mode, clean body
--- config
    location /t {
        strata on;
        strata_request_body_mode stream;
        add_header X-Action $strata_action always;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/backend/;
    }
--- request
POST /t
name=example
--- response_headers
X-Action: allow
--- response_body
backend uri=/backend/ len=12

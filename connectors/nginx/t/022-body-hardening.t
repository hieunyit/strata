# Request body hardening:
# - bodies larger than strata_request_body_limit follow the policy's
#   "oversize" (rule 100020): block, or recorded and passed;
# - a body read before this location's PREACCESS (internal redirect from a
#   location without strata) is inspected from the buffers NGINX kept;
#   parts already in a temporary file are not read in the event loop: the
#   transaction fails and strata_fail_mode applies.

use FindBin;
use lib "$FindBin::Bin/lib";
use Test::Strata 'no_plan';

our $ID = qr/(?:STR|EVT)-[0-9A-HJKMNP-TV-Z]{4}(?:-[0-9A-HJKMNP-TV-Z]{4}){3}/;

# /first reads the body (proxy, no strata), gets 404 and redirects to /second
our $Redirect = <<'_EOC_';
    location /first {
        strata off;
        proxy_intercept_errors on;
        error_page 404 = /second;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/missing/;
    }
    location /missing/ {
        strata off;
        return 404;
    }
_EOC_

run_tests();

__DATA__

=== TEST 1: body over the limit, policy oversize block: 403, rule 100020
--- config
    location /t {
        strata on;
        strata_policy example-api;
        strata_request_body_limit 16;
        add_header X-Rules $strata_rules always;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/backend/;
    }
--- request
POST /t
this body is longer than sixteen bytes
--- error_code: 403
--- response_headers_like eval
["X-Rules: 100020", "X-Strata-Block-Id: $::ID"]
--- error_log
strata: request body over the limit by 22 bytes



=== TEST 2: body over the limit, policy oversize pass: recorded, passed
--- config
    location /t {
        strata on;
        strata_policy example-web;
        strata_request_body_limit 16;
        add_header X-Rules $strata_rules always;
        add_header X-Action $strata_action always;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/backend/;
    }
--- request
POST /t
this body is longer than sixteen bytes
--- response_headers
X-Rules: 100020
X-Action: allow
--- response_body
backend uri=/backend/ len=38



=== TEST 3: body within the limit: no rule 100020
--- config
    location /t {
        strata on;
        strata_policy example-api;
        strata_request_body_limit 64;
        add_header X-Action $strata_action always;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/backend/;
    }
--- request
POST /t
short body
--- response_headers
X-Action: allow



=== TEST 4: oversize under strata_mode shadow only logs
--- config
    location /t {
        strata on;
        strata_policy example-api;
        strata_mode shadow;
        strata_request_body_limit 16;
        add_header X-Action $strata_action always;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/backend/;
    }
--- request
POST /t
this body is longer than sixteen bytes
--- response_headers
X-Action: log



=== TEST 5: body read before the redirect is inspected from memory
--- config eval
$::Redirect . q{
    location /second {
        strata on;
        add_header X-Action $strata_action always;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/backend/;
    }
}
--- request
POST /first
name=STRATA-TEST-BLOCK
--- error_code: 403
--- error_log
strata: body read before, inspected from its buffers



=== TEST 6: clean body read before the redirect passes
--- config eval
$::Redirect . q{
    location /second {
        strata on;
        add_header X-Action $strata_action always;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/backend/;
    }
}
--- request
POST /first
name=example
--- response_headers
X-Action: allow



=== TEST 7: body read before the redirect and spooled to a file: fail mode open
--- config eval
$::Redirect . q{
    client_body_buffer_size 1k;
    location /second {
        strata on;
        add_header X-Action $strata_action always;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/backend/;
    }
}
--- request eval
"POST /first\n" . ("a" x 5000) . "STRATA-TEST-BLOCK"
--- response_headers
X-Action: error
--- error_log
strata: request body buffer not in memory, not inspected; applying strata_fail_mode
strata: engine error 7



=== TEST 8: same with fail mode closed: 503 with an Event ID
--- config eval
$::Redirect . q{
    client_body_buffer_size 1k;
    location /second {
        strata on;
        strata_fail_mode closed;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/backend/;
    }
}
--- request eval
"POST /first\n" . ("a" x 5000)
--- error_code: 503
--- response_headers_like eval
"X-Strata-Block-Id: EVT-[0-9A-Z-]{19}"

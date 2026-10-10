# Response layer of a policy (W06-R-01), fixture policy example-guard:
# allowed codes, database errors, data guard for citizen ID numbers (CCCD)
# and JSON Web Tokens. Masking keeps the length; shadow never masks.

use FindBin;
use lib "$FindBin::Bin/lib";
use Test::Strata 'no_plan';

our $Token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U';
our $Stars = '*' x length($Token);

run_tests();

__DATA__

=== TEST 1: CCCD in a JSON response is masked, Content-Length unchanged
--- config
    location /t {
        strata on;
        strata_policy example-guard;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/up;
    }
    location /up {
        strata off;
        default_type application/json;
        return 200 '{"name":"A","cccd":"001203012345","ts":1760000000123}';
    }
--- response_headers
Content-Length: 53
--- response_body: {"name":"A","cccd":"************","ts":1760000000123}



=== TEST 2: CCCD split across 7-byte buffers of a static file
--- config
    location /t {
        strata on;
        strata_policy example-guard;
        output_buffers 2 7;
        alias html/data.json;
    }
--- user_files
>>> data.json
[{"cccd":"079099001122"},{"cccd":"001203012345"}]
--- response_body
[{"cccd":"************"},{"cccd":"************"}]



=== TEST 3: JWT in a response is masked
--- config
    location /t {
        strata on;
        strata_policy example-guard;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/up;
    }
    location /up {
        strata off;
        alias html/token.json;
    }
--- user_files eval
">>> token.json\n{\"access_token\":\"$::Token\"}\n"
--- response_body eval
"{\"access_token\":\"$::Stars\"}\n"



=== TEST 4: shadow: recorded, never masked
--- config
    location /t {
        strata on;
        strata_policy example-guard;
        strata_mode shadow;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/up;
    }
    location /up {
        strata off;
        return 200 '{"cccd":"001203012345"}';
    }
--- response_body: {"cccd":"001203012345"}



=== TEST 5: policy without the response layer: not masked
--- config
    location /t {
        strata on;
        strata_policy example-api;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/up;
    }
    location /up {
        strata off;
        return 200 '{"cccd":"001203012345"}';
    }
--- response_body: {"cccd":"001203012345"}



=== TEST 6: status outside the allowed codes is recorded (log phase), response unchanged
--- http_config eval
$Test::Strata::HttpConfig . 'log_format strata "rules=$strata_rules action=$strata_action id=$strata_block_id";'
--- config
    location /t {
        strata on;
        strata_policy example-guard;
        access_log logs/strata.log strata;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/up;
    }
    location /up {
        strata off;
        return 500 "boom\n";
    }
    location /log {
        strata off;
        alias logs/strata.log;
    }
--- request eval
["GET /t", "GET /log"]
--- error_code eval
[500, 200]
--- response_body_like eval
[qr/^boom$/, qr/^rules=600001 action=allow id=EVT-[0-9A-Z-]{19}$/]



=== TEST 7: database error page passes unchanged (recorded only)
--- config
    location /t {
        strata on;
        strata_policy example-guard;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/up;
    }
    location /up {
        strata off;
        return 200 "You have an error in your SQL syntax near 001203012345\n";
    }
--- response_body
You have an error in your SQL syntax near ************

# Protocol layer (W03-R-01) seen through NGINX.

use FindBin;
use lib "$FindBin::Bin/lib";
use Test::Strata 'no_plan';

our $ID = qr/STR-[0-9A-HJKMNP-TV-Z]{4}(?:-[0-9A-HJKMNP-TV-Z]{4}){3}/;

our $Location = <<'_EOC_';
    location /t {
        strata on;
        add_header X-Rules $strata_rules always;
        add_header X-Score $strata_score always;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/backend/;
    }
_EOC_

add_block_preprocessor(sub {
    my $block = shift;
    $block->set_value("config", $Location) unless defined $block->config;
});

run_tests();

__DATA__

=== TEST 1: encoded dot-segment in the raw URI is blocked (NGINX already normalized r->uri)
--- request
GET /t/%2e%2e/t/x
--- error_code: 403
--- response_headers_like eval
["X-Strata-Block-Id: $::ID", "X-Rules: 100011", "X-Score: 100"]



=== TEST 2: matrix parameter is scored but allowed
--- request
GET /t/app;jsessionid=1/x
--- response_headers
X-Rules: 100012
X-Score: 20
--- response_body_like: ^backend



=== TEST 3: double encoding plus matrix parameter stays under the threshold
--- request
GET /t/a;b/%2541
--- response_headers
X-Rules: 100010,100012
X-Score: 70



=== TEST 4: duplicated Content-Length is rejected by NGINX itself (400) before the module
--- raw_request eval
"POST /t HTTP/1.1\r
Host: localhost\r
Content-Length: 3\r
Content-Length: 3\r
Connection: close\r
\r
abc"
--- error_code: 400
--- no_error_log
strata: tx created



=== TEST 5: Content-Length with Transfer-Encoding is rejected by NGINX itself (400)
--- raw_request eval
"POST /t HTTP/1.1\r
Host: localhost\r
Content-Length: 3\r
Transfer-Encoding: chunked\r
Connection: close\r
\r
3\r
abc\r
0\r
\r
"
--- error_code: 400
--- no_error_log
strata: tx created

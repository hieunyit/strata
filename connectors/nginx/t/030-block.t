# W04-N-01: block page and the seven $strata_* variables.
#
# The access log is written into the error log file, so the test can read it.

use FindBin;
use lib "$FindBin::Bin/lib";
use Test::Strata 'no_plan';

our $ID = qr/STR-[0-9A-HJKMNP-TV-Z]{4}(?:-[0-9A-HJKMNP-TV-Z]{4}){3}/;

our $HttpConfig = $Test::Strata::HttpConfig . <<'_EOC_';
    log_format strata 'strata-access blk=$strata_block_id act=$strata_action score=$strata_score rules=$strata_rules policy=$strata_policy bundle=$strata_bundle_version t=$strata_time_us';
_EOC_

our $Location = <<'_EOC_';
    location /t {
        strata on;
        strata_policy example-api;
        access_log logs/error.log strata;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/backend/;
    }
_EOC_

add_block_preprocessor(sub {
    my $block = shift;
    $block->set_value("http_config", $HttpConfig) unless defined $block->http_config;
    $block->set_value("config", $Location) unless defined $block->config;
});

run_tests();

__DATA__

=== TEST 1: JSON block response, exact shape and headers
--- request
GET /t?q=STRATA-TEST-BLOCK
--- more_headers
Accept: application/json
--- error_code: 403
--- response_headers_like eval
["Content-Type: application/json", "X-Strata-Block-Id: $::ID", "Cache-Control: no-store", "Server: "]
--- response_body_like eval
qr/^\{"error":"blocked","block_id":"$::ID"\}$/



=== TEST 2: HTML block page comes from the bundle, with its support contact
--- request
GET /t?q=STRATA-TEST-BLOCK
--- error_code: 403
--- response_headers_like eval
["Content-Type: text/html; charset=utf-8", "X-Strata-Block-Id: $::ID", "Cache-Control: no-store"]
--- response_body_like eval
qr{<!-- example bundle block page -->.*Block ID: <code>$::ID</code>.*<p>Support: support\@example.test</p>}s



=== TEST 3: the block page never reflects the request (no <script> from the URL)
--- request
GET /t?q=%3Cscript%3Ealert(1)%3C/script%3E&x=<script>alert(2)</script>&STRATA-TEST-BLOCK
--- error_code: 403
--- response_body_unlike eval
qr/script|alert/i



=== TEST 4: strata_block_page overrides the bundle page, support contact still from the bundle
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
qr{^<html><body>Blocked: $::ID at [\d:T+-]+ \{\{unknown\}\} Support: support\@example.test</body></html>$}



=== TEST 5: without a bundle, the built-in page is used
--- http_config
    strata_control_file  $TEST_NGINX_STRATA_FIXTURES/empty/control;
    strata_bundle_dir    $TEST_NGINX_STRATA_FIXTURES/empty;
    strata_bundle_pubkey $TEST_NGINX_STRATA_FIXTURES/bundle.pub;
--- config
    location /t {
        strata on;
        strata_fail_mode closed;
    }
--- error_code: 503
--- response_body_like eval
qr/Your request was blocked by the web application firewall/
--- response_body_unlike eval
qr/example bundle block page/



=== TEST 6: all seven variables in the access log of a blocked request
--- request
GET /t?STRATA-TEST-BLOCK
--- error_code: 403
--- wait: 0.1
--- error_log eval
qr/strata-access blk=$::ID act=block score=100 rules=899001 policy=example-api bundle=1 t=\d+/



=== TEST 7: and of an allowed request scored by the protocol layer
--- request
GET /t/x;y
--- wait: 0.1
--- error_log eval
qr/strata-access blk= act=allow score=20 rules=100012 policy=example-api bundle=1 t=\d+/

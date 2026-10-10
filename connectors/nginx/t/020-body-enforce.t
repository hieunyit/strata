# W03-N-02: in buffer mode the module reads the whole body and decides before
# the CONTENT phase, so "proxy_request_buffering off" cannot leak the first
# bytes upstream. The upstream request is never created when blocked: the
# debug log has no "http proxy header" line (NGINX logs it while building the
# upstream request).

use FindBin;
use lib "$FindBin::Bin/lib";
use Test::Strata 'no_plan';

our $ID = qr/STR-[0-9A-HJKMNP-TV-Z]{4}(?:-[0-9A-HJKMNP-TV-Z]{4}){3}/;

our $Location = <<'_EOC_';
    location /t {
        strata on;
        proxy_request_buffering off;
        client_max_body_size 1m;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/backend/;
    }
_EOC_

add_block_preprocessor(sub {
    my $block = shift;
    $block->set_value("config", $Location) unless defined $block->config;
});

our $Blocked = ("a" x 70000) . "STRATA-TEST-BLOCK" . ("b" x 100);
our $Clean   = ("a" x 70000) . ("b" x 117);

run_tests();

__DATA__

=== TEST 1: test string at byte 70,000, proxy_request_buffering off: 403, upstream gets nothing
--- request eval
"POST /t\n$::Blocked"
--- error_code: 403
--- response_headers_like eval
"X-Strata-Block-Id: $::ID"
--- error_log
strata: verdict action:3
--- no_error_log
http proxy header



=== TEST 2: same size, clean: forwarded upstream in full
--- request eval
"POST /t\n$::Clean"
--- response_body
backend uri=/backend/ len=70117
--- error_log
http proxy header



=== TEST 3: chunked body in pieces (async read), test string after 70,000 bytes
--- raw_request eval
["POST /t HTTP/1.1\r
Host: localhost\r
Transfer-Encoding: chunked\r
Connection: close\r
\r
" . sprintf("%x", 70000) . "\r
" . ("a" x 70000) . "\r
", "11\r
STRATA-TEST-BLOCK\r
0\r
\r
"]
--- raw_request_middle_delay: 0.05
--- error_code: 403
--- no_error_log
http proxy header



=== TEST 4: HTTP/2, test string at byte 70,000: 403, upstream gets nothing
--- http2
--- request eval
"POST /t\n$::Blocked"
--- error_code: 403
--- no_error_log
http proxy header



=== TEST 5: stream mode (shadow) is the only way to let the body through first
--- config
    location /t {
        strata on;
        strata_request_body_mode stream;
        proxy_request_buffering off;
        add_header X-Action $strata_action always;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/backend/;
    }
--- request eval
"POST /t\n$::Blocked"
--- response_headers
X-Action: log
--- response_body
backend uri=/backend/ len=70117

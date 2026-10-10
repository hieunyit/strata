# Response path (W06-N-01): the test data guard of libstrata (test-hooks)
# masks STRATA-TEST-MASK in response bodies. Checks that the filter sees
# the body before gzip, in memory (static files with sendfile), across
# buffer boundaries (libstrata holds back the tail of a chunk), without
# changing the length, up to strata_response_body_limit, and that bodies
# the upstream already compressed are passed and logged.

use FindBin;
use lib "$FindBin::Bin/lib";
use Test::Strata 'no_plan';
use IO::Uncompress::Gunzip qw(gunzip);

our $Masked = '*' x 16;

sub ungzip { my $in = shift; my $out; gunzip(\$in => \$out) or die; $out }

run_tests();

__DATA__

=== TEST 1: proxied body is masked, Content-Length unchanged
--- config
    location /t {
        strata on;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/up;
    }
    location /up {
        strata off;
        return 200 "id=STRATA-TEST-MASK end\n";
    }
--- response_headers
Content-Length: 24
--- response_body eval
"id=$::Masked end\n"



=== TEST 2: static file, sendfile on, 7-byte buffers: needle split across buffers
--- config
    sendfile on;
    location /t {
        strata on;
        output_buffers 2 7;
        alias html/data.txt;
    }
--- user_files
>>> data.txt
0123456789 STRATA-TEST-MASK 0123 STRATA-TEST-MASKSTRATA-TEST-MASK tail
--- response_headers
Content-Length: 71
--- response_body eval
"0123456789 $::Masked 0123 $::Masked$::Masked tail\n"



=== TEST 3: gzip on: masked before compression
--- config
    gzip on;
    gzip_min_length 1;
    gzip_types text/plain;
    location /t {
        strata on;
        default_type text/plain;
        alias html/data.txt;
    }
--- user_files
>>> data.txt
before STRATA-TEST-MASK after
--- more_headers
Accept-Encoding: gzip
--- response_headers
Content-Encoding: gzip
--- response_body_filters eval
\&main::ungzip
--- response_body eval
"before $::Masked after\n"



=== TEST 4: body compressed by the upstream: not inspected, logged
--- config
    location /t {
        strata on;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/up;
    }
    location /up {
        strata off;
        add_header Content-Encoding gzip;
        return 200 "STRATA-TEST-MASK\n";
    }
--- response_body
STRATA-TEST-MASK
--- error_log
strata: response body compressed by the upstream (Content-Encoding: gzip), not inspected



=== TEST 5: strata_response_inspect off
--- config
    location /t {
        strata on;
        strata_response_inspect off;
        return 200 "STRATA-TEST-MASK\n";
    }
--- response_body
STRATA-TEST-MASK



=== TEST 6: past strata_response_body_limit the body passes untouched
--- config
    location /t {
        strata on;
        strata_response_body_limit 20;
        output_buffers 1 8;
        alias html/data.txt;
    }
--- user_files
>>> data.txt
a STRATA-TEST-MASK b STRATA-TEST-MASK c
--- response_body eval
"a $::Masked b STRATA-TEST-MASK c\n"



=== TEST 7: needle straddling the limit: what was inspected is flushed as is
--- config
    location /t {
        strata on;
        strata_response_body_limit 10;
        alias html/data.txt;
    }
--- user_files
>>> data.txt
xxxx STRATA-TEST-MASK yy
--- response_body
xxxx STRATA-TEST-MASK yy



=== TEST 8: chunked upstream response, several reads
--- config
    location /t {
        strata on;
        proxy_buffering off;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/up;
    }
    location /up {
        strata off;
        chunked_transfer_encoding on;
        output_buffers 1 5;
        alias html/data.txt;
    }
--- user_files
>>> data.txt
1 STRATA-TEST-MASK 2 STRATA-TEST-MASK 3
--- response_body eval
"1 $::Masked 2 $::Masked 3\n"



=== TEST 9: HEAD: no body, nothing held
--- config
    location /t {
        strata on;
        alias html/data.txt;
    }
--- user_files
>>> data.txt
STRATA-TEST-MASK
--- request
HEAD /t
--- response_headers
Content-Length: 17
--- response_body



=== TEST 10: block page is not inspected
--- config
    location /t {
        strata on;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/backend/;
    }
--- request
GET /t?STRATA-TEST-BLOCK
--- error_code: 403
--- response_body_unlike
\*{16}



=== TEST 11: HTTP/2 response masked
--- http2
--- config
    location /t {
        strata on;
        output_buffers 2 6;
        alias html/data.txt;
    }
--- user_files
>>> data.txt
h2 STRATA-TEST-MASK h2
--- response_body eval
"h2 $::Masked h2\n"

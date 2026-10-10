# Request bodies larger than client_body_buffer_size are spooled to a
# temporary file by NGINX. The module's request body filter runs before
# NGINX's save filter, so it sees every chunk in memory before it is
# written: a payload deep in a spooled body is still inspected.

use FindBin;
use lib "$FindBin::Bin/lib";
use Test::Strata 'no_plan';

our $Location = <<'_EOC_';
    location /t {
        strata on;
        client_body_buffer_size 1k;
        client_max_body_size 4m;
        add_header X-Action $strata_action always;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/backend/;
    }
_EOC_

add_block_preprocessor(sub {
    my $block = shift;
    $block->set_value("config", $Location) unless defined $block->config;
});

our $Deep = ("a" x 900000) . "STRATA-TEST-BLOCK" . ("b" x 1000);

sub chunked {
    my ($body, $piece) = @_;
    my @parts = ("POST /t HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n");
    for (my $i = 0; $i < length $body; $i += $piece) {
        my $c = substr($body, $i, $piece);
        push @parts, sprintf("%x\r\n", length $c) . $c . "\r\n";
    }
    push @parts, "0\r\n\r\n";
    return \@parts;
}

run_tests();

__DATA__

=== TEST 1: payload at byte 900,000 of a spooled body (Content-Length)
--- request eval
"POST /t\n$::Deep"
--- error_code: 403
--- error_log
a client request body is buffered to a temporary file
strata: request body inspected:901017 last:1



=== TEST 2: same, chunked, sent in 64 KB pieces (async reads)
--- raw_request eval
::chunked($::Deep, 65536)
--- raw_request_middle_delay: 0.01
--- error_code: 403
--- error_log
a client request body is buffered to a temporary file



=== TEST 3: same over HTTP/2
--- http2
--- request eval
"POST /t\n$::Deep"
--- error_code: 403
--- error_log
a client request body is buffered to a temporary file



=== TEST 4: client_body_in_file_only: the body only ever lands in a file, still inspected
--- config
    location /t {
        strata on;
        client_body_in_file_only clean;
        client_max_body_size 4m;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/backend/;
    }
--- request eval
"POST /t\n$::Deep"
--- error_code: 403



=== TEST 5: clean spooled body reaches the upstream in full
--- request eval
"POST /t\n" . ("a" x 900000)
--- response_body
backend uri=/backend/ len=900000
--- error_log
a client request body is buffered to a temporary file

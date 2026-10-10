# W03-N-01: the PREACCESS handler passes the request line in three forms
# (raw r->unparsed_uri, normalized r->uri, r->args) and every header in
# arrival order, duplicates included. A test hook in libstrata (feature
# test-hooks, never in release builds) echoes what it received to stderr,
# which is the worker's error log, when the request has X-Strata-Test-Echo.

use FindBin;
use lib "$FindBin::Bin/lib";
use Test::Strata 'no_plan';

# Test::Nginx adds a static "location /": requests that pass get 404, which
# does not matter here; the echo line is what is checked.
our $Config = <<'_EOC_';
    strata on;
_EOC_

add_block_preprocessor(sub {
    my $block = shift;
    $block->set_value("config", $Config) unless defined $block->config;
});

run_tests();

__DATA__

=== TEST 1: raw, normalized and query forms of /a/%2e%2e/b?x=1
--- raw_request eval
"GET /a/%2e%2e/b?x=1 HTTP/1.1\r
Host: localhost\r
X-Strata-Test-Echo: 1\r
Connection: close\r
\r
"
--- error_code: 403
--- error_log
strata-test-echo method="GET" raw="/a/%2e%2e/b?x=1" norm="/b" args="x=1" proto="HTTP/1.1"



=== TEST 2: duplicated headers are passed as many times as sent, in order
--- raw_request eval
"GET /dup HTTP/1.1\r
Host: localhost\r
X-Dup: one\r
X-Other: middle\r
X-Dup: two\r
X-Dup: one\r
X-Strata-Test-Echo: 1\r
Connection: close\r
\r
"
--- error_code: 404
--- error_log
headers=[Host: localhost][X-Dup: one][X-Other: middle][X-Dup: two][X-Dup: one][X-Strata-Test-Echo: 1][Connection: close]



=== TEST 3: header names keep their case, values are not altered
--- raw_request eval
"GET /case HTTP/1.1\r
Host: localhost\r
x-MiXeD-Case: Value With  Spaces\r
X-Strata-Test-Echo: 1\r
Connection: close\r
\r
"
--- error_code: 404
--- error_log
[x-MiXeD-Case: Value With  Spaces]



=== TEST 4: percent-decoding and slash merging show only in the normalized form
--- raw_request eval
"GET //c/%41%42?q=%41 HTTP/1.1\r
Host: localhost\r
X-Strata-Test-Echo: 1\r
Connection: close\r
\r
"
--- error_code: 404
--- error_log
raw="//c/%41%42?q=%41" norm="/c/AB" args="q=%41"



=== TEST 5: no query: empty args
--- raw_request eval
"POST /plain HTTP/1.1\r
Host: localhost\r
Content-Length: 0\r
X-Strata-Test-Echo: 1\r
Connection: close\r
\r
"
--- error_code: 404
--- error_log
method="POST" raw="/plain" norm="/plain" args="" proto="HTTP/1.1"

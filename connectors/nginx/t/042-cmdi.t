# W17-R-01: signed CMDi rules through the actual connector/FFI/body path.
use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/lib";
use Cwd qw(abs_path);
use File::Path qw(make_path);
use File::Temp qw(tempdir);
use Test::Strata 'no_plan';

my $compiler = $ENV{TEST_NGINX_STRATA_COMPILE} or die "compiler required\n";
my $mk = $ENV{TEST_NGINX_STRATA_MKBUNDLE} or die "mkbundle required\n";
my $repo = abs_path("$FindBin::Bin/../../..");
my $fixtures = "$FindBin::Bin/fixtures";
make_path("$repo/build");
my $dir = tempdir('cmdi-nginx-XXXXXX', DIR => "$repo/build", CLEANUP => 1);
open my $fh, '>', "$dir/policies.yaml" or die $!;
print $fh "policies:\n  - { name: example-api, mode: enforce }\n  - { name: example-shadow, mode: shadow }\n";
close $fh or die $!;
system($compiler, '--rules', "$repo/engine/compiler/examples/cmdi-test.yaml",
       '--policies', "$dir/policies.yaml", '--key', "$fixtures/test.key",
       '--version', '18', '--out', "$dir/bundle-18.sbn") == 0 or die "compile failed\n";
system($mk, 'control', '--out', "$dir/control", '--generation', '2',
       '--version', '18', '--name', 'bundle-18.sbn', '--bundle', "$dir/bundle-18.sbn") == 0
    or die "control failed\n";
my $budget = $ENV{ASAN_OPTIONS} ? '1s' : '10ms'; # instrumentation only
my $http = "strata_control_file $dir/control;\nstrata_bundle_dir $dir;\n"
    . "strata_bundle_pubkey $fixtures/bundle.pub;\nstrata_cpu_budget $budget;\n"
    . 'strata_metrics_file $TEST_NGINX_SERVER_ROOT/logs/metrics;';
my $config = <<'NGINX';
location /t/ {
    strata on;
    strata_policy example-api;
    add_header X-Rules $strata_rules always;
    add_header X-Action $strata_action always;
    proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/backend/;
}
location /shadow/ {
    strata on;
    strata_policy example-shadow;
    add_header X-Rules $strata_rules always;
    add_header X-Action $strata_action always;
    proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/backend/;
}
location /backend/ { strata off; return 200 "ok\n"; }
NGINX
add_block_preprocessor(sub {
    my $block = shift;
    $block->set_value('http_config', $http);
    $block->set_value('config', $config);
});
run_tests();
__DATA__

=== TEST 1: command after a separator in the query blocks
--- request
GET /t/ping?host=127.0.0.1%3Bcat+%2Fetc%2Fpasswd
--- error_code: 403
--- response_headers
X-Rules: 800818
X-Action: block

=== TEST 2: form body command substitution blocks
--- request
POST /t/ping
host=%24%28uname+-a%29
--- more_headers
Content-Type: application/x-www-form-urlencoded
--- error_code: 403
--- response_headers
X-Rules: 800818
X-Action: block

=== TEST 3: a word glued to a path remains allowed
--- request
GET /t/ping?pkg=net%2Fhttp
--- error_code: 200
--- response_headers
X-Rules:
X-Action: allow

=== TEST 4: prose with a command word on a new line remains allowed
--- request
POST /t/ping
note=Thanks%0Afind+me+at+the+desk%3B+more+later
--- more_headers
Content-Type: application/x-www-form-urlencoded
--- error_code: 200
--- response_headers
X-Rules:
X-Action: allow

=== TEST 5: shadow records the same match without blocking
--- request
GET /shadow/ping?host=x%7C%7Cwhoami
--- error_code: 200
--- response_headers
X-Rules: 800818
X-Action: log

=== TEST 6: double encoded separator blocks through the rule transform
--- request
GET /t/ping?host=x%253Bid
--- error_code: 403
--- response_headers
X-Action: block

=== TEST 7: absent arguments do not match
--- request
GET /t/ping
--- error_code: 200
--- response_headers
X-Rules:
X-Action: allow

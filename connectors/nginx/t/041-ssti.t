# W17-R-01: signed SSTI rules through the actual connector/FFI/body path.
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
my $dir = tempdir('ssti-nginx-XXXXXX', DIR => "$repo/build", CLEANUP => 1);
open my $fh, '>', "$dir/policies.yaml" or die $!;
print $fh "policies:\n  - { name: example-api, mode: enforce }\n  - { name: example-shadow, mode: shadow }\n";
close $fh or die $!;
system($compiler, '--rules', "$repo/engine/compiler/examples/ssti-test.yaml",
       '--policies', "$dir/policies.yaml", '--key', "$fixtures/test.key",
       '--version', '17', '--out', "$dir/bundle-17.sbn") == 0 or die "compile failed\n";
system($mk, 'control', '--out', "$dir/control", '--generation', '2',
       '--version', '17', '--name', 'bundle-17.sbn', '--bundle', "$dir/bundle-17.sbn") == 0
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

=== TEST 1: encoded Jinja probe blocks through the body stage
--- request
GET /t/render?tpl=%7B%7B7*7%7D%7D
--- error_code: 403
--- response_headers
X-Rules: 800817
X-Action: block

=== TEST 2: form body Spring expression blocks
--- request
POST /t/render
tpl=%24%7B7*7%7D
--- more_headers
Content-Type: application/x-www-form-urlencoded
--- error_code: 403
--- response_headers
X-Rules: 800817
X-Action: block

=== TEST 3: benign template variable remains allowed
--- request
GET /t/render?tpl=Hello+%7B%7Bname%7D%7D
--- error_code: 200
--- response_headers
X-Rules:
X-Action: allow

=== TEST 4: unmatched delimiters remain allowed
--- request
GET /t/render?tpl=%7B%7B%24%7B%3C%25
--- error_code: 200
--- response_headers
X-Rules:
X-Action: allow

=== TEST 5: shadow records the same match without blocking
--- request
GET /shadow/render?tpl=%7B%7B7*7%7D%7D
--- error_code: 200
--- response_headers
X-Rules: 800817
X-Action: log

=== TEST 6: ERB expression blocks
--- request
GET /t/render?tpl=%3C%25%3D7*7%25%3E
--- error_code: 403
--- response_headers
X-Rules: 800817
X-Action: block

=== TEST 7: absent arguments do not match
--- request
GET /t/render
--- error_code: 200
--- response_headers
X-Rules:
X-Action: allow

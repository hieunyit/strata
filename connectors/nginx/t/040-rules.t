# W05-R-01: rules from the bundle (engine/compiler/examples/rules.yaml,
# compiled into the test fixture with its Hyperscan section) are evaluated
# on the request line and headers.

use FindBin;
use lib "$FindBin::Bin/lib";
use Test::Strata 'no_plan';

our $Location = <<'_EOC_';
    location / {
        strata on;
        add_header X-Rules $strata_rules always;
        add_header X-Score $strata_score always;
        add_header X-Action $strata_action always;
        return 200 "ok\n";
    }
_EOC_

add_block_preprocessor(sub {
    my $block = shift;
    if (!defined $block->config) {
        # "return" runs before PREACCESS: proxy to the backend instead
        my $c = $Location;
        $c =~ s{return 200 "ok\\n";}{proxy_pass http://127.0.0.1:\$TEST_NGINX_SERVER_PORT/backend/;};
        $c =~ s{location / }{location /t };
        $block->set_value("config", $c);
    }
});

run_tests();

__DATA__

=== TEST 1: a scanner user agent (rule 500100, pm, caseless) is scored
--- request
GET /t/page
--- more_headers
User-Agent: Mozilla/5.0 SQLMap/1.8
--- response_headers
X-Rules: 500100
X-Score: 20
X-Action: allow



=== TEST 2: a web shell path (rule 400100, ends_with after lowercase) is scored
--- request
GET /t/uploads/CMD.PHP
--- response_headers
X-Rules: 400100
X-Score: 50



=== TEST 3: or the same rule through its other condition (args_names streq)
--- request
GET /t/x?c99shell=1
--- response_headers
X-Rules: 400100



=== TEST 4: rule scores add up with the protocol layer and the stub rule
--- request
GET /t/uploads/cmd.php?q=STRATA-TEST-BLOCK
--- more_headers
User-Agent: nikto
--- error_code: 403
--- response_headers
X-Rules: 899001,400100,500100
X-Score: 170
X-Action: block



=== TEST 5: a clean request matches no rule
--- request
GET /t/index.html?a=1
--- more_headers
User-Agent: curl/8.5
--- response_headers
X-Rules:
X-Score: 0
X-Action: allow

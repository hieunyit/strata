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



=== TEST 6: request_body rules run on the query of a GET (942100, detect_sqli)
The body of a GET is empty; the rule still sees the query once the
connector reports the end of the body.
--- request
GET /t/users?id=1'%20OR%201=1--
--- response_headers
X-Rules: 942100
X-Score: 5
X-Action: allow



=== TEST 7: and on the fields of a form body
--- request
POST /t/login
user=alice&pass=1'%20OR%20'1'='1
--- more_headers
Content-Type: application/x-www-form-urlencoded
--- response_headers
X-Rules: 942100
X-Score: 5



=== TEST 8: a body that is not a form has no fields
--- request
POST /t/login
user=alice&pass=1'%20OR%20'1'='1
--- more_headers
Content-Type: text/plain
--- response_headers
X-Rules:



=== TEST 9: and on the scalars of a JSON body
--- request
POST /t/search
{"filter": {"name": "x", "id": "1' OR '1'='1"}}
--- more_headers
Content-Type: application/json
--- response_headers
X-Rules: 942100
X-Score: 5



=== TEST 10: and on the fields of a multipart body
--- request eval
"POST /t/profile\r\n--b0\r\nContent-Disposition: form-data; name=\"bio\"\r\n\r\n1' OR '1'='1\r\n--b0--\r\n"
--- more_headers
Content-Type: multipart/form-data; boundary=b0
--- response_headers
X-Rules: 942100
X-Score: 5

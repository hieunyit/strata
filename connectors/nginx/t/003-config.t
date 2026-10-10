# Directives: parsing, merge between levels, and configuration-time errors.

use FindBin;
use lib "$FindBin::Bin/lib";
use Test::Strata 'no_plan';

run_tests();

__DATA__

=== TEST 1: every directive is accepted in its documented contexts
--- http_config
    strata on;
    strata_control_file  $TEST_NGINX_STRATA_FIXTURES/bundle/control;
    strata_bundle_dir          $TEST_NGINX_STRATA_FIXTURES/bundle;
    strata_bundle_pubkey       $TEST_NGINX_STRATA_FIXTURES/bundle.pub;
    strata_bundle_check        2s;
    strata_node_id             web-01;
    strata_event_socket        unix:/run/strata/events.sock;
    strata_mode                inherit;
    strata_fail_mode           open;
    strata_request_body_mode   buffer;
    strata_request_body_limit  2m;
    strata_response_inspect    on;
    strata_response_body_limit 256k;
    strata_identity            $http_x_client_id;
    strata_block_page          $TEST_NGINX_STRATA_FIXTURES/block.html;
    strata_cpu_budget          5ms;
--- config
    strata_policy example-api;
    location /t {
        strata_policy example-api-upload;
        strata_mode shadow;
        strata_fail_mode closed;
        strata_request_body_mode stream;
        strata_request_body_limit 8m;
        strata_response_inspect off;
        strata_response_body_limit 1m;
        strata_identity $remote_user;
        strata_cpu_budget 1ms;
        add_header X-Policy $strata_policy always;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/backend/;
    }
--- response_headers
X-Policy: example-api-upload
--- no_error_log
[error]
[emerg]



=== TEST 2: "strata on" at http level is inherited, "strata off" overrides
--- http_config
    strata on;
    strata_control_file  $TEST_NGINX_STRATA_FIXTURES/bundle/control;
    strata_bundle_dir    $TEST_NGINX_STRATA_FIXTURES/bundle;
    strata_bundle_pubkey $TEST_NGINX_STRATA_FIXTURES/bundle.pub;
--- config
    location /on {
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/backend/;
    }
    location /off {
        strata off;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/backend/;
    }
--- pipelined_requests eval
["GET /on?STRATA-TEST-BLOCK", "GET /off?STRATA-TEST-BLOCK"]
--- error_code eval
[403, 200]



=== TEST 3: server-level policy and fail mode are inherited by locations
--- http_config
    strata_control_file  $TEST_NGINX_STRATA_FIXTURES/empty/control;
    strata_bundle_dir    $TEST_NGINX_STRATA_FIXTURES/empty;
    strata_bundle_pubkey $TEST_NGINX_STRATA_FIXTURES/bundle.pub;
--- config
    strata on;
    strata_policy example-api;
    strata_fail_mode closed;
    location /t {
        add_header X-Policy $strata_policy always;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/backend/;
    }
--- error_code: 503
--- response_headers
X-Policy: example-api



=== TEST 4: module loaded but never enabled: no pubkey needed, nothing inspected
--- http_config
--- config
    location /t {
        add_header X-Action $strata_action always;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/backend/;
    }
--- request
GET /t?STRATA-TEST-BLOCK
--- response_headers
X-Action:
--- no_error_log
strata: tx created



=== TEST 5: strata_bundle_pubkey is required when strata is enabled
--- http_config
    strata_control_file  $TEST_NGINX_STRATA_FIXTURES/bundle/control;
    strata_bundle_dir $TEST_NGINX_STRATA_FIXTURES/bundle;
--- config
    location /t { strata on; }
--- must_die
--- error_log
"strata_bundle_pubkey" is required when "strata" is enabled



=== TEST 6: public key of the wrong size is rejected
--- http_config
    strata_control_file  $TEST_NGINX_STRATA_FIXTURES/bundle/control;
    strata_bundle_dir    $TEST_NGINX_STRATA_FIXTURES/bundle;
    strata_bundle_pubkey $TEST_NGINX_STRATA_FIXTURES/short.pub;
--- config
    location /t { strata on; }
--- must_die
--- error_log
must be 32 raw bytes



=== TEST 7: a bundle libstrata rejects makes the configuration fail
--- http_config
    strata_control_file  $TEST_NGINX_STRATA_FIXTURES/bad/control;
    strata_bundle_dir    $TEST_NGINX_STRATA_FIXTURES/bad;
    strata_bundle_pubkey $TEST_NGINX_STRATA_FIXTURES/bundle.pub;
--- config
    location /t { strata on; }
--- must_die
--- error_log
rejected (5): bad bundle signature



=== TEST 8: event socket must be a unix socket
--- http_config
    strata_event_socket 127.0.0.1:9000;
--- config
--- must_die
--- error_log
invalid event socket "127.0.0.1:9000", expected unix:<path>



=== TEST 9: missing block page file
--- http_config
    strata_block_page /nonexistent/block.html;
--- config
--- must_die
--- error_log
/nonexistent/block.html



=== TEST 10: invalid enum value
--- http_config
    strata_fail_mode sometimes;
--- config
--- must_die
--- error_log
invalid value "sometimes"



=== TEST 11: strata_policy is not allowed at http level
--- http_config
    strata_policy example-api;
--- config
--- must_die
--- error_log
"strata_policy" directive is not allowed here



=== TEST 12: duplicate block page
--- http_config
    strata_block_page $TEST_NGINX_STRATA_FIXTURES/block.html;
    strata_block_page $TEST_NGINX_STRATA_FIXTURES/block.html;
--- config
--- must_die
--- error_log
"strata_block_page" directive is duplicate

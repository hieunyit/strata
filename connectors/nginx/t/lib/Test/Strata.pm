package Test::Strata;

# Shared setup for the ngx_http_strata_module Test::Nginx suites.
#
# Environment (set by `make test-nginx`):
#   TEST_NGINX_LOAD_MODULES   path to ngx_http_strata_module.so
#   PATH                      must contain the matching nginx binary
#
# Exposes $TEST_NGINX_STRATA_FIXTURES to configs, and gives every block a
# default http_config (bundle + pubkey) and a backend on the same server.

use strict;
use warnings;

use Cwd qw(abs_path);
use File::Basename qw(dirname);
use Test::Nginx::Socket -Base;

$ENV{TEST_NGINX_STRATA_FIXTURES} = abs_path(dirname(__FILE__) . '/../../fixtures');

die "TEST_NGINX_LOAD_MODULES must point to ngx_http_strata_module.so\n"
    unless $ENV{TEST_NGINX_LOAD_MODULES};

our $HttpConfig = <<'_EOC_';
    strata_control_file  $TEST_NGINX_STRATA_FIXTURES/bundle/control;
    strata_bundle_dir    $TEST_NGINX_STRATA_FIXTURES/bundle;
    strata_bundle_pubkey $TEST_NGINX_STRATA_FIXTURES/bundle.pub;
    strata_node_id       web-01;
    strata_metrics_file  $TEST_NGINX_SERVER_ROOT/logs/metrics;
_EOC_

# Backend locations appended to every server block: they echo what the
# upstream received, and are never inspected.
our $Backend = <<'_EOC_';
    location /backend/ {
        strata off;
        return 200 "backend uri=$request_uri len=$content_length\n";
    }
_EOC_

add_block_preprocessor(sub {
    my $block = shift;

    if (!defined $block->http_config) {
        $block->set_value("http_config", $HttpConfig);
    } elsif ($block->http_config !~ /strata_metrics_file/) {
        $block->set_value("http_config", $block->http_config . "\n    strata_metrics_file \$TEST_NGINX_SERVER_ROOT/logs/metrics;\n");
    }

    if (defined $block->config && !defined $block->no_backend
        && $block->config !~ m{location /backend/})
    {
        $block->set_value("config", $block->config . $Backend);
    }

    # Under Valgrind, Test::Nginx restarts nginx asynchronously and retries
    # socket requests, but not the curl requests of "--- http2" blocks.
    # The module's HTTP/2 paths stay covered there by the raw-frame tests.
    if ($ENV{TEST_NGINX_USE_VALGRIND} && defined $block->http2) {
        $block->set_value("SKIP", 1);
    }

    # Valgrind slows nginx so much that paced writes are already buffered
    # when it reads: which body-read path runs is then timing, not code.
    # Keep the response and error checks, drop the path assertions.
    if ($ENV{TEST_NGINX_USE_VALGRIND} && defined $block->raw_request_middle_delay
        && defined $block->error_log)
    {
        $block->set_value("error_log", undef);
    }

    # Valgrind runs libstrata 20-50 times slower: any CPU budget sized for
    # native code would turn requests into fail-mode cases. The suites that
    # exceed the budget on purpose (t/060) do not run under Valgrind.
    if ($ENV{TEST_NGINX_USE_VALGRIND}) {
        for my $k ("http_config", "config") {
            my $v = $block->$k;
            next unless defined $v;
            $v =~ s/strata_cpu_budget\s+\S+;/strata_cpu_budget 60s;/g;
            $block->set_value($k, $v);
        }
        if ($block->http_config !~ /strata_cpu_budget/) {
            $block->set_value("http_config", $block->http_config . "\n    strata_cpu_budget 60s;\n");
        }
    }

    # ASan + UBSan run libstrata several times slower, and the machine may
    # be busy (a fuzz run): a request near the default budget (2 ms) then
    # falls into the fail mode by chance, not by code. Raise the default
    # only; a block that sets strata_cpu_budget itself keeps it.
    if ($ENV{ASAN_OPTIONS} && !$ENV{TEST_NGINX_USE_VALGRIND}
        && $block->http_config !~ /strata_cpu_budget/
        && (!defined $block->config || $block->config !~ /strata_cpu_budget/))
    {
        $block->set_value("http_config", $block->http_config . "\n    strata_cpu_budget 1s;\n");
    }

    # A short timeout on a stream that never ends ("--- abort") is how long
    # the test reads before it stops; under Valgrind the first bytes alone
    # take longer than that.
    if ($ENV{TEST_NGINX_USE_VALGRIND} && defined $block->abort
        && defined $block->timeout && $block->timeout < 5)
    {
        $block->set_value("timeout", 5);
    }

    if (!defined $block->request && !defined $block->raw_request
        && !defined $block->must_die)
    {
        $block->set_value("request", "GET /t");
    }
});

no_long_string();
log_level('debug');

1;

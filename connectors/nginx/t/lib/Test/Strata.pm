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
    strata_bundle_dir    $TEST_NGINX_STRATA_FIXTURES/bundle;
    strata_bundle_pubkey $TEST_NGINX_STRATA_FIXTURES/bundle.pub;
    strata_node_id       web-01;
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

    if (!defined $block->request && !defined $block->raw_request
        && !defined $block->must_die)
    {
        $block->set_value("request", "GET /t");
    }
});

no_long_string();
log_level('debug');

1;

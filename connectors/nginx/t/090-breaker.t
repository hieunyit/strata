# W11-N-01: worker circuit breaker (nginx-module.md › Circuit breaker cấp
# worker). Mass engine panics open the breaker, the worker runs degraded
# (protocol layer only, STRATA_TXF_DEGRADED), half-open closes it again once
# the errors stop, a failing half-open reopens it for twice as long, and
# requests over the CPU budget never open it.
#
# Drives nginx itself, like t/060-fail-mode-events.t: one worker, so the
# breaker state seen by the requests is the one of the metrics slot. Needs
# TEST_NGINX_LOAD_MODULES, TEST_NGINX_STRATA_COMPILE and nginx in PATH (see
# `make test-nginx`); libstrata built with test-hooks (STRATA-TEST-BLOCK,
# STRATA-TEST-PANIC).

use strict;
use warnings;

use Cwd qw(abs_path);
use File::Basename qw(dirname);
use File::Path qw(make_path remove_tree);
use HTTP::Tiny;
use IO::Socket::INET;
use POSIX qw(WNOHANG _exit);
use Test::More;
use Time::HiRes qw(sleep time);

plan skip_all => "real master/workers do not run under the valgrind harness"
    if $ENV{TEST_NGINX_USE_VALGRIND};

my $module = $ENV{TEST_NGINX_LOAD_MODULES}
    or plan skip_all => "TEST_NGINX_LOAD_MODULES not set";
my $mk = $ENV{TEST_NGINX_STRATA_MKBUNDLE}
    or plan skip_all => "TEST_NGINX_STRATA_MKBUNDLE not set";
my $compiler = $ENV{TEST_NGINX_STRATA_COMPILE}
    or plan skip_all => "TEST_NGINX_STRATA_COMPILE not set";

my $here     = abs_path(dirname(__FILE__));
my $fixtures = "$here/fixtures";
my $repo     = abs_path("$here/../../..");
my $root     = "$here/servroot-breaker";

# metrics counters (docs/design/control-file.md)
use constant { C_BUDGET => 10, C_BREAKER => 21, C_OPENS => 22, C_DEGRADED => 23 };

# 2% of at least 20 requests within 1 s; open 2 s (4 s, 8 s... on reopen)
my $threshold = "2% 1s 20 open=2s";

my ($port, $pid);
my $http = HTTP::Tiny->new(timeout => 10, keep_alive => 0);

sub run { system(@_) == 0 or die "command failed: @_\n" }

sub errlog {
    open my $fh, "<", "$root/logs/error.log" or return "";
    local $/;
    return <$fh>;
}

sub count { my @m = (errlog() =~ /$_[0]/g); scalar @m }

sub free_port {
    my $s = IO::Socket::INET->new(Listen => 1, LocalAddr => "127.0.0.1",
                                  LocalPort => 0, ReuseAddr => 1) or die $!;
    my $p = $s->sockport;
    close $s;
    return $p;
}

sub bundle {
    my ($rules) = @_;
    open my $fh, ">", "$root/policies.yaml" or die $!;
    print $fh "policies:\n  - { name: example-api, mode: enforce }\n";
    close $fh;
    my $r = join " ", map { "--rules $_" } @$rules;
    run("$compiler $r --policies $root/policies.yaml --key $fixtures/test.key"
        . " --version 7 --out $root/bundles/bundle-7.sbn 2>/dev/null");
    run($mk, "control", "--out", "$root/control", "--generation", 2,
        "--version", 7, "--name", "bundle-7.sbn");
}

sub write_conf {
    my ($breaker) = @_;
    open my $fh, ">", "$root/conf/nginx.conf" or die $!;
    print $fh <<"_EOC_";
load_module $module;
worker_processes 1;
daemon off;
pid logs/nginx.pid;
error_log logs/error.log notice;
events { worker_connections 128; }
thread_pool default threads=2;

http {
    access_log off;
    client_max_body_size 4m;
    client_body_buffer_size 4m;
    strata_control_file  $root/control;
    strata_bundle_dir    $root/bundles;
    strata_bundle_pubkey $fixtures/bundle.pub;
    strata_bundle_check  50ms;
    strata_event_socket  unix:$root/events.sock;
    strata_metrics_file  $root/metrics;
    strata_request_body_limit 4m;
    $breaker

    server {
        listen 127.0.0.1:$port;
        add_header X-Action \$strata_action always;
        add_header X-Id \$strata_block_id always;

        location /t      { strata on; strata_policy example-api; strata_fail_mode open;
                           proxy_pass http://127.0.0.1:$port/backend/; }
        location /reject { strata on; strata_policy example-api; strata_fail_mode open;
                           strata_breaker_action reject;
                           proxy_pass http://127.0.0.1:$port/backend/; }
        location /budget { strata on; strata_policy example-api; strata_cpu_budget 1ms;
                           proxy_pass http://127.0.0.1:$port/backend/; }

        location /backend/ { strata off; return 200 "ok\\n"; }
    }
}
_EOC_
    close $fh;
}

sub start {
    $pid = fork() // die "fork: $!";
    if ($pid == 0) {
        open STDERR, ">>", "$root/logs/stderr.log";
        exec "nginx", "-p", "$root/", "-c", "conf/nginx.conf";
        _exit(127);
    }
    my $deadline = time + 15;
    while (time < $deadline) {
        my $r = $http->get("http://127.0.0.1:$port/backend/");
        return if $r->{status} == 200;
        sleep 0.05;
    }
    die "nginx did not start: " . errlog();
}

sub stop {
    return unless $pid;
    kill "QUIT", $pid;
    my $deadline = time + 10;
    while (time < $deadline) {
        return $pid = undef if waitpid($pid, WNOHANG) == $pid;
        sleep 0.05;
    }
    kill "KILL", $pid;
    waitpid($pid, 0);
    $pid = undef;
}

END { stop() }

sub setup {
    my ($rules, $breaker) = @_;
    stop();
    remove_tree($root);
    make_path("$root/conf", "$root/logs", "$root/bundles");
    $port = free_port();
    bundle($rules);
    write_conf($breaker);
    start();
    sleep 0.3;
}

sub req {
    my ($path, $body) = @_;
    return $http->request($body ? "POST" : "GET", "http://127.0.0.1:$port$path",
        $body ? { content => $body,
                  headers => { "content-type" => "application/x-www-form-urlencoded" } }
              : {});
}

# the counters of the only worker, once the last request was counted
sub metrics {
    sleep 0.1;
    open my $fh, "<:raw", "$root/metrics" or die "metrics: $!";
    local $/;
    my $f = <$fh>;
    my ($n) = unpack "L<", substr $f, 20, 4;
    return [ unpack "Q<$n", substr $f, 64, 8 * $n ];
}

sub panics { req("/t?STRATA-TEST-PANIC") for 1 .. $_[0] }

# ---------------------------------------------------------------------------

setup([], "strata_breaker_threshold $threshold;");

subtest "closed: full engine" => sub {
    is(req("/t")->{status}, 200, "clean request passes");
    is(req("/t?STRATA-TEST-BLOCK")->{status}, 403, "stub rule blocks");
    is(metrics()->[C_BREAKER], 0, "breaker closed");
};

subtest "mass panics open the breaker" => sub {
    my $t0 = time;
    my $r = req("/t?STRATA-TEST-PANIC");
    is($r->{status}, 200, "a panic fails open");
    is($r->{headers}{"x-action"}, "error", "as an engine error");
    panics(39);    # fast: at least 20 of them fall in one 1 s window
    ok(time - $t0 < 10, "within 10 seconds");
    is(metrics()->[C_BREAKER], 1, "breaker open");
    is(metrics()->[C_OPENS], 1, "opened once");
    is(count(qr/strata: circuit breaker open, \d+ internal errors in \d+ requests, degraded mode/),
       1, "logged once");
};

subtest "open: degraded mode" => sub {
    my $d0 = metrics()->[C_DEGRADED];
    my $r = req("/t?STRATA-TEST-PANIC");
    is($r->{status}, 200, "the full engine does not run: no panic");
    is($r->{headers}{"x-action"}, "allow", "no engine error");
    is(req("/t?STRATA-TEST-BLOCK")->{status}, 200, "rules of the full engine skipped");
    is(req("/t/a/%2e%2e/b")->{status}, 403, "protocol layer still blocks");
    my $rj = req("/reject");
    is($rj->{status}, 503, "strata_breaker_action reject: 503");
    like($rj->{headers}{"x-id"} // "", qr/^EVT-/, "with an Event ID");
    is(metrics()->[C_DEGRADED] - $d0, 4, "every request degraded and counted");
};

subtest "half-open with errors reopens for twice as long" => sub {
    sleep 2.1;
    # 1 request in 20 goes to the full engine in half-open: the first one
    is(req("/t?STRATA-TEST-PANIC")->{headers}{"x-action"}, "error",
       "half-open: a sampled request reaches the full engine");
    is(metrics()->[C_BREAKER], 2, "half-open");
    req("/t") for 1 .. 5;
    sleep 1.1;
    req("/t");
    is(metrics()->[C_BREAKER], 1, "open again after the window");
    is(metrics()->[C_OPENS], 2, "opened twice");
    sleep 2.5;
    req("/t");
    is(metrics()->[C_BREAKER], 1, "still open after 2.5 s: open for 4 s now");
};

subtest "half-open without errors closes" => sub {
    sleep 1.6;
    is(req("/t")->{status}, 200, "half-open");
    is(metrics()->[C_BREAKER], 2, "half-open state");
    req("/t") for 1 .. 30;
    sleep 1.1;
    req("/t");
    is(metrics()->[C_BREAKER], 0, "closed again");
    is(count(qr/strata: circuit breaker closed/), 1, "logged");
    is(req("/t?STRATA-TEST-BLOCK")->{status}, 403, "full engine again");
};

# ---------------------------------------------------------------------------
# heavy payloads over the CPU budget never open the breaker (CRS rules:
# 100 KB through them takes more than 1 ms)

setup([ glob("$repo/rules/crs/*.yaml") ], "strata_breaker_threshold $threshold;");

subtest "budget exceeded does not count" => sub {
    my $heavy = "q=" . ("%26amp%3B%26lt%3B" x 6_200);
    my $b0 = metrics()->[C_BUDGET];
    is(req("/budget", $heavy)->{status}, 200, "fails open") for 1 .. 25;
    ok(metrics()->[C_BUDGET] - $b0 >= 20, "budget exceeded on the heavy requests");
    is(metrics()->[C_BREAKER], 0, "breaker stays closed");
    is(metrics()->[C_OPENS], 0, "never opened");
};

# ---------------------------------------------------------------------------

setup([], "strata_breaker off; strata_breaker_threshold $threshold;");

subtest "strata_breaker off" => sub {
    panics(30);
    is(metrics()->[C_BREAKER], 0, "stays closed");
    is(req("/t?STRATA-TEST-PANIC")->{headers}{"x-action"}, "error", "full engine");
};

stop();
done_testing();

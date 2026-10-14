# W12-G2-01: per canary group counters in the metrics file (indices 24..49,
# docs/design/control-file.md). A request of a policy with an enforce canary
# counts in its group, inside (enforced) or outside (shadow): requests,
# blocked, logged, upstream 5xx and a latency histogram. Policies without
# canary count in neither.
#
# Drives nginx itself, like t/060-fail-mode-events.t. Needs
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
my $root     = "$here/servroot-canary";

my ($port, $pid, $gen);
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
    my ($rules, $version) = @_;
    $version //= 7;
    open my $fh, ">", "$root/policies.yaml" or die $!;
    print $fh "policies:\n  - { name: example-api, mode: enforce }\n"
        . "  - { name: example-canary, mode: enforce, canary_percent: 50 }\n";
    close $fh;
    my $r = join " ", map { "--rules $_" } @$rules;
    run("$compiler $r --policies $root/policies.yaml --key $fixtures/test.key"
        . " --version $version --out $root/bundles/bundle-$version.sbn 2>/dev/null");
}

# a new control file (generation 2) naming bundle-7
sub control {
    run($mk, "control", "--out", "$root/control", "--generation", 2,
        "--version", 7, "--name", "bundle-7.sbn");
    $gen = 2;
}

# in place, under the seqlock, as the agent writes them
sub seqlock {
    my ($write) = @_;
    open my $fh, "+<:raw", "$root/control" or die $!;
    seek $fh, 16, 0; print $fh pack("Q<", $gen + 1);
    $write->($fh);
    $gen += 2;
    seek $fh, 16, 0; print $fh pack("Q<", $gen);
    close $fh;
}



sub write_conf {
    open my $fh, ">", "$root/conf/nginx.conf" or die $!;
    print $fh <<"_EOC_";
load_module $module;
worker_processes 2;
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

    server {
        listen 127.0.0.1:$port;
        add_header X-Action \$strata_action always;
        add_header X-Id \$strata_block_id always;

        strata_identity \$http_x_user;

        location /c/     { strata on; strata_policy example-canary; strata_fail_mode open;
                           proxy_pass http://127.0.0.1:$port/backend/; }
        location /a/     { strata on; strata_policy example-api; strata_fail_mode open;
                           proxy_pass http://127.0.0.1:$port/backend/; }

        location /backend/ { strata off; return 200 "ok\\n"; }
        location /backend/fail { strata off; return 503; }
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
    stop();
    remove_tree($root);
    make_path("$root/conf", "$root/logs", "$root/bundles");
    $port = free_port();
    bundle([], 7);
    control();
    write_conf();
    start();
    sleep 0.3;
}

sub req {
    my ($path, $user) = @_;
    return $http->request("GET", "http://127.0.0.1:$port$path",
                          { headers => { "x-user" => $user } });
}


sub metrics {
    open my $fh, "<:raw", "$root/metrics" or die "metrics: $!";
    local $/;
    my $f = <$fh>;
    my ($magic, $layout, $slots, $size, $n) = unpack "a8 L< L< L< L<", $f;
    my @sum = (0) x $n;
    for my $s (0 .. $slots - 1) {
        my @c = unpack "Q<$n", substr $f, 64 + $s * $size, 8 * $n;
        next unless $c[0];
        $sum[$_] += $c[$_] for 2 .. $n - 1;
    }
    return { n => $n, size => $size, c => \@sum };
}

# the counters of a group: requests, blocked, logged, upstream 5xx, latency
# buckets (9)
use constant { ENFORCED => 24, SHADOW => 37 };
sub group {
    my ($c, $base) = @_;
    my @h = @$c[$base + 4 .. $base + 12];
    my $h = 0; $h += $_ for @h;
    return { req => $c->[$base], blocked => $c->[$base + 1], logged => $c->[$base + 2],
             x5 => $c->[$base + 3], hist => $h, fast => $h[0] };
}

sub delta {
    my ($code) = @_;
    my $a = metrics()->{c};
    $code->();
    sleep 0.2;
    my $b = metrics()->{c};
    my @d = map { $b->[$_] - $a->[$_] } 0 .. $#$b;
    return { e => group(\@d, ENFORCED), s => group(\@d, SHADOW) };
}

setup();

my $m = metrics();
is($m->{n}, 50, "50 counters");
is($m->{size}, 448, "448-byte slots");

my @users = map { "user-$_" } 0 .. 199;

subtest "clean requests: counted in their group, nothing blocked" => sub {
    my $d = delta(sub { req("/c/ok", $_) for @users });
    ok($d->{e}{req} > 40 && $d->{s}{req} > 40, "both groups ($d->{e}{req} + $d->{s}{req})");
    is($d->{e}{req} + $d->{s}{req}, 200, "every request in one group");
    is($d->{$_}{blocked} + $d->{$_}{logged} + $d->{$_}{x5}, 0, "$_: no block, log, 5xx") for qw(e s);
    is($d->{$_}{hist}, $d->{$_}{req}, "$_: one latency bucket per request") for qw(e s);
    ok($d->{e}{fast} > 0, "local requests in the first bucket (<= 5 ms)");
};

subtest "a matching request: blocked inside the canary, logged outside" => sub {
    my $blocked = 0;
    my $d = delta(sub { $blocked += (req("/c/x?STRATA-TEST-BLOCK", $_)->{status} == 403) for @users });
    is($d->{e}{blocked}, $blocked, "blocked = the 403s");
    is($d->{e}{req}, $blocked, "every enforced request blocked");
    is($d->{s}{logged}, 200 - $blocked, "the others logged");
    is($d->{s}{blocked} + $d->{e}{logged}, 0, "never the other way");
};

subtest "the same user stays in the same group" => sub {
    my $d1 = delta(sub { req("/c/ok", "user-7") for 1 .. 5 });
    my $g = $d1->{e}{req} ? "e" : "s";
    is($d1->{$g}{req}, 5, "5 requests of user-7 in one group");
};

subtest "upstream 5xx" => sub {
    my $d = delta(sub { req("/c/fail", $_) for @users[0 .. 99] });
    is($d->{e}{x5} + $d->{s}{x5}, 100, "every 503 of the upstream counted");
    is($d->{e}{x5}, $d->{e}{req}, "in the group of the request");
};

subtest "a policy without canary counts in neither group" => sub {
    my $d = delta(sub { req("/a/ok", $_) for @users[0 .. 49]; req("/a/x?STRATA-TEST-BLOCK", "u") });
    is($d->{e}{req} + $d->{s}{req}, 0, "no canary counters");
};

stop();
done_testing();

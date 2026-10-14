# W12-N-02: the emergency kill switch. The agent writes the rules to switch
# off into the control file (offset 2128: count, then the IDs at 2136, under
# the seqlock); every worker applies them within a second, without
# reloading the bundle, and again to the engine of a new bundle.
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
my $root     = "$here/servroot-killswitch";

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
    print $fh "policies:\n  - { name: example-api, mode: enforce }\n";
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

sub disable {
    my @ids = @_;
    seqlock(sub {
        my $fh = shift;
        seek $fh, 2128, 0; print $fh pack("L<L<", scalar @ids, 0), pack("L<*", @ids, (0) x (480 - @ids));
    });
}

# points the control file at another bundle file, as an agent install does
sub switch_bundle {
    my ($version) = @_;
    my $name = "bundle-$version.sbn";
    seqlock(sub {
        my $fh = shift;
        seek $fh, 24, 0; print $fh pack("Q<", $version);
        seek $fh, 64, 0; print $fh pack("S<", length $name), $name, "\0" x (256 - length $name);
    });
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

        location /t      { strata on; strata_policy example-api; strata_fail_mode open;
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
    my ($path, $body) = @_;
    return $http->request($body ? "POST" : "GET", "http://127.0.0.1:$port$path",
        $body ? { content => $body,
                  headers => { "content-type" => "application/x-www-form-urlencoded" } }
              : {});
}

# stub rule of test-hooks (STRATA-TEST-BLOCK) and a protocol rule (100011,
# encoded dot segment in the raw path)
use constant { STUB => 899001, DOT => 100011 };

# both workers answer: every connection is new (keep_alive 0)
sub blocked_by_all {
    my ($path) = @_;
    my %s;
    $s{ req($path)->{status} }++ for 1 .. 10;
    return join ",", sort keys %s;
}

# waits up to 1.5 s for every request of path to answer status
sub within {
    my ($path, $status) = @_;
    my $t0 = time;
    while (time - $t0 < 1.5) {
        return time - $t0 if blocked_by_all($path) eq $status;
        sleep 0.05;
    }
    return undef;
}

setup();

subtest "rules on: both block" => sub {
    is(blocked_by_all("/t?STRATA-TEST-BLOCK"), "403", "stub rule");
    is(blocked_by_all("/t/a/%2e%2e/b"), "403", "protocol rule");
};

subtest "disable: every worker within a second, no reload" => sub {
    disable(STUB, 123456);
    my $dt = within("/t?STRATA-TEST-BLOCK", "200");
    ok(defined $dt && $dt <= 1.2, "stub rule off on every worker");
    diag(sprintf "kill switch applied in %.2f s", $dt // -1);
    is(blocked_by_all("/t/a/%2e%2e/b"), "403", "other rules still on");
    like(errlog(), qr/strata: 2 rules disabled by the kill switch/, "logged");
    unlike(errlog(), qr/loading "/, "no bundle load");
};

subtest "a new bundle keeps the rules off" => sub {
    bundle([], 8);
    switch_bundle(8);
    my $t0 = time;
    sleep 0.05 until count(qr/bundle version 8 active/) == 2 || time - $t0 > 5;
    is(count(qr/bundle version 8 active/), 2, "both workers run bundle 8");
    is(blocked_by_all("/t?STRATA-TEST-BLOCK"), "200", "still off on bundle 8");
};

subtest "the protocol layer can be switched off too, and everything back on" => sub {
    disable(DOT);
    ok(defined within("/t/a/%2e%2e/b", "200"), "protocol rule off");
    ok(defined within("/t?STRATA-TEST-BLOCK", "403"), "stub rule back on");
    disable();
    ok(defined within("/t/a/%2e%2e/b", "403"), "every rule back on");
};

subtest "a bad count is ignored, the list in force stays" => sub {
    disable(STUB);
    ok(defined within("/t?STRATA-TEST-BLOCK", "200"), "off");
    seqlock(sub { my $fh = shift; seek $fh, 2128, 0; print $fh pack("L<", 481) });
    sleep 0.5;
    is(blocked_by_all("/t?STRATA-TEST-BLOCK"), "200", "still off");
};

subtest "after a reload, new workers start with the rules off" => sub {
    disable(STUB);
    ok(defined within("/t?STRATA-TEST-BLOCK", "200"), "off");
    my $before = count(qr/start worker process/);
    kill "HUP", $pid;
    my $t0 = time;
    sleep 0.02 until count(qr/start worker process/) >= $before + 2 || time - $t0 > 5;
    # the first requests of the new workers, before their first timer tick
    is(req("/t?STRATA-TEST-BLOCK")->{status}, 200, "first request of a new worker");
    is(blocked_by_all("/t?STRATA-TEST-BLOCK"), "200", "every new worker");
};

stop();
done_testing();

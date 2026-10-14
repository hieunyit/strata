# W12-N-01: replay sampling at the connector. The agent writes the group's
# key to replay.key in the bundle directory, then the rate and key id to the
# control file (offset 4056, under the seqlock); every worker reads the key
# within a second and sends a share of its requests, anonymized by
# libstrata, on the event socket ("\xffSR1" + ReplaySample). No original
# sensitive value leaves the worker.
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
use IO::Select;
use IO::Socket::INET;
use IO::Socket::UNIX;
use Socket qw(SOCK_DGRAM);
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
my $root     = "$here/servroot-replay";

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
    listen_events();
    write_conf();
    start();
    sleep 0.3;
}

my $sock;
sub listen_events {
    unlink "$root/events.sock";
    $sock = IO::Socket::UNIX->new(Type => SOCK_DGRAM, Local => "$root/events.sock")
        or die "event socket: $!";
    chmod 0777, "$root/events.sock";
}

sub req {
    my ($path, $body) = @_;
    return $http->request($body ? "POST" : "GET", "http://127.0.0.1:$port$path",
        $body ? { content => $body,
                  headers => { "content-type" => "application/x-www-form-urlencoded" } }
              : {});
}


my $KEY = "\x5a" x 32;

# as the agent writes them: the key file, then the block
sub sampling {
    my ($rate, $id, $file_id) = @_;
    if ($rate) {
        open my $fh, ">:raw", "$root/bundles/.replay.key.new" or die $!;
        print $fh "SRK1", pack("a16", $file_id // $id), $KEY;
        close $fh;
        rename "$root/bundles/.replay.key.new", "$root/bundles/replay.key" or die $!;
    }
    seqlock(sub {
        my $fh = shift;
        seek $fh, 4056, 0; print $fh pack("L<L<a16", $rate, 0, $rate ? $id : "");
    });
}

# the replay samples among the datagrams of the next $wait seconds
sub samples {
    my ($wait) = @_;
    my @out;
    my $sel = IO::Select->new($sock);
    my $deadline = time + ($wait // 0.5);
    while ((my $left = $deadline - time) > 0) {
        last unless $sel->can_read($left);
        my $d;
        $sock->recv($d, 65536);
        push @out, $d if substr($d, 0, 4) eq "\xffSR1";
    }
    return @out;
}

sub varint {
    my ($b, $i) = @_;
    my ($v, $s) = (0, 0);
    while (1) {
        my $c = ord substr $$b, $$i++, 1;
        $v |= ($c & 0x7f) << $s;
        return $v if $c < 0x80;
        $s += 7;
    }
}

# field number => value of a flat message
sub fields {
    my ($d) = @_;
    my $b = substr $d, 4;
    my ($i, %f) = (0);
    while ($i < length $b) {
        my $tag = varint(\$b, \$i);
        my ($n, $wt) = ($tag >> 3, $tag & 7);
        if ($wt == 0) { $f{$n} = varint(\$b, \$i); next }
        my $len = varint(\$b, \$i);
        $f{$n} = substr $b, $i, $len;
        $i += $len;
    }
    return \%f;
}

my $q = "/t/verify?user=alice%40example.test&q=1%27%20OR%201%3D1&token=abc123";
my $form = "password=hunter2&phone=0912345678&comment=%27+UNION+SELECT+1--";

sub sensitive_req {
    return $http->request("POST", "http://127.0.0.1:$port$q", {
        content => $form,
        headers => { "content-type" => "application/x-www-form-urlencoded",
                     "authorization" => "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln",
                     "cookie" => "sid=s3cr3t; theme=dark",
                     "x-forwarded-for" => "203.0.113.9" } });
}

setup();

subtest "off by default: no sample" => sub {
    is(sensitive_req()->{status}, 200, "request");
    is(scalar samples(), 0, "nothing sampled");
};

subtest "every request, anonymized, within a second" => sub {
    sampling(10000, "kq7v2");
    my $t0 = time;
    my @s;
    while (time - $t0 < 1.5 && !@s) {
        sensitive_req();
        @s = samples(0.2);
    }
    ok(@s, "a sample");
    diag(sprintf "sampling on after %.2f s", time - $t0);
    like(errlog(), qr/strata: replay sampling 10000 bp, key "kq7v2"/, "logged");
    my $f = fields($s[0]);
    is($f->{1}, "kq7v2", "key id");
    is($f->{4}, "example-api", "policy");
    is($f->{5}, "POST", "method");
    # the client address (127.0.0.1) is a token; Host, the server's, stays
    like($f->{10}, qr/^~h:[0-9a-f]{16}:s9$/, "client address is a token");
    is($f->{13}, length $form, "body length");
    my $all = $s[0];
    for my $secret ("alice\@example.test", "alice%40example.test", "abc123", "hunter2", "0912345678",
                    "eyJhbGciOiJIUzI1NiJ9", "s3cr3t", "203.0.113.9") {
        unlike($all, qr/\Q$secret\E/, "no $secret");
    }
    for my $kept ("q=1%27%20OR%201%3D1", "comment=%27+UNION+SELECT+1--", "theme=~h:", "Bearer ~h:") {
        like($all, qr/\Q$kept\E/, "kept: $kept");
    }
    # every worker samples every request
    my @more;
    for (1 .. 10) { sensitive_req() }
    @more = samples(0.5);
    is(scalar @more, 10, "10 requests, 10 samples");
};

subtest "a key file of another key id: sampling off" => sub {
    sampling(10000, "knew1", "kold0");
    my $t0 = time;
    sleep 0.05 until count(qr/replay key "knew1" not usable/) >= 2 || time - $t0 > 3;
    is(count(qr/replay key "knew1" not usable/), 2, "both workers refuse it");
    samples(0.3);
    sensitive_req();
    is(scalar samples(), 0, "nothing sampled");
};

subtest "off again" => sub {
    sampling(10000, "kq7v2");
    sleep 1.2;
    samples(0.3);
    sampling(0, "");
    sleep 1.2;
    samples(0.3);
    sensitive_req() for 1 .. 5;
    is(scalar samples(), 0, "rate 0: nothing sampled");
};

stop();
done_testing();

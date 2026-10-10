# Bundle hot reload with a real master and two workers.
#
# Test::Nginx cannot change files between the requests of one block, so this
# suite drives nginx itself: it compiles bundles with strata-compile,
# publishes them with mkbundle (seqlock updates of the control file, in
# place) and watches the error log of every worker. Needs
# TEST_NGINX_LOAD_MODULES, TEST_NGINX_STRATA_MKBUNDLE, TEST_NGINX_STRATA_COMPILE
# and nginx in PATH (see `make test-nginx`).

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
my $root     = "$here/servroot-reload";
my $workers  = 2;

my ($port, $pid, $gen);
my $http = HTTP::Tiny->new(timeout => 5, keep_alive => 0);

sub run {
    system(@_) == 0 or die "command failed: @_\n";
}

sub bundle {
    my ($version, %o) = @_;
    my $name = $o{name} // "bundle-$version.sbn";
    my $mode = $o{mode} // "shadow";
    my $pol = "$root/policies-$mode.yaml";
    open my $fh, ">", $pol or die $!;
    print $fh "policies: [{ name: example-api, mode: $mode }]\n",
              "block_page: { html: '<p>page v$version {{block_id}} {{support_contact}}</p>',",
              " support_contact: 'contact v$version' }\n";
    close $fh;
    run("$compiler --policies $pol --key $fixtures/" . ($o{key} // "test.key")
        . " --version $version" . ($o{rollback} ? " --rollback" : "")
        . " --out $root/bundles/$name 2>/dev/null");
    return $name;
}

# seqlock update of the control file, in place
sub publish {
    my ($name, %o) = @_;
    $gen += 2;
    run($mk, "control", "--in-place", "--out", "$root/control",
        "--generation", $gen, "--version", 0, "--name", $name,
        ($o{writing} ? ("--writing") : ()));
}

sub errlog {
    open my $fh, "<", "$root/logs/error.log" or return "";
    local $/;
    return <$fh>;
}

sub count {
    my ($re) = @_;
    my @m = (errlog() =~ /$re/g);
    return scalar @m;
}

# waits until $re appears $n times in the error log
sub wait_log {
    my ($re, $n, $what) = @_;
    my $deadline = time + 10;
    while (time < $deadline) {
        return pass($what) if count($re) >= $n;
        sleep 0.05;
    }
    fail($what);
    diag("expected $n x $re, got " . count($re));
}

sub get {
    my ($path) = @_;
    return $http->get("http://127.0.0.1:$port$path");
}

sub versions_seen {
    my %v;
    for (1 .. 30) {
        my $r = get("/t");
        $v{ $r->{headers}{'x-bundle'} // 'none' }++;
    }
    return join ",", sort keys %v;
}

sub free_port {
    my $s = IO::Socket::INET->new(Listen => 1, LocalAddr => "127.0.0.1",
                                  LocalPort => 0, ReuseAddr => 1) or die $!;
    my $p = $s->sockport;
    close $s;
    return $p;
}

sub write_conf {
    my ($extra) = @_;
    open my $fh, ">", "$root/conf/nginx.conf" or die $!;
    print $fh <<"_EOC_";
load_module $module;
worker_processes $workers;
daemon off;
pid logs/nginx.pid;
error_log logs/error.log notice;
events { worker_connections 128; }
thread_pool default threads=2;

http {
    access_log off;
    strata_control_file  $root/control;
    strata_bundle_dir    $root/bundles;
    strata_bundle_pubkey $fixtures/bundle.pub;
    strata_bundle_check  50ms;
    $extra

    server {
        listen 127.0.0.1:$port;

        location /t {
            strata on;
            add_header X-Bundle \$strata_bundle_version always;
            add_header X-Action \$strata_action always;
            proxy_pass http://127.0.0.1:$port/backend/;
        }

        location /stream {
            strata on;
            strata_policy example-api;
            strata_request_body_mode stream;
            add_header X-Action \$strata_action always;
            proxy_pass http://127.0.0.1:$port/backend/;
        }

        location /backend/ {
            strata off;
            return 200 "ok\\n";
        }
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
    my $deadline = time + 10;
    while (time < $deadline) {
        my $r = get("/backend/");
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

sub fresh {
    stop();
    remove_tree($root);
    make_path("$root/conf", "$root/logs", "$root/bundles");
    $port = free_port();
    $gen = 2;
}

# ---------------------------------------------------------------------------

fresh();
bundle(1);
run($mk, "control", "--out", "$root/control", "--generation", $gen,
    "--version", 1, "--name", "bundle-1.sbn");
write_conf("");
start();

is(versions_seen(), "1", "started with the bundle named by the control file");
is(get("/t?STRATA-TEST-BLOCK")->{status}, 403, "test rule blocks with bundle 1");

# a new version reaches every worker
publish(bundle(2));
wait_log(qr/bundle version 2 active/, $workers, "every worker activates v2");
is(versions_seen(), "2", "requests use v2");
like(get("/t?STRATA-TEST-BLOCK")->{content}, qr/^<p>page v2 STR-\S+ contact v2<\/p>$/,
     "block page and support contact come from the new bundle");
wait_log(qr/bundle version 1 released, unmapping/, $workers,
         "every worker unmaps v1");

# bad signature: keep v2
publish(bundle(3, key => "other.key"));
wait_log(qr/bundle-3\.sbn" rejected \(5\): bad bundle signature, keeping/,
         $workers, "bad signature is rejected by every worker");
is(versions_seen(), "2", "still v2 after a bad signature");

# older version without the signed rollback flag: keep v2
publish(bundle(1, name => "old-1.sbn"));
wait_log(qr/version 1 is not newer than 2 and not a signed rollback/, $workers,
         "older version is refused");
is(versions_seen(), "2", "still v2 after an older bundle");

# same version again: refused too, nothing to do
publish(bundle(2, name => "again-2.sbn"));
wait_log(qr/version 2 is not newer than 2/, $workers, "same version is refused");

# signed rollback to v1
publish(bundle(1, name => "rollback-1.sbn", rollback => 1));
wait_log(qr/bundle version 1 active \(generation \d+\), rollback/, $workers,
         "signed rollback is accepted");
is(versions_seen(), "1", "requests use the rolled back v1");

# a writer that died mid-update (odd generation) is ignored...
my $before = count(qr/active/);
publish(bundle(5), writing => 1);
sleep 0.5;
is(count(qr/active/), $before, "odd generation is ignored");
is(versions_seen(), "1", "still v1 while the control file is being written");

# ...until the update completes
run($mk, "control", "--in-place", "--out", "$root/control",
    "--generation", $gen, "--version", 0, "--name", "bundle-5.sbn");
wait_log(qr/bundle version 5 active/, $workers, "completed update is loaded");

# missing bundle file: keep v5
publish("missing-9.sbn");
wait_log(qr/open\("[^"]*missing-9\.sbn"\) failed/, $workers,
         "missing bundle file is reported");
is(versions_seen(), "5", "still v5 after a missing file");

# a request in flight keeps its bundle mapped until it ends
{
    my $s = IO::Socket::INET->new(PeerAddr => "127.0.0.1", PeerPort => $port)
        or die $!;
    print $s "POST /t HTTP/1.1\r\nHost: localhost\r\nContent-Length: 10\r\n"
           . "Connection: close\r\n\r\n12345";
    sleep 0.3;                                   # tx created on v5

    my $released = count(qr/bundle version 5 released/);
    publish(bundle(6));
    wait_log(qr/bundle version 6 active/, $workers, "v6 active with a request "
             . "in flight");
    sleep 0.3;
    is(count(qr/bundle version 5 released/), $released + $workers - 1,
       "the worker serving the request still holds v5");

    print $s "67890";
    local $/;
    my $resp = <$s>;
    like($resp, qr/^HTTP\/1\.1 200/, "in-flight request completes");
    like($resp, qr/X-Bundle: 5\r\n/, "in-flight request was inspected with v5");
    wait_log(qr/bundle version 5 released/, $released + $workers,
             "v5 is unmapped once the request is done");
}

# old bundle files may be unlinked: the mapping stays valid until released
unlink glob("$root/bundles/bundle-[1-5].sbn");
is(versions_seen(), "6", "still serving after old files were unlinked");
is(get("/t?STRATA-TEST-BLOCK")->{status}, 403, "and still blocking");

# reload under load: requests never fail while bundles change
{
    my $kid = fork() // die "fork: $!";
    if ($kid == 0) {
        my ($ok, $bad) = (0, 0);
        my $until = time + 3;
        while (time < $until) {
            my $r = get("/t");
            my $b = get("/t?STRATA-TEST-BLOCK");
            ($r->{status} == 200 && ($r->{headers}{'x-bundle'} // '') =~ /^\d+$/
             && $b->{status} == 403) ? $ok++ : $bad++;
        }
        # _exit: a plain exit would run END and stop the parent's nginx
        _exit($bad == 0 && $ok > 50 ? 0 : 1);
    }
    for my $v (7 .. 16) {
        publish(bundle($v));
        sleep 0.2;
    }
    waitpid($kid, 0);
    is($? >> 8, 0, "no failed request while ten bundles were published");
    wait_log(qr/bundle version 16 active/, $workers, "last bundle is active");
}

# the policy of a "stream" location becomes enforce: warn, stay in shadow
publish(bundle(17, mode => "enforce"));
wait_log(qr/location "\/stream" uses "strata_request_body_mode stream".*the location stays in shadow/,
         $workers, "every worker warns about the stream location");
{
    my $r = $http->request("POST", "http://127.0.0.1:$port/stream",
                           { content => "x=STRATA-TEST-BLOCK" });
    is($r->{status}, 200, "stream location is not blocked by an enforce policy");
    is($r->{headers}{'x-action'}, "log", "it only logs");
}

my $log = errlog();
unlike($log, qr/\[(alert|crit|emerg)\]/, "no alert in the error log");
unlike($log, qr/exited on signal/, "no worker crashed");

# nginx -s reload is refused while the current bundle enforces the policy of
# a "stream" location; the running workers keep serving
{
    write_conf("# reloaded");
    kill "HUP", $pid;
    wait_log(qr/\[emerg\].*location "\/stream" uses "strata_request_body_mode stream"/, 1,
             "reload with a stream location under an enforce policy is refused");
    is(versions_seen(), "17", "old workers keep serving v17");
}

# with a shadow policy again, the reload goes through and the new workers
# start from the bundle the control file names
{
    publish(bundle(18));
    wait_log(qr/bundle version 18 active/, $workers, "v18 active");
    kill "HUP", $pid;
    wait_log(qr/start worker process/, 2 * $workers, "workers restarted");
    sleep 0.5;
    is(versions_seen(), "18", "reload maps the current bundle again");
}

# no control file at start: fail mode, then the control file appears
{
    fresh();
    bundle(1);
    write_conf("");
    start();
    is(get("/t")->{headers}{'x-action'}, "error", "no control file: fail mode");

    run($mk, "control", "--out", "$root/control", "--generation", 2,
        "--version", 1, "--name", "bundle-1.sbn");
    wait_log(qr/control file "[^"]*" mapped/, $workers,
             "workers map the control file once it exists");
    wait_log(qr/bundle version 1 active/, $workers, "and load its bundle");
    is(versions_seen(), "1", "requests use it");
}

stop();
done_testing();

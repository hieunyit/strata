# HTTP/3 (W08-N-01): the module inspects requests arriving over HTTP/3 the
# same way as HTTP/1 and HTTP/2.
#
# Needs an NGINX built with --with-http_v3_module against quictls
# (`make nginx-h3` / `make test-nginx-h3`) and the CryptX Perl modules for the
# pure-Perl QUIC client (t/lib/Test/Strata/HTTP3.pm). Like t/004-reload.t this
# drives nginx itself rather than through the Test::Nginx::Socket harness,
# because the client speaks QUIC over UDP.

use strict;
use warnings;

use FindBin;
use lib "$FindBin::Bin/lib";

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

my $nginx = $ENV{TEST_NGINX_STRATA_H3_NGINX}
    or plan skip_all => "TEST_NGINX_STRATA_H3_NGINX not set (run: make test-nginx-h3)";
my $module = $ENV{TEST_NGINX_STRATA_H3_MODULE}
    or plan skip_all => "TEST_NGINX_STRATA_H3_MODULE not set";
-x $nginx or plan skip_all => "HTTP/3 nginx not built: $nginx";
my $mk = $ENV{TEST_NGINX_STRATA_MKBUNDLE} or plan skip_all => "TEST_NGINX_STRATA_MKBUNDLE not set";
my $compiler = $ENV{TEST_NGINX_STRATA_COMPILE} or plan skip_all => "TEST_NGINX_STRATA_COMPILE not set";

eval { require Test::Strata::HTTP3; 1 }
    or plan skip_all => "Test::Strata::HTTP3 did not load: $@";
eval { require Crypt::PK::X25519; 1 }
    or plan skip_all => "CryptX not installed (needed by the QUIC client)";

my $here     = abs_path(dirname(__FILE__));
my $fixtures = "$here/fixtures";
my $root     = "$here/servroot-http3";

my ($qport, $tcpport, $pid);
my $http = HTTP::Tiny->new(timeout => 5);

sub free_port {
    my $s = IO::Socket::INET->new(Listen => 1, LocalAddr => "127.0.0.1",
                                  LocalPort => 0, ReuseAddr => 1) or die $!;
    my $p = $s->sockport;
    close $s;
    return $p;
}

sub errlog {
    open my $fh, "<", "$root/logs/error.log" or return "";
    local $/;
    return <$fh>;
}

sub run { system(@_) == 0 or die "command failed: @_\n" }

sub write_conf {
    open my $fh, ">", "$root/conf/nginx.conf" or die $!;
    print $fh <<"_EOC_";
load_module $module;
worker_processes 1;
daemon off;
pid logs/nginx.pid;
error_log logs/error.log info;
events { worker_connections 64; }

http {
    access_log off;
    strata_control_file  $root/control;
    strata_bundle_dir    $root/bundles;
    strata_bundle_pubkey $fixtures/bundle.pub;

    # readiness probe and the proxied backend, on plain HTTP; not inspected.
    # strata runs at PREACCESS, so /t must reach a real content handler
    # (proxy_pass), not a rewrite-phase "return" that short-circuits first.
    server {
        listen 127.0.0.1:$tcpport;
        location /ping     { strata off; return 200 "ok\\n"; }
        location /backend/ { strata off; return 200 "ok\\n"; }
    }

    server {
        listen 127.0.0.1:$qport quic reuseport;
        listen 127.0.0.1:$qport ssl;
        server_name localhost;

        ssl_certificate     $root/cert.pem;
        ssl_certificate_key $root/key.pem;
        ssl_protocols TLSv1.3;
        http3 on;

        location /t {
            strata on;
            add_header X-Action    \$strata_action    always;
            add_header X-Block-Id  \$strata_block_id   always;
            proxy_pass http://127.0.0.1:$tcpport/backend/;
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
        exec($nginx, "-p", "$root/", "-c", "conf/nginx.conf") or _exit(127);
    }
    my $deadline = time + 10;
    while (time < $deadline) {
        my $r = $http->get("http://127.0.0.1:$tcpport/ping");
        return if $r->{status} == 200;
        sleep 0.1;
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

# One HTTP/3 GET; returns the :status of the response HEADERS frame and the
# strata action header, or undef on a handshake/transport failure.
sub h3_get {
    my ($path) = @_;
    my $s = eval { Test::Strata::HTTP3->new($qport, sni => "localhost") };
    return undef unless $s;
    my $sid = $s->new_stream({ path => $path });
    my $frames = eval { $s->read(all => [{ sid => $sid, fin => 1 }]) } || [];
    my ($h) = grep { ($_->{type} // "") eq "HEADERS" } @$frames;
    return undef unless $h;
    return ($h->{headers}{':status'}, $h->{headers});
}

# One HTTP/3 POST, the body sent as several DATA frames.
sub h3_post {
    my ($path, $body, $split) = @_;
    my $s = eval { Test::Strata::HTTP3->new($qport, sni => "localhost") };
    return undef unless $s;
    my $sid = $s->new_stream({ method => "POST", path => $path, body => $body,
                               body_split => $split });
    my $frames = eval { $s->read(all => [{ sid => $sid, fin => 1 }]) } || [];
    my ($h) = grep { ($_->{type} // "") eq "HEADERS" } @$frames;
    return undef unless $h;
    return ($h->{headers}{':status'}, $h->{headers});
}

# retries the first request until the QUIC listener answers
sub h3_get_ready {
    my ($path) = @_;
    my $deadline = time + 10;
    while (time < $deadline) {
        my ($status, $hdr) = h3_get($path);
        return ($status, $hdr) if defined $status;
        sleep 0.2;
    }
    return undef;
}

# ---------------------------------------------------------------------------

stop();
remove_tree($root);
make_path("$root/conf", "$root/logs", "$root/bundles");
$qport   = free_port();
$tcpport = free_port();

# self-signed cert for the QUIC/TLS listener (the client does not verify it)
run("openssl req -x509 -newkey rsa:2048 -nodes -keyout $root/key.pem"
    . " -out $root/cert.pem -days 2 -subj /CN=localhost 2>/dev/null");

# a signed bundle so a policy is active; STRATA-TEST-BLOCK is the built-in
# stub rule and blocks regardless of the bundle's own rules
open my $pol, ">", "$root/policies.yaml" or die $!;
print $pol "policies: [{ name: example-api, mode: enforce }]\n";
close $pol;
run("$compiler --policies $root/policies.yaml --key $fixtures/test.key"
    . " --version 1 --out $root/bundles/bundle-1.sbn 2>/dev/null");
run($mk, "control", "--out", "$root/control", "--generation", 2,
    "--version", 1, "--name", "bundle-1.sbn");

write_conf();
start();

# sanity: the HTTP/3 build really advertises v3
my $v = `$nginx -V 2>&1`;
like($v, qr/--with-http_v3_module/, "nginx built with the HTTP/3 module");

# clean request over HTTP/3 passes and is inspected (allow)
{
    my ($status, $hdr) = h3_get_ready("/t?q=hello");
    ok(defined $status, "HTTP/3 handshake and request completed")
        or diag(errlog());
    is($status, "200", "clean HTTP/3 request passes");
    is($hdr->{'x-action'}, "allow", "and was inspected (action allow)");
}

# the same test rule that blocks over HTTP/1 and HTTP/2 blocks over HTTP/3
{
    my ($status, $hdr) = h3_get("/t?STRATA-TEST-BLOCK");
    is($status, "403", "HTTP/3 request with the test string is blocked");
    like($hdr->{'x-block-id'} // "", qr/^STR-/,
        "blocked HTTP/3 request carries a Block ID");
}

# the request body over HTTP/3 (DATA frames) is read and inspected in
# enforce: a clean body passes, the test string in the body (split across
# DATA frames, so only the reassembled body has it) blocks
{
    my $clean = "a=1&b=" . ("x" x 4000);
    my ($status, $hdr) = h3_post("/t", $clean, [1000, 1000]);
    is($status, "200", "clean HTTP/3 POST body passes");
    is($hdr->{'x-action'}, "allow", "and was inspected (action allow)");

    my $bad = ("x" x 3000) . "STRATA-TEST-BLOCK" . ("y" x 100);
    ($status, $hdr) = h3_post("/t", $bad, [3008]);
    is($status, "403", "HTTP/3 POST with the test string in the body is blocked");
    like($hdr->{'x-block-id'} // "", qr/^STR-/, "and carries a Block ID");
}

my $log = errlog();
unlike($log, qr/\[(alert|crit|emerg)\]/, "no alert in the error log");
unlike($log, qr/exited on signal/, "no worker crashed");

stop();
done_testing();

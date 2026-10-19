# RV-N-02: JA4 of the client's TLS connection, from the module's OpenSSL
# message callback through libstrata: $strata_ja4, rules on tls_ja4. The
# client is curl over real TLS, so like t/070-http3.t this drives nginx
# itself rather than through the Test::Nginx::Socket harness.

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

my $module = $ENV{TEST_NGINX_LOAD_MODULES}
    or plan skip_all => "TEST_NGINX_LOAD_MODULES not set";
my $mk = $ENV{TEST_NGINX_STRATA_MKBUNDLE} or plan skip_all => "TEST_NGINX_STRATA_MKBUNDLE not set";
my $compiler = $ENV{TEST_NGINX_STRATA_COMPILE} or plan skip_all => "TEST_NGINX_STRATA_COMPILE not set";
system("curl --version >/dev/null 2>&1") == 0 or plan skip_all => "curl not installed";
`nginx -V 2>&1` =~ /--with-http_ssl_module/
    or plan skip_all => "nginx built without --with-http_ssl_module";

my $here     = abs_path(dirname(__FILE__));
my $fixtures = "$here/fixtures";
my $root     = "$here/servroot-ja4";

my ($tls, $plain, $pid);
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

    server {
        listen 127.0.0.1:$plain;
        location /ping     { strata off; return 200 "ok\\n"; }
        location /backend/ { strata off; return 200 "ok\\n"; }
        location /t {
            strata on;
            strata_policy example-api;
            add_header X-JA4    "\$strata_ja4"   always;
            add_header X-Action \$strata_action always;
            proxy_pass http://127.0.0.1:$plain/backend/;
        }
    }

    server {
        listen 127.0.0.1:$tls ssl;
        http2 on;
        server_name api.example.test;

        ssl_certificate     $root/cert.pem;
        ssl_certificate_key $root/key.pem;

        location /t {
            strata on;
            strata_policy example-api;
            add_header X-JA4    "\$strata_ja4"   always;
            add_header X-Action \$strata_action always;
            add_header X-Rules  \$strata_rules  always;
            proxy_pass http://127.0.0.1:$plain/backend/;
        }
        location /off {
            strata off;
            add_header X-JA4 "\$strata_ja4" always;
            return 200 "off\\n";
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
        exec("nginx", "-p", "$root/", "-c", "conf/nginx.conf") or _exit(127);
    }
    my $deadline = time + 10;
    while (time < $deadline) {
        my $r = $http->get("http://127.0.0.1:$plain/ping");
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

# curl over TLS; returns (status, lowercase headers)
sub curl {
    my (@args) = @_;
    my $out = `curl -sk -o /dev/null -D - --max-time 5 @args 2>&1`;
    my ($status) = $out =~ m{^HTTP/\S+ (\d+)}m;
    my @pairs = $out =~ /^([\w-]+):[ \t]*(.*?)\r?$/mg;
    my %h;
    while (my ($k, $v) = splice(@pairs, 0, 2)) {
        $h{lc $k} = $v;
    }
    return ($status, \%h);
}

stop();
remove_tree($root);
make_path("$root/conf", "$root/logs", "$root/bundles");
$tls   = free_port();
$plain = free_port();

run("openssl req -x509 -newkey rsa:2048 -nodes -keyout $root/key.pem"
    . " -out $root/cert.pem -days 2 -subj /CN=api.example.test 2>/dev/null");

# rule 800819: block a TLS 1.3 client that sent no SNI (prefix t13i)
open my $rules, ">", "$root/rules.yaml" or die $!;
print $rules <<'_EOR_';
ir_version: 1
ruleset: { name: example-ja4-test, version: "1" }
rules:
  - id: 800819
    name: Example JA4 block fixture
    layer: managed
    stage: request_headers
    score: 100
    severity: critical
    action_mode: block_alone
    match:
      all:
        - targets: [{ var: tls_ja4 }]
          operator: { type: begins_with, value: t13i }
    metadata: { source: organization, license: Apache-2.0 }
_EOR_
close $rules;
open my $pol, ">", "$root/policies.yaml" or die $!;
print $pol "policies: [{ name: example-api, mode: enforce }]\n";
close $pol;
run("$compiler --rules $root/rules.yaml --policies $root/policies.yaml"
    . " --key $fixtures/test.key --version 1 --out $root/bundles/bundle-1.sbn");
run($mk, "control", "--out", "$root/control", "--generation", 2,
    "--version", 1, "--name", "bundle-1.sbn");

write_conf();
start();

my $sni = "--resolve api.example.test:$tls:127.0.0.1 https://api.example.test:$tls";
my $ja4 = qr/^t1[0-3][di]\d{4}[0-9a-z]{2}_[0-9a-f]{12}_[0-9a-f]{12}$/;

# curl with SNI and ALPN h2: allowed, its fingerprint in $strata_ja4
my ($status, $h) = curl("$sni/t");
is($status, 200, "TLS request with SNI passes") or diag(errlog());
like($h->{'x-ja4'} // "", qr/^t13d\d{4}h2_/, "JA4 of curl over TLS 1.3, SNI, h2");
like($h->{'x-ja4'} // "", $ja4, "JA4 well formed");
is($h->{'x-action'}, "allow", "inspected and allowed");

# the exact value of the recorded vector, for the same curl and OpenSSL
my $version = `curl --version`;
SKIP: {
    skip "vector recorded with curl 8.5.0 / OpenSSL 3.0.13", 1
        unless $version =~ m{^curl 8\.5\.0 .*OpenSSL/3\.0\.13 };
    is($h->{'x-ja4'}, "t13d3112h2_e8f1e7e78f70_b26ce05bbdd6",
        "JA4 equals engine/tests/vectors/ja4-client-hellos.json (curl, SNI)");
}

# HTTP/1.1 ALPN changes only the ALPN characters; keepalive reuses it
($status, $h) = curl("--http1.1 $sni/t $sni/t");
like($h->{'x-ja4'} // "", qr/^t13d\d{4}h1_/, "ALPN http/1.1 gives h1");

# TLS 1.2 only
($status, $h) = curl("--tlsv1.2 --tls-max 1.2 $sni/t");
like($h->{'x-ja4'} // "", qr/^t12d/, "TLS 1.2 client gives t12");
is($status, 200, "and passes");

# no SNI (IP literal): the rule on tls_ja4 blocks
($status, $h) = curl("https://127.0.0.1:$tls/t");
is($status, 403, "TLS 1.3 without SNI blocked by the rule on tls_ja4");
like($h->{'x-ja4'} // "", qr/^t13i/, "and its JA4 has i");
is($h->{'x-rules'}, "800819", "rule 800819 matched");

# the variable works where strata is off, and is empty without TLS
($status, $h) = curl("$sni/off");
like($h->{'x-ja4'} // "", $ja4, "\$strata_ja4 set with strata off");
my $r = $http->get("http://127.0.0.1:$plain/t");
is($r->{status}, 200, "plain HTTP passes");
is($r->{headers}{'x-ja4'} // "", "", "no JA4 without TLS");
is($r->{headers}{'x-action'}, "allow", "plain HTTP inspected");

unlike(errlog(), qr/\[(alert|emerg|crit)\]/, "no alert in the error log");

stop();
done_testing();

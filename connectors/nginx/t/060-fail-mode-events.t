# W07-N-01: fail mode (4 incidents x 2 modes), events sent to the agent's
# socket, the metrics file, force-shadow from the control file, internal
# redirects.
#
# Like t/004-reload.t this suite drives nginx itself: it reads the metrics
# file and the event datagrams between requests, and edits the control
# file in place. Needs TEST_NGINX_LOAD_MODULES, TEST_NGINX_STRATA_MKBUNDLE,
# TEST_NGINX_STRATA_COMPILE and nginx in PATH (see `make test-nginx`); the
# library is built with test-hooks (STRATA-TEST-BLOCK, STRATA-TEST-PANIC).

use strict;
use warnings;

use Cwd qw(abs_path);
use File::Basename qw(dirname);
use File::Path qw(make_path remove_tree);
use HTTP::Tiny;
use IO::Select;
use IO::Socket::INET;
use IO::Socket::UNIX;
use POSIX qw(WNOHANG _exit);
use Socket qw(SOCK_DGRAM);
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
my $root     = "$here/servroot-events";
my $workers  = 2;

# counters of the metrics file (docs/design/control-file.md)
use constant {
    C_PID => 0, C_BUNDLE => 1, C_ALLOW => 2, C_LOG => 3, C_BLOCK => 5,
    C_BODY => 6, C_OPEN => 7, C_CLOSED => 8, C_DROPPED => 9, C_BUDGET => 10,
    C_NS => 11, C_HIST => 12,
};

my ($port, $pid, $gen, $sock);
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

# --- bundle and control file ------------------------------------------------

sub bundle {
    my ($rules) = @_;
    open my $fh, ">", "$root/policies.yaml" or die $!;
    print $fh "policies:\n",
              "  - { name: example-api, mode: enforce }\n",
              "  - { name: example-web, mode: shadow }\n",
              "  - { name: example-guard, mode: enforce }\n";
    close $fh;
    my $r = join " ", map { "--rules $_" } @$rules;
    run("$compiler $r --policies $root/policies.yaml --key $fixtures/test.key"
        . " --version 7 --out $root/bundles/bundle-7.sbn 2>/dev/null");
    run($mk, "control", "--out", "$root/control", "--generation", 2,
        "--version", 7, "--name", "bundle-7.sbn");
    $gen = 2;
}

# force-shadow fields at 324 (flags), 328 (count), 336 (names, 32 x 56),
# written in place under the seqlock as the agent does
sub force_shadow {
    my ($flags, $count, @names) = @_;
    open my $fh, "+<:raw", "$root/control" or die $!;
    seek $fh, 16, 0; print $fh pack("Q<", $gen + 1);
    seek $fh, 324, 0; print $fh pack("L<L<", $flags, $count);
    seek $fh, 336, 0; print $fh "\0" x (32 * 56);
    for my $i (0 .. $#names) {
        seek $fh, 336 + 56 * $i, 0;
        print $fh substr($names[$i] . ("\0" x 56), 0, 56);
    }
    $gen += 2;
    seek $fh, 16, 0; print $fh pack("Q<", $gen);
    close $fh;
    sleep 0.4;    # strata_bundle_check 50ms, two workers
}

# --- nginx ------------------------------------------------------------------

sub write_conf {
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

        location /t       { strata on; strata_policy example-api;   proxy_pass http://127.0.0.1:$port/backend/; }
        location /guard   { strata on; strata_policy example-guard; proxy_pass http://127.0.0.1:$port/backend/; }
        location /shadow  { strata on; strata_policy example-web;   proxy_pass http://127.0.0.1:$port/backend/; }
        location /open    { strata on; strata_policy example-api; strata_fail_mode open;
                            proxy_pass http://127.0.0.1:$port/backend/; }
        location /closed  { strata on; strata_policy example-api; strata_fail_mode closed;
                            proxy_pass http://127.0.0.1:$port/backend/; }
        location /bopen   { strata on; strata_policy example-api; strata_fail_mode open;
                            strata_cpu_budget 1ms; proxy_pass http://127.0.0.1:$port/backend/; }
        location /bclosed { strata on; strata_policy example-api; strata_fail_mode closed;
                            strata_cpu_budget 1ms; proxy_pass http://127.0.0.1:$port/backend/; }

        # inspected, then an internal redirect (error_page) to /shadow
        location /redir   { strata on; strata_policy example-web;
                            proxy_pass http://127.0.0.1:$port/missing/;
                            proxy_intercept_errors on; error_page 404 = /shadow; }

        location /backend/ { strata off; return 200 "ok\\n"; }
        location /missing/ { strata off; return 404; }
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

sub fresh {
    stop();
    remove_tree($root);
    make_path("$root/conf", "$root/logs", "$root/bundles");
    $port = free_port();
}

sub listen_events {
    unlink "$root/events.sock";
    $sock = IO::Socket::UNIX->new(Type => SOCK_DGRAM, Local => "$root/events.sock")
        or die "event socket: $!";
}

# --- requests, events, metrics ----------------------------------------------

sub req {
    my ($method, $path, $body) = @_;
    return $http->request($method, "http://127.0.0.1:$port$path",
        $body ? { content => $body,
                  headers => { "content-type" => "application/x-www-form-urlencoded" } }
              : {});
}

# every \xffSC1 datagram seen so far: { policy => [requests, partial,
# body_skipped, error, degraded] }
our @policy_counts;

# every datagram that arrives within $wait seconds
sub events {
    my ($wait) = @_;
    my @out;
    my $sel = IO::Select->new($sock);
    my $deadline = time + ($wait // 1);
    while ((my $left = $deadline - time) > 0) {
        last unless $sel->can_read($left);
        my $d;
        $sock->recv($d, 65536);
        # per-policy counts (RV-N-01) are kept apart; replay samples
        # (W12-N-01) are not on here
        if (substr($d, 0, 4) eq "\xffSC1") {
            push @policy_counts, policy_counts(substr $d, 4);
            next;
        }
        push @out, decode($d);
        $deadline = time + 0.2 if @out;    # a little longer for a second one
    }
    return @out;
}

sub varint {
    my ($b, $i) = @_;
    my ($v, $s) = (0, 0);
    while (1) {
        die "truncated varint" if $$i >= length $$b;
        my $c = ord substr($$b, $$i++, 1);
        $v |= ($c & 0x7f) << $s;
        return $v unless $c & 0x80;
        $s += 7;
    }
}

# the fields of strata.event.v1.Event this suite checks
sub policy_counts {
    my ($d) = @_;
    my ($i, %m) = (0);
    while ($i < length $d) {
        my $tag = varint(\$d, \$i);
        my ($f, $wt) = ($tag >> 3, $tag & 7);
        if ($wt == 0) {
            varint(\$d, \$i);
            next;
        }
        my $n = varint(\$d, \$i);
        my $v = substr $d, $i, $n;
        $i += $n;
        next unless $f == 4;
        my ($j, $name, @c) = (0, '', 0, 0, 0, 0, 0);
        while ($j < length $v) {
            my $t = varint(\$v, \$j);
            if (($t & 7) == 0) {
                my $x = varint(\$v, \$j);
                $c[($t >> 3) - 2] = $x if ($t >> 3) >= 2 && ($t >> 3) <= 6;
            } else {
                my $k = varint(\$v, \$j);
                $name = substr $v, $j, $k if ($t >> 3) == 1;
                $j += $k;
            }
        }
        $m{$name} = \@c;
    }
    return \%m;
}

sub policy_total {
    my ($policy, $k) = @_;
    my $t = 0;
    for my $m (@policy_counts) { $t += $m->{$policy}[$k] // 0 }
    return $t;
}

sub decode {
    my ($d) = @_;
    my ($i, %e) = (0);
    $e{size} = length $d;
    while ($i < length $d) {
        my $tag = varint(\$d, \$i);
        my ($f, $wt) = ($tag >> 3, $tag & 7);
        if ($wt == 0) {
            my $v = varint(\$d, \$i);
            $e{status} = $v if $f == 12;
            $e{action} = $v if $f == 13;
        } elsif ($wt == 2) {
            my $n = varint(\$d, \$i);
            my $v = substr $d, $i, $n;
            $i += $n;
            $e{block_id} = $v if $f == 1;
            $e{policy} = $v if $f == 5;
        } else {
            die "wire type $wt";
        }
    }
    return \%e;
}

sub metrics {
    open my $fh, "<:raw", "$root/metrics" or die "metrics: $!";
    local $/;
    my $f = <$fh>;
    my ($magic, $layout, $slots, $size, $n) = unpack "a8 L< L< L< L<", $f;
    my ($nginx, $module, $abi) = unpack "Z16 Z12 L<", substr $f, 32, 32;
    my @sum = (0) x $n;
    for my $s (0 .. $slots - 1) {
        my @c = unpack "Q<$n", substr $f, 64 + $s * $size, 8 * $n;
        next unless $c[C_PID];
        $sum[$_] += $c[$_] for C_ALLOW .. $n - 1;
        $sum[C_PID]++;
        $sum[C_BUNDLE] = $c[C_BUNDLE];
    }
    return { magic => $magic, layout => $layout, slots => $slots, size => $size,
             n => $n, len => length $f, c => \@sum, nginx => $nginx, module => $module, abi => $abi };
}

# runs $code, returns how much each counter moved
sub delta {
    my ($code) = @_;
    my $a = metrics()->{c};
    $code->();
    sleep 0.1;
    my $b = metrics()->{c};
    return [ map { $b->[$_] - $a->[$_] } 0 .. $#$b ];
}

sub hist_total { my ($d) = @_; my $t = 0; $t += $d->[$_] for C_HIST .. C_HIST + 8; $t }

# ---------------------------------------------------------------------------
# small bundle: the stub rule of test-hooks (STRATA-TEST-BLOCK) and the panic
# needle (STRATA-TEST-PANIC) need no rules

fresh();
bundle([]);
listen_events();
write_conf();
start();
sleep 0.3;

subtest "metrics file layout" => sub {
    my $m = metrics();
    is($m->{magic}, "STRMET1\0", "magic");
    is($m->{layout}, 1, "layout version");
    is($m->{slots}, $workers, "one slot per worker");
    is($m->{size}, 448, "slot size");
    is($m->{n}, 50, "50 counters");
    is($m->{len}, 64 + $workers * 448, "file size");
    is($m->{c}[C_PID], $workers, "every worker wrote its pid");
    is($m->{c}[C_BUNDLE], 7, "bundle version of the workers");
    like($m->{nginx}, qr/^1\.\d+\.\d+$/, "NGINX version in the header");
    like(`nginx -v 2>&1`, qr/\Q$m->{nginx}\E/, "the running NGINX");
    is($m->{module}, "0.1.0", "module version");
    is($m->{abi}, (1 << 16) | 5, "ABI version");
};

subtest "clean request: no event, counted as allow" => sub {
    my $d = delta(sub { is(req("GET", "/t")->{status}, 200, "200") });
    is(scalar(events(0.5)), 0, "no event");
    is($d->[C_ALLOW], 1, "allow +1");
    is($d->[C_BLOCK] + $d->[C_OPEN] + $d->[C_CLOSED] + $d->[C_DROPPED], 0, "nothing else");
    is(hist_total($d), 1, "one request in the engine time histogram");
};

subtest "blocked request: one event with its Block ID, 403" => sub {
    my $r;
    my $d = delta(sub { $r = req("GET", "/t?STRATA-TEST-BLOCK") });
    is($r->{status}, 403, "403");
    my @e = events(1);
    is(scalar(@e), 1, "one event");
    like($e[0]{block_id} // "", qr/^STR-/, "Block ID");
    is($e[0]{block_id}, $r->{headers}{"x-id"}, "the Block ID of the response");
    is($e[0]{status}, 403, "status 403 in the event");
    is($e[0]{action}, 4, "ACTION_BLOCK");
    is($e[0]{policy}, "example-api", "policy");
    is($d->[C_BLOCK], 1, "block +1");
};

subtest "shadow policy: event with an Event ID and the upstream status" => sub {
    my $r;
    my $d = delta(sub { $r = req("GET", "/shadow?STRATA-TEST-BLOCK") });
    is($r->{status}, 200, "passes");
    my @e = events(1);
    is(scalar(@e), 1, "one event");
    like($e[0]{block_id} // "", qr/^EVT-/, "Event ID");
    is($e[0]{status}, 200, "upstream status in the event");
    is($e[0]{action}, 2, "ACTION_LOG");
    is($d->[C_LOG], 1, "log +1");
};

# incident (b): engine error / panic
subtest "engine panic, fail mode open: passes, error event" => sub {
    my $r;
    my $d = delta(sub { $r = req("GET", "/open?STRATA-TEST-PANIC") });
    is($r->{status}, 200, "passes");
    my @e = events(1);
    is(scalar(@e), 1, "one event");
    like($e[0]{block_id} // "", qr/^EVT-/, "Event ID");
    is($d->[C_OPEN], 1, "fail open +1");
    is($d->[C_CLOSED], 0, "fail closed unchanged");
};

subtest "engine panic, fail mode closed: 503 with an Event ID" => sub {
    my $r;
    my $d = delta(sub { $r = req("GET", "/closed?STRATA-TEST-PANIC") });
    is($r->{status}, 503, "503");
    like($r->{headers}{"x-id"} // "", qr/^EVT-/, "Event ID in the response");
    my @e = events(1);
    is(scalar(@e), 1, "one event");
    is($e[0]{block_id}, $r->{headers}{"x-id"}, "same Event ID");
    is($e[0]{status}, 503, "status 503 in the event");
    is($d->[C_CLOSED], 1, "fail closed +1");
};

subtest "redirect after inspection: one inspection, one count, one event" => sub {
    my $r;
    my $d = delta(sub { $r = req("GET", "/redir?STRATA-TEST-BLOCK") });
    is($r->{status}, 200, "redirected to /shadow, passes");
    is(scalar(events(1)), 1, "one event");
    is($d->[C_LOG] + $d->[C_ALLOW] + $d->[C_BLOCK], 1, "counted once");
    is(hist_total($d), 1, "one engine time sample");
};

# RV-N-01: libstrata's per-policy counts reach the event socket about once a
# second (through strata_tx_sample, no connector code of their own): the
# requests of each policy, and the engine errors of the panics above
subtest "requests per policy on the event socket" => sub {
    my ($api0, $web0) = (policy_total("example-api", 0), policy_total("example-web", 0));
    req("GET", "/t/") for 1 .. 5;
    req("GET", "/shadow/");
    # each worker sends its counts on a request of its own, a second after
    # its last send: keep asking until both have
    my $deadline = time + 6;
    while (time < $deadline
        && (policy_total("example-api", 0) - $api0 < 5 || policy_total("example-web", 0) - $web0 < 1)) {
        req("GET", "/t/");
        events(0.3);
    }
    ok(@policy_counts > 0, "counts datagrams: " . scalar @policy_counts);
    cmp_ok(policy_total("example-api", 0) - $api0, '>=', 5, "example-api requests");
    cmp_ok(policy_total("example-web", 0) - $web0, '>=', 1, "example-web requests");
    cmp_ok(policy_total("example-api", 3), '>=', 1, "engine errors of the panics counted");
};

# incident (d): no agent
subtest "no event socket: requests unaffected, drops counted" => sub {
    close $sock;
    unlink "$root/events.sock";
    my $d = delta(sub {
        is(req("GET", "/closed?STRATA-TEST-BLOCK")->{status}, 403, "closed: still 403, not 503");
        is(req("GET", "/open?STRATA-TEST-BLOCK")->{status}, 403, "open: still 403");
        is(req("GET", "/t")->{status}, 200, "clean request: 200");
    });
    # two events (the clean request has none), and maybe a per-policy counts
    # datagram from each worker (RV-N-01: at most one a second per worker)
    ok($d->[C_DROPPED] >= 2 && $d->[C_DROPPED] <= 2 + $workers, "two events dropped: $d->[C_DROPPED]");
    is($d->[C_OPEN] + $d->[C_CLOSED], 0, "not a fail mode");
    listen_events();
};

# The worker's socket is connect()ed to the agent's (#29): it must follow
# the agent across restarts.
subtest "agent back after a gap: events resume after the retry delay" => sub {
    sleep 1.2;    # the workers retry a lost agent at most once a second
    my $d = delta(sub {
        is(req("GET", "/closed?STRATA-TEST-BLOCK")->{status}, 403, "blocked") for 1 .. 4;
    });
    is(scalar(events(1)), 4, "every event reaches the new socket");
    is($d->[C_DROPPED], 0, "none dropped");
};

subtest "agent restarts between two requests: no event lost" => sub {
    is(scalar(events(0.2)), 0, "nothing pending");
    listen_events();    # a new socket at the same path, the old one closed
    my $d = delta(sub {
        is(req("GET", "/closed?STRATA-TEST-BLOCK")->{status}, 403, "blocked") for 1 .. 4;
    });
    is(scalar(events(1)), 4, "the first event after the restart is not lost");
    is($d->[C_DROPPED], 0, "none dropped");
};

# force-shadow from the control file
my $loads = count(qr/strata: generation \d+, loading/);

subtest "force-shadow for every policy" => sub {
    force_shadow(1, 0);
    my $r = req("GET", "/t?STRATA-TEST-BLOCK");
    is($r->{status}, 200, "would be blocked: passes");
    like($r->{headers}{"x-id"} // "", qr/^EVT-/, "Event ID");
    like((events(1))[0]{block_id} // "", qr/^EVT-/, "event with the Event ID");
    is(count(qr/strata: generation \d+, loading/), $loads, "bundle not loaded again");
};

subtest "force-shadow for one policy" => sub {
    force_shadow(0, 1, "example-api");
    is(req("GET", "/t?STRATA-TEST-BLOCK")->{status}, 200, "example-api: shadow");
    is(req("GET", "/guard?STRATA-TEST-BLOCK")->{status}, 403, "example-guard: still enforced");
    events(0.5);
};

subtest "invalid force-shadow fields are ignored" => sub {
    force_shadow(0, 40, "example-api");
    is(req("GET", "/t?STRATA-TEST-BLOCK")->{status}, 403, "count over 32: ignored");
    force_shadow(0, 1, "Example-API");
    is(req("GET", "/t?STRATA-TEST-BLOCK")->{status}, 403, "name outside [a-z0-9._-]: ignored");
    my $n = count(qr/invalid force_shadow in control file/);
    ok($n >= 1 && $n <= $workers, "logged once per worker ($n)");
    force_shadow(0, 0);
    is(req("GET", "/t?STRATA-TEST-BLOCK")->{status}, 403, "cleared: enforced");
    is(count(qr/strata: generation \d+, loading/), $loads, "bundle never loaded again");
    events(0.5);
};

stop();

# ---------------------------------------------------------------------------
# incident (c): CPU budget, with the CRS rules (1 MB through them takes
# far more than 1 ms)

fresh();
bundle([ glob("$repo/rules/crs/*.yaml") ]);
listen_events();
write_conf();
start();
sleep 0.3;

my $heavy = "q=" . ("%26amp%3B%26lt%3B" x 62_000);    # ~1 MB

subtest "budget exceeded, fail mode open: passes, counted" => sub {
    my $r;
    my $d = delta(sub { $r = req("POST", "/bopen", $heavy) });
    is($r->{status}, 200, "passes");
    like($r->{headers}{"x-id"} // "", qr/^EVT-/, "Event ID");
    is($d->[C_BUDGET], 1, "budget exceeded +1");
    is($d->[C_OPEN], 1, "fail open +1");
    like((events(1))[0]{block_id} // "", qr/^EVT-/, "error event");
};

subtest "budget exceeded, fail mode closed: 503" => sub {
    my $r;
    my $d = delta(sub { $r = req("POST", "/bclosed", $heavy) });
    is($r->{status}, 503, "503");
    is($d->[C_BUDGET], 1, "budget exceeded +1");
    is($d->[C_CLOSED], 1, "fail closed +1");
    is((events(1))[0]{status}, 503, "event with status 503");
};

subtest "default budget, fail mode open: the heavy body passes, bytes counted" => sub {
    my $d = delta(sub { is(req("POST", "/t", $heavy)->{status}, 200, "200") });
    is($d->[C_BODY] > 0, 1, "body bytes counted");
};

stop();

# ---------------------------------------------------------------------------
# incident (a): no bundle

fresh();
listen_events();
write_conf();
start();

subtest "no bundle, fail mode open: passes" => sub {
    my $d = delta(sub { is(req("GET", "/open")->{status}, 200, "200") });
    is($d->[C_OPEN], 1, "fail open +1");
};

subtest "no bundle, fail mode closed: 503 with an Event ID" => sub {
    my $r;
    my $d = delta(sub { $r = req("GET", "/closed") });
    is($r->{status}, 503, "503");
    like($r->{headers}{"x-id"} // "", qr/^EVT-/, "Event ID");
    is($d->[C_CLOSED], 1, "fail closed +1");
    is(metrics()->{c}[C_BUNDLE], 0, "no bundle version");
};

stop();

unlike(errlog(), qr/\[(?:alert|crit|emerg)\]/, "no alert, crit or emerg in the last run");

done_testing();

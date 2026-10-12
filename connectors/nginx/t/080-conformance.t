# W08-Q-01 (reworked by the W08 review): conformance corpus v1 through NGINX.
# Every request of conformance/corpus/v1.jsonl is sent raw to a location with
# policy example-api and the fixture bundle (the same bundle and policy as
# engine/compiler/tests/conformance.rs); a "block" expectation must answer
# 403, an "allow" one 200, and the rules NGINX reports ($strata_rules) must
# be the expected set. A case NGINX itself refuses before the module (its
# "nginx" field) only checks that status.
#
# The blocks are built from the corpus when the file runs, so the engine
# and NGINX runners can never disagree on what the corpus says.

use FindBin;
use lib "$FindBin::Bin/lib";
use Test::Strata 'no_plan';
use JSON::PP;

my $corpus = "$FindBin::Bin/../../../conformance/corpus/v1.jsonl";

sub expand {
    my ($uri) = @_;
    $uri =~ s/\@ARGS(\d+)\@/join "&", map { "a$_=1" } 0 .. $1 - 1/e;
    return $uri;
}

# all orders of a list: $strata_rules keeps the match order
sub orders {
    my @l = @_;
    return ([]) unless @l;
    return map { my $i = $_; map { [$l[$i], @$_] } orders(@l[grep { $_ != $i } 0 .. $#l]) } 0 .. $#l;
}

sub perl_escape {
    my ($s) = @_;
    $s =~ s/(["\\\$\@])/\\$1/g;
    $s =~ s/\r/\\r/g;
    $s =~ s/\n/\\n/g;
    return $s;
}

my $spec = "";
open my $fh, "<", $corpus or die "$corpus: $!";
my $n = 0;
while (my $line = <$fh>) {
    next unless $line =~ /\S/;
    my $c = decode_json($line);
    $n++;
    my $method = $c->{method} // "GET";
    my $body = $c->{body} // "";
    my @h = ("Host: api.example.test");
    my ($chunked, $has_cl);
    for my $k (sort keys %{ $c->{headers} // {} }) {
        my $v = $c->{headers}{$k};
        for my $x (ref $v ? @$v : ($v)) {
            push @h, "$k: $x";
            $chunked = 1 if lc $k eq "transfer-encoding";
            $has_cl = 1 if lc $k eq "content-length";
        }
    }
    # a chunked case gives the decoded body: frame it here; a framed case
    # is sent exactly as written
    if ($chunked && !$c->{framed}) {
        $body = sprintf("%x\r\n%s\r\n0\r\n\r\n", length $body, $body);
    } elsif (length $body && !$chunked && !$has_cl) {
        push @h, "Content-Length: " . length $body;
    }
    push @h, "Connection: close";
    my $raw = "$method " . expand($c->{uri}) . " HTTP/1.1\r\n" . join("", map { "$_\r\n" } @h) . "\r\n" . $body;

    my $exp = $c->{expect};
    my $nginx = $c->{nginx};
    my $status = $nginx ? $nginx->{status} : $exp->{action} eq "block" ? 403 : 200;
    $spec .= "=== TEST $n: $c->{name}\n";
    $spec .= "--- raw_request eval\n\"" . perl_escape($raw) . "\"\n";
    $spec .= "--- error_code: $status\n";
    unless ($nginx) {
        my @rules = @{ $exp->{rules} };
        if (@rules) {
            my $alt = join "|", map { join ",", @$_ } orders(@rules);
            $spec .= "--- response_headers_like\nX-Rules: ^(?:$alt)\$\n";
        } else {
            $spec .= "--- response_headers\n!X-Rules\n";
        }
    }
    $spec .= "--- no_error_log\n[emerg]\n[alert]\n\n\n";
}
close $fh;
die "corpus has only $n cases\n" if $n < 30;

add_block_preprocessor(sub {
    my $block = shift;
    $block->set_value("config", <<'_EOC_') unless defined $block->config;
    # Test::Nginx already writes "location /"
    location ~ ^/(?!backend/) {
        strata on;
        strata_policy example-api;
        add_header X-Rules $strata_rules always;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/backend$request_uri;
    }
_EOC_
});

spec_string($spec);
run_tests();

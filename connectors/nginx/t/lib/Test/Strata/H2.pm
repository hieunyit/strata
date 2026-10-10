package Test::Strata::H2;

# Kept out of Test::Strata on purpose: Spiffy's -Base turns every sub of
# that package into a method (injects "my $self = shift").

use strict;
use warnings;

# Minimal HTTP/2 (prior knowledge, cleartext) frame builders for raw_request,
# for cases curl cannot produce (e.g. RST_STREAM in the middle of a body).
# Needs "http2 on;" in the server block.

sub h2_frame {
    my ($type, $flags, $stream, $payload) = @_;
    my $len = length $payload;
    return pack("CnCCN", $len >> 16, $len & 0xffff, $type, $flags,
                $stream & 0x7fffffff) . $payload;
}

# HPACK literal without indexing, indexed name, no Huffman (values < 127 bytes)
sub h2_literal {
    my ($name_index, $value) = @_;
    my $prefix = $name_index < 15 ? pack("C", $name_index)
                                  : pack("CC", 0x0f, $name_index - 15);
    return $prefix . pack("C", length $value) . $value;
}

# connection preface + SETTINGS + HEADERS for "POST <path>" on stream 1
sub h2_post {
    my ($path, $content_length) = @_;
    my $block = "\x83"                       # :method POST (static 3)
              . "\x86"                       # :scheme http (static 6)
              . h2_literal(4, $path)          # :path
              . h2_literal(1, "localhost")    # :authority
              . h2_literal(28, $content_length);   # content-length
    return "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
         . h2_frame(0x4, 0, 0, "")              # SETTINGS
         . h2_frame(0x1, 0x4, 1, $block);       # HEADERS, END_HEADERS
}

sub h2_data { h2_frame(0x0, $_[1] // 0, 1, $_[0]) }

sub h2_rst_stream { h2_frame(0x3, 0, 1, pack("N", 0x8)) }   # CANCEL

1;

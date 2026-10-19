# RV-N-02: JA4 TLS fingerprint

Source reviewed: `engine/src/ja4.rs` and the connector changes of `517c5f1`
(branch `W17-cmdi-ssti-ja4`). Rewritten, not selected: the source computed a
wrong fingerprint for every real client.

## Defects of the source

| Defect | Evidence | Now |
| --- | --- | --- |
| Extension count without SNI and ALPN (the spec counts them; only the hash leaves them out) | Source on the 6 real ClientHellos below: **6/6 wrong**, e.g. curl `t13d3110h2_…` instead of `t13d3112h2_…`, Chrome `t13d1516h2_…` instead of `t13d1518h2_…`. Its "Chrome reference vector" test was hand-built to match the code | Counted as the spec says; 6/6 match |
| ALPN with a non-alphanumeric first/last byte printed as `0`; `i` for an SNI extension holding an IP literal | FoxIO `technical_details/JA4.md` (hex of the ALPN value; `d` whenever the SNI extension is present, as FoxIO's code does) | Spec rules |
| `strata_conn_t` grew a field without an ABI minor bump | `engine/ffi/strata.h` of the source | ABI 1.8 adds two functions, struct unchanged |
| Heap allocation per handshake (`Vec`, `String`, `format!`) | source | Fixed-size lists, streamed SHA-256, no heap |
| NGINX test build had no `--with-http_ssl_module`: every `#if (NGX_HTTP_SSL)` block (TLS flag, JA4) was compiled out, in tests **and in the packages** (`deploy/packaging/build.sh` uses the same script) | `connectors/nginx/scripts/build.sh` | Flag added, as nginx.org builds have it |

## Design

- C (`ngx_http_strata_module.c`): message callback on the SSL context of every
  server (NGINX owns the ClientHello callback). The first ClientHello message
  of a connection goes to `strata_ja4` as pointer + length; the 36 bytes are
  kept in the SSL's ex_data (connection pool). Per request
  `strata_tx_set_ja4`; `$strata_ja4` reads the ex_data directly.
- libstrata: `engine/src/ja4.rs`, bounded parse, `None` instead of a guess on
  malformed or oversized input. Target `tls_ja4` (variable code 27), event
  field 24 `ja4`, control plane column `ja4` (added by `EnsureColumns`),
  validated `[0-9a-z_]{36}`, in `GET /v1/events/{block_id}`.
- A refused fingerprint returns `STRATA_E_INVALID` without breaking the
  transaction (the other request calls mark it failed).
- HTTP/3 through NGINX's OpenSSL compatibility layer: that layer sets its own
  per-connection message callback, so no JA4 (documented).
- Not in this change: JA4 as a rate-limit key (needs RV-R-03, not merged);
  HTTP/2 fingerprint (NGINX gives modules no SETTINGS frame).

## Reference vectors

`engine/tests/vectors/ja4-client-hellos.json`: six ClientHellos captured on
2026-10-19 on loopback (Ubuntu 24.04 container, `openssl s_server`): curl
8.5.0 / OpenSSL 3.0.13 with SNI and with an IP literal, python-requests
2.31.0, Chrome for Testing 156.0.8078.4 (first and resumed connection),
Firefox (Playwright 1.64.0). Expected values are tshark 4.2.2's
`tls.handshake.ja4`, an independent implementation. For the two Chrome
hellos tshark keeps GREASE values in the signature algorithms, against the
spec ("ignore GREASE values anywhere") and FoxIO's reference code, which
filters them; their expected value is tshark's `ja4_r` raw string with those
GREASE values removed, hashed again.

## Tests

- `engine/src/ja4.rs`: GREASE, counts with SNI/ALPN, ALPN/version edge
  cases, every truncation refused, storage limits.
- `engine/compiler/tests/ja4.rs`: the 6 real hellos; a rule on `tls_ja4`
  through a signed bundle (block, other fingerprint, no TLS, negation); the
  event carries field 24; malformed values refused.
- `engine/ffi/tests/c/abi_test.c`: `strata_ja4` value and errors,
  `strata_tx_set_ja4` without breaking the transaction.
- `connectors/nginx/t/043-ja4.t`: curl over real TLS to NGINX:
  `$strata_ja4` (exact vector value for curl 8.5.0 / OpenSSL 3.0.13), h1/h2,
  TLS 1.2, a rule blocking TLS 1.3 without SNI, `strata off`, plain HTTP.
- Go: `control-plane/fleet/ja4_test.go`, `TestValidJA4`.

Gate results are in the PR description.

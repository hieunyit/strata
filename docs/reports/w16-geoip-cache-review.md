# W16 GeoIP cache selection

The original W15–W16 `geoip.go` was copied verbatim from 0dce6de into an isolated Go module, with an Event stub containing exactly the fields that file reads. Three focused tests failed: mutating a returned country changed future lookups; one address and its IPv4-mapped/port form consumed two cache keys; a missing lookup preserved forged event metadata. This is an extracted-source regression fixture, not a whole-control-plane run. Source hash, harness and failing output are retained.

This change fixes the first two cache issues and prepares reload. Reader and cache are one atomically published generation; lookups that finish after a reader replacement can populate only their own old cache. Cache values, including coordinate/accuracy pointers, are copied at both boundaries. Canonical netip keys unify IPv4-mapped and port forms. Positive and negative results are cached up to a strict 50,000 entries; additional addresses still receive uncached lookups. Private/loopback/link-local/CGNAT/multicast/unspecified addresses bypass the DB with an INTERNAL label and absent coordinates. Malformed/oversized raw addresses return no location. Lookup errors stay errors and are not cached.

Reload privately loads/verifies the complete configured City/ASN pair, then publishes a fresh generation; cancellation or either file's failure preserves the last good reader/cache. Callers serialize/schedule reload attempts. No network download, weekly object-store update job or auto-reload is implemented in this step.

Go 1.26.9: all 13 reader/cache tests passed with -race (2.029s package); ingest lint 0 issues. Tests cover a deliberately blocked old lookup completed after replacement, independent returned pointers/canonical keys, 50,010 addresses without exceeding the 50,000 bound, no private-IP DB calls, concurrent real-MMDB reads during 200 reader/cache replacements, failed/canceled replacement pairs, successful replacement and negative-cache reset. The reader's isolated full ingest unit/race suite was accepted in the preceding reader change.

The third original failure (forged event metadata on missing/disabled/error lookup) remains for the authoritative ingest integration. This cache is not yet activated in the running server; ClickHouse schema/projections and real DB acceptance are still pending. No Gate or rollout status changes follow.

Self-review: constant cache/input/metadata bounds; no PII labels/logs; typed decoder output; immutable readers retained by outstanding generations; error paths preserved; no shared proto/C ABI/rules changes. Old in-flight requests may return the old reader's result by design, but cannot contaminate replacement generations.

Combined-main acceptance after #241/#240: full ingest unit/race suite passed in 6.239s, lint 0 issues, with the current dependency pins. Raw output is attached separately.

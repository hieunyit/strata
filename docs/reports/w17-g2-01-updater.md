# W17-G2-01: weekly GeoIP database updates

Source reviewed: `control-plane/ingest/worker/geoip_updater.go` of
`1cac91c`, `04b21f9`, `d645ffc` (branch `w17-geoip-map-platform`).
Rewritten: the source never used what it downloaded.

## Defects of the source

| Defect | Effect | Now |
| --- | --- | --- |
| After the download it only called `ResetCache()`: the new database was stored but never opened nor activated | Events kept the start-time database forever | Activated with `SetReader` once checked and stored |
| No check that the bytes are a database: anything of 16+ bytes was stored | An HTML error page or a truncated file became a "version" | `NewMMDBReaderBytes`: database type (City / ASN), `Verify()`, 128 MiB; any failure keeps the active version |
| One URL for one file; MaxMind serves `.tar.gz` | Unusable with MaxMind downloads | City and ASN URLs, `.mmdb` or `.tar.gz` (exactly one `.mmdb`), bounded decompression |
| Download URL (MaxMind license key in the query) in errors (`*url.Error` prints it) | License key in logs | `RedactURL` in errors, logs and the manifest; tests check the key never appears |
| Not wired in the server, no metric | — | `STRATA_GEOIP_{CITY,ASN}_URL`, `-geoip-update-interval`, metrics and alert `StrataGeoIPStale` |
| Redirects followed to any scheme | — | At most 5, http(s) only |

## What

- `control-plane/ingest/geoip_update.go`: `GeoIPUpdater` (`Update`,
  `LoadLatest`, `Run`), `ExtractMMDB`, `RedactURL`; `NewMMDBReaderBytes`
  shares the checks of the start-time files.
- Objects: `geoip/<version>/{city,asn}.mmdb`, `geoip/<version>/manifest.json`,
  `geoip/latest.json`; `<version>` is the fingerprint events carry
  (`geoip_version`). At start every replica loads `latest.json` (SHA-256 of
  each file and the version are checked) before downloading.
- Server: URLs from the environment (license keys), `-s3-endpoint` required,
  not together with `-geoip-city`/`-geoip-asn`.
- Metrics `strata_cp_geoip_update_last_success_timestamp_seconds`,
  `strata_cp_geoip_update_failures_total`; alert `StrataGeoIPStale` (> 9 days,
  for 1 h). Runbook: `docs/runbook/geoip.md`.

## Tests

`TestGeoIPUpdateStoresActivatesAndRedacts` (MaxMind-style `.tar.gz` and a
plain `.mmdb` from a test server: stored, activated, lookups use the new
version, no license key stored; unchanged second run stores nothing; another
replica loads the stored version without downloading; a tampered stored
file is refused), `TestGeoIPUpdateFailuresKeepTheActiveVersion` (HTTP 500,
corrupt, wrong type, two or no `.mmdb`, redirect to `file://`, object store
down, `file://` URL, unreachable host: active version kept, key not in the
error), `TestExtractMMDBBounds` (gzip bomb, redaction),
`TestGeoIPUpdateRunDownloadsWhenNothingIsStored`; metrics collector; alert
unit tests (`make test-alerts`).

# Synthetic MMDB fixtures

Only synthetic test databases, not GeoLite production data. Source: MaxMind/MaxMind-DB, commit `0ee49278e35fd7bdf341ac236edbba20de1aceb9`, `test-data/`. Redistributed under the Apache-2.0 option of the upstream dual Apache-2.0/MIT license; see LICENSE-APACHE. Copyright MaxMind, Inc. Upstream: https://github.com/maxmind/MaxMind-DB/tree/0ee49278e35fd7bdf341ac236edbba20de1aceb9/test-data

SHA-256:

- GeoIP2-City-Test.mmdb: `7ecd1a263834096e3948b459713102ef350412a9f18367b4a88efec018153004`
- GeoLite2-ASN-Test.mmdb: `5f2da5602a6947dae10486fe337d6112d2e37eaa2bc8d32e1fdeeeae645a3e4a`

These fixtures exercise the actual binary decoder. They do not establish real-world geographic accuracy, data licensing for a deployment, or performance with a full-size database. The decoder dependency is pinned separately in go.mod/go.sum.

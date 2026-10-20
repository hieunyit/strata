# W19-R-01 and W19-G2-01: geo/ASN rules

Plan items:
- W19-R-01. Done when: rules blocking by country and by ASN have tests,
  and the bundle size growth is recorded.
- W19-G2-01. Done when: geo/ASN rules can be created, edited and deployed
  through the API.

PO decision (21/10): the bundle carries only the networks of the
countries and ASNs that rules name, not the whole `.mmdb`. Default
bundles are about 21.6 MB already, and whole Country + ASN databases
(about 20 MB) would put every bundle over Vault transit's 24 MiB signing
limit. Locations on events are still added at Event ingest.

## Engine (#283)

Targets `geo_country` and `geo_asn` give, for the client address:
- the country or ASN that holds it, among those the bundle carries;
- `private` for local addresses;
- `other` for any other address.

Section 15 `GEO` holds sorted, non-overlapping ranges per country and
ASN. Conditions on these targets take `streq`/`pm` only, so the compiler
knows which names to pack. Details: `docs/design/control-file.md`.

## Policy geo rules (this PR)

- **Policy field.** `geo_rules` (at most 16 per policy). Each rule has an
  id (190000–199999), countries and/or ASNs, `not` (match the addresses
  outside them, except local ones), and an `action` of `block` or `log`.
- **Engine.** Each geo rule compiles to a rule scoped to its own policy:
  rule flag bit 4, plus section 16 `SCOPE` with the policy and the mode.
  `log` mode goes through the report-only path: Event ID, never blocks.
- **Admin API.** `PolicySpec.geo_rules`. A new rule is sent with id 0,
  and the control plane gives it the lowest id that no version of any
  other policy uses. An id belonging to another policy is refused. If two
  edits race for the same id, the deploy fails on the duplicate rule id.
  Changing geo rules is a spec change like any other: draft, replay,
  four-eyes approval, deploy.
- **Deploy.** The compiler asks the control plane's GeoIP databases for
  the networks of the countries and ASNs the geo rules name
  (`ingest.MMDBReader.Networks`). The walk takes about 1.3 s per
  database, and the result is cached per database version. It passes
  them with `--geo`. Geo rules without a GeoIP database (City for
  countries, ASN for ASNs) fail the build with a clear error.

## Bundle size

Measured with DB-IP Lite (CC BY 4.0, 2026-10), one policy with one
block rule, against the same bundle without it (42 KB). The growth
includes the rule's Hyperscan patterns.

| Geo rule on | Prefixes (IPv4 + IPv6) | Bundle | Growth |
| --- | ---: | ---: | ---: |
| VN | 1,961 + 1,290 | 107 KB | **+65 KB** |
| CN, RU, KP, IR | 23,264 + 18,558 | 561 KB | **+519 KB** |
| US | 155,176 + 97,731 | 1,446 KB | **+1.40 MB** |
| AS7552 (one ASN) | 245 + 4 | | ≤ 2 KB |

For comparison, the whole Country + ASN databases are about 18 MB.

## Tests

- `engine/src/geo.rs`, `engine/src/scope.rs`: codecs, lookups, and
  refusals.
- `engine/compiler/tests/geo_rules.rs`: IR rules on the two targets.
- `engine/compiler/tests/geo_policy_rules.rs`: one bundle with four
  policies.
  - Block US.
  - Log AS64500: action log, Event ID.
  - Only VN: US and other addresses blocked, VN and local addresses
    allowed.
  - No geo rules: nothing applied.
  - Shared rules still run for all policies.
  - Duplicate ids across policies, out-of-range ids, and bad
    countries/ASNs/actions are refused.
- `control-plane/ingest/geoip_networks_test.go`: on the MaxMind test
  databases, every network listed for a country looks up to that
  country; the fixtures' addresses are covered; IPv4 is written as IPv4;
  results are cached; a missing database or a canceled context is
  refused.
- `control-plane/policy`: validation, sorting, `GeoKeys`, and `--geo`
  passed only for geo rules (refused without a GeoIP database). With the
  real `strata-compile`: sections `GEO` and `SCOPE`, and a duplicate id
  across policies fails the build.
- `control-plane/admin/policy_geo_test.go`: API round trip, assignment
  of free ids (skipping other policies' ids from any version, keeping
  the policy's own), and refusals.

## UI (W19-F-01 part 2)

- **Policy editor.** A "Geo rules" block where each rule has:
  - countries and ASNs typed as lists (`VN, US`; `7552, AS15169`), with
    bad entries flagged;
  - block or log only;
  - "every address outside them";
  - remove, and add a new rule (at most 16).
  A new rule shows "new" until saved, when the control plane gives it an
  id. Save is disabled while a rule names nothing. Geo rules stay out of
  the YAML view, whose parser reads only a flat shape, and are kept when
  the YAML is edited. The version diff shows them as one line per rule
  in the General block, for example `190001 block outside VN, AS7552`.
- **Map.** With a country or ASN filter set (not `INTERNAL`), operators
  and admins see "Create a rule for <country / ASN>". It picks a policy
  (the policy filter by default) and block or log, then saves a new draft
  version of that policy with the rule. That version is enforced only
  after replay, approval and deploy. The policy is read again just before
  saving, for a fresh etag. If the policy already has a rule of that
  action for the target, nothing is saved. A conflict (someone saved in
  between) is reported.
- **Tests.** `ui/src/__tests__/PolicyGeo.test.tsx` covers:
  - the helpers (parsing, normalizing, summaries, adding a rule once,
    the 16-rule limit);
  - the YAML view and the diff;
  - the editor: an existing id is kept, a rule is added, a bad token is
    flagged, save is blocked while empty, and the payload is saved;
  - the map action: hidden for viewers, a block draft for a country, a
    log rule for an ASN, an existing rule, and a 409 conflict.

Combined with #285 (the map's events table and the events search
filters), this gives the plan's demo: from the map to an approved and
deployed ASN block rule.

# Crawler IP ranges (good bots)

Rule 500001 (core pack) flags a request whose User-Agent claims Googlebot,
Bingbot or Applebot from an address outside the ranges the crawler's owner
publishes (W18-R-02). The ranges come with the bundle; the control plane
fetches them (W18-G2-02).

**Turn it on.** `-good-bots-interval 24h` (default 0: the control plane
makes no outbound request) with `-s3-endpoint`. The job fetches at start and
then every interval:

| Crawler | Source |
| --- | --- |
| googlebot | `https://developers.google.com/static/search/apis/ipranges/googlebot.json` |
| bingbot | `https://www.bing.com/toolbox/bingbot.json` |
| applebot | `https://search.developer.apple.com/applebot.json` |

A list with any invalid prefix, a prefix with host bits, one broader than /8
(IPv4) or /16 (IPv6), no prefix or more than 65,536 is refused whole; a feed
that fails keeps the crawler's previous ranges. Each version is stored as
`goodbots/<sha256>.json` and copied to `goodbots/latest.json` (with the source,
fetch time and the list's creation time per crawler). Every bundle built
afterwards (deploy, staging, replay) carries the latest; a running fleet gets
new ranges with the next deploy. If the object store cannot be read, the
build fails rather than drop the ranges.

**Without ranges** (job off, or nothing stored yet) the crawler is `unknown`
and rule 500001 never matches: nothing is blocked, nothing is verified.

**Air-gapped.** Leave the job off and put a list in the object store by hand
(same JSON as `goodbots/latest.json`: `version` is checked, so produce it with
the job on a connected control plane and copy both objects).

**Metrics and alert.** `strata_cp_good_bots_update_last_success_timestamp_seconds`
(every feed fetched well), `strata_cp_good_bots_update_failures_total`;
`StrataGoodBotsStale` after 3 days without a full update. Look for
`[WARN] good bots` in the control plane log: an HTTP error or a refused list
names the feed (without its query).

**False positives.** SEO tools that send a crawler User-Agent from another
address match rule 500001 by design: add a policy exception for the route,
or disable the rule for the group.

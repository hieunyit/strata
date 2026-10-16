# Policy exception artifact (candidate, not yet emitted by the compiler)

The scope is one policy index + Rule ID + HTTP method + exact Host + exact path + field, with a mandatory absolute expiry in Unix milliseconds. Host/header names compare without ASCII case; paths and argument names preserve case. No wildcard/prefix match is implied. Unknown time (0), mismatched scope and time at/after expiry never enable an exception. Request scope must use a single Host header; duplicates or missing Host cannot enable an exception.

Supported fields initially are `ARGS:<name>` and `REQUEST_HEADERS:<name>`. Names are nonempty, at most 128 bytes. Argument names may contain printable UTF-8; header names are ASCII tokens. A field suffix such as `|base64` is not implicitly stripped by this codec. Runtime alias handling must preserve the exact source field and have a separate regression before integration. Body-wide, unknown field namespaces and `*` are rejected. A matching field must be removed before rule evaluation; suppressing only the first returned violation could hide a second malicious field and is prohibited.

Candidate binary layout (all integers little-endian):

```text
"SEX1" [4 bytes] | count u32
count records:
  policy_index u32 | rule_id u32 | expires_unix_ms u64
  method_length u16 | method UTF-8 bytes
  host_length u16 | host UTF-8 bytes
  path_length u16 | path UTF-8 bytes
  field_length u16 | field UTF-8 bytes
```

Bounds: at most 4,096 records overall, 128 per policy, 4,096 policies; method 32, host 253, path 2,048 and field 160 bytes. Strings are bounded before allocating. IDs, scope and lengths are validated again on read. Truncation, trailing bytes, invalid UTF-8, counts outside limits and policy-index mismatch are rejected. Empty settings emit no section.

Before the compiler emits this format, bundle integration must assign a section kind and a mandatory per-policy compatibility bit that older engines reject. Policies with that bit and policies represented in the section must be exactly the same set. Silently adding an unknown optional section is insufficient: old nodes could otherwise accept a bundle and ignore its exceptions. The current standalone codec validates the flagged set but is not wired to bundle loading; no exception is active from this change alone.

Creation from Block ID must persist a new policy version and its audit/request_id response atomically. The endpoint must derive exact scope from the stored event, require etag, explicit Rule ID/field selection if ambiguous, reason and TTL (prototype contract: 60 seconds to 30 days). It must use the existing replay/submit/four-eyes/deploy flow and M5 bound proof; creation is not runtime activation. Revocation is another version; expiry must stop applying at runtime without a redeploy. These API/compiler/runtime steps remain to be integrated.

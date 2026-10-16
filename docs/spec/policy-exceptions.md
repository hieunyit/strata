# Policy exception artifact (compiler and runtime supported)

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

Runtime uses section kind 10 (EXCEPTIONS) and bit 4 of byte 62 of each policy entry. Older engines reject this bit. Policies with that bit and policies represented in the section must be exactly the same set. Empty flagged policies and unflagged records are rejected. Engine loading also requires each referenced Rule ID to exist in the managed layer. No C ABI signature changes are needed. Compiler YAML/JSON emits the section and mandatory bit only for configured policies, and refuses unknown/non-managed Rule IDs. API emission is a pending step; signed compiler and manual fixtures exercise runtime support.

At evaluation, active scope is checked against the single Host, method, canonical path and current Unix time. Only values of the selected field for that Rule ID are removed, before evaluating its conditions/counts. Other fields remain inspected. Decoder-owned argument aliases normalize to their source name using ownership of the decoder's name buffer; a literal parameter named `Name|base64` is distinct. This normalization happens in the evaluator, not in the standalone string matcher. Filtering participates in the existing cooperative CPU budget.

Creation from Block ID must persist a new policy version and its audit/request_id response atomically. The endpoint must derive exact scope from the stored event, require etag, explicit Rule ID/field selection if ambiguous, reason and TTL (prototype contract: 60 seconds to 30 days). It must use the existing replay/submit/four-eyes/deploy flow and M5 bound proof; creation is not runtime activation. Revocation is another version; expiry must stop applying at runtime without a redeploy. The compiler and runtime implement this scope; the API workflow remains to be integrated.

Compiler policy `exceptions` entries require `id` (`exc-` plus 32 lowercase hex digits), `rule_id`, `method`, `host`, `path`, `field`, `expires_unix_ms` and a nonblank `reason` (at most 500 bytes). Optional `source_block_id` links the originating event. IDs must be unique within a policy. ID/reason/source metadata stays in the policy version, not in the runtime section. Removing an entry in another approved/deployed version revokes it; the engine also enforces absolute expiry without reload.

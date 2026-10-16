# Replay provenance v1

When replay is configured, approval binds a completed operation and deploy checks its inputs before publishing a bundle. These additive API fields make that proof inspectable:

| Resource | Fields | Meaning |
| --- | --- | --- |
| `GET /v1/operations/{id}` → `replay` | `input_digest` | SHA-256 commitment to the prepared compiler inputs |
| same | `draft_sha256`, `baseline_sha256` | Exact signed bundle bytes passed to compare |
| same | `replay_sha256` | Copied replay executable actually run |
| same | `sample_sha256` | Copied corpus first if configured, then downloaded traffic sample files in replay order |
| policy version | `approved_replay_id` | Operation bound by the approval; a newer replay does not replace it |
| bundle | `input_digest` | Prepared inputs from which deploy compiled the published bundle |

All hashes are lowercase hexadecimal. They contain no signing keys or request snippets. Existing role checks apply; viewers still cannot see replay examples with request input. Old operations and approvals have empty provenance and cannot satisfy the configured deploy gate.

The input digest is SHA-256 of the version 1 manifest produced by `policy.Compiler.Prepare`: hash of the copied compiler executable, ordered rule-file hashes, optional block-page hash, deep-copied named policies, support contact, cost budget, and hash of the identity HMAC key when used. Policies are ordered by name in both runner and deployer. Signing key, bundle version and build timestamp are excluded because replay uses its own key and deploy allocates the final version later.

Matching input digests do not imply identical bundle SHA: headers and signatures differ. The deployer compiles from the same private snapshot it hashed, avoiding a file replacement between checking replay and compiling. Compiler/replay shared libraries and the node engine image must also be pinned operationally; these fields do not attest those runtime images.

The baseline is the latest published bundle, matching the existing replay implementation. It does not assert every node has activated that bundle. When inputs, baseline, or the policy set change, create a new policy version, replay, review and approve again. Do not approve an old result by merely rerunning replay after its approval. For multiple policies, every policy/version in the new bundle must have a matching bound proof.

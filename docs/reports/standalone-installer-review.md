# RV-G1-01: signed standalone installer selection

Source: `46f3d0a` / `9569d12`. This selects a repaired installer on top of the
watcher, CLI and packaged units accepted in #230–235 and #247–250. Source W17–W19
ancestors remain unreviewed; this does not acknowledge their code or Done claims.

The prototype allowed no trusted key, did not activate an inspected location,
and its test could substitute an empty bundle after compilation failure. Those
paths are excluded. The replacement requires local operator-trusted packages,
a signed bundle, an independently trusted key, a named full-enforce policy and
explicit listen/upstream. Signature/policy checks and a real native module load
run against isolated scratch state before live publication. It waits for an even,
stable control generation naming the exact SHA-256 file. Every copy is bounded;
address grammar excludes config injection; a lock serializes installers.

It refuses existing Fleet/active Strata state and active NGINX. The dedicated
route uses existing body/CPU/fail defaults. A failed activation disables the pair
just started, restores nginx.conf and removes its snippet; packages and diagnostic
bundle state can remain. This is not an atomic OS rollback or a mode migration.
`install.sh --packages-only` separates package installation from enrollment and
configuration; package-manager hooks still run. Both installers are distributed.

A real Ubuntu failure exposed a 0600 keyring inherited from umask 077: `_apt`
could not read it and reported NO_PUBKEY. Keyring/source-list permissions are now
explicit, and the key fetch and dearmor errors propagate separately. Repository
URLs use HTTPS, matching the [NGINX package instructions](https://nginx.org/en/linux_packages.html).
Initial own candidates also exposed missing `cmp` on minimal Rocky and binary
matches while following the modules symlink; SHA-256 and text-only scanning fix
these. A test initially expected `block` instead of protobuf `ACTION_BLOCK`; the
assertion now uses the actual contract and requires SQLi Rule 942100 plus the
new-version fixture Rule 199999. No existing test was changed or disabled.

## Evidence and acceptance boundary

Fresh release packages were built from `a635da1` with no test hooks, matching
Hyperscan/compiler and NGINX 1.30.5. Go/C/Rust product bytes did not change here.
`strata-rules release --pack core` generated/verified 212 unchanged repository
rules. Version 2 contains those rules plus one explicitly test-only organization
rule: ID 199999, request_headers, uri_raw contains `/__standalone_update_fixture__`,
block_alone. It is not added to the shipped pack. Signing uses the existing public
test fixture key only. Invalid signed fixtures alter first-policy mode/canary or
oversize bytes (120/123/121) and regenerate the signature; tamper flips the last byte.

The harness checks hostile/missing/oversized inputs, existing Fleet/config refusal,
benign 200, SQLi 403 with Block ID, changed route behavior after a tool-built update,
unchanged master/worker PIDs, JSONL rule/version evidence, tamper/rollback LKG,
signed shadow/canary/layout refusal, and configuration restoration on a missing
conf.d include. Outbound network is disconnected after package installation.
[Raw outputs and artifact receipts](evidence/standalone-installer/) are authoritative.

The Rocky fixture offers `--rpm-nginx-repo-only`: its base already supplies all
NGINX OS dependencies; DNF still verifies dependency resolution and upstream RPM
signatures, but unused OS repositories are disabled only in this disposable lab.
Default mirror and direct Rocky HTTPS runs hit interrupted/checksum-mismatched OS
metadata downloads; those attempts remain in evidence. Product repository settings
are unchanged by this fixture option. Do not count those timeouts as successful tests.

A clean VM/five-minute operational acceptance remains **unproven** (no /dev/kvm on
this host); containers are not VM evidence. No task/Gate/week-pointer status is
advanced. Source branch is retained while its inherited features await disposition.

Self-review: relevant shell/Python/diff checks and actual release-package integration
runs are required below; errors propagate, scratch reads/copies/polls are bounded,
no unsigned fallback or credential output, no new dependency/interface/rule change.
No hosted CI was awaited, as requested. Existing agent race/native sanitizer proofs
remain in preceding reports; this patch changes shell packaging only.

Final local output (seconds measure the container path with artifacts prebuilt):

| Fixture | Installer | Full harness | Output |
| --- | ---: | ---: | --- |
| Ubuntu 24.04, normal APT repositories | 48.378s | 108.590s | PASS, 5 JSONL events |
| Rocky 9, nginx-repo-only lab option | 16.730s | 61.284s | PASS, 5 JSONL events |

New script: ShellCheck v0.10.0 clean at all severities. Existing installer/build:
warning-level ShellCheck clean; sh/bash syntax, Python AST, git diff check and
package SHA256SUMS verification pass. The first lint invocation mistakenly forced
the Bash build script through POSIX sh; the correct shebang-aware check passed.
Initial failed and final successful runtime logs are retained, not substituted.

Reproduce lab artifacts with the checked-in stdlib/OpenSSL helper (no production
key, generated timestamps vary). First build `tools/strata-rules` and the matching
`strata-compile`/`strata-eval`, then set STRATA_COMPILE and STRATA_EVAL to those paths:

```sh
python3 docs/reports/evidence/standalone-installer/prepare-fixtures.py \
  --repo . --rules-tool build/standalone-packaging/strata-rules \
  --out build/standalone-fixtures
python3 deploy/packaging/test/test-standalone-install.py \
  --image strata-pkgtest:ubuntu-24.04 --packages build/packages \
  --bundle build/standalone-fixtures/core-1/strata-core-lab-standalone-1.sbn \
  --update build/standalone-fixtures/core-2/strata-core-lab-standalone-2.sbn \
  --negative-bundles build/standalone-fixtures/invalid \
  --key connectors/nginx/t/fixtures/bundle.pub
```

Use the Rocky systemd image plus `--rpm-nginx-repo-only` for the disclosed RPM
fixture variant. The helper itself was executed successfully: 212/213 rule releases
and detached manifests verified; malformed policy fixtures were signed with the
existing public TEST seed using OpenSSL PKCS#8. Temporary test-key files are removed.

Fresh regenerated fixtures were also run through the real native evaluator: benign
score 0/allow; SQLi score 100/block with only Rule 942100; the update route changes
from allow to score 100/block with only Rule 199999. The signed oversize=2 fixture
passes named-policy metadata verification but the native engine rejects it as
`bad policy entry`, proving that the two preflight layers are distinct. All six
regenerated signature/policy expectations pass; their raw logs are retained.

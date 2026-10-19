# Standalone bootstrap follow-up

Scope: Debian/Ubuntu repository bootstrap and package-test fixture reliability.
Source main `7726a60`; no Go/C/Rust/ABI/rule/body/budget/default-action change.

APT accepts armored `.asc` public keys directly ([APT format documentation](https://manpages.debian.org/bookworm/apt/apt-key.8.en.html)). The helper no longer installs
the full GnuPG suite only to convert a public key. It fetches that key using HTTPS
only, installs it readable by `_apt`, keeps Signed-By and signature verification,
and updates only the newly added NGINX source on the second refresh. Existing OS
indexes are retained for dependency resolution. It does not replace OS repositories.

Actual package/NGINX/core-rule harness: Ubuntu **PASS, 42.212s install / 103.861s
harness / 5 events**; Debian 12 **PASS, 27.659s / 76.388s / 5 events**. Both verify
benign/SQLi, changed rule behavior with stable workers, hostile/oversized input,
signed invalid metadata/layout, tamper/rollback and failed-activation recovery.
Debian's old fixture lacked Python; the test dependency is now explicit. Optional
`--cpuset` isolates independent labs on this host, with unchanged default affinity.

A separate real regression exposed the fixture Dockerfile swallowing dependency
errors through its outer `|| true`. Before repair a stub APT returning **42** still
produced a successful image. After repair only optional unit masking is tolerated;
actual Docker builds reject both APT and DNF exit **42**. No existing test is removed
or disabled. [Raw outputs and receipts](evidence/standalone-bootstrap/) include failures.

ShellCheck/syntax/diff/AST checks apply to the changed shell/Python files. This is
not the clean-VM/five-minute acceptance. The user explicitly put that criterion
on hold because no other lab VM is available. A TCG attempt exceeded five minutes
and did not prove SQLi blocking; its cause is unresolved. No further VM attempts
are planned for this criterion until it is resumed. The source branch is retained.

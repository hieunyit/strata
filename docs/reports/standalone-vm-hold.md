# RV-G1-01: VM acceptance held

The user explicitly chose **“Chưa có VM khác; giữ tiêu chí này chờ”**.
No further VM attempt is scheduled. The clean-VM/SQLi/under-five-minute criterion
remains unaccepted, with no change to CPU budget, fail mode or request handling.
The original `RV-G1-01-standalone-lite` source is retained; its inherited feature
history is not accepted through an ancestry-only merge.

The host and Docker host expose no usable KVM device. Genuine Ubuntu 24.04 minimal
cloud guests were booted under QEMU 8.2/TCG, four vCPUs and 2 GiB RAM. The official
cloud-image signature and image SHA-256 were verified before boot. SSH used a
pinned guest host key. Fresh baseline showed cloud-init done, QEMU virtualization,
and no NGINX or Strata agent. Guest disks and ephemeral SSH private keys were kept
only in private tmpfs; none is part of this evidence.

| Attempt | Observed outcome | Acceptance |
| --- | --- | --- |
| 1 | Harness lacked an NSS entry for its container UID; stopped before boot | Failed harness |
| 2 | SSH readiness probe timed out before installation | Failed harness |
| 3 | SSH ready after 241.486s; installer exceeded its 600s diagnostic timeout | Not accepted |
| 4 | SSH ready after 260.393s; installer completed in **591.731s**, benign request passed, first SQLi assertion failed to observe HTTP 403 | **Failed functional check and time bound** |
| 5 | SSH ready after 237.714s; fresh baseline passed; stopped after the user held the criterion | Cancelled, partial evidence |

Boot time was separate from installer timing, so excluding boot still does not
meet 300 seconds. Attempt 4 did not capture request event/metrics before exit;
the SQLi failure cause is **unresolved**. Do not attribute it to CPU budget or claim
successful VM protection. Diagnostic harness/tool-image files are retained locally
for later work; they are not a passing acceptance test in main.

[Raw outputs and hashes](evidence/standalone-vm-hold/) preserve the negative outcomes.
They do not substitute for a clean-VM pass. The separately accepted [native
package/container checks](standalone-installer-review.md) and [APT bootstrap
checks](standalone-bootstrap-review.md) remain scoped to their recorded environments.
Resumption requires a suitable lab VM and investigation of the failed first SQLi
request, followed by the unchanged five-minute and hot-update acceptance checks.

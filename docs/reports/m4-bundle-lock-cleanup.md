# M4 — bounded bundle-lock cleanup before periodic writes

Branch `codex/m4-bundle-lock-cleanup`, based on PR #195.

The shared build lock previously ignored unlock errors and used an unbounded background context. Canceled acquisition could also return a session whose server-side lock ownership was uncertain to the pool. That is unsuitable for periodic automatic writes across replicas.

Cleanup now uses a separate two-second unlock context. If ownership/unlock is uncertain, it removes the session from the pool and closes it with a separate two-second context; cleanup errors join, rather than replace, a build error. Cancellation of work does not prevent releasing the lock. A recorded action may therefore return a cleanup error; its durable publication intent remains the recovery source, rather than rebuilding blindly.

Real PostgreSQL `-race` tests cancel work after acquiring, cancel another waiter, terminate exactly the fixture database's lock-holder backend, and prove the next build can acquire the lock. Terminating that test session cannot touch another database/session. The full store/policy suites include the real compiler writer integration. Parent source reproduces the regression: `failed unlock silently reported success` (FAIL 0.713 s); fixed source passes 1.659 s. Full race suites pass: store 16.948 s, policy 23.127 s; lint 0 issues. Evidence: [output](evidence/m4-bundle-lock-cleanup/checks.txt).

Self-review: bounded cleanup I/O, discarded uncertain sessions, preserved build errors, no credentials/dependencies/interfaces/test removals; only store lock/tests and related docs. Does not enable the worker or claim node activation. Remaining M4: observation/worker/notification wiring and activation deadline proof.

# Compact B · Final integration corrections

Two regressions were found while validating B01/B02/B04/B05 together.

1. The agent's default optional module manifest was wrapped in an error that
   `os.IsNotExist` did not recognize. A real enrolled agent therefore exited before its
   first Hello when the manifest was absent. Use a dedicated missing-manifest sentinel;
   only absence of that file is tolerated. A present manifest with a missing module binary
   continues to fail. The manifest is still diagnostic and never grants authority.
2. A global administrator could assign themselves a scoped binding and lose their only
   global authority. Binding writes now serialize and recheck actor authority inside the
   transaction, both before and after mutation. Two already-authenticated administrators
   cannot concurrently demote one another. Self-restriction rolls back, with a stable 403
   reason and a translated UI explanation. Trusted internal/bootstrap writers retain their
   explicit store access; the HTTP layer always supplies the authenticated principal.

Evidence on CPUs 6–10:

```text
Before: TestBindingChangesCannotLockOutGlobalAdministrators FAIL
  administrator restricted their own only global authority: <nil>
After: same test + TestApplicationsScopesAndRetriesInPostgres PASS (race, 2.607s)
TestMissingManifestAllowsUnknownCapabilities PASS (race, 1.184s)
Real agent FleetEnrollConnectRevoke failed online-before-Hello before the manifest fix;
rerun after the fix PASS (race, 31.074s), including persisted spool heartbeat telemetry.
```

Negative tests retain rejection of an invalid existing manifest, last-global-binding deletion,
and concurrent stale authorization. API regression checks the 403 reason and that the failed
assignment leaves the administrator global. The final B05 report records the integrated
full race/lint/UI/e2e gates. No signing, TLS or authentication check was relaxed.

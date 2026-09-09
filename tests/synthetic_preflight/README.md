# Original synthetic gap corpus

The September 8 corpus is retained here, including its fictional routes, formula
truth and network-denial probes. It previously had 50 passing/5 failing checks.

Intentional expectation migrations (not removed coverage):

- The unknown-field case now checks the extraction boundary that actually receives
  captured source context. The schema-free parser is not expected to know a schema.
- The two route handoff checks now exercise public review/build commands and reopen
  actual model/document artifacts. Phase strings no longer count as success.
- The original complex capture still has unresolved behaviors. A separate,
  explicitly reduced fictional example tests the supported build slice; passing it
  does not mean the original full workbook migrated.
- Domo-specific coverage belongs in the Domo repo. Existing Sigma lifecycle,
  revocation, replay, retry-budget and synthetic-evidence barriers remain exercised.

Run from the repository root:

```sh
.venv/bin/python -m pytest tests/synthetic_preflight/tests -q
```

The legacy `preflight.py` helper is test-only mock/proposal infrastructure, not the
operator interface. Use `sigma-migrate` to operate the tool. Never use its test
approvals or simulated-live branch as real evidence.

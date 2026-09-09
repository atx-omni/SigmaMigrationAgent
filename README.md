# Sigma Migration Agent

Prepare a Sigma-to-Omni migration, review it, and generate a local pre-push package.
This is the dedicated **ATX Sigma repository**, independent of DomoMigrationAgent.

Two explicit choices, with no default:

- **Lift and shift into Omni's semantic layer:** use existing warehouse relations; no dbt changes.
- **Model upstream first:** generate data-layer artifacts plus the downstream Omni package; deployment remains outstanding.

## Start here

Read [the operator guide](customer/sigma/SETUP-AND-USAGE.md), or open
[the self-contained instruction page](customer/sigma/START-HERE.html).
The guide assumes you own the platforms and have full setup access.

Python 3.11+ on macOS or Linux is required. Windows users need a Linux environment
(for example WSL); native Windows process locking/identity is not supported.

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -e 'packages/omnikit-migration-engine[dev]'
.venv/bin/sigma-migrate --help
```

The public workflow is `capture → configure → init → route → review → build → validate → export`.
You can also import a previously captured snapshot. Review is interactive; hashes
and immutable bindings are generated automatically. No target apply command exists.

## Readiness boundaries

This release is for **supervised local preparation**, not a promise of arbitrary
Sigma workbook parity. Unsupported formulas, incomplete behavior evidence, security
and operational features remain explicit blockers. A package may contain useful
supported output while its overall status remains blocked.

- A local accepted proposal is not a target-write approval.
- A fictional demonstration never becomes live evidence.
- Offline validation does not prove Omni API acceptance, live query parity, persona security or customer acceptance.
- Model/dataset source captures do not contain every layout, control and action detail; source-bound supplemental context may be required.
- Local approval trusts the OS account. It is not shared-service authentication and cannot distinguish a human from another process running as that same account.

See [the plan audit](docs/IMPLEMENTATION-AUDIT.md) for completed work, focused test
evidence and remaining gates. The original synthetic corpus remains in
`tests/synthetic_preflight`; checks verify actual output instead of invented phase names.

## Provenance and isolation

Sigma source and selected shared runtime components were separated from a preserved
development snapshot. [The import inventory](IMPORT-MANIFEST.json) records original
file hashes; [software notices](SOFTWARE-NOTICES.md) explain shared ownership and
excluded surfaces. Shared data types still use some historical Domo names, but no
Domo extractor or Domo operator command is available in this distribution.

No customer data, credentials or local run outputs belong in Git. The package's
Apache-2.0 license and upstream provenance are retained.

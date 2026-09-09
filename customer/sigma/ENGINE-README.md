# OmniKit Migration Engine — Sigma pilot distribution

This source distribution provides bounded Sigma acquisition, reviewed local model/dashboard generation and independent pre-push validation. It is derived from selected shared migration-engine dependencies; use the Sigma platform-owner instructions in `../SETUP-AND-USAGE.md` for this pilot.

The offline `../start.py` walkthrough exercises fictional source extraction and the neutral routing prompt. It performs no network calls, makes no trusted approvals, and does not build Omni content.

Operator-configured `sigma-capability-spike` can capture approved read-only source evidence. The `sigma-semantic-route` and `sigma-run-*` commands connect exact human-reviewed routing to bounded, persisted model proposals. Neither route has a default. Direct Omni reconstruction excludes warehouse/dbt planning; warehouse-first includes it. Sigma planning completion does not authorize or establish target deployment or migration acceptance.

Use Python 3.11 or newer on macOS or Linux. The workflow uses Unix-only file locking and local OS identity. `requirements-tested.txt` records versions tested on Python 3.11; it is not an offline dependency bundle. Do not install target extras for this workflow.

The current `sigma-migrate` commands implement the guided local workflow. The legacy `sigma-run-*` AI planning runner remains separate; its completion does not automatically feed or approve the deterministic compiler. No target apply command exists.

The original Apache-2.0 license and historical upstream import attribution are preserved in `LICENSE` and `PROVENANCE.json`. See `../SOFTWARE-NOTICES.md` for later-adaptation and current-scope notices, and `../PACKAGE-MANIFEST.json` for current file fingerprints. Current source snapshot provenance is distinct from the historical upstream freeze.

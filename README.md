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
.venv/bin/python -m pip install --require-hashes --only-binary=:all: -r packages/omnikit-migration-engine/requirements-build.lock
.venv/bin/python -m pip install --require-hashes --only-binary=:all: -r packages/omnikit-migration-engine/requirements-dev.lock
.venv/bin/python -m pip install --no-deps --no-build-isolation -e packages/omnikit-migration-engine
.venv/bin/sigma-migrate --help
MIGRATION_WORKSPACE="$HOME/.sigma-migrate/workspaces/migration"
.venv/bin/sigma-migrate setup --directory "$MIGRATION_WORKSPACE"
```

Start with guided `setup`, then `doctor`, optional read-only `discover`,
`capture` or snapshot import, optional `scope`, `configure`, `init`, `review`,
`build`, `validate`, `report`, and `export`. Setup records the explicit route;
pass its profile to configure/init so you are not asked twice.
You can also import a previously captured snapshot. Review is interactive; hashes
and immutable bindings are generated automatically. No target apply command exists.

For a tagged chart/table's PNG, JSON results and configuration evidence, see
[source-only visual capture](docs/source-visual-capture.md). `capture-visual`
uses explicit source read/query authorization and resumable export records.
Version 2 adds page PNG and explicitly unselected model support. For fixed host
check/inventory/snapshot/capture requests, implementation pins and optional workbook
contents Beta, see [source operations](docs/source-operations.md). Local checks do
not establish live capture qualification; no target apply command is added.

## Use the current agent skill

The maintained skill is
[sigma-to-omni-migration](.agents/skills/sigma-to-omni-migration/SKILL.md), aligned
with runtime **0.4.1**. It replaces the older bespoke POC instructions; it does not
require Sigma/Omni MCP, Omni CLI, or an AI-provider key for local preparation.
Optional OAuth and live topic discovery use the official Omni CLI. Token-based
model/connection discovery does not require it. Discovery is read-only.

Setup writes a private, conditional `.env` template and a step-by-step local
checklist. It never asks for secrets in chat or overwrites existing credentials.
Choose dashboard-only reuse to preserve an existing Topic; this emits query and
document proposals without model or dbt changes. Reviewed target field evidence
is still required. See [the operator guide](customer/sigma/SETUP-AND-USAGE.md)
for the supported workflow and remaining limits.

Open this checkout as your Codex project. Its repository-scoped skill lives in
`.agents/skills`, following [official Codex skill discovery](https://developers.openai.com/codex/skills).
Ask: “Use the sigma-to-omni-migration skill to prepare one workbook. Ask me whether
to model upstream or lift and shift directly, and stop for my local review.”
If the skill does not appear, restart Codex. Skill discovery does not install
Python; complete the runtime installation above first.

For another project, copy the complete `sigma-to-omni-migration` folder into that
project's `.agents/skills/` without overwriting an existing customized skill, and
tell the agent where this runtime checkout lives. Keep skill and runtime from the
same repository revision. The customer-package builder includes the same skill
files and checksums; no nested skill ZIP is needed. The standalone terminal
workflow remains available without an AI assistant.

The agent must not answer the terminal approval prompt for you. It will pause
and give you the `review` command when it cannot hand over an interactive terminal.

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

See [the release notes](CHANGELOG.md) and [security policy](SECURITY.md) for
delivered controls and remaining gates. The original synthetic corpus remains in
`tests/synthetic_preflight`; checks verify actual output instead of invented phase names.

## Provenance and isolation

Sigma source and selected shared runtime components were separated from a preserved
development snapshot. [The import inventory](IMPORT-MANIFEST.json) records original
file hashes; it is historical provenance, not the current file inventory. Internal
plans and work logs are excluded from deployment. [Software notices](SOFTWARE-NOTICES.md)
explain shared ownership and excluded surfaces. Shared data types still use some historical Domo names, but no
Domo extractor or Domo operator command is available in this distribution.

No customer data, credentials or local run outputs belong in Git. The package's
Apache-2.0 license and upstream provenance are retained.

## Security hardening in 0.4.1

Operational files now belong in a private workspace outside the checkout. Existing
evidence is never moved, deleted, or silently re-permissioned. Git-trackable and
shared output directories are refused. All exports use one maintained secret
scanner; a credential finding blocks export even when semantic blockers are allowed.
Default exports contain a minimal support summary; full confidential source and
target artifacts require `export --purpose migration` and separate sharing review.

The advanced AI proposal path is disabled pending an independently authenticated
egress gateway. An approval reference or local review cannot re-enable it. This
does not disable deterministic offline migration preparation. Capture and discovery
enforce streaming byte, request, and time limits and keep only required source
connections. Install from the hash-locked dependency files above.

See [the release notes](CHANGELOG.md) and [security/release policy](SECURITY.md)
for delivered controls, upgrade steps, and external
release-signing and repository-control gates. A draft ZIP and its checksums are
not an authenticated customer release.

The follow-up scanner policy covers API-token and credentials properties across
structured data, assignments and URLs. Acquisition accepts UTF-8 JSON only and
checks structure on the same decoded text it parses, while preserving raw evidence
hashes. Revalidate older runs and create a new export before sharing; installing
this update does not clear existing ZIPs. GitHub protection remains separately
configured; see the setup steps in [SECURITY.md](SECURITY.md#github-protection-setup).

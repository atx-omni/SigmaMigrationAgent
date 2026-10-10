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
.venv/bin/sigma-migrate setup --directory migration-setup
```

Start with guided `setup`, then `doctor`, optional read-only `discover`,
`capture` or snapshot import, optional `scope`, `configure`, `init`, `review`,
`build`, `validate`, `report`, and `export`. Setup records the explicit route;
pass its profile to configure/init so you are not asked twice.
You can also import a previously captured snapshot. Review is interactive; hashes
and immutable bindings are generated automatically. No target apply command exists.

## Use the current agent skill

The maintained skill is
[sigma-to-omni-migration](.agents/skills/sigma-to-omni-migration/SKILL.md), aligned
with runtime **0.3.0**. It replaces the older bespoke POC instructions; it does not
require Sigma/Omni MCP, Omni CLI, or an AI-provider key for local preparation.
Optional OAuth and live topic discovery use the official Omni CLI. Token-based
model/connection discovery does not require it. Discovery is read-only.

Setup writes a private, conditional `.env` template and a step-by-step local
checklist. It never asks for secrets in chat or overwrites existing credentials.
Choose dashboard-only reuse to preserve an existing Topic; this emits query and
document proposals without model or dbt changes. Reviewed target field evidence
is still required. See [the configuration-first audit](docs/GUIDED-SETUP-AUDIT.md)
for delivered features and remaining limits.

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

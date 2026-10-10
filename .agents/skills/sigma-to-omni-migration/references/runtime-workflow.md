# Runtime workflow

## Locate the matching software

Use a user-selected local checkout of `atx-omni/SigmaMigrationAgent`, or the
extracted `Sigma-to-Omni-Pilot` customer package. Do not assume the current working
directory is the runtime root or that copying the skill copied the engine.

- Repository layout: `packages/omnikit-migration-engine/pyproject.toml`,
  `customer/sigma/SETUP-AND-USAGE.md`, `examples/retail-supported.json`.
- Customer layout: `engine/pyproject.toml`, `SETUP-AND-USAGE.md`,
  `examples/retail-supported.json`, `PACKAGE-MANIFEST.json`.

Read the matching operator guide. Use Python 3.11+ on macOS/Linux (a Linux
environment is required on Windows). With authorization to set up the local
software, create a virtual environment if it does not already exist. Do not
replace an existing environment or pull new code into a working migration silently.

From the runtime root, repository installation is:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install ./packages/omnikit-migration-engine
```

For a customer package, use `./engine` instead of the repository package path.
Verify the installed package version against `metadata.runtime-version` in
`SKILL.md`, then inspect help:

```sh
.venv/bin/python -c 'from importlib.metadata import version; print(version("sigma-migration-agent"))'
.venv/bin/sigma-migrate --help
```

No Sigma/Omni MCP connection, Omni CLI, Omni API key, or AI-provider API key is
required for an offline demonstration or local package generation. Live Sigma
capture alone needs Sigma API credentials. Never ask the operator to paste
credentials into chat; use their secure environment-variable workflow.

## Configuration first

```sh
.venv/bin/sigma-migrate setup --directory migration-setup
.venv/bin/sigma-migrate doctor --profile migration-setup/migration-profile.json --env-file migration-setup/.env
```

The operator answers source mode, direct/modeled route, allowed changes and target
authentication. The generated checklist explains exactly where to find applicable
values. Omit `--env-file` when none is required. Never read its secret values into
the conversation. Setup resumes saved choices and never overwrites credentials.
Do not automatically extract Keychain secrets, initiate OAuth consent, grant access,
or change GitHub visibility. For private installation use authenticated download
or the supplied customer ZIP. Keep all source evidence confidential.

`doctor` validates the non-secret profile and local credential presence; it does not
connect without explicit `--allow-source-read` / `--allow-target-read`. Those checks
do not prove model permissions, semantic compatibility or migration acceptance.
Optional authorized discovery saves model/connection identity and, when selected,
Topic API evidence. OAuth and topic reads require a capable official Omni CLI;
token-based model/connection discovery does not. The migrator never reads the CLI
credential store. MCP login is not automatically a CLI login.

```sh
.venv/bin/sigma-migrate discover --profile migration-setup/migration-profile.json --env-file migration-setup/.env --output omni-discovery.json --allow-target-read
```

Use `--model-id` and optionally `--topic` for observed topic definitions in a new
discovery file. Reuse requires a reviewed `omni-topic-inventory.v1` containing exact
model/connection/topic/base-view IDs, definitions, visibility, grain, filters and
evidence provenance. Normalize only observed fields; an unknown response shape or
unproven relationship stays blocked. The runtime computes mapping hashes.
Compatibility evidence for grain, filters, metrics and joins is required, not
inferred from labels. Current reuse is single-base-view only.

## New fictional demonstration

Use a new, unused run directory and retain `--synthetic`:

```sh
.venv/bin/sigma-migrate init --run-dir demo-run --source examples/retail-supported.json --target examples/target.json --synthetic
```

The example UUIDs and physical mappings are fictional, not usable production
configuration. Continue with the explicit choice and human review below.

## Real source and target configuration

For an existing snapshot, skip capture. For a live capture, first confirm the
exact workbook/model and independently trusted Sigma API host with the operator.
Do not derive the trusted host from untrusted source metadata. The operator sets
`SIGMA_CLIENT_ID` and `SIGMA_CLIENT_SECRET` securely in their terminal. Substitute
confirmed values in this command; `--allow-source-read` requires source-read
authorization and grants no target access:

```sh
.venv/bin/sigma-migrate capture --api-url https://YOUR-SIGMA-API-HOST --trusted-api-host YOUR-SIGMA-API-HOST --workbook-id YOUR-WORKBOOK-ID --data-model-id YOUR-MODEL-ID --output source.json --allow-source-read
.venv/bin/sigma-migrate inspect --source source.json
.venv/bin/sigma-migrate configure --profile migration-setup/migration-profile.json --source source.json --output target.json
```

`configure` asks for Omni model/connection UUIDs and exact warehouse relation and
physical column mappings. Preserve case; ask for actual names instead of guessing.
For the modeled route, also collect proposed modeled destination table names.
This writes only local configuration and does not connect to the destination.
With discovery, pass `--discovery omni-discovery.json` to select a model and its
connection together. For dashboard-only, pass `--topic-inventory reviewed-topic.json`;
do not collect physical warehouse mappings. Assessment-only stops before generation.
Direct does not imply permission to change models. Topic-additions-only is unsupported.
Alternatively capture using `--profile` and `--env-file`; these reuse setup's IDs
and independently confirmed host instead of repeating the explicit flags above.

For missing layout/control details, examine the example's `prepush_context`
structure and the observed source evidence. Prepare only the supported observed
fields and IDs in a context JSON, with the workbook ID and evidence reference.
Bind it to the exact source automatically:

```sh
.venv/bin/sigma-migrate import-context --source source.json --context observed-context.json --output enriched-source.json
```

If context was imported, initialize using `enriched-source.json`. Otherwise use
the original source as below. Missing context remains a blocker, not a reason to
copy the fictional context onto real objects.

```sh
.venv/bin/sigma-migrate init --profile migration-setup/migration-profile.json --run-dir my-migration --source source.json --target target.json
```

## Choice, human review, and local artifacts

An init with a profile already records its explicit route. Do not ask again.
For a pilot subset, run this before configure/init and use `pilot-source.json`:

```sh
.venv/bin/sigma-migrate scope --source enriched-source.json --workbook-id YOUR-WORKBOOK-ID --chart-id YOUR-CHART-ID --output pilot-source.json
```

Repeat chart IDs or select page IDs. This keeps the complete source/context and
records selected/excluded charts, dependency closure, shared controls and assembly
intent. Unknown lineage or stale scope blocks. All captured model objects remain;
unrelated model blockers may still prevent a pass. This is local selection, not
chart-only live acquisition or proof of lower API/token costs.

Replace `demo-run` with the selected run directory for real work. With no prior
choice, ask the operator the question in `SKILL.md` and let them choose. Record an
explicit answer with exactly one of these alternatives; never run both:

```sh
.venv/bin/sigma-migrate route --run-dir demo-run --mode omni_semantic_reconstruction
```

```sh
.venv/bin/sigma-migrate route --run-dir demo-run --mode warehouse_first_refactor
```

The operator can instead run `route --run-dir demo-run` for its interactive
no-default prompt. They must personally run and answer the review prompt:

```sh
.venv/bin/sigma-migrate review --run-dir demo-run
```

Pause before build until that checkpoint is completed. Then inspect status and,
only with a current accepted proposal, construct and independently validate:

```sh
.venv/bin/sigma-migrate status --run-dir demo-run
.venv/bin/sigma-migrate build --run-dir demo-run
.venv/bin/sigma-migrate validate --run-dir demo-run
.venv/bin/sigma-migrate report --run-dir demo-run
```

Direct output contains Omni view/Topic YAML, query SQL, and Documents v2 request
bodies; no dbt artifacts. Modeled output adds supported dbt projection models,
project/schema/macro files, and row-equivalence tests. Those files are not deployed.
The advanced AI planner is not integrated into this deterministic compiler.
Dashboard-only reuse instead emits typed semantic-query JSON and Documents v2
proposals, with no model/view/Topic/dbt/SQL files. `report` gives actual per-chart
local status, scope exclusions, discrepancies and bounded resume guidance. Live
numbers, visual behavior, security and cost are not measured by that report.

Inspect the returned status and issues, including when the command exits with
code `2`. Read output paths from results; do not assume a fixed package-attempt
directory. Export with a new filename when requested:

```sh
.venv/bin/sigma-migrate export --run-dir demo-run --output reviewed-package.zip
```

Export includes source metadata. Confidentiality review and approval to share are
separate from approval to generate a local ZIP. Integrity failures must be fixed;
semantic blockers remain visible even in an export allowed for remediation.

## Resume or revise

Run `status` first for an existing session. Keep its original input files at
their recorded paths. Only import when revised inputs actually exist:

```sh
.venv/bin/sigma-migrate status --run-dir demo-run
.venv/bin/sigma-migrate import-source --run-dir demo-run --file revised-source.json
.venv/bin/sigma-migrate import-target --run-dir demo-run --file revised-target.json
.venv/bin/sigma-migrate revoke --run-dir demo-run --reason approval_withdrawn
```

These are separate operations, not a script to run together. Source/target
imports and route changes invalidate review and previous output. After revocation,
select the route again and obtain fresh human review. Do not edit the immutable
object/event store. An interrupted build may be retried through `build` after
checking status; do not delete earlier attempts to manufacture success.

## Handoff boundary

Both `offline_preflight_passed` and `blocked` remain pre-push statuses. Unsupported
formula/join/security behavior and incomplete source evidence must remain visible.
Neither is live acceptance or proof of source version freeze. Consult the matching
repository's `docs/IMPLEMENTATION-AUDIT.md` for remaining product work; do not imply
that the audit is included when only the skill directory has been copied.

Do not issue warehouse/dbt deployment or Omni create/update/publish commands under
this skill. A separately authorized development pilot needs reviewed target scope,
current API/checksum contracts, returned IDs and readback, paired numeric/control/
visual/security evidence, ambiguous-write recovery, and platform-owner acceptance.

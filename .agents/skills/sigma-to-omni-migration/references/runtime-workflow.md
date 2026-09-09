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
.venv/bin/sigma-migrate configure --source source.json --output target.json
```

`configure` asks for Omni model/connection UUIDs and exact warehouse relation and
physical column mappings. Preserve case; ask for actual names instead of guessing.
For the modeled route, also collect proposed modeled destination table names.
This writes only local configuration and does not connect to the destination.

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
.venv/bin/sigma-migrate init --run-dir my-migration --source source.json --target target.json
```

## Choice, human review, and local artifacts

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
```

Direct output contains Omni view/Topic YAML, query SQL, and Documents v2 request
bodies; no dbt artifacts. Modeled output adds supported dbt projection models,
project/schema/macro files, and row-equivalence tests. Those files are not deployed.
The advanced AI planner is not integrated into this deterministic compiler.

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

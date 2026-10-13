# Sigma-to-Omni: setup and operating guide

**DRAFT — requires explicit SE/AE review before sending to customer.**

## 1. What this tool does

This tool reads Sigma metadata, helps you choose a migration approach, and prepares
a reviewed local package containing model and dashboard proposals. It does not
publish to Omni. You are the migration operator and platform owner; the instructions
assume you have full access to configure Sigma, the warehouse and Omni.

Supported output is generated; product/integration gaps remain clearly listed.
A green local check is not proof that a real workbook has migrated successfully.

## 2. What you need

Use macOS or Linux with Python 3.11 or newer, a terminal and an extracted copy of
this package. Native Windows is not supported; use a Linux environment such as WSL.
You do not need to gather every credential in advance. Guided setup asks which
path you need and creates the right checklist. Live source capture needs a Sigma
API client ID/secret, the organization's API host, one workbook and its data-model
ID. Omni discovery is optional: choose browser login, a personal token, or stay
offline with reviewed target details. Model/connection IDs can be discovered.

No AI-provider credential is needed for this deterministic workflow. The advanced
AI proposal runner is disabled until a separate authenticated approval gateway
exists. No local approval flag or reference enables it.

## 3. Install once

First confirm the intended release and publisher through your team's trusted
delivery channel. A ZIP's own checksums do not prove who supplied it. Have the
release signature/attestation verified using independently trusted publisher
details before extracting or installing it. An unsigned draft is for supervised
evaluation only, not an authenticated customer release.

Open a terminal in the extracted customer package folder (the one containing
START-HERE.html). Run:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install --require-hashes --only-binary=:all: -r engine/requirements-build.lock
.venv/bin/python -m pip install --require-hashes --only-binary=:all: -r engine/requirements-runtime.lock
.venv/bin/python -m pip install --no-deps --no-build-isolation ./engine
.venv/bin/sigma-migrate --help
```

From a GitHub checkout instead, replace `./engine` with
`./packages/omnikit-migration-engine`. Always run the remaining commands from the
same folder. Keep the terminal and source files available while reviewing a run.

## 4. Start with guided setup

```sh
MIGRATION_WORKSPACE="$HOME/.sigma-migrate/workspaces/migration"
.venv/bin/sigma-migrate setup --directory "$MIGRATION_WORKSPACE"
```

This is your private working folder, separate from the downloaded software. Use a
different final folder name for each migration. Keep this terminal open; if you
open another, set `MIGRATION_WORKSPACE` to the same folder again. You can also run
`setup` without `--directory` to use this default location. Setup prints its exact
location; open it using your file browser's **Go to Folder** option.

Answer four short questions: source capture or existing snapshot; direct or
modeled migration; allowed changes; and optional Omni connection method.
There is no silent migration-route default. These choices are separate:

- **Assessment only:** inspect source coverage; no target artifacts are built.
- **Dashboard-only:** use an existing Omni Topic; no view, model, Topic or dbt changes.
- **Model changes:** prepare model/Topic and dashboard proposals; modeled migration adds supported dbt artifacts.

Setup creates `migration-profile.json`, `SETUP-NEXT-STEPS.txt`, and, only when
needed, a private `.env` containing exactly the required variables. It creates
owner-only folders/files and a `.gitignore` protecting all working data, including
renamed snapshots, target mappings, discovery and runs. Open the checklist, then edit `.env` locally
to replace `REPLACE_LOCALLY`. Do not paste secrets into chat or run `source .env`.
Do not commit working files—even in a private repository. The tool refuses
Git-trackable, already-tracked or shared output locations. Do not force-add them
to Git. The privacy checks prevent accidental publication; another process using
your OS account still has access. Original source metadata remains confidential
even when it contains no credentials.

Where to get each value:

| Selected path | What to provide | Where to find it |
|---|---|---|
| Sigma API capture | `SIGMA_API_URL` | Sigma Administration → Developer access → API base URL. Use the displayed regional host, not your workbook browser URL. |
| Sigma API capture | `SIGMA_CLIENT_ID`, `SIGMA_CLIENT_SECRET` | Create REST API credentials in Developer access, choose the intended owner, and save the displayed ID/secret locally. The secret is shown once. |
| Omni personal token | `OMNI_BASE_URL` | Your organization's HTTPS origin, with no workbook path. |
| Omni personal token | `OMNI_API_TOKEN` | User profile → Manage account → Generate token. Use the permissions needed for the selected reads; a broad organization key is not the default. |
| Omni browser login | No Omni secret in `.env` | Install the current official Omni CLI. Create/select the named profile and complete browser consent yourself; follow the generated checklist. |
| Offline snapshot and target | No credentials | Use reviewed local files. Neither MCP nor an AI-provider key is required. |

Official instructions: [Sigma credentials](https://help.sigmacomputing.com/reference/generate-client-credentials),
[Omni authentication](https://docs.omni.co/api/authentication), and
[Omni CLI browser login](https://docs.omni.co/developers/cli/authentication).
The CLI owns its OAuth tokens. This tool does not read Apple Keychain; if credentials
are already there, retrieve them yourself and fill the private file, or use the
existing supported CLI OAuth profile. MCP authentication alone does not configure
the CLI. Never make the GitHub repository public to bypass installation access:
use an authenticated private download or the provided customer ZIP.

Check local configuration without connecting:

```sh
.venv/bin/sigma-migrate doctor --profile "$MIGRATION_WORKSPACE/migration-profile.json" --env-file "$MIGRATION_WORKSPACE/.env"
```

Omit `--env-file` if your selected path did not create one. When ready, add
`--allow-source-read` and/or `--allow-target-read` to authorize the applicable
connection checks. Source checks verify selected workbook/model access, not their
lineage or full capture. Target checks verify identity, not write permission or
semantic compatibility. Process environment overrides the selected `.env`; a host
conflict blocks before credentials are sent. No implicit `.env` search occurs.

Re-run setup with the same directory to resume without replacing the profile or
credentials. For different choices, use a new setup directory, then import revised
inputs into your existing migration and review again. Setup does not install
software, grant access, create keys, or change platform settings on your behalf.

### Optional fictional first run

The supplied small example is a supported, explicitly fictional slice. It is not
a substitute for your workbook and does not contain customer data. Start with:

```sh
.venv/bin/sigma-migrate init --run-dir "$MIGRATION_WORKSPACE/demo-run" --source examples/retail-supported.json --target examples/target.json --synthetic
```

Then continue at step 7 (this legacy demo chooses its route there). Do not reuse the example's target UUIDs for real work.
The old `start.py` is retained only as a source-extraction demonstration; use
`sigma-migrate` for the complete local review/build flow.

## 5. Capture your Sigma source

After completing the generated setup checklist:

```sh
.venv/bin/sigma-migrate capture --profile "$MIGRATION_WORKSPACE/migration-profile.json" --env-file "$MIGRATION_WORKSPACE/.env" --output "$MIGRATION_WORKSPACE/source.json" --allow-source-read
```

This authorizes only a bounded Sigma metadata read. Some layout, control targets,
security, actions and input-table details are not complete in API metadata. The
tool must block those gaps until sufficient source-bound context is supplied.
Capture does not certify a version freeze or live source completeness. Existing
capture files are not overwritten; use a new filename for a new capture.
Only connections required by the selected source lineage are retained, with a
small identity/type field set. Unknown or ambiguous connection lineage stops
capture; do not select all connections to bypass that error.
The default request budget is 100; `--request-budget` permits an explicit 5–1000
bound. Increasing it does not resolve missing access or unsupported behavior.
Separate streamed-response, cumulative-data and time limits cannot be bypassed by
raising the request count. If a limit is reached, choose a smaller coherent source
scope; the tool does not save a successful-looking partial capture.
Compressed API responses are refused. Run these commands directly in the terminal
on macOS/Linux; embedded background-thread HTTP execution is not supported.
For a workbook in another user's My Documents, check access using the credential's
owner. A deliberate copy may help, but it creates a new identity: recapture and
review it as a new source, preserving the original and its dependencies.

## 6. Configure your destination

Optionally discover real model/connection IDs instead of copying UUIDs manually:

```sh
.venv/bin/sigma-migrate discover --profile "$MIGRATION_WORKSPACE/migration-profile.json" --env-file "$MIGRATION_WORKSPACE/.env" --output "$MIGRATION_WORKSPACE/omni-discovery.json" --allow-target-read
```

Omit `--env-file` for OAuth-only setup. This lists shared models and connections;
extensions/workbook models are not in this first-pass list. To capture topic
definitions too, repeat into a new output file with `--model-id YOUR-MODEL-ID`
and optionally `--topic YOUR_TOPIC`. Topic discovery requires the current official
Omni CLI for either authentication method; token-based ID discovery uses REST and
does not require it. Older CLI builds without `whoami` must be updated for OAuth.

Run guided configuration with the choices already saved in setup:

```sh
.venv/bin/sigma-migrate configure --profile "$MIGRATION_WORKSPACE/migration-profile.json" --source "$MIGRATION_WORKSPACE/source.json" --discovery "$MIGRATION_WORKSPACE/omni-discovery.json" --output "$MIGRATION_WORKSPACE/target.json"
```

Enter the intended Omni model/connection IDs and exact warehouse schema, table and
physical column names when prompted. Preserve capitalization. For warehouse-first,
also enter the proposed modeled destination table name. This writes a local
mapping file and makes no connection to Omni.
Omit `--discovery` when supplying IDs manually. Direct migrations do not prompt
for modeled destination tables. Assessment-only prints coverage and stops here.

For dashboard-only reuse, also pass `--topic-inventory "$MIGRATION_WORKSPACE/reviewed-topic.json"`.
The inventory must use `omni-topic-inventory.v1` and contain the observed Topic's
exact model/connection IDs, base view, timestamp, evidence reference, grain,
filters, and field definitions/visibility. The agent can help normalize the saved
topic response into this contract; the tool does not guess an unknown API response
shape. Review those definitions, then map exact field IDs and explain compatible
grain, filters, metrics and joins. Hashes are calculated automatically. Unmapped,
hidden or incompatible fields block; matching display names is not sufficient.
This first pass supports one base view, not arbitrary joined Topic migrations.
`examples/retail-topic-inventory.json` shows the exact structure using fictional
data. Use it only with the fictional retail snapshot; for real work, replace every
identity and definition with observed evidence. Do not relabel this example as a
live inventory. No manual hashes are needed.

For captured/reviewed layout and controls, use `sigma-migrate inspect --source "$MIGRATION_WORKSPACE/source.json"`
to list captured identities. Prepare a context JSON with the workbook ID, evidence
reference, observed element fields/chart/layout/sorts/limit and observed control
targets, following the `prepush_context` structure in the example. Do not calculate
its hash. Bind it automatically with:

```sh
.venv/bin/sigma-migrate import-context --source "$MIGRATION_WORKSPACE/source.json" --context "$MIGRATION_WORKSPACE/observed-context.json" --output "$MIGRATION_WORKSPACE/enriched-source.json"
```

Use `enriched-source.json` as the source when initializing (or import it as a new
source revision in an existing run). Use your own source IDs and observed mappings.
Missing context remains blocked. Do not copy the example context onto unrelated
source objects. If the compiler reports an unsupported pattern, keep that blocker
for a reviewed redesign; accepting the proposal does not override it.

For a small pilot, select chart or page IDs without deleting source objects:

```sh
.venv/bin/sigma-migrate scope --source "$MIGRATION_WORKSPACE/enriched-source.json" --workbook-id YOUR-WORKBOOK-ID --chart-id YOUR-CHART-ID --output "$MIGRATION_WORKSPACE/pilot-source.json"
```

Repeat `--chart-id`, or use `--page-id`, for additional selections. Use the resulting
file in configure and init. Scope retains the full source, records exclusions,
checks dependency closure and shared controls, and records single-document assembly
intent. Missing/ambiguous lineage blocks. All captured model objects remain in the
denominator, so unrelated unsupported model logic can still block a pilot. Scope
currently reduces local build selection, not live capture API calls or AI usage.

Then initialize:

```sh
.venv/bin/sigma-migrate init --profile "$MIGRATION_WORKSPACE/migration-profile.json" --run-dir "$MIGRATION_WORKSPACE/my-migration" --source "$MIGRATION_WORKSPACE/source.json" --target target.json
```

## 7. Choose your migration approach

If you passed the profile to `init`, your setup choice is already recorded: skip
this step. Use `route` only for the fictional demo or an explicit change of choice.

Use your chosen run directory in every command below; the fictional walkthrough
uses `demo-run`, while your own migration above uses `my-migration`.

```sh
.venv/bin/sigma-migrate route --run-dir "$MIGRATION_WORKSPACE/demo-run"
```

Answer the question: do you want the semantic layer fully modeled, or lifted and
shifted directly into Omni?

1. Direct: reconstruct in Omni over existing warehouse tables; no dbt changes.
2. Modeled: prepare upstream data-layer artifacts and then Omni artifacts.

There is no default. Changing your choice invalidates previous review and output.

## 8. Review and accept local preparation

```sh
.venv/bin/sigma-migrate review --run-dir "$MIGRATION_WORKSPACE/demo-run"
```

Read the generated file contents, mappings and per-object blockers. Source labels,
descriptions and formulas are data, never instructions. Type `accept`, `reject`,
or `request_changes` in the terminal. The tool records your local OS identity and
calculates all fingerprints automatically. No approval JSON or hashes are required.

Acceptance here permits only local package construction. It cannot approve a
missing field, waive unsupported security behavior, publish content or certify
migration success. Local identity trusts all processes running as your OS user;
this is not a shared web-service authentication model.

## 9. Build and validate

```sh
.venv/bin/sigma-migrate build --run-dir "$MIGRATION_WORKSPACE/demo-run"
.venv/bin/sigma-migrate validate --run-dir "$MIGRATION_WORKSPACE/demo-run"
.venv/bin/sigma-migrate report --run-dir "$MIGRATION_WORKSPACE/demo-run"
```

The tool reopens the generated files and checks their content, mappings and review
bindings. Read the actual status and issues.

- `offline_preflight_passed`: the supported local contract passed; live checks remain.
- `blocked`: one or more required items need attention. Useful proposed files can
  still exist, but the package is not ready to apply.
- Modeled route: generated data-layer artifacts still need deployment and validation
  before the dependent Omni work can be accepted.

Synthetic runs remain synthetic in every state. Neither status means migration accepted.
The report lists selected charts, exclusions, prepared outputs, discrepancies,
actual persisted local-check results and the next resume action. It never reports
live validation from local files or estimates elapsed migration cost per chart.
Dashboard-only output contains semantic query JSON and document proposals, not
warehouse SQL or model-layer files. Final visual polish remains separate.

## 10. Export and share the result

```sh
.venv/bin/sigma-migrate export --run-dir "$MIGRATION_WORKSPACE/demo-run" --output "$MIGRATION_WORKSPACE/reviewed-package.zip"
```

The default creates a new ZIP with a minimal support summary only: counts and local
status, without source labels, formulas, SQL, target files or connection metadata.
To hand the full confidential migration package to an authorized migration team,
explicitly request:

```sh
.venv/bin/sigma-migrate export --run-dir "$MIGRATION_WORKSPACE/demo-run" --output "$MIGRATION_WORKSPACE/confidential-migration.zip" --purpose migration
```

The full export includes original source metadata and proposed target files.
Review its contents and intended recipients before sharing. The scanner is a
credential guard, not proof that business information is safe to disclose.
Credential or integrity findings block both export types; semantic blockers remain
visible in a permitted remediation export. Existing ZIPs are never overwritten.
There is no Omni push command.

Before sharing an export made with an older version, update the runtime and skill
together through your reviewed installation process. Run `validate` on the original
run, read its current result, and export again using a new filename. A previous
passed report does not clear the package under the newer credential checks, and
installing the update does not change an existing ZIP. Keep the original inputs,
ZIPs and history private and unchanged. If you only have the old ZIP, pause sharing
and arrange a private security/integrity review; the tool does not import ZIPs.

## 11. Resume, update or withdraw review

```sh
.venv/bin/sigma-migrate status --run-dir "$MIGRATION_WORKSPACE/demo-run"
.venv/bin/sigma-migrate import-source --run-dir "$MIGRATION_WORKSPACE/demo-run" --file "$MIGRATION_WORKSPACE/revised-source.json"
.venv/bin/sigma-migrate import-target --run-dir "$MIGRATION_WORKSPACE/demo-run" --file "$MIGRATION_WORKSPACE/revised-target.json"
.venv/bin/sigma-migrate revoke --run-dir "$MIGRATION_WORKSPACE/demo-run" --reason approval_withdrawn
```

Only run the update commands when you actually have revised input. Updating either
input invalidates the review and package; repeat review and build. Source changes
made outside the tool are detected and require reimport. Revocation stops reuse;
select a route and perform a fresh review to resume. Keep the original input files
at their recorded paths while the run is active.

## 12. Troubleshooting and the final live gate

If an input is missing, changed, oversized, credential-bearing or uses symbolic
links, correct that input and retry. The tool refuses unsafe paths and duplicate
JSON keys. Existing run names and ZIP filenames are not overwritten; choose a new
name. A build interrupted before completion is not a successful package; rebuild
after checking status.

Live capture and discovery require UTF-8 JSON. If a source or CLI returns UTF-16,
UTF-32 or invalid JSON, correct that producer's output and capture again; do not
convert a sealed capture in place or weaken the size/structure limits. Unicode
names and labels remain supported in UTF-8.

For an existing 0.3.0 run, preserve its originals and history. If the new version
refuses its location or permissions, do not delete the evidence, force-add it to
Git or rewrite recorded paths. Plan a reviewed move/import into a new private
workspace. The upgrade never relocates or changes old files automatically.

Unresolved formulas/field references, unsupported controls/actions/writeback,
security policy differences and missing layout evidence need explicit remediation.
Do not remove source objects just to obtain a green result. Any reduced pilot scope
must be deliberately recorded as a different migration, not claimed as the original
workbook's complete migration.

For connection problems: rejected credentials require refresh/login; denied access
requires checking the selected identity's role and resource access; missing resources
require checking organization and IDs; rate limits require waiting before retry.
Do not disable TLS checks or add broader keys merely to make a check green. After a
one-time lookup, revoke temporary keys through the platform when no longer needed;
the tool never revokes or creates keys automatically.

When comparing numbers, distinguish migration errors, source quirks, deliberate
corrections, and data-timing differences. A discrepancy is unresolved until evidence
supports its classification; matching Sigma does not prove the original logic correct.

Before claiming success, separately authorize a bounded live development pilot:
apply reviewed artifacts, confirm returned IDs and readback, compare source/target
numbers, controls, visibility, allowed/denied personas and visual behavior, then
obtain platform-owner acceptance. No live deployment or independent human operator
walkthrough is claimed by the synthetic checks delivered with this tool.

## 13. Optional: use the agent skill

The current `sigma-to-omni-migration` skill is included in
`.agents/skills/sigma-to-omni-migration`. It guides the same steps above and is
aligned with runtime version 0.4.1. It does not add an Omni push capability.
Using the terminal directly remains an option; an AI assistant is not required.

After installing Python and the runtime in step 3, open the extracted package
folder or GitHub checkout as your Codex project. Ask: “Use the
sigma-to-omni-migration skill to guide setup first, then prepare one workbook.
Ask whether I want it modeled upstream or lifted and shifted, and whether to
reuse an existing Topic without model changes. Stop for my review.”

Codex discovers repository/project skills in `.agents/skills`; if the skill does
not appear, restart Codex. See [official skill setup](https://developers.openai.com/codex/skills).
Some file browsers hide folders beginning with a dot; the `.agents` folder is
included in the package even when it is not initially visible.

For a different project, copy the entire `sigma-to-omni-migration` folder into
that project's `.agents/skills/`, preserve any existing customized version, and
tell the agent where this installed runtime lives. Copying the skill does not copy
the engine or examples. Keep the skill and runtime from the same package/repository
revision, instead of mixing these instructions with the old bespoke POC skill.

The agent can explain mappings and run authorized preparation steps, but it must
not accept its own proposal. You personally run the `review` command from step 8
and enter your decision in the terminal. The agent then checks status before
continuing. Never paste credentials into the conversation.

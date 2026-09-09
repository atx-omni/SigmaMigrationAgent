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
For your own source capture, have a Sigma API client ID/secret, the correct regional
API host, one workbook ID and its data-model ID. Have the intended Omni model and
connection UUIDs and the warehouse schema, table and column names.

No AI-provider credential is needed for this deterministic workflow. The advanced
proposal runner is separate from this guide.

## 3. Install once

Open a terminal in the extracted customer package folder (the one containing
START-HERE.html). Run:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install ./engine
.venv/bin/sigma-migrate --help
```

From a GitHub checkout instead, replace `./engine` with
`./packages/omnikit-migration-engine`. Always run the remaining commands from the
same folder. Keep the terminal and source files available while reviewing a run.

## 4. First try the fictional example

The supplied small example is a supported, explicitly fictional slice. It is not
a substitute for your workbook and does not contain customer data. Start with:

```sh
.venv/bin/sigma-migrate init --run-dir demo-run --source examples/retail-supported.json --target examples/target.json --synthetic
```

Then continue at step 7. Do not reuse the example's target UUIDs for real work.
The old `start.py` is retained only as a source-extraction demonstration; use
`sigma-migrate` for the complete local review/build flow.

## 5. Capture your Sigma source

In your terminal, set SIGMA_CLIENT_ID and SIGMA_CLIENT_SECRET using your normal
secure credential workflow. Do not put credentials in a JSON file, Git, screenshots
or the package you share.

Replace the host and IDs in this command with your own:

```sh
.venv/bin/sigma-migrate capture --api-url https://YOUR-SIGMA-API-HOST --trusted-api-host YOUR-SIGMA-API-HOST --workbook-id YOUR-WORKBOOK-ID --data-model-id YOUR-MODEL-ID --output source.json --allow-source-read
```

This authorizes only a bounded Sigma metadata read. Some layout, control targets,
security, actions and input-table details are not complete in API metadata. The
tool must block those gaps until sufficient source-bound context is supplied.
Capture does not certify a version freeze or live source completeness. Existing
capture files are not overwritten; use a new filename for a new capture.

## 6. Configure your destination

Run the guided configuration command:

```sh
.venv/bin/sigma-migrate configure --source source.json --output target.json
```

Enter the intended Omni model/connection IDs and exact warehouse schema, table and
physical column names when prompted. Preserve capitalization. For warehouse-first,
also enter the proposed modeled destination table name. This writes a local
mapping file and makes no connection to Omni.

For captured/reviewed layout and controls, use `sigma-migrate inspect --source source.json`
to list captured identities. Prepare a context JSON with the workbook ID, evidence
reference, observed element fields/chart/layout/sorts/limit and observed control
targets, following the `prepush_context` structure in the example. Do not calculate
its hash. Bind it automatically with:

```sh
.venv/bin/sigma-migrate import-context --source source.json --context observed-context.json --output enriched-source.json
```

Use `enriched-source.json` as the source when initializing (or import it as a new
source revision in an existing run). Use your own source IDs and observed mappings.
Missing context remains blocked. Do not copy the example context onto unrelated
source objects. If the compiler reports an unsupported pattern, keep that blocker
for a reviewed redesign; accepting the proposal does not override it.

Then initialize:

```sh
.venv/bin/sigma-migrate init --run-dir my-migration --source source.json --target target.json
```

## 7. Choose your migration approach

Use your chosen run directory in every command below; the fictional walkthrough
uses `demo-run`, while your own migration above uses `my-migration`.

```sh
.venv/bin/sigma-migrate route --run-dir demo-run
```

Answer the question: do you want the semantic layer fully modeled, or lifted and
shifted directly into Omni?

1. Direct: reconstruct in Omni over existing warehouse tables; no dbt changes.
2. Modeled: prepare upstream data-layer artifacts and then Omni artifacts.

There is no default. Changing your choice invalidates previous review and output.

## 8. Review and accept local preparation

```sh
.venv/bin/sigma-migrate review --run-dir demo-run
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
.venv/bin/sigma-migrate build --run-dir demo-run
.venv/bin/sigma-migrate validate --run-dir demo-run
```

The tool reopens the generated files and checks their content, mappings and review
bindings. Read the actual status and issues.

- `offline_preflight_passed`: the supported local contract passed; live checks remain.
- `blocked`: one or more required items need attention. Useful proposed files can
  still exist, but the package is not ready to apply.
- Modeled route: generated data-layer artifacts still need deployment and validation
  before the dependent Omni work can be accepted.

Synthetic runs remain synthetic in every state. Neither status means migration accepted.

## 10. Export and share the result

```sh
.venv/bin/sigma-migrate export --run-dir demo-run --output reviewed-package.zip
```

This creates a new ZIP without overwriting an existing file. It includes the source
metadata and proposed target files; review the contents for confidentiality before
sharing. A blocked package may be shared for remediation but must not be described
as deployment-ready. There is no Omni push command.

## 11. Resume, update or withdraw review

```sh
.venv/bin/sigma-migrate status --run-dir demo-run
.venv/bin/sigma-migrate import-source --run-dir demo-run --file revised-source.json
.venv/bin/sigma-migrate import-target --run-dir demo-run --file revised-target.json
.venv/bin/sigma-migrate revoke --run-dir demo-run --reason approval_withdrawn
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

Unresolved formulas/field references, unsupported controls/actions/writeback,
security policy differences and missing layout evidence need explicit remediation.
Do not remove source objects just to obtain a green result. Any reduced pilot scope
must be deliberately recorded as a different migration, not claimed as the original
workbook's complete migration.

Before claiming success, separately authorize a bounded live development pilot:
apply reviewed artifacts, confirm returned IDs and readback, compare source/target
numbers, controls, visibility, allowed/denied personas and visual behavior, then
obtain platform-owner acceptance. No live deployment or independent human operator
walkthrough is claimed by the synthetic checks delivered with this tool.

## 13. Optional: use the agent skill

The current `sigma-to-omni-migration` skill is included in
`.agents/skills/sigma-to-omni-migration`. It guides the same steps above and is
aligned with runtime version 0.2.0. It does not add an Omni push capability.
Using the terminal directly remains an option; an AI assistant is not required.

After installing Python and the runtime in step 3, open the extracted package
folder or GitHub checkout as your Codex project. Ask: “Use the
sigma-to-omni-migration skill to prepare one workbook. Ask whether I want it
modeled upstream or lifted and shifted to Omni directly. Stop for my review.”

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

# Sigma-to-Omni Phase 0 capability-spike agent

The September 8 follow-up hardens this source boundary and connects reviewed source/route
artifacts to a supervised planning workflow. See [current review reconciliation](sigma-review-implementation-status.md)
and [operator workflow](sigma-supervised-workflow.md). Capability capture itself still grants no
target or migration-acceptance authority.

## Outcome

The implemented first milestone is a bounded, read-only capability spike for exactly one approved
Sigma workbook and one approved data model. It produces a reviewable property matrix and source
artifacts; it does **not** claim the requirements document's full functional first pass.
The requirement-by-requirement boundary is recorded in
[`sigma-phase0-requirements-status.md`](sigma-phase0-requirements-status.md).

The agent:

- validates the configured HTTPS API host against a separate operator-controlled CLI allowlist
  before resolving credentials;
- validates the shape and exact scope bindings of privacy, sanitization, retention, and
  metadata-only references, while keeping those approvals reference-only until a trusted resolver
  is wired;
- resolves credentials only from environment variables and persists only a `secret-ref://`;
- calls `whoami` first and stops before content reads if organization or user identity differs;
- probes direct workbook/data-model endpoints without enumerating the organization;
- brackets the run with workbook and data-model identity/version observations and requires an
  existing version tag for the workbook definition endpoints that support it;
- supports both documented cursor families, exact provider-total reconciliation, opaque cursor
  hashing, duplicate-ID detection, total and per-endpoint request budgets, selector-stable
  same-origin continuation checks, server `Retry-After`, and bounded jittered retry backoff;
- records structural response shapes, hashes, status, exact source IDs, permissions context, and
  redacted diagnostics without storing response values or unrestricted row data;
- keeps workbook API evidence partial where Sigma has no complete workbook code representation;
- creates explicit fallback/redesign work for controls, actions, layout, formatting, saved views,
  input tables, security, schedules, and embeds;
- exposes no Sigma mutation or target-write tool and keeps artifact registration, inventory,
  acceptance, release, cutover, and decommission gates closed.

## Required semantic implementation choice

The target-architecture choice is intentionally separate from the Phase 0 source request and
bundle. The executable manager state asks:

> Which implementation path should this Sigma semantic layer use: warehouse-first refactoring
> before Omni, or direct reconstruction in Omni?

Both paths target bounded semantic equivalence with explicit exceptions and the same
closed-denominator QA. Neither guarantees one-to-one semantic, behavioral, visual, or workflow
parity. There is no default, and the agent must not infer a choice from repository availability or
platform maturity.

| User-facing path | Contract mode | Routing effect |
|---|---|---|
| Fully modeled | `warehouse_first_refactor` | Commonality analysis evaluates reuse/merge/parameterize/split. Approved persistent/shared logic may route through dbt or the warehouse before Omni. |
| Omni semantic lift-and-shift | `omni_semantic_reconstruction` | Commonality analysis still closes the denominator and preserves source boundaries. The Omni modeler reconstructs semantics over accepted existing warehouse relations; Sigma is not an Omni data source. dbt is always skipped. Any later data-layer need requires a superseding warehouse-first decision. |

Run the manager without a request to receive the question and two options:

```bash
./.venv/bin/python scripts/run_sigma_semantic_route.py
```

That returns exit `2` with `awaiting_human_choice`; it blocks target design but not the read-only
source spike. After the user chooses, populate one of the two request examples under
`contracts/sigma/examples/` and record the decision:

```bash
./.venv/bin/python scripts/run_sigma_semantic_route.py \
  --request /absolute/path/to/semantic-routing-request.json \
  --output /absolute/path/to/new-semantic-routing-decision.json
```

The create-only decision is per migration unit and binds canonical comparison/build scopes,
target environments, exact source artifact identities/hashes/timestamps, reference-only source
acceptance provenance, and the human decision record's reference/revision/hash. Re-selecting a
mode creates a typed successor; it invalidates downstream target plans without changing or
reacquiring source evidence. A trusted registry/policy resolver must still verify currentness,
producer, acceptance, and supersession before any target-design gate can open.

## Contracts

The Pydantic source contracts live under
`packages/omnikit-migration-engine/src/omni_migrator/extractors/sigma/`. Exported JSON Schemas live
under `contracts/sigma/` and are checked with:

```bash
./.venv/bin/python scripts/export_sigma_capability_schemas.py --check
```

The schemas encode representable field constraints, including safe source IDs and secret-reference
shape. The Pydantic model remains mandatory for cross-field scope, freeze, host, port, and approval
coherence; JSON Schema validation alone is not an authorization decision.

The output bundle contains:

- `sigma-run-manifest.v1`
- one or more `sigma-observation.v1`
- `sigma-api-capability-matrix.v1`
- `sigma-workbook-graph.v1`
- `sigma-data-model-snapshot.v1`
- `sigma-behavior-manifest.v1`

It does not contain the semantic-routing decision or target-environment references. Those are
downstream target-planning inputs, so changing either cannot change source-observation hashes.

Every artifact is deeply immutable, content-addressed, temporally ordered after its declared
upstream inputs within the bundle, and explicit about evidence classification and supersession
state. Bundle validation recomputes hashes and rejects inconsistent run/scope, upstream, status,
denominator, or gate bindings.

## Live invocation

1. Copy `contracts/sigma/examples/sigma-capability-spike-request.v1.example.json` and replace every
   placeholder. Bind an existing workbook tag and exact data-model document version. Creating a
   tag is a separate Sigma write and is not part of this agent. The privacy approval must authorize
   the chosen data classification and sanitization/retention policies; row data is always disabled.
   Set both `request_budget` and `per_endpoint_request_budget` for the approved pilot size; these
   are operational ceilings, not invented Sigma rate-limit claims.
2. Configure `SIGMA_CLIENT_ID` and `SIGMA_CLIENT_SECRET` in the process environment or pass the
   names of equivalent environment variables. Never put their values in the request file.
3. Obtain the exact regional Sigma API hostname from trusted deployment configuration. The
   request's `approved_api_hosts` field is declarative evidence and cannot authorize egress by
   itself; the same exact host must be supplied independently to `--trusted-api-host`.
4. Run from the repository root:

```bash
./.venv/bin/python scripts/run_sigma_capability_spike.py \
  --request /absolute/path/to/approved-sigma-request.json \
  --trusted-api-host aws-api.sigmacomputing.com \
  --output /absolute/path/to/new-sigma-capability-bundle.json
```

The output path must not already exist. It is created with owner-only permissions. Exit `0` means
the live matrix is ready for independent human review—not approved. Exit `2` means the spike ran
but remains blocked. Exit `1` means request validation or execution failed.

## Human review checkpoint

Before opening `sigma_api_capability_verified`, review:

- exact organization, principal, base URL, workbook/data-model IDs, and freeze selectors;
- every `verified_partial` and `manual_required` property plus its evidence owner;
- endpoint-specific version context and the workbook cross-endpoint consistency limitation;
- permission-hidden and personal saved-view coverage;
- input-table values/history extraction and external action/embed/delivery redesign;
- retention, sanitization, and accepted exclusions.

No caller-provided boolean can open a gate. The next implementation milestone is Phase 1 portfolio
inventory and closure only after the Phase 0 matrix and fallbacks are approved.

## Current limits

- No live Sigma tenant was used while developing this milestone; tests use fictional sanitized
  response shapes.
- The CLI emits a create-only, content-addressed local bundle, but it does not yet register that
  bundle in the shared append-only control plane or enforce supersession/invalidation there.
- Human approval, authorization, retention, and sanitization references are structurally bound but
  are not resolved from a trusted authorization/policy store in this milestone. They cannot open a
  mutation, release, or acceptance gate.
- The semantic prompt, request/artifact contracts, create-only CLI, and specialist route resolver
  are executable locally. Shared control-plane currentness, full work-package planning, target
  authorization, target execution, QA, and documentation handoffs remain unwired.
- The existing generic Sigma IR/translation path is not treated as accepted semantic equivalence
  or target readiness.
- Reports, legacy datasets, templates, audit/usage, members/teams/user attributes, warehouse row
  comparisons, target builds, independent QA, and acceptance-only documentation remain future
  phases.
- The existing Domo end-to-end minimum slice currently has an unrelated target-outcome envelope
  failure. Reused target/QA components must be green before Sigma Phase 4 can inherit them.

# Supervised Sigma migration planning

The Sigma workflow now connects a bounded capability capture, explicit human route selection, shared work packages, and the shared durable model-proposal runner. It supports both routes:

- `omni_semantic_reconstruction`: five planning packages, no dbt work.
- `warehouse_first_refactor`: six planning packages, including a dbt proposal.

This is **supervised planning**, not an accepted migration or target deployment. SQL, YAML, QA plans, and documentation returned by the model are inert proposals. No `sigma-run-*` command writes to Sigma, a warehouse, dbt, or Omni. Completed planning does not satisfy source-completeness, build, independent-QA, release, or cutover gates.

## Intake and human decision

1. Run the existing `sigma-capability-spike` against one approved tenant/principal/workbook tag/model version. A blocked capture cannot initialize planning. Keep the source and credential references separate; never put secrets into JSON.
2. Ask `sigma-semantic-route` without a request to get the required two-option question. Neither route has a default. The legacy `extract` command remains source-only for Sigma even if a caller supplies an unbound route hint.
3. Have the host's authorized reviewers approve the exact source artifacts used for planning and the exact semantic decision. The decision's reference-only approval hashes must resolve to the supplied human records at workflow registration.

`SigmaPlanningApproval` contains `record_ref`, `revision`, `reviewer`, timezone-aware `approved_at`, `purpose`, and `subject`. Its digest is `sha256_json(record.model_dump(mode="json"))`. Use `source_approval_subject(artifact)` and `route_approval_subject(request)` from `orchestration/sigma_workflow.py` to derive the exact subjects. Populate source acceptance hashes first, then the route approval hash, then create the route artifact. This avoids circular hashes. A host should generate these records from its review interface; models must never generate approvals for themselves.

Human records in this local reference implementation are trusted operator inputs, not cryptographic signatures or an enterprise identity provider. A deployed host must authenticate the reviewer, enforce who can supply these records/configuration, and protect the canonical store. Matching a `human-ref://` string alone is not authentication.

## Initialize and resume

The run configuration uses the shared `MigrationRunConfig`. Its `context` is a `SigmaPlanningContext` containing:

- `source_system: "sigma"`
- canonical `tenant_ref`, migration `run_id`, `migration_unit_id`, and `validation_cycle_id`
- `created_at` after the route artifact was created
- the full validated `decision` artifact

The remaining configuration is an explicit `model`, `human_reviewers`, `budget`, optional `model_egress_approval_ref`, and optional additional `inputs`. No model is selected automatically. Budget prices are operator-supplied estimates, not a claim about vendor billing. Source/route inputs are imported automatically and cannot be overridden by additional input JSON.

```sh
python -m omni_migrator.runtime sigma-run-init \
  --config reviewed-run-config.json \
  --bundle sigma-capability-bundle.json \
  --route-approval reviewed-route-record.json \
  --source-approvals reviewed-source-records.json \
  --reviewer human-ref://migration-owner \
  --expected-sigma-organization-ref sigma-org-ref://approved-org \
  --run-dir ./runs/sigma-pilot \
  --control-dir ./control-plane
```

The exact Sigma organization must be mapped explicitly to the canonical tenant; they use different reference namespaces. Initialization imports the original source artifact content and lineage into that migration partition, records the exact reviewed route, and registers only proposal/read-only packages. Once a run exists, resume it rather than overwrite it. Every load verifies the entire registered graph against the immutable configuration before interpreting completion. An interruption during initial graph registration fails closed; automated repair of that partial initialization is not implemented. Preserve the run and control-store evidence for operator reconciliation rather than deleting or resetting either store.

```sh
python -m omni_migrator.runtime sigma-run-status \
  --run-dir ./runs/sigma-pilot --control-dir ./control-plane

python -m omni_migrator.runtime sigma-run-step \
  --run-dir ./runs/sigma-pilot --control-dir ./control-plane \
  --allow-model-call --api-key-env OPENAI_API_KEY
```

The second command makes at most one model call, only when work is ready and explicit model-call/egress approval is present. Credentials are resolved from the named environment variable at execution time, not stored in run configuration. The provider uses a fixed API origin and structured output; refusals, incomplete output, invalid citations, and budget exhaustion stop work. See [official structured-output guidance](https://developers.openai.com/api/docs/guides/structured-outputs). No remote tools, shell, URL-following, or source/target writes are exposed to the model.

## Review and handoff

- `sigma-run-attach --evidence ...` attaches a bounded, hashed `EvidenceInput`; attachment does not approve it.
- `sigma-run-complete --package ... --reviewer ... --artifact-ref ...` requires host-registered current artifacts of the exact expected planning types, correct producer package, source/route and transitive predecessor lineage, migration unit, and cycle. Dispatch and completion resolve the same reviewed input references and exact revision/hash bindings. Model JSON or a guessed artifact reference cannot complete work.
- Completed predecessor outputs are passed to later specialists only through current canonical artifact references and matching attached contents. Mere dependency ordering is not treated as an evidence handoff.
- `sigma-run-retry --attempt ... --reviewer ...` permits an explicit reviewed retry. Failed/interrupted calls retain their budget reservation because the provider might have processed them. There is no automatic repeat-call loop.
- `sigma-run-revoke --reviewer ... --reason source_changed|route_changed|approval_withdrawn` revokes the current route and stops dependent status/dispatch/completion operations.

Source or route revisions invalidate dependent Sigma planning through currentness and recursive lineage checks. An unseen change in the external tenant cannot be detected without a new capture or operator revocation. Reselection requires an exact registered predecessor and a new reviewed decision; use a new planning cycle so old work is not silently repurposed.

The shared local runner persists configuration, attempts, evidence, budget reservations, and review state. It prevents concurrent workers and automatic replay after interruption. Local persistence is not deployment-grade encryption, identity enforcement, retention, disaster recovery, or multi-tenant operational acceptance.

## What remains before a functional migration

The route-aware shared planner/policy treats dbt readback as not applicable for direct Omni reconstruction only when the full decision and current source hashes resolve in the canonical ledger. That prerequisite change does not by itself create executable Sigma target packages.

Still required: a live capability pilot; closed source/behavior inventory; accepted semantic profiles and target design; explicit development/quarantine target authorization; configured target drivers with receipts/readbacks; independent numerical/security/behavior/visual evidence; and accepted documentation. Warehouse-first additionally requires approved data-layer work and dbt validation. Portfolio scaling and model-only acquisition remain separate increments.

See [review closure checklist](sigma-review-implementation-status.md) for item-by-item status and validation evidence. The existing original Phase-0 source contract remains deliberately bounded to one workbook and one data model.

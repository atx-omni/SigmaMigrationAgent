# Sigma review implementation status

Historical baseline: September 8 senior engineering review, commit `912e56d8`.
Current repository implementation and readiness are recorded in `IMPLEMENTATION-AUDIT.md`.

Reconciled September 8, 2026 (America/Chicago). This checklist tracks implementation against the review; it does not replace the original review or claim live acceptance. Concurrent Domo runtime/target changes are separate work and retain their provenance.

**Outcome: all seven reproduced defects are repaired locally, and both human-selected routes now connect to supervised, durable specialist planning. The full functional-first migration plan is not complete.** Live capture, executable Sigma target packages, independently accepted migrations, and the coverage/operations increments below remain open. Confidence is high for the locally tested behavior; tenant behavior and release readiness are unverified.

| Review item | Status | Closure evidence / remaining requirement |
|---|---|---|
| F1 wrong specification identity | Implemented locally | Wrong/missing specification identity or invalid version blocks capture; unavailable specification is empty, reasoned, and serializable. Snapshot contracts defend the same binding. Negative and matching cases are covered in `test_sigma_capability_spike.py`. |
| F2 documented source variants | Implemented locally | Shared typed parser preserves model/element/tag compound identity and SQL/connection identity; graph and duplicate checks use it. Documentation-derived fixtures cover variants and malformed inputs in `test_sigma_source_contracts.py`. Data-model source bindings retain their explicitly unversioned status. |
| F3 legacy choice bypass | Implemented locally | Sigma bridge is source-only; no choice and unbound hints for either mode cannot enable target suggestions. Public-entry regressions cover API/manual extraction in `test_sigma_end_to_end.py`. |
| F4 column type loss | Implemented locally | Recursive provider `type` values survive graph construction and serialization; round-trip tests cover nested types. |
| F5 superseded route dispatch | Implemented locally | Both explicit superseded routes fail specialist resolution; current canonical selection, revocation, and source revisions are checked again on planning resume/dispatch/completion. |
| F6 materialization page limit | Implemented locally | Endpoint maximum is 500 with pagination regression coverage; failed/missing materialization acquisition produces a visible blocking capability disposition. |
| F7 numeric version normalization | Implemented locally | Dedicated normalizer accepts integral numeric versions such as `7.0`; native IDs stay strict. Boolean, fractional, non-finite, and malformed versions are rejected. |
| Fast Sigma CI | Implemented locally | Independent Sigma contract/schema workflow; GitHub result requires publication and execution. |
| Shared QA fixture failure | Fixture repair implemented; full probe still unverified | Canonical fixture/result/context joins now use exact immutable references and aligned coverage. A genuine incompatible orders/accounts comparison yields an ineligible, rejected negative consolidation control without build authority. No production acceptance rules were weakened. See validation caveat below. |
| Both-route planning | Implemented locally; acceptance integration partial | Sigma scopes and exact route-bound work packages are supported: five direct planning packages, six warehouse-first packages. Direct mode excludes dbt work. Shared QA treats dbt readback as not applicable only with a verified current direct decision; this does not create executable Sigma target packages. |
| Supervised agent execution | Planning loop implemented locally | Source capture → exact human records → registered decision → durable run → one bounded model proposal → human-reviewed canonical artifact → next specialist. Shared provider/runner/CLI are reused. Proposals cannot self-approve or execute target writes. |
| Trusted route currentness | Local reference implementation complete; deployment identity open | Canonical-store selection/revocation binds exact source/decision content and human approval records. Stale revisions and recursive lineage block work; generic events cannot forge selection. A trusted operator supplies reviewer identity/configuration; an authenticated production review service remains required. |
| Interrupted runs and evidence handoff | Safe local resume implemented; initial-setup repair open | Calls/attempts/budgets survive reopen; no automatic replay. Entire Sigma and Domo graphs must match immutable configuration, so partial initialization cannot claim completion. Sigma completion must retain exact transitive predecessor revision/hash lineage. Partial initial registration requires operator reconciliation; automatic repair/caching is not implemented. |
| AI isolation and resource boundaries | Implemented locally with limited evaluation | Actual model boundary labels source content untrusted; no model tools or source/target writes. Structured proposals, scoped citations, input/call/token/cost limits, fixed provider origin, explicit egress/call approval, and explicit retry are enforced. These controls do not prove semantic correctness. |
| Held-out agent-quality evaluations | Not yet complete | Synthetic routing/forgery/staleness tests are not a held-out model-quality suite. Context-changing formulas, unsupported detection, false-positive consolidation, malicious source text, and live model cost/latency still need separately maintained evaluations. |
| Live source capture | Blocked on configuration/approval | Exact tenant, credential reference, principal, workbook tag, model version, and named reviewers have been requested. |
| Direct-to-Omni accepted slice | Not yet complete | Requires accepted source/profile/design, configured target development environment, guarded operation receipts/readbacks, and independent comparisons. |
| Warehouse-first accepted slice | Not yet complete | Adds approved data-layer changes and dbt evidence; cannot reuse direct-mode not-applicable evidence. |
| Portfolio inventory and semantic profiles | Deferred delivery work | Complete source denominator, repository/warehouse context, context-bound formula/equivalence analysis. |
| Accepted translation and equivalence | Not yet complete | Specialist drafts and narrow deterministic translations do not prove grain/join/fanout, null/time, filter/security, or row/aggregate/window correctness. The shared synthetic negative control is not Sigma tenant acceptance. |
| Operational behaviors | Deferred delivery work | Manual evidence ingestion and owned dispositions for actions/input tables/controls/schedules/saved views/embeds/layout. |
| Model-only migration scope | Deferred delivery work | Separate from the deliberate one-workbook/one-model capability pilot. |
| Sigma target execution | Not yet complete | Host-specific target authorization, executable Sigma build packages, receipts/readbacks, idempotency, and ambiguous-write reconciliation must be connected. Concurrent Domo driver work does not establish Sigma acceptance or authorize tenant writes. |
| Full independent QA | Not yet complete | Numerical/security/behavior/visual comparisons over aligned source and target contexts; every item accounted for. |
| Deployment operations | Not yet complete | Deployment-specific identity/secret/retention/tenant controls and runtime recovery acceptance. |
| Documentation/training/release | Not yet complete | Generate from accepted output; human release/cutover and rollback validation remain required. |

## Validation performed, bounded to the requested budget

- Combined Sigma, shared planner, and Domo runner regression pass: **373 passed in 15.80 seconds**. This covered `test_sigma*.py`, `test_orchestration_planner.py`, and `test_domo_supervised_runner.py`.
- Final recovery/lineage additions: **24 passed in 3.58 seconds**, using only the small Sigma workflow and Domo runner suites. This includes interrupted initialization for both source systems, accepted predecessor handoff on both Sigma routes, and rejection of missing predecessor lineage. Do not sum overlapping test counts into a unique-test claim.
- Sigma generated-schema freshness and Ruff across engine source/tests/scripts passed before the final narrow runner changes. Final changed-file Ruff and `git diff --check` also passed.
- The one slow shared negative-policy probe ran once (**147.97 seconds**) after context repair. It reached the remaining missing-negative-control failure. The subsequent negative-chain regression passed (**0.39 seconds**), and a memory-only fixture preflight confirmed **168 exact subjects, one negative control**, and aligned context/fixture/result/coverage references. The slow durable probe was deliberately **not rerun** after that final addition. Its final policy acceptance remains unverified.
- No full repository test run, live provider call, Sigma/Omni/warehouse mutation, customer acceptance, commit, push, or new remote CI run was performed by this Sigma implementation pass.

## Reconciliation with the review's recommended sequence

1. **Repair implemented boundary:** F1–F7 are locally closed; fast CI configuration exists. Published green CI and the slow shared-probe acceptance are still open evidence, not silently marked complete.
2. **Authorized live capability pilot:** waiting for approved source coordinates and human reviewers. Contract fixtures exercise simulated transport, not a real tenant.
3. **Direct Omni first:** the required human choice, verified local registration, durable planning, and handoff are connected. Accepted design/build/readback/independent comparison remain the next functional delivery work.
4. **Warehouse-first:** separate route and dbt planning exist. Approved warehouse/dbt execution and a separately accepted slice are still required.
5. **Expand coverage and operations:** portfolio/model-only scope, owned behavior dispositions, held-out evaluations, caching/recovery operations, performance, accepted enablement, and governed cutover remain explicitly tracked above.

The original minimum slice remains unchanged: two pages, three to five analytical elements, representative dependencies, row/aggregate/window formulas, a cross-element control, saved view, action, input-table evidence or proven absence, schedule, allowed/denied personas, false-positive consolidation, Omni Topic and quarantine content, plus independent semantic/behavior/security/visual evidence. dbt applies only to warehouse-first. None of those acceptance criteria is waived by planning completion.

## Entry points and next human input

See [supervised workflow instructions](sigma-supervised-workflow.md) for `sigma-run-init`, status, step, attach, complete, retry, and revoke. The existing neutral two-choice prompt has **no default**; semantic-only users can select direct Omni reconstruction without proposing warehouse remodeling.

For the live pilot, supply the exact Sigma organization/tenant and principal references, approved read-only credential reference, workbook/tag, data model/version, and named reviewers. Supply references only, never secret values. Target environments and write approvals are separate later checkpoints.

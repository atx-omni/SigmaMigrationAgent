# Sigma Phase 0 requirements status

Historical milestone boundary: the September 8 review follow-up adds source-contract repairs,
canonical source/route registration and currentness, both-route shared planning, and a supervised
proposal runtime. For the current follow-up status, see
[review reconciliation](sigma-review-implementation-status.md) and
[workflow guide](sigma-supervised-workflow.md). Those additions do not complete target execution,
live QA, customer acceptance, release, or the original functional-first requirements.

This is the implementation boundary for the first-pass agent in this repository. `Implemented`
means deterministic code and tests exist. It does not mean a live Sigma tenant, customer, security,
or migration owner accepted the behavior.

## Governance and agent controls

| Requirement | Status | First-pass evidence or remaining gate |
|---|---|---|
| GOV-01 immutable run identity | Partial by design | The target-neutral source request/run manifest bind organization, HTTPS host, principal, secret reference, policy, scope, source freeze, data classification, privacy approval, sanitization, and retention. The separate per-migration-unit semantic-routing decision binds target environments without making source observations depend on target plans. A unified registered migration-run identity remains deferred. |
| GOV-02 dual scope | Implemented for the pilot | Comparison/build references are distinct; Phase 0 permits exactly one Sigma workbook and one data model. |
| GOV-03 read-only source posture | Implemented | The Phase-0 tool surface permits token creation plus bounded `GET` calls only. No source mutation or target tool is exposed. |
| GOV-04 least privilege | Partial | `whoami`, declared account type, per-endpoint results, and visibility gaps are recorded. Organization-wide permission closure is Phase 1. |
| GOV-05 human authority | Partial | Scope and freeze require human references. The semantic route requires an explicit, non-default human choice plus record revision/hash; it remains `reference_only` until resolved. Later consolidation, security, target, acceptance, and release approvals remain unavailable. |
| GOV-06 append-only lineage | Partial; registry blocker remains | Artifacts are create-only and content-addressed. Semantic-route reselection has a typed predecessor hash and supersession link. Shared control-plane registration, currentness, identity conflict detection, predecessor-state resolution, and downstream invalidation are not wired. |
| GOV-07 target authorization binding | Deferred | No target operation is available in Phase 0. |
| GOV-08 evidence classification | Implemented | Contracts distinguish documented fact, stated evidence, observed behavior, field pattern, assumption, recommendation, unresolved gap, and synthetic fixture. |
| GOV-09 temporal provenance | Partial | Source-bundle construction orders every artifact after declared upstream inputs. The semantic route is a separate downstream artifact that must postdate exact declared source context and acceptance timestamps; target environments and route choice are absent from source hashes. Shared-registry currentness is deferred with GOV-06. |
| AGT-01 through AGT-05 | Implemented as specifications; Phase-0 runtime bounded | One manager and nine specialist contracts declare tools, typed inputs/outputs, stops, retries, escalation, separation of duties, and untrusted-source rules. The manager has an executable missing-choice prompt/decision transition and deterministic specialist route resolver. Only four source/read roles are active; later execution remains unwired. |

## Semantic target-routing flexibility

| Requirement | Status | First-pass evidence or remaining gate |
|---|---|---|
| Required user choice with no default | Implemented | `sigma-semantic-route` returns exactly two options when the mode is missing or unknown. Target design is blocked; source evidence acquisition is not. |
| Warehouse-first/full-model route | Implemented as a local routing contract | `warehouse_first_refactor` routes formula analysis, commonality/consolidation, conditional dbt work, Omni modeling, and independent QA. It grants no write authority. |
| Direct Omni/lift-and-shift route | Implemented as a local routing contract | `omni_semantic_reconstruction` routes formula analysis, preserve-boundary commonality disposition, direct Omni modeling, and independent QA while always skipping dbt. Any later data-layer need requires a superseding warehouse-first decision. |
| Equivalent assurance standard | Implemented in contract; target runtime deferred | Both modes require bounded semantic equivalence with explicit exceptions, separate operational-behavior disposition, and independent closed-denominator QA. Neither permits an automatic one-to-one claim. |
| Per-unit provenance and reselection | Implemented locally; registry resolution deferred | The decision binds `migration_unit_id`, canonical comparison/build scope, target environments, exact source context hashes/timestamps, reference-only acceptance evidence, human decision revision/hash, and an optional typed predecessor. Trusted-store currentness and invalidation are not wired. |
| Full lifecycle routing | Deferred blocker | The local resolver returns the exact specialist path, but shared work-package planning, gate resolution, target authorization, dbt/Omni execution, independent QA execution, and documentation handoffs are not integrated for Sigma. |

### Recorded interpretation amendment for later phases

The user-requested two-path strategy makes the original requirements' unconditional dbt sequence
conditional per migration unit. For future implementation, read the architecture diagram,
TRN-04, DOC-02, Phase 4 sequence, minimum vertical slice, required-gate list, readiness criteria,
and “decisions before coding” checklist as follows:

- `warehouse_first_refactor` may execute approved dbt/warehouse changes before Omni;
- `omni_semantic_reconstruction` reconstructs semantics in Omni over accepted existing warehouse
  relations and records dbt as not applicable; a later data-layer need requires a superseding
  `warehouse_first_refactor` decision;
- documentation emits source-to-dbt-to-Omni or source-to-Omni lineage according to the current
  route;
- `semantic_migration_strategy_selected` is a distinct exact-bound human gate before target design;
- at least one accepted vertical slice is ultimately required for each supported route before a
  full lifecycle claim.

This amendment changes logic placement, not the semantic coverage, security, behavior, QA,
acceptance, or evidence standard.

## API capability spike

| Requirement | Status | First-pass evidence or remaining gate |
|---|---|---|
| CAP-01 tenant verification | Implemented; live run required | Direct acquisition is bounded to one approved pair and calls `whoami` before content. A mismatch stops content reads. |
| CAP-02 property matrix | Implemented | Typed assessments cover identity, model specification, workbook structure, formulas, sources, lineage, controls, actions, layout, formatting, security, schedules, saved views, embeds, versions, input tables, visibility, and pagination. |
| CAP-03 sanitized response evidence | Implemented | Observations retain method/path, safe query context, shape, status, response hash/size, exact source IDs, totals, cursor hashes, attempts, and safe diagnostics; no response values or row data. |
| CAP-04 full versus partial | Implemented | Workbook portability and context-sensitive surfaces stay partial/manual even when endpoints return HTTP 200. |
| CAP-05 version behavior | Partial by documented API boundary | Data-model spec uses exact `documentVersion`; supported workbook definition calls use an existing tag; unversioned calls are bracketed by stable workbook/data-model metadata and workbook-tag reads and explicitly labeled. Draft/arbitrary-version definitions remain manual/unavailable. |
| CAP-06 fallback definition | Implemented | Every partial/manual surface carries an owned export, render, structured manifest, host manifest, persona test, or proposed unsupported disposition. Request-supplied exclusion references are recorded but remain non-authorizing until resolved by a trusted human-control store. |
| CAP-07 build stop | Implemented | Source-adapter build authorization is a typed constant `false`; target, release, cutover, and decommission gates remain blocked. |
| CAP-08 principal visibility | Partial | Exact organization/user binding is tested. Effective account-type and permission-hidden organization denominators require administrator evidence in Phase 1. |
| CAP-09 deprecated surfaces | Implemented for probed calls | The deprecated workbook-schema endpoint is absent; `hasMore` is observation-only and never the pagination authority. |

## Non-functional boundary

| Requirement | Status | First-pass evidence or remaining gate |
|---|---|---|
| NFR-01 security | Partial; deployment gate remains | HTTPS port 443 and an independent operator host allowlist are enforced before environment-backed credentials are resolved. Structural observations and outputs are secret-redacted and owner-only. A production secret manager, durable encryption/retention controls, tenant isolation, and deployment review remain external. |
| NFR-02 privacy | Implemented for Phase 0 | Row-data authority is typed `false`; collection is limited to metadata, formulas, structure, IDs, hashes, and bounded diagnostics. Any later row or aggregate comparison needs a separate privacy design and authorization. |
| NFR-03 resumability | Deferred blocker | Pagination closes deterministically within a run, but durable checkpoints and resume without duplicated observations are not implemented. |
| NFR-04 rate-limit control | Implemented for bounded serial probing; live tuning required | Concurrency is one. Total and per-endpoint request budgets, capped attempts, token refresh, server delta/date `Retry-After`, bounded wait refusal, and jittered client backoff are enforced. No universal Sigma rate limit is claimed; endpoint budgets require live validation. |
| NFR-04A export bounds | Deferred | The agent does not export workbook data or make row-completeness claims. |
| NFR-05 determinism | Implemented for local contracts | Typed contracts, canonical ordering/hashes, artifact IDs, semantic-route selection, eligibility, blockers, and bundle validation are deterministic; retry jitter affects timing only. |
| NFR-06 observability | Partial | Sanitized source calls, shapes, IDs, totals, retries, version context, blockers, and API/byte budgets are emitted. Shared work-package status, elapsed duration, and cost telemetry are later-phase work. |
| NFR-07 idempotency and recovery | Not applicable to Phase-0 writes | No source or target mutation is exposed. Target idempotency, readback, and ambiguity reconciliation remain required before Phase 4. |
| NFR-08 scalability | Deferred | The pilot is deliberately one workbook plus one data model; portfolio waves require Phase 1 inventory closure and resumability. |
| NFR-09 maintainability | Implemented for the milestone | Sigma API, contracts, spike orchestration, role registry, tests, and schemas are isolated from reusable target adapters. |
| NFR-10 cost control | Partial | Outputs are content-addressed and the model receives only structural summaries; durable hash caching and unchanged-object reuse are not wired. |
| NFR-11 explainability | Partial | Capability decisions carry exact observation and documentation references plus owned fallbacks. Semantic routing records rationale, migration unit, exact source bindings, target environments, human decision provenance, and route effects. Counterevidence and trusted human-decision resolution remain later gates. |
| NFR-12 accessibility and UX | Deferred | Layout, formatting, responsive behavior, and accessibility remain manual evidence and later acceptance requirements. |
| NFR-13 pagination variants | Implemented for probed endpoints | Both cursor families are opaque, selectors cannot drift, page-size context is rebuilt, totals and duplicate IDs reconcile, and deprecated `hasMore` is not authoritative. |

## Deferred lifecycle

Portfolio closure (`INV-*`), repository/warehouse inventory (`REP-*`), Sigma semantic profiles
(`SEM-*`), formula/SQL translation contracts (`TRN-*`), equivalence and Topic design, target builds,
independent QA execution, documentation generation, release, cutover, rollback, and decommission
are not implemented by this milestone. The semantic prompt, decision artifact, and local route
resolver do not change that boundary. Existing generic extraction and target components may be
reused only after their Domo-shaped control-plane contracts are generalized and their own failing
integration paths are green.

## Honest completion test

The Phase-0 code is complete when its schemas, adversarial tests, focused Sigma regression, and CLI
smoke path pass. The capability decision remains unverified until a named owner approves one live,
read-only run against the exact tenant, principal, workbook tag, and data-model document version.
The full requirements document's definition of done is not met by Phase 0.

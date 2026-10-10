# Configuration-first implementation audit

October 9, 2026 · runtime/skill 0.3.0 · local preparation only

## Outcome and evidence boundary

The supported repository workflow now starts with guided setup, has explicit
read-only discovery, can prepare dashboard-only artifacts against a reviewed
existing Topic, and retains full source evidence while selecting a chart/page pilot.
It has per-chart local reporting and review-safe resume behavior. Nothing deploys
to Sigma, Omni, or the warehouse.

Confidence is high for the automated local checks and mocked connection paths;
live tenant behavior, customer usability and migration success remain unmeasured.
The workshop notes describe a separate Claude/MCP/CLI live flow. Its exact installed
skill/version was not supplied, so this change updates the repository's maintained
deterministic runtime, not an unverified copy of that live flow.

## Review against the approved enhancements

| Enhancement | Delivered | Remaining boundary |
|---|---|---|
| Configuration first | `setup` asks source, direct/modeled route, allowed changes and target authentication before mapping. Private non-secret profile, conditional `.env`, local checklist, and new-directory Git-ignore protection. Existing saved setup resumes without overwriting credentials. | Interrupted setup before profile creation must be rerun; no UI outside the terminal. Existing custom ignore files are preserved and must be checked. |
| Exact credential instructions | Instructions for Sigma regional host/REST credentials; Omni personal token or CLI OAuth; offline path needs no credentials. Operators are assumed to own the platforms. | No automatic credential creation, revocation, Keychain extraction, software install or browser consent. These are deliberate authority boundaries. |
| Safe settings loading | Explicit selected `.env`; process environment precedence; host conflict refusal; no shell evaluation; duplicate/unknown syntax rejection; owner-only files; symlink checks; value-free errors. | Local OS identity remains the trust boundary. Secret manager integrations are not added. |
| Readiness and discovery | `doctor` checks local profile/credential presence and optionally selected Sigma resources/Omni identity. `discover` reads connections, paginated shared models, optional Topic metadata. No target writes; bounded calls and redacted failures. | Mocked contract checks only. Topic reads and OAuth require official CLI capability; extensions/workbook models are not enumerated. Model permissions and source lineage are not inferred from identity/readability. |
| Private distribution and ownership gotchas | Guide covers authenticated private download/customer ZIP, My Documents/API identity mismatch, deliberate copy identity changes, and temporary-key cleanup. | No repo visibility or workbook ownership changes performed. Do not copy/delete customer content automatically. |
| Route and change policy | Both routes remain explicit. Assessment-only stops before artifacts; dashboard-only does not change the model; model-change proposals permit existing supported model/dbt generation. Setup route reused during init/configure. | Topic-additions-only compilation fails closed; the operator cannot silently widen to model changes. Unsupported modeled transformations remain blocked. |
| Existing-topic reuse | Strict imported single-base-view inventory with grain/filters/definitions/visibility, exact field mappings, automatic evidence hashes, human compatibility notes; typed query JSON + document proposals only. Independent validation denies model/dbt/SQL artifacts and catches stale/tampered mappings. | Discovery responses still need reviewed normalization into the inventory contract. Compatibility notes are operator assertions, not automatic semantic proof. Multi-view/joined topics and live target freshness remain unverified. |
| Chart/page pilot selection | `scope` records selections, exclusions, dependency closure, shared controls and single-document assembly intent while keeping all source/context evidence. Unknown/ownerless/ambiguous/cyclic lineage blocks. | Local selection does not reduce full capture API calls. All captured model objects and some separate workbook metadata remain conservative blockers. No arbitrary large-workbook streaming or automatic source cleanup. |
| Progress, manifest, resume | `report` projects real source dispositions and reopened validation onto charts; includes counts, artifact refs, discrepancies, exclusions and next local action. Input/scope/target revisions invalidate review; previous attempts remain preserved. | No live chart checkpoint/retry, cost estimate, or duration estimate is invented. Existing event/package manifests remain local and append-only. |
| Validation and assembly | Source IDs and semantic/control/layout intent retained; generated files independently reopened. Guide distinguishes migration fidelity from analytical correctness and final UX polish. | No record-level live comparisons, numeric discrepancy classification, persona/security parity or visual acceptance. Differences stay unresolved without paired evidence. |
| Skill and customer guide | Canonical skill/runtime version aligned, new public commands documented, platform-owner setup guide and self-contained HTML regenerated. Customer packaging preserves exact skill bytes and excludes every `.env*`. | Independent non-engineer operator walkthrough and exact workshop-skill reconciliation still required. |

## Focused verification

Tests exercise unsafe dotenv syntax/permissions/host conflicts, conditional setup
and resume, HTTP redaction/pagination, OAuth command isolation, public profile
initialization, real guided mappings, scope tampering and lineage, per-chart reports,
persisted dashboard-only artifacts, forbidden artifacts, and review invalidation.
Network access is mocked for discovery and denied during compiler/integration tests.
Synthetic human-input fixtures are not a human walkthrough or live approval.

Final combined milestone: **579 tests passed in 12.55 seconds**, including the
original synthetic corpus, new setup/reuse/scope/report integration, skill command
compatibility and archive checks. The initial combined run had one documentation
allowlist failure; adding the official `docs.omni.co` domain repaired it. No tests
were skipped to hide unsupported behavior. Scoped Ruff, HTML synchronization and
Git whitespace checks passed. The local editable runtime was refreshed and reports
0.3.0 with all new public commands available.

No live connection, customer data capture, target write, GitHub push, or customer
acceptance is claimed. The customer archive is a reviewed-source working-tree
snapshot, not a published GitHub release; its manifest records that distinction.

## Next gates

1. Obtain the exact installed workshop skill/version and reconcile its live adapter
   before claiming the same successful execution path was enhanced.
2. Have an independent platform owner complete setup and one supported local pilot.
3. Exercise authorized live read-only discovery against a development tenant and
   normalize the observed Topic response contract; add joined-topic support only
   with evidence and corresponding independent checks.
4. Separately authorize any live deployment pilot, then verify returned IDs,
   readback, numbers, controls, visuals, security/personas and owner acceptance.

## Official contracts consulted

- [Sigma API credentials](https://help.sigmacomputing.com/reference/generate-client-credentials)
- [Omni authentication](https://docs.omni.co/api/authentication)
- [Omni CLI authentication](https://docs.omni.co/developers/cli/authentication)
- [Omni identity](https://docs.omni.co/api/who-am-i/get-current-identity-and-permissions)
- [Omni connections](https://docs.omni.co/api/connections/list-connections)
- [Omni models](https://docs.omni.co/api/models/list-models)

Installed CLI help confirmed model list/list-topics/get-topic syntax. The locally
installed CLI lacks `whoami`; it was not used for authenticated calls and would
need updating for the OAuth path. No guessed Topic REST endpoint was introduced.

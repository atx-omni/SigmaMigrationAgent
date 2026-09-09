# Sigma migrator: gap-remediation plan

Historical approved implementation baseline, September 8, 2026. Repository creation
and implementation were authorized September 9. See `IMPLEMENTATION-AUDIT.md` for
the actual completed/partial status; live target writes remain outside scope.

## Outcome we are targeting

A platform owner can capture a supported Sigma workbook, choose **direct reconstruction in Omni** or **warehouse-first modeling**, review the proposed changes through a supported interface, and obtain a complete, validated local build package. The workflow stops before any Omni write and clearly identifies remaining live validation and approval requirements.

For the first delivery, implement and prove the direct route first while retaining both choices and their existing protections. Then connect the modeled route to the same output contract. This is an implementation sequence, not a default route or a requirement to remodel the warehouse.

**Assessment:** high confidence in the two reproduced preservation/binding problems and the missing build integration. Effort and final live-migration success remain unestimated until the separate Sigma repository and target contract are confirmed.

## Baseline and scope

The [synthetic test report](SYNTHETIC-BASELINE-REPORT.md) records 55 focused checks: 50 passed and 5 failed. Five failures represent three gaps:

| Gap | What needs to change | Closure evidence |
|---|---|---|
| Unknown field references emitted without warning | Bind formula references to the captured source schema before emitting usable fields | Missing/ambiguous references block the affected output; valid references still work |
| Hidden aggregate metadata lost | Preserve visibility through calculated-field construction and serialization | True, false and omitted values behave consistently through the final model output |
| Planning does not produce a target-build handoff | Add supported review/import, deterministic artifact generation, validation and export | Real persisted model/dashboard payloads, exact lineage and complete scope accounting; no placeholder plans masquerading as builds |

The same synthetic corpus remains the regression baseline. Its failing expectations must not be deleted or suppressed simply to turn the suite green.

## 0. Establish the separate Sigma implementation home

**Work**

- Confirm the exact Sigma repository URL or checkout path with Austin. Do not guess the remote.
- Create/use a separate checkout and a scoped `atx/` implementation branch once implementation is authorized.
- Bring across Sigma source, tests, contracts and the deliberately selected common-engine dependencies using the preserved ownership handoff. Preserve applicable provenance and licenses.
- Make a dependency/import inventory: the recovery source contains Domo-origin common runtime code. Reuse must be intentional and independently versioned; it must not rely on imports from the Domo checkout or copy its complete application wholesale.
- Leave the frozen mixed recovery copy and the dedicated Domo repository untouched. Keep the original recovery archive and synthetic evidence.

**Done when:** Sigma imports and the compact test corpus run exclusively from its own checkout; its remote and baseline are recorded. No shared working directory or mixed publication remains.

**Dependency:** this is the only repository choice needed before implementation begins. It does not block planning or review of this document.

## 1. Repair source binding and visibility

### 1A. Context-aware field-reference validation

- Add a validation step at the extraction/semantic-compilation boundary, where captured table, element and column identities are available. Keep the formula translator's existing schema-free parsing role; it cannot know whether a field exists without source context.
- Resolve references to stable source identities, not just normalized labels. Handle explicitly supported aliases, calculated-field dependencies and table qualification. Treat duplicate labels, ambiguous mappings and dependency cycles as blocking conditions.
- Parse references using the supported formula grammar so quoted text is not accidentally treated as a field reference. Unsupported syntax must remain explicit review work, not a best-effort guess.
- Apply the same validation to aggregate operands and conditional/filter references, including metrics nested in a model and those declared separately.
- Produce a review item with the original formula, source object ID, unresolved reference and reason. Do not emit a seemingly valid deployable measure for that item.
- Track coverage: each required field is either compiled and validated or explicitly unresolved. An unresolved dependency blocks its consumers and whole-scope readiness. A separately approved reduced scope is a new scope decision, not silent omission.

### 1B. Preserve hidden metadata

- Carry the source visibility value through dimensions, calculated measures, standalone metrics and final model serialization.
- Retain documented/default behavior when the value is absent; validate malformed values rather than relying on truthiness of strings such as `"false"`.
- Preserve identifiers, descriptions and lineage while doing this narrow repair.
- Keep visibility metadata separate from RLS/CLS and access policy. This fix is not proof of security equivalence.

**Done when:** the unknown-reference and hidden-field failures close at the appropriate context-aware/output boundaries, with focused cases for valid aliases, ambiguity, calculated dependencies and true/false/absent visibility. Existing supported aggregates retain their results.

**Likely code areas:** Sigma extractor, reference binding/semantic validation, common field serialization and Sigma-specific tests. Do not add a broad formula engine as part of this defect fix.

## 2. Replace simulated review with a usable operator workflow

The current test harness constructs approvals and registers reviewed outputs through internal APIs. A customer cannot be expected to reproduce that.

**Work**

- Add a guided command flow or lightweight review page that displays source coverage, the neutral two-option route question, proposed mappings and unresolved items.
- Generate hashes, immutable references and exact source/route/predecessor bindings automatically. Operators should review the meaning and changes, not calculate fingerprints or edit approval JSON.
- Bind actions to a configured, verified operator identity. For a local single-operator pilot, explicitly define the OS/process trust boundary and its limitations; for a shared/hosted deployment, resolve identity through its authenticated session. A claimed reviewer string or approval-shaped file must not authenticate itself.
- Provide supported review actions to accept, reject, request changes, import reviewed typed output, and resume. Reject stale approvals after source, route or output changes.
- Keep AI proposals untrusted and non-authoritative. Require human review for ambiguous semantics and route choice; no model may approve its own output or authorize writes.
- Store secrets outside artifacts; keep synthetic test mode and test approvals permanently non-production.

**Done when:** a platform owner completes capture → choose route → review → register output → resume using only shipped commands/interface and the guide. The test uses those public entry points rather than directly inserting approval records into a store.

## 3. Generate the actual pre-push build package

### 3A. Define the shared package contract first

Create a versioned, source-bound build manifest containing:

- Source workbook/model/version, selected route, exact artifact hashes and review bindings.
- One disposition for every scoped page, analytical element, field, formula, control and behavior.
- Model/view/relationship/Topic definitions; typed dashboard queries, visual configuration, layout and control mappings.
- All generated files and hashes, source-to-target mappings, target environment requirements and ordered proposed operations.
- Validation outcomes, unresolved blockers and explicitly approved exceptions. No embedded credentials.
- Separate state for offline preflight, live validation, write authorization and final acceptance. A synthetic package cannot become production evidence merely by being renamed or approved.

**Generation must create actual machine-readable output.** Empty files, placeholder SQL, prose plans, or additional phase names are not sufficient.

### 3B. Complete direct reconstruction first

- Compile reviewed source semantics into Omni model artifacts over existing, explicitly selected warehouse relations.
- Preserve field identities, join/grain assumptions, aggregate/filter context, visibility and security intent. Reject unresolved or hallucinated references before packaging.
- Generate dashboard content and control-to-tile mappings from the reviewed workbook evidence. Include intended pages/layout, not only a named empty document.
- Support the representative pilot's row arithmetic and cumulative calculation through a reviewed, source-context-bound implementation, including grouping/order/null behavior. If a pattern is not supported, leave it blocked. Any pilot scope reduction must be explicit and must not be reported as a full migration of the original workbook.
- Do not generate dbt work or warehouse mutations for the direct route.

### 3C. Connect warehouse-first outputs

- Generate meaningful dbt/SQL/test artifacts for the reviewed upstream logic, then build Omni semantics against the exact expected resulting relations.
- Preserve the same route/source/review manifest and downstream validation contract as direct mode.
- Distinguish a locally valid data-layer build package from an actually deployed/validated warehouse relation. Until those dependencies are accepted, report that data-layer work remains; do not say that only the Omni push is left.

### API and write-boundary requirements

Current official documentation was checked September 8:

- The older [Documents v1 create endpoint is deprecated](https://docs.omni.co/api/documents/create-document); select and pin the current Documents v2 request/response contract for this implementation. Do not carry forward old driver assumptions without reviewing them.
- [Documents v2 creation](https://docs.omni.co/api/documents-v2/create-document) creates **and publishes** a new document. Therefore a pre-push preview must remain a local artifact; no create call can be treated as a harmless preview or dry run. New-content creation needs its own explicit authorization, regardless of later edit approval settings.
- The [model YAML endpoint](https://docs.omni.co/api/models/create-or-update-yaml-files) supports model-file writes and checksum conflict detection, with model-type/Git-mode restrictions. Record those compatibility requirements before any future apply step; preserve authored state and use current checksums.

**Done when:** after reopening a run, the supported direct slice and the modeled slice each expose concrete, schema-valid, fully referenced artifacts and an honest readiness manifest. Current runtime/API capabilities are explicitly checked; no remote write occurs.

## 4. Add a deterministic pre-push validator and hard stop

**Work**

- Reopen exported files and parse them independently of the generator. Check missing references, duplicates, join dependencies, control targets, required query/visual fields, source hashes and reviewer lineage.
- Compare the generated query logic—not manually supplied target answers—with the independent fixture expectations for totals, filtered totals, group/order behavior and null handling. Keep the source oracle separate from generated target output.
- Ensure the global benchmark stays outside the Region business filter while every required security rule remains accounted for independently. Local checks do not claim live persona enforcement.
- Make unsupported actions, input-table/writeback behavior, schedules, embeds, complex formulas and visual differences explicit per-item dispositions. Never remove them from the denominator to obtain a green result.
- Provide an export/preview mode that cannot invoke target drivers or load target credentials. Keep any future apply operation separate, disabled by default and bound to exact reviewed hashes/environment.
- Preserve the existing synthetic barrier, revocation, retry-budget, replay and source-currentness controls.

**Proposed statuses:** `blocked`, `offline_preflight_passed`, and a separate live-validation/write-approval state. `offline_preflight_passed` is never `migration_accepted`; it does not imply Omni executed the output successfully.

**Done when:** genuine generated artifacts pass positive cases, intentionally broken artifacts fail independently, restart preserves the same result, and a write-attempt sentinel confirms no target invocation during preflight.

## 5. Reconcile tests and update the operator kit

**Testing discipline**

1. After each defect fix, run only its reproducer and a few neighboring regressions.
2. After review/output integration, run one route end to end locally, then the other route.
3. At the combined milestone, run the existing compact 55-check corpus plus the essential new output/review checks once. Investigate meaningful failures; do not repeatedly run unrelated slow suites after every edit.
4. Replace the two phase-name readiness assertions with checks of actual persisted model/dashboard payloads, mappings, validation and lineage. Merely adding `semantic_build`/`document_create`/`content_build` strings must not satisfy them.
5. Replace the schema-free translator's missing-reference expectation with a context-aware rejection check while preserving coverage of the same unsafe input. Do not delete the failing scenario or teach the parser to special-case its fictional field name.
6. Retain all unsupported cases as unsupported until their implementations have independent evidence. No `xfail` or blanket skip to make readiness appear green.

**Operator handoff**

- Update the instruction page to show the actual supported setup, review, build, validate, export, resume and troubleshooting flow. Assume full-access platform owners, not AI engineers; no administrator handoffs and no hand-authored hashes.
- Add an honest supported/blocked behavior checklist and separate synthetic demonstration mode.
- Verify a clean installation once in the supported environment and have a platform owner repeat the pre-push flow without internal APIs or engineer-authored approval files. Record what was actually tested.
- Build a Sigma-only versioned package from its own confirmed repository; leave historical recovery and test artifacts intact.

**Done when:** the three gap categories are closed with observable evidence, the operator can use the supported flow from the guide, and the pre-push package is useful without implying live deployment acceptance.

## Later live acceptance gate — separate authorization

Only after implementation and explicit live-test/write authority: run one bounded workbook against a permitted Omni development destination, confirm returned IDs and readback, compare numerical results, controls, relevant allowed/denied personas and visual behavior, and test recovery for partial/ambiguous writes. Never replay an uncertain write without reconciliation.

That gate is required before claiming successful real migration. It is not silently included in this no-push remediation plan. Omni's [Content Validator](https://docs.omni.co/api/content-validator/validate-content) may contribute target validation once the appropriate target state exists; it does not substitute for independent source-to-target comparisons or offline proof of live behavior.

## Traceability and execution order

| Requirement | Phase | Completion evidence |
|---|---|---|
| Separate Sigma/Domo ownership | 0 | Verified separate checkout/remote/imports |
| Unknown-reference gap | 1A | Source-bound rejection plus valid-reference regressions |
| Hidden metadata gap | 1B | End-to-end field metadata round trip |
| Missing review integration | 2 | Operator-facing review/registration/resume |
| Direct route build handoff | 3A–3B | Real model/dashboard package; zero dbt work |
| Modeled route build handoff | 3A–3C | Real data-layer artifacts and honest Omni dependencies |
| Unsupported behavior accounting | 3–4 | Complete scope/disposition manifest |
| No Omni push during preflight | 4 | No target driver invocation; network/credential isolation |
| Functional proof, not phase labels | 4–5 | Independently checked generated artifacts after reopen |
| Customer usability and packaging | 5 | Clean-install and owner-run evidence |
| Live success claim | Later gate | Explicitly authorized deployment/readback/paired comparisons |

Execute 0 → 1 → 2 → 3 → 4 → 5. After isolation, the narrow binding/visibility repairs can run alongside the design of the review interface and package contract, with one owner per file. Complete the direct build slice before extending the modeled build slice. Do not expand into broad formula coverage or portfolio migration before this one-workbook path is usable.

The next required input before implementation is the exact Sigma repository URL or checkout path. No owners, dates, delivery promises or live approvals are invented by this plan.

# Sigma pre-push test results

Historical September 8 baseline. Its original evidence-path references belong to
the preserved test kit, not this repository. Current changes and test results are
in `IMPLEMENTATION-AUDIT.md`; do not interpret the failures below as current status.

**Outcome: the synthetic workbook reaches the end of supervised planning on both routes, but is NOT ready for Omni deployment.**

September 8, 2026 · Internal artificial-data exercise · No live credentials, model calls or target writes

## The short answer

The experiment ran **55 focused checks: 50 passed, 5 failed in 9.37 seconds**. The five failures describe **three distinct gaps**, not five independent defects. These are the final results after correcting two mistakes in the new test harness: the engine's successful specification state is named `bound`, and model IDs belong to the model snapshot rather than the workbook graph. No production code was changed to obtain this result. The initial 7-failure run is retained separately in `evidence/tests.xml`; the authoritative run is `evidence/tests-final.xml`.

**Confidence: High for these reproduced local behaviors; live Sigma/Omni migration success remains unverified.** This is not a statistical success-rate estimate or a full regression-suite result.

## Artificial workbook and reference data

`artifacts/fixture-suite.json` describes fictional Cedar & Compass Retail:

- Two pages, four analytical elements, a Region control, and an input-table element.
- A data model with order lines and stores, plus a separate custom-SQL identity.
- Row-level net sales/profit expressions, aggregated revenue and a cumulative calculation.
- Recursive column-type metadata; exact workbook/model/element/column identifiers and a selected source version.
- Separate, explicitly manual-only expectations for layout, control targets, access personas, actions and input-table behavior.
- Six fictional order lines with independently authored reference totals: net sales **495**, profit **206**, East sales **220**, West sales **275**. These are fixture arithmetic, not observed Sigma query results. The global benchmark deliberately ignores the Region control; that filter choice must not be confused with row-level security.

The fixture contains 28 configured route keys and nine source scenarios. Their structure is grounded in official [Sigma model specification](https://help.sigmacomputing.com/reference/get-data-model-spec), [model source](https://help.sigmacomputing.com/reference/list-data-model-sources), [workbook source](https://help.sigmacomputing.com/reference/get-workbook-sources), [page](https://help.sigmacomputing.com/reference/list-workbook-pages), [element](https://help.sigmacomputing.com/reference/list-workbook-elements), and [column](https://help.sigmacomputing.com/reference/get-workbook-columns) documentation, checked September 8. Documentation-shaped test data is not a complete vendor contract certification; all source URLs and caveats are recorded inside the fixture.

## What actually worked

| Checkpoint | Observed local result | Limit of the evidence |
|---|---|---|
| Mocked Sigma acquisition | 34 in-memory requests; no unconfigured routes; selected IDs/formulas/nested type retained; sensitive fixture markers redacted | No real authentication, tenant response or row query was tested |
| Synthetic evidence barrier | Correctly blocked with `live tenant evidence has not been collected`; refused planning registration | A safeguard pass, not a successful migration |
| Version/identity failures | Wrong/missing model identity and fractional version blocked; `7.0` accepted as integral version 7 | Simulated responses only |
| Pagination and missing access | Both opaque pagination styles retained; withheld columns/materializations produced visible blocking gaps | No portfolio-scale or live rate-limit proof |
| Human architecture choice | No default; direct mode excluded dbt; modeled mode included it | Route selection does not establish semantic correctness |
| Direct route | All five planning packages completed with durable reopen/reviewed lineage | AI and review service were test doubles; no model/dashboard build package |
| Warehouse-first route | All six planning packages completed with durable reopen/reviewed lineage | No dbt execution, warehouse validation or Omni build package |
| Failure/recovery controls | Forged approval/citation, unregistered output, missing predecessor lineage, changed source, revocation and partial initialization rejected; explicit retry retained reserved budget | Authenticated customer review integration and full operational recovery remain unproved |
| Adversarial source text | Preserved as untrusted input; injected secret marker redacted; no source text created approval, completion or a network call | A deterministic stub cannot prove real LLM prompt-injection resistance |
| Narrow formula evaluation | 12 translated aggregate/filter expressions matched independently authored SQLite expectations | SQLite agreement is not live Sigma/Omni equivalence |

The separate formula corpus has **25 cases**: 12 locally evaluated, 11 explicitly unsupported, one median translation not locally evaluated, and one unchecked missing-reference case. It also has five extractor-boundary checks. Explicitly unsupported formulas count as correct refusal behavior, **not** successful translations. In particular, the tested row/window/null/division cases still need reviewed implementation.

## Failures that stop a pre-push handoff

| Gap | Actual behavior | Failed checks | Required next implementation |
|---|---|---:|---|
| Missing source-field binding | `Sum([Never Captured])` becomes the aggregate tuple `sql=never_captured`, `aggregate=sum`, with no reason; extraction emits the metric without a review note despite the absent field | 2 | Validate references against captured columns at the context-aware boundary; refuse or explicitly flag unresolved references. The pure formula translator itself does not currently receive a schema, so a source-bound validation step is required |
| Hidden calculated field loses metadata | An input aggregate column with `hidden: true` becomes a measure with `hidden: false` | 1 | Preserve hidden metadata when constructing calculated measures. This is a metadata-preservation defect; it does not by itself demonstrate an RLS/CLS leak |
| No connected target-build handoff | Both graphs contain only `sigma_*_planning` steps; no `semantic_build`, `document_create` or `content_build` handoff | 2 | Connect reviewed Sigma outputs to deployable model/document/content artifacts and pre-push validation; retain a separate explicit write approval |

The two build-handoff tests are deliberately strict **user-goal readiness assertions**, not unexpected regressions in the existing proposal-only planner. They fail normally rather than being suppressed as expected passes.

No fixes were applied to engine code in this exercise. The failures remain reproducible. The Sigma repository destination is still a separate unresolved publication/setup question; it did not prevent isolated testing.

## How far did we really get?

The actual capture, source hashing, route validation, canonical registration, durable runner, completion and retry code executed from the isolated recovery snapshot. Test-only approval records supplied the missing review service, and a deterministic provider returned structurally valid inert proposals. The test harness used internal registration APIs; it did not prove a platform owner can perform those steps using the shipped guide alone.

Both route results were `work_graph_completed_not_released`, with:

- `target_build_package_ids: []`
- `up_to_omni_push_ready: false`
- `target_write_authority: false`
- `release_authority: false`

The system stops earlier than “all output is ready and only the Omni push remains.” The exercise improves confidence in capture and control flow, but **does not change the conclusion that the current kit is not end-to-end migration-ready**.

## Safety and next action

Zero network attempts occurred during the route exercise; zero Omni writes occurred. The test suite also verifies that an intentional socket attempt is rejected by the network guard. No AI usage charges, database/warehouse writes, Git mutations, or edits to either product checkout were performed. The existing dependency environment was reused, so fresh installation remains untested.

Recommended next work: fix the two local preservation/binding gaps in a separately confirmed Sigma checkout, then implement the missing review-to-build handoff. Reuse this compact corpus before a narrowly authorized live comparison. Keep actions/input tables, row/window calculations, controls, security and visual behavior explicitly unresolved until their own evidence exists; do not hide them behind the passing test count.

## Evidence

- `artifacts/fixture-suite.json` — source inputs, scenarios and independent expected facts
- `artifacts/formula-cases.json` — authored formula/row corpus
- `artifacts/formula-results.json` — actual translator/extractor outputs and source fingerprints
- `artifacts/scenario-results.json` — actual capture dispositions and request traces
- `evidence/preflight-results.json` — both route states and request/network counts
- `evidence/*-trace.json` — synthetic proposal and reviewed-lineage traces
- `evidence/tests-final.xml` — final 55-check test result
- `README.md` — reproducibility and isolation instructions

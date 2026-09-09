# Remediation implementation audit

September 9, 2026. Confidence: **High for the observed local results**; live migration
success has not been measured. This is not a success-rate estimate.

## Outcome

A dedicated private Sigma repository now contains the source fixes, guided local
review workflow, concrete Omni/dbt artifacts and an independent pre-push validator.
The implementation materially advances preparation; **the full original workbook
and the entire remediation plan are not complete**. The supported fictional slice
must not be represented as migration of the original complex synthetic workbook.

## Review against every plan row

| Requirement | Status | Evidence and remaining boundary |
|---|---|---|
| Separate Sigma/Domo ownership | Implemented | Independent `atx-omni/SigmaMigrationAgent` checkout/remote/package. No sibling imports; original Domo and recovery copies untouched. Import inventory and software notices preserve shared-code provenance. |
| Unknown-reference gap | Implemented for supported grammar | Source-context binder resolves IDs/names/aliases, checks cycles/ambiguous references and blocks dependent fields. Schema-free parser unchanged. Includes documented qualified physical references. |
| Hidden metadata gap | Implemented locally | Strict true/false/absent semantics across dimensions, calculated measures and metrics, including JSON-to-YAML serialization. This is not RLS/CLS parity evidence. |
| Missing review integration | Implemented for local OS trust | Public configure/init/route/review/import/build/validate/export/revoke commands. Interactive decisions, automatic hashes, exact source/target/route binding, rejection, revision invalidation, restart and interrupted-build retry. Supplemental observed context still uses structured JSON; `inspect` and `import-context` remove manual identity/hash work. |
| Direct build handoff | Partial against original pilot | Actual Omni view/Topic YAML, typed Documents v2 create/patch bodies, page layout, string controls and executable queries. Six files in supported example; no dbt. Original row arithmetic, cumulative/window calculations, joins and cross-view queries remain blocked. |
| Modeled build handoff | Partial against original pilot | Eleven files in example including dbt projection models, project/macro/schema definitions and duplicate-aware row-equivalence tests. Unsupported transformations are not implemented upstream. Warehouse deployment/validation explicitly remains outstanding. |
| Unsupported behavior accounting | Implemented for captured denominator | Every captured inventory item has implemented/blocked disposition and source-target mappings. Unknown objects, actions, input tables, security, raw unhandled visual/control behavior and unsupported formulas cannot silently disappear. Missing uncaptured behavior is not proven absent. |
| No Omni push during preflight | Implemented locally | No apply command; independent validator never imports builder/provider/targets. Network-denial tests, no target credential access during preparation, false write/acceptance flags, sticky synthetic taint and private output files. |
| Functional proof, not phase labels | Implemented for supported slice | Original 55-test corpus retained; handoff checks now reopen real artifacts from public commands. Generated queries execute against independent fictional rows; tampered packages fail. |
| Customer usability and packaging | Partial | Full platform-owner instruction page, example, versioned package builder, and isolated Python 3.11 installation/checks. No independent human platform-owner walkthrough has occurred. |
| Live success claim | Not performed / separate authority | No live Sigma/Omni parity, target creation, readback, visual/persona validation, warehouse deployment, customer acceptance or cutover. |

## Verification performed

- Source binding/visibility and existing neighboring tests: **112 passed**.
- Full copied Sigma suite plus original synthetic corpus: **495 passed in 12.80s**.
- After the final documented-source-shape and guided-mapping fixes, focused builder,
  public-session and independent-validator checks: **47 passed in 0.98s**.
- Original synthetic corpus's 55 checks were included in the combined run. Its
  two phase-name expectations were replaced with actual persisted artifact checks;
  the unsafe missing-reference case moved to the context-aware extraction boundary.
  No failing scenario was hidden behind xfail/skip or fictional migration acceptance.
- Customer archive inventory/reproducibility/scanner/instruction-page/starter checks:
  **7 passed in 1.09s**, included in the combined milestone.
- New code's scoped Ruff checks, Python compilation and authored HTML synchronization
  passed. The new Python 3.11 environment imports only this checkout.
- Direct and modeled example SQL produces independently expected East revenue 250
  and completed revenue 200. The modeled row-equivalence test returns no discrepancy
  for equivalent rows and detects an intentionally deleted row.
- Malformed/resealed files, missing/duplicate identifiers, control-target drift,
  visibility loss, credential shapes, symlinks, unlisted files, stale review and
  unknown SQL columns are negative checks, not unsupported-behavior successes.

The first combined attempt stopped because one fixture had not been copied during
separation; the fixture was restored from the unchanged recovery snapshot before
the successful combined run. A clean-install Python 3.11 validator incompatibility
was fixed with strict bracket-identifier compilation in its local SQLite check;
exported SQL is unchanged and unknown quoted identifiers still fail.

## Important boundaries and residual work

1. **Original pilot support remains partial.** Implement and independently test row
   arithmetic, cumulative/window/group/null behavior and joins before claiming the
   original complex workbook migrates. Supported examples are explicitly reduced
   fictional scopes, not a waiver of original objects.
2. **Local freshness is not remote freshness.** Source/target file hashes and
   enrichment bindings are checked. Guided capture does not validate a Sigma
   version freeze. The preserved bounded capability-spike workflow has stronger
   version evidence checks but is not automatically joined to this new compiler.
3. **The AI planner is separate.** Legacy `sigma-run-*` proposal/retry/lineage controls
   are preserved and tested. They are not an integrated autonomous end-to-end path
   feeding the new deterministic builder. No model-quality claim is made.
4. **Local identity has a defined limit.** Review records the OS account and requires
   an interactive terminal. Another process with the same account has the same
   trust boundary; shared-service authentication and external approval attestations
   remain future integration work. Manifest hashes detect changes, not authorship.
5. **Portability is bounded.** The emitted slice uses simple identifiers, one view
   per query, table/column/line/bar visuals and string equality controls. Validate
   actual Omni model namespace, connection, authored YAML, query/view naming and
   Documents v2 acceptance in the separately authorized live pilot. No source
   security policy is silently replaced by a Region business filter.
6. **Do not publish a document as a preview.** The current documented Documents v2
   create API creates and publishes. Prepared request bodies remain local. Future
   model writes also require current authored checksums and target-model/Git-mode
   compatibility checks.
7. **Operational handoff is not human acceptance.** Run a platform-owner walkthrough,
   then a bounded live development pilot with explicit write authority, readback,
   paired numeric/control/security/visual observations and ambiguous-write recovery.

Current wire-contract references were verified September 9:
[Documents v2 creation](https://docs.omni.co/api/documents-v2/create-document),
[draft patching](https://docs.omni.co/api/documents-v2/create-draft-and-patch-document),
and the official Omni content-builder reference files cited in `prepush/build.py`.

## Next implementation sequence

Extend the original pilot's blocked formula/join patterns; connect verified source
freeze and reviewed specialist outputs to the local compiler; conduct the owner
walkthrough; only then request a bounded live target pilot. Keep live deployment,
security acceptance and release as distinct gates throughout.

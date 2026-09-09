# Software notices and separation record

This private SigmaMigrationAgent repository contains modified Apache-2.0 code
derived from exploreomni/omni-migrator and ATX's shared migration runtime. Preserve
`packages/omnikit-migration-engine/LICENSE` and `PROVENANCE.json` when redistributing.

The initial source snapshot baseline was 912e56d80431b50738397605d346ff5bf6c1b1be;
the recovery archive SHA-256 is recorded in IMPORT-MANIFEST.json. That manifest
records the initial import, not checksums of subsequently modified release files.

Deliberately retained shared dependencies: canonical IR, serialization, source
evidence, control-plane hashing/store/policy, semantic/consolidation types,
planner/provider/runner contracts and typed target contracts consumed by that
legacy runtime. These are independently vendored here, not loaded from Domo's
checkout. Historical Domo model/inventory type names do not indicate a Domo product
entry point. The new pre-push pipeline does not invoke target drivers.

Excluded after initial dependency inventory: Domo API, broker, extractor, manual
acquisition, report/evidence clients; all unrelated source extractors; all live
Omni/dbt/Snowflake target drivers; the Domo operator CLI; Domo customer/evaluation
assets; developer environments, secrets and run artifacts. The import script's
dependency traversal is an inventory aid, not authority to copy or publish a
complete sibling application. New distribution overrides enforce a Sigma-only registry.

The Domo comparison branch of the shared interrupted-registration test remains in
the original Domo effort; this repository retains the equivalent Sigma regression.
The original five failing synthetic expectations are retained at appropriate
source-bound and persisted-output boundaries; no unsupported case is marked accepted.

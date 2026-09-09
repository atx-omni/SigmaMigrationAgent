# Sigma customer package — repository handoff

Prepared September 8, 2026. **Internal release coordination; not included in the customer ZIP.**

## Audience revision — pilot.2

Austin clarified that recipients are the migration operators and platform owners, with full setup access, rather than business users who need administrator handoffs. The current guide assumes that authority and gives direct installation, credential, request, capture, review, run, retry, and revocation steps. It preserves actual runtime approval/lineage requirements and labels missing review integration as a product gap—not a request for more platform permissions.

`SETUP-AND-USAGE.md` replaces `ADMIN-SETUP.md`; `START-HERE.html` is generated from that single source using `scripts/render_sigma_operator_guide.py`. The package builder refuses stale HTML. Customer starter messages, worksheet, and README now address the owner directly. The original pilot.1 ZIP remains unchanged; distribute the new v2 ZIP after review.

Revision validation: **7 focused customer checks passed in 1.37 seconds**, including source/HTML consistency and navigation/reference links. Changed-file Ruff and whitespace checks passed. No core migration behavior, target write gates, or live source/provider operations changed or ran for this revision.

## Outcome and publication boundary

The customer kit is a draft, supervised Sigma source/planning distribution with an offline source-reading/routing walkthrough and nontechnical instructions. It is not a production release or an accepted migration. The source includes the shared engine dependencies developed alongside the Domo update; those do not grant customer target-write authority.

Historical packaging baseline only: `912e56d80431b50738397605d346ff5bf6c1b1be`.
**Superseded September 9, 2026:** this effort now lives exclusively in
`atx-omni/SigmaMigrationAgent`. Do not publish Sigma changes to the old recovery or
Domo repository. Follow the current root README, operator guide and
`docs/IMPLEMENTATION-AUDIT.md` for current packaging and readiness status.

This packaging task has not staged, committed, pushed, created a release, or sent the ZIP to a customer. The Domo and Sigma changes share files, so coordinate one combined commit/push owner after Austin confirms publication scope/destination. Preserve all existing work. Do not stage the entire dirty tree without reviewing that combined scope.

## New repository files for this packaging increment

- `customer/sigma/README.md`
- `customer/sigma/START-HERE.html`
- `customer/sigma/SETUP-AND-USAGE.md`
- `customer/sigma/PILOT-WORKSHEET.md`
- `customer/sigma/SOFTWARE-NOTICES.md`
- `customer/sigma/ENGINE-README.md` (distributed as `engine/README.md`)
- `customer/sigma/start.py`
- `customer/sigma/examples/fictional-sigma-snapshot.json`
- `scripts/build_sigma_customer_package.py`
- `scripts/render_sigma_operator_guide.py`
- `packages/omnikit-migration-engine/tests/test_sigma_customer_starter.py`
- `packages/omnikit-migration-engine/tests/test_sigma_customer_package.py`
- This handoff document.

The underlying Sigma implementation remains listed in `docs/sigma-review-implementation-status.md`. These package files do not replace that implementation or its shared dependencies.

## Rebuild and verify

From the repository root, with Python available:

```sh
python scripts/build_sigma_customer_package.py \
  --output dist/Sigma-to-Omni-Pilot-2026-09-08-v2.zip \
  --release-id 2026-09-08-pilot.2

python scripts/build_sigma_customer_package.py \
  --verify dist/Sigma-to-Omni-Pilot-2026-09-08-v2.zip
```

After changing the authored guide, run `python scripts/render_sigma_operator_guide.py` first. The builder refuses stale HTML and an existing output; use a new version/filename for a later package. It includes only curated customer files, Python/rulebook source, licenses/provenance, runtime locks, and reference schemas plus three explicit Sigma templates. It excludes internal review documents, Git/configuration, tests/evaluations, dependency environments, caches, credentials, and run/customer evidence. A bounded scan rejects common embedded-secret signatures and personal checkout/internal-chat references without printing the possible secret. This is not a full security certification.

Every engine Python file receives a distribution adaptation comment in the ZIP, without modifying the checkout. The manifest records both original source and distributed-content hashes. The original Apache license and upstream provenance remain unchanged. Provenance describes the historical import, not the current engine's security boundary. ZIP timestamps/order are deterministic; the manifest is an integrity aid, not a signature.

## Original pilot.1 focused validation

- Customer starter + packaging suites: **6 passed in 1.31 seconds**. These cover both choices, no default, no sockets/Sigma API construction in the demo, fresh private output directories, changed sample rejection, non-echoing errors, ZIP reproducibility/inventory/hashes, symlink/secret rejection, and bundled guide links.
- Changed Python-file Ruff and `git diff --check`: passed.
- Extracted ZIP: `start.py --check`, `--demo --route direct`, and `--demo --route modeled` all passed. Confirmed the Sigma workflow module loaded from the extracted `engine/src`, not the developer checkout.
- Smoke environment: macOS/Python **3.12.14**, using pre-existing third-party dependencies. No provider/source/target calls or credentials were used.
- **Not verified:** fresh-machine locked dependency download/build/install, Windows/WSL, customer tenant permissions, live capture, live model quality, target parity, or release/production acceptance. No repeated full suite or slow QA probe was run for packaging.

The package deliberately does not use the shared `conformance` command as an install check: its source-layout contract resources are not currently included in a built wheel. The Sigma walkthrough and live Sigma commands do not depend on those resources. Optional Snowflake installation/frozen uv setup is not part of the customer instructions.

## Before publication or customer delivery

1. Confirm the combined Domo/Sigma repository scope and branch with Austin, then use a single commit/push owner. This draft ZIP can be reviewed before that publication; it is not labeled as a released commit.
2. Verify relevant source/dependency files and gates for the approved combined change. Local focused results do not establish green remote CI.
3. Rebuild from the intended committed snapshot if publishing a release; preserve an immutable package ID and record the returned ZIP SHA-256. Do not reuse an old ZIP filename or imply that a working-tree archive was built from the final release commit.
4. Obtain explicit SE/AE review of the customer-facing draft and acceptance of the kit's supervised-pilot limitations. The recipient already owns setup; an implemented review integration is still needed for exact approval records and reviewed-artifact registration, irrespective of platform access.
5. Share only the original clean ZIP through the approved channel. Never distribute a customer-used working directory or demo/pilot evidence. No customer delivery has been performed here.

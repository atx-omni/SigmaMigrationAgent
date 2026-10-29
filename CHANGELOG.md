# Release notes

## Unreleased — Source-operation compatibility extension

- Adds a credential-free capabilities probe and fixed source-only check, inventory,
  snapshot and capture operations with pinned requests and immutable receipts.
- Workbook acquisition can omit an associated model while retaining unresolved
  dependency evidence. Existing semantic build/review prerequisites stay intact.
- Optional workbook contents Beta is retained separately from tagged evidence,
  with documented omissions; opaque text is never evaluated.
- Visual request v2 adds page PNG and optional associated-model selection. Resume
  verifies final source observations and exact attachment identities; uncertain
  export submissions are never automatically repeated.
- Keeps terminal review, dependency activation and target publication boundaries.
  Source-only isolated checks are distinct from dependency-backed transport tests,
  installation, release publication and live tenant qualification.


## 0.4.1 — Credential and JSON boundary fixes

- Scanner policy v2 recognizes API-token and credentials aliases consistently in
  structured properties, text assignments and URL parameters. Older validation
  results do not exempt current validation or export scanning.
- Full-export checks inspect exact archived bytes. Credential findings block both
  support and migration exports without modifying sealed source evidence.
- Sigma and Omni JSON acquisition requires UTF-8, allowing one leading UTF-8 BOM;
  structural checks and parsing use the same decoded text. UTF-16/32 bypasses are
  rejected while byte ceilings, deadlines and original response hashes remain intact.
- Runtime, bundled skill and operator guide are aligned at 0.4.1. Older exports
  need current revalidation before sharing; they are not changed automatically.
- Security policy includes owner-operated GitHub protection setup with the actual
  required check names. Billing, collaborator access and repository settings are
  separate owner actions, not changes made by this release.

Local verification: 792 combined offline tests passed, including actual ZIP-byte
and old-package regressions. The repository artifact gate passed 241 files;
locked dependency consistency, installation, project-configured lint and static
security checks passed. The dependency audit found no known vulnerabilities at
check time. The rendered guide and bundled skill match the runtime.

Source publication, remote CI, effective GitHub protection, authenticated customer
release signing and live migration acceptance are separate evidence. No target
apply capability or production AI dispatch is added.

## 0.4.0 — Security hardening

- One pinned offline scanner checks imported/persisted evidence and exact outgoing
  filenames/bytes. Credential and integrity findings block all exports.
- Export defaults to a minimal support summary. Full confidential source/target
  export requires explicit `--purpose migration` and separate sharing review.
- Guided setup uses an owner-private workspace outside the checkout. Tracked,
  Git-trackable and symbolic-link outputs are refused; existing evidence is not moved.
- Capture retains only connections required by verified selected-source lineage
  and necessary identity/type fields. Ambiguous lineage blocks acquisition.
- Sigma/Omni responses and CLI output have streaming, aggregate, structural and
  time limits. HTTP compression is refused; HTTP requires the POSIX main thread.
- Production advanced AI dispatch is disabled before credential loading. A local
  review or prepared egress manifest cannot authorize transmission.
- Dependencies are hash-locked, CI Actions use immutable commits, and security
  gates cover confidential artifacts, dependency vulnerabilities and static analysis.
- Release verification binds exact ZIP bytes to reviewed source and an independently
  trusted signing identity. Checksums alone do not authenticate the publisher.
- Current guide and agent skill remain aligned with runtime 0.4.0. Historical
  planning/status documents are not part of the deployed source or customer ZIP.

Verification before publication: 675 combined offline tests passed; the final
bounded-export refinement passed 46 focused tests. Locked 0.4.0 installation,
dependency consistency, secret scanning and static checks passed. The dependency
audit found no known vulnerabilities at check time. CI execution on the published
commit is separate evidence.

Both explicit migration routes and dashboard-only reuse retain their existing
limits. No target apply command or live security acceptance was added. Production
AI re-enablement requires an independent authenticated gateway; customer release
distribution requires an external signer/trust channel. See [SECURITY.md](SECURITY.md)
and the [operator guide](customer/sigma/SETUP-AND-USAGE.md).

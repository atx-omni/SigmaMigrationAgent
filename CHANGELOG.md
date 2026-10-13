# Release notes

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

# Security and release policy

Version 0.4.0 is a supervised, local preparation tool. It does not apply changes to
Omni or the warehouse. Offline validation is not live security acceptance.

## Working data and upgrades

Use `sigma-migrate setup` to create a private workspace outside the software
checkout. Default: `~/.sigma-migrate/workspaces/migration`. Keep source snapshots,
context, discovery, target mappings, runs and exports there. The runtime checks
owner-only folders, denies symbolic links, and rejects Git-trackable/already-tracked
outputs. All workspace descendants are ignored, not just credential filenames.
This prevents accidental disclosure; it cannot isolate processes sharing an OS user.

Existing evidence is not automatically moved, deleted, altered, untracked or made
private. For an older run, first preserve its originals and hash/event history.
Review its location and access privately. If its directory permissions or Git
status fail the new checks, stop and plan an explicitly approved migration to a
new private workspace; do not edit recorded paths or rewrite history to resume.
Never paste `.env`, raw snapshots or confidential ZIPs into an issue or chat.
If actual exposure is suspected, rotate affected credentials through their owning
platform, review recipients/history, and coordinate remediation separately.

## Data leaving the tool

Imports, JSON persistence, independent validation, both run-export purposes and
customer distributions use one pinned, offline scanner policy. Scanner errors,
unavailable/wrong dependencies, unsupported binary content and size limits fail
closed. It checks credential formats, key/value properties, free text, URL
credentials and filenames. It never verifies secrets over the network or emits
matched values. It has no user pragma or ignore-baseline bypass.

Default run exports contain only a support summary. `--purpose migration` is an
explicit confidential full export: original sealed evidence is preserved, not
silently redacted. A credential finding blocks **both** purposes even if semantic
blockers are otherwise acceptable for remediation. A scanner pass is not proof
that customer business metadata may be shared. Review recipients separately.

Production advanced AI dispatch is disabled before credential loading. The only
remaining runner provider is an exact built-in, credential-free synthetic fixture.
An egress preparation function constructs scanned canonical bytes and a hash-bound,
expiring proposal, but explicitly grants no authorization and sends nothing.
There is no local flag to unlock real dispatch. Enabling it requires a separate
service with authenticated approvers, credentials held outside the agent, exact
payload/provider/account binding, expiry, revocation, replay prevention, audit and
retention-policy review. `store:false` alone is not zero retention; see
[official OpenAI data controls](https://developers.openai.com/api/docs/guides/your-data).

## Bounded acquisition

Source capture verifies selected-object connection lineage and retains only
required connection identity/dialect fields. Unknown or ambiguous bindings block;
no successful-looking partial snapshot is saved. Broader minimized inventory is
an explicit library option, not a lineage override in the guided workflow.

Sigma and Omni reads enforce per-response and aggregate bytes, request counts,
JSON structure, records, pages and deadlines. HTTP compression is deliberately
rejected. Hard HTTP deadlines require the POSIX main thread with no existing alarm.
CLI output uses bounded concurrent stdout/stderr draining and process-group cleanup.
These are local macOS/Linux controls, not a multi-tenant sandbox.

## Commit and CI gates

Before proposing source changes, run:

```sh
.venv/bin/python scripts/security_gate.py --staged
```

Maintainers can explicitly enable the supplied fail-closed pre-commit hook once:

```sh
git config --local core.hooksPath .githooks
```

This changes only that checkout's hook location; review existing local hooks before
enabling it. The implementation does not replace your existing hook settings.

This inspects exact staged bytes, not only the working copy. The default without
`--staged` inspects tracked and nonignored source files. The gate recognizes renamed
operational artifacts by content as well as credential/file patterns. Synthetic
fixtures with intentional security examples have narrow rule + exact path + exact
SHA-256 exceptions and an expiry; changing any bytes requires renewed review.
Exceptions are not reusable runtime or export exemptions. Scanner output uses
redacted file identifiers. Review the corresponding local files privately.

CI uses immutable Action commits, read-only permissions and locked dependencies;
it runs offline tests, the artifact gate, dependency auditing, and medium/high
confidence/severity static security checks. It never runs privileged pull-request
code with publishing credentials. The GitHub repository owner must separately
configure required status checks/reviews and restrict changes to security policy,
locks and workflows. A workflow file does not enable branch protection or licensed
GitHub security features. Git-history clearance requires a separate scoped review.

## Dependencies and authenticated customer releases

Install the hash-locked build and runtime/dev requirements with `--require-hashes`
and `--only-binary=:all:`. Install this reviewed local package with `--no-deps
--no-build-isolation` so hidden build dependencies cannot escape the lock. Lock
updates are reviewable source changes, not automatic upgrades during migrations.

`scripts/build_sigma_customer_package.py` makes scanned, reproducible **draft**
ZIPs. Its `--verify` establishes inventory/integrity, not publisher identity.
Do not distribute a draft as an authenticated release. After independent review
and a clean source commit, prepare the separate provenance/SBOM manifest:

```sh
.venv/bin/python scripts/release_security.py prepare --artifact dist/REVIEWED.zip --expected-repository atx-omni/SigmaMigrationAgent --output dist/release-attestation.json
```

An external release custodian must sign those exact manifest bytes with an
organization-controlled key, or use supported organization-bound attestations.
This repository creates no signing keys and holds no signing credentials. Before
extracting or installing a release, verify using an independently obtained public
key fingerprint and expected source commit:

```sh
.venv/bin/python scripts/release_security.py verify --artifact dist/REVIEWED.zip --manifest dist/release-attestation.json --signature dist/release-attestation.sig --public-key publisher-public.pem --public-key-sha256 TRUSTED-FINGERPRINT --expected-repository atx-omni/SigmaMigrationAgent --expected-commit TRUSTED-COMMIT
```

Run verification from an already trusted verifier checkout/environment, never code
supplied only by the unverified ZIP. A key and fingerprint bundled with that ZIP
cannot establish its own publisher identity. Private-repository native attestation
availability depends on the organization's GitHub plan; do not make the repository
public to obtain it. Until a signing custodian/trust channel is configured, release
distribution remains blocked. No signer or independent source review is claimed
by local tests, a clean commit, or a self-computed checksum.

## Remaining deployment gates

Separately authorize and verify live readback, numeric/control/visual parity and
allowed/denied row/column/persona behavior before customer acceptance. Shared or
unattended automation needs independent user authentication and approval services.
The local terminal review is not that service.

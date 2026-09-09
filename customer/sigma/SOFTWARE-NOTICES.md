DRAFT — requires explicit SE/AE review before sending to customer.

# Software and snapshot notices

The engine's Apache License 2.0 is preserved in `engine/LICENSE`. Original upstream attribution is preserved in `engine/PROVENANCE.json`. That provenance file describes the historical source import and its then-current boundaries; it is **not** an assertion that the current shared engine has no AI or target-execution code.

This package contains later local adaptations, including governed Sigma source acquisition, two-route semantic planning, the shared supervised runner, and a customer offline starter. `PACKAGE-MANIFEST.json` fingerprints the exact supplied files and records whether the source was a working-tree snapshot. The original upstream file hashes remain historical attribution, not current package fingerprints. All engine source files bear a distribution modification notice where this package is built; the original upstream reference is retained.

The shared engine includes code for multiple source platforms and guarded target integrations. Only the documented Sigma source/planning workflow and fictional example are in scope here. The Sigma starter performs no network calls. Live source capture and AI planning require separate operator setup and approval. This is not a production-readiness, security-certification, compatibility, or support commitment.

Third-party dependencies are downloaded during installation rather than redistributed as binaries in this ZIP. Their licenses and notices remain with those packages. The runtime requirements lock and upstream attribution are included. The optional Snowflake dependency is not part of this Sigma pilot's installed dependency set.

Customer-facing material is a draft for explicit SE/AE review. This pilot package does not waive your organization's privacy/security controls or any migration acceptance gate.

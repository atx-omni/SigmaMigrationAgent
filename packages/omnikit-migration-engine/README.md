# Sigma migration engine

Install this package from the dedicated SigmaMigrationAgent repository. The
`sigma-migrate` command offers local import, route selection, review, build,
validation and export. It has no target apply/push command. See the repository's
operator guide and implementation audit for the supported scope and evidence.

Shared migration-runtime modules are deliberately vendored and independently
versioned; see `PROVENANCE.json`, the repository import manifest and notices.

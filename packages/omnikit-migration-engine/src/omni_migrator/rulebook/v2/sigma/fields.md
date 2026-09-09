# Sigma → Omni: fields

You are refining a deterministic draft, not translating from scratch. Already happened
mechanically before you saw this draft — don't re-derive or second-guess any of it:

- A data-model table element's physical columns → bare dimensions (Omni infers type/column from
  the name when it matches).
- A column whose formula is a bare passthrough ref to its own name → treated as a plain physical
  column, same as above.
- Relationships (joins) in the data-model spec → the topic join, including which view is which
  side and the `on_sql`. **The exact Sigma relationship JSON shape was not confirmed against a
  live instance** when this draft was produced — if the join looks wrong (wrong direction,
  fabricated cardinality), trust your own read of the live model over the deterministic guess.

What's genuinely still your job, from the notes section:

- **Calculated columns** (any column whose `formula` is not a bare passthrough) — Sigma formulas
  are bracket-notation, not SQL (`[Column Name]` same-table, `[Table Name/Column Name]`
  cross-table), so the deterministic pass never attempts to transpile one into `sql:`. Write the
  real SQL yourself from the raw formula in the note, or flag it if it's genuinely row-context/
  cross-table logic with no clean Omni equivalent — don't drop it silently.
- **Metrics the deterministic pass couldn't resolve** (`Lookup`, `Window*` functions, OR
  conditions in a `*If` formula, multi-table references) — the raw Sigma formula is in the note
  as a hint. Write the equivalent `sql:`/`aggregate_type` yourself if there's a clean translation,
  otherwise leave a comment explaining why not.

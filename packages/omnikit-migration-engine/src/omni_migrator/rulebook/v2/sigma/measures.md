# Sigma → Omni: measures

Already translated deterministically, trust it:

- A **Metric** (Sigma's term for a reusable, standardized calc — distinct from a plain data-model
  column) whose formula was a plain `Sum`/`Average`/`Count`/`Min`/`Max`/`Median`/`CountDistinct`
  wrapper around a single same-table `[Column]` reference → `aggregate_type` + bare `sql` (no
  `${TABLE}` token — Omni doesn't have one).
- A `SumIf`/`AvgIf`/`CountIf` whose condition was a simple equals/not-equals (optionally ANDed
  across *distinct* fields) → the measure's `filters:` block. The `is`/`is_not` shape there is the
  *only* Omni measure-filter wire format the deterministic pass has actually confirmed against
  real Omni YAML — don't assume it also handles ranges/OR/other operators; if it had, the measure
  would already carry `filters:` for that case too.

What was deliberately left untranslated rather than guessed — real limitations, not gaps in the
deterministic pass, each with the raw Sigma formula as a hint:

- `Lookup` and the `Window*` family — no Omni aggregate-type equivalent for cross-row/cross-table
  lookups (mirrors how DAX time-intelligence functions have none either).
- Any aggregation reached through a cross-table `[Table Name/Column Name]` reference — cross-table
  aggregations need real judgment about which Omni join path and SQL to use, not a mechanical
  guess.
- `SumIf`/`CountIf`/`AvgIf` whose condition has an OR, or repeats a condition on the same field —
  translate the intent into real filter SQL yourself; the shape didn't fit the one verified
  `filters:` wire format, not that it's unsupported by Omni.

**A note on confidence**: this source was built entirely from Sigma's public documentation, with
no live instance to verify the actual API wire shapes against (unlike Looker/Power BI/Metabase).
If what you're seeing in the live model or the deterministic draft doesn't match what these rules
describe, trust the live instance — flag the discrepancy in a comment so it can be fixed at the
source, rather than silently working around it.

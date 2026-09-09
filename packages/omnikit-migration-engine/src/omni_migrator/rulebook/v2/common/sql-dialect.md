# SQL dialect rules

A physical column is referenced **bare** (`sql: amount`), or `sql:` is omitted entirely when the field
name already matches the column name — Omni infers it. `${...}` is reserved for *field* references:
`${field_name}` for the same view, `${view_name.field_name}` for another view. Identifier casing and
quoting in the draft already match the source connection's actual physical columns — leave them as-is;
nothing to fix there.

A handful of common cross-dialect function quirks (`ISNULL(x)`→`x IS NULL`, `DATEPART`→`DATE_PART`,
`IFNULL`/`NVL`→`COALESCE`) are already normalized in the draft. For anything else dialect-specific you
encounter, rewrite to the target dialect's equivalent if you're confident; otherwise keep the original
expression and flag it rather than guessing. Never reformat or "optimize" SQL beyond what's required
for correctness.

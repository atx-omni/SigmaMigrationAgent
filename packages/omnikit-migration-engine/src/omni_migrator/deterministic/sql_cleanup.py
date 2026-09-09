"""Deterministic SQL/formula cleanups (sandwich stage 3, plan Appendix A.8).

Pure regex fixups that run on emitted/translated SQL — no full parse. Catch recurring
mechanical issues so the AI doesn't have to spend turns on them. Ported (clean-room)
from the omnify/snowparser cleanup ideas.
"""

from __future__ import annotations

import re

# (pattern, replacement) applied in order. Dialect-agnostic source-function normalizations.
_FIXUPS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\bISNULL\s*\(\s*([^()]+?)\s*\)", re.IGNORECASE), r"\1 IS NULL"),
    (re.compile(r"\bDATEPART\b", re.IGNORECASE), "DATE_PART"),
    (re.compile(r"\bIFNULL\b", re.IGNORECASE), "COALESCE"),
    (re.compile(r"\bNVL\b", re.IGNORECASE), "COALESCE"),
]

_TF_TOKENS = (
    "raw date week month quarter year day_of_week_name day_of_week_num day_of_month "
    "day_of_year month_num month_name hour minute second"
).split()
_TF_ALT = "|".join(sorted(map(re.escape, _TF_TOKENS), key=len, reverse=True))
_DOLLAR = re.compile(r"\$\{([^}]+)\}")
_TF_IN = re.compile(rf"\b([A-Za-z0-9_]+)_({_TF_ALT})\b")
_TABLE_COL = re.compile(r"\$\{TABLE\}\.(\w+)")


def apply_sql_fixups(sql: str) -> str:
    """Normalize known source-specific SQL functions to portable equivalents."""
    out = sql
    for pat, repl in _FIXUPS:
        out = pat.sub(repl, out)
    return out


def bracket_timeframes(text: str) -> str:
    """Rewrite `field_month` -> `field[month]` inside `${...}` only (Omni timeframe syntax)."""
    return _DOLLAR.sub(lambda m: "${" + _TF_IN.sub(r"\1[\2]", m.group(1)) + "}", text)


def strip_table_token(sql: str | None) -> str | None:
    """LookML's `${TABLE}.col` -> Omni's bare `col` (Omni has no `${TABLE}` token at all —
    verified against `docs.omni.co/modeling` and the Omni compiler source).

    Every extractor strips this at the source already; this is the single emit-time
    backstop (called from `model_emitter`) that guarantees it, so a `${TABLE}` reference
    can never reach the agentic API's prompt regardless of which source produced it — the
    AI shouldn't have to be told the token doesn't exist if it's structurally impossible
    for one to show up in its input.
    """
    return _TABLE_COL.sub(r"\1", sql) if sql else sql


def clean_sql(sql: str | None) -> str | None:
    """`None`-safe `strip_table_token` + `apply_sql_fixups`, applied together wherever a
    source's raw `sql:` lands in the IR. Keeps the deterministic pass — not the agentic
    prompt's rulebook text — responsible for source-function/table-token normalization."""
    if not sql:
        return sql
    return apply_sql_fixups(strip_table_token(sql))

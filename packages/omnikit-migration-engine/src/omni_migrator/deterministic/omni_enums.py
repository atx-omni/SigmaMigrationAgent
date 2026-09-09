"""Canonical Omni enums — the emit target's vocabulary.

These values are extracted directly from the Omni codebase (June 2026) and are the
exact accepted values. Cited to source-of-truth so they can be re-pinned.

- Dimension type:  query-manager .../model/types/OmniType.kt
- aggregate_type:  query-manager .../model/fields/Measure.kt  (Measure.AggregateType)
- format tokens:   bi-app .../utils/display/consts.ts          (FORMAT enum)
- chart types:     bi-app                                       (ChartType)
- filter kinds:    query-manager .../api/Filter.kt              (*FilterKind)
- relationships:   ModelYamlConverter.kt + docs.omni.co/modeling/relationships
"""

from __future__ import annotations

# --- dimension `type` (OmniType). Dates are `timestamp` (no separate date type). ---
OMNI_TYPES: frozenset[str] = frozenset(
    {"timestamp", "string", "boolean", "number", "interval", "array", "json"}
)

# --- measure `aggregate_type` (Measure.AggregateType), wire (lowercase) values. ---
OMNI_AGGREGATES: frozenset[str] = frozenset(
    {
        "sum", "count", "average", "max", "min", "median", "count_distinct",
        "list", "percentile",
        "sum_distinct", "average_distinct", "median_distinct", "percentile_distinct",
        "semantic_view_agg",
    }
)
# Aggregates whose result defaults to NUMBER_0 (count family) — format is dropped.
AGGREGATES_DEFAULT_NUMBER_0: frozenset[str] = frozenset({"count", "count_distinct"})

# --- named `format` base tokens (FORMAT). A `_<0-9>` decimal suffix may be appended. ---
_CURRENCIES = ["USD", "EUR", "GBP", "JPY", "BRL", "AUD"]
FORMAT_BASE_TOKENS: frozenset[str] = frozenset(
    {"NUMBER", "PERCENT", "ID", "CURRENCY", "ACCOUNTING", "FINANCIAL",
     "TRILLIONS", "BILLIONS", "MILLIONS", "THOUSANDS",
     "BIG", "BIGNUMBER", "BIGCURRENCY", "BIGACCOUNTING", "BIGFINANCIAL",
     "RELATIVE", "RELATIVENUMERIC", "RELATIVESHORT"}
    | {f"{c}CURRENCY" for c in _CURRENCIES}
    | {f"{c}ACCOUNTING" for c in _CURRENCIES}
    | {f"{c}FINANCIAL" for c in _CURRENCIES}
    | {f"BIG{c}CURRENCY" for c in _CURRENCIES}
    | {f"BIG{c}ACCOUNTING" for c in _CURRENCIES}
    | {f"BIG{c}FINANCIAL" for c in _CURRENCIES}
)
SUPPORTED_DECIMALS = frozenset(str(n) for n in range(10))

# --- chart types (ChartType) ---
OMNI_CHART_TYPES: frozenset[str] = frozenset(
    {
        "auto", "bar", "bar_grouped", "bar_stacked", "bar_stacked_percentage", "bar_line",
        "column", "column_grouped", "column_stacked", "column_stacked_percentage",
        "line", "line_color", "area", "area_stacked", "area_stacked_percentage",
        "point", "point_color", "point_size", "point_size_color",
        "pie", "funnel", "heatmap", "boxplot", "kpi", "single_record", "summary_value",
        "table", "spreadsheet", "map", "region_map", "svg_map", "sankey", "markdown", "code",
    }
)

# --- relationship enums ---
OMNI_JOIN_TYPES: frozenset[str] = frozenset(
    {"always_left", "always_inner", "always_right", "always_full"}
)
OMNI_RELATIONSHIP_TYPES: frozenset[str] = frozenset(
    {"many_to_one", "one_to_many", "one_to_one", "many_to_many", "assumed_many_to_one"}
)


def is_valid_format(token: str) -> bool:
    """True if `token` is a valid named format (base, optionally `_<0-9>`).

    Excel-style strings (anything else) are also accepted by Omni but are not
    validated here — the caller passes them through verbatim.
    """
    base, _, dec = token.upper().partition("_")
    if base not in FORMAT_BASE_TOKENS:
        return False
    return dec == "" or dec in SUPPORTED_DECIMALS

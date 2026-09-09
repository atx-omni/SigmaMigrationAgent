"""Deterministic dashboard mappings: chart type, grid normalization (Appendix A.10).

Pure, unit-tested lookups shared by dashboard translators. Omni uses a 12-column grid;
sources differ (Looker 24, etc.).
"""

from __future__ import annotations

import re

from omni_migrator.ir.schema import GridRect

# Looker vis type -> Omni ChartType (verified set in deterministic.omni_enums).
LOOKER_VIS: dict[str, str] = {
    "looker_column": "column",
    "looker_bar": "bar",
    "looker_line": "line",
    "looker_area": "area",
    "looker_scatter": "point",
    "looker_pie": "pie",
    "looker_donut_multiples": "pie",
    "looker_grid": "table",
    "table": "table",
    "looker_single_record": "single_record",
    "single_value": "kpi",
    "looker_funnel": "funnel",
    "looker_boxplot": "boxplot",
    "looker_map": "map",
    "looker_geo_coordinates": "map",
    "looker_geo_choropleth": "region_map",
    "text": "markdown",
}


def looker_chart_type(vis_type: str | None) -> str | None:
    if not vis_type:
        return None
    return LOOKER_VIS.get(vis_type)


def grid_from_24(col: int, row: int, width: int, height: int) -> GridRect:
    """Looker's 24-col grid -> Omni's 12-col grid (Appendix A.10)."""
    return GridRect(
        x=max(0, min(12, round((col or 0) / 2))),
        y=max(0, row or 0),
        w=max(1, min(12, round((width or 2) / 2))),
        h=max(1, height or 4),
    )


# Power BI report visualType -> Omni ChartType. Reverse-engineered from the (undocumented,
# internal) legacy Report/Layout JSON schema — not a published API contract, so treat
# unmapped/uncertain types as untranslatable rather than guessing (plan §12.2 discipline).
POWERBI_VIS: dict[str, str] = {
    "columnChart": "column",
    "clusteredColumnChart": "column_grouped",
    "stackedColumnChart": "column_stacked",
    "hundredPercentStackedColumnChart": "column_stacked_percentage",
    "barChart": "bar",
    "clusteredBarChart": "bar_grouped",
    "stackedBarChart": "bar_stacked",
    "hundredPercentStackedBarChart": "bar_stacked_percentage",
    "lineChart": "line",
    "areaChart": "area",
    "stackedAreaChart": "area_stacked",
    "pieChart": "pie",
    "donutChart": "pie",
    "scatterChart": "point",
    "card": "kpi",
    "multiRowCard": "summary_value",
    "tableEx": "table",
    "table": "table",
    "pivotTable": "spreadsheet",
    "funnel": "funnel",
    "map": "map",
    "filledMap": "region_map",
    "treemap": "heatmap",
}


def powerbi_chart_type(vis_type: str | None) -> str | None:
    if not vis_type:
        return None
    return POWERBI_VIS.get(vis_type)


# Best-effort row-height heuristic (px/row) for normalizing Power BI's absolute pixel
# canvas to Omni's grid — Power BI has no native row concept (unlike Looker's 24-col
# grid), so this is a documented assumption, not a verified Omni convention.
POWERBI_ROW_PX = 40


def grid_from_pixels(x: int, y: int, width: int, height: int, page_width: int, page_height: int) -> GridRect:
    """Power BI's absolute pixel canvas -> Omni's 12-col grid (best-effort, see `POWERBI_ROW_PX`)."""
    page_width = page_width or 1280
    return GridRect(
        x=max(0, min(12, round((x or 0) / page_width * 12))),
        y=max(0, round((y or 0) / POWERBI_ROW_PX)),
        w=max(1, min(12, round((width or page_width) / page_width * 12))),
        h=max(1, round((height or POWERBI_ROW_PX) / POWERBI_ROW_PX)),
    )


# Tableau dashboard zones use a proportional coordinate space (0-100000 = 0-100% of the
# canvas), not pixels — but the `<dashboard><size>` element gives the canvas's real pixel
# dimensions, so a zone converts to pixels first and then reuses `grid_from_pixels` (and its
# already-flagged-as-heuristic `POWERBI_ROW_PX` row scale) rather than inventing a second,
# unverified row-height constant for a second source.
TABLEAU_ZONE_UNITS = 100000


def grid_from_tableau_zone(
    x: int, y: int, w: int, h: int, canvas_width: int, canvas_height: int,
) -> GridRect:
    """A Tableau dashboard zone's proportional (0-100000) rect -> Omni's 12-col grid."""
    canvas_width = canvas_width or 1200
    canvas_height = canvas_height or 800

    def to_px(v: int, dim: int) -> float:
        return (v or 0) / TABLEAU_ZONE_UNITS * dim

    return grid_from_pixels(
        to_px(x, canvas_width), to_px(y, canvas_height),
        to_px(w, canvas_width), to_px(h, canvas_height),
        canvas_width, canvas_height,
    )


# Metabase `card.display` -> Omni ChartType. Best-effort from public API/docs, **not** verified
# against a live instance (unlike Looker/Power BI's vis-type tables, no real dashboard export was
# available while building this) — treat unmapped/uncertain values as untranslatable rather than
# guessing, and re-pin this table against a real instance before relying on it (plan discipline;
# same caveat as `grid_from_metabase`'s "18" below).
METABASE_VIS: dict[str, str] = {
    "bar": "column",
    "row": "bar",
    "line": "line",
    "area": "area",
    "pie": "pie",
    "table": "table",
    "pivot": "spreadsheet",
    "scalar": "kpi",
    "smartscalar": "kpi",
    "funnel": "funnel",
    "map": "map",
    "scatter": "point",
    "combo": "bar_line",
    "waterfall": "table",  # no direct Omni equivalent yet
    "gauge": "table",  # no direct Omni equivalent yet
    "progress": "table",  # no direct Omni equivalent yet
    "text": "markdown",
    "heading": "markdown",
}


def metabase_chart_type(display: str | None) -> str | None:
    if not display:
        return None
    return METABASE_VIS.get(display)


# Metabase's dashboard grid is unit-based (like Looker's 24-col, unlike Power BI's pixel canvas):
# `dashcard.col`/`row`/`size_x`/`size_y` are already grid cells, not pixels. The "18" column width
# is carried over from plan Appendix A.10's pre-existing assumption — spot-check against a real
# `GET /api/dashboard/:id` response before treating it as more than a documented starting point.
METABASE_GRID_COLS = 18


def grid_from_metabase(col: int, row: int, size_x: int, size_y: int) -> GridRect:
    """Metabase's 18-col grid -> Omni's 12-col grid (plan Appendix A.10)."""
    return GridRect(
        x=max(0, min(12, round((col or 0) / METABASE_GRID_COLS * 12))),
        y=max(0, row or 0),
        w=max(1, min(12, round((size_x or METABASE_GRID_COLS // 3) / METABASE_GRID_COLS * 12))),
        h=max(1, size_y or 4),
    )


# Tableau worksheet `<panes><pane><mark class=...>` -> Omni ChartType. Not verified against a
# live instance (no live Tableau access while building this — same caveat as Metabase's table
# above): built from the documented, stable `.twb` mark-class vocabulary, not reverse-engineered
# from an undocumented internal format the way Power BI's Layout JSON was. Bar vs. column is not
# encoded in the mark class itself — Tableau distinguishes them by which shelf (rows or cols)
# holds the continuous (measure) pill, hence the `measure_on_cols` parameter. Unmapped/uncertain
# marks (Shape, Polygon, GanttBar, Density, ...) fall through to `None` -> untranslatable, not a
# guessed chart type.
TABLEAU_MARK: dict[str, tuple[str, str]] = {  # class -> (measure-on-rows, measure-on-cols) chart type
    "Bar": ("bar", "column"),
    "Line": ("line", "line"),
    "Area": ("area", "area"),
    "Circle": ("point", "point"),
    "Square": ("point", "point"),
    "Pie": ("pie", "pie"),
    "Text": ("table", "table"),
    "Automatic": ("table", "table"),
}


def tableau_chart_type(mark_class: str | None, *, measure_on_cols: bool) -> str | None:
    if not mark_class:
        return None
    pair = TABLEAU_MARK.get(mark_class)
    if not pair:
        return None
    return pair[1] if measure_on_cols else pair[0]


# Sigma element `vizualizationType` (that spelling is the API's own, not ours to fix, §6.4) ->
# Omni ChartType. Best-effort from the documented chart-type *names* only (`Intro to
# visualizations`/`Build a KPI chart`) — no live instance to confirm the actual wire-value casing
# against (unlike Looker/Power BI's tables); treat with the same skepticism as Tableau's
# unverified mark-class table until spot-checked live.
SIGMA_VIS: dict[str, str] = {
    "table": "table",
    "pivottable": "spreadsheet",
    "bar": "bar",
    "column": "column",
    "line": "line",
    "area": "area",
    "scatter": "point",
    "combo": "bar_line",
    "boxplot": "boxplot",
    "boxandwhisker": "boxplot",
    "pie": "pie",
    "donut": "pie",
    "piedonut": "pie",  # docs list this chart type combined as "Pie/Donut"
    "sankey": "sankey",
    "funnel": "funnel",
    "gauge": "table",  # no direct Omni equivalent yet
    "waterfall": "table",  # no direct Omni equivalent yet
    "regionmap": "region_map",
    "pointmap": "point",
    "geographymap": "map",
    "progressbar": "table",  # no direct Omni equivalent yet (Beta)
    "progressring": "table",  # no direct Omni equivalent yet (Beta)
    "kpi": "kpi",
}


def sigma_chart_type(viz_type: str | None) -> str | None:
    if not viz_type:
        return None
    key = re.sub(r"[^0-9a-zA-Z]", "", viz_type).lower()
    return SIGMA_VIS.get(key)


def grid_naive_stack(index: int, *, height: int = 6) -> GridRect:
    """Sigma has no confirmed dashboard/element layout API at all (plan §6.4 — `pages`/`elements`
    carry no x/y/width/height, unlike every other source built so far). Rather than fabricate a
    grid mapping with nothing to map *from*, stack tiles top-to-bottom, full-width, in element
    order, and lean on the AI dashboard sub-agent for real layout entirely — same posture as the
    plan's explicit recommendation for this gap. Revisit if "Workbooks as Code" (private beta,
    §6.4) turns out to expose real layout."""
    return GridRect(x=0, y=index * height, w=12, h=height)

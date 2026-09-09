"""Sigma workbook `pages[].elements[]` -> `DashboardIR`, one per page.

A Sigma workbook is organized into pages (like tabs) — the closest analog among sources built so
far is Power BI's report pages (`powerbi/dashboard.py`, one `DashboardIR` per page), not Looker's
single whole-dashboard object, since a page is what a user would actually pick to migrate as "one
dashboard" (mirrors the `sigma-workbook-pages` / `migrate-sigma-dashboard --page` CLI pattern).

**The real, load-bearing gap: no layout API.** `GET .../pages/{id}/elements` returns
`elementId, name, type, columns[], vizualizationType` (that spelling is the API's own documented
typo, not ours to fix) `, error` — no x/y/width/height anywhere (plan §6.4). Every tile gets
`deterministic.dashboard_maps.grid_naive_stack`'s top-to-bottom full-width placement instead of a
real grid mapping, and the AI dashboard sub-agent is relied on for actual layout entirely — same
posture as the plan's explicit recommendation for this source.

**Element -> topic resolution is itself a bridge, not a documented field.** Nothing in the
workbook pages/elements response says which data-model view an element's `columns[]` belong to
(unlike Metabase's dashcard -> card -> `dataset_query.source-table`) — resolved here by looking
each column id up in the data-model `column_ref` map the model extractor already built
(`extractor.py`'s `_build_views`), and using whichever view the *first* resolved column belongs to
as the tile's topic; a column resolving to a different view is flagged, not silently dropped or
guessed into a fabricated join.

The documented workbook-controls response does not expose an authoritative field binding. Control
objects therefore remain explicit blockers even when an acquired payload happens to contain keys
such as ``columnId``. Unknown visualizations, missing element IDs, query errors, and unresolved
fields likewise never become fallback tables or disappear from review evidence.

Generated SQL is retained only as a content fingerprint for validation. It is never used to infer
semantic objects or emitted as target SQL.

**Not verified against a live Sigma instance** — see the module-level caveat in `extractor.py`;
treat with the same skepticism as Tableau's dashboard translator until spot-checked live.
"""

from __future__ import annotations

import hashlib
import json

from omni_migrator.deterministic.dashboard_maps import grid_naive_stack, sigma_chart_type
from omni_migrator.ir.schema import DashboardIR, FilterIR, QueryIR, TileIR, UntranslatableNote


def _row_id(row: dict, *keys: str) -> str | None:
    for key in keys:
        value = row.get(key)
        if value not in (None, ""):
            return str(value)
    return None


def _fingerprint(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def sigma_generated_sql_evidence(value: object) -> dict | None:
    """Return content-addressed validation evidence without retaining generated SQL text."""
    if value in (None, "", {}, []):
        return None
    return {
        "sha256": _fingerprint(value),
        "role": "validation_evidence_only",
    }


def _feature_kind(element: dict) -> str | None:
    raw = str(element.get("type") or element.get("kind") or "").casefold().replace("_", " ")
    compact = raw.replace("-", " ").strip()
    if compact == "control":
        return "control"
    if compact in {"input table", "inputtable"} or element.get("inputTable") is not None:
        return "input table"
    if compact in {"action", "button", "action button"} or any(
        key in element for key in ("action", "actions", "actionType")
    ):
        return "action"
    if element.get("writeback") is not None or element.get("writeBack") is not None:
        return "writeback"
    return None


def _source_ids(value: object) -> list[str]:
    found: set[str] = set()

    def visit(node: object) -> None:
        if isinstance(node, dict):
            for key, child in node.items():
                if key in {"sourceId", "elementId", "nodeId", "inodeId"} and child not in (
                    None,
                    "",
                ):
                    found.add(str(child))
                elif key in {"sourceIds", "elementIds", "nodeIds"} and isinstance(child, list):
                    found.update(str(item) for item in child if item not in (None, ""))
                visit(child)
        elif isinstance(node, list):
            for child in node:
                visit(child)

    visit(value)
    return sorted(found)


def _element_evidence(element: dict, viz_type: object) -> dict:
    evidence: dict = {
        "source_visualization_type": viz_type,
        "layout_source": "naive_stack",
    }
    formulas = []
    for column in element.get("columns", []) or []:
        if not isinstance(column, dict) or not column.get("formula"):
            continue
        formulas.append(
            {
                "source_id": _row_id(column, "columnId", "id"),
                "label": column.get("label") or column.get("name"),
                "formula": str(column["formula"]),
            }
        )
    if formulas:
        evidence["column_formulas"] = formulas
    if generated := sigma_generated_sql_evidence(element.get("generatedSql")):
        evidence["generated_sql"] = generated
    if lineage := element.get("lineage"):
        evidence["lineage"] = {
            "sha256": _fingerprint(lineage),
            "source_ids": _source_ids(lineage),
            "role": "validation_evidence_only",
        }
    return {"sigma": evidence}


def _control_column_ids(control: dict) -> set[str]:
    column_ids = {
        str(value)
        for value in (control.get("columnId"), control.get("targetColumnId"))
        if value not in (None, "")
    }
    for raw in control.get("columns", []) or []:
        value = _row_id(raw, "columnId", "id") if isinstance(raw, dict) else str(raw)
        if value:
            column_ids.add(value)
    return column_ids


def _control_to_filter(
    control: dict, column_ref: dict[str, tuple[str, str]]
) -> tuple[FilterIR | None, UntranslatableNote | None]:
    control_id = _row_id(control, "controlId", "elementId", "id")
    label = str(control.get("name") or control.get("label") or control_id or "control")
    column_ids = _control_column_ids(control)
    del column_ref
    return None, UntranslatableNote(
        object=f"control «{label}»",
        reason="Sigma's documented workbook-controls response does not expose an authoritative "
        "field binding. Configure and validate the target filter explicitly or waive the control.",
        severity="blocker",
        hint=(
            "Unverified payload column IDs: " + ", ".join(sorted(column_ids))
            if column_ids
            else "No documented source column binding"
        ),
    )


def _resolved_element_fields(
    element: dict,
    column_ref: dict[str, tuple[str, str]],
) -> tuple[str | None, list[str], list[UntranslatableNote]]:
    label = f"element «{element.get('name') or element.get('elementId')}»"
    notes: list[UntranslatableNote] = []
    topic: str | None = None
    fields: list[str] = []
    for col in element.get("columns", []):
        col_id = col.get("columnId") if isinstance(col, dict) else col
        ref = column_ref.get(col_id)
        if ref is None:
            notes.append(
                UntranslatableNote(
                    object=f"{label} column",
                    severity="blocker",
                    hint=str(col),
                    reason="Unresolved column reference — not found in any extracted data model.",
                )
            )
            continue
        view_name, field_name = ref
        if topic is None:
            topic = view_name
        elif view_name != topic:
            notes.append(
                UntranslatableNote(
                    object=f"{label} column {field_name}",
                    severity="blocker",
                    reason=f"References a different table ({view_name}) than this element's topic "
                    f"({topic}) — the field was not silently added; cross-table behavior requires "
                    "an explicit relationship and query review.",
                )
            )
            continue
        fields.append(field_name)
    return topic, fields, notes


def sigma_element_can_emit_tile(
    element: dict,
    column_ref: dict[str, tuple[str, str]],
) -> bool:
    """Mirror tile emission readiness for the acquisition dependency manifest."""
    return sigma_element_blocker_reason(element, column_ref) is None


def sigma_element_blocker_reason(
    element: dict,
    column_ref: dict[str, tuple[str, str]],
) -> str | None:
    if _row_id(element, "elementId", "id") is None:
        return "the source omitted its required elementId"
    if element.get("error"):
        return "the source query has an error"
    viz_type = element.get("vizualizationType")
    if not viz_type or sigma_chart_type(str(viz_type)) is None:
        return "the visualization type is missing or unsupported"
    topic, fields, notes = _resolved_element_fields(element, column_ref)
    if any(note.severity == "blocker" for note in notes):
        return "one or more fields did not resolve without semantic loss"
    if topic is None or not fields:
        return "its fields did not resolve to the extracted model"
    return None


def _element_to_tile(
    element: dict,
    column_ref: dict[str, tuple[str, str]],
    index: int,
) -> tuple[TileIR | None, list[UntranslatableNote]]:
    label = f"element «{element.get('name') or element.get('elementId')}»"
    raw_element_id = element.get("elementId") or element.get("id")
    if raw_element_id in (None, ""):
        return None, [
            UntranslatableNote(
                object=label,
                severity="blocker",
                reason="Sigma visual omitted its required elementId; OmniKit cannot preserve "
                "identity or safely emit the tile.",
            )
        ]
    if element.get("error"):
        return None, [
            UntranslatableNote(
                object=label,
                severity="blocker",
                reason=f"Element has a query error in Sigma: {element['error']}",
            )
        ]

    topic, fields, notes = _resolved_element_fields(element, column_ref)

    viz_type = element.get("vizualizationType")
    chart = sigma_chart_type(str(viz_type)) if viz_type not in (None, "") else None
    if chart is None:
        notes.append(
            UntranslatableNote(
                object=label,
                severity="blocker",
                hint=str(viz_type) if viz_type not in (None, "") else "missing",
                reason="Sigma visualization type is missing or unsupported; OmniKit did not "
                "substitute a table. Choose a reviewed target visualization before migration.",
            )
        )
        return None, notes

    if any(note.severity == "blocker" for note in notes) or topic is None or not fields:
        generated_evidence = sigma_generated_sql_evidence(element.get("generatedSql"))
        if topic is None or not fields:
            notes.append(
                UntranslatableNote(
                    object=label,
                    severity="blocker",
                    reason="No column on this element resolved to a known data-model field; not "
                    "emitted as a tile. Resolve its fields or explicitly waive the visual before "
                    "migration.",
                    hint=(
                        "Generated-SQL validation evidence sha256: "
                        f"{generated_evidence['sha256']}"
                        if generated_evidence
                        else None
                    ),
                )
            )
        return None, notes
    native_id = str(raw_element_id)
    return TileIR(
        native_source_id=native_id,
        source_locator=f"element:{native_id}" if native_id else None,
        kind="query",
        title=element.get("name") or label,
        query=QueryIR(topic=topic, fields=fields),
        chart_type=chart,
        vis_config=_element_evidence(element, viz_type),
        layout=grid_naive_stack(index),
    ), notes


def translate_sigma_page(
    page: dict,
    *,
    column_ref: dict[str, tuple[str, str]] | None = None,
    source_url: str | None = None,
    workbook_id: str | None = None,
    controls: list[dict] | None = None,
    workbook_grants: list[dict] | None = None,
    workbook_schedules: list[dict] | None = None,
) -> DashboardIR:
    column_ref = column_ref or {}
    tiles: list[TileIR] = []
    notes: list[UntranslatableNote] = []
    page_controls: list[dict] = []
    for element in page.get("elements", []) or []:
        feature = _feature_kind(element)
        if feature == "control":
            page_controls.append(dict(element))
            continue
        if feature is not None:
            element_id = _row_id(element, "elementId", "id")
            notes.append(
                UntranslatableNote(
                    object=f"{feature} «{element.get('name') or element_id or 'element'}»",
                    reason=f"Sigma {feature} behavior cannot be inferred or deployed safely; "
                    "provide a reviewed target behavior or explicitly waive it.",
                    severity="blocker",
                )
            )
            continue
        tile, tile_notes = _element_to_tile(element, column_ref, len(tiles))
        if tile:
            tiles.append(tile)
        notes.extend(tile_notes)

    raw_page_id = page.get("pageId") or page.get("id")
    page_id = str(raw_page_id) if raw_page_id is not None else None
    controls_by_key: dict[str, dict] = {}
    for raw_control in [*(controls or []), *page_controls]:
        control = dict(raw_control)
        control_page_id = _row_id(control, "pageId")
        if control_page_id is not None and page_id is not None and control_page_id != page_id:
            continue
        key = _row_id(control, "controlId", "elementId", "id") or str(
            control.get("name") or len(controls_by_key)
        )
        controls_by_key[key] = {**controls_by_key.get(key, {}), **control}
    filters: list[FilterIR] = []
    for control in controls_by_key.values():
        filter_item, control_note = _control_to_filter(control, column_ref)
        if filter_item is not None:
            filters.append(filter_item)
        if control_note is not None:
            notes.append(control_note)

    notes.append(
        UntranslatableNote(
            object=f"page layout {page.get('name') or page_id or 'page'}",
            reason="Sigma's acquired workbook evidence has no authoritative grid coordinates; "
            "tiles use an explicit full-width naive stack pending human layout review.",
            severity="info",
        )
    )
    if workbook_grants:
        notes.append(
            UntranslatableNote(
                object=f"workbook permissions {workbook_id or page.get('name') or 'workbook'}",
                reason=f"{len(workbook_grants)} Sigma grant(s) require governed Omni permission mapping.",
                severity="blocker",
            )
        )
    if workbook_schedules:
        notes.append(
            UntranslatableNote(
                object=f"workbook schedules {workbook_id or page.get('name') or 'workbook'}",
                reason=f"{len(workbook_schedules)} Sigma schedule(s) require a delivery or upstream "
                "orchestration decision.",
                severity="blocker",
            )
        )
    aliases = [item for item in [workbook_id, page_id] if item]
    return DashboardIR(
        native_source_id=page_id,
        selection_aliases=list(dict.fromkeys(aliases)),
        source_locator=f"workbook:{workbook_id}/page:{page_id or page.get('name')}"
        if workbook_id
        else None,
        name=page.get("name") or "page",
        tiles=tiles,
        filters=filters,
        source_url=source_url,
        untranslatable=notes,
    )

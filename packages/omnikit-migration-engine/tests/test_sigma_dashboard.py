"""Sigma workbook page ``elements[]`` -> ``DashboardIR``.

These fictional fixtures follow Sigma's documented element shape. Unsupported evidence is kept as
an explicit blocker, never silently converted to a table or guessed into a filter.
"""

from __future__ import annotations

import hashlib
import json

from omni_migrator.extractors.sigma.dashboard import translate_sigma_page
from omni_migrator.ir.schema import GridRect


def _column_ref():
    return {
        "col-price": ("order_items", "sale_price"),
        "col-status": ("order_items", "status"),
        "col-brand": ("inventory_items", "brand"),
    }


def test_element_becomes_query_tile_with_resolved_fields():
    page = {
        "name": "Overview",
        "elements": [
            {
                "elementId": "e1",
                "name": "Revenue Trend",
                "vizualizationType": "Line",
                "columns": [{"columnId": "col-price"}],
            },
        ],
    }
    dash = translate_sigma_page(page, column_ref=_column_ref())
    (tile,) = dash.tiles
    assert tile.title == "Revenue Trend"
    assert tile.chart_type == "line"
    assert tile.query.topic == "order_items"
    assert tile.query.fields == ["sale_price"]
    assert tile.native_source_id == "e1"
    assert tile.source_locator == "element:e1"


def test_documented_page_and_element_ids_are_preserved_for_provenance():
    page = {
        "pageId": "page-1",
        "name": "Overview",
        "elements": [
            {
                "elementId": "element-1",
                "name": "Revenue",
                "vizualizationType": "Bar",
                "columns": [{"columnId": "col-price"}],
            },
        ],
    }

    dash = translate_sigma_page(page, column_ref=_column_ref(), workbook_id="workbook-1")

    assert dash.native_source_id == "page-1"
    assert dash.selection_aliases == ["workbook-1", "page-1"]
    assert dash.source_locator == "workbook:workbook-1/page:page-1"
    assert dash.tiles[0].native_source_id == "element-1"
    assert dash.tiles[0].source_locator == "element:element-1"


def test_tiles_stack_top_to_bottom_full_width():
    """No layout API exists at all (plan §6.4) — every tile is a naive full-width stack, not a
    guessed grid mapping."""
    page = {
        "name": "Overview",
        "elements": [
            {
                "elementId": "e1",
                "name": "A",
                "vizualizationType": "Bar",
                "columns": [{"columnId": "col-price"}],
            },
            {
                "elementId": "e2",
                "name": "B",
                "vizualizationType": "Bar",
                "columns": [{"columnId": "col-status"}],
            },
        ],
    }
    dash = translate_sigma_page(page, column_ref=_column_ref())
    assert dash.tiles[0].layout == GridRect(x=0, y=0, w=12, h=6)
    assert dash.tiles[1].layout == GridRect(x=0, y=6, w=12, h=6)


def test_pie_donut_combined_type_maps_to_pie():
    """Sigma's docs list this chart type combined as "Pie/Donut" — confirm the `/` doesn't break
    the normalized lookup key."""
    page = {
        "name": "P",
        "elements": [
            {
                "elementId": "e1",
                "name": "Status Split",
                "vizualizationType": "Pie/Donut",
                "columns": [{"columnId": "col-status"}],
            },
        ],
    }
    dash = translate_sigma_page(page, column_ref=_column_ref())
    (tile,) = dash.tiles
    assert tile.chart_type == "pie"
    assert all("layout" in note.object for note in dash.untranslatable)


def test_unmapped_visualization_type_is_blocking_and_not_emitted():
    page = {
        "name": "P",
        "elements": [
            {
                "elementId": "e1",
                "name": "Weird",
                "vizualizationType": "Sunburst",
                "columns": [{"columnId": "col-status"}],
            },
        ],
    }
    dash = translate_sigma_page(page, column_ref=_column_ref())
    assert dash.tiles == []
    note = next(note for note in dash.untranslatable if note.hint == "Sunburst")
    assert note.severity == "blocker"
    assert "did not substitute a table" in note.reason


def test_visual_without_native_element_id_is_blocking_and_not_emitted():
    page = {
        "name": "P",
        "elements": [
            {
                "name": "Identity missing",
                "vizualizationType": "Bar",
                "columns": [{"columnId": "col-price"}],
            }
        ],
    }

    dash = translate_sigma_page(page, column_ref=_column_ref())

    assert dash.tiles == []
    note = next(note for note in dash.untranslatable if "Identity missing" in note.object)
    assert note.severity == "blocker"
    assert "elementId" in note.reason


def test_element_with_query_error_is_skipped_not_emitted():
    page = {
        "name": "P",
        "elements": [
            {"elementId": "e1", "name": "Broken", "error": "query timeout", "columns": []}
        ],
    }
    dash = translate_sigma_page(page, column_ref=_column_ref())
    assert dash.tiles == []
    note = next(note for note in dash.untranslatable if "query timeout" in note.reason)
    assert note.severity == "blocker"


def test_unresolved_column_reference_is_noted_not_guessed():
    page = {
        "name": "P",
        "elements": [
            {
                "elementId": "e1",
                "name": "Ghost",
                "vizualizationType": "Bar",
                "columns": [{"columnId": "col-unknown"}],
            },
        ],
    }
    dash = translate_sigma_page(page, column_ref=_column_ref())
    assert dash.tiles == []
    note = next(note for note in dash.untranslatable if "Unresolved column reference" in note.reason)
    assert note.severity == "blocker"


def test_cross_table_columns_on_one_element_block_the_partial_tile():
    """A cross-table query is not reduced to whichever source field happened to resolve first."""
    page = {
        "name": "P",
        "elements": [
            {
                "elementId": "e1",
                "name": "Mixed",
                "vizualizationType": "Table",
                "columns": [{"columnId": "col-price"}, {"columnId": "col-brand"}],
            },
        ],
    }
    dash = translate_sigma_page(page, column_ref=_column_ref())
    assert dash.tiles == []
    note = next(note for note in dash.untranslatable if "different table" in note.reason)
    assert note.severity == "blocker"


def test_generated_sql_is_fingerprinted_as_validation_evidence_not_copied():
    generated = {"sql": "select sum(amount) from private.orders", "elementId": "e1"}
    page = {
        "pageId": "p1",
        "name": "Overview",
        "elements": [
            {
                "elementId": "e1",
                "name": "Revenue",
                "type": "visualization",
                "vizualizationType": "Table",
                "columns": [
                    {
                        "columnId": "col-price",
                        "label": "Revenue",
                        "formula": "Sum([Order Items/Sale Price])",
                    }
                ],
                "generatedSql": generated,
            }
        ],
    }

    dash = translate_sigma_page(page, column_ref=_column_ref())
    evidence = dash.tiles[0].vis_config["sigma"]

    expected = hashlib.sha256(
        json.dumps(generated, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    assert evidence["generated_sql"] == {
        "sha256": expected,
        "role": "validation_evidence_only",
    }
    assert "private.orders" not in json.dumps(dash.model_dump())
    assert evidence["column_formulas"][0]["formula"] == "Sum([Order Items/Sale Price])"


def test_lineage_is_preserved_as_fingerprinted_source_ids():
    lineage = [{"elementId": "e1", "sourceIds": ["model-source-1"]}]
    page = {
        "name": "Overview",
        "elements": [
            {
                "elementId": "e1",
                "name": "Revenue",
                "type": "visualization",
                "vizualizationType": "Table",
                "columns": [{"columnId": "col-price"}],
                "lineage": lineage,
            }
        ],
    }

    dash = translate_sigma_page(page, column_ref=_column_ref())
    evidence = dash.tiles[0].vis_config["sigma"]["lineage"]

    assert evidence["source_ids"] == ["e1", "model-source-1"]
    assert len(evidence["sha256"]) == 64
    assert evidence["role"] == "validation_evidence_only"


def test_documented_control_shape_remains_blocking_without_authoritative_binding():
    page = {
        "pageId": "p1",
        "name": "Overview",
        "elements": [
            {
                "elementId": "e1",
                "name": "Revenue",
                "vizualizationType": "Table",
                "columns": [{"columnId": "col-price"}],
            }
        ],
    }
    controls = [
        {
            "controlId": "control-region",
            "name": "Status",
            "pageId": "p1",
            "columnId": "col-status",
            "defaultValue": "Complete",
            "valueType": "text",
        }
    ]

    dash = translate_sigma_page(page, column_ref=_column_ref(), controls=controls)

    assert dash.filters == []
    note = next(note for note in dash.untranslatable if "control" in note.object)
    assert note.severity == "blocker"
    assert "authoritative field binding" in note.reason
    assert "col-status" in (note.hint or "")


def test_ambiguous_control_is_blocking_and_not_guessed():
    page = {"pageId": "p1", "name": "Overview", "elements": []}
    controls = [
        {
            "controlId": "control-mixed",
            "name": "Mixed filter",
            "columns": [{"columnId": "col-status"}, {"columnId": "col-brand"}],
        }
    ]

    dash = translate_sigma_page(page, column_ref=_column_ref(), controls=controls)

    assert dash.filters == []
    note = next(note for note in dash.untranslatable if "control" in note.object)
    assert note.severity == "blocker"
    assert "authoritative field binding" in note.reason


def test_input_table_action_and_writeback_are_not_emitted_as_tiles():
    page = {
        "name": "Operations",
        "elements": [
            {"elementId": "input1", "name": "Forecast Entry", "type": "input_table"},
            {"elementId": "action1", "name": "Approve", "type": "button"},
            {"elementId": "write1", "name": "Update", "writeback": {"enabled": True}},
        ],
    }

    dash = translate_sigma_page(page, column_ref=_column_ref())

    assert dash.tiles == []
    blockers = [note for note in dash.untranslatable if note.severity == "blocker"]
    assert {note.object.split(" ")[0] for note in blockers} == {"input", "action", "writeback"}


def test_layout_permissions_and_schedules_remain_explicit():
    page = {"pageId": "p1", "name": "Overview", "elements": []}

    dash = translate_sigma_page(
        page,
        workbook_id="wb1",
        workbook_grants=[{"grantId": "g1"}],
        workbook_schedules=[{"scheduleId": "s1"}],
    )

    assert any(note.object.startswith("page layout") for note in dash.untranslatable)
    assert any(note.object.startswith("workbook permissions") for note in dash.untranslatable)
    assert any(note.object.startswith("workbook schedules") for note in dash.untranslatable)

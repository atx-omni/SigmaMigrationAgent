"""Synthetic pilot scopes retain the original denominator and fail closed."""
from copy import deepcopy
import json
from pathlib import Path

import pytest

from omni_migrator.prepush.scope import (
    SCOPE_KEY, chart_inventory, create_scope, original_source_hash, validate_scope,
)

ROOT = Path(__file__).resolve().parents[3]
WORKBOOK = "fictional-overview"
PREFIX = "data-model:fictional-retail/element:orders/"


@pytest.fixture
def source():
    return json.loads((ROOT / "examples/retail-supported.json").read_text())


def refresh(source):
    source["prepush_context"]["source_sha256"] = original_source_hash(source)


def test_select_chart_retains_source_hidden_dependencies_and_shared_controls(source):
    before = deepcopy(source)
    scoped = create_scope(source, workbook_id=WORKBOOK, chart_ids=["revenue-table"])
    assert source == before
    assert {key: value for key, value in scoped.items() if key != SCOPE_KEY} == before
    scope = validate_scope(scoped)
    assert scope["issues"] == []
    assert scope["selected_chart_ids"] == ["revenue-table"]
    assert scope["excluded_chart_ids"] == ["revenue-chart"]
    assert PREFIX + "column:status" in scope["dependency_field_locators"]
    assert PREFIX + "column:amount" in scope["dependency_field_locators"]
    assert scope["required_control_ids"] == ["region-filter"]
    assert scope["shared_controls"] == [{"control_id": "region-filter",
        "target_element_ids": ["revenue-chart", "revenue-table"],
        "selected_target_ids": ["revenue-table"], "excluded_target_ids": ["revenue-chart"]}]
    assert "/workbooks/0/pages/0/elements/0" in scope["excluded_source_paths"]
    assert "/workbooks/0/pages/0" not in scope["excluded_source_paths"]
    assert scope["target_write_authority"] is False


def test_page_selection_and_repeated_scope_are_deterministic(source):
    first = create_scope(source, workbook_id=WORKBOOK, page_ids=["overview"])
    assert first == create_scope(first, workbook_id=WORKBOOK, page_ids=["overview"])
    scope = validate_scope(first)
    assert scope["selected_chart_ids"] == ["revenue-chart", "revenue-table"]
    assert scope["excluded_chart_ids"] == []


@pytest.mark.parametrize("kwargs", [
    {}, {"chart_ids": ["missing"]}, {"page_ids": ["missing"]},
    {"chart_ids": ["revenue-chart", "revenue-chart"]}, {"chart_ids": "revenue-chart"},
])
def test_selection_is_explicit_exact_and_unambiguous(source, kwargs):
    with pytest.raises(ValueError):
        create_scope(source, workbook_id=WORKBOOK, **kwargs)


@pytest.mark.parametrize("change", ["source", "context", "closure", "exclusion"])
def test_scope_rederivation_rejects_stale_or_forged_metadata(source, change):
    scoped = create_scope(source, workbook_id=WORKBOOK, chart_ids=["revenue-chart"])
    if change == "source":
        scoped["workbooks"][0]["name"] = "Changed source"
    elif change == "context":
        scoped["prepush_context"]["evidence_ref"] = "different-observation"
    elif change == "closure":
        scoped[SCOPE_KEY]["dependency_field_locators"] = []
    else:
        scoped[SCOPE_KEY]["excluded_source_paths"].append("/dataModels/0")
    with pytest.raises(ValueError, match="stale or modified"):
        validate_scope(scoped)


def test_upstream_workbook_element_retained_as_dependency(source):
    chart = source["workbooks"][0]["pages"][0]["elements"][0]
    chart["sourceElementId"] = "revenue-table"
    refresh(source)
    scope = validate_scope(create_scope(source, workbook_id=WORKBOOK, chart_ids=["revenue-chart"]))
    assert scope["issues"] == []
    assert scope["excluded_chart_ids"] == []
    assert "workbook:fictional-overview/element:revenue-table" in scope["dependency_element_locators"]
    assert PREFIX + "column:status" in scope["dependency_field_locators"]


@pytest.mark.parametrize("lineage, expected", [
    ([{"unrecognized": "shape"}], "scope_unknown_lineage"),
    ([{"sourceElementId": "missing"}], "scope_ambiguous_or_missing_dependency"),
    ([{"sourceElementId": "revenue-chart"}], "scope_dependency_cycle"),
])
def test_unknown_missing_and_cyclic_lineage_are_blockers(source, lineage, expected):
    source["workbooks"][0]["pages"][0]["elements"][0]["lineage"] = lineage
    refresh(source)
    scope = validate_scope(create_scope(source, workbook_id=WORKBOOK, chart_ids=["revenue-chart"]))
    assert expected in {row["code"] for row in scope["issues"]}


def test_unqualified_duplicate_upstream_identity_is_not_guessed(source):
    page = source["workbooks"][0]["pages"][0]
    page["elements"].append({"elementId": "orders", "type": "table"})
    page["elements"][0]["sourceElementId"] = "orders"
    refresh(source)
    scope = validate_scope(create_scope(source, workbook_id=WORKBOOK, chart_ids=["revenue-chart"]))
    assert "scope_ambiguous_or_missing_dependency" in {row["code"] for row in scope["issues"]}


@pytest.mark.parametrize("owner", ["workbooks", "dataModels"])
@pytest.mark.parametrize("lineage", [[{"sourceElementId": "orders"}],
                                    [{"elementId": "absent-owner", "sourceElementId": "orders"}],
                                    {"nodes": []}])
def test_ownerless_or_unknown_top_level_lineage_cannot_be_ignored(source, owner, lineage):
    source[owner][0]["lineage"] = lineage
    refresh(source)
    scope = validate_scope(create_scope(source, workbook_id=WORKBOOK, chart_ids=["revenue-chart"]))
    blockers = [row for row in scope["issues"] if row["code"] == "scope_unknown_lineage"]
    assert blockers
    assert all(row["path"].startswith(f"/{owner}/0/lineage") for row in blockers)


def test_unknown_control_scope_is_retained_and_blocks(source):
    del source["prepush_context"]["controls"]["region-filter"]
    scope = validate_scope(create_scope(source, workbook_id=WORKBOOK, chart_ids=["revenue-chart"]))
    assert scope["required_control_ids"] == ["region-filter"]
    assert "scope_unknown_control_targets" in {row["code"] for row in scope["issues"]}
    assert "/workbooks/0/controls/0" not in scope["excluded_source_paths"]


def test_known_unrelated_control_and_nested_excluded_objects_are_accounted(source):
    source["workbooks"][0]["pages"][0]["elements"][1]["actions"] = [{"id": "unused-action"}]
    source["prepush_context"]["controls"]["region-filter"]["target_element_ids"] = ["revenue-table"]
    refresh(source)
    scope = validate_scope(create_scope(source, workbook_id=WORKBOOK, chart_ids=["revenue-chart"]))
    assert scope["excluded_control_ids"] == ["region-filter"]
    assert "/workbooks/0/pages/0/elements/1/actions/0" in scope["excluded_source_paths"]
    assert "/workbooks/0/controls/0" in scope["excluded_source_paths"]


def test_page_selection_includes_unsupported_visuals_instead_of_hiding_them(source):
    source["workbooks"][0]["pages"][0]["elements"].append({"elementId": "unsupported", "type": "plugin"})
    refresh(source)
    scope = validate_scope(create_scope(source, workbook_id=WORKBOOK, page_ids=["overview"]))
    assert "unsupported" in scope["selected_chart_ids"]
    assert "scope_missing_field_context" in {row["code"] for row in scope["issues"]}
    assert len(chart_inventory(source, workbook_id=WORKBOOK)) == 3

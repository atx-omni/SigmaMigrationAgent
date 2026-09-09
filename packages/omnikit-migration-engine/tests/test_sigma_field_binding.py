"""Independent source-bound regressions: bad references must not become usable fields."""

from __future__ import annotations

import json

import pytest
import yaml

from omni_migrator.deterministic.model_emitter import emit_view
from omni_migrator.extractors.sigma.extractor import _build_bundle
from omni_migrator.ir.schema import MigrationBundle


def snapshot(columns=None, *, nested_metrics=None, standalone_metrics=None):
    return {"dataModels": [{
        "dataModelId": "model-binding",
        "spec": {
            "pages": [{"elements": [{
                "id": "element-orders", "kind": "table", "name": "Order Items",
                "aliases": ["Sales"],
                "source": {"kind": "warehouse-table", "path": ["SYNTHETIC", "PUBLIC", "ORDERS"]},
                "columns": columns if columns is not None else [
                    {"id": "amount-id", "name": "Line Amount", "label": "Revenue", "aliases": ["Sales Value"]},
                    {"id": "status-id", "name": "Status"},
                ],
                "metrics": nested_metrics or [],
            }]}],
            "metrics": standalone_metrics or [],
        },
    }]}


def compile_snapshot(data):
    bundle = _build_bundle(data)
    return bundle, {field.source_id: field for view in bundle.model.views for field in view.fields}


def assert_blocked(bundle, fields, source_id, reason):
    assert source_id not in fields
    requirements = [item for item in bundle.model.requirements if item.source_id == source_id]
    assert requirements, f"Missing unresolved-field accounting for {source_id}"
    assert any(item.config.get("blocking") and reason.lower() in item.reason.lower()
               for item in requirements)
    assert all(item.config.get("source_field_id") == source_id for item in requirements)


@pytest.mark.parametrize("reference", [
    "[amount-id]", "[Line Amount]", "[Revenue]", "[Sales Value]", "[Sales/Revenue]",
    "[element-orders/amount-id]", "[Order Items/Line Amount]", "[ORDERS/Revenue]",
])
def test_captured_ids_labels_and_explicit_aliases_bind(reference):
    bundle, fields = compile_snapshot(snapshot(nested_metrics=[
        {"id": "total-id", "name": "Total", "formula": f"Sum({reference})"},
    ]))
    assert fields["total-id"].sql == "line_amount"
    assert fields["total-id"].aggregate == "sum"
    assert not [item for item in bundle.model.requirements if item.source_id == "total-id"]


@pytest.mark.parametrize("formula,reference", [
    ("Sum([Does Not Exist])", "[Does Not Exist]"),
    ('SumIf([Revenue], [Unknown Filter] = "ok")', "[Unknown Filter]"),
    ('CountIf([Unknown Filter] = "ok")', "[Unknown Filter]"),
    ("Sum([line_amount])", "[line_amount]"),
    ("Sum([Missing Table/Revenue])", "[Missing Table/Revenue]"),
])
@pytest.mark.parametrize("representation", ["column", "nested", "standalone"])
def test_unknown_operands_and_conditions_fail_closed(formula, reference, representation):
    item = {"id": "bad-id", "name": "Bad", "formula": formula}
    data = snapshot()
    element = data["dataModels"][0]["spec"]["pages"][0]["elements"][0]
    if representation == "column":
        element["columns"].append(item)
    elif representation == "nested":
        element["metrics"].append(item)
    else:
        data["dataModels"][0]["spec"]["metrics"].append({**item, "elementId": "element-orders"})
    bundle, fields = compile_snapshot(data)
    assert_blocked(bundle, fields, "bad-id", "unknown")
    requirement = next(item for item in bundle.model.requirements if item.source_id == "bad-id")
    assert requirement.config["formula"] == formula
    assert any(issue["reference"] == reference for issue in requirement.config["binding_issues"])
    assert "Bad" not in emit_view(bundle.model.views[0]).split("measures:")[-1].split("#")[0]


def test_quoted_bracket_text_is_a_literal_not_a_reference():
    _, fields = compile_snapshot(snapshot(nested_metrics=[{
        "id": "quoted-id", "name": "Quoted", "formula": 'SumIf([Revenue], [Status] = "[Does Not Exist]")',
    }]))
    assert fields["quoted-id"].filters == {"status": {"is": "[Does Not Exist]"}}


def test_duplicate_labels_block_labels_but_stable_ids_keep_distinct_binding():
    bundle, fields = compile_snapshot(snapshot([
        {"id": "left-id", "name": "Value"}, {"id": "right-id", "name": "Value"},
    ], nested_metrics=[
        {"id": "ambiguous-id", "name": "Ambiguous", "formula": "Sum([Value])"},
        {"id": "exact-id", "name": "Exact", "formula": "Sum([right-id])"},
    ]))
    assert_blocked(bundle, fields, "ambiguous-id", "ambiguous")
    assert fields["exact-id"].sql == "${" + fields["right-id"].name + "}"
    assert fields["left-id"].name != fields["right-id"].name


def test_alias_dependencies_compile_in_source_order_independent_way():
    data = snapshot([
        {"id": "total-id", "name": "Total", "formula": "Sum([Alias Two])"},
        {"id": "alias-two", "name": "Alias Two", "formula": "[Alias One]"},
        {"id": "alias-one", "name": "Alias One", "formula": "[Amount]"},
        {"id": "amount-id", "name": "Amount"},
    ])
    _, fields = compile_snapshot(data)
    assert fields["alias-one"].sql == "${amount}"
    assert fields["alias-two"].sql == "${alias_one}"
    assert fields["total-id"].sql == "${alias_two}"
    data["dataModels"][0]["spec"]["pages"][0]["elements"][0]["columns"].reverse()
    _, reversed_fields = compile_snapshot(data)
    assert {key: value.sql for key, value in fields.items()} == {
        key: value.sql for key, value in reversed_fields.items()
    }


def test_cycles_and_their_consumers_are_unresolved():
    bundle, fields = compile_snapshot(snapshot([
        {"id": "a-id", "name": "A", "formula": "[B]"},
        {"id": "b-id", "name": "B", "formula": "[A]"},
        {"id": "consumer-id", "name": "Consumer", "formula": "Sum([A])"},
    ]))
    for source_id in ("a-id", "b-id", "consumer-id"):
        assert_blocked(bundle, fields, source_id, "cycle")


def test_unsupported_calculated_dependency_blocks_aggregate_consumers():
    bundle, fields = compile_snapshot(snapshot([
        {"id": "amount-id", "name": "Amount"},
        {"id": "row-id", "name": "Computed", "formula": "[Amount] * 2"},
    ], nested_metrics=[{"id": "total-id", "name": "Total", "formula": "Sum([Computed])"}]))
    assert_blocked(bundle, fields, "row-id", "syntax")
    assert_blocked(bundle, fields, "total-id", "unresolved dependency")


def test_metric_cycles_and_measure_dependencies_are_not_reaggregated():
    bundle, fields = compile_snapshot(snapshot(nested_metrics=[
        {"id": "a-id", "name": "A", "formula": "Sum([B])"},
        {"id": "b-id", "name": "B", "formula": "Sum([A])"},
        {"id": "total-id", "name": "Total", "formula": "Sum([Revenue])"},
        {"id": "reaggregate-id", "name": "Reaggregate", "formula": "Sum([Total])"},
    ]))
    assert_blocked(bundle, fields, "a-id", "cycle")
    assert_blocked(bundle, fields, "b-id", "cycle")
    assert_blocked(bundle, fields, "reaggregate-id", "aggregate/evaluation")


def test_duplicate_ids_and_absent_metric_element_are_visible_not_silently_emitted():
    bundle, fields = compile_snapshot(snapshot([
        {"id": "same-id", "name": "Left"}, {"id": "same-id", "name": "Right"},
    ], standalone_metrics=[{"id": "orphan-id", "name": "Orphan", "formula": "Count()"}]))
    assert_blocked(bundle, fields, "same-id", "duplicate")
    assert_blocked(bundle, fields, "orphan-id", "source element")


@pytest.mark.parametrize("visibility", [True, False, "absent"])
@pytest.mark.parametrize("kind", ["dimension", "calculated", "nested", "standalone"])
def test_visibility_is_preserved_through_extraction_roundtrip_and_yaml(visibility, kind):
    row = {"id": "visibility-id", "name": "Visibility", "description": "Keep this description"}
    if visibility != "absent":
        row["hidden"] = visibility
    data = snapshot()
    element = data["dataModels"][0]["spec"]["pages"][0]["elements"][0]
    if kind == "dimension":
        element["columns"].append(row)
    elif kind == "calculated":
        element["columns"].append({**row, "formula": "Sum([Revenue])"})
    elif kind == "nested":
        element["metrics"].append({**row, "formula": "Sum([Revenue])"})
    else:
        data["dataModels"][0]["spec"]["metrics"].append({
            **row, "elementId": "element-orders", "formula": "Sum([Revenue])",
        })
    bundle, fields = compile_snapshot(data)
    field = fields["visibility-id"]
    assert field.hidden is (False if visibility == "absent" else visibility)
    assert field.description == "Keep this description"
    reloaded = MigrationBundle.model_validate_json(bundle.model_dump_json(exclude_unset=True))
    payload = yaml.safe_load(emit_view(reloaded.model.views[0]))
    definition = payload["dimensions" if kind == "dimension" else "measures"][field.name]
    if visibility == "absent":
        assert "hidden" not in definition
    else:
        assert definition["hidden"] is visibility
    assert json.loads(reloaded.model_dump_json())["model"]["views"][0]["fields"]


@pytest.mark.parametrize("visibility", ["false", "true", 0, 1, None, [], {}])
def test_malformed_visibility_blocks_field_and_dependent_metric(visibility):
    bundle, fields = compile_snapshot(snapshot([
        {"id": "bad-id", "name": "Amount", "hidden": visibility},
    ], nested_metrics=[{"id": "consumer-id", "name": "Consumer", "formula": "Sum([Amount])"}]))
    assert_blocked(bundle, fields, "bad-id", "visibility")
    assert_blocked(bundle, fields, "consumer-id", "unresolved dependency")


def test_warehouse_qualified_passthrough_needs_captured_self_binding():
    bundle, fields = compile_snapshot(snapshot([
        {"id": "amount-id", "name": "Line Amount", "formula": "[ORDERS/LINE_AMOUNT]"},
        {"id": "missing-id", "name": "Missing", "formula": "[ORDERS/UNKNOWN_COLUMN]"},
    ]))
    assert fields["amount-id"].sql == "line_amount"
    assert_blocked(bundle, fields, "missing-id", "unknown")


def test_conflicting_or_duplicate_metric_ids_are_not_silently_first_wins():
    bundle, fields = compile_snapshot(snapshot(nested_metrics=[
        {"id": "duplicate-id", "name": "First", "formula": "Sum([Revenue])"},
        {"id": "duplicate-id", "name": "Second", "formula": "Count()"},
    ]))
    assert_blocked(bundle, fields, "duplicate-id", "duplicate")


def test_identical_legacy_copy_is_deduplicated_but_conflicting_copy_is_blocked():
    metric = {"id": "total-id", "name": "Total", "formula": "Sum([Revenue])"}
    data = snapshot(nested_metrics=[metric], standalone_metrics=[{
        **metric, "elementId": "element-orders",
    }])
    _, fields = compile_snapshot(data)
    assert fields["total-id"].aggregate == "sum"
    data["dataModels"][0]["spec"]["metrics"][0]["formula"] = "Count()"
    bundle, fields = compile_snapshot(data)
    assert_blocked(bundle, fields, "total-id", "duplicate")


@pytest.mark.parametrize("standalone", [False, True])
def test_malformed_metric_visibility_is_not_coerced(standalone):
    metric = {"id": "bad-id", "name": "Bad", "formula": "Count()", "hidden": "false"}
    data = snapshot(
        nested_metrics=[] if standalone else [metric],
        standalone_metrics=[{**metric, "elementId": "element-orders"}] if standalone else [],
    )
    bundle, fields = compile_snapshot(data)
    assert_blocked(bundle, fields, "bad-id", "visibility")


def test_table_alias_ambiguity_and_known_cross_table_refs_stay_blocked():
    data = snapshot(nested_metrics=[
        {"id": "ambiguous-id", "name": "Ambiguous", "formula": "Sum([Sales/Revenue])"},
        {"id": "foreign-id", "name": "Foreign", "formula": "Sum([element-other/Amount])"},
    ])
    data["dataModels"][0]["spec"]["pages"][0]["elements"].append({
        "id": "element-other", "name": "Other", "kind": "table", "aliases": ["Sales"],
        "source": {"path": ["SYNTHETIC", "PUBLIC", "OTHER"]},
        "columns": [{"id": "other-id", "name": "Amount"}],
    })
    bundle, fields = compile_snapshot(data)
    assert_blocked(bundle, fields, "ambiguous-id", "ambiguous table")
    assert_blocked(bundle, fields, "foreign-id", "cross-table")

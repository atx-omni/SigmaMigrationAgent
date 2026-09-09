"""Actual offline compiler outputs, not phase-name or self-reported-success tests."""

from __future__ import annotations

import json
import re
import sqlite3
from copy import deepcopy
from pathlib import Path

import pytest
import yaml

import omni_migrator.prepush.build as compiler


ROOT = Path(__file__).resolve().parents[3]
DIRECT = "omni_semantic_reconstruction"
MODELED = "warehouse_first_refactor"


@pytest.fixture
def inputs():
    return (json.loads((ROOT / "examples/retail-supported.json").read_text()),
            json.loads((ROOT / "examples/target.json").read_text()))


def _refresh(snapshot):
    snapshot["prepush_context"]["source_sha256"] = compiler.source_context_hash(snapshot)


def _database():
    db = sqlite3.connect(":memory:")
    db.execute("ATTACH DATABASE ':memory:' AS analytics")
    db.execute("CREATE TABLE analytics.orders (region TEXT, amount REAL, status TEXT)")
    db.executemany("INSERT INTO analytics.orders VALUES (?, ?, ?)", [
        ("East", 100, "complete"), ("East", 50, "pending"),
        ("East", None, "complete"), ("East", 100, "complete"),
        ("West", 70, "complete"), (None, 20, "complete"),
    ])
    return db


@pytest.mark.parametrize("route", [DIRECT, MODELED])
def test_real_files_and_independently_expected_default_query_results(inputs, route, monkeypatch):
    snapshot, target = inputs
    untouched = deepcopy((snapshot, target))

    def no_network(*args, **kwargs):
        raise AssertionError("The local compiler must never acquire live source/target state")

    monkeypatch.setattr("omni_migrator.extractors.sigma.api.SigmaApi.__init__", no_network)
    result = compiler.build(snapshot, route, target)
    assert (snapshot, target) == untouched
    assert result == compiler.build(snapshot, route, target)
    assert result["target_write_authority"] is False
    assert result["production_ready"] is False
    assert all(row["status"] == "implemented" for row in result["dispositions"])
    assert {row["source_kind"] for row in result["dispositions"]} == {
        "connections", "dataModels", "workbooks", "pages", "elements", "columns", "metrics", "controls"
    }
    assert len(result["dispositions"]) == 15
    files = result["files"]
    assert bool([path for path in files if path.startswith("dbt/")]) is (route == MODELED)
    view = yaml.safe_load(files["omni/model/analytics/orders.view"])
    assert view["dimensions"]["region"]["hidden"] is False
    assert view["dimensions"]["status"]["hidden"] is True
    assert "hidden" not in view["dimensions"]["amount"]
    assert view["measures"]["total_revenue"]["aggregate_type"] == "sum"
    assert view["measures"]["completed_revenue"]["filters"] == {"status": {"is": "complete"}}
    topic = yaml.safe_load(files["omni/model/orders.topic"])
    assert topic["base_view"] == "orders"

    # Independently authored rows/totals: duplicates contribute; nulls don't; defaults filter East.
    with _database() as db:
        if route == MODELED:
            model_sql = files["dbt/models/orders.sql"]
            select = re.sub(r"\A\{\{ config\([^\n]+\) \}\}\n", "", model_sql)
            assert select.startswith("SELECT")
            db.execute("CREATE TABLE analytics.sigma_orders AS " + select)
            assert db.execute("SELECT COUNT(*) FROM analytics.sigma_orders").fetchone() == (6,)
            singular = files["dbt/tests/orders_row_equivalence.sql"].replace(
                "{{ ref('orders') }}", "analytics.sigma_orders"
            )
            assert db.execute(singular).fetchall() == []
            db.execute("DELETE FROM analytics.sigma_orders WHERE rowid = 1")
            assert db.execute(singular).fetchall()  # The dbt test actually detects data loss.
            db.execute("INSERT INTO analytics.sigma_orders SELECT region, amount, status, region FROM analytics.orders WHERE rowid=1")
            assert any(item["kind"] == "warehouse_deployment" and item["status"] == "undeployed"
                       for item in result["dependencies"])
        assert db.execute(files["queries/1.sql"]).fetchall() == [("East", 250.0)]
        assert db.execute(files["queries/2.sql"]).fetchall() == [("East", 200.0)]


def test_document_contains_real_v2_queries_control_and_nonoverlapping_layout(inputs):
    result = compiler.build(inputs[0], DIRECT, inputs[1])
    create = json.loads(result["files"]["omni/document.create.json"])
    patch = json.loads(result["files"]["omni/document.patch.json"])
    assert patch == {key: value for key, value in create.items() if key != "modelId"}
    assert create["modelId"] == inputs[1]["model_id"]
    assert create["queryPresentations"]["order"] == ["1", "2"]
    query = create["queryPresentations"]["data"]["1"]
    assert query["query"]["fields"] == ["orders.display_region", "orders.total_revenue"]
    assert {"sorts", "filters", "pivots", "calculations", "column_totals", "row_totals",
            "fill_fields", "userEditedSQL"} <= set(query["query"])
    assert query["visConfig"]["visConfig"]["config"]["series"][0]["field"]["name"] == "orders.total_revenue"
    control = create["controls"]["data"]["control_1"]
    assert control["config"]["values"] == ["East"]
    assert control["map"] == {"1": "orders.region", "2": "orders.region"}
    assert create["containers"][0]["children"][0]["id"] == "control_1"
    layout = create["containers"][1]["container"]["children"]
    assert [item["metadata"]["attachedQueryKey"] for item in layout] == ["1", "2"]
    assert [item["gridPosition"]["x"] for item in layout] == [0, 12]
    assert "miniUuid" not in json.dumps(create)


@pytest.mark.parametrize("route", [DIRECT, MODELED])
def test_unsupported_formulas_security_actions_and_unknown_objects_stay_blocked(inputs, route):
    snapshot, target = inputs
    table = snapshot["dataModels"][0]["spec"]["pages"][0]["elements"][0]
    table["metrics"].append({"metricId": "cumulative", "name": "cumulative", "formula": "CumulativeSum([amount])"})
    workbook = snapshot["workbooks"][0]
    workbook["security"] = {"policy": "Restricted to the source tenant"}
    workbook["pages"][0]["elements"].append({"elementId": "writeback", "type": "input-table"})
    workbook["actions"] = [{"id": "refresh-action", "type": "custom-action"}]
    workbook["futureObjects"] = [{"id": "future-behavior", "meaning": "unimplemented"}]
    _refresh(snapshot)
    result = compiler.build(snapshot, route, target)
    by_id = {row["source_id"]: row for row in result["dispositions"]}
    for identity in ("cumulative", "writeback", "refresh-action", "future-behavior", "fictional-overview"):
        assert by_id[identity]["status"] == "blocked"
    assert by_id["path:/workbooks/0/security"]["status"] == "blocked"
    assert "cumulative" not in yaml.safe_load(result["files"]["omni/model/analytics/orders.view"])["measures"]


def test_missing_context_and_unresolved_fields_cannot_fabricate_content(inputs):
    snapshot, target = inputs
    snapshot.pop("prepush_context")
    result = compiler.build(snapshot, DIRECT, target)
    assert "omni/document.create.json" not in result["files"]
    assert any(row["source_kind"] == "workbooks" and row["status"] == "blocked"
               for row in result["dispositions"])


def test_stale_context_and_unknown_target_bindings_are_rejected(inputs):
    snapshot, target = inputs
    with pytest.raises(ValueError, match="Choose"):
        compiler.build(snapshot, "", target)
    snapshot["workbooks"][0]["name"] = "New revision"
    with pytest.raises(ValueError, match="stale"):
        compiler.build(snapshot, DIRECT, target)
    _refresh(snapshot)
    target["relations"]["data-model:fictional-retail/source:orders"]["columns"]["invented"] = "invented"
    with pytest.raises(ValueError, match="physical field identity"):
        compiler.build(snapshot, DIRECT, target)


def test_unknown_sql_source_is_not_silently_replaced_with_bound_table(inputs):
    snapshot, target = inputs
    snapshot["dataModels"][0]["spec"]["pages"][0]["elements"][0]["source"]["type"] = "custom-sql"
    _refresh(snapshot)
    result = compiler.build(snapshot, DIRECT, target)
    assert not result["files"]
    assert all(row["status"] == "blocked" for row in result["dispositions"])


def test_physical_column_remapping_applies_to_emitted_measures_not_only_probe_sql(inputs):
    snapshot, target = inputs
    target["relations"]["data-model:fictional-retail/source:orders"]["columns"]["amount"] = "sales_amount"
    result = compiler.build(snapshot, DIRECT, target)
    model = yaml.safe_load(result["files"]["omni/model/analytics/orders.view"])
    assert model["dimensions"]["amount"]["sql"] == '"sales_amount"'
    assert model["measures"]["total_revenue"]["sql"] == "${amount}"
    assert 'SUM("sales_amount")' in result["files"]["queries/1.sql"]


def test_control_hidden_flag_is_preserved_and_unknown_behavior_stays_blocked(inputs):
    snapshot, target = inputs
    snapshot["workbooks"][0]["controls"][0]["hidden"] = True
    _refresh(snapshot)
    result = compiler.build(snapshot, DIRECT, target)
    document = json.loads(result["files"]["omni/document.create.json"])
    assert document["controls"]["data"]["control_1"]["config"]["hidden"] is True
    assert all(item["containerType"] == "page" for item in document["containers"])
    assert "WHERE" in result["files"]["queries/1.sql"]
    snapshot["workbooks"][0]["controls"][0]["onChangeAction"] = "refresh-action"
    _refresh(snapshot)
    result = compiler.build(snapshot, DIRECT, target)
    assert next(row for row in result["dispositions"] if row["source_id"] == "region-filter")["status"] == "blocked"


@pytest.mark.parametrize("route", [DIRECT, MODELED])
def test_spec_warehouse_table_and_qualified_physical_columns_compile_with_actual_outputs(inputs, route):
    snapshot, target = inputs
    # Capture shape from the original source fixtures: id keys, source.kind and
    # warehouse-qualified physical references, not the reduced example's type.
    element = snapshot["dataModels"][0]["spec"]["pages"][0]["elements"][0]
    element["id"] = element.pop("elementId")
    element["source"] = {"connectionId": "fictional-source", "kind": "warehouse-table",
                         "path": ["SYNTHETIC", "PUBLIC", "ORDERS"]}
    for column in element["columns"]:
        column["id"] = column.pop("columnId")
        if column["id"] != "region-alias":
            column["formula"] = "[ORDERS/" + column["name"].upper() + "]"
    _refresh(snapshot)
    captured = compiler._build_bundle(snapshot).model.views[0].fields
    fields = {field.source_id: field for field in captured}
    assert {row["id"] for row in element["columns"]
            if compiler.physical_source_field(fields[row["id"]], row)} == {"region", "amount", "status"}
    # A wrong native identity cannot reuse a correctly bound field as evidence.
    assert not compiler.physical_source_field(fields["amount"], {"id": "different", "name": "amount"})
    result = compiler.build(snapshot, route, target)
    assert all(row["status"] == "implemented" for row in result["dispositions"])
    model = yaml.safe_load(result["files"]["omni/model/analytics/orders.view"])
    assert model["measures"]["total_revenue"]["sql"] == "${amount}"
    with _database() as db:
        if route == MODELED:
            select = re.sub(r"\A\{\{ config\([^\n]+\) \}\}\n", "",
                            result["files"]["dbt/models/orders.sql"])
            db.execute("CREATE TABLE analytics.sigma_orders AS " + select)
        assert db.execute(result["files"]["queries/1.sql"]).fetchall() == [("East", 250.0)]
        assert db.execute(result["files"]["queries/2.sql"]).fetchall() == [("East", 200.0)]


def test_warehouse_kind_cannot_override_custom_sql_discriminator(inputs):
    snapshot, target = inputs
    element = snapshot["dataModels"][0]["spec"]["pages"][0]["elements"][0]
    element["source"].update(kind="warehouse-table", type="custom-sql")
    _refresh(snapshot)
    result = compiler.build(snapshot, DIRECT, target)
    assert not result["files"]
    assert all(row["status"] == "blocked" for row in result["dispositions"])

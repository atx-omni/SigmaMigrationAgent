"""Synthetic Sigma acquisition-to-bridge regression coverage.

The fixture is fictional and intentionally exercises source-evidence retention. It is not a
canonical Sigma wire example or customer migration benchmark.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import httpx
import pytest

from omni_migrator.bridge import BridgeExtractRequest, execute_bridge_extract
from omni_migrator.deterministic.model_emitter import view_path
from omni_migrator.extractors.sigma.api import SigmaApi
from omni_migrator.extractors.sigma.semantic_routing import create_sigma_semantic_routing_decision

FIXTURE = Path(__file__).parent / "fixtures" / "sigma" / "representative_snapshot.json"
ROUTE_EXAMPLES = Path(__file__).resolve().parents[3] / "contracts" / "sigma" / "examples"

_DATA_MODEL_DETAILS = {
    "spec",
    "sources",
    "columns",
    "lineage",
    "grants",
    "materializationSchedules",
}
_WORKBOOK_DETAILS = {
    "sources",
    "pages",
    "elements",
    "columns",
    "controls",
    "queries",
    "lineage",
    "grants",
    "schedules",
    "materializationSchedules",
}


def _inventory(record: dict, details: set[str]) -> dict:
    return {key: value for key, value in record.items() if key not in details}


def _entries(rows: list[dict]) -> httpx.Response:
    return httpx.Response(200, json={"entries": rows, "total": len(rows)})


def _sigma_transport(payload: dict) -> httpx.MockTransport:
    data_models = {item["dataModelId"]: item for item in payload["dataModels"]}
    workbooks = {item["workbookId"]: item for item in payload["workbooks"]}
    grants = {
        item["dataModelId"]: item["grants"] for item in payload["dataModels"]
    } | {
        item["workbookId"]: item["grants"] for item in payload["workbooks"]
    }

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if request.method == "POST" and path == "/v2/auth/token":
            return httpx.Response(
                200,
                json={"access_token": "synthetic-token", "refresh_token": "synthetic-refresh"},
            )
        if request.method != "GET":
            return httpx.Response(405)
        if path == "/v2/connections":
            return _entries(payload["connections"])
        if path == "/v2/dataModels":
            return _entries(
                [_inventory(item, _DATA_MODEL_DETAILS) for item in payload["dataModels"]]
            )
        if path == "/v2/workbooks":
            return _entries(
                [_inventory(item, _WORKBOOK_DETAILS) for item in payload["workbooks"]]
            )
        if path == "/v2/grants":
            return _entries(grants.get(request.url.params.get("inodeId", ""), []))

        parts = path.strip("/").split("/")
        if len(parts) == 4 and parts[:2] == ["v2", "dataModels"]:
            model = data_models.get(parts[2])
            if model is None:
                return httpx.Response(404)
            detail = parts[3]
            if detail == "spec":
                return httpx.Response(200, json=model["spec"])
            key = {
                "sources": "sources",
                "columns": "columns",
                "lineage": "lineage",
                "materializationSchedules": "materializationSchedules",
            }.get(detail)
            return _entries(model[key]) if key else httpx.Response(404)

        if len(parts) >= 4 and parts[:2] == ["v2", "workbooks"]:
            workbook = workbooks.get(parts[2])
            if workbook is None:
                return httpx.Response(404)
            if len(parts) == 4 and parts[3] == "pages":
                return _entries(
                    [_inventory(page, {"elements"}) for page in workbook["pages"]]
                )
            if (
                len(parts) == 6
                and parts[3] == "pages"
                and parts[5] == "elements"
            ):
                page = next(
                    (item for item in workbook["pages"] if item["pageId"] == parts[4]),
                    None,
                )
                return _entries(page["elements"]) if page else httpx.Response(404)
            if len(parts) == 4:
                key = {
                    "sources": "sources",
                    "elements": "elements",
                    "columns": "columns",
                    "controls": "controls",
                    "queries": "queries",
                    "lineage": "lineage",
                    "schedules": "schedules",
                    "materialization-schedules": "materializationSchedules",
                }.get(parts[3])
                return _entries(workbook[key]) if key else httpx.Response(404)
        return httpx.Response(404, json={"path": path})

    return httpx.MockTransport(handler)


@pytest.fixture(scope="module")
def endpoint_payload() -> dict:
    return json.loads(FIXTURE.read_text())


@pytest.fixture(scope="module")
def acquired_snapshot(endpoint_payload: dict) -> dict:
    api = SigmaApi(
        base_url="https://api.example.invalid",
        client_id="synthetic-client",
        client_secret="synthetic-secret",
        transport=_sigma_transport(endpoint_payload),
    )
    try:
        return api.snapshot()
    finally:
        api.close()


def _bridge_result(snapshot: dict, scope: dict) -> object:
    request = BridgeExtractRequest.model_validate(
        {
            "request_id": "sigma-synthetic-end-to-end",
            "source": "sigma",
            "mode": "api",
            "connection": {
                "base_url": "https://api.example.invalid",
                "auth": {"snapshot": snapshot},
            },
            "scope": scope,
        }
    )
    return execute_bridge_extract(request)


def _review_text(bundle: object) -> str:
    notes = list(bundle.model.untranslatable)
    for view in bundle.model.views:
        notes.extend(view.untranslatable)
        for field in view.fields:
            notes.extend(field.untranslatable)
    for dashboard in bundle.dashboards:
        notes.extend(dashboard.untranslatable)
        for tile in dashboard.tiles:
            notes.extend(tile.untranslatable)
    text = [
        f"{note.object} {note.reason} {note.hint or ''}"
        for note in notes
    ]
    text.extend(
        f"{requirement.name} {requirement.support_outcome} {requirement.reason}"
        for requirement in bundle.model.requirements
    )
    return "\n".join(text).lower()


def test_api_snapshot_preserves_complete_dependency_evidence(acquired_snapshot: dict):
    snapshot = acquired_snapshot
    assert snapshot["diagnostics"] == []
    assert snapshot["_omnikit_acquisition"] == {
        "contract": "sigma-api-v2",
        "definitionClass": "authoritative_definition",
        "dataModelDefinitionEndpoint": "/v2/dataModels/{dataModelId}/spec?format=json",
        "workbookDefinitionClass": "content_evidence",
        "workbookSpecClaimed": False,
        "selectedDataModelIds": ["dm-orders"],
        "selectedWorkbookIds": ["wb-exec", "wb-sandbox"],
        "optional_endpoint_diagnostic_count": 0,
    }
    assert {item["connectionId"] for item in snapshot["connections"]} == {
        "conn-snowflake",
        "conn-bigquery",
    }

    (model,) = snapshot["dataModels"]
    assert {item["sourceId"] for item in model["sources"]} == {
        "model-source-orders",
        "model-source-customers",
    }
    assert next(
        item for item in model["columns"] if item["columnId"] == "model-col-margin"
    )["formula"] == "[Revenue] - [Cost]"
    assert model["lineage"][0]["lineageId"] == "lineage-model-orders"
    assert model["grants"][0]["grantId"] == "grant-dm-analysts"
    assert model["materializationSchedules"][0]["scheduleId"] == "schedule-dm-refresh"

    workbook = next(item for item in snapshot["workbooks"] if item["workbookId"] == "wb-exec")
    assert workbook["sources"][0]["sourceId"] == "workbook-source-orders"
    assert workbook["controls"][0]["targetElementIds"] == [
        "e-revenue-kpi",
        "e-revenue-trend",
        "e-orders-table",
    ]
    assert {item["grantId"] for item in workbook["grants"]} == {
        "grant-wb-finance-reviewers",
        "grant-wb-owner",
    }
    assert workbook["schedules"][0]["scheduleId"] == "schedule-weekly-email"
    assert workbook["materializationSchedules"][0]["scheduleId"] == "schedule-wb-cache"

    overview = next(item for item in workbook["pages"] if item["pageId"] == "p-overview")
    trend = next(
        item for item in overview["elements"] if item["elementId"] == "e-revenue-trend"
    )
    columns = {item["columnId"]: item for item in trend["columns"]}
    assert columns["model-col-order-date"]["formula"] == "[Order Date]"
    assert columns["model-col-revenue"]["formula"] == "Sum([Revenue])"
    assert trend["generatedSql"]["queryId"] == "query-revenue-trend"
    assert trend["lineage"][0]["lineageId"] == "lineage-revenue-trend"

    serialized = json.dumps(snapshot, sort_keys=True)
    assert "synthetic-secret" not in serialized
    assert "synthetic-token" not in serialized


@pytest.mark.parametrize(
    ("scope", "expected_dashboards"),
    [
        ({"selected_dashboard_ids": ["p-overview"]}, ["Executive Overview"]),
        (
            {"workbook_ids": ["wb-exec"]},
            ["Executive Overview", "Order Detail"],
        ),
    ],
)
def test_bridge_selection_scopes_pages_without_dropping_model_dependencies(
    acquired_snapshot: dict,
    scope: dict,
    expected_dashboards: list[str],
):
    result = _bridge_result(acquired_snapshot, scope)

    assert [dashboard.name for dashboard in result.bundle.dashboards] == expected_dashboards
    assert "Scratch Page" not in expected_dashboards
    assert {view.name for view in result.bundle.model.views} == {"orders", "customers"}

    orders = next(view for view in result.bundle.model.views if view.name == "orders")
    fields = {field.name: field for field in orders.fields}
    assert fields["total_revenue"].aggregate == "sum"
    assert fields["completed_revenue"].filters == {"status": {"is": "Complete"}}
    assert "margin" not in fields
    assert "rolling_revenue" not in fields
    assert "calculated column" in _review_text(result.bundle)
    assert "windowsum" in _review_text(result.bundle)

    (topic,) = result.bundle.model.topics
    assert topic.base_view == "orders"
    assert topic.joins[0].join_to_view == "customers"

    overview = next(
        dashboard
        for dashboard in result.bundle.dashboards
        if dashboard.native_source_id == "p-overview"
    )
    assert overview.selection_aliases == ["wb-exec", "p-overview"]
    assert [tile.title for tile in overview.tiles] == ["Revenue Trend"]
    assert all(tile.source_id and tile.source_locator and tile.evidence for tile in overview.tiles)
    unsupported_kpi = next(
        note for note in overview.untranslatable if (note.hint or "") == "SingleValue"
    )
    assert unsupported_kpi.severity == "blocker"
    assert result.model_suggestions == []


@pytest.mark.parametrize("mode", ["api", "manual"])
@pytest.mark.parametrize("route", [None, "warehouse-first", "omni-reconstruction"])
def test_legacy_bridge_cannot_generate_target_design_from_missing_or_unbound_choice(
    acquired_snapshot: dict, tmp_path: Path, mode: str, route: str | None,
):
    scope = {"selected_dashboard_ids": ["p-overview"]}
    if route is not None:
        path = ROUTE_EXAMPLES / f"sigma-semantic-routing-decision-request.v1.{route}.example.json"
        decision = create_sigma_semantic_routing_decision(json.loads(path.read_text()))
        # Legacy scope is caller-supplied metadata, not a trusted decision binding.
        scope["semantic_routing_decision"] = decision.model_dump(mode="json")
        scope["semantic_migration_mode"] = decision.payload.mode

    request = {
        "request_id": "sigma-unbound-target-design",
        "source": "sigma",
        "mode": mode,
        "scope": scope,
        "include_model_suggestions": True,
    }
    if mode == "api":
        request["connection"] = {
            "base_url": "https://api.example.invalid",
            "auth": {"snapshot": acquired_snapshot},
        }
    else:
        snapshot_path = tmp_path / "sigma-snapshot.json"
        snapshot_path.write_text(json.dumps(acquired_snapshot))
        request["artifact_root"] = str(tmp_path)
        request["artifacts"] = [{"path": snapshot_path.name}]

    result = execute_bridge_extract(BridgeExtractRequest.model_validate(request))

    assert result.bundle.model.views
    assert result.bundle.dashboards
    assert result.model_suggestions == []
    assert any("current semantic-route decision" in note for note in result.diagnostics.limitations)


def test_selected_dashboard_keeps_operational_dependencies_as_manual_handoffs(
    acquired_snapshot: dict,
):
    result = _bridge_result(
        acquired_snapshot,
        {"selected_dashboard_ids": ["p-overview"]},
    )
    serialized = json.dumps(result.bundle.model_dump(mode="json"), sort_keys=True)

    required_evidence = {
        "model-source-orders",
        "workbook-source-orders",
        "ctrl-region",
        "e-plan-input",
        "input-col-plan",
        "query-revenue-kpi",
        "query-revenue-trend",
        "lineage-revenue-kpi",
        "lineage-revenue-trend",
        "grant-dm-analysts",
        "grant-wb-finance-reviewers",
        "grant-wb-owner",
        "schedule-dm-refresh",
        "schedule-weekly-email",
        "schedule-wb-cache",
    }
    missing = sorted(identifier for identifier in required_evidence if identifier not in serialized)
    assert not missing, f"selected Sigma dependencies disappeared from the bridge bundle: {missing}"

    excluded_evidence = {
        "ctrl-sandbox",
        "query-scratch",
        "lineage-scratch",
        "grant-wb-sandbox",
        "schedule-sandbox",
    }
    leaked = sorted(identifier for identifier in excluded_evidence if identifier in serialized)
    assert not leaked, f"unselected workbook dependencies leaked into the scoped bundle: {leaked}"

    review = _review_text(result.bundle)
    assert any(token in review for token in ("manual", "unsupported", "handoff"))
    assert "control" in review
    assert "input" in review or "writeback" in review
    assert "grant" in review or "permission" in review or "governance" in review
    assert "schedule" in review or "delivery" in review


def test_normalized_view_collision_is_rejected_or_losslessly_disambiguated(
    acquired_snapshot: dict,
):
    snapshot = copy.deepcopy(acquired_snapshot)
    duplicate = copy.deepcopy(snapshot["dataModels"][0])
    duplicate["dataModelId"] = "dm-orders-archive"
    duplicate["name"] = "Example order archive model"
    duplicate["sources"] = [
        {
            "sourceId": "model-source-orders-archive",
            "elementId": "model-orders-archive",
            "connectionId": "conn-snowflake",
            "path": ["ANALYTICS", "MART_ARCHIVE", "ORDERS_ARCHIVE"],
        }
    ]
    duplicate["columns"] = [
        {
            "columnId": "archive-col-order-id",
            "elementId": "model-orders-archive",
            "name": "Order ID",
            "formula": "[Order ID]",
        }
    ]
    duplicate["lineage"] = []
    duplicate["grants"] = []
    duplicate["materializationSchedules"] = []
    duplicate["spec"] = {
        "dataModelId": "dm-orders-archive",
        "pages": [
            {
                "id": "dm-page-archive",
                "name": "Archive",
                "elements": [
                    {
                        "id": "model-orders-archive",
                        "kind": "table",
                        "name": "Orders!",
                        "source": {
                            "connectionId": "conn-snowflake",
                            "kind": "warehouse-table",
                            "path": ["ANALYTICS", "MART_ARCHIVE", "ORDERS_ARCHIVE"],
                        },
                        "columns": [
                            {"id": "archive-col-order-id", "name": "Order ID"}
                        ],
                    }
                ],
            }
        ],
        "relationships": [],
        "metrics": [],
    }
    snapshot["dataModels"].append(duplicate)

    try:
        result = _bridge_result(
            snapshot,
            {"selected_dashboard_ids": ["p-overview"]},
        )
    except ValueError as error:
        message = str(error).lower()
        assert "orders" in message
        assert any(token in message for token in ("collision", "conflict", "duplicate"))
        return

    colliding_views = [
        view
        for view in result.bundle.model.views
        if view.source_table in {"ORDERS", "ORDERS_ARCHIVE"}
    ]
    assert {view.source_table for view in colliding_views} == {"ORDERS", "ORDERS_ARCHIVE"}
    emitted_paths = {view_path(view) for view in colliding_views}
    assert len(emitted_paths) == 2
    assert result.model_suggestions == []

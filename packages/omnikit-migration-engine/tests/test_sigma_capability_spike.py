"""Contract and safety tests for the Sigma Phase-0 capability-spike agent."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest
from jsonschema import Draft202012Validator, FormatChecker
from pydantic import ValidationError

from omni_migrator.control_plane.canonical import sha256_json
from omni_migrator.extractors.sigma.api import SigmaApi
from omni_migrator.extractors.sigma.capability_contracts import (
    DataModelSnapshotPayload,
    RunManifestPayload,
    SigmaCapabilitySpikeBundle,
    SigmaCapabilitySpikeRequest,
)
from omni_migrator.extractors.sigma.capability_spike import (
    run_sigma_capability_spike,
    validate_artifact_content_hash,
)
from omni_migrator.extractors.sigma.semantic_routing import (
    create_sigma_semantic_routing_decision,
)


ROOT = Path(__file__).resolve().parents[3]


def _request(**overrides) -> SigmaCapabilitySpikeRequest:
    value = {
        "schema_version": "sigma-capability-spike-request.v1",
        "run_id": "run.sigma.phase0.0001",
        "scope_id": "scope.sigma.phase0.0001",
        "organization_ref": "sigma-org-ref://approved-org",
        "expected_organization_id": "org-1",
        "api_base_url": "https://api.example.invalid",
        "approved_api_hosts": ["api.example.invalid"],
        "principal_ref": "principal-ref://sigma-reader",
        "expected_user_id": "user-1",
        "effective_account_type": "viewer",
        "credential_ref": "secret-ref://sigma/phase0-reader",
        "authorization_ref": "authorization-ref://sigma/read-only/0001",
        "scope_approval_ref": "human-approval-ref://sigma/scope/0001",
        "comparison_scope_refs": [
            "sigma://workbooks/wb-1",
            "sigma://dataModels/dm-1",
        ],
        "build_scope_refs": ["sigma://workbooks/wb-1"],
        "policy_version": "sigma-phase0-policy.v1",
        "workbook_id": "wb-1",
        "data_model_id": "dm-1",
        "source_freeze": {
            "strategy": "version_tag",
            "source_reference": "sigma://workbooks/wb-1/tags/release-candidate",
            "workbook_tag_name": "release-candidate",
            "workbook_published_version": None,
            "data_model_document_version": 7,
            "approved_by_ref": "human-ref://migration-owner",
            "approval_ref": "human-approval-ref://sigma/freeze/0001",
        },
        "manual_evidence_owner_ref": "human-ref://sigma-content-owner",
        "privacy_approval_ref": "human-approval-ref://sigma/privacy/0001",
        "sanitization_policy_ref": "sanitization-policy-ref://sigma/metadata-only/v1",
        "retention_policy_ref": "retention-policy-ref://migration-metadata/30d",
        "data_classification": "confidential",
        "row_data_authorized": False,
        "evidence_mode": "live_tenant",
        "request_budget": 100,
        "approved_exclusions": [],
    }
    value.update(overrides)
    return SigmaCapabilitySpikeRequest.model_validate(value)


def _entries(rows: list[dict], *, total: int | None = None, **extra) -> httpx.Response:
    body = {"entries": rows, "total": len(rows) if total is None else total, **extra}
    return httpx.Response(200, json=body)


def _handler(
    calls: list[tuple[str, str, dict[str, str]]],
    *,
    organization_id: str = "org-1",
    user_id: str = "user-1",
    empty_columns: bool = False,
    duplicate_model_sources: bool = False,
    duplicate_workbook_inode_sources: bool = False,
    mismatched_source_total: bool = False,
    missing_workbook_metadata: bool = False,
    cross_origin_bookmark_cursor: bool = False,
    same_origin_endpoint_change: bool = False,
    changed_page_selector: bool = False,
    missing_element_id: bool = False,
    orphan_workbook_column: bool = False,
    workbook_version_drift: bool = False,
    malformed_workbook_version: bool = False,
    malformed_tag_source_version: bool = False,
    wrong_data_model_version: bool = False,
    data_model_version_drift: bool = False,
    expected_workbook_tag: str | None = "release-candidate",
):
    workbook_metadata_calls = 0
    data_model_metadata_calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal data_model_metadata_calls, workbook_metadata_calls
        path = request.url.path
        calls.append((request.method, path, dict(request.url.params)))
        if request.method == "POST" and path == "/v2/auth/token":
            return httpx.Response(
                200,
                json={
                    "access_token": "live-access-token-do-not-persist",
                    "refresh_token": "live-refresh-token-do-not-persist",
                },
            )
        if request.method != "GET":
            return httpx.Response(405)
        if path == "/v2/whoami":
            return httpx.Response(
                200,
                json={
                    "organizationId": organization_id,
                    "userId": user_id,
                    "email": "sensitive.user@example.com",
                },
            )
        if path == "/v2/dataModels/dm-1":
            data_model_metadata_calls += 1
            return httpx.Response(
                200,
                json={
                    "dataModelId": "dm-1",
                    "name": "Orders",
                    "latestDocumentVersion": (
                        9 if data_model_version_drift and data_model_metadata_calls > 1 else 8
                    ),
                },
            )
        if path == "/v2/dataModels/dm-1/spec":
            assert request.url.params.get("documentVersion") == "7"
            return httpx.Response(
                200,
                json={
                    "schemaVersion": 1,
                    "dataModelId": "dm-1",
                    "documentVersion": 8 if wrong_data_model_version else 7,
                    "latestDocumentVersion": 8,
                    "clientSecret": "must-be-redacted",
                    "createdById": "model-author-user-secret",
                    "emailAddress": "alternate-owner@example.com",
                    "recipient_email": "alternate-recipient@example.com",
                    "dynamic-key@example.com": "present",
                    "sk-dynamic-secret-key": "present",
                    "pages": [
                        {
                            "elements": [
                                {
                                    "id": "model-element-1",
                                    "kind": "table",
                                    "columns": [
                                        {
                                            "id": "model-column-1",
                                            "name": "Revenue",
                                            "formula": "Sum([Revenue])",
                                        }
                                    ],
                                }
                            ]
                        }
                    ],
                    "metrics": [],
                    "relationships": [],
                },
            )
        if path == "/v2/dataModels/dm-1/sources":
            if duplicate_model_sources:
                return _entries(
                    [
                        {"tableId": "source-1", "type": "table"},
                        {"tableId": "source-1", "type": "table"},
                    ]
                )
            if request.url.params.get("pageToken") == "opaque-cursor-2":
                return _entries([{"tableId": "source-2", "type": "table"}], total=2)
            return _entries(
                [
                    {
                        "dataModelId": "source-1",
                        "elementIds": ["upstream-element-1"],
                        "type": "data-model",
                    }
                ],
                total=3 if mismatched_source_total else 2,
                nextPageToken="opaque-cursor-2",
            )
        if path == "/v2/dataModels/dm-1/columns":
            return _entries(
                []
                if empty_columns
                else [
                    {
                        "columnId": "model-column-1",
                        "elementId": "model-element-1",
                        "formula": "Sum([Revenue])",
                        "type": {"kind": "number", "nullable": True},
                    }
                ]
            )
        if path == "/v2/dataModels/dm-1/elements":
            return _entries([{"elementId": "model-element-1", "type": "table"}])
        if path == "/v2/dataModels/dm-1/lineage":
            return _entries([{"elementId": "model-element-1", "sourceIds": ["source-1"]}])
        if path == "/v2/dataModels/dm-1/materializationSchedules":
            assert int(request.url.params["pageSize"]) <= 500
            return _entries([])
        if path == "/v2/dataModels/dm-1/tags":
            return _entries([{"tagId": "model-tag-1", "name": "release-candidate"}])
        if path == "/v2/workbooks/wb-1":
            workbook_metadata_calls += 1
            if missing_workbook_metadata:
                return httpx.Response(404, json={"code": "not_found"})
            return httpx.Response(
                200,
                json={
                    "workbookId": "wb-1",
                    "name": "Executive Operations",
                    "latestVersion": (
                        {"unexpected": 12}
                        if malformed_workbook_version
                        else 13
                        if workbook_version_drift and workbook_metadata_calls > 1
                        else 12
                    ),
                    "ownerEmail": "owner@example.com",
                },
            )
        if path == "/v2/workbooks/wb-1/pages":
            assert request.url.params.get("tag") == expected_workbook_tag
            return _entries(
                [{"pageId": "page-1", "name": "Overview", "hidden": False}],
                **(
                    {"links": {"next": "/v2/workbooks/wb-1/pages?tag=other&page=2"}}
                    if changed_page_selector
                    else {}
                ),
            )
        if path == "/v2/workbooks/wb-1/pages/page-1/elements":
            assert request.url.params.get("tag") == expected_workbook_tag
            return _entries(
                [
                    {
                        "elementId": "element-chart",
                        "name": "Revenue",
                        "type": "visualization",
                        "vizualizationType": "Line",
                    },
                    {"elementId": "control-region", "name": "Region", "type": "control"},
                    {"elementId": "input-plan", "name": "Plan", "type": "input-table"},
                    *([{"name": "Unsafe", "type": "table"}] if missing_element_id else []),
                ]
            )
        if path == "/v2/workbooks/wb-1/sources":
            return httpx.Response(
                200,
                json=(
                    [
                        {"inodeId": "workbook-source-1", "type": "table"},
                        {"inodeId": "workbook-source-1", "type": "table"},
                    ]
                    if duplicate_workbook_inode_sources
                    else [
                        {
                            "type": "data-model",
                            "dataModelId": "dm-1",
                            "elementIds": ["model-element-1"],
                        }
                    ]
                ),
            )
        if path == "/v2/workbooks/wb-1/elements":
            assert request.url.params.get("tagName") == expected_workbook_tag
            return _entries(
                [
                    {"elementId": "element-chart", "type": "visualization"},
                    {"elementId": "control-region", "type": "control"},
                    {"elementId": "input-plan", "type": "input-table"},
                ]
            )
        if path == "/v2/workbooks/wb-1/columns":
            return _entries(
                []
                if empty_columns
                else [
                    {
                        "columnId": "workbook-column-1",
                        "elementId": (
                            "missing-element" if orphan_workbook_column else "element-chart"
                        ),
                        "label": "Revenue",
                        "formula": "Sum([Revenue])",
                        "type": {"kind": "number", "nullable": True},
                    }
                ]
            )
        if path == "/v2/workbooks/wb-1/controls":
            return _entries([{"name": "Region", "valueType": "text"}])
        if path == "/v2/workbooks/wb-1/queries":
            return _entries(
                [{"queryId": "query-1", "elementId": "element-chart", "sql": "select sum(revenue)"}]
            )
        if path == "/v2/workbooks/wb-1/lineage":
            return _entries([{"elementId": "element-chart", "sourceIds": ["source-1"]}])
        if path == "/v2/grants":
            return _entries(
                [
                    {
                        "grantId": "grant-redacted-from-id-evidence",
                        "inodeId": request.url.params.get("inodeId"),
                        "permission": "view",
                    }
                ]
            )
        if path == "/v2.1/workbooks/wb-1/schedules":
            return _entries(
                [
                    {
                        "scheduleId": "schedule-1",
                        "frequency": "weekly",
                        "recipientEmail": "recipient@example.com",
                        "recipients": [{"userId": "recipient-user-secret"}],
                    }
                ]
            )
        if path == "/v2/workbooks/wb-1/materialization-schedules":
            return _entries([])
        if path == "/v2/workbooks/wb-1/version-history":
            return _entries([{"version": 12, "publishedAt": "2026-09-01T12:00:00Z"}])
        if path == "/v2/workbooks/wb-1/tags":
            return _entries(
                [
                    {
                        "tagId": "tag-1",
                        "tagName": "release-candidate",
                        "sourceVersion": (
                            {"unexpected": 12} if malformed_tag_source_version else 12
                        ),
                    }
                ]
            )
        if path in {
            "/v2/workbooks/wb-1/bookmarks",
            "/v2/workbooks/wb-1/tags/release-candidate/bookmarks",
        }:
            if (
                cross_origin_bookmark_cursor or same_origin_endpoint_change
            ) and path == "/v2/workbooks/wb-1/bookmarks":
                return httpx.Response(
                    200,
                    json={
                        "entries": [{"bookmarkId": "bookmark-1"}],
                        "links": {
                            "next": (
                                "/v2/members?page=2"
                                if same_origin_endpoint_change
                                else "https://evil.example.invalid/steal"
                            )
                        },
                    },
                )
            return _entries([{"bookmarkId": "bookmark-1", "name": "Default", "shared": True}])
        if path == "/v2/workbooks/wb-1/embeds":
            return _entries([{"embedId": "embed-1", "public": False}])
        return httpx.Response(404, json={"code": "not_found"})

    return handler


def _run(*, request=None, **handler_options):
    calls: list[tuple[str, str, dict[str, str]]] = []
    approved_request = request or _request()
    api = SigmaApi(
        base_url=approved_request.api_base_url,
        client_id="client-id-sensitive",
        client_secret="client-secret-sensitive",
        transport=httpx.MockTransport(_handler(calls, **handler_options)),
        request_budget=approved_request.request_budget,
    )
    result = run_sigma_capability_spike(
        approved_request,
        api=api,
        started_at=datetime(2026, 9, 2, 14, 0, tzinfo=UTC),
    )
    api.close()
    return result, calls


def _run_with_responses(transform):
    """Replace one provider response while retaining the full acquisition workflow."""

    calls = []
    base_handler = _handler(calls)

    def handler(request):
        return transform(request, base_handler(request))

    api = SigmaApi(
        base_url="https://api.example.invalid",
        client_id="test-client",
        client_secret="test-secret",
        transport=httpx.MockTransport(handler),
    )
    try:
        return run_sigma_capability_spike(_request(), api=api)
    finally:
        api.close()


def test_documented_source_contracts_and_recursive_column_types_survive_roundtrip():
    fixture = json.loads(
        (Path(__file__).parent / "fixtures/sigma/documented_source_contracts.json").read_text()
    )

    def transform(request, response):
        if request.url.path == "/v2/dataModels/dm-1/sources":
            return _entries(fixture["data_model_sources"])
        if request.url.path == "/v2/workbooks/wb-1/sources":
            return httpx.Response(200, json=fixture["workbook_sources"])
        if request.url.path == "/v2/workbooks/wb-1/columns":
            payload = response.json()
            payload["entries"][0]["type"] = fixture["recursive_column_type"]
            return httpx.Response(200, json=payload)
        return response

    result = _run_with_responses(transform)
    assert result.status == "ready_for_human_review"
    restored = SigmaCapabilitySpikeBundle.model_validate_json(result.model_dump_json())
    assert restored == result
    source_nodes = [
        node for node in restored.workbook_graph.payload.nodes if node.node_type == "source"
    ]
    assert len(source_nodes) == 5
    model_nodes = [node for node in source_nodes if node.properties["type"] == "data-model"]
    assert {node.properties["elementId"] for node in model_nodes} == {"element-a", "element-b"}
    assert all(node.properties["versionTagId"] == "tag-1" for node in model_nodes)
    custom_sql = next(node for node in source_nodes if node.properties["type"] == "custom-sql")
    assert custom_sql.properties["connectionId"] == "warehouse-connection-1"
    assert custom_sql.properties["customSqlId"] == "custom-sql-1"
    assert custom_sql.properties["definition"] == "select 1 as source_value"
    persisted_model_bindings = restored.data_model_snapshot.payload.source_bindings
    assert (
        restored.data_model_snapshot.payload.source_bindings_version_context
        == "bracketed_unversioned"
    )
    assert len(persisted_model_bindings) == 5
    model_sql = next(
        binding for binding in persisted_model_bindings if binding.type == "custom-sql"
    )
    assert model_sql.connectionId == "warehouse-connection-1"
    columns = [node for node in restored.workbook_graph.payload.nodes if node.node_type == "column"]
    assert columns[0].properties["type"] == fixture["recursive_column_type"]
    payload = restored.data_model_snapshot.payload.model_dump(mode="json")
    payload["source_bindings"].append(payload["source_bindings"][0])
    with pytest.raises(ValidationError, match="duplicate compound identities"):
        DataModelSnapshotPayload.model_validate(payload)


@pytest.mark.parametrize(
    "invalid_source",
    [
        {"type": "table", "sourceId": "invented-identity"},
        {"type": "data-model", "dataModelId": "upstream", "elementIds": []},
        {"type": "data-model", "dataModelId": "upstream", "elementIds": ["../unsafe"]},
        {"type": "custom-sql", "customSqlId": "sql-1", "definition": "select 1"},
        {"type": "future-unknown-source", "id": "source-1"},
    ],
)
def test_malformed_or_unknown_source_variants_block_with_reviewable_evidence(invalid_source):
    result = _run_with_responses(
        lambda request, response: (
            _entries([invalid_source])
            if request.url.path == "/v2/dataModels/dm-1/sources"
            else response
        )
    )
    assert result.status == "blocked"
    assert "capability:sources" in result.blockers
    assert SigmaCapabilitySpikeBundle.model_validate_json(result.model_dump_json()) == result


def test_repeated_compound_model_element_identity_across_source_pages_blocks():
    def transform(request, response):
        if request.url.path == "/v2/dataModels/dm-1/sources":
            row = {
                "type": "data-model",
                "dataModelId": "upstream",
                "elementIds": ["element-a"],
                "versionTagId": "tag-a",
            }
            return _entries(
                [row],
                total=2,
                **({"nextPageToken": "page-2"} if "pageToken" not in request.url.params else {}),
            )
        return response

    result = _run_with_responses(transform)
    assert "capability:sources" in result.blockers
    assert "capability:pagination" in result.blockers


@pytest.mark.parametrize("returned_id", [None, "wrong-dm", 7])
def test_missing_or_wrong_spec_identity_is_omitted_and_blocks_serializable_bundle(returned_id):
    def transform(request, response):
        if request.url.path == "/v2/dataModels/dm-1/spec":
            payload = response.json()
            payload.pop("dataModelId")
            if returned_id is not None:
                payload["dataModelId"] = returned_id
            return httpx.Response(200, json=payload)
        return response

    result = _run_with_responses(transform)
    snapshot = result.data_model_snapshot.payload
    assert result.status == "blocked"
    assert "capability:selected_object_identity" in result.blockers
    assert snapshot.specification_state == "unavailable"
    assert snapshot.specification_unavailability_reason == "identity_mismatch"
    assert snapshot.sanitized_specification == {}
    assert SigmaCapabilitySpikeBundle.model_validate_json(result.model_dump_json()) == result


@pytest.mark.parametrize(
    "field,value",
    [
        ("dataModelId", "wrong-dm"),
        ("dataModelId", None),
        ("documentVersion", 8),
        ("documentVersion", True),
    ],
)
def test_snapshot_contract_rejects_spec_binding_tampering_even_after_rehash(field, value):
    result, _ = _run()
    payload = result.data_model_snapshot.payload.model_dump(mode="json")
    payload["sanitized_specification"][field] = value
    payload["specification_sha256"] = sha256_json(payload["sanitized_specification"])
    with pytest.raises(ValidationError, match="specification (identity|version)"):
        DataModelSnapshotPayload.model_validate(payload)
    payload["specification_state"] = "unavailable"
    payload["specification_unavailability_reason"] = "identity_mismatch"
    with pytest.raises(ValidationError, match="unavailable specification must be empty"):
        DataModelSnapshotPayload.model_validate(payload)


def test_integral_double_versions_bind_to_integer_selectors_throughout_run():
    def transform(request, response):
        payload = response.json()
        if request.url.path == "/v2/dataModels/dm-1/spec":
            payload["documentVersion"] = 7.0
        elif request.url.path == "/v2/dataModels/dm-1":
            payload["latestDocumentVersion"] = 8.0
        elif request.url.path == "/v2/workbooks/wb-1":
            payload["latestVersion"] = 12.0
        elif request.url.path == "/v2/workbooks/wb-1/tags":
            payload["entries"][0]["sourceVersion"] = 12.0
        return httpx.Response(response.status_code, json=payload)

    result = _run_with_responses(transform)
    assert result.status == "ready_for_human_review"
    assert result.data_model_snapshot.payload.specification_state == "bound"
    assert SigmaCapabilitySpikeBundle.model_validate_json(result.model_dump_json()) == result


@pytest.mark.parametrize("invalid_version", [True, 7.25, 0, -1, "7.0", {"version": 7}])
def test_invalid_spec_versions_block_without_persisting_unbound_definition(invalid_version):
    def transform(request, response):
        if request.url.path == "/v2/dataModels/dm-1/spec":
            payload = response.json()
            payload["documentVersion"] = invalid_version
            return httpx.Response(200, json=payload)
        return response

    result = _run_with_responses(transform)
    assert result.status == "blocked"
    assert result.data_model_snapshot.payload.specification_state == "unavailable"
    assert (
        result.data_model_snapshot.payload.specification_unavailability_reason == "version_mismatch"
    )
    assert SigmaCapabilitySpikeBundle.model_validate_json(result.model_dump_json()) == result


@pytest.mark.parametrize("status_code", [400, 403, 404])
def test_materialization_endpoint_failure_is_an_explicit_capability_gap(status_code):
    result = _run_with_responses(
        lambda request, response: (
            httpx.Response(status_code, json={"error": "unavailable"})
            if request.url.path == "/v2/dataModels/dm-1/materializationSchedules"
            else response
        )
    )
    assert result.status == "blocked"
    assert "capability:materialization_schedules" in result.blockers
    capability = next(
        item
        for item in result.capability_matrix.payload.assessments
        if item.capability_id == "materialization_schedules"
    )
    assert "endpoint:/v2/dataModels/dm-1/materializationSchedules" in capability.missing_properties
    assert capability.fallback is not None


def test_request_binds_exact_scope_host_human_approval_and_secret_reference():
    request = _request()
    assert set(request.build_scope_refs).issubset(request.comparison_scope_refs)

    with pytest.raises(ValidationError, match="not in approved_api_hosts"):
        _request(api_base_url="https://other.example.invalid")
    with pytest.raises(ValidationError, match="absolute HTTPS"):
        _request(api_base_url="http://api.example.invalid")
    with pytest.raises(ValidationError, match="host names only"):
        _request(approved_api_hosts=["api..example.invalid"])
    with pytest.raises(ValidationError, match="standard HTTPS port"):
        _request(
            api_base_url="https://api.example.invalid:8443",
            approved_api_hosts=["api.example.invalid"],
        )
    with pytest.raises(ValidationError, match="subset"):
        _request(build_scope_refs=["sigma://workbooks/outside"])
    with pytest.raises(ValidationError, match="cannot exceed request_budget"):
        _request(request_budget=10, per_endpoint_request_budget=11)
    with pytest.raises(ValidationError, match="exactly one Sigma workbook"):
        _request(
            comparison_scope_refs=[
                "sigma://workbooks/wb-1",
                "sigma://workbooks/wb-2",
                "sigma://dataModels/dm-1",
            ]
        )
    with pytest.raises(ValidationError, match="secret-ref"):
        _request(credential_ref="raw-client-secret")
    with pytest.raises(ValidationError):
        _request(row_data_authorized=True)
    with pytest.raises(ValidationError, match="human-approval-ref"):
        _request(privacy_approval_ref="approval-ref://self-approved")
    with pytest.raises(ValidationError):
        SigmaCapabilitySpikeRequest.model_validate(
            {**request.model_dump(mode="json"), "client_secret": "forbidden"}
        )
    mixed_freeze = request.model_dump(mode="json")
    mixed_freeze["source_freeze"]["workbook_published_version"] = 12
    with pytest.raises(ValidationError, match="cannot also declare"):
        SigmaCapabilitySpikeRequest.model_validate(mixed_freeze)
    wrong_freeze = request.model_dump(mode="json")
    wrong_freeze["source_freeze"]["source_reference"] = (
        "sigma://workbooks/other/tags/release-candidate"
    )
    with pytest.raises(ValidationError, match="exact workbook and tag"):
        SigmaCapabilitySpikeRequest.model_validate(wrong_freeze)


@pytest.mark.parametrize(
    ("field", "unsafe"),
    [
        ("workbook_id", "../../members"),
        ("credential_ref", "raw-client-secret"),
        ("api_base_url", "http://api.example.invalid"),
    ],
)
def test_exported_request_schema_rejects_representable_security_constraints(field, unsafe):
    payload = _request().model_dump(mode="json")
    payload[field] = unsafe
    schema = json.loads(
        (ROOT / "contracts" / "sigma" / "sigma-capability-spike-request.v1.schema.json").read_text()
    )

    errors = list(Draft202012Validator(schema).iter_errors(payload))

    assert errors


def test_live_spike_is_read_only_sanitized_content_addressed_and_review_gated():
    result, calls = _run()

    assert result.status == "ready_for_human_review"
    assert calls[0][:2] == ("POST", "/v2/auth/token")
    assert calls[1][:2] == ("GET", "/v2/whoami")
    assert all(method == "GET" for method, _, _ in calls[1:])
    assert not any("/v2/workbooks" == path or "/v2/dataModels" == path for _, path, _ in calls)
    assert result.run_manifest.payload.mutation_endpoints_exposed is False
    assert result.run_manifest.payload.target_write_authority is False
    assert (
        next(
            gate
            for gate in result.gate_recommendations
            if gate.gate_id == "target_write_authorized"
        ).state
        == "blocked"
    )
    assert (
        next(
            gate
            for gate in result.gate_recommendations
            if gate.gate_id == "artifact_registry_registered"
        ).state
        == "blocked"
    )
    assert (
        next(
            gate
            for gate in result.gate_recommendations
            if gate.gate_id == "semantic_migration_strategy_selected"
        ).state
        == "blocked"
    )
    assert (
        next(
            gate
            for gate in result.gate_recommendations
            if gate.gate_id == "semantic_target_design_approved"
        ).state
        == "blocked"
    )

    serialized = result.model_dump_json()
    for forbidden in (
        "client-id-sensitive",
        "client-secret-sensitive",
        "live-access-token-do-not-persist",
        "live-refresh-token-do-not-persist",
        "opaque-cursor-2",
        "sensitive.user@example.com",
        "owner@example.com",
        "alternate-owner@example.com",
        "recipient@example.com",
        "alternate-recipient@example.com",
        "must-be-redacted",
        "model-author-user-secret",
        "recipient-user-secret",
        "dynamic-key@example.com",
        "sk-dynamic-secret-key",
    ):
        assert forbidden not in serialized
    assert '"redacted":"secret"' in serialized
    assert all(
        observation.payload.row_data_retained is False for observation in result.observations
    )
    assert all(
        observation.payload.redaction_state == "structural_only"
        for observation in result.observations
    )
    spec_observation = next(
        item for item in result.observations if item.payload.endpoint == "/v2/dataModels/dm-1/spec"
    )
    pages_observation = next(
        item for item in result.observations if item.payload.endpoint == "/v2/workbooks/wb-1/pages"
    )
    columns_observation = next(
        item
        for item in result.observations
        if item.payload.endpoint == "/v2/workbooks/wb-1/columns"
    )
    assert spec_observation.payload.version_context == "data_model_document_version"
    assert spec_observation.payload.version_selector == {"documentVersion": "7"}
    assert pages_observation.payload.version_context == "workbook_tag"
    assert pages_observation.payload.version_selector == {"tag": "release-candidate"}
    assert columns_observation.payload.version_context == "bracketed_unversioned"
    assert result.metrics.row_data_retained is False
    assert result.metrics.model_tokens_used == 0
    assert result.metrics.per_endpoint_request_budget == 20

    artifacts = (
        result.run_manifest,
        *result.observations,
        result.capability_matrix,
        result.workbook_graph,
        result.data_model_snapshot,
        result.behavior_manifest,
    )
    assert all(validate_artifact_content_hash(artifact) for artifact in artifacts)
    timestamps = [artifact.created_at for artifact in artifacts]
    assert timestamps == sorted(timestamps)
    assert len(set(timestamps)) == len(timestamps)

    schema = json.loads(
        (ROOT / "contracts" / "sigma" / "sigma-capability-spike-bundle.v1.schema.json").read_text()
    )
    errors = list(
        Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(
            result.model_dump(mode="json")
        )
    )
    assert errors == []


def test_changing_semantic_route_does_not_change_or_reacquire_source_evidence():
    result, calls = _run()
    source_before = result.model_dump_json()
    call_count_before = len(calls)
    source_hashes_before = tuple(
        artifact.content_hash
        for artifact in (
            result.run_manifest,
            *result.observations,
            result.capability_matrix,
            result.workbook_graph,
            result.data_model_snapshot,
            result.behavior_manifest,
        )
    )
    source_context = {
        "artifact_id": result.data_model_snapshot.artifact_id,
        "artifact_schema_version": result.data_model_snapshot.schema_version,
        "artifact_run_id": result.data_model_snapshot.run_id,
        "artifact_scope_id": result.data_model_snapshot.scope_id,
        "content_hash": result.data_model_snapshot.content_hash,
        "artifact_created_at": result.data_model_snapshot.created_at,
        "accepted_by_ref": "human-ref://migration-owner",
        "acceptance_ref": "human-approval-ref://sigma/source-context/0001",
        "acceptance_record_revision": "revision-1",
        "acceptance_record_sha256": "a" * 64,
        "accepted_at": "2026-09-02T15:00:00+00:00",
    }
    common = {
        "schema_version": "sigma-semantic-routing-decision-request.v1",
        "run_id": "run.sigma.migration.0001",
        "scope_id": result.scope_id,
        "migration_unit_id": "migration-unit-orders-0001",
        "comparison_scope_refs": result.run_manifest.payload.comparison_scope_refs,
        "build_scope_refs": result.run_manifest.payload.build_scope_refs,
        "decided_by_ref": "human-ref://migration-owner",
        "decision_record_revision": "revision-1",
        "decided_at": "2026-09-02T16:00:00+00:00",
        "rationale": "Record the selected target placement without changing source evidence.",
        "source_context_bindings": [source_context],
    }
    warehouse = create_sigma_semantic_routing_decision(
        {
            **common,
            "decision_id": "semantic-route-warehouse",
            "mode": "warehouse_first_refactor",
            "target_environment_refs": [
                "environment-ref://dbt/development",
                "environment-ref://omni/quarantine",
            ],
            "decision_ref": "human-decision-ref://sigma/semantic-route/warehouse",
            "decision_record_sha256": "b" * 64,
        },
        created_at=datetime(2026, 9, 2, 17, 0, tzinfo=UTC),
    )
    direct = create_sigma_semantic_routing_decision(
        {
            **common,
            "decision_id": "semantic-route-direct",
            "mode": "omni_semantic_reconstruction",
            "target_environment_refs": ["environment-ref://omni/quarantine"],
            "decision_ref": "human-decision-ref://sigma/semantic-route/direct",
            "decision_record_sha256": "c" * 64,
        },
        created_at=datetime(2026, 9, 2, 17, 0, tzinfo=UTC),
    )

    assert warehouse.content_hash != direct.content_hash
    assert len(calls) == call_count_before
    assert result.model_dump_json() == source_before
    assert (
        tuple(
            artifact.content_hash
            for artifact in (
                result.run_manifest,
                *result.observations,
                result.capability_matrix,
                result.workbook_graph,
                result.data_model_snapshot,
                result.behavior_manifest,
            )
        )
        == source_hashes_before
    )


def test_manifest_hash_binds_manual_owner_and_approved_exclusions():
    baseline, _ = _run()
    changed, _ = _run(
        request=_request(
            manual_evidence_owner_ref="human-ref://alternate-content-owner",
            approved_exclusions=[
                {
                    "property_id": "actions",
                    "reason": "Pilot owner accepted no action coverage.",
                    "approved_by_ref": "human-ref://migration-owner",
                    "approval_ref": "human-approval-ref://sigma/exclusion/0001",
                }
            ],
        )
    )

    assert baseline.run_manifest.content_hash != changed.run_manifest.content_hash
    assert (
        changed.run_manifest.payload.manual_evidence_owner_ref
        == "human-ref://alternate-content-owner"
    )
    assert changed.run_manifest.payload.approved_exclusions[0].property_id == "actions"

    action_capability = next(
        item
        for item in changed.capability_matrix.payload.assessments
        if item.capability_id == "actions"
    )
    action_behavior = next(
        item
        for item in changed.behavior_manifest.payload.behaviors
        if item.behavior_id == "action.manual"
    )
    assert action_capability.fallback is not None
    assert action_capability.fallback.approval_state == "proposed"
    assert action_capability.fallback.approval_ref is None
    assert action_behavior.disposition == "external_redesign_required"
    assert action_behavior.blocking is True
    assert action_behavior.behavior_id in changed.behavior_manifest.payload.unresolved_behavior_ids


def test_bundle_is_deeply_immutable_and_rejects_hash_or_status_contradictions():
    result, _ = _run()

    with pytest.raises(TypeError, match="immutable"):
        result.data_model_snapshot.payload.sanitized_specification["tampered"] = True
    with pytest.raises(TypeError, match="immutable"):
        result.data_model_snapshot.payload.sanitized_specification.__init__({"tampered": True})

    tampered = result.model_dump(mode="json")
    tampered["data_model_snapshot"]["payload"]["sanitized_specification"]["schemaVersion"] = 999
    with pytest.raises(ValidationError, match="specification hash is inconsistent"):
        type(result).model_validate(tampered)

    contradictory = result.model_dump(mode="json")
    contradictory["status"] = "blocked"
    with pytest.raises(ValidationError, match="status contradicts"):
        type(result).model_validate(contradictory)


def test_derived_checksums_and_behavior_denominator_are_revalidated():
    result, _ = _run()

    bad_specification_hash = result.model_dump(mode="json")
    bad_specification_hash["data_model_snapshot"]["payload"]["specification_sha256"] = "0" * 64
    with pytest.raises(ValidationError, match="specification hash is inconsistent"):
        type(result).model_validate(bad_specification_hash)

    orphan_behavior = result.model_dump(mode="json")
    orphan_behavior["behavior_manifest"]["payload"]["unresolved_behavior_ids"].append(
        "ghost.behavior"
    )
    with pytest.raises(ValidationError, match="unresolved denominator is inconsistent"):
        type(result).model_validate(orphan_behavior)

    unsupported_evidence_claim = result.model_dump(mode="json")
    for assessment in unsupported_evidence_claim["capability_matrix"]["payload"]["assessments"]:
        assessment.update(
            status="verified_full",
            evidence_refs=[],
            missing_properties=[],
            fallback=None,
            blocks_full_adapter=False,
        )
    with pytest.raises(ValidationError, match="requires observed evidence"):
        type(result).model_validate(unsupported_evidence_claim)

    erased_identity_requirement = result.model_dump(mode="json")
    tenant_binding = next(
        item
        for item in erased_identity_requirement["capability_matrix"]["payload"]["assessments"]
        if item["capability_id"] == "tenant_principal_binding"
    )
    tenant_binding.update(
        status="not_applicable",
        evidence_refs=[],
        missing_properties=[],
        fallback=None,
        blocks_full_adapter=False,
    )
    with pytest.raises(ValidationError, match="must block unless verified_full"):
        type(result).model_validate(erased_identity_requirement)


def test_generated_serialization_schema_preserves_closed_contract_shape():
    request_schema = SigmaCapabilitySpikeRequest.model_json_schema(mode="serialization")
    bundle_schema = SigmaCapabilitySpikeBundle.model_json_schema(mode="serialization")

    assert request_schema["additionalProperties"] is False
    assert "api_base_url" in request_schema["properties"]
    assert "approved_api_hosts" in request_schema["properties"]
    assert bundle_schema["additionalProperties"] is False
    assert "run_manifest" in bundle_schema["properties"]
    assert "gate_recommendations" in bundle_schema["properties"]


@pytest.mark.parametrize(
    ("field", "unsafe"),
    [
        ("credential_ref", "raw-client-secret"),
        ("workbook_id", "../escape"),
        ("data_model_id", "bad/id"),
        ("api_base_url", "http://evil.example"),
    ],
)
def test_published_run_manifest_schema_rejects_representable_security_violations(field, unsafe):
    result, _ = _run()
    manifest = result.run_manifest.model_dump(mode="json")
    manifest["payload"][field] = unsafe
    schema = json.loads(
        (ROOT / "contracts" / "sigma" / "sigma-run-manifest.v1.schema.json").read_text()
    )

    errors = list(
        Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(manifest)
    )
    assert errors


def _rehash_artifact(value: dict) -> None:
    material = dict(value)
    material.pop("content_hash")
    value["content_hash"] = sha256_json(material)


def test_bundle_rejects_removed_upstreams_and_incomplete_capability_denominator():
    result, _ = _run()
    without_upstreams = result.model_dump(mode="json")
    for key in (
        "run_manifest",
        "capability_matrix",
        "workbook_graph",
        "data_model_snapshot",
        "behavior_manifest",
    ):
        without_upstreams[key]["upstream_hashes"] = []
        _rehash_artifact(without_upstreams[key])
    for observation in without_upstreams["observations"]:
        observation["upstream_hashes"] = []
        _rehash_artifact(observation)

    with pytest.raises(ValidationError, match="upstream closure mismatch"):
        type(result).model_validate(without_upstreams)

    incomplete = result.model_dump(mode="json")
    matrix = incomplete["capability_matrix"]
    matrix["payload"]["assessments"] = []
    matrix["payload"]["blocking_capability_ids"] = []
    matrix["payload"]["manual_fallback_capability_ids"] = []
    matrix["payload"]["matrix_status"] = "ready_for_human_review"
    _rehash_artifact(matrix)
    behavior = incomplete["behavior_manifest"]
    for upstream in behavior["upstream_hashes"]:
        if upstream["artifact_id"] == matrix["artifact_id"]:
            upstream["content_hash"] = matrix["content_hash"]
    _rehash_artifact(behavior)

    with pytest.raises(ValidationError, match="denominator is incomplete"):
        type(result).model_validate(incomplete)


@pytest.mark.parametrize(
    ("field", "value", "expected_error"),
    [
        ("credential_ref", "raw-client-secret", "secret-ref"),
        ("api_base_url", "http://attacker.invalid", "absolute HTTPS"),
    ],
)
def test_standalone_run_manifest_revalidates_security_bindings(field, value, expected_error):
    result, _ = _run()
    payload = result.run_manifest.payload.model_dump(mode="json")
    payload[field] = value

    with pytest.raises(ValidationError, match=expected_error):
        RunManifestPayload.model_validate(payload)


def test_property_matrix_never_claims_complete_workbook_portability_from_http_200():
    result, _ = _run()
    by_id = {item.capability_id: item for item in result.capability_matrix.payload.assessments}

    assert by_id["workbook_structure"].status == "verified_full"
    for partial in (
        "data_model_specification",
        "formulas",
        "controls",
        "security",
        "schedules",
        "saved_views",
        "embeds",
        "versions",
        "input_tables",
        "principal_visibility",
    ):
        assert by_id[partial].status in {"verified_partial", "manual_required"}
        assert by_id[partial].fallback is not None
    assert by_id["actions"].status == "manual_required"
    assert result.capability_matrix.payload.source_adapter_build_authorized is False


def test_whoami_mismatch_stops_before_selected_content_and_blocks():
    result, calls = _run(organization_id="wrong-org")

    assert result.status == "blocked"
    assert [(method, path) for method, path, _ in calls] == [
        ("POST", "/v2/auth/token"),
        ("GET", "/v2/whoami"),
    ]
    binding = next(
        item
        for item in result.capability_matrix.payload.assessments
        if item.capability_id == "tenant_principal_binding"
    )
    assert binding.status == "unavailable"
    assert binding.blocks_full_adapter is True


def test_missing_formula_property_blocks_even_when_endpoints_return_200():
    result, _ = _run(empty_columns=True)
    formula = next(
        item
        for item in result.capability_matrix.payload.assessments
        if item.capability_id == "formulas"
    )

    assert formula.status == "verified_partial"
    assert formula.blocks_full_adapter is True
    assert "capability:formulas" in result.blockers
    assert result.status == "blocked"


@pytest.mark.parametrize(
    "handler_options",
    [
        {"duplicate_model_sources": True},
        {"duplicate_workbook_inode_sources": True},
        {"mismatched_source_total": True},
    ],
)
def test_duplicate_ids_or_provider_total_mismatch_block_pagination(handler_options):
    result, _ = _run(**handler_options)
    pagination = next(
        item
        for item in result.capability_matrix.payload.assessments
        if item.capability_id == "pagination"
    )

    assert pagination.status == "unavailable"
    assert pagination.blocks_full_adapter is True
    assert "capability:pagination" in result.blockers


def test_request_budget_is_hard_and_observable():
    request = _request(request_budget=10, per_endpoint_request_budget=10)
    result, calls = _run(request=request)

    assert len(calls) == 10
    assert result.metrics.api_calls == 10
    assert result.metrics.request_budget_exhausted is True
    assert "Sigma API request budget was exhausted" in result.blockers
    assert result.status == "blocked"


def test_synthetic_fixture_can_exercise_code_but_never_open_capability_gate():
    result, _ = _run(request=_request(evidence_mode="synthetic_fixture"))

    assert result.status == "blocked"
    assert "live tenant evidence has not been collected" in result.blockers
    gate = next(
        item
        for item in result.gate_recommendations
        if item.gate_id == "sigma_api_capability_verified"
    )
    assert gate.state == "blocked"
    assert result.capability_matrix.payload.live_tenant_evidence is False


def test_cursor_is_hashed_in_observation_and_query_selectors_remain_auditable():
    result, calls = _run()
    cursor_call = next(
        call
        for call in calls
        if call[1] == "/v2/dataModels/dm-1/sources" and "pageToken" in call[2]
    )
    assert cursor_call[2]["pageToken"] == "opaque-cursor-2"

    cursor_observation = next(
        observation
        for observation in result.observations
        if observation.payload.endpoint == "/v2/dataModels/dm-1/sources"
        and "pageToken" in observation.payload.request_query
    )
    cursor_evidence = cursor_observation.payload.request_query["pageToken"]
    assert cursor_evidence["present"] is True
    assert len(cursor_evidence["sha256"]) == 64
    assert "opaque-cursor-2" not in json.dumps(cursor_observation.model_dump(mode="json"))


def test_required_endpoint_failure_is_a_final_blocker():
    result, _ = _run(missing_workbook_metadata=True)

    assert result.status == "blocked"
    assert any(
        blocker.startswith("acquisition:workbook_metadata_before:http_status")
        for blocker in result.blockers
    )
    identity = next(
        item
        for item in result.capability_matrix.payload.assessments
        if item.capability_id == "selected_object_identity"
    )
    assert identity.blocks_full_adapter is True


@pytest.mark.parametrize(
    ("handler_options", "expected_error"),
    [
        ({"cross_origin_bookmark_cursor": True}, "pagination_cross_origin"),
        ({"same_origin_endpoint_change": True}, "pagination_endpoint_change"),
    ],
)
def test_unsafe_continuation_blocks_even_on_optional_endpoint(handler_options, expected_error):
    result, _ = _run(**handler_options)

    assert result.status == "blocked"
    assert f"acquisition:workbook_bookmarks:{expected_error}" in result.blockers
    pagination = next(
        item
        for item in result.capability_matrix.payload.assessments
        if item.capability_id == "pagination"
    )
    assert pagination.status == "unavailable"
    assert pagination.blocks_full_adapter is True


def test_changed_pagination_selector_blocks_before_followup_read():
    result, calls = _run(changed_page_selector=True)

    assert result.status == "blocked"
    assert "acquisition:workbook_pages:pagination_selector_change" in result.blockers
    assert not any(
        path == "/v2/workbooks/wb-1/pages" and query.get("tag") == "other"
        for _, path, query in calls
    )


def test_missing_element_native_id_blocks_structure_closure():
    result, _ = _run(missing_element_id=True)

    structure = next(
        item
        for item in result.capability_matrix.payload.assessments
        if item.capability_id == "workbook_structure"
    )
    assert structure.status == "verified_partial"
    assert structure.blocks_full_adapter is True
    assert "capability:workbook_structure" in result.blockers
    assert result.status == "blocked"


@pytest.mark.parametrize(
    "handler_options",
    [
        {"workbook_version_drift": True},
        {"malformed_workbook_version": True},
        {"malformed_tag_source_version": True},
        {"wrong_data_model_version": True},
        {"data_model_version_drift": True},
    ],
)
def test_unstable_or_mismatched_source_freeze_blocks(handler_options):
    result, _ = _run(**handler_options)

    versions = next(
        item
        for item in result.capability_matrix.payload.assessments
        if item.capability_id == "versions"
    )
    assert versions.blocks_full_adapter is True
    assert "capability:versions" in result.blockers
    assert result.status == "blocked"


def test_orphan_formula_column_binding_blocks_and_is_not_graphed():
    result, _ = _run(orphan_workbook_column=True)

    formulas = next(
        item
        for item in result.capability_matrix.payload.assessments
        if item.capability_id == "formulas"
    )
    assert formulas.blocks_full_adapter is True
    assert "capability:formulas" in result.blockers
    assert "sigma.column.missing-element.workbook-column-1" not in {
        node.node_id for node in result.workbook_graph.payload.nodes
    }


def test_numeric_workbook_version_without_supported_definition_selector_blocks():
    request = _request()
    payload = request.model_dump(mode="json")
    payload["source_freeze"] = {
        **payload["source_freeze"],
        "strategy": "published_version",
        "workbook_tag_name": None,
        "workbook_published_version": 12,
        "source_reference": "sigma://workbooks/wb-1/versions/12",
    }
    result, _ = _run(
        request=SigmaCapabilitySpikeRequest.model_validate(payload),
        expected_workbook_tag=None,
    )

    assert result.status == "blocked"
    assert (
        "acquisition:workbook_definition_selector:workbook_definition_selector_unavailable"
        in result.blockers
    )

"""Sigma API acquisition tests use MockTransport only; no live tenant is required."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from omni_migrator.extractors.sigma.api import (
    SigmaApi,
    _safe_response_observation,
    normalize_sigma_connection_type,
)


def _handler(request: httpx.Request) -> httpx.Response:
    path = request.url.path
    if path == "/v2/auth/token":
        return httpx.Response(200, json={"access_token": "tok-1", "refresh_token": "refresh-1"})
    if path == "/v2/connections":
        return httpx.Response(
            200,
            json={"entries": [{"connectionId": "c1", "name": "Warehouse", "type": "bigQuery"}]},
        )
    if path == "/v2/dataModels":
        return httpx.Response(200, json={"entries": [{"dataModelId": "dm1", "name": "Sales"}]})
    if path == "/v2/dataModels/dm1/spec":
        return httpx.Response(200, json={"dataModelId": "dm1", "pages": []})
    if path == "/v2/dataModels/dm1/sources":
        return httpx.Response(
            200,
            json={"entries": [{"type": "table", "tableId": "table1"}]},
        )
    if path == "/v2/dataModels/dm1/columns":
        return httpx.Response(
            200,
            json={
                "entries": [
                    {
                        "columnId": "dm-col1",
                        "elementId": "dme1",
                        "name": "Revenue",
                        "formula": "Sum([Orders/Amount])",
                    }
                ]
            },
        )
    if path == "/v2/dataModels/dm1/lineage":
        return httpx.Response(
            200, json={"entries": [{"elementId": "dme1", "sourceIds": ["table1"]}]}
        )
    if path == "/v2/dataModels/dm1/materializationSchedules":
        return httpx.Response(200, json={"entries": [{"sheetId": "dme1", "paused": False}]})
    if path == "/v2/workbooks":
        return httpx.Response(200, json={"entries": [{"workbookId": "wb1", "name": "Ops"}]})
    if path == "/v2/workbooks/wb1/sources":
        return httpx.Response(
            200, json=[{"type": "data-model", "dataModelId": "dm1", "elementIds": ["dme1"]}]
        )
    if path == "/v2/workbooks/wb1/pages":
        return httpx.Response(
            200,
            json={"entries": [{"pageId": "p1", "name": "Overview", "hidden": False}]},
        )
    if path == "/v2/workbooks/wb1/pages/p1/elements":
        return httpx.Response(
            200,
            json={
                "entries": [
                    {
                        "elementId": "e1",
                        "name": "Revenue",
                        "type": "visualization",
                        "columns": ["col1"],
                    },
                    {"elementId": "ctl1", "name": "Region", "type": "control", "columns": []},
                ]
            },
        )
    if path == "/v2/workbooks/wb1/elements":
        return httpx.Response(
            200,
            json={
                "entries": [
                    {"elementId": "e1", "name": "Revenue", "type": "visualization"},
                    {"elementId": "ctl1", "name": "Region", "type": "control"},
                ]
            },
        )
    if path == "/v2/workbooks/wb1/columns":
        return httpx.Response(
            200,
            json={
                "entries": [
                    {
                        "columnId": "col1",
                        "elementId": "e1",
                        "label": "Revenue",
                        "formula": "Sum([Orders/Amount])",
                    }
                ]
            },
        )
    if path == "/v2/workbooks/wb1/controls":
        return httpx.Response(200, json={"entries": [{"name": "Region", "valueType": "text"}]})
    if path == "/v2/workbooks/wb1/queries":
        return httpx.Response(
            200,
            json={"entries": [{"elementId": "e1", "name": "Revenue", "sql": "select sum(amount)"}]},
        )
    if path == "/v2/workbooks/wb1/lineage":
        return httpx.Response(
            200,
            json={"entries": [{"elementId": "e1", "sourceIds": ["dme1"], "type": "element"}]},
        )
    if path == "/v2/grants":
        inode_id = request.url.params.get("inodeId")
        return httpx.Response(
            200,
            json={
                "entries": [
                    {"grantId": f"grant-{inode_id}", "inodeId": inode_id, "permission": "view"}
                ]
            },
        )
    if path == "/v2/workbooks/wb1/schedules":
        # Sigma supported this legacy list shape before making pagination mandatory.
        return httpx.Response(200, json=[{"scheduledNotificationId": "schedule1"}])
    if path == "/v2/workbooks/wb1/materialization-schedules":
        return httpx.Response(200, json={"entries": [{"sheetId": "e1", "paused": False}]})
    if path == "/v2/workbooks/wb1/elements/e1/columns":
        return httpx.Response(
            200,
            json={"entries": [{"columnId": "col1", "formula": "Sum([Orders/Amount])"}]},
        )
    if path == "/v2/workbooks/wb1/elements/e1/query":
        return httpx.Response(200, json={"elementId": "e1", "sql": "select sum(amount)"})
    if path == "/v2/workbooks/wb1/lineage/elements/e1":
        return httpx.Response(
            200,
            json={
                "dependencies": {"dme1": {"nodeId": "dme1", "type": "dataModel"}},
                "edges": [],
            },
        )
    return httpx.Response(404)


def _api(handler=_handler) -> SigmaApi:
    return SigmaApi(
        base_url="https://aws-api.sigmacomputing.com",
        client_id="cid",
        client_secret="secret",
        transport=httpx.MockTransport(handler),
    )


def test_login_sets_bearer_header_and_stores_refresh_token():
    api = _api()
    assert api.login() == "tok-1"
    assert api._http.headers["Authorization"] == "Bearer tok-1"
    assert api._refresh_token == "refresh-1"


def test_login_retries_transient_token_failures_with_a_bound(monkeypatch):
    attempts = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        assert request.url.path == "/v2/auth/token"
        attempts += 1
        if attempts < 3:
            return httpx.Response(503, headers={"Retry-After": "0"})
        return httpx.Response(200, json={"access_token": "tok-recovered"})

    monkeypatch.setattr("omni_migrator.extractors.sigma.api.time.sleep", lambda _: None)
    api = _api(handler)

    assert api.login() == "tok-recovered"
    assert attempts == 3


def test_retry_after_honors_delta_seconds_and_http_date():
    delta_response = httpx.Response(429, headers={"Retry-After": "60"})
    dated_response = httpx.Response(
        429,
        headers={
            "Date": "Wed, 02 Sep 2026 12:00:00 GMT",
            "Retry-After": "Wed, 02 Sep 2026 12:00:30 GMT",
        },
    )

    assert SigmaApi._retry_delay(delta_response, 0) == 60.0
    assert SigmaApi._retry_delay(dated_response, 0) == 30.0


def test_retry_after_over_bounded_wait_fails_closed():
    response = httpx.Response(429, headers={"Retry-After": "61"})

    with pytest.raises(RuntimeError, match="bounded retry window"):
        SigmaApi._retry_delay(response, 0)


def test_client_backoff_uses_bounded_jitter(monkeypatch):
    monkeypatch.setattr(
        "omni_migrator.extractors.sigma.api.random.uniform",
        lambda lower, upper: upper,
    )

    assert SigmaApi._retry_delay(httpx.Response(503), 0) == 0.2
    assert SigmaApi._retry_delay(httpx.Response(503), 20) == 2.0


def test_refresh_retries_transient_token_failures(monkeypatch):
    refresh_attempts = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal refresh_attempts
        assert request.url.path == "/v2/auth/token"
        if request.content and b"refresh_token" in request.content:
            refresh_attempts += 1
            if refresh_attempts == 1:
                return httpx.Response(429, headers={"Retry-After": "0"})
            return httpx.Response(200, json={"access_token": "tok-refreshed"})
        return httpx.Response(200, json={"access_token": "tok", "refresh_token": "refresh"})

    monkeypatch.setattr("omni_migrator.extractors.sigma.api.time.sleep", lambda _: None)
    api = _api(handler)
    api.login()

    assert api.refresh() == "tok-refreshed"
    assert refresh_attempts == 2


def test_api_repr_does_not_expose_credentials_or_tokens():
    api = _api()
    api.login()

    rendered = repr(api)

    assert "cid" not in rendered
    assert "secret" not in rendered
    assert "tok-1" not in rendered
    assert "refresh-1" not in rendered


@pytest.mark.parametrize(
    "unsafe",
    ("..", "../../members", "segment/child", "segment?admin=true", "segment#fragment", "%2e%2e"),
)
@pytest.mark.parametrize(
    "invoke",
    (
        lambda api, value: api.get_workbook(value),
        lambda api, value: api.data_model_spec(value),
        lambda api, value: api.workbook_page_elements("wb1", value),
        lambda api, value: api.data_model_element_query("dm1", value),
        lambda api, value: api.workbook_tagged_bookmarks("wb1", value),
    ),
)
def test_untrusted_dynamic_path_segments_fail_before_transport(unsafe, invoke):
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(500)

    with pytest.raises(ValueError, match="not a safe URL path segment"):
        invoke(_api(handler), unsafe)

    assert requests == []


def test_dynamic_path_segment_is_encoded_as_one_segment():
    raw_paths: list[bytes] = []

    def handler(request: httpx.Request) -> httpx.Response:
        raw_paths.append(request.url.raw_path)
        if request.url.path == "/v2/auth/token":
            return httpx.Response(200, json={"access_token": "tok"})
        return httpx.Response(200, json={"entries": []})

    assert _api(handler).workbook_tagged_bookmarks("wb1", "Release Candidate") == []
    assert raw_paths[-1].split(b"?", 1)[0] == (
        b"/v2/workbooks/wb1/tags/Release%20Candidate/bookmarks"
    )


def test_same_origin_pagination_cannot_change_the_approved_endpoint():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v2/auth/token":
            return httpx.Response(200, json={"access_token": "tok"})
        return httpx.Response(
            200,
            json={
                "entries": [{"workbookId": "wb1"}],
                "links": {"next": "/v2/members?page=2"},
            },
        )

    with pytest.raises(RuntimeError, match="another endpoint"):
        _api(handler).list_workbooks()


def test_same_origin_pagination_cannot_change_an_immutable_selector():
    requested_queries: list[dict[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v2/auth/token":
            return httpx.Response(200, json={"access_token": "tok"})
        requested_queries.append(dict(request.url.params))
        return httpx.Response(
            200,
            json={
                "entries": [{"pageId": "p1"}],
                "links": {"next": "/v2/workbooks/wb1/pages?tag=other&page=2"},
            },
        )

    with pytest.raises(RuntimeError, match="changed selector context"):
        _api(handler).workbook_pages("wb1", tag="approved-tag")

    assert requested_queries == [{"tag": "approved-tag", "limit": "1000"}]


def test_snapshot_rejects_untrusted_derived_page_id_before_followup_request():
    requested_paths: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested_paths.append(request.url.path)
        if request.url.path == "/v2/workbooks/wb1/pages":
            return httpx.Response(200, json={"entries": [{"pageId": "../../members"}]})
        return _handler(request)

    with pytest.raises(ValueError, match="page ID is not a safe URL path segment"):
        _api(handler).snapshot()

    assert "/members" not in requested_paths


def test_snapshot_rejects_non_scalar_derived_id_without_rendering_its_value():
    requested_urls: list[str] = []
    sensitive_id = "dict-page-id-secret"

    def handler(request: httpx.Request) -> httpx.Response:
        requested_urls.append(str(request.url))
        if request.url.path == "/v2/workbooks/wb1/pages":
            return httpx.Response(200, json={"entries": [{"pageId": {"secret": sensitive_id}}]})
        return _handler(request)

    with pytest.raises(ValueError, match="workbook page omitted pageId"):
        _api(handler).snapshot()

    assert sensitive_id not in json.dumps(requested_urls)


def test_observation_retains_only_top_level_whoami_user_id():
    schedule_request = httpx.Request(
        "GET", "https://aws-api.sigmacomputing.com/v2.1/workbooks/wb1/schedules"
    )
    schedule_response = httpx.Response(
        200,
        request=schedule_request,
        json={
            "entries": [
                {
                    "scheduleId": "schedule-1",
                    "recipients": [{"userId": "sensitive-recipient-id"}],
                    "dynamic-key@example.com": "present",
                    "sk-dynamic-secret-key": "present",
                }
            ]
        },
    )
    schedule_observation = _safe_response_observation(schedule_response, attempt=1)

    assert schedule_observation["exact_ids"] == {"scheduleId": ["schedule-1"]}
    assert "sensitive-recipient-id" not in json.dumps(schedule_observation)
    assert "dynamic-key@example.com" not in json.dumps(schedule_observation)
    assert "sk-dynamic-secret-key" not in json.dumps(schedule_observation)

    whoami_request = httpx.Request("GET", "https://aws-api.sigmacomputing.com/v2/whoami")
    whoami_response = httpx.Response(
        200,
        request=whoami_request,
        json={
            "organizationId": "organization-1",
            "userId": "credential-owner-id",
            "nested": {"userId": "nested-user-id"},
        },
    )
    whoami_observation = _safe_response_observation(whoami_response, attempt=1)

    assert whoami_observation["exact_ids"]["userId"] == ["credential-owner-id"]
    assert "nested-user-id" not in json.dumps(whoami_observation)

    malformed_response = httpx.Response(
        200,
        request=httpx.Request("GET", "https://aws-api.sigmacomputing.com/v2/workbooks"),
        json={"entries": [{"workbookId": {"secret": "nested-id-secret"}}]},
    )
    malformed_observation = _safe_response_observation(malformed_response, attempt=1)
    assert "nested-id-secret" not in json.dumps(malformed_observation)
    assert malformed_observation["exact_ids"] == {}


def test_observation_uses_grant_id_instead_of_repeated_foreign_inode_id():
    request = httpx.Request("GET", "https://aws-api.sigmacomputing.com/v2/grants?inodeId=wb1")
    response = httpx.Response(
        200,
        request=request,
        json={
            "entries": [
                {"grantId": "grant-1", "inodeId": "wb1", "permission": "view"},
                {"grantId": "grant-2", "inodeId": "wb1", "permission": "edit"},
            ]
        },
    )

    observation = _safe_response_observation(response, attempt=1)

    assert observation["primary_ids"] == {"grantId": ["grant-1", "grant-2"]}
    assert observation["duplicate_id_count"] == 0


def test_observation_retains_control_ids_and_detects_duplicates():
    request = httpx.Request("GET", "https://aws-api.sigmacomputing.com/v2/workbooks/wb1/controls")
    response = httpx.Response(
        200,
        request=request,
        json={
            "entries": [
                {"controlId": "control-1", "valueType": "text"},
                {"controlId": "control-1", "valueType": "text"},
            ]
        },
    )

    observation = _safe_response_observation(response, attempt=1)

    assert observation["exact_ids"]["controlId"] == ["control-1"]
    assert observation["primary_ids"] == {"controlId": ["control-1"]}
    assert observation["duplicate_id_count"] == 1


def test_endpoint_primary_ids_ignore_repeated_foreign_ids():
    cases = (
        (
            "/v2/workbooks/wb1/controls",
            [
                {"controlId": "control-1", "columnId": "shared-column"},
                {"controlId": "control-2", "columnId": "shared-column"},
            ],
            {"controlId": ["control-1", "control-2"]},
        ),
        (
            "/v2/workbooks/wb1/queries",
            [
                {"queryId": "query-1", "controlId": "shared-control"},
                {"queryId": "query-2", "controlId": "shared-control"},
            ],
            {"queryId": ["query-1", "query-2"]},
        ),
    )

    for endpoint, rows, expected in cases:
        response = httpx.Response(
            200,
            request=httpx.Request("GET", f"https://aws-api.sigmacomputing.com{endpoint}"),
            json={"entries": rows},
        )
        observation = _safe_response_observation(response, attempt=1)
        assert observation["primary_ids"] == expected
        assert observation["duplicate_id_count"] == 0


def test_documented_source_variants_use_compound_primary_identities():
    fixture = json.loads(
        (Path(__file__).parent / "fixtures/sigma/documented_source_contracts.json").read_text()
    )
    for owner, endpoint in (
        ("data_model", "/v2/dataModels/dm1/sources"),
        ("workbook", "/v2/workbooks/wb1/sources"),
    ):
        rows = fixture[f"{owner}_sources"]
        # Reusing a model, element, or custom SQL ID in a different binding is legitimate.
        rows.extend(
            [
                {
                    "type": "data-model",
                    "dataModelId": "upstream-model",
                    "elementIds": ["element-c"],
                    "versionTagId": "tag-1",
                },
                {
                    "type": "data-model",
                    "dataModelId": "upstream-model",
                    "elementIds": ["element-a"],
                    "versionTagId": "tag-2",
                },
                {
                    "type": "custom-sql",
                    "customSqlId": "custom-sql-1",
                    "connectionId": "warehouse-connection-2",
                    "definition": "select 2",
                },
            ]
        )
        observation = _safe_response_observation(
            httpx.Response(
                200,
                request=httpx.Request("GET", f"https://api.example.invalid{endpoint}"),
                json={"entries": rows},
            ),
            attempt=1,
        )
        bindings = [json.loads(value) for value in observation["primary_ids"]["sourceBinding"]]
        assert len(bindings) == 8
        assert observation["duplicate_id_count"] == 0
        assert observation["exact_ids"]["elementId"] == ["element-a", "element-b", "element-c"]
        assert observation["exact_ids"]["customSqlId"] == ["custom-sql-1"]
        assert observation["exact_ids"]["versionTagId"] == ["tag-1", "tag-2"]
        duplicate_observation = _safe_response_observation(
            httpx.Response(
                200,
                request=httpx.Request("GET", f"https://api.example.invalid{endpoint}"),
                json={"entries": [*rows, rows[0]]},
            ),
            attempt=1,
        )
        assert duplicate_observation["duplicate_id_count"] == 2


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("bigQuery", "bigquery"),
        ("some-future-type", "other"),
        (None, "other"),
    ],
)
def test_normalize_sigma_connection_type(raw, expected):
    assert normalize_sigma_connection_type(raw) == expected


def test_data_model_detail_endpoints():
    api = _api()

    assert api.data_model_spec("dm1")["dataModelId"] == "dm1"
    assert api.data_model_sources("dm1")[0]["tableId"] == "table1"
    assert api.data_model_columns("dm1")[0]["formula"] == "Sum([Orders/Amount])"
    assert api.data_model_lineage("dm1")[0]["sourceIds"] == ["table1"]
    assert api.data_model_grants("dm1")[0]["inodeId"] == "dm1"
    assert api.data_model_materialization_schedules("dm1")[0]["sheetId"] == "dme1"


def test_workbook_bulk_and_element_detail_endpoints():
    api = _api()

    assert api.workbook_sources("wb1")[0]["elementIds"] == ["dme1"]
    assert api.workbook_elements("wb1")[1]["type"] == "control"
    assert api.workbook_columns("wb1")[0]["formula"] == "Sum([Orders/Amount])"
    assert api.workbook_controls("wb1")[0]["name"] == "Region"
    assert api.workbook_queries("wb1")[0]["sql"] == "select sum(amount)"
    assert api.workbook_lineage("wb1")[0]["sourceIds"] == ["dme1"]
    assert api.workbook_grants("wb1")[0]["inodeId"] == "wb1"
    assert api.workbook_schedules("wb1")[0]["scheduledNotificationId"] == "schedule1"
    assert api.workbook_materialization_schedules("wb1")[0]["sheetId"] == "e1"
    assert api.workbook_element_columns("wb1", "e1")[0]["columnId"] == "col1"
    assert api.workbook_element_query("wb1", "e1")["elementId"] == "e1"
    assert "dme1" in api.workbook_element_lineage("wb1", "e1")["dependencies"]


def test_snapshot_assembles_full_acquisition_and_enriches_page_elements():
    api = _api()

    snapshot = api.snapshot()

    assert snapshot["connections"][0]["connectionId"] == "c1"
    (data_model,) = snapshot["dataModels"]
    assert data_model["spec"]["dataModelId"] == "dm1"
    assert data_model["sources"][0]["tableId"] == "table1"
    assert data_model["columns"][0]["formula"] == "Sum([Orders/Amount])"
    assert data_model["lineage"][0]["sourceIds"] == ["table1"]
    assert data_model["grants"][0]["grantId"] == "grant-dm1"
    assert data_model["materializationSchedules"][0]["sheetId"] == "dme1"

    (workbook,) = snapshot["workbooks"]
    assert workbook["sources"][0]["elementIds"] == ["dme1"]
    assert workbook["controls"][0]["name"] == "Region"
    assert workbook["queries"][0]["sql"] == "select sum(amount)"
    assert workbook["lineage"][0]["sourceIds"] == ["dme1"]
    assert workbook["grants"][0]["grantId"] == "grant-wb1"
    assert workbook["schedules"][0]["scheduledNotificationId"] == "schedule1"
    assert workbook["materializationSchedules"][0]["sheetId"] == "e1"

    (page,) = workbook["pages"]
    element = page["elements"][0]
    assert element["columns"] == [
        {
            "columnId": "col1",
            "elementId": "e1",
            "label": "Revenue",
            "formula": "Sum([Orders/Amount])",
        }
    ]
    assert element["generatedSql"]["sql"] == "select sum(amount)"
    assert element["lineage"][0]["sourceIds"] == ["dme1"]
    assert snapshot["diagnostics"] == []
    assert snapshot["_omnikit_acquisition"] == {
        "contract": "sigma-api-v2",
        "definitionClass": "authoritative_definition",
        "dataModelDefinitionEndpoint": "/v2/dataModels/{dataModelId}/spec?format=json",
        "workbookDefinitionClass": "content_evidence",
        "workbookSpecClaimed": False,
        "selectedDataModelIds": ["dm1"],
        "selectedWorkbookIds": ["wb1"],
        "optional_endpoint_diagnostic_count": 0,
    }

    serialized = json.dumps(snapshot)
    assert "secret" not in serialized
    assert "tok-1" not in serialized
    assert "refresh-1" not in serialized


def test_pagination_follows_cursor_and_preserves_filter_params():
    requests: list[dict[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v2/auth/token":
            return httpx.Response(200, json={"access_token": "tok"})
        if request.url.path == "/v2/grants":
            requests.append(dict(request.url.params))
            if request.url.params.get("page") is None:
                return httpx.Response(
                    200,
                    json={
                        "entries": [{"grantId": "g1"}],
                        "nextPage": "cursor-2",
                        "total": 2,
                        "hasMore": True,
                    },
                )
            return httpx.Response(
                200,
                json={
                    "entries": [{"grantId": "g2"}],
                    "nextPage": None,
                    "total": 2,
                    "hasMore": False,
                },
            )
        return httpx.Response(404)

    grants = _api(handler).list_grants("wb1")

    assert [grant["grantId"] for grant in grants] == ["g1", "g2"]
    assert requests == [
        {"inodeId": "wb1", "limit": "1000"},
        {"inodeId": "wb1", "limit": "1000", "page": "cursor-2"},
    ]


def test_pagination_supports_nested_payload_and_same_origin_next_link():
    queries: list[dict[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v2/auth/token":
            return httpx.Response(200, json={"access_token": "tok"})
        if request.url.path == "/v2/connections":
            queries.append(dict(request.url.params))
            if request.url.params.get("cursor") == "two":
                return httpx.Response(200, json={"data": {"entries": [{"id": "c2"}]}})
            return httpx.Response(
                200,
                json={
                    "data": {
                        "entries": [{"id": "c1"}],
                        "links": {"next": "?cursor=two"},
                    }
                },
            )
        return httpx.Response(404)

    assert [row["id"] for row in _api(handler).list_connections()] == ["c1", "c2"]
    assert queries == [{"limit": "1000"}, {"cursor": "two", "limit": "1000"}]


def test_pagination_supports_next_page_token():
    requests: list[dict[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v2/auth/token":
            return httpx.Response(200, json={"access_token": "tok"})
        if request.url.path == "/v2/connections":
            requests.append(dict(request.url.params))
            if request.url.params.get("pageToken") == "token-2":
                return httpx.Response(200, json={"entries": [{"id": "c2"}]})
            return httpx.Response(
                200,
                json={"entries": [{"id": "c1"}], "nextPageToken": "token-2"},
            )
        return httpx.Response(404)

    assert [row["id"] for row in _api(handler).list_connections()] == ["c1", "c2"]
    assert requests == [
        {"limit": "1000"},
        {"limit": "1000", "pageToken": "token-2"},
    ]


def test_per_endpoint_request_budget_stops_runaway_pagination():
    page = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal page
        if request.url.path == "/v2/auth/token":
            return httpx.Response(200, json={"access_token": "tok"})
        page += 1
        return httpx.Response(
            200,
            json={
                "entries": [{"connectionId": f"connection-{page}"}],
                "links": {"next": f"?cursor={page + 1}"},
            },
        )

    api = _api(handler)
    api.request_budget = 100
    api.per_endpoint_request_budget = 3

    with pytest.raises(RuntimeError, match="per-endpoint request budget exhausted"):
        api.list_connections()

    assert page == 3


def test_data_model_materialization_schedules_use_documented_cursor_contract():
    requests: list[dict[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v2/auth/token":
            return httpx.Response(200, json={"access_token": "tok"})
        if request.url.path == "/v2/dataModels/dm1/materializationSchedules":
            assert int(request.url.params["pageSize"]) <= 500
            requests.append(dict(request.url.params))
            if request.url.params.get("pageToken") == "schedule-token-2":
                return httpx.Response(200, json={"entries": [{"scheduleId": "schedule-2"}]})
            return httpx.Response(
                200,
                json={
                    "entries": [{"scheduleId": "schedule-1"}],
                    "nextPageToken": "schedule-token-2",
                },
            )
        return httpx.Response(404)

    schedules = _api(handler).data_model_materialization_schedules("dm1")

    assert [schedule["scheduleId"] for schedule in schedules] == ["schedule-1", "schedule-2"]
    assert requests == [
        {"pageSize": "500"},
        {"pageSize": "500", "pageToken": "schedule-token-2"},
    ]


def test_pagination_rejects_repeated_cursor_instead_of_looping():
    calls = {"connections": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v2/auth/token":
            return httpx.Response(200, json={"access_token": "tok"})
        if request.url.path == "/v2/connections":
            calls["connections"] += 1
            return httpx.Response(
                200, json={"entries": [{"id": calls["connections"]}], "nextPage": "same"}
            )
        return httpx.Response(404)

    with pytest.raises(RuntimeError, match="repeated its continuation"):
        _api(handler).list_connections()
    assert calls["connections"] == 2


def test_pagination_rejects_cross_origin_next_link_before_token_can_leak():
    hosts: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        hosts.append(request.url.host)
        if request.url.path == "/v2/auth/token":
            return httpx.Response(200, json={"access_token": "tok"})
        return httpx.Response(
            200,
            json={
                "entries": [{"id": "c1"}],
                "next": "https://attacker.example/v2/connections?page=2",
            },
        )

    with pytest.raises(RuntimeError, match="another origin"):
        _api(handler).list_connections()
    assert hosts == ["aws-api.sigmacomputing.com", "aws-api.sigmacomputing.com"]


def test_get_retries_rate_limit_during_pagination():
    calls = {"connections": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v2/auth/token":
            return httpx.Response(200, json={"access_token": "tok"})
        if request.url.path == "/v2/connections":
            calls["connections"] += 1
            if calls["connections"] == 1:
                return httpx.Response(429, headers={"Retry-After": "0"})
            return httpx.Response(200, json={"entries": [{"connectionId": "c1"}]})
        return httpx.Response(404)

    assert _api(handler).list_connections()[0]["connectionId"] == "c1"
    assert calls["connections"] == 2


def test_optional_endpoint_failures_are_diagnostic_and_do_not_store_error_bodies():
    optional_paths = {
        "/v2/dataModels/dm1/sources",
        "/v2/dataModels/dm1/columns",
        "/v2/dataModels/dm1/lineage",
        "/v2/dataModels/dm1/materializationSchedules",
        "/v2/grants",
        "/v2/workbooks/wb1/sources",
        "/v2/workbooks/wb1/elements",
        "/v2/workbooks/wb1/columns",
        "/v2/workbooks/wb1/controls",
        "/v2/workbooks/wb1/queries",
        "/v2/workbooks/wb1/lineage",
        "/v2/workbooks/wb1/schedules",
        "/v2/workbooks/wb1/materialization-schedules",
    }

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path in optional_paths:
            return httpx.Response(403, json={"message": "private-secret-from-server"})
        return _handler(request)

    snapshot = _api(handler).snapshot()

    operations = {item["operation"] for item in snapshot["diagnostics"]}
    assert "data_model_columns" in operations
    assert "workbook_queries" in operations
    assert "workbook_schedules" in operations
    assert all(item["status_code"] == 403 for item in snapshot["diagnostics"])
    workbook = snapshot["workbooks"][0]
    assert workbook["controls"][0]["elementId"] == "ctl1"
    assert workbook["columns"][0]["formula"] == "Sum([Orders/Amount])"
    assert workbook["queries"][0]["sql"] == "select sum(amount)"
    assert workbook["lineage"][0]["dependencies"]["dme1"]["type"] == "dataModel"
    assert "private-secret-from-server" not in json.dumps(snapshot)
    assert snapshot["_omnikit_acquisition"]["optional_endpoint_diagnostic_count"] == len(
        snapshot["diagnostics"]
    )


def test_optional_endpoint_does_not_hide_transient_server_failure():
    attempts = {"sources": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v2/workbooks/wb1/sources":
            attempts["sources"] += 1
            return httpx.Response(503, headers={"Retry-After": "0"})
        return _handler(request)

    with pytest.raises(httpx.HTTPStatusError):
        _api(handler).snapshot()
    assert attempts["sources"] == 3


def test_token_refresh_on_401_then_retries():
    calls = {"connections": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v2/auth/token":
            if request.content and b"refresh_token" in request.content:
                return httpx.Response(
                    200, json={"access_token": "tok-2", "refresh_token": "refresh-2"}
                )
            return httpx.Response(200, json={"access_token": "tok-1", "refresh_token": "refresh-1"})
        if request.url.path == "/v2/connections":
            calls["connections"] += 1
            if request.headers.get("Authorization") == "Bearer tok-1":
                return httpx.Response(401)
            return httpx.Response(200, json={"entries": []})
        return httpx.Response(404)

    api = _api(handler)
    api.list_connections()

    assert calls["connections"] == 2
    assert api._http.headers["Authorization"] == "Bearer tok-2"

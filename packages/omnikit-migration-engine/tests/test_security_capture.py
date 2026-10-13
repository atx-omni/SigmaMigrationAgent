"""Selected lineage and aggregate capture limits use fictional local responses."""
from __future__ import annotations

import json

import httpx
import pytest

from omni_migrator.extractors.sigma import api as sigma
from omni_migrator.prepush.discovery import OmniReader
from omni_migrator.security.transport import ByteBudget, ResourceLimitError
from tests.test_security_transport import CountedStream
from tests.test_sigma_api import _api, _handler


def scoped_handler(request):
    if request.url.path == "/v2/connections":
        return httpx.Response(200, json={"entries": [
            {"connectionId": "c1", "type": "bigQuery", "name": "selected-private-name", "host": "private-host", "user": "private-user"},
            {"connectionId": "unrelated-payroll", "type": "snowflake", "name": "payroll-name", "host": "payroll-host", "user": "payroll-user"},
        ]})
    return _handler(request)


def test_capture_saves_only_verified_connections_and_minimal_properties():
    snapshot = _api(scoped_handler).snapshot(data_model_ids=["dm1"], workbook_ids=["wb1"])
    assert snapshot["connections"] == [{"connectionId": "c1", "type": "bigQuery"}]
    serialized = json.dumps(snapshot)
    for value in ("unrelated-payroll", "payroll-host", "payroll-name", "private-host", "private-user", "selected-private-name"):
        assert value not in serialized


def test_broader_connection_inventory_is_explicit_and_still_minimized():
    snapshot = _api(scoped_handler).snapshot(include_all_connections=True)
    assert {row["connectionId"] for row in snapshot["connections"]} == {"c1", "unrelated-payroll"}
    assert all(set(row) == {"connectionId", "type"} for row in snapshot["connections"])
    assert snapshot["_omnikit_acquisition"]["connection_scope"] == "explicit_minimized_inventory"


@pytest.mark.parametrize("failure", ["missing_connection", "upstream_missing", "sources_denied", "bad_source"])
def test_incomplete_lineage_never_returns_snapshot_or_collects_connections(failure):
    requests = []
    def handler(request):
        requests.append(request.url.path)
        if request.url.path == "/v2/dataModels/dm1/sources":
            if failure == "missing_connection":
                return httpx.Response(200, json={"entries": [{"type": "table", "tableId": "t1"}]})
            if failure == "bad_source":
                return httpx.Response(200, json={"entries": [{"connectionId": "c1", "private": "do-not-echo"}]})
        if request.url.path == "/v2/workbooks/wb1/sources":
            if failure == "sources_denied":
                return httpx.Response(403, json={"message": "do-not-echo"})
            if failure == "upstream_missing":
                return httpx.Response(200, json={"entries": [{"type": "data-model", "dataModelId": "other-model", "elementIds": ["e1"]}]})
        return _handler(request)
    with pytest.raises(sigma.ConnectionLineageError) as error:
        _api(handler).snapshot()
    assert error.value.diagnostics[0]["status"] == "incomplete"
    assert "do-not-echo" not in str(error.value)
    assert "/v2/connections" not in requests


def test_unknown_and_duplicate_required_connections_block():
    for rows in ([], [{"connectionId": "c1"}, {"connectionId": "c1"}]):
        with pytest.raises(sigma.ConnectionLineageError):
            sigma._minimized_connections(rows, {"c1"}, include_all=False)


def test_capture_final_size_limit_is_enforced_after_enrichment(monkeypatch):
    monkeypatch.setattr(sigma, "AGGREGATE_BYTES", 100)
    with pytest.raises(ResourceLimitError, match="Final snapshot"):
        _api().snapshot()


def test_sigma_token_and_get_paths_enforce_cumulative_bytes_without_retry():
    api = _api()
    api._byte_budget = ByteBudget(max_bytes=100)
    api.login()
    with pytest.raises(ResourceLimitError, match="Aggregate"):
        api.list_connections()
    assert api.request_count == 2


@pytest.mark.parametrize("path", ["token", "get"])
def test_sigma_stream_limit_covers_token_and_error_body(path):
    stream = CountedStream([b"x" * (16 * 1024)] * 600)
    def handler(request):
        if request.url.path == "/v2/auth/token" and path != "token":
            return _handler(request)
        return httpx.Response(503, stream=stream)
    api = _api(handler)
    with pytest.raises(ResourceLimitError, match="size"):
        api.list_connections()
    assert stream.reads < 400 and stream.closed
    assert api.request_count == (1 if path == "token" else 2)


def test_sigma_record_limit_prevents_accumulating_unbounded_pages(monkeypatch):
    monkeypatch.setattr(sigma, "MAX_PAGINATION_RECORDS", 1)
    def handler(request):
        if request.url.path == "/v2/connections":
            return httpx.Response(200, json={"entries": [{"connectionId": "c1"}, {"connectionId": "c2"}]})
        return _handler(request)
    with pytest.raises(ResourceLimitError, match="record"):
        _api(handler).list_connections()


def test_optional_endpoint_cannot_swallow_a_transport_limit():
    stream = CountedStream([b"x" * (16 * 1024)] * 600)
    def handler(request):
        if request.url.path == "/v2/workbooks/wb1/queries":
            return httpx.Response(403, stream=stream)
        return _handler(request)
    with pytest.raises(ResourceLimitError, match="size"):
        _api(handler).snapshot()
    assert stream.closed and stream.reads < 400


def test_omni_stops_oversize_before_consuming_full_response(monkeypatch):
    original = httpx.Client
    stream = CountedStream([b"x" * (16 * 1024)] * 600)
    monkeypatch.setattr(httpx, "Client", lambda **kwargs: original(**kwargs, transport=httpx.MockTransport(
        lambda request: httpx.Response(200, stream=stream))))
    reader = OmniReader({"target_auth": "token", "omni_origin": "https://example.invalid"}, {"OMNI_API_TOKEN": "fictional"})
    with pytest.raises(ResourceLimitError, match="size"):
        reader.read("/api/v1/whoami", ["whoami", "whoami"])
    assert stream.reads < 400 and stream.closed


def test_omni_aggregate_budget_persists_across_reads(monkeypatch):
    original = httpx.Client
    monkeypatch.setattr(httpx, "Client", lambda **kwargs: original(**kwargs, transport=httpx.MockTransport(
        lambda request: httpx.Response(200, json={"id": "fictional"}))))
    reader = OmniReader({"target_auth": "token", "omni_origin": "https://example.invalid"}, {"OMNI_API_TOKEN": "fictional"})
    reader.byte_budget = ByteBudget(max_bytes=25)
    assert reader.read("/api/v1/whoami", []) == {"id": "fictional"}
    with pytest.raises(ResourceLimitError, match="Aggregate"):
        reader.read("/api/v1/whoami", [])

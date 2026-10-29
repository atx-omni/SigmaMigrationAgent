"""Selected-tag and export lifecycle tests under a denied socket boundary."""
import json
import socket
import httpx
import pytest
from omni_migrator.extractors.sigma.api import SigmaApi
from omni_migrator.security.transport import ResourceLimitError


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def denied(*args, **kwargs):
        raise AssertionError("network forbidden")
    monkeypatch.setattr(socket, "getaddrinfo", denied)
    monkeypatch.setattr(socket.socket, "connect", denied)


def api(handler):
    result = SigmaApi("https://api.sigmacomputing.com", "synthetic", "synthetic", httpx.MockTransport(handler))
    result._token = "synthetic"
    result._http.headers["Authorization"] = "Bearer synthetic"
    return result


def test_tag_capture_is_explicit_and_untagged_fields_not_mixed():
    def handler(request):
        if request.url.path.endswith("/pages"):
            assert request.url.params["tag"] == "approved"
            return httpx.Response(200, json=[{"pageId": "p1"}])
        if request.url.path.endswith("/elements"):
            assert request.url.params.get("tag", request.url.params.get("tagName")) == "approved"
            return httpx.Response(200, json=[{"elementId": "e1"}])
        if request.url.path.endswith("/tags"):
            return httpx.Response(200, json=[{"name": "approved", "version": 3}])
        return httpx.Response(200, json={"workbookId": "w1", "version": 3})
    snapshot = api(handler).workbook_snapshot("w1", tag="approved")
    assert snapshot["pages"][0]["elements"][0]["elementId"] == "e1"
    assert not snapshot["translation_ready"]
    assert "controls" not in snapshot


def test_drift_blocks():
    versions = []
    def handler(request):
        if request.url.path == "/v2/workbooks/w1":
            versions.append(1)
            return httpx.Response(200, json={"version": len(versions)})
        return httpx.Response(200, json=[])
    with pytest.raises(ValueError, match="changed"):
        api(handler).workbook_snapshot("w1", tag="approved")


def test_export_once_then_binary_download():
    calls = []
    def handler(request):
        calls.append(request)
        if request.method == "POST":
            assert json.loads(request.content)["tag"] == "approved"
            return httpx.Response(200, json={"queryId": "q1", "jobComplete": False})
        return httpx.Response(200, content=b"\x89PNG\r\n\x1a\nsynthetic", headers={"content-type": "image/png"})
    client = api(handler)
    result = client.export_workbook("w1", tag="approved", format={"type": "png"})
    response = client.download_export(result["queryId"])
    assert response.content.startswith(b"\x89PNG") and len(calls) == 2


@pytest.mark.parametrize("status", [202, 403, 404, 410, 429])
def test_download_retains_unclassified_status(status):
    assert api(lambda request: httpx.Response(status)).download_export("q1").status_code == status


def test_export_post_not_replayed_on_failure():
    calls = []
    def handler(request):
        calls.append(request)
        return httpx.Response(503)
    with pytest.raises(httpx.HTTPStatusError):
        api(handler).export_workbook("w1", tag="approved", format={"type": "pdf"})
    assert len(calls) == 1


def test_download_binary_limit_and_redirect_not_followed():
    client = api(lambda request: httpx.Response(200, headers={"content-length": "999999999"}))
    with pytest.raises(ResourceLimitError):
        client.download_export("q1")
    assert api(lambda request: httpx.Response(302, headers={"location": "https://evil.example"})).download_export("q1").status_code == 302

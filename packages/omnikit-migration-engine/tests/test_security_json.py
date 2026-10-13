"""Synthetic JSON encoding regressions; no live services or real credentials."""
from __future__ import annotations

import argparse
import codecs
import hashlib
import json

import httpx
import pytest

from omni_migrator.extractors.sigma import api as sigma
from omni_migrator.prepush import discovery
from omni_migrator.prepush.capture import capture
from omni_migrator.security import transport
from tests.test_security_transport import CountedStream, client_for
from tests.test_sigma_api import _api, _handler


ENCODINGS = [
    ("utf-16-le", b""), ("utf-16-be", b""),
    ("utf-32-le", b""), ("utf-32-be", b""),
    ("utf-16-le", codecs.BOM_UTF16_LE), ("utf-16-be", codecs.BOM_UTF16_BE),
    ("utf-32-le", codecs.BOM_UTF32_LE), ("utf-32-be", codecs.BOM_UTF32_BE),
]


def escaped_quote_payload(depth=90):
    value = 0
    for _ in range(depth):
        value = [value]
    # The escaped quote made byte-level validation misread UTF-16/32 quote state.
    return json.dumps({"label": '"', "nested": value}, separators=(",", ":"))


@pytest.mark.parametrize("encoding,bom", ENCODINGS)
@pytest.mark.parametrize("depth", [1, 90])
def test_non_utf8_json_is_rejected_with_and_without_bom(encoding, bom, depth):
    raw = bom + escaped_quote_payload(depth).encode(encoding)
    with pytest.raises(transport.JsonResponseError):
        transport.check_json_structure(raw)
    with pytest.raises(transport.JsonResponseError):
        transport.parse_json_bytes(raw)
    with client_for(CountedStream([raw])) as client:
        with pytest.raises(transport.JsonResponseError):
            transport.bounded_request(client, "GET", "https://example.invalid")


@pytest.mark.parametrize("raw", [
    b'{"label":"synthetic-private-\xff"}', b'{"label":"\xc0\xaf"}',
    b'{"label":"\x00"}', codecs.BOM_UTF8 * 2 + b"{}",
    b"", b" \n\t", b'{"synthetic-private-label":',
])
def test_invalid_encoding_bom_or_json_fails_without_body_details(raw):
    with pytest.raises(transport.JsonResponseError) as error:
        transport.parse_json_bytes(raw)
    assert "synthetic-private" not in str(error.value)


@pytest.mark.parametrize("content_type", [
    "application/json; charset=utf-16", "application/json; charset=utf-32",
    "application/json; charset=latin-1", "application/json; charset=unknown",
    "application/json; charset=", "application/json; charset=utf-8; charset=utf-16",
    "application/json; charset=utf-8; charset=utf-8",
])
def test_incompatible_or_ambiguous_charset_is_not_used_to_decode(content_type):
    with pytest.raises(transport.JsonResponseError, match="charset"):
        transport.response_json(httpx.Response(200, content=b"{}", headers={"content-type": content_type}))


@pytest.mark.parametrize("bom", [b"", codecs.BOM_UTF8])
@pytest.mark.parametrize("content_type", [None, "application/json", 'application/json; charset="UTF-8"', "application/json; charset=utf8"])
def test_unicode_and_one_leading_utf8_bom_use_same_checked_and_parsed_text(monkeypatch, bom, content_type):
    value = {"名前": "café 🧭", "quote": '\\"[[,', "escaped_nul": "\x00"}
    text = json.dumps(value, ensure_ascii=False)
    checked, parsed = [], []
    real_check, real_loads = transport.check_json_structure, json.loads

    def check(candidate, **kwargs):
        checked.append(candidate)
        return real_check(candidate, **kwargs)

    def parse(candidate, **kwargs):
        parsed.append(candidate)
        assert isinstance(candidate, str)
        return real_loads(candidate, **kwargs)

    monkeypatch.setattr(transport, "check_json_structure", check)
    monkeypatch.setattr(transport.json, "loads", parse)
    raw = bom + text.encode("utf-8")
    assert transport.parse_json_bytes(raw, content_type=content_type) == value
    assert checked == parsed == [text]


def test_depth_and_item_limits_check_decoded_structure_before_parser(monkeypatch):
    # 64 arrays is the inclusive depth boundary, including a leading UTF-8 BOM.
    accepted = codecs.BOM_UTF8 + b"[" * 64 + b"0" + b"]" * 64
    transport.parse_json_bytes(accepted)
    assert transport.parse_json_bytes(b"[0,0,0]", max_items=3) == [0, 0, 0]
    # Container/commas inside escaped strings are not structural items.
    assert transport.parse_json_bytes(b'["\\\"[[,,,,",0,0]', max_items=3) == ['"[[,,,,', 0, 0]

    def no_parse(_):
        pytest.fail("The parser must not see a structurally over-limit document")

    monkeypatch.setattr(transport.json, "loads", no_parse)
    for raw, limits in (
        (b"[" * 65 + b"0" + b"]" * 65, {}),
        (escaped_quote_payload().encode("utf-8"), {}),
        (b"[0,0,0,0]", {"max_items": 3}),
    ):
        with pytest.raises(transport.ResourceLimitError, match="structure"):
            transport.parse_json_bytes(raw, **limits)


@pytest.mark.parametrize("aggregate", [False, True])
def test_byte_caps_are_independent_of_invalid_json_encoding(aggregate):
    stream = CountedStream([escaped_quote_payload().encode("utf-16")])
    limits = {"budget": transport.ByteBudget(max_bytes=64)} if aggregate else {"max_bytes": 64}
    with client_for(stream) as client:
        with pytest.raises(transport.ResourceLimitError, match="size"):
            transport.bounded_request(client, "GET", "https://example.invalid", **limits)
    assert stream.closed


@pytest.mark.parametrize("method,args,path", [
    ("login", (), "/v2/auth/token"), ("refresh", (), "/v2/auth/token"),
    ("whoami", (), "/v2/whoami"), ("get_data_model", ("dm1",), "/v2/dataModels/dm1"),
    ("data_model_spec", ("dm1",), "/v2/dataModels/dm1/spec"),
    ("data_model_element_query", ("dm1", "e1"), "/v2/dataModels/dm1/elements/e1/query"),
    ("get_workbook", ("wb1",), "/v2/workbooks/wb1"),
    ("workbook_element_query", ("wb1", "e1"), "/v2/workbooks/wb1/elements/e1/query"),
    ("workbook_element_lineage", ("wb1", "e1"), "/v2/workbooks/wb1/lineage/elements/e1"),
    ("list_connections", (), "/v2/connections"),
])
def test_all_sigma_read_paths_avoid_httpx_json_autodetection(monkeypatch, method, args, path):
    value = {"access_token": "synthetic", "entries": [], "label": "café 🧭"}
    raw = codecs.BOM_UTF8 + json.dumps(value, ensure_ascii=False).encode("utf-8")

    def handler(request):
        return httpx.Response(200, content=raw) if request.url.path == path else _handler(request)

    def no_autodetect(_):
        pytest.fail("HTTPX byte auto-detection must not parse migration JSON")

    monkeypatch.setattr(httpx.Response, "json", no_autodetect)
    api = _api(handler)
    api._refresh_token = "synthetic-refresh"
    observations = []
    api.observation_sink = observations.append
    try:
        result = getattr(api, method)(*args)
    finally:
        api.close()
    expected = "synthetic" if method in {"login", "refresh"} else [] if method == "list_connections" else value
    assert result == expected
    if observations:
        assert observations[-1]["json_valid"] is True
        assert observations[-1]["response_bytes"] == len(raw)
        assert observations[-1]["response_body_sha256"] == hashlib.sha256(raw).hexdigest()


@pytest.mark.parametrize("method,path", [("login", "/v2/auth/token"), ("list_connections", "/v2/connections")])
def test_sigma_auth_and_paginated_metadata_reject_invalid_encoding(method, path):
    def handler(request):
        if request.url.path == path:
            return httpx.Response(200, content=escaped_quote_payload().encode("utf-16"))
        return _handler(request)

    api = _api(handler)
    try:
        with pytest.raises(transport.JsonResponseError):
            getattr(api, method)()
    finally:
        api.close()


def install_omni_reader(monkeypatch, auth, handler):
    if auth == "token":
        real_client = httpx.Client
        monkeypatch.setattr(httpx, "Client", lambda **kwargs: real_client(**kwargs, transport=httpx.MockTransport(handler)))
    else:
        monkeypatch.setattr(discovery.shutil, "which", lambda _: "/synthetic/omni")

        def run(*args, **kwargs):
            response = handler(httpx.Request("GET", "https://example.invalid"))
            return argparse.Namespace(returncode=0, stdout=response.content, stderr=b"")

        monkeypatch.setattr(discovery, "bounded_process", run)
    profile = {"target_auth": auth, "omni_origin": "https://example.invalid", "omni_profile": "synthetic"}
    return discovery.OmniReader(profile, {"OMNI_API_TOKEN": "synthetic"})


@pytest.mark.parametrize("auth", ["token", "oauth"])
@pytest.mark.parametrize("encoding,bom", ENCODINGS)
def test_omni_http_and_oauth_reject_non_utf8_json(monkeypatch, auth, encoding, bom):
    raw = bom + escaped_quote_payload().encode(encoding)
    reader = install_omni_reader(monkeypatch, auth, lambda _: httpx.Response(200, content=raw))
    with pytest.raises((transport.JsonResponseError, discovery.DiscoveryError)):
        reader.read("/api/v1/whoami", ["whoami", "whoami"])


@pytest.mark.parametrize("auth", ["token", "oauth"])
@pytest.mark.parametrize("bom", [b"", codecs.BOM_UTF8])
def test_omni_http_and_oauth_accept_unicode_and_single_bom(monkeypatch, auth, bom):
    value = {"keyScope": "user", "label": "café 🧭"}
    raw = bom + json.dumps(value, ensure_ascii=False).encode("utf-8")
    reader = install_omni_reader(monkeypatch, auth, lambda _: httpx.Response(200, content=raw))
    assert reader.read("/api/v1/whoami", ["whoami", "whoami"]) == value


@pytest.mark.parametrize("raw", [b"", b"<html>synthetic-private-error</html>", b"\xff\x00"])
@pytest.mark.parametrize("status", [401, 403, 429])
def test_sigma_errors_preserve_status_retry_and_sanitized_diagnostics(monkeypatch, raw, status):
    monkeypatch.setattr(sigma.time, "sleep", lambda _: None)

    def handler(request):
        if request.url.path == "/v2/auth/token":
            return _handler(request)
        return httpx.Response(status, content=raw, headers={"content-type": "application/json; charset=utf-16"})

    api = _api(handler)
    observations = []
    api.observation_sink = observations.append
    try:
        with pytest.raises(httpx.HTTPStatusError) as error:
            api.list_connections()
        assert error.value.response.status_code == status
        assert "synthetic-private" not in str(discovery.safe_failure(error.value))
        assert all(item["json_valid"] is False for item in observations)
        assert len(observations) == (sigma.MAX_GET_ATTEMPTS if status == 429 else 2 if status == 401 else 1)
    finally:
        api.close()


@pytest.mark.parametrize("raw", [b"", b"synthetic-private-error", b"\xff\x00"])
def test_omni_non_json_error_retains_status_without_body_details(monkeypatch, raw):
    reader = install_omni_reader(monkeypatch, "token", lambda _: httpx.Response(403, content=raw))
    with pytest.raises(httpx.HTTPStatusError) as error:
        reader.read("/api/v1/whoami", [])
    assert error.value.response.status_code == 403
    assert "synthetic-private" not in str(discovery.safe_failure(error.value))


@pytest.mark.parametrize("raw", [escaped_quote_payload().encode("utf-16"), b'{"invalid":'])
@pytest.mark.parametrize("path", ["/v2/dataModels/dm1/spec", "/v2/workbooks/wb1/queries"])
def test_capture_rejects_bad_required_or_optional_data_without_persisting(tmp_path, monkeypatch, raw, path):
    real_api = sigma.SigmaApi
    requests = []

    def handler(request):
        requests.append(request.url.path)
        return httpx.Response(200, content=raw) if request.url.path == path else _handler(request)

    monkeypatch.setattr(sigma, "SigmaApi", lambda **kwargs: real_api(**kwargs, transport=httpx.MockTransport(handler)))
    monkeypatch.setenv("SIGMA_CLIENT_ID", "synthetic")
    monkeypatch.setenv("SIGMA_CLIENT_SECRET", "synthetic")
    out = tmp_path / "capture.json"
    args = argparse.Namespace(allow_source_read=True, output=out, profile=None, env_file=None,
        api_url="https://example.invalid", trusted_api_host="example.invalid", workbook_id="wb1",
        data_model_id="dm1", request_budget=100)
    with pytest.raises(ValueError):
        capture(args)
    assert path in requests
    assert not out.exists()
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("auth", ["token", "oauth"])
def test_discovery_bad_late_response_does_not_persist_partial_inventory(tmp_path, monkeypatch, auth):
    responses = iter([
        httpx.Response(200, json={"keyScope": "user"}),
        httpx.Response(200, json={"connections": []}),
        httpx.Response(200, content=escaped_quote_payload().encode("utf-32")),
    ])
    reader = install_omni_reader(monkeypatch, auth, lambda _: next(responses))
    monkeypatch.setattr(discovery, "load_profile", lambda _: reader.profile)
    monkeypatch.setattr(discovery, "resolve", lambda *args, **kwargs: reader.values)
    out = tmp_path / "discovery.json"
    args = argparse.Namespace(allow_target_read=True, output=out, profile=None, env_file=None,
                              model_id=None, topic=None)
    with pytest.raises(ValueError):
        discovery.discover(args)
    assert not out.exists()
    assert list(tmp_path.iterdir()) == []

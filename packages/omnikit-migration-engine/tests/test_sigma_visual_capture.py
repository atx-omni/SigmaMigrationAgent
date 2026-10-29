"""Actual producer and persisted bytes under a denied-network boundary."""
import hashlib
import json
from pathlib import Path
import socket
import struct
from datetime import UTC, datetime, timedelta
import zlib

import httpx
import pytest

from omni_migrator.control_plane.canonical import sha256_json
from omni_migrator.extractors.sigma.api import SigmaApi
from omni_migrator.extractors.sigma.visual_capture import capture_visual
from omni_migrator.prepush.cli import parser
from omni_migrator.security.visual_evidence import atomic_private_write, inspect_evidence


@pytest.fixture(autouse=True)
def denied_network(monkeypatch):
    def deny(*args, **kwargs):
        raise AssertionError("Tenant/network calls forbidden in this fixture")
    monkeypatch.setattr(socket, "getaddrinfo", deny)
    monkeypatch.setattr(socket.socket, "connect", deny)


def request():
    return {"schema_version": "sigma-visual-capture-request.v1", "capture_id": "synthetic-capture",
        "api_base_url": "https://api.sigmacomputing.com", "approved_api_host": "api.sigmacomputing.com",
        "expected_organization_id": "org-1", "expected_user_id": "user-1",
        "principal_ref": "principal-ref://synthetic/viewer", "authorization_ref": "human-authorization-ref://synthetic/capture",
        "workbook_id": "w1", "page_id": "p1", "element_id": "e1", "data_model_id": "m1",
        "source_freeze": {"strategy": "version_tag", "source_reference": "sigma://workbooks/w1/tags/approved",
            "workbook_tag_name": "approved", "data_model_document_version": 3,
            "approved_by_ref": "human-ref://synthetic/owner", "approval_ref": "human-approval-ref://synthetic/tag"},
        "parameters": {"region": "East"}, "timezone": "America/Chicago",
        "evidence_mode": "synthetic_fixture", "row_limit": 10}


def png():
    def chunk(kind, body):
        return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", zlib.crc32(kind + body) & 0xffffffff)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 2, 1, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(b"\x00\x00\x00\x00\xff\xff\xff")) + chunk(b"IEND", b""))


class Source:
    def __init__(self):
        self.calls = []
        self.posts = []
        self.download_status = 200
        self.retry_after = None
        self.version = 3
        self.organization = "org-1"
        self.user = "user-1"
        self.post_failure = False
        self.drift_after_png = False
        self.png_bytes = png()
        self.rows = [{"site": "East", "available": 12}]

    def handler(self, call):
        self.calls.append(call)
        path = call.url.path
        if path == "/v2/whoami":
            return httpx.Response(200, json={"organizationId": self.organization, "userId": self.user})
        if path == "/v2/workbooks/w1":
            return httpx.Response(200, json={"workbookId": "w1", "version": self.version})
        if path.endswith("/tags"):
            return httpx.Response(200, json=[{"tagName": "approved", "sourceVersion": self.version}])
        if path == "/v2/dataModels/m1/spec":
            assert call.url.params["documentVersion"] == "3"
            return httpx.Response(200, json={"dataModelId": "m1", "documentVersion": 3, "pages": []})
        if path.endswith("/pages"):
            assert call.url.params["tag"] == "approved"
            return httpx.Response(200, json=[{"pageId": "p1"}])
        if path.endswith("/elements"):
            assert call.url.params.get("tag", call.url.params.get("tagName")) == "approved"
            return httpx.Response(200, json=[{"elementId": "e1", "type": "chart", "title": "Synthetic inventory"}])
        if path.endswith("/export"):
            body = json.loads(call.content)
            self.posts.append(body)
            if self.post_failure:
                raise httpx.ReadTimeout("synthetic transport interruption")
            return httpx.Response(200, json={"queryId": "q-" + body["format"]["type"], "jobComplete": False})
        if path.startswith("/v2/query/"):
            if self.download_status != 200:
                return httpx.Response(self.download_status, headers={"retry-after": self.retry_after} if self.retry_after else {})
            if "q-png" in path:
                if self.drift_after_png:
                    self.version = 4
                return httpx.Response(200, content=self.png_bytes, headers={"content-type": "image/png"})
            return httpx.Response(200, json=self.rows)
        raise AssertionError("Unexpected endpoint: " + path)

    def api(self):
        api = SigmaApi("https://api.sigmacomputing.com", "synthetic", "synthetic", httpx.MockTransport(self.handler))
        api._token = "synthetic"
        return api


def run(source, directory, **kwargs):
    api = source.api()
    try:
        return capture_visual(request(), api=api, directory=directory,
                              allow_source_read=True, allow_source_query=True, **kwargs)
    finally:
        api.close()


def test_real_producer_persists_pair_and_original_contract(tmp_path):
    source = Source()
    result = run(source, tmp_path)
    assert result["status"] == "complete"
    envelope = json.loads(Path(result["output"]).read_bytes())
    assert envelope == result["capture"]
    assert envelope["content_hash"] == sha256_json({k: v for k, v in envelope.items() if k != "content_hash"})
    assert envelope["source"]["tagged_snapshot"]["coherence"] == "unchanged_before_after_not_atomic"
    assert envelope["source"]["tagged_snapshot_sha256"] == sha256_json(envelope["source"]["tagged_snapshot"])
    assert [b["format"]["type"] for b in source.posts] == ["png", "json"]
    assert source.posts[1]["rowLimit"] == 10
    assert source.posts[0]["parameters"] == source.posts[1]["parameters"] == {"region": "East"}
    assert (tmp_path / "element.png").read_bytes() == source.png_bytes
    assert json.loads((tmp_path / "element.json").read_bytes()) == source.rows
    for item in envelope["attachments"]:
        assert hashlib.sha256((tmp_path / item["path"]).read_bytes()).hexdigest() == item["sha256"]
        assert item["privacy_review"] == "pending"
        assert (tmp_path / item["path"]).stat().st_mode & 0o777 == 0o600
    assert envelope["attachments"][0]["actual_dimensions"] == {"width": 2, "height": 1}
    assert envelope["attachments"][1]["row_completeness"] == "not_established"
    assert not envelope["target_write_authority"]
    assert envelope["evidence_mode"] == "synthetic_fixture"


def test_resume_reuses_job_and_classifies_no_pending_status(tmp_path):
    source = Source()
    source.download_status = 404
    first = run(source, tmp_path)
    assert first["status"] == "partial"
    assert first["capture"]["jobs"][0]["status"] == "download_unresolved"
    assert len(source.posts) == 1
    source.download_status = 200
    second = run(source, tmp_path, resume=True)
    assert second["status"] == "complete"
    assert len(source.posts) == 2  # Only the second, never previously submitted JSON job.


def test_unknown_post_outcome_never_replayed(tmp_path):
    source = Source()
    source.post_failure = True
    assert run(source, tmp_path)["status"] == "partial"
    source.post_failure = False
    second = run(source, tmp_path, resume=True)
    assert second["status"] == "partial"
    assert len(source.posts) == 1
    assert second["capture"]["jobs"][0]["status"] == "ambiguous_submission"


def test_throttle_wait_is_persisted_and_bounded(tmp_path):
    source = Source()
    source.download_status = 429
    source.retry_after = "30"
    now = datetime(2026, 10, 21, tzinfo=UTC)
    first = run(source, tmp_path, now=now)
    assert first["capture"]["jobs"][0]["status"] == "throttled"
    run(source, tmp_path, resume=True, now=now + timedelta(seconds=10))
    assert sum("/download" in str(c.url) for c in source.calls) == 1
    source.download_status = 200
    assert run(source, tmp_path, resume=True, now=now + timedelta(seconds=31))["status"] == "complete"


@pytest.mark.parametrize("failure", ["principal", "drift", "bad_image", "too_many_rows", "denied"])
def test_failure_never_claims_capture_completion(tmp_path, failure):
    source = Source()
    if failure == "principal":
        source.organization = "wrong-org"
    if failure == "drift":
        source.drift_after_png = True
    if failure == "bad_image":
        source.png_bytes = b"<html>not an image</html>"
    if failure == "too_many_rows":
        source.rows = [{}] * 11
    if failure == "denied":
        source.download_status = 403
    result = run(source, tmp_path)
    assert result["status"] == "blocked"
    assert not result["capture"]["target_write_authority"]
    if failure in {"principal", "drift", "bad_image", "denied"}:
        assert len(source.posts) <= 1


def test_tampered_persisted_bytes_and_request_refuse_resume(tmp_path):
    source = Source()
    run(source, tmp_path)
    (tmp_path / "element.png").write_bytes(b"changed")
    with pytest.raises(ValueError, match="Persisted evidence changed"):
        run(source, tmp_path, resume=True)
    assert len(source.posts) == 2


def test_changed_source_before_resume_does_not_resubmit(tmp_path):
    source = Source()
    source.download_status = 404
    run(source, tmp_path)
    source.version = 4
    source.download_status = 200
    assert run(source, tmp_path, resume=True)["status"] == "blocked"
    assert len(source.posts) == 1


def test_private_atomic_destination_and_inert_payload_guards(tmp_path):
    destination = tmp_path / "image.png"
    atomic_private_write(destination, png(), text=False)
    with pytest.raises(ValueError, match="exists"):
        atomic_private_write(destination, png(), text=False)
    linked = tmp_path / "linked.png"
    linked.symlink_to(destination)
    with pytest.raises(ValueError, match="symbolic"):
        atomic_private_write(linked, png(), text=False)
    with pytest.raises(ValueError):
        inspect_evidence(png()[:-2], "png", "image/png", 10)
    with pytest.raises(ValueError):
        inspect_evidence(b"<svg/>", "png", "image/svg+xml", 10)
    assert not list(tmp_path.glob(".capture-*"))


def test_cli_requires_source_only_explicit_flags():
    args = parser().parse_args(["capture-visual", "--request", "request.json", "--directory", "/private/tmp/capture"])
    assert not args.allow_source_read and not args.allow_source_query and not args.resume
    from omni_migrator.prepush.visual_capture import capture
    with pytest.raises(ValueError, match="allow-source-query"):
        capture(args)
    assert not hasattr(args, "target")


def test_no_route_or_target_fields_accepted():
    from omni_migrator.extractors.sigma.visual_contracts import VisualCaptureRequest
    value = request()
    value["target_token"] = "forbidden"
    with pytest.raises(ValueError):
        VisualCaptureRequest.model_validate(value)


def test_attempt_budget_and_expired_capture_are_finite(tmp_path):
    source = Source()
    source.download_status = 202  # Deliberately NOT classified as documented processing.
    now = datetime(2026, 10, 21, tzinfo=UTC)
    first = run(source, tmp_path, now=now)
    for _ in range(6):
        result = run(source, tmp_path, resume=True, now=now)
    assert result["capture"]["jobs"][0]["download_attempts"] == 5
    assert len(source.posts) == 1
    assert first["capture"]["jobs"][0]["status"] == "download_unresolved"
    expired = run(source, tmp_path, resume=True, now=now + timedelta(hours=2))
    assert expired["status"] == "blocked"


def test_rehashed_missing_attachment_cannot_claim_complete(tmp_path):
    source = Source()
    result = run(source, tmp_path)
    path = Path(result["output"])
    changed = json.loads(path.read_bytes())
    changed["attachments"].pop()
    changed["content_hash"] = sha256_json({k: v for k, v in changed.items() if k != "content_hash"})
    path.write_text(json.dumps(changed))
    with pytest.raises(ValueError, match="denominator"):
        run(source, tmp_path, resume=True)
    assert len(source.posts) == 2


def test_commit_failure_does_not_expose_partial_final_file(tmp_path, monkeypatch):
    import omni_migrator.security.visual_evidence as writer
    def fail(*args, **kwargs):
        raise OSError("synthetic commit failure")
    monkeypatch.setattr(writer.os, "link", fail)
    with pytest.raises(OSError):
        atomic_private_write(tmp_path / "image.png", png(), text=False)
    assert not (tmp_path / "image.png").exists()
    assert not list(tmp_path.glob(".capture-*"))


def test_process_interruption_after_intent_is_not_replayed(tmp_path):
    source = Source()
    handler = source.handler
    def interrupted(call):
        if call.url.path.endswith("/export"):
            source.posts.append(json.loads(call.content))
            raise KeyboardInterrupt()
        return handler(call)
    source.handler = interrupted
    with pytest.raises(KeyboardInterrupt):
        run(source, tmp_path)
    last = json.loads(sorted(tmp_path.glob("capture-*.json"))[-1].read_bytes())
    assert last["jobs"][0]["status"] == "submission_uncertain"
    source.handler = handler
    result = run(source, tmp_path, resume=True)
    assert result["status"] == "partial" and len(source.posts) == 1


@pytest.mark.parametrize("issue", ["missing_tag", "duplicate_tag", "missing_element", "conflicting_element"])
def test_invalid_selected_source_never_submits_query(tmp_path, issue):
    source = Source()
    handler = source.handler
    def invalid(call):
        if call.url.path.endswith("/tags"):
            if issue == "missing_tag":
                return httpx.Response(200, json=[])
            if issue == "duplicate_tag":
                return httpx.Response(200, json=[{"name": "approved", "version": 3}] * 2)
        if call.url.path == "/v2/workbooks/w1/pages/p1/elements" and issue == "missing_element":
            return httpx.Response(200, json=[])
        if call.url.path == "/v2/workbooks/w1/elements" and issue == "conflicting_element":
            return httpx.Response(200, json=[{"elementId": "e1", "type": "table"}])
        return handler(call)
    source.handler = invalid
    assert run(source, tmp_path)["status"] == "blocked"
    assert source.posts == []


def test_cli_uses_only_source_credentials_and_fixed_source_request(tmp_path, monkeypatch):
    import omni_migrator.extractors.sigma.api as api_module
    import omni_migrator.prepush.visual_capture as command
    from omni_migrator.prepush.session import private_write
    source = Source()
    api = source.api()
    monkeypatch.setattr(api_module, "SigmaApi", lambda *args, **kwargs: api)
    class SourceEnvironment(dict):
        def get(self, key, default=None):
            if key not in {"SIGMA_CLIENT_ID", "SIGMA_CLIENT_SECRET"}:
                raise AssertionError("Unexpected credential lookup: " + key)
            return "synthetic"
    # Patch only the command module's os binding, not the process-wide environment.
    from types import SimpleNamespace
    monkeypatch.setattr(command, "os", SimpleNamespace(environ=SourceEnvironment()))
    request_path = tmp_path / "request.json"
    private_write(request_path, request())
    args = parser().parse_args(["capture-visual", "--request", str(request_path),
        "--directory", str(tmp_path / "capture"), "--allow-source-read", "--allow-source-query"])
    result = command.capture(args)
    assert result["status"] == "complete"
    assert set(result) == {"status", "output", "target_write_authority", "native_validation"}


def test_v2_page_png_and_unselected_model_remain_separate_evidence(tmp_path):
    value = request()
    value.update(schema_version="sigma-visual-capture-request.v2", target_kind="page",
                 element_id=None, data_model_id=None)
    value["source_freeze"]["data_model_document_version"] = None
    source = Source(); api = source.api()
    try:
        result = capture_visual(value, api=api, directory=tmp_path,
                                allow_source_read=True, allow_source_query=True)
    finally:
        api.close()
    assert result["status"] == "complete"
    assert [job["kind"] for job in result["capture"]["jobs"]] == ["png"]
    assert source.posts == [{"pageId": "p1", "tag": "approved", "parameters": {"region": "East"},
                             "format": {"type": "png"}}]
    assert not any("/dataModels/" in str(call.url) for call in source.calls)
    assert (tmp_path / "page.png").read_bytes() == source.png_bytes
    assert "page_image_has_no_paired_numerical_result" in result["capture"]["gaps"]
    assert result["capture"]["source"]["baseline"]["data_model_specification"] is None


def test_v2_ambiguous_model_or_page_scope_is_rejected(tmp_path):
    from omni_migrator.extractors.sigma.visual_contracts import parse_visual_request
    value = request()
    value.update(schema_version="sigma-visual-capture-request.v2", target_kind="page")
    with pytest.raises(ValueError):
        parse_visual_request(value)  # Page cannot retain an element selector.
    value["element_id"] = None
    value["data_model_id"] = None
    with pytest.raises(ValueError):
        parse_visual_request(value)  # No model cannot retain a model-version assertion.

"""Standard-library source-operation contracts; no credentials, clients or evaluation.

This interface describes source acquisition only. A request/reference is not proof
of human approval. The CLI host supplies the separate read/query grants.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re
from urllib.parse import urlsplit

REQUEST_SCHEMA = "sigma-source-operation-request.v1"
SCHEMA = "sigma-source-operation.v1"
CAPABILITIES_SCHEMA = "sigma-source-capabilities.v1"
OPERATIONS = ("check", "inventory", "snapshot", "capture")
MAX_REQUEST_BYTES = 256 * 1024
_ID = re.compile(r"[A-Za-z0-9_-][A-Za-z0-9._~-]{0,511}\Z")
_SECRET = re.compile(r"(?i)(?:authorization|bearer|password|passwd|secret|api[_-]?key|api[_-]?token|access[_-]?token|refresh[_-]?token|credentials?)\s*[:=]\s*[^\s,}]+")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("utf-8")


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def _need(condition, message):
    if not condition:
        raise ValueError(message)


def _text(value, label, maximum=512):
    _need(type(value) is str and 0 < len(value) <= maximum and
          not any(ord(c) < 32 or ord(c) == 127 for c in value), "Invalid " + label)
    _need(not _SECRET.search(value) and not re.search(r"(?i)\bBearer\s+\S+", value),
          "Credential-like request text is not accepted")
    return value


def _ids(value, label, maximum):
    _need(type(value) is list and len(value) <= maximum and
          all(type(v) is str and _ID.fullmatch(v) for v in value) and
          len(set(value)) == len(value), "Invalid " + label)


def validate_request(value):
    _need(type(value) is dict, "Source operation must be an object")
    required = {"schema_version", "request_id", "operation", "api_base_url", "approved_api_host",
                "expected_organization_id", "expected_user_id", "principal_ref", "authorization_ref",
                "evidence_mode", "max_requests", "scope", "options"}
    _need(set(value) in (required, required | {"visual_capture_request"}), "Unexpected source-operation fields")
    _need(len(canonical(value)) <= MAX_REQUEST_BYTES, "Source request exceeds byte budget")
    _need(value["schema_version"] == REQUEST_SCHEMA and value["operation"] in OPERATIONS,
          "Unsupported source operation")
    _need(type(value["request_id"]) is str and re.fullmatch(r"[A-Za-z0-9_-]{1,80}", value["request_id"]),
          "Invalid request ID")
    for key in ("expected_organization_id", "expected_user_id", "principal_ref", "authorization_ref"):
        _text(value[key], key)
    _need(re.fullmatch(r"principal-ref://[^\s?#]+", value["principal_ref"]) and
          re.fullmatch(r"human-authorization-ref://[^\s?#]+", value["authorization_ref"]), "Invalid source evidence references")
    _need(value["evidence_mode"] in {"synthetic_fixture", "live_tenant"}, "Invalid source evidence mode")
    _need(type(value["max_requests"]) is int and 5 <= value["max_requests"] <= 500, "Invalid request budget")
    try:
        url = urlsplit(value["api_base_url"])
        good = (url.scheme == "https" and url.hostname == value["approved_api_host"] and
                re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?", url.hostname or "") and
                url.port in (None, 443) and not url.username and not url.password and
                not url.query and not url.fragment and url.path in ("", "/"))
    except (ValueError, TypeError):
        good = False
    _need(good, "An exact approved HTTPS source origin is required")
    scope = value["scope"]
    _need(type(scope) is dict and set(scope) == {"workbook_ids", "data_model_ids"}, "Invalid source scope")
    _ids(scope["workbook_ids"], "selected workbook IDs", 10)
    _ids(scope["data_model_ids"], "selected data-model IDs", 10)
    options = value["options"]
    _need(type(options) is dict and set(options) == {"include_contents_beta"} and
          type(options["include_contents_beta"]) is bool, "Invalid source options")
    op = value["operation"]
    if op in {"snapshot", "capture"}:
        _need(bool(scope["workbook_ids"]), "Select a workbook before capture")
    if op == "capture":
        _need(len(scope["workbook_ids"]) == 1 and len(scope["data_model_ids"]) <= 1 and
              not options["include_contents_beta"], "Visual capture is a separately versioned single-workbook scope")
        child = value.get("visual_capture_request")
        _need(type(child) is dict and child.get("schema_version") in {"sigma-visual-capture-request.v1", "sigma-visual-capture-request.v2"}, "An exact supported visual capture request is required")
        for key in ("api_base_url", "approved_api_host", "expected_organization_id", "expected_user_id",
                    "principal_ref", "authorization_ref", "evidence_mode"):
            _need(child.get(key) == value[key], "Nested visual request changes source authority or identity")
        _need(child.get("workbook_id") == scope["workbook_ids"][0] and
              ([child["data_model_id"]] if child.get("data_model_id") else []) == scope["data_model_ids"] and
              child.get("max_requests_per_invocation", 100) == value["max_requests"], "Nested visual request changes scope or budget")
    else:
        _need("visual_capture_request" not in value, "Only capture accepts a visual request")
    if options["include_contents_beta"]:
        _need(op == "snapshot", "Beta contents is an explicit snapshot supplement only")
    return deepcopy(value)


def inspect_contents_beta(response, workbook_id):
    """Retain native contents verbatim, without parsing YAML or executing expressions."""
    _need(type(response) is dict, "Beta workbook response must be an object")
    identifiers = {str(response[k]) for k in ("workbookId", "id") if response.get(k) is not None}
    _need(identifiers == {workbook_id}, "Beta workbook identity is missing or conflicting")
    contents = response.get("contents")
    _need(type(contents) in (dict, str) and bool(contents), "Beta workbook contents was not returned")
    version = contents.get("schemaVersion") if type(contents) is dict else None
    if version is not None:
        _need(type(version) in (str, int) and type(version) is not bool and str(version), "Invalid Beta schemaVersion")
    return {"schema_version": "sigma-workbook-contents-evidence.v1", "feature_status": "Beta",
            "workbook_id": workbook_id, "response": deepcopy(response), "response_sha256": digest(response),
            "contents_format": "json_object" if type(contents) is dict else "opaque_text",
            "schemaVersion": version, "definition_scope": "current_workbook_not_tagged",
            "interpretation": "retained_not_compiled", "source_execution": False,
            "gaps": ["beta_schema_semantics_not_qualified", "not_bound_to_tagged_or_saved_view",
                     "input_table_data_omitted", "webhook_hmac_secrets_omitted", "tagged_versions_omitted",
                     "comments_and_sharing_omitted", "referenced_assets_not_embedded",
                     "duplicate_table_name_roundtrip_not_assured"]}


def capabilities():
    package = Path(__file__).resolve().parents[1]
    files = {}
    total = 0
    for path in sorted(package.rglob("*.py")):
        _need(not path.is_symlink(), "Runtime source pins cannot follow symbolic links")
        raw = path.read_bytes()
        total += len(raw)
        _need(len(files) < 300 and total <= 25 * 1024 * 1024, "Runtime source fingerprint budget exceeded")
        files[path.relative_to(package).as_posix()] = hashlib.sha256(raw).hexdigest()
    return {"schema_version": CAPABILITIES_SCHEMA, "runtime_name": "sigma-migration-agent",
            "runtime_version": "0.4.1", "extension_name": "sigma-source-operations", "extension_version": "0.1.0",
            "distribution_status": "source_extension_requires_separate_reviewed_release",
            "operations": list(OPERATIONS), "request_schema": REQUEST_SCHEMA, "result_schema": SCHEMA,
            "visual_request_schemas": ["sigma-visual-capture-request.v1", "sigma-visual-capture-request.v2"],
            "visual_result_schema": "sigma-visual-capture.v1", "visual_formats": {"element": ["png", "json"], "page": ["png"]},
            "limits": {"request_bytes": MAX_REQUEST_BYTES, "max_requests": 500, "selected_workbooks": 10,
                       "selected_data_models": 10, "result_completeness": "not_established"},
            "beta_contents": {"supported": True, "status": "Beta", "tagged": False, "compiled": False},
            "implementation_sha256": digest(files), "implementation_files": files,
            "dependency_activation_authorized": False, "target_write_authority": False,
            "terminal_review_bypass": False, "live_qualification": "not_established"}

"""Fixed source-only host operations. No target client, shell, converter or review acceptance.

Metadata orchestration is standard-library only. Connected CLI execution lazily
uses the existing reviewed Sigma transport/scanner after explicit host grants.
"""
from __future__ import annotations

from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path

from omni_migrator.prepush.source_protocol import (
    SCHEMA, canonical, digest, inspect_contents_beta, validate_request,
)


def _bind_api(request, api):
    if api.base_url.rstrip("/") != request["api_base_url"].rstrip("/"):
        raise ValueError("Source API origin differs from reviewed request")
    if api.request_budget != request["max_requests"]:
        raise ValueError("Source API request budget differs from reviewed request")


def _identity(request, api):
    identity = api.whoami()
    if (type(identity) is not dict or identity.get("organizationId") != request["expected_organization_id"]
            or identity.get("userId") != request["expected_user_id"]):
        raise ValueError("Source principal or organization differs from reviewed request")
    return {key: identity[key] for key in ("organizationId", "userId")}


def _selected(rows, ids, keys):
    if type(rows) is not list:
        raise ValueError("Invalid source inventory")
    result, seen = [], set()
    for row in rows:
        if type(row) is not dict:
            raise ValueError("Invalid source inventory item")
        values = {str(row[k]) for k in keys if row.get(k) is not None}
        if len(values) != 1:
            raise ValueError("Missing or conflicting source inventory identity")
        native = values.pop()
        if native in seen:
            raise ValueError("Duplicate source inventory identity")
        seen.add(native)
        if not ids or native in ids:
            result.append(row)
    if ids and not set(ids) <= seen:
        raise ValueError("A selected source item was not accessible")
    return result


def acquire(request, *, api, allow_source_read=False):
    """Produce a metadata envelope using a host-supplied bounded client; no disk I/O.

Tests may inject inert source responses. This does not authenticate the client or
make a synthetic envelope live evidence; the boundary is the executing host.
"""
    request = validate_request(request)
    if not allow_source_read:
        raise ValueError("Explicit source-read authorization is required")
    if request["operation"] == "capture":
        raise ValueError("Visual capture uses the separately journaled execute path")
    _bind_api(request, api)
    observed = _identity(request, api)
    scope = request["scope"]
    operation = request["operation"]
    gaps = ["source_metadata_is_not_native_behavior_or_access_parity",
            "underlying_data_freshness_not_verified"]
    if operation == "check":
        result = {"workbooks": [], "dataModels": []}
        for id_ in scope["workbook_ids"]:
            row = api.get_workbook(id_)
            _selected([row], [id_], ("workbookId", "id"))
            result["workbooks"].append({"workbookId": id_, "readable": True})
        for id_ in scope["data_model_ids"]:
            row = api.get_data_model(id_)
            _selected([row], [id_], ("dataModelId", "id"))
            result["dataModels"].append({"dataModelId": id_, "readable": True})
        gaps.append("readability_does_not_verify_dependency_relationship")
    elif operation == "inventory":
        result = {"workbooks": _selected(api.list_workbooks(), scope["workbook_ids"], ("workbookId", "id")),
                  "dataModels": _selected(api.list_data_models(), scope["data_model_ids"], ("dataModelId", "id"))}
        gaps.append("accessible_inventory_not_organization_complete_or_definition_complete")
    else:
        # [] means no selected associated model; it must not expand to all models.
        result = api.snapshot(workbook_ids=scope["workbook_ids"], data_model_ids=scope["data_model_ids"],
                              allow_unresolved_dependencies=not scope["data_model_ids"])
        if type(result) is not dict:
            raise ValueError("Invalid source snapshot")
        _selected(result.get("workbooks"), scope["workbook_ids"], ("workbookId", "id"))
        workbook_ids = {str(row.get("workbookId", row.get("id"))) for row in result["workbooks"]}
        if workbook_ids != set(scope["workbook_ids"]):
            raise ValueError("Source snapshot expanded selected workbook scope")
        _selected(result.get("dataModels"), scope["data_model_ids"], ("dataModelId", "id"))
        model_ids = {str(row.get("dataModelId", row.get("id"))) for row in result["dataModels"]}
        if model_ids != set(scope["data_model_ids"]):
            raise ValueError("Source snapshot expanded selected data-model scope")
        if request["options"]["include_contents_beta"]:
            supplement = []
            for id_ in scope["workbook_ids"]:
                supplement.append(inspect_contents_beta(api.workbook_contents(id_), id_))
            result = {**result, "_sigma_contents_beta": supplement}
            gaps.append("beta_current_contents_not_tagged_definition_or_automatic_conversion")
        if not scope["data_model_ids"]:
            gaps.append("no_associated_data_model_selected_dependencies_still_require_evidence")
        gaps.append("metadata_capture_not_atomic_or_version_frozen")
    if _identity(request, api) != observed:
        raise ValueError("Source identity changed during acquisition")
    return {"schema_version": SCHEMA, "operation": operation, "request": request,
            "request_sha256": digest(request), "observed_principal": observed,
            "observed_at": datetime.now(timezone.utc).isoformat(), "result": result,
            "result_sha256": digest(result), "gaps": sorted(gaps), "status": "captured_requires_review",
            "evidence_mode": request["evidence_mode"], "target_write_authority": False,
            "native_validation": "not_performed", "business_acceptance": "not_assessed"}


def capture_envelope(request, receipt, status):
    """Wrap the separately retained visual journal without copying its source payload."""
    result = {"visual_capture": receipt}
    return {"schema_version": SCHEMA, "operation": "capture", "request": request,
            "request_sha256": digest(request), "observed_at": datetime.now(timezone.utc).isoformat(),
            "result": result, "result_sha256": digest(result), "status": status,
            "gaps": ["visual_journal_and_attachment_bytes_require_verification",
                     "result_completeness_and_effective_source_state_not_established"],
            "evidence_mode": request["evidence_mode"], "target_write_authority": False,
            "native_validation": "not_performed", "business_acceptance": "not_assessed"}


def execute(request, *, api, directory, allow_source_read=False, allow_source_query=False, resume=False):
    request = validate_request(request)
    if not allow_source_read or (request["operation"] == "capture" and not allow_source_query):
        raise ValueError("Required explicit source read/query authorization is missing")
    _bind_api(request, api)
    from omni_migrator.prepush.session import read_json, reject_secrets
    from omni_migrator.security.visual_evidence import atomic_private_write
    from omni_migrator.security.workspace import prepare_workspace
    reject_secrets(request)
    directory = prepare_workspace(Path(directory))
    lock = os.open(directory / ".source-operation.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        files = sorted(directory.glob("source-operation-*.json"))
        if bool(files) != resume or len(files) >= 64:
            raise ValueError("Choose an empty directory or explicitly resume the bounded source journal")
        previous = None
        for index, path in enumerate(files, 1):
            prior = read_json(path)
            if (path.name != f"source-operation-{index:06d}.json" or
                    prior.get("schema_version") != SCHEMA or prior.get("journal_revision") != index or
                    prior.get("operation") != request["operation"] or prior.get("evidence_mode") != request["evidence_mode"] or
                    prior.get("request_sha256") != digest(request) or
                    prior.get("request") != request or prior.get("previous_content_hash") != previous or
                    prior.get("content_hash") != digest({k: v for k, v in prior.items() if k != "content_hash"}) or
                    prior.get("result_sha256") != digest(prior.get("result")) or
                    prior.get("target_write_authority") is not False):
                raise ValueError("Metadata journal or source binding changed")
            previous = prior["content_hash"]
        def append(envelope):
            nonlocal previous
            envelope.update(journal_revision=len(files) + 1, previous_content_hash=previous)
            envelope["content_hash"] = digest(envelope)
            path = directory / f"source-operation-{len(files) + 1:06d}.json"
            reject_secrets(envelope)
            atomic_private_write(path, canonical(envelope) + b"\n")
            files.append(path)
            previous = envelope["content_hash"]
            return path

        if request["operation"] == "capture":
            from omni_migrator.extractors.sigma.visual_capture import capture_visual
            visual_directory = directory / "visual"
            if not resume:
                if visual_directory.exists() or visual_directory.is_symlink():
                    raise ValueError("Existing visual evidence requires its original operation journal")
                # Durable outer intent before delegating; the child records each POST intent.
                append(capture_envelope(request, None, "pending"))
            elif visual_directory.is_symlink():
                raise ValueError("Visual evidence directory cannot be a symbolic link")
            elif prior["result"].get("visual_capture"):
                receipt = prior["result"]["visual_capture"]
                retained = directory / receipt["path"]
                if (not receipt["path"].startswith("visual/capture-") or
                        Path(receipt["path"]).parts != ("visual", Path(receipt["path"]).name) or
                        retained.is_symlink() or not retained.is_file() or retained.stat().st_size > 25 * 1024 * 1024 or
                        retained.stat().st_size != receipt["bytes"] or
                        hashlib.sha256(retained.read_bytes()).hexdigest() != receipt["sha256"]):
                    raise ValueError("Retained visual capture receipt changed")
            child_resume = visual_directory.is_dir() and bool(list(visual_directory.glob("capture-*.json")))
            result = capture_visual(request["visual_capture_request"], api=api, directory=visual_directory,
                                    allow_source_read=True, allow_source_query=True, resume=child_resume)
            retained = Path(result["output"])
            if retained.parent != visual_directory or retained.is_symlink() or not retained.is_file():
                raise ValueError("Visual capture returned an unsafe output path")
            raw = retained.read_bytes()
            receipt = {"path": retained.relative_to(directory).as_posix(), "bytes": len(raw),
                       "sha256": hashlib.sha256(raw).hexdigest(),
                       "schema_version": "sigma-visual-capture.v1", "status": result["status"]}
            envelope = capture_envelope(request, receipt, result["status"])
        else:
            envelope = acquire(request, api=api, allow_source_read=True)
        path = append(envelope)
        return {"status": envelope["status"], "output": str(path),
                "output_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "target_write_authority": False, "native_validation": "not_performed"}
    finally:
        os.close(lock)


def run_cli(args):
    # Validate the request and explicit grants before loading any credentials/client.
    from omni_migrator.prepush.session import read_json
    request = validate_request(read_json(args.request))
    if not args.allow_source_read or (request["operation"] == "capture" and not args.allow_source_query):
        raise ValueError("Required explicit source read/query authorization is missing")
    if request["operation"] == "capture":
        from omni_migrator.extractors.sigma.visual_contracts import parse_visual_request
        parse_visual_request(request["visual_capture_request"])
    client, secret = os.environ.get("SIGMA_CLIENT_ID"), os.environ.get("SIGMA_CLIENT_SECRET")
    if not client or not secret:
        raise ValueError("Set source credentials outside the request file")
    from omni_migrator.extractors.sigma.api import SigmaApi
    api = SigmaApi(request["api_base_url"], client, secret, request_budget=request["max_requests"])
    try:
        return execute(request, api=api, directory=args.directory, allow_source_read=args.allow_source_read,
                       allow_source_query=args.allow_source_query, resume=args.resume)
    except Exception:
        # No source response, result rows, query parameters or credentials in stdout.
        raise ValueError("Source operation failed; retained local evidence may be inspected privately") from None
    finally:
        api.close()

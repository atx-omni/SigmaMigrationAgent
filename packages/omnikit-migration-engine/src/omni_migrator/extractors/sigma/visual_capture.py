"""One tagged element PNG/JSON or page PNG; durable source-only jobs.

Unknown download statuses stop. An explicit resume retries an existing query ID,
never an uncertain export POST. Local hashes detect drift, not hostile-user forgery.
"""
from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path

from omni_migrator.control_plane.canonical import sha256_json
from omni_migrator.extractors.sigma.source_contracts import selected_sigma_document_version
from omni_migrator.extractors.sigma.visual_contracts import VisualCaptureRequest, parse_visual_request
from omni_migrator.prepush.session import read_json
from omni_migrator.security.visual_evidence import atomic_private_write, inspect_evidence, persist_evidence
from omni_migrator.security.workspace import prepare_workspace


SCHEMA = "sigma-visual-capture.v1"
BASE_GAPS = ["capture_is_not_atomic_underlying_data_snapshot", "result_completeness_not_established",
             "untagged_controls_queries_grants_sources_not_captured",
             "selected_data_model_dependency_not_verified_by_tagged_endpoints",
             "recorded_timezone_not_verified_as_effective_source_timezone",
             "privacy_native_behavior_access_and_business_review_pending"]


def _id(row, *keys):
    values = {str(row[k]) for k in keys if row.get(k) is not None}
    if len(values) != 1:
        raise ValueError("Source identity is missing or conflicting")
    return values.pop()


def _observation(api, request):
    identity = api.whoami()
    if (identity.get("organizationId") != request.expected_organization_id
            or identity.get("userId") != request.expected_user_id):
        raise ValueError("Source principal or organization does not match the request")
    workbook = api.get_workbook(request.workbook_id)
    if _id(workbook, "workbookId", "id") != request.workbook_id:
        raise ValueError("Source workbook identity does not match")
    tags = api.workbook_tags(request.workbook_id)
    matches = [row for row in tags if isinstance(row, dict)
               and (row.get("tagName") or row.get("name")) == request.tag]
    if len(matches) != 1:
        raise ValueError("Selected workbook tag is missing or ambiguous")
    version = selected_sigma_document_version(matches[0], "sourceVersion", "version", "workbookVersion")
    if version is None:
        raise ValueError("Selected tag has no unambiguous source version")
    spec = None
    if request.data_model_id is not None:
        spec = api.data_model_spec(request.data_model_id,
                                  document_version=request.source_freeze.data_model_document_version)
        if (_id(spec, "dataModelId", "id") != request.data_model_id
                or selected_sigma_document_version(spec, "documentVersion")
                != str(request.source_freeze.data_model_document_version)):
            raise ValueError("Data model specification identity or version does not match")
    return {"identity": identity, "workbook": workbook, "tags": tags,
            "tag_source_version": version, "data_model_specification": spec}


def _coherence(observation):
    return sha256_json({**observation, "identity": {
        key: observation["identity"][key] for key in ("organizationId", "userId")}})


def _membership(snapshot, request):
    if snapshot.get("workbookId") != request.workbook_id or snapshot.get("tag") != request.tag:
        raise ValueError("Tagged capture selection does not match")
    pages = snapshot.get("pages")
    if not isinstance(pages, list):
        raise ValueError("Tagged capture omitted pages")
    page_ids, element_locations, selected = set(), {}, None
    for page in pages:
        pid = _id(page, "pageId", "id")
        if pid in page_ids:
            raise ValueError("Duplicate page identity")
        page_ids.add(pid)
        for element in page.get("elements", []):
            eid = _id(element, "elementId", "id")
            if eid in element_locations:
                raise ValueError("Ambiguous element placement")
            element_locations[eid] = pid
            if pid == request.page_id and eid == request.element_id:
                selected = element
    if request.file_stem == "page":
        if request.page_id not in page_ids:
            raise ValueError("Selected page is not present in tagged evidence")
        return
    if selected is None:
        raise ValueError("Selected element is not present on the selected page")
    if selected.get("type") not in {"chart", "table"}:
        raise ValueError("This capture slice supports a chart or table element only")
    bulk = [e for e in snapshot.get("elements", []) if _id(e, "elementId", "id") == request.element_id]
    if len(bulk) != 1:
        raise ValueError("Selected element is absent or duplicated in bulk evidence")
    # Endpoints may expose different fields, but shared fields must agree.
    if any(selected[k] != bulk[0][k] for k in selected.keys() & bulk[0].keys()):
        raise ValueError("Selected element definitions conflict across endpoints")


def _encode(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True, allow_nan=False) + "\n").encode()


def _save(directory, state):
    previous = state.pop("content_hash", None)
    state["previous_content_hash"] = previous
    state["journal_revision"] += 1
    state["content_hash"] = sha256_json(state)
    path = directory / f"capture-{state['journal_revision']:06d}.json"
    atomic_private_write(path, _encode(state))
    return path


def _load(directory, request_hash):
    paths = sorted(directory.glob("capture-*.json"))
    if not paths or len(paths) > 512:
        raise ValueError("Capture journal is absent or exceeds the bounded revision limit")
    previous = None
    for index, path in enumerate(paths, 1):
        if path.name != f"capture-{index:06d}.json":
            raise ValueError("Capture journal has a missing revision")
        state = read_json(path)
        actual = sha256_json({k: v for k, v in state.items() if k != "content_hash"})
        if (state.get("schema_version") != SCHEMA or state.get("content_hash") != actual
                or state.get("previous_content_hash") != previous
                or state.get("journal_revision") != index or state.get("request_sha256") != request_hash
                or sha256_json(state.get("request")) != request_hash):
            raise ValueError("Capture journal or request changed")
        previous = actual
    source = state.get("source")
    if source:
        if (sha256_json(source["tagged_snapshot"]) != source["tagged_snapshot_sha256"]
                or sha256_json(source["baseline"]) != source["baseline_sha256"]
                or _coherence(source["baseline"]) != source["coherence_sha256"]):
            raise ValueError("Source evidence changed")
    if source and "final_observation" in source:
        if sha256_json(source["final_observation"]) != source.get("final_observation_sha256"):
            raise ValueError("Final source observation changed")
        if state["status"] == "complete" and _coherence(source["final_observation"]) != source["coherence_sha256"]:
            raise ValueError("Completed capture has conflicting final source state")
    if state["status"] == "complete" and (not source or "final_observation" not in source):
        raise ValueError("Completed capture omitted its final source observation")
    request = parse_visual_request(state["request"])
    if (sha256_json(state.get("original_request")) != state.get("original_request_sha256")
            or parse_visual_request(state["original_request"]).model_dump(mode="json") != state["request"]
            or state.get("evidence_mode") != request.evidence_mode
            or state.get("capture_id") != request.capture_id
            or state.get("target_write_authority") is not False):
        raise ValueError("Original capture request or authority boundary changed")
    if source:
        _membership(source["tagged_snapshot"], request)
    if [job.get("kind") for job in state["jobs"]] != list(request.job_kinds):
        raise ValueError("Capture job denominator changed")
    allowed_statuses = {"planned", "submission_uncertain", "ambiguous_submission", "submitted",
                        "download_started", "download_unresolved", "throttled", "access_denied_or_auth_required",
                        "evidence_invalid_or_unpersisted", "downloaded"}
    for job in state["jobs"]:
        if job.get("status") not in allowed_statuses:
            raise ValueError("Unknown export lifecycle state")
        if job["status"] != "planned" and not source:
            raise ValueError("Export lifecycle lacks its original source evidence")
        if job["status"] not in {"planned", "submission_uncertain", "ambiguous_submission"} and not job.get("query_id"):
            raise ValueError("Submitted export has no retained query identity")
        body = request.export_body(job["kind"])
        if job["request_body"] != body or job["request_sha256"] != sha256_json(body):
            raise ValueError("Export request intent changed")
        if type(job.get("download_attempts")) is not int or not 0 <= job["download_attempts"] <= request.max_download_attempts:
            raise ValueError("Export attempt evidence changed")
    downloaded = [job["kind"] for job in state["jobs"] if job["status"] == "downloaded"]
    if (sorted(a["format"] for a in state["attachments"]) != sorted(downloaded)
            or (state["status"] == "complete" and downloaded != list(request.job_kinds))):
        raise ValueError("Capture completion or attachment denominator is inconsistent")
    for attachment in state["attachments"]:
        name = attachment["path"]
        if name not in {request.file_stem + "." + kind for kind in request.job_kinds}:
            raise ValueError("Unsafe evidence path")
        path = directory / name
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 5 * 1024 * 1024:
            raise ValueError("Missing or unsafe evidence file")
        data = path.read_bytes()
        if len(data) != attachment["bytes"] or hashlib.sha256(data).hexdigest() != attachment["sha256"]:
            raise ValueError("Persisted evidence changed")
        job = next(j for j in state["jobs"] if j["kind"] == attachment["format"])
        if (attachment["capture_id"] != request.capture_id or attachment["workbook_id"] != request.workbook_id
                or attachment["page_id"] != request.page_id or attachment["element_id"] != request.element_id
                or attachment["query_id"] != job["query_id"] or attachment["request_sha256"] != request_hash
                or attachment["source_snapshot_sha256"] != source["tagged_snapshot_sha256"]):
            raise ValueError("Attachment state binding changed")
        metadata = inspect_evidence(data, attachment["format"], attachment["media_type"], request.row_limit)
        if any(attachment.get(key) != value for key, value in metadata.items()):
            raise ValueError("Attachment metadata disagrees with persisted bytes")
    return state, paths[-1]


def _retry_after(response, now):
    raw = response.headers.get("retry-after")
    if raw is None:
        return None
    try:
        seconds = float(raw)
        if not 0 <= seconds <= 3600:
            return None
        return (now + timedelta(seconds=seconds)).isoformat()
    except ValueError:
        try:
            date = parsedate_to_datetime(raw)
            if date.tzinfo is not None and 0 <= (date - now).total_seconds() <= 3600:
                return date.isoformat()
        except (ValueError, TypeError, OverflowError):
            pass
    return None


def capture_visual(request, *, api, directory, allow_source_read=False, allow_source_query=False,
                   resume=False, now=None):
    """Capture/resume once. No background polling, remote send, or target operation."""
    if not allow_source_read or not allow_source_query:
        raise ValueError("Explicit source-read and source-query authorization are required")
    original = request.model_dump(mode="json") if isinstance(request, VisualCaptureRequest) else deepcopy(request)
    request = parse_visual_request(original)
    effective = request.model_dump(mode="json")
    request_hash = sha256_json(effective)
    if api.base_url.rstrip("/") != request.api_base_url.rstrip("/"):
        raise ValueError("Source API origin does not match the authorized request")
    if api.request_budget is None:
        api.request_budget = request.max_requests_per_invocation
    elif api.request_budget != request.max_requests_per_invocation:
        raise ValueError("Source request budget does not match")
    directory = prepare_workspace(Path(directory))
    lock_path = directory / ".visual-capture.lock"
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        instant = now or datetime.now(UTC)
        if instant.tzinfo is None:
            raise ValueError("Capture clock must include a timezone")
        if resume:
            state, path = _load(directory, request_hash)
            if state["status"] == "blocked":
                return {"status": "blocked", "output": str(path), "capture": state}
            if (instant - datetime.fromisoformat(state["created_at"])).total_seconds() > request.max_capture_age_seconds:
                state["status"] = "blocked"
                state["gaps"].append("capture_age_limit_reached_not_a_vendor_expiry_assertion")
                path = _save(directory, state)
                return {"status": "blocked", "output": str(path), "capture": state}
        else:
            if list(directory.glob("capture-*.json")) or any((directory / n).exists() for n in ("element.png", "element.json", "page.png")):
                raise ValueError("Capture already exists; explicitly resume it or choose a new directory")
            state = {"schema_version": SCHEMA, "capture_id": request.capture_id,
                     "request": effective, "request_sha256": request_hash,
                     "original_request": original, "original_request_sha256": sha256_json(original),
                     "created_at": instant.isoformat(), "source": None, "attachments": [],
                     "jobs": [{"kind": kind, "request_body": request.export_body(kind),
                               "request_sha256": sha256_json(request.export_body(kind)),
                               "query_id": None, "status": "planned", "download_attempts": 0}
                              for kind in request.job_kinds],
                     "gaps": list(BASE_GAPS), "status": "partial", "journal_revision": 0,
                     "evidence_mode": request.evidence_mode, "target_write_authority": False,
                     "native_validation": "not_performed", "business_acceptance": "not_assessed"}
            if request.data_model_id is None:
                state["gaps"].append("no_associated_data_model_selected_dependencies_unverified")
            if request.file_stem == "page":
                state["gaps"].append("page_image_has_no_paired_numerical_result")
            path = _save(directory, state)
        try:
            observation = _observation(api, request)
            if state["source"] is None:
                snapshot = api.workbook_snapshot(request.workbook_id, tag=request.tag)
                _membership(snapshot, request)
                if snapshot["revisionEvidence"] != {"workbook": observation["workbook"], "tags": observation["tags"]}:
                    raise ValueError("Configuration changed while capturing the tagged snapshot")
                if _coherence(_observation(api, request)) != _coherence(observation):
                    raise ValueError("Source changed during configuration capture")
                state["source"] = {"tagged_snapshot": snapshot,
                    "tagged_snapshot_sha256": sha256_json(snapshot), "baseline": observation,
                    "baseline_sha256": sha256_json(observation), "coherence_sha256": _coherence(observation),
                    "coherence": "unchanged_before_after_not_atomic"}
                path = _save(directory, state)
            elif _coherence(observation) != state["source"]["coherence_sha256"]:
                raise ValueError("Source changed before export or resume")
            elif all(job["status"] == "downloaded" for job in state["jobs"]):
                # A crash can follow the last byte receipt but precede the final
                # observation. Resume completes that bracket without another POST.
                state["source"]["final_observation"] = observation
                state["source"]["final_observation_sha256"] = sha256_json(observation)
            for job in state["jobs"]:
                if job["status"] == "downloaded":
                    continue
                if job["status"] in {"submission_uncertain", "ambiguous_submission"}:
                    state["gaps"].append("export_submission_uncertain_requires_external_reconciliation")
                    break
                if job.get("retry_not_before") and instant < datetime.fromisoformat(job["retry_not_before"]):
                    break
                if job["status"] == "planned":
                    job["status"] = "submission_uncertain"
                    job["submitted_at"] = instant.isoformat()
                    path = _save(directory, state)  # Durable intent BEFORE the query-producing POST.
                    try:
                        response = api.export_workbook(request.workbook_id, tag=request.tag,
                            element_id=request.element_id,
                            page_id=request.page_id if request.file_stem == "page" else None,
                            parameters=request.parameters,
                            format={"type": job["kind"]},
                            row_limit=request.row_limit if job["kind"] == "json" else None)
                        query_id = response["queryId"]
                        if any(other["query_id"] == query_id for other in state["jobs"] if other is not job):
                            raise ValueError("Different export formats returned the same query identity")
                        job["query_id"] = query_id
                        job["creation_response"] = response
                        job["status"] = "submitted"
                    except Exception:
                        job["status"] = "ambiguous_submission"
                        state["gaps"].append("export_submission_uncertain_requires_external_reconciliation")
                        path = _save(directory, state)
                        break
                    path = _save(directory, state)  # Resume a known query ID, never recreate it.
                if job["download_attempts"] >= request.max_download_attempts:
                    state["gaps"].append("download_attempt_budget_exhausted")
                    break
                job["download_attempts"] += 1
                job["status"] = "download_started"
                path = _save(directory, state)
                try:
                    response = api.download_export(job["query_id"])
                except Exception:
                    job["status"] = "download_unresolved"
                    state["gaps"].append("download_transport_or_budget_failure")
                    path = _save(directory, state)
                    break
                job["last_http_status"] = response.status_code
                if response.status_code != 200:
                    job["status"] = "throttled" if response.status_code == 429 else "download_unresolved"
                    if response.status_code == 429:
                        job["retry_not_before"] = _retry_after(response, instant)
                    if response.status_code in {401, 403}:
                        job["status"] = "access_denied_or_auth_required"
                        state["status"] = "blocked"
                    state["gaps"].append("download_not_ready_or_invalid_or_expired_unclassified" if response.status_code not in {401, 403, 429}
                                         else job["status"])
                    path = _save(directory, state)
                    break
                try:
                    attachment = persist_evidence(directory / f"{request.file_stem}.{job['kind']}", response.content,
                        job["kind"], response.headers.get("content-type", ""), request.row_limit)
                except Exception:
                    job["status"] = "evidence_invalid_or_unpersisted"
                    state["status"] = "blocked"
                    state["gaps"].append("download_content_or_private_storage_validation_failed")
                    path = _save(directory, state)
                    break
                attachment.update({"query_id": job["query_id"], "capture_id": request.capture_id,
                    "request_sha256": request_hash, "source_snapshot_sha256": state["source"]["tagged_snapshot_sha256"],
                    "workbook_id": request.workbook_id, "page_id": request.page_id,
                    "element_id": request.element_id, "captured_at": instant.isoformat()})
                state["attachments"].append(attachment)
                job["status"] = "downloaded"
                path = _save(directory, state)
                # Detect drift BETWEEN PNG/results, not only after the pair.
                after = _observation(api, request)
                state["source"]["final_observation"] = after
                state["source"]["final_observation_sha256"] = sha256_json(after)
                if _coherence(after) != state["source"]["coherence_sha256"]:
                    raise ValueError("Source changed during image/result acquisition")
            if state["status"] != "blocked":
                state["status"] = "complete" if all(j["status"] == "downloaded" for j in state["jobs"]) else "partial"
        except Exception:
            state["status"] = "blocked"
            state["gaps"].append("source_identity_membership_configuration_or_capture_failure")
        state["gaps"] = sorted(set(state["gaps"]))
        path = _save(directory, state)
        return {"status": state["status"], "output": str(path), "capture": state}
    finally:
        os.close(fd)

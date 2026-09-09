"""Fail-closed Phase-0 capability spike for one Sigma workbook and one data model.

The agent uses only the read-only methods exposed by :class:`SigmaApi`.  It produces typed,
content-addressed artifacts for human review; it does not mark a gate approved or expose any
target write operation.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Mapping
from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, TypeVar
from urllib.parse import quote

import httpx
from pydantic import BaseModel

from omni_migrator.control_plane.canonical import sha256_json
from omni_migrator.extractors.sigma.api import SigmaApi
from omni_migrator.extractors.sigma.source_contracts import (
    normalize_sigma_document_version,
    parse_sigma_source,
    selected_sigma_document_version,
    sigma_source_binding_key,
    sigma_source_bindings,
)
from omni_migrator.extractors.sigma.capability_contracts import (
    ArtifactInput,
    BehaviorItem,
    BehaviorManifestPayload,
    CapabilityAssessment,
    CapabilityMatrixPayload,
    DataModelSnapshotPayload,
    FallbackPlan,
    GateRecommendation,
    GraphEdge,
    GraphNode,
    ObservationPayload,
    RunManifestPayload,
    SigmaBehaviorManifestArtifact,
    SigmaCapabilityMatrixArtifact,
    SigmaCapabilitySpikeBundle,
    SigmaCapabilitySpikeRequest,
    SigmaDataModelSnapshotArtifact,
    SigmaObservationArtifact,
    SigmaRunManifestArtifact,
    SigmaWorkbookGraphArtifact,
    SpikeMetrics,
    WorkbookGraphPayload,
)


_ArtifactT = TypeVar("_ArtifactT", bound=BaseModel)
_SECRET_KEY_RE = re.compile(
    r"(?i)(secret|password|token|credential|authorization|cookie|private.?key|api.?key)"
)
_SECRET_VALUE_RE = re.compile(
    r"(?i)(bearer\s+\S+|sk-[a-z0-9_-]{8,}|(?:secret|password|token|api[_-]?key)\s*[:=]\s*\S+)"
)
_UNSAFE_PATH_SEGMENT_RE = re.compile(r"[/\\?#%\x00-\x1f\x7f]")
_SAFE_METADATA_KEY_RE = re.compile(r"^[A-Za-z0-9_.~-]{1,256}$")

_DOCS = {
    "api": "https://help.sigmacomputing.com/reference/get-started-sigma-api",
    "whoami": "https://help.sigmacomputing.com/reference/whoami",
    "data_model_code": "https://help.sigmacomputing.com/docs/manage-data-models-as-code",
    "data_model_spec": "https://help.sigmacomputing.com/reference/get-data-model-spec",
    "data_model_sources": "https://help.sigmacomputing.com/reference/list-data-model-sources",
    "workbook_sources": "https://help.sigmacomputing.com/reference/get-workbook-sources",
    "materializations": "https://help.sigmacomputing.com/reference/list-data-model-materialization-schedules",
    "workbook_pages": "https://help.sigmacomputing.com/reference/list-workbook-pages",
    "workbook_elements": "https://help.sigmacomputing.com/reference/list-workbook-elements",
    "workbook_columns": "https://help.sigmacomputing.com/reference/get-workbook-columns",
    "workbook_lineage": "https://help.sigmacomputing.com/reference/list-lineage-tree",
    "workbook_controls": "https://help.sigmacomputing.com/reference/get-workbook-controls",
    "actions": "https://help.sigmacomputing.com/docs/intro-to-actions",
    "workbook_schedules": "https://help.sigmacomputing.com/reference/list-workbook-schedules",
    "input_tables": "https://help.sigmacomputing.com/docs/intro-to-input-tables",
    "saved_views": "https://help.sigmacomputing.com/docs/create-and-share-saved-views",
    "bookmarks_api": "https://help.sigmacomputing.com/reference/get-workbook-bookmarks",
    "versions": "https://help.sigmacomputing.com/docs/workbook-versions-and-version-history",
    "version_history": "https://help.sigmacomputing.com/reference/get-version-history",
    "workbook_tags": "https://help.sigmacomputing.com/reference/get-workbook-tags",
    "embeds": "https://help.sigmacomputing.com/docs/intro-to-embedded-analytics",
    "embeds_api": "https://help.sigmacomputing.com/reference/list-workbook-embeds",
    "rls": "https://help.sigmacomputing.com/docs/set-up-row-level-security",
    "cls": "https://help.sigmacomputing.com/docs/column-level-security",
}


class _ArtifactClock:
    """Issue strict, timezone-aware timestamps so upstream evidence never postdates a child."""

    def __init__(self, start: datetime | None = None) -> None:
        self._current = start or datetime.now(UTC)
        if self._current.tzinfo is None or self._current.utcoffset() is None:
            raise ValueError("capability-spike clock must be timezone-aware")

    def next(self) -> datetime:
        value = self._current
        self._current += timedelta(microseconds=1)
        return value


def _artifact_ref(artifact: BaseModel) -> str:
    return f"artifact-ref://{artifact.artifact_id}"  # type: ignore[attr-defined]


def _artifact_input(artifact: BaseModel) -> ArtifactInput:
    return ArtifactInput(
        artifact_id=artifact.artifact_id,  # type: ignore[attr-defined]
        content_hash=artifact.content_hash,  # type: ignore[attr-defined]
    )


def _make_artifact(
    model: type[_ArtifactT],
    *,
    artifact_id: str,
    schema_version: str,
    request: SigmaCapabilitySpikeRequest,
    created_at: datetime,
    producer: str,
    source_references: tuple[str, ...],
    upstream: tuple[BaseModel, ...],
    classification: str,
    payload: BaseModel,
) -> _ArtifactT:
    material: dict[str, Any] = {
        "artifact_id": artifact_id,
        "schema_version": schema_version,
        "run_id": request.run_id,
        "scope_id": request.scope_id,
        "created_at": created_at,
        "producer": producer,
        "source_references": source_references,
        "upstream_hashes": tuple(_artifact_input(value) for value in upstream),
        "classification": classification,
        "supersession_state": "current",
        "supersedes_artifact_id": None,
        "superseded_by_artifact_id": None,
        "immutable": True,
        "payload": payload,
    }
    draft = model.model_construct(**material, content_hash="0" * 64)
    canonical_material = draft.model_dump(mode="json")
    canonical_material.pop("content_hash")
    return model.model_validate(
        {**canonical_material, "content_hash": sha256_json(canonical_material)}
    )


def validate_artifact_content_hash(artifact: BaseModel) -> bool:
    """Recompute the canonical artifact hash rather than trusting the declared value."""

    material = artifact.model_dump(mode="json")
    declared = material.pop("content_hash")
    return declared == sha256_json(material)


def _fingerprint(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    ).hexdigest()


def _safe_metadata_key(value: object) -> str:
    rendered = str(value)
    if _SAFE_METADATA_KEY_RE.fullmatch(rendered) and not _SECRET_VALUE_RE.search(rendered):
        return rendered
    return f"redacted-key-{_fingerprint(rendered)[:16]}"


def sanitize_source_value(
    value: object,
    *,
    key: str | None = None,
    depth: int = 0,
    max_depth: int = 24,
    max_items: int = 5_000,
    max_string: int = 50_000,
) -> object:
    """Preserve bounded metadata/formulas while hashing identities and removing secrets."""

    if key and _SECRET_KEY_RE.search(key):
        return {"redacted": "secret"}
    if key and _is_identity_key(key):
        values = value if isinstance(value, list) else [value]
        return {
            "redacted": "identity",
            "count": len(values),
            "sha256": [_fingerprint(item) for item in values[:max_items]],
        }
    if depth >= max_depth:
        return {"truncated": "max_depth", "sha256": _fingerprint(value)}
    if isinstance(value, dict):
        items = sorted(value.items(), key=lambda item: str(item[0]))
        result = {
            _safe_metadata_key(child_key): sanitize_source_value(
                child_value,
                key=str(child_key),
                depth=depth + 1,
                max_depth=max_depth,
                max_items=max_items,
                max_string=max_string,
            )
            for child_key, child_value in items[:max_items]
        }
        if len(items) > max_items:
            result["_omitted_keys"] = len(items) - max_items
        return result
    if isinstance(value, list):
        result = [
            sanitize_source_value(
                item,
                key=key,
                depth=depth + 1,
                max_depth=max_depth,
                max_items=max_items,
                max_string=max_string,
            )
            for item in value[:max_items]
        ]
        if len(value) > max_items:
            result.append({"_omitted_items": len(value) - max_items})
        return result
    if isinstance(value, str):
        if _SECRET_VALUE_RE.search(value):
            return {"redacted": "secret", "sha256": _fingerprint(value)}
        if len(value) > max_string:
            return {
                "value": value[:max_string],
                "truncated": True,
                "sha256": _fingerprint(value),
            }
        return value
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return sanitize_source_value(str(value), key=key, depth=depth + 1)


def _row_id(row: Mapping[str, Any], *keys: str) -> str | None:
    for key in keys:
        value = row.get(key)
        if isinstance(value, (str, int)) and not isinstance(value, bool) and str(value).strip():
            return str(value)
    return None


def _safe_path_segment(value: str | None) -> bool:
    return bool(value and value not in {".", ".."} and not _UNSAFE_PATH_SEGMENT_RE.search(value))


@dataclass(frozen=True)
class _Acquisition:
    snapshot: dict[str, Any]
    diagnostics: tuple[dict[str, Any], ...]


def _safe_acquisition_error_type(error: Exception) -> str:
    """Classify acquisition failures without retaining exception text or response values."""

    normalized = str(error).lower()
    if "request budget exhausted" in normalized:
        return "request_budget_exhausted"
    if "another origin" in normalized:
        return "pagination_cross_origin"
    if "another endpoint" in normalized:
        return "pagination_endpoint_change"
    if "changed selector context" in normalized:
        return "pagination_selector_change"
    if "repeated its continuation" in normalized:
        return "pagination_repeated_continuation"
    if "reported hasmore without a continuation" in normalized:
        return "pagination_missing_continuation"
    if "stopped after" in normalized and "entries" in normalized:
        return "pagination_total_mismatch"
    if "exceeded its page safety limit" in normalized:
        return "pagination_page_limit"
    if "pagination" in normalized and (
        "malformed" in normalized
        or "non-object" in normalized
        or "non-list/object" in normalized
        or "omitted its entries" in normalized
    ):
        return "pagination_malformed_response"
    if "not a safe url path segment" in normalized:
        return "unsafe_path_segment"
    return {
        RuntimeError: "runtime_invariant_failure",
        TypeError: "response_type_invalid",
        ValueError: "response_value_invalid",
    }.get(type(error), "acquisition_failure")


def _selected_workbook_version(metadata: Mapping[str, Any]) -> str | None:
    return selected_sigma_document_version(
        metadata,
        "latestVersion",
        "publishedVersion",
        "version",
        "workbookVersion",
    )


def _is_identity_key(value: str) -> bool:
    normalized = re.sub(r"[^a-z0-9]", "", value.lower())
    return (
        normalized
        in {
            "username",
            "createdby",
            "createdbyid",
            "createdbyids",
            "updatedby",
            "updatedbyid",
            "updatedbyids",
        }
        or normalized.startswith("recipient")
        or normalized.endswith(
            (
                "email",
                "emails",
                "emailaddress",
                "emailaddresses",
                "userid",
                "userids",
                "memberid",
                "memberids",
                "ownerid",
                "ownerids",
            )
        )
    )


def _selected_data_model_version(metadata: Mapping[str, Any]) -> str | None:
    return selected_sigma_document_version(
        metadata,
        "latestDocumentVersion",
        "documentVersion",
        "version",
    )


def _selected_tag_source_version(tags: object, tag_name: str | None) -> str | None:
    if not tag_name or not isinstance(tags, list):
        return None
    matches = [
        item
        for item in tags
        if isinstance(item, Mapping)
        and str(item.get("tagName") or item.get("name") or "") == tag_name
    ]
    if len(matches) != 1:
        return None
    return selected_sigma_document_version(
        matches[0], "sourceVersion", "version", "workbookVersion"
    )


def _bounded_acquisition(api: SigmaApi, request: SigmaCapabilitySpikeRequest) -> _Acquisition:
    """Acquire exact IDs directly; never enumerate the organization before the spike."""

    diagnostics: list[dict[str, Any]] = []

    def probe(
        operation: str,
        endpoint: str,
        fetch: Callable[[], Any],
        default: Any,
        *,
        required: bool = False,
    ) -> Any:
        try:
            return fetch()
        except httpx.HTTPStatusError as error:
            diagnostics.append(
                {
                    "operation": operation,
                    "endpoint": endpoint,
                    "required": required,
                    "error_type": "http_status",
                    "status_code": error.response.status_code,
                }
            )
        except httpx.RequestError:
            diagnostics.append(
                {
                    "operation": operation,
                    "endpoint": endpoint,
                    "required": required,
                    "error_type": "transport",
                    "status_code": None,
                }
            )
        except (RuntimeError, TypeError, ValueError) as error:
            error_type = _safe_acquisition_error_type(error)
            diagnostics.append(
                {
                    "operation": operation,
                    "endpoint": endpoint,
                    "required": required,
                    "error_type": error_type,
                    "status_code": None,
                }
            )
        return deepcopy(default)

    def required_object(value: object, *, operation: str, endpoint: str) -> dict[str, Any]:
        if isinstance(value, Mapping):
            return dict(value)
        diagnostics.append(
            {
                "operation": operation,
                "endpoint": endpoint,
                "required": True,
                "error_type": "response_type_invalid",
                "status_code": None,
            }
        )
        return {}

    data_model_id = request.data_model_id
    workbook_id = request.workbook_id
    data_model_prefix = f"/v2/dataModels/{data_model_id}"
    workbook_prefix = f"/v2/workbooks/{workbook_id}"

    identity = required_object(
        probe(
            "whoami",
            "/v2/whoami",
            api.whoami,
            {},
            required=True,
        ),
        operation="whoami",
        endpoint="/v2/whoami",
    )
    observed_organization_id = _row_id(identity, "organizationId")
    observed_user_id = _row_id(identity, "userId")
    if (
        observed_organization_id != request.expected_organization_id
        or observed_user_id != request.expected_user_id
    ):
        diagnostics.append(
            {
                "operation": "whoami_binding",
                "endpoint": "/v2/whoami",
                "required": True,
                "error_type": "identity_mismatch",
                "status_code": None,
            }
        )
        return _Acquisition(
            snapshot={
                "identity": {
                    "organizationId": observed_organization_id,
                    "userId": observed_user_id,
                },
                "dataModel": {"dataModelId": data_model_id, "spec": {}},
                "workbook": {"workbookId": workbook_id, "pages": []},
            },
            diagnostics=tuple(diagnostics),
        )

    workbook_metadata_before = required_object(
        probe(
            "workbook_metadata_before",
            workbook_prefix,
            lambda: api.get_workbook(workbook_id),
            {},
            required=True,
        ),
        operation="workbook_metadata_before",
        endpoint=workbook_prefix,
    )
    workbook_tags_before = probe(
        "workbook_tags_before",
        f"{workbook_prefix}/tags",
        lambda: api.workbook_tags(workbook_id),
        [],
        required=request.source_freeze.strategy == "version_tag",
    )
    workbook_version_history = probe(
        "workbook_version_history",
        f"{workbook_prefix}/version-history",
        lambda: api.workbook_version_history(workbook_id),
        [],
    )

    specification = required_object(
        probe(
            "data_model_specification",
            f"{data_model_prefix}/spec",
            lambda: api.data_model_spec(
                data_model_id,
                document_version=request.source_freeze.data_model_document_version,
            ),
            {},
            required=True,
        ),
        operation="data_model_specification",
        endpoint=f"{data_model_prefix}/spec",
    )
    data_model_metadata = required_object(
        probe(
            "data_model_metadata",
            data_model_prefix,
            lambda: api.get_data_model(data_model_id),
            {},
            required=True,
        ),
        operation="data_model_metadata",
        endpoint=data_model_prefix,
    )
    observed_data_model_id = _row_id(data_model_metadata, "dataModelId", "id")
    if observed_data_model_id != data_model_id:
        diagnostics.append(
            {
                "operation": "data_model_identity_binding",
                "endpoint": data_model_prefix,
                "required": True,
                "error_type": "selected_object_identity_mismatch",
                "status_code": None,
            }
        )
    specification_unavailability_reason = None
    if not specification:
        specification_unavailability_reason = "acquisition_unavailable"
    elif specification.get("dataModelId") != data_model_id:
        specification_unavailability_reason = "identity_mismatch"
        diagnostics.append(
            {
                "operation": "data_model_specification_identity_binding",
                "endpoint": f"{data_model_prefix}/spec",
                "required": True,
                "error_type": "selected_object_identity_mismatch",
                "status_code": None,
            }
        )
    observed_document_version = normalize_sigma_document_version(
        specification.get("documentVersion")
    )
    if observed_document_version != str(request.source_freeze.data_model_document_version):
        specification_unavailability_reason = (
            specification_unavailability_reason or "version_mismatch"
        )
        diagnostics.append(
            {
                "operation": "data_model_version_binding",
                "endpoint": f"{data_model_prefix}/spec",
                "required": True,
                "error_type": "source_version_mismatch",
                "status_code": None,
            }
        )
    data_model = {
        **dict(data_model_metadata),
        "dataModelId": data_model_id,
        # Keep only the response hash/structural observations when the returned definition
        # cannot be bound to the selected object and version. Never relabel another model.
        "spec": specification if specification_unavailability_reason is None else {},
        "specificationUnavailabilityReason": specification_unavailability_reason,
        "sources": probe(
            "data_model_sources",
            f"{data_model_prefix}/sources",
            lambda: api.data_model_sources(data_model_id),
            [],
        ),
        "columns": probe(
            "data_model_columns",
            f"{data_model_prefix}/columns",
            lambda: api.data_model_columns(data_model_id),
            [],
        ),
        "elements": probe(
            "data_model_elements",
            f"{data_model_prefix}/elements",
            lambda: api.data_model_elements(data_model_id),
            [],
        ),
        "lineage": probe(
            "data_model_lineage",
            f"{data_model_prefix}/lineage",
            lambda: api.data_model_lineage(data_model_id),
            [],
        ),
        "grants": probe(
            "data_model_grants",
            "/v2/grants",
            lambda: api.data_model_grants(data_model_id),
            [],
        ),
        "materializationSchedules": probe(
            "data_model_materialization_schedules",
            f"{data_model_prefix}/materializationSchedules",
            lambda: api.data_model_materialization_schedules(data_model_id),
            [],
        ),
        "tags": probe(
            "data_model_tags",
            f"{data_model_prefix}/tags",
            lambda: api.data_model_tags(data_model_id),
            [],
        ),
    }

    observed_workbook_id = _row_id(workbook_metadata_before, "workbookId", "id")
    if observed_workbook_id != workbook_id:
        diagnostics.append(
            {
                "operation": "workbook_identity_binding_before",
                "endpoint": workbook_prefix,
                "required": True,
                "error_type": "selected_object_identity_mismatch",
                "status_code": None,
            }
        )
    pages = probe(
        "workbook_pages",
        f"{workbook_prefix}/pages",
        lambda: api.workbook_pages(
            workbook_id,
            tag=request.source_freeze.workbook_tag_name,
        ),
        [],
        required=True,
    )
    hydrated_pages: list[dict[str, Any]] = []
    for raw_page in pages:
        page = dict(raw_page)
        page_id = _row_id(page, "pageId", "id")
        if not _safe_path_segment(page_id):
            diagnostics.append(
                {
                    "operation": "workbook_page_elements",
                    "endpoint": f"{workbook_prefix}/pages/{{invalid}}/elements",
                    "required": True,
                    "error_type": "invalid_page_id",
                    "status_code": None,
                }
            )
            page["elements"] = []
        else:
            page["elements"] = probe(
                "workbook_page_elements",
                f"{workbook_prefix}/pages/{page_id}/elements",
                lambda page_id=page_id: api.workbook_page_elements(
                    workbook_id,
                    page_id,
                    tag=request.source_freeze.workbook_tag_name,
                ),
                [],
                required=True,
            )
        hydrated_pages.append(page)

    workbook = {
        **dict(workbook_metadata_before),
        "workbookId": workbook_id,
        "pages": hydrated_pages,
        "sources": probe(
            "workbook_sources",
            f"{workbook_prefix}/sources",
            lambda: api.workbook_sources(workbook_id),
            [],
        ),
        "elements": probe(
            "workbook_elements",
            f"{workbook_prefix}/elements",
            lambda: api.workbook_elements(
                workbook_id,
                tag_name=request.source_freeze.workbook_tag_name,
            ),
            [],
            required=True,
        ),
        "columns": probe(
            "workbook_columns",
            f"{workbook_prefix}/columns",
            lambda: api.workbook_columns(workbook_id),
            [],
        ),
        "controls": probe(
            "workbook_controls",
            f"{workbook_prefix}/controls",
            lambda: api.workbook_controls(workbook_id),
            [],
        ),
        "queries": probe(
            "workbook_queries",
            f"{workbook_prefix}/queries",
            lambda: api.workbook_queries(workbook_id),
            [],
        ),
        "lineage": probe(
            "workbook_lineage",
            f"{workbook_prefix}/lineage",
            lambda: api.workbook_lineage(workbook_id),
            [],
        ),
        "grants": probe(
            "workbook_grants",
            "/v2/grants",
            lambda: api.workbook_grants(workbook_id),
            [],
        ),
        "schedules": probe(
            "workbook_schedules",
            f"/v2.1/workbooks/{workbook_id}/schedules",
            lambda: api.workbook_schedules_v21(workbook_id),
            [],
        ),
        "materializationSchedules": probe(
            "workbook_materialization_schedules",
            f"{workbook_prefix}/materialization-schedules",
            lambda: api.workbook_materialization_schedules(workbook_id),
            [],
        ),
        "versionHistory": workbook_version_history,
        "tags": workbook_tags_before,
        "bookmarks": probe(
            "workbook_bookmarks",
            f"{workbook_prefix}/bookmarks",
            lambda: api.workbook_bookmarks(workbook_id),
            [],
        ),
        "taggedBookmarks": (
            probe(
                "workbook_tagged_bookmarks",
                f"{workbook_prefix}/tags/{request.source_freeze.workbook_tag_name}/bookmarks",
                lambda: api.workbook_tagged_bookmarks(
                    workbook_id,
                    request.source_freeze.workbook_tag_name or "",
                ),
                [],
            )
            if request.source_freeze.workbook_tag_name
            else []
        ),
        "embeds": probe(
            "workbook_embeds",
            f"{workbook_prefix}/embeds",
            lambda: api.workbook_embeds(workbook_id),
            [],
        ),
    }
    data_model_metadata_after = required_object(
        probe(
            "data_model_metadata_after",
            data_model_prefix,
            lambda: api.get_data_model(data_model_id),
            {},
            required=True,
        ),
        operation="data_model_metadata_after",
        endpoint=data_model_prefix,
    )
    observed_data_model_id_after = _row_id(data_model_metadata_after, "dataModelId", "id")
    if observed_data_model_id_after != data_model_id:
        diagnostics.append(
            {
                "operation": "data_model_identity_binding_after",
                "endpoint": data_model_prefix,
                "required": True,
                "error_type": "selected_object_identity_mismatch",
                "status_code": None,
            }
        )
    before_data_model_version = _selected_data_model_version(data_model_metadata)
    after_data_model_version = _selected_data_model_version(data_model_metadata_after)
    data_model_stable = (
        bool(before_data_model_version)
        and before_data_model_version == after_data_model_version
        and _fingerprint(data_model_metadata) == _fingerprint(data_model_metadata_after)
    )
    if not data_model_stable:
        diagnostics.append(
            {
                "operation": "data_model_freeze_bracket",
                "endpoint": data_model_prefix,
                "required": True,
                "error_type": "source_freeze_unstable",
                "status_code": None,
            }
        )
    data_model["freezeVerification"] = {
        "beforeVersion": before_data_model_version,
        "afterVersion": after_data_model_version,
        "beforeMetadataSha256": _fingerprint(data_model_metadata),
        "afterMetadataSha256": _fingerprint(data_model_metadata_after),
        "selectedDocumentVersion": str(request.source_freeze.data_model_document_version),
        "stable": data_model_stable,
    }
    workbook_metadata_after = required_object(
        probe(
            "workbook_metadata_after",
            workbook_prefix,
            lambda: api.get_workbook(workbook_id),
            {},
            required=True,
        ),
        operation="workbook_metadata_after",
        endpoint=workbook_prefix,
    )
    workbook_tags_after = probe(
        "workbook_tags_after",
        f"{workbook_prefix}/tags",
        lambda: api.workbook_tags(workbook_id),
        [],
        required=request.source_freeze.strategy == "version_tag",
    )
    observed_workbook_id_after = _row_id(workbook_metadata_after, "workbookId", "id")
    if observed_workbook_id_after != workbook_id:
        diagnostics.append(
            {
                "operation": "workbook_identity_binding_after",
                "endpoint": workbook_prefix,
                "required": True,
                "error_type": "selected_object_identity_mismatch",
                "status_code": None,
            }
        )

    before_version = _selected_workbook_version(workbook_metadata_before)
    after_version = _selected_workbook_version(workbook_metadata_after)
    before_tag_version = _selected_tag_source_version(
        workbook_tags_before, request.source_freeze.workbook_tag_name
    )
    after_tag_version = _selected_tag_source_version(
        workbook_tags_after, request.source_freeze.workbook_tag_name
    )
    freeze_stable = (
        bool(before_version)
        and before_version == after_version
        and _fingerprint(workbook_metadata_before) == _fingerprint(workbook_metadata_after)
    )
    if request.source_freeze.strategy == "version_tag":
        freeze_stable = (
            freeze_stable and bool(before_tag_version) and before_tag_version == after_tag_version
        )
    elif request.source_freeze.strategy == "published_version":
        freeze_stable = freeze_stable and before_version == str(
            request.source_freeze.workbook_published_version
        )

    if not freeze_stable:
        diagnostics.append(
            {
                "operation": "workbook_freeze_bracket",
                "endpoint": workbook_prefix,
                "required": True,
                "error_type": "source_freeze_unstable",
                "status_code": None,
            }
        )
    if request.source_freeze.strategy != "version_tag":
        diagnostics.append(
            {
                "operation": "workbook_definition_selector",
                "endpoint": f"{workbook_prefix}/pages",
                "required": True,
                "error_type": "workbook_definition_selector_unavailable",
                "status_code": None,
            }
        )
    workbook["freezeVerification"] = {
        "strategy": request.source_freeze.strategy,
        "beforeVersion": before_version,
        "afterVersion": after_version,
        "beforeMetadataSha256": _fingerprint(workbook_metadata_before),
        "afterMetadataSha256": _fingerprint(workbook_metadata_after),
        "tagSourceVersionBefore": before_tag_version,
        "tagSourceVersionAfter": after_tag_version,
        "stable": freeze_stable,
        "selectorBoundEndpoints": [
            f"{workbook_prefix}/pages",
            f"{workbook_prefix}/pages/{{pageId}}/elements",
            f"{workbook_prefix}/elements",
        ]
        if request.source_freeze.strategy == "version_tag"
        else [],
        "bracketedUnversionedEndpoints": [
            f"{workbook_prefix}/sources",
            f"{workbook_prefix}/columns",
            f"{workbook_prefix}/controls",
            f"{workbook_prefix}/queries",
            f"{workbook_prefix}/lineage",
            "/v2/grants",
            f"/v2.1/workbooks/{workbook_id}/schedules",
            f"{workbook_prefix}/materialization-schedules",
            f"{workbook_prefix}/bookmarks",
            f"{workbook_prefix}/embeds",
        ],
    }
    return _Acquisition(
        snapshot={
            "identity": {
                "organizationId": observed_organization_id,
                "userId": observed_user_id,
            },
            "dataModel": data_model,
            "workbook": workbook,
        },
        diagnostics=tuple(diagnostics),
    )


def _successful_traces(traces: list[dict[str, Any]], endpoint: str) -> list[dict[str, Any]]:
    return [
        trace
        for trace in traces
        if trace.get("endpoint") == endpoint and 200 <= int(trace.get("status_code", 0)) < 300
    ]


def _trace_version_context(
    request: SigmaCapabilitySpikeRequest, trace: Mapping[str, Any]
) -> tuple[str, dict[str, str]]:
    endpoint = str(trace.get("endpoint") or "")
    query = trace.get("request_query")
    query = query if isinstance(query, Mapping) else {}
    workbook_prefix = f"/v2/workbooks/{request.workbook_id}"
    data_model_prefix = f"/v2/dataModels/{request.data_model_id}"
    if endpoint == "/v2/whoami":
        return "tenant_principal_binding", {}
    if endpoint == f"{data_model_prefix}/spec":
        return "data_model_document_version", {
            "documentVersion": str(request.source_freeze.data_model_document_version)
        }
    if (
        endpoint in {f"{workbook_prefix}/pages", f"{workbook_prefix}/elements"}
        or (endpoint.startswith(f"{workbook_prefix}/pages/") and endpoint.endswith("/elements"))
    ) and ("tag" in query or "tagName" in query):
        return "workbook_tag", {"tag": request.source_freeze.workbook_tag_name or ""}
    if endpoint in {
        workbook_prefix,
        f"{workbook_prefix}/tags",
        f"{workbook_prefix}/version-history",
    }:
        return "lifecycle_bracket", {}
    if endpoint.startswith(workbook_prefix) or endpoint.startswith("/v2.1/workbooks/"):
        return "bracketed_unversioned", {}
    if endpoint.startswith(data_model_prefix) or endpoint == "/v2/grants":
        return "bracketed_unversioned", {}
    return "current_unversioned", {}


def _endpoint_refs(
    observations: tuple[SigmaObservationArtifact, ...], endpoint: str
) -> tuple[str, ...]:
    return tuple(
        _artifact_ref(observation)
        for observation in observations
        if observation.payload.endpoint == endpoint
    )


def _shape_paths(traces: list[dict[str, Any]], endpoints: tuple[str, ...]) -> tuple[str, ...]:
    paths = {
        str(shape["path"])
        for trace in traces
        if trace.get("endpoint") in endpoints and 200 <= int(trace.get("status_code", 0)) < 300
        for shape in trace.get("response_shape", [])
        if isinstance(shape, Mapping) and shape.get("path")
    }
    return tuple(sorted(paths))


def _endpoint_coverage(traces: list[dict[str, Any]], endpoints: tuple[str, ...]) -> tuple[int, int]:
    return sum(bool(_successful_traces(traces, endpoint)) for endpoint in endpoints), len(endpoints)


def _pagination_errors(traces: list[dict[str, Any]]) -> tuple[str, ...]:
    errors: list[str] = []
    sequences: dict[tuple[str, str], list[list[dict[str, Any]]]] = {}
    for trace in traces:
        if 200 <= int(trace.get("status_code", 0)) < 300:
            query = {
                key: value
                for key, value in trace.get("request_query", {}).items()
                if key not in {"cursor", "page", "pageToken", "nextPage", "nextPageToken"}
            }
            key = (str(trace.get("endpoint")), _fingerprint(query))
            endpoint_sequences = sequences.setdefault(key, [])
            if not endpoint_sequences or not endpoint_sequences[-1][-1].get("continuation", {}).get(
                "present"
            ):
                endpoint_sequences.append([])
            endpoint_sequences[-1].append(trace)
    for (endpoint, _), endpoint_sequences in sorted(sequences.items()):
        for items in endpoint_sequences:
            if items[-1].get("continuation", {}).get("present"):
                errors.append(f"{endpoint}: pagination did not close")
            if any(int(item.get("duplicate_id_count", 0)) > 0 for item in items):
                errors.append(f"{endpoint}: duplicate primary IDs within a page")
            declared = [
                item.get("declared_total")
                for item in items
                if item.get("declared_total") is not None
            ]
            if declared:
                if len({int(value) for value in declared}) != 1:
                    errors.append(f"{endpoint}: provider total changed across pages")
                observed = sum(int(item.get("entry_count") or 0) for item in items)
                if observed != int(declared[-1]):
                    errors.append(
                        f"{endpoint}: observed {observed} rows but provider declared {declared[-1]}"
                    )
            identities: set[tuple[str, str]] = set()
            duplicates: set[tuple[str, str]] = set()
            for item in items:
                for id_type, values in item.get("primary_ids", {}).items():
                    for value in values:
                        identity = (str(id_type), str(value))
                        if identity in identities:
                            duplicates.add(identity)
                        identities.add(identity)
            if duplicates:
                errors.append(f"{endpoint}: duplicate source IDs across pages")
    return tuple(dict.fromkeys(errors))


def _workbook_structure_errors(acquisition: _Acquisition) -> tuple[str, ...]:
    workbook = acquisition.snapshot.get("workbook", {})
    pages = workbook.get("pages", [])
    all_elements = workbook.get("elements", [])
    errors: list[str] = []

    page_ids: list[str] = []
    page_element_ids: list[str] = []
    for page in pages if isinstance(pages, list) else []:
        if not isinstance(page, Mapping):
            errors.append("page inventory contains a non-object row")
            continue
        page_id = _row_id(page, "pageId", "id")
        if not _safe_path_segment(page_id):
            errors.append("page inventory contains a missing or unsafe native ID")
            continue
        page_ids.append(page_id)
        elements = page.get("elements", [])
        if not isinstance(elements, list):
            errors.append(f"page {page_id} has a malformed element collection")
            continue
        for element in elements:
            if not isinstance(element, Mapping):
                errors.append(f"page {page_id} contains a non-object element")
                continue
            element_id = _row_id(element, "elementId", "id")
            if not _safe_path_segment(element_id):
                errors.append(f"page {page_id} contains a missing or unsafe element ID")
                continue
            page_element_ids.append(element_id)
            if not str(element.get("type") or "").strip():
                errors.append(f"element {element_id} omitted its type")

    if len(page_ids) != len(set(page_ids)):
        errors.append("page inventory contains duplicate native IDs")
    if len(page_element_ids) != len(set(page_element_ids)):
        errors.append("page element inventory contains duplicate native IDs")

    bulk_element_ids: list[str] = []
    for element in all_elements if isinstance(all_elements, list) else []:
        if not isinstance(element, Mapping):
            errors.append("all-elements inventory contains a non-object row")
            continue
        element_id = _row_id(element, "elementId", "id")
        if not _safe_path_segment(element_id):
            errors.append("all-elements inventory contains a missing or unsafe native ID")
            continue
        bulk_element_ids.append(element_id)
        if not str(element.get("type") or "").strip():
            errors.append(f"all-elements row {element_id} omitted its type")
    if len(bulk_element_ids) != len(set(bulk_element_ids)):
        errors.append("all-elements inventory contains duplicate native IDs")
    if set(page_element_ids) != set(bulk_element_ids):
        errors.append("page and all-elements ID sets do not reconcile")
    return tuple(dict.fromkeys(errors))


def _source_identity_errors(acquisition: _Acquisition) -> tuple[str, ...]:
    errors: list[str] = []
    for owner_key in ("dataModel", "workbook"):
        sources = acquisition.snapshot.get(owner_key, {}).get("sources", [])
        source_ids: list[str] = []
        for source in sources if isinstance(sources, list) else []:
            if not isinstance(source, Mapping):
                errors.append(f"{owner_key} sources contain a non-object row")
                continue
            try:
                parsed = parse_sigma_source(
                    source, owner="data_model" if owner_key == "dataModel" else "workbook"
                )
            except ValueError:
                errors.append(
                    f"{owner_key} source does not match a documented source identity contract"
                )
                continue
            source_ids.extend(
                sigma_source_binding_key(binding) for binding in sigma_source_bindings(parsed)
            )
        if len(source_ids) != len(set(source_ids)):
            errors.append(f"{owner_key} sources contain duplicate native IDs")
    return tuple(dict.fromkeys(errors))


def _formula_structure_errors(acquisition: _Acquisition) -> tuple[str, ...]:
    """Require every formula-bearing column to bind to one observed native element."""

    errors: list[str] = []
    for owner_key in ("dataModel", "workbook"):
        owner = acquisition.snapshot.get(owner_key, {})
        raw_elements = owner.get("elements", []) if isinstance(owner, Mapping) else []
        element_ids = {
            element_id
            for element in (raw_elements if isinstance(raw_elements, list) else [])
            if isinstance(element, Mapping)
            and _safe_path_segment(element_id := _row_id(element, "elementId", "id"))
        }
        raw_columns = owner.get("columns", []) if isinstance(owner, Mapping) else []
        column_bindings: list[tuple[str, str]] = []
        for column in raw_columns if isinstance(raw_columns, list) else []:
            if not isinstance(column, Mapping):
                errors.append(f"{owner_key} columns contain a non-object row")
                continue
            column_id = _row_id(column, "columnId", "id")
            element_id = _row_id(column, "elementId")
            if not _safe_path_segment(column_id):
                errors.append(f"{owner_key} column omitted a safe native ID")
                continue
            if not _safe_path_segment(element_id):
                errors.append(f"{owner_key} column {column_id} omitted a safe element binding")
                continue
            column_bindings.append((element_id, column_id))
            if element_id not in element_ids:
                errors.append(f"{owner_key} column {column_id} references an unobserved element")
        if len(column_bindings) != len(set(column_bindings)):
            errors.append(f"{owner_key} columns contain duplicate native bindings")
    return tuple(dict.fromkeys(errors))


def _capability_matrix(
    request: SigmaCapabilitySpikeRequest,
    acquisition: _Acquisition,
    traces: list[dict[str, Any]],
    observations: tuple[SigmaObservationArtifact, ...],
) -> CapabilityMatrixPayload:
    workbook_id = request.workbook_id
    data_model_id = request.data_model_id
    wp = f"/v2/workbooks/{workbook_id}"
    dp = f"/v2/dataModels/{data_model_id}"
    page_endpoints = tuple(
        f"{wp}/pages/{_row_id(page, 'pageId', 'id')}/elements"
        for page in acquisition.snapshot["workbook"].get("pages", [])
        if _row_id(page, "pageId", "id") is not None
    )
    structure_errors = _workbook_structure_errors(acquisition)
    source_errors = _source_identity_errors(acquisition)
    formula_errors = _formula_structure_errors(acquisition)
    exclusions = {item.property_id: item for item in request.approved_exclusions}

    def fallback(
        capability_id: str,
        method: str,
        acceptance_test: str,
    ) -> FallbackPlan:
        exclusion = exclusions.get(capability_id)
        if exclusion is not None:
            return FallbackPlan(
                method="explicit_unsupported_disposition",
                owner_ref=exclusion.approved_by_ref,
                approval_state="proposed",
                approval_ref=None,
                acceptance_test=acceptance_test,
            )
        return FallbackPlan(
            method=method,
            owner_ref=request.manual_evidence_owner_ref,
            approval_state="proposed",
            approval_ref=None,
            acceptance_test=acceptance_test,
        )

    def assessment(
        capability_id: str,
        object_types: tuple[str, ...],
        properties: tuple[str, ...],
        endpoints: tuple[str, ...],
        docs: tuple[str, ...],
        *,
        expected_shape_suffixes: tuple[str, ...] = (),
        additional_missing: tuple[str, ...] = (),
        maximum_status: str = "verified_full",
        fallback_plan: FallbackPlan | None = None,
        critical: bool = False,
    ) -> CapabilityAssessment:
        successes, total = _endpoint_coverage(traces, endpoints)
        paths = _shape_paths(traces, endpoints)
        missing_shape = tuple(
            suffix
            for suffix in expected_shape_suffixes
            if not any(path.endswith(suffix) for path in paths)
        )
        if successes == 0:
            status = "manual_required" if fallback_plan is not None else "unavailable"
        elif successes < total or missing_shape or additional_missing:
            status = "verified_partial"
        else:
            status = maximum_status
        missing = tuple(
            [
                *(
                    f"endpoint:{endpoint}"
                    for endpoint in endpoints
                    if not _successful_traces(traces, endpoint)
                ),
                *(f"shape:{suffix}" for suffix in missing_shape),
                *additional_missing,
            ]
        )
        evidence_refs = tuple(
            dict.fromkeys(
                ref for endpoint in endpoints for ref in _endpoint_refs(observations, endpoint)
            )
        )
        blocks = status == "unavailable" or (critical and bool(missing))
        return CapabilityAssessment(
            capability_id=capability_id,
            object_types=object_types,
            property_names=properties,
            status=status,  # type: ignore[arg-type]
            evidence_refs=evidence_refs,
            documentation_refs=docs,
            observed_shape_paths=paths,
            missing_properties=missing,
            fallback=fallback_plan if status != "verified_full" else None,
            blocks_full_adapter=blocks,
            rationale=(
                "Observed every required endpoint and property shape for the bounded pilot."
                if status == "verified_full"
                else "The bounded pilot needs additional or manual evidence before this property can be treated as complete."
            ),
        )

    rows: list[CapabilityAssessment] = []
    identity = acquisition.snapshot.get("identity", {})
    identity_matches = (
        identity.get("organizationId") == request.expected_organization_id
        and identity.get("userId") == request.expected_user_id
    )
    rows.append(
        CapabilityAssessment(
            capability_id="tenant_principal_binding",
            object_types=("organization", "principal"),
            property_names=("organization ID", "credential owner user ID", "API base URL"),
            status="verified_full" if identity_matches else "unavailable",
            evidence_refs=_endpoint_refs(observations, "/v2/whoami"),
            documentation_refs=(_DOCS["whoami"], _DOCS["api"]),
            observed_shape_paths=_shape_paths(traces, ("/v2/whoami",)),
            missing_properties=()
            if identity_matches
            else ("whoami did not match the approved run identity",),
            fallback=None,
            blocks_full_adapter=not identity_matches,
            rationale=(
                "The credential resolved to the exact approved organization and principal."
                if identity_matches
                else "Acquisition stopped before selected content because the credential identity did not match."
            ),
        )
    )
    object_binding_errors = tuple(
        f"{item['operation']}:{item['error_type']}"
        for item in acquisition.diagnostics
        if item["error_type"] == "selected_object_identity_mismatch"
    )
    rows.append(
        assessment(
            "selected_object_identity",
            ("workbook", "data_model"),
            ("workbook ID", "data-model ID"),
            (wp, dp),
            (_DOCS["api"],),
            expected_shape_suffixes=(".workbookId", ".dataModelId"),
            additional_missing=object_binding_errors,
            critical=True,
        )
    )
    rows.append(
        assessment(
            "data_model_specification",
            ("data_model",),
            ("sources", "elements", "columns", "formulas", "metrics", "relationships", "security"),
            (f"{dp}/spec",),
            (_DOCS["data_model_code"], _DOCS["data_model_spec"]),
            expected_shape_suffixes=(".pages",),
            maximum_status="verified_partial",
            fallback_plan=fallback(
                "data_model_specification",
                "customer_operated_export",
                "A version-bound data-model representation is captured, hashed, reviewed, and reconciled to the selected model ID.",
            ),
            critical=True,
        )
    )
    rows.append(
        assessment(
            "workbook_structure",
            ("workbook", "page", "element"),
            ("page IDs", "element IDs", "element types", "parent relationships"),
            (f"{wp}/pages", f"{wp}/elements", *page_endpoints),
            (_DOCS["workbook_pages"], _DOCS["workbook_elements"]),
            expected_shape_suffixes=(".pageId", ".elementId", ".type"),
            additional_missing=structure_errors,
            fallback_plan=fallback(
                "workbook_structure",
                "structured_owner_manifest",
                "Every selected page and element ID is reconciled to a version-bound owner manifest.",
            ),
            critical=True,
        )
    )
    rows.append(
        assessment(
            "formulas",
            ("data_model", "workbook", "column"),
            ("formula text", "element binding", "column identity", "evaluation context"),
            (f"{dp}/columns", f"{wp}/columns"),
            (_DOCS["workbook_columns"], _DOCS["data_model_code"]),
            expected_shape_suffixes=(".formula", ".columnId"),
            additional_missing=formula_errors,
            maximum_status="verified_partial",
            fallback_plan=fallback(
                "formulas",
                "structured_owner_manifest",
                "All pilot formulas are captured with IDs, grouping/filter context, hashes, and owner review.",
            ),
            critical=True,
        )
    )
    rows.append(
        assessment(
            "sources",
            ("data_model", "workbook", "source"),
            ("source identity", "source type", "warehouse/data-model binding"),
            (f"{dp}/sources", f"{wp}/sources"),
            (_DOCS["data_model_sources"], _DOCS["workbook_sources"]),
            maximum_status="verified_partial",
            additional_missing=source_errors,
            fallback_plan=fallback(
                "sources",
                "structured_owner_manifest",
                "Every source is reconciled to an immutable warehouse or model identity.",
            ),
            critical=True,
        )
    )
    rows.append(
        assessment(
            "lineage",
            ("data_model", "workbook", "element"),
            ("upstream identities", "element lineage", "source lineage"),
            (f"{dp}/lineage", f"{wp}/lineage"),
            (_DOCS["workbook_lineage"],),
            maximum_status="verified_partial",
            fallback_plan=fallback(
                "lineage",
                "structured_owner_manifest",
                "UI lineage evidence is version-bound and reconciled to every pilot source and element.",
            ),
            critical=True,
        )
    )
    rows.append(
        assessment(
            "controls",
            ("workbook", "control"),
            ("ID", "type", "default", "domain", "targets", "scope"),
            (f"{wp}/controls",),
            (_DOCS["workbook_controls"],),
            maximum_status="verified_partial",
            fallback_plan=fallback(
                "controls",
                "structured_owner_manifest",
                "A reviewer captures defaults, allowed values, dependencies, targets, and propagation for each control.",
            ),
        )
    )
    rows.append(
        CapabilityAssessment(
            capability_id="actions",
            object_types=("workbook", "action"),
            property_names=(
                "trigger",
                "condition",
                "order",
                "side effect",
                "retry",
                "failure handling",
            ),
            status="manual_required",
            evidence_refs=(),
            documentation_refs=(_DOCS["actions"],),
            observed_shape_paths=(),
            missing_properties=("complete action definitions",),
            fallback=fallback(
                "actions",
                "structured_owner_manifest",
                "Every action sequence is exercised in a safe source context and captured with ordered effects and failure behavior.",
            ),
            blocks_full_adapter=False,
            rationale="No complete action-definition API is treated as authoritative in this first pass.",
        )
    )
    for capability_id, behavior_type, method, docs_key, acceptance in (
        (
            "layout",
            "layout",
            "version_bound_render",
            "workbook_elements",
            "Version-bound renders and a structured layout manifest cover hierarchy, clipping, and responsive priority.",
        ),
        (
            "formatting",
            "formatting",
            "version_bound_render",
            "workbook_elements",
            "Version-bound renders capture formatting that changes analytical meaning.",
        ),
    ):
        rows.append(
            CapabilityAssessment(
                capability_id=capability_id,
                object_types=("workbook", behavior_type),
                property_names=(capability_id,),
                status="manual_required",
                evidence_refs=(),
                documentation_refs=(_DOCS[docs_key],),
                observed_shape_paths=(),
                missing_properties=(f"complete {capability_id} definition",),
                fallback=fallback(capability_id, method, acceptance),
                blocks_full_adapter=False,
                rationale="The API evidence is not treated as a complete portable workbook definition.",
            )
        )
    rows.append(
        assessment(
            "security",
            ("workbook", "data_model", "principal"),
            ("grants", "RLS", "CLS", "effective access", "leakage behavior"),
            ("/v2/grants", f"{dp}/spec"),
            (_DOCS["rls"], _DOCS["cls"]),
            maximum_status="verified_partial",
            fallback_plan=fallback(
                "security",
                "persona_test",
                "Approved allowed and denied personas prove row, column, export, owner, and derived-field behavior.",
            ),
        )
    )
    rows.append(
        assessment(
            "schedules",
            ("workbook", "schedule"),
            (
                "cadence",
                "timezone",
                "conditions",
                "variables",
                "version/view",
                "destination class",
                "status",
            ),
            (f"/v2.1/workbooks/{workbook_id}/schedules",),
            (_DOCS["workbook_schedules"],),
            maximum_status="verified_partial",
            fallback_plan=fallback(
                "schedules",
                "structured_owner_manifest",
                "Every delivery schedule is reconciled without copying recipient addresses and has a replacement acceptance test.",
            ),
        )
    )
    rows.append(
        assessment(
            "materialization_schedules",
            ("data_model", "workbook", "materialization"),
            ("element identity", "cadence", "timezone", "paused state", "freshness dependency"),
            (f"{dp}/materializationSchedules", f"{wp}/materialization-schedules"),
            (_DOCS["materializations"],),
            maximum_status="verified_partial",
            fallback_plan=fallback(
                "materialization_schedules",
                "structured_owner_manifest",
                "Every materialization schedule and freshness dependency is reconciled to its element and an approved replacement.",
            ),
            critical=True,
        )
    )
    bookmark_endpoints = [f"{wp}/bookmarks"]
    if request.source_freeze.workbook_tag_name:
        bookmark_endpoints.append(f"{wp}/tags/{request.source_freeze.workbook_tag_name}/bookmarks")
    rows.append(
        assessment(
            "saved_views",
            ("workbook", "saved_view"),
            ("bookmark ID", "name", "shared/default state", "tag binding", "personal visibility"),
            tuple(bookmark_endpoints),
            (_DOCS["saved_views"], _DOCS["bookmarks_api"]),
            maximum_status="verified_partial",
            fallback_plan=fallback(
                "saved_views",
                "structured_owner_manifest",
                "Shared and critical personal saved views are inventoried by owners and tested against the frozen workbook.",
            ),
        )
    )
    rows.append(
        assessment(
            "embeds",
            ("workbook", "embed"),
            (
                "static embed identity",
                "public flag",
                "source scope",
                "host claims",
                "runtime events",
            ),
            (f"{wp}/embeds",),
            (_DOCS["embeds"], _DOCS["embeds_api"]),
            maximum_status="verified_partial",
            fallback_plan=fallback(
                "embeds",
                "host_application_manifest",
                "Static embed IDs are reconciled with authorized host code and runtime event traces.",
            ),
        )
    )
    tag_names = {
        str(item.get("name") or item.get("tagName"))
        for item in acquisition.snapshot["workbook"].get("tags", [])
        if item.get("name") or item.get("tagName")
    }
    version_missing: list[str] = [
        "workbook detail endpoints do not share one universal numeric version selector",
        "draft definitions are not exposed by a documented selector",
    ]
    if (
        request.source_freeze.workbook_tag_name
        and request.source_freeze.workbook_tag_name not in tag_names
    ):
        version_missing.append("approved workbook tag was not observed in the tag inventory")
    freeze_verification = acquisition.snapshot["workbook"].get("freezeVerification", {})
    freeze_diagnostics = tuple(
        f"{item['operation']}:{item['error_type']}"
        for item in acquisition.diagnostics
        if item["error_type"]
        in {
            "source_freeze_unstable",
            "source_version_mismatch",
            "workbook_definition_selector_unavailable",
        }
    )
    version_missing.extend(freeze_diagnostics)
    freeze_viable = (
        request.source_freeze.strategy == "version_tag"
        and request.source_freeze.workbook_tag_name in tag_names
        and freeze_verification.get("stable") is True
        and not freeze_diagnostics
    )
    rows.append(
        CapabilityAssessment(
            capability_id="versions",
            object_types=("workbook", "version_tag", "data_model"),
            property_names=(
                "published version",
                "tag",
                "draft visibility",
                "saved-view binding",
                "data-model documentVersion",
            ),
            status=("verified_partial" if freeze_viable else "manual_required"),
            evidence_refs=tuple(
                dict.fromkeys(
                    ref
                    for endpoint in (f"{wp}/version-history", f"{wp}/tags", f"{dp}/spec")
                    for ref in _endpoint_refs(observations, endpoint)
                )
            ),
            documentation_refs=(
                _DOCS["versions"],
                _DOCS["version_history"],
                _DOCS["workbook_tags"],
                _DOCS["data_model_spec"],
            ),
            observed_shape_paths=_shape_paths(
                traces,
                (f"{wp}/version-history", f"{wp}/tags", f"{dp}/spec"),
            ),
            missing_properties=tuple(version_missing),
            fallback=fallback(
                "versions",
                "structured_owner_manifest",
                "The approved freeze reference resolves to the exact published version or version tag used by every observation.",
            ),
            blocks_full_adapter=not freeze_viable,
            rationale=(
                "Tag-bound definition endpoints were bracketed by stable workbook metadata and tag observations; unversioned endpoints still require human review."
                if freeze_viable
                else "The declared workbook freeze was not proven stable and selector-bound for this run."
            ),
        )
    )
    element_paths = (f"{wp}/elements", *page_endpoints)
    element_success, _ = _endpoint_coverage(traces, element_paths)
    input_tables = [
        element
        for page in acquisition.snapshot["workbook"].get("pages", [])
        for element in page.get("elements", [])
        if re.sub(r"[^a-z]", "", str(element.get("type", "")).lower()) == "inputtable"
    ]
    rows.append(
        CapabilityAssessment(
            capability_id="input_tables",
            object_types=("workbook", "input_table"),
            property_names=(
                "existence",
                "schema",
                "keys",
                "validation",
                "permissions",
                "history",
                "extraction route",
            ),
            status="verified_partial" if element_success else "manual_required",
            evidence_refs=tuple(
                dict.fromkeys(
                    ref
                    for endpoint in element_paths
                    for ref in _endpoint_refs(observations, endpoint)
                )
            ),
            documentation_refs=(_DOCS["input_tables"],),
            observed_shape_paths=_shape_paths(traces, element_paths),
            missing_properties=(
                "configuration and history require supported extraction and owner review",
                *(
                    ()
                    if input_tables
                    else ("no input table observed; exact element closure is the absence proof",)
                ),
            ),
            fallback=fallback(
                "input_tables",
                "customer_operated_export",
                "Current values and required history reconcile to an approved destination with keys, validation, permissions, and recovery tests.",
            ),
            blocks_full_adapter=False,
            rationale="Element inventory can prove presence or bounded absence, but not complete writeback behavior.",
        )
    )
    rows.append(
        assessment(
            "principal_visibility",
            ("principal", "workbook", "data_model"),
            (
                "credential owner identity",
                "effective account type",
                "endpoint visibility",
                "permission-hidden content",
            ),
            ("/v2/whoami",),
            (_DOCS["whoami"], _DOCS["api"]),
            maximum_status="verified_partial",
            fallback_plan=fallback(
                "principal_visibility",
                "structured_owner_manifest",
                "An administrator confirms the principal's account type and per-endpoint visibility limitations.",
            ),
        )
    )

    pagination_errors = tuple(
        dict.fromkeys(
            (
                *_pagination_errors(traces),
                *(
                    f"{item['endpoint']}: {item['error_type']}"
                    for item in acquisition.diagnostics
                    if str(item["error_type"]).startswith("pagination_")
                ),
            )
        )
    )
    rows.append(
        CapabilityAssessment(
            capability_id="pagination",
            object_types=("api_response",),
            property_names=(
                "opaque cursor",
                "closed continuation",
                "provider total",
                "duplicate IDs",
            ),
            status="verified_full" if traces and not pagination_errors else "unavailable",
            evidence_refs=tuple(_artifact_ref(item) for item in observations),
            documentation_refs=(_DOCS["api"],),
            observed_shape_paths=(),
            missing_properties=pagination_errors
            or (() if traces else ("no API responses observed",)),
            fallback=None,
            blocks_full_adapter=bool(pagination_errors or not traces),
            rationale=(
                "All observed endpoint sequences closed without total or duplicate-ID conflicts."
                if traces and not pagination_errors
                else "Pagination evidence is incomplete or internally inconsistent."
            ),
        )
    )

    deprecated = tuple(
        sorted(
            {
                "hasMore"
                for trace in traces
                for shape in trace.get("response_shape", [])
                if isinstance(shape, Mapping) and str(shape.get("path", "")).endswith(".hasMore")
            }
        )
    )
    blocking = tuple(sorted(row.capability_id for row in rows if row.blocks_full_adapter))
    manual = tuple(
        sorted(
            row.capability_id
            for row in rows
            if row.status in {"manual_required", "verified_partial"} and row.fallback is not None
        )
    )
    return CapabilityMatrixPayload(
        workbook_id=workbook_id,
        data_model_id=data_model_id,
        assessments=tuple(rows),
        matrix_status="blocked" if blocking else "ready_for_human_review",
        blocking_capability_ids=blocking,
        manual_fallback_capability_ids=manual,
        deprecated_surfaces_encountered=deprecated,
        live_tenant_evidence=request.evidence_mode == "live_tenant",
    )


def _selected_properties(value: Mapping[str, Any], names: tuple[str, ...]) -> dict[str, Any]:
    return {name: sanitize_source_value(value[name], key=name) for name in names if name in value}


def _workbook_graph(
    request: SigmaCapabilitySpikeRequest,
    acquisition: _Acquisition,
) -> WorkbookGraphPayload:
    workbook = acquisition.snapshot["workbook"]
    workbook_id = request.workbook_id
    workbook_node_id = f"sigma.workbook.{workbook_id}"
    nodes: dict[str, GraphNode] = {}
    edges: set[tuple[str, str, str]] = set()
    unresolved: set[str] = {
        "actions require a reviewed behavior manifest",
        "layout and formatting require version-bound rendered evidence",
        "saved-view visibility requires owner reconciliation",
        "embed runtime behavior requires separately authorized host evidence",
    }

    def add_node(node: GraphNode) -> None:
        if prior := nodes.get(node.node_id):
            if prior != node:
                unresolved.add(f"conflicting duplicate node identity: {node.node_id}")
            return
        nodes[node.node_id] = node

    add_node(
        GraphNode(
            node_id=workbook_node_id,
            node_type="workbook",
            native_id=workbook_id,
            parent_node_id=None,
            properties=_selected_properties(
                workbook,
                (
                    "name",
                    "path",
                    "archived",
                    "version",
                    "latestVersion",
                    "publishedVersion",
                    "tags",
                    "createdAt",
                    "updatedAt",
                ),
            ),
            source_refs=(f"sigma://workbooks/{workbook_id}",),
        )
    )
    for page in workbook.get("pages", []):
        page_id = _row_id(page, "pageId", "id")
        if not _safe_path_segment(page_id):
            unresolved.add("workbook page omitted a safe native ID")
            continue
        page_node_id = f"sigma.page.{page_id}"
        add_node(
            GraphNode(
                node_id=page_node_id,
                node_type="page",
                native_id=page_id,
                parent_node_id=workbook_node_id,
                properties=_selected_properties(
                    page, ("name", "hidden", "index", "createdAt", "updatedAt")
                ),
                source_refs=(f"sigma://workbooks/{workbook_id}/pages/{page_id}",),
            )
        )
        edges.add((workbook_node_id, page_node_id, "contains"))
        for element in page.get("elements", []):
            element_id = _row_id(element, "elementId", "id")
            if not _safe_path_segment(element_id):
                unresolved.add(f"page {page_id} contains an element without a safe native ID")
                continue
            element_type = str(element.get("type") or "unknown")
            element_node_id = f"sigma.element.{element_id}"
            add_node(
                GraphNode(
                    node_id=element_node_id,
                    node_type=element_type,
                    native_id=element_id,
                    parent_node_id=page_node_id,
                    properties=_selected_properties(
                        element,
                        (
                            "name",
                            "type",
                            "vizualizationType",
                            "visualizationType",
                            "hidden",
                            "layout",
                            "format",
                        ),
                    ),
                    source_refs=(f"sigma://workbooks/{workbook_id}/elements/{element_id}",),
                )
            )
            edges.add((page_node_id, element_node_id, "contains"))

    for column in workbook.get("columns", []):
        column_id = _row_id(column, "columnId", "id")
        element_id = _row_id(column, "elementId")
        if not _safe_path_segment(column_id):
            unresolved.add("workbook column omitted a safe native ID")
            continue
        if not _safe_path_segment(element_id):
            unresolved.add(f"workbook column {column_id} omitted a safe element binding")
            continue
        parent = f"sigma.element.{element_id}"
        if parent not in nodes:
            unresolved.add(f"workbook column {column_id} references an unobserved element")
            continue
        node_id = f"sigma.column.{element_id}.{column_id}"
        add_node(
            GraphNode(
                node_id=node_id,
                node_type="column",
                native_id=column_id,
                parent_node_id=parent,
                properties=_selected_properties(
                    column,
                    ("name", "label", "type", "dataType", "formula", "hidden", "format"),
                ),
                source_refs=(f"sigma://workbooks/{workbook_id}/columns/{column_id}",),
            )
        )
        edges.add((parent, node_id, "has_column"))

    for source in workbook.get("sources", []):
        try:
            parsed_source = parse_sigma_source(source, owner="workbook")
        except ValueError:
            unresolved.add("workbook source does not match a documented source identity contract")
            continue
        for binding in sigma_source_bindings(parsed_source):
            binding_hash = sha256_json(binding)
            node_id = f"sigma.source.{binding_hash}"
            add_node(
                GraphNode(
                    node_id=node_id,
                    node_type="source",
                    native_id=sigma_source_binding_key(binding),
                    parent_node_id=workbook_node_id,
                    properties={
                        **_selected_properties(source, ("name", "path", "definition")),
                        **binding,
                    },
                    source_refs=(f"sigma://workbooks/{workbook_id}/sources/{binding_hash}",),
                )
            )
            edges.add((workbook_node_id, node_id, "uses_source"))

    for schedule in workbook.get("schedules", []):
        schedule_id = _row_id(schedule, "scheduleId", "scheduledNotificationId", "id")
        if not _safe_path_segment(schedule_id):
            unresolved.add("workbook schedule omitted a safe native ID")
            continue
        node_id = f"sigma.schedule.{schedule_id}"
        add_node(
            GraphNode(
                node_id=node_id,
                node_type="schedule",
                native_id=schedule_id,
                parent_node_id=workbook_node_id,
                properties=_selected_properties(
                    schedule,
                    (
                        "status",
                        "frequency",
                        "timezone",
                        "condition",
                        "format",
                        "versionTag",
                        "bookmarkId",
                    ),
                ),
                source_refs=(f"sigma://workbooks/{workbook_id}/schedules/{schedule_id}",),
            )
        )
        edges.add((workbook_node_id, node_id, "delivered_by"))

    sorted_nodes = tuple(nodes[key] for key in sorted(nodes))
    return WorkbookGraphPayload(
        workbook_id=workbook_id,
        source_freeze=request.source_freeze,
        nodes=sorted_nodes,
        edges=tuple(
            GraphEdge(from_node_id=source, to_node_id=target, relation=relation)
            for source, target, relation in sorted(edges)
        ),
        exact_node_set_sha256=sha256_json(
            [
                {"node_id": node.node_id, "node_type": node.node_type, "native_id": node.native_id}
                for node in sorted_nodes
            ]
        ),
        unresolved_behavior=tuple(sorted(unresolved)),
    )


def _behavior_manifest(
    request: SigmaCapabilitySpikeRequest,
    acquisition: _Acquisition,
    observations: tuple[SigmaObservationArtifact, ...],
) -> BehaviorManifestPayload:
    workbook = acquisition.snapshot["workbook"]
    workbook_id = request.workbook_id
    exclusions = {item.property_id: item for item in request.approved_exclusions}
    items: list[BehaviorItem] = []

    def add_manual(
        behavior_id: str,
        behavior_type: str,
        source_ref: str,
        acceptance_test: str,
        *,
        disposition: str = "manual_capture_required",
    ) -> None:
        exclusion = exclusions.get(behavior_type) or exclusions.get(behavior_id)
        items.append(
            BehaviorItem(
                behavior_id=behavior_id,
                behavior_type=behavior_type,  # type: ignore[arg-type]
                source_ref=source_ref,
                disposition=disposition,  # type: ignore[arg-type]
                evidence_refs=(),
                owner_ref=exclusion.approved_by_ref
                if exclusion
                else request.manual_evidence_owner_ref,
                acceptance_test=acceptance_test,
                blocking=True,
            )
        )

    control_refs = _endpoint_refs(observations, f"/v2/workbooks/{workbook_id}/controls")
    for index, control in enumerate(workbook.get("controls", [])):
        control_id = _row_id(control, "controlId", "elementId", "id") or f"unidentified-{index + 1}"
        items.append(
            BehaviorItem(
                behavior_id=f"control.{control_id}",
                behavior_type="control",
                source_ref=f"sigma://workbooks/{workbook_id}/controls/{control_id}",
                disposition="partial",
                evidence_refs=control_refs,
                owner_ref=request.manual_evidence_owner_ref,
                acceptance_test="Capture and test default, domain, dependency, targets, scope, and cross-page propagation.",
                blocking=True,
            )
        )

    for page in workbook.get("pages", []):
        for element in page.get("elements", []):
            normalized_type = re.sub(r"[^a-z]", "", str(element.get("type", "")).lower())
            if normalized_type != "inputtable":
                continue
            element_id = _row_id(element, "elementId", "id") or _fingerprint(element)[:16]
            items.append(
                BehaviorItem(
                    behavior_id=f"input_table.{element_id}",
                    behavior_type="input_table",
                    source_ref=f"sigma://workbooks/{workbook_id}/elements/{element_id}",
                    disposition="external_redesign_required",
                    evidence_refs=(),
                    owner_ref=request.manual_evidence_owner_ref,
                    acceptance_test="Reconcile current values and required history, validation, permissions, protected columns, keys, side effects, and recovery in a non-production test.",
                    blocking=True,
                )
            )

    schedule_refs = _endpoint_refs(observations, f"/v2.1/workbooks/{workbook_id}/schedules")
    for index, schedule in enumerate(workbook.get("schedules", [])):
        schedule_id = (
            _row_id(schedule, "scheduleId", "scheduledNotificationId", "id")
            or f"unidentified-{index + 1}"
        )
        items.append(
            BehaviorItem(
                behavior_id=f"schedule.{schedule_id}",
                behavior_type="schedule",
                source_ref=f"sigma://workbooks/{workbook_id}/schedules/{schedule_id}",
                disposition="partial",
                evidence_refs=schedule_refs,
                owner_ref=request.manual_evidence_owner_ref,
                acceptance_test="Verify cadence, timezone, conditions, variables, saved version/view, destination class, run-as identity, status, and replacement delivery.",
                blocking=True,
            )
        )

    generic = (
        (
            "action.manual",
            "action",
            "Every action trigger, ordered effect, condition, target, retry, failure, feedback, and authorization is captured and safely tested.",
            "external_redesign_required",
        ),
        (
            "saved_view.manual",
            "saved_view",
            "Shared and critical personal saved views reconcile to owner evidence and frozen-workbook tests.",
            "manual_capture_required",
        ),
        (
            "embed.manual",
            "embed",
            "Authorized host code and runtime traces prove claims, events, handlers, theming, localization, and version routing.",
            "external_redesign_required",
        ),
        (
            "layout.manual",
            "layout",
            "Version-bound renders prove hierarchy, placement, clipping, responsive priority, and accessibility.",
            "manual_capture_required",
        ),
        (
            "formatting.manual",
            "formatting",
            "Version-bound renders and a structured manifest capture formatting that changes analytical meaning.",
            "manual_capture_required",
        ),
        (
            "security.manual",
            "security",
            "Allowed and denied persona tests prove RLS, CLS, export, owner, saved-view, and derived-field leakage behavior.",
            "manual_capture_required",
        ),
    )
    for behavior_id, behavior_type, acceptance_test, disposition in generic:
        add_manual(
            behavior_id,
            behavior_type,
            f"sigma://workbooks/{workbook_id}",
            acceptance_test,
            disposition=disposition,
        )

    unresolved = tuple(sorted(item.behavior_id for item in items if item.blocking))
    return BehaviorManifestPayload(
        workbook_id=workbook_id,
        behaviors=tuple(sorted(items, key=lambda item: item.behavior_id)),
        closed_denominator=not unresolved,
        unresolved_behavior_ids=unresolved,
    )


def run_sigma_capability_spike(
    request: SigmaCapabilitySpikeRequest | Mapping[str, Any],
    *,
    api: SigmaApi,
    started_at: datetime | None = None,
) -> SigmaCapabilitySpikeBundle:
    """Run the bounded Phase-0 agent and return artifacts ready for human review."""

    request = (
        request
        if isinstance(request, SigmaCapabilitySpikeRequest)
        else SigmaCapabilitySpikeRequest.model_validate(request)
    )
    if api.base_url.rstrip("/") != request.api_base_url.rstrip("/"):
        raise ValueError("SigmaApi base URL does not match the approved capability-spike request")
    if api.request_budget is None:
        api.request_budget = request.request_budget
    elif api.request_budget != request.request_budget:
        raise ValueError("SigmaApi request budget does not match the approved request")
    if api.per_endpoint_request_budget is None:
        api.per_endpoint_request_budget = request.per_endpoint_request_budget
    elif api.per_endpoint_request_budget != request.per_endpoint_request_budget:
        raise ValueError("SigmaApi per-endpoint budget does not match the approved request")

    clock = _ArtifactClock(started_at)
    classification = (
        "observed_tenant_behavior"
        if request.evidence_mode == "live_tenant"
        else "synthetic_fixture"
    )
    source_refs = (
        f"sigma://workbooks/{request.workbook_id}",
        f"sigma://dataModels/{request.data_model_id}",
    )
    run_manifest = _make_artifact(
        SigmaRunManifestArtifact,
        artifact_id=f"sigma-run-manifest.{request.run_id}",
        schema_version="sigma-run-manifest.v1",
        request=request,
        created_at=clock.next(),
        producer="agent-ref://sigma-to-omni-architect",
        source_references=source_refs,
        upstream=(),
        classification="assumption",
        payload=RunManifestPayload(
            organization_ref=request.organization_ref,
            expected_organization_id=request.expected_organization_id,
            api_base_url=request.api_base_url,
            approved_api_hosts=request.approved_api_hosts,
            principal_ref=request.principal_ref,
            expected_user_id=request.expected_user_id,
            effective_account_type=request.effective_account_type,
            credential_ref=request.credential_ref,
            authorization_ref=request.authorization_ref,
            scope_approval_ref=request.scope_approval_ref,
            comparison_scope_refs=request.comparison_scope_refs,
            build_scope_refs=request.build_scope_refs,
            policy_version=request.policy_version,
            workbook_id=request.workbook_id,
            data_model_id=request.data_model_id,
            source_freeze=request.source_freeze,
            manual_evidence_owner_ref=request.manual_evidence_owner_ref,
            privacy_approval_ref=request.privacy_approval_ref,
            sanitization_policy_ref=request.sanitization_policy_ref,
            retention_policy_ref=request.retention_policy_ref,
            data_classification=request.data_classification,
            row_data_authorized=request.row_data_authorized,
            evidence_mode=request.evidence_mode,
            request_budget=request.request_budget,
            per_endpoint_request_budget=request.per_endpoint_request_budget,
            approved_exclusions=request.approved_exclusions,
        ),
    )

    traces: list[dict[str, Any]] = []
    prior_sink = api.observation_sink

    def sink(value: dict[str, object]) -> None:
        traces.append(dict(value))
        if prior_sink is not None:
            prior_sink(value)

    api.observation_sink = sink
    try:
        acquisition = _bounded_acquisition(api, request)
    finally:
        api.observation_sink = prior_sink

    diagnostic_by_endpoint: dict[str, list[str]] = {}
    for item in acquisition.diagnostics:
        diagnostic_by_endpoint.setdefault(str(item["endpoint"]), []).append(
            f"{item['operation']}:{item['error_type']}:{item.get('status_code')}"
        )

    observations: list[SigmaObservationArtifact] = []
    for index, trace in enumerate(traces, start=1):
        endpoint = str(trace["endpoint"])
        version_context, version_selector = _trace_version_context(request, trace)
        payload = ObservationPayload.model_validate(
            {
                **trace,
                "organization_ref": request.organization_ref,
                "principal_ref": request.principal_ref,
                "effective_account_type": request.effective_account_type,
                "authorization_ref": request.authorization_ref,
                "version_context": version_context,
                "version_selector": version_selector,
                "diagnostics": diagnostic_by_endpoint.get(endpoint, []),
                "row_data_retained": False,
            }
        )
        observations.append(
            _make_artifact(
                SigmaObservationArtifact,
                artifact_id=f"sigma-observation.{request.run_id}.{index:04d}",
                schema_version="sigma-observation.v1",
                request=request,
                created_at=clock.next(),
                producer="agent-ref://sigma-inventory-admin",
                source_references=(
                    f"sigma-api://{httpx.URL(request.api_base_url).host}"
                    f"{quote(endpoint, safe='/-._~')}",
                ),
                upstream=(run_manifest,),
                classification=classification,
                payload=payload,
            )
        )
    observation_tuple = tuple(observations)

    matrix_payload = _capability_matrix(request, acquisition, traces, observation_tuple)
    capability_matrix = _make_artifact(
        SigmaCapabilityMatrixArtifact,
        artifact_id=f"sigma-capability-matrix.{request.run_id}",
        schema_version="sigma-api-capability-matrix.v1",
        request=request,
        created_at=clock.next(),
        producer="agent-ref://sigma-inventory-admin",
        source_references=source_refs,
        upstream=(run_manifest, *observation_tuple),
        classification=classification,
        payload=matrix_payload,
    )

    graph_payload = _workbook_graph(request, acquisition)
    workbook_graph = _make_artifact(
        SigmaWorkbookGraphArtifact,
        artifact_id=f"sigma-workbook-graph.{request.run_id}",
        schema_version="sigma-workbook-graph.v1",
        request=request,
        created_at=clock.next(),
        producer="agent-ref://sigma-bi-workbook",
        source_references=(source_refs[0],),
        upstream=(run_manifest, *observation_tuple),
        classification=classification,
        payload=graph_payload,
    )

    sanitized_spec = sanitize_source_value(acquisition.snapshot["dataModel"].get("spec", {}))
    assert isinstance(sanitized_spec, dict)
    model_source_bindings: dict[str, dict[str, str]] = {}
    for source in acquisition.snapshot["dataModel"].get("sources", []):
        try:
            parsed_source = parse_sigma_source(source, owner="data_model")
        except ValueError:
            continue  # The source capability retains the explicit contract blocker.
        for binding in sigma_source_bindings(parsed_source):
            model_source_bindings[sigma_source_binding_key(binding)] = binding
    data_model_payload = DataModelSnapshotPayload(
        data_model_id=request.data_model_id,
        source_freeze=request.source_freeze,
        specification_state="bound" if sanitized_spec else "unavailable",
        specification_unavailability_reason=(
            acquisition.snapshot["dataModel"].get("specificationUnavailabilityReason")
            or ("acquisition_unavailable" if not sanitized_spec else None)
        ),
        sanitized_specification=sanitized_spec,
        source_bindings=tuple(model_source_bindings[key] for key in sorted(model_source_bindings)),
        specification_sha256=sha256_json(sanitized_spec),
        documented_omissions=(
            "input tables",
            "Python elements",
            "UI elements",
            "custom functions",
            "metrics or links defined on a source",
        ),
    )
    data_model_snapshot = _make_artifact(
        SigmaDataModelSnapshotArtifact,
        artifact_id=f"sigma-data-model-snapshot.{request.run_id}",
        schema_version="sigma-data-model-snapshot.v1",
        request=request,
        created_at=clock.next(),
        producer="agent-ref://sigma-analytics-formula",
        source_references=(source_refs[1], _DOCS["data_model_code"]),
        upstream=(run_manifest, *observation_tuple),
        classification=classification,
        payload=data_model_payload,
    )

    behavior_payload = _behavior_manifest(request, acquisition, observation_tuple)
    behavior_manifest = _make_artifact(
        SigmaBehaviorManifestArtifact,
        artifact_id=f"sigma-behavior-manifest.{request.run_id}",
        schema_version="sigma-behavior-manifest.v1",
        request=request,
        created_at=clock.next(),
        producer="agent-ref://sigma-bi-workbook",
        source_references=(source_refs[0],),
        upstream=(run_manifest, capability_matrix, workbook_graph),
        classification="recommendation",
        payload=behavior_payload,
    )

    blockers = [
        f"capability:{capability_id}" for capability_id in matrix_payload.blocking_capability_ids
    ]
    for item in acquisition.diagnostics:
        if bool(item.get("required")) or item.get("error_type") not in {
            "http_status",
            "transport",
        }:
            blockers.append(f"acquisition:{item['operation']}:{item['error_type']}")
    if request.evidence_mode != "live_tenant":
        blockers.append("live tenant evidence has not been collected")
    if any(item["error_type"] == "request_budget_exhausted" for item in acquisition.diagnostics):
        blockers.append("Sigma API request budget was exhausted")
    status = (
        "ready_for_human_review"
        if not blockers and matrix_payload.matrix_status == "ready_for_human_review"
        else "blocked"
    )
    capability_gate_state = (
        "requires_human_approval" if status == "ready_for_human_review" else "blocked"
    )
    gate_recommendations = (
        GateRecommendation(
            gate_id="sigma_api_capability_verified",
            state=capability_gate_state,
            reason=(
                "The bounded live matrix has viable evidence paths but requires independent human approval."
                if capability_gate_state == "requires_human_approval"
                else "Capability evidence is synthetic, incomplete, or internally inconsistent."
            ),
            evidence_refs=(_artifact_ref(capability_matrix),),
        ),
        GateRecommendation(
            gate_id="source_inventory_complete",
            state="blocked",
            reason="Phase 0 proves one bounded pilot; it does not establish the portfolio denominator.",
            evidence_refs=(_artifact_ref(workbook_graph),),
        ),
        GateRecommendation(
            gate_id="artifact_registry_registered",
            state="blocked",
            reason="The Phase-0 CLI emits a create-only local bundle; shared append-only registration and supersession invalidation are not wired yet.",
            evidence_refs=(_artifact_ref(run_manifest),),
        ),
        GateRecommendation(
            gate_id="semantic_migration_strategy_selected",
            state="blocked",
            reason="Strategy selection requires a separate current semantic-routing decision whose source and human records resolve in the trusted control plane.",
            evidence_refs=(_artifact_ref(data_model_snapshot),),
        ),
        GateRecommendation(
            gate_id="semantic_target_design_approved",
            state="blocked",
            reason="Target design remains a later human approval even after migration strategy selection.",
            evidence_refs=(_artifact_ref(data_model_snapshot),),
        ),
        GateRecommendation(
            gate_id="target_write_authorized",
            state="blocked",
            reason="This source-only agent exposes no target write capability.",
            evidence_refs=(_artifact_ref(run_manifest),),
        ),
        GateRecommendation(
            gate_id="release_authorized",
            state="blocked",
            reason="Capability-spike evidence cannot authorize release or cutover.",
            evidence_refs=(_artifact_ref(run_manifest),),
        ),
        GateRecommendation(
            gate_id="decommission_authorized",
            state="blocked",
            reason="Decommissioning is a separate human gate and is never implied.",
            evidence_refs=(_artifact_ref(run_manifest),),
        ),
    )
    return SigmaCapabilitySpikeBundle(
        schema_version="sigma-capability-spike-bundle.v1",
        run_id=request.run_id,
        scope_id=request.scope_id,
        status=status,
        run_manifest=run_manifest,
        observations=observation_tuple,
        capability_matrix=capability_matrix,
        workbook_graph=workbook_graph,
        data_model_snapshot=data_model_snapshot,
        behavior_manifest=behavior_manifest,
        gate_recommendations=gate_recommendations,
        blockers=tuple(sorted(set(blockers))),
        metrics=SpikeMetrics(
            api_calls=api.request_count,
            retry_responses=sum(
                bool(trace.get("retryable")) or int(trace.get("attempt", 1)) > 1 for trace in traces
            ),
            response_bytes_hashed=sum(int(trace.get("response_bytes", 0)) for trace in traces),
            request_budget=request.request_budget,
            per_endpoint_request_budget=request.per_endpoint_request_budget,
            request_budget_exhausted=any(
                item["error_type"] == "request_budget_exhausted" for item in acquisition.diagnostics
            ),
        ),
    )

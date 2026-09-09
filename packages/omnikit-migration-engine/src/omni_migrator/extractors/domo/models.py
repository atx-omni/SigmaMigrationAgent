"""Deterministic evidence models for read-only Domo acquisition."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from typing import Any, Literal
from urllib.parse import urlparse

from pydantic import BaseModel, Field, field_validator, model_validator

DomoMode = Literal["api", "manual", "hybrid"]
DefinitionState = Literal[
    "definition_complete",
    "definition_partial",
    "metadata_only",
    "manual_capture_required",
    "blocked",
]
ContractEvidenceState = Literal[
    "extracted_complete", "extracted_partial", "metadata_only", "manual_capture_required", "blocked"
]
Channel = Literal[
    "domo_platform_api_oauth",
    "domo_product_api_developer_token",
    "domostats_connector",
    "governance_connector",
    "domo_cli",
    "workbench_export",
    "pro_code_zip_export",
    "customer_operated_export",
    "manual_capture",
]

CONTRACT_EVIDENCE_STATE: dict[DefinitionState, ContractEvidenceState] = {
    "definition_complete": "extracted_complete",
    "definition_partial": "extracted_partial",
    "metadata_only": "metadata_only",
    "manual_capture_required": "manual_capture_required",
    "blocked": "blocked",
}


def validate_non_secret_ref(value: str) -> str:
    if any(character.isspace() for character in value):
        raise ValueError("provenance references must not contain whitespace")
    parsed = urlparse(value)
    if not parsed.scheme or parsed.scheme.lower() in {
        "secret",
        "secret-ref",
        "vault",
        "vault-ref",
        "credential",
        "credential-ref",
    }:
        raise ValueError("provenance references must use a non-secret URI scheme")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("provenance references must not contain userinfo, query, or fragment")
    if parsed.scheme.lower() == "http":
        raise ValueError("web provenance references must use HTTPS")
    if parsed.scheme.lower() == "https" and not parsed.hostname:
        raise ValueError("HTTPS provenance references require a hostname")
    if not parsed.netloc and not parsed.path:
        raise ValueError("provenance references require a target")
    return value


def canonical_hash(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return hashlib.sha256(encoded).hexdigest()


class DomoObject(BaseModel):
    object_type: str
    object_id: str
    title: str | None = None
    attributes: dict[str, Any] = Field(default_factory=dict)
    tenant_ref: str
    environment: Literal["production", "sandbox", "development", "unknown"] = "unknown"
    visibility_principal_ref: str
    acquired_at: str
    extraction_method: Channel
    permission_context_ref: str | None = None
    definition_state: DefinitionState = "metadata_only"
    channels: list[Channel] = Field(default_factory=list)
    source_refs: list[str] = Field(default_factory=list)
    content_hash: str | None = None
    sensitivity: Literal["public", "internal", "confidential", "restricted"] = "confidential"
    redaction_state: Literal[
        "not_required", "redacted", "tokenized", "restricted_reference_only", "pending"
    ] = "pending"
    provenance: dict[str, Any] = Field(default_factory=dict)

    @field_validator("tenant_ref", "visibility_principal_ref", "permission_context_ref")
    @classmethod
    def non_secret_reference(cls, value: str | None) -> str | None:
        if value is None:
            return value
        return validate_non_secret_ref(value)

    @field_validator("source_refs")
    @classmethod
    def safe_source_references(cls, value: list[str]) -> list[str]:
        return [validate_non_secret_ref(item) for item in value]

    @field_validator("acquired_at")
    @classmethod
    def timezone_aware_timestamp(cls, value: str) -> str:
        try:
            parsed = datetime.fromisoformat(value)
        except ValueError as exc:
            raise ValueError("acquired_at must be an ISO-8601 timestamp") from exc
        if parsed.tzinfo is None:
            raise ValueError("acquired_at must include a timezone")
        return value

    @field_validator("content_hash")
    @classmethod
    def prefixed_content_hash(cls, value: str | None) -> str | None:
        if value is not None and not re.fullmatch(r"sha256:[a-f0-9]{64}", value):
            raise ValueError("content_hash must be a prefixed lowercase SHA-256")
        return value

    @property
    def key(self) -> str:
        return f"{self.object_type}:{self.object_id}"

    def normalized_fingerprint(self) -> str:
        return canonical_hash({
            "object_type": self.object_type,
            "object_id": self.object_id,
            "title": self.title,
            "attributes": self.attributes,
            "definition_state": self.definition_state,
            "content_hash": self.content_hash,
        })

    @property
    def evidence_state(self) -> ContractEvidenceState:
        """Map ADR definition completeness to the frozen cross-agent evidence vocabulary."""
        return CONTRACT_EVIDENCE_STATE[self.definition_state]


class DomoEdge(BaseModel):
    source_key: str
    target_key: str
    relation: str
    definition_state: DefinitionState = "definition_complete"
    source_refs: list[str] = Field(default_factory=list)

    @field_validator("source_refs")
    @classmethod
    def safe_source_references(cls, value: list[str]) -> list[str]:
        return [validate_non_secret_ref(item) for item in value]

    @property
    def key(self) -> str:
        return f"{self.source_key}|{self.relation}|{self.target_key}"


class CoverageRecord(BaseModel):
    capability: str
    status: Literal["complete", "partial", "blocked", "not_requested"]
    object_keys: list[str] = Field(default_factory=list)
    gaps: list[str] = Field(default_factory=list)
    truncated: bool = False
    source_refs: list[str] = Field(default_factory=list)
    provenance: dict[str, Any] = Field(default_factory=dict)

    @field_validator("source_refs")
    @classmethod
    def safe_source_references(cls, value: list[str]) -> list[str]:
        return [validate_non_secret_ref(item) for item in value]

    @model_validator(mode="after")
    def complete_coverage_cannot_be_truncated(self) -> "CoverageRecord":
        if self.status == "complete" and self.truncated:
            raise ValueError("truncated coverage cannot be complete")
        return self


class ManualCaptureRequest(BaseModel):
    request_id: str
    object_key: str
    evidence_kind: str
    reason: str
    blocking: bool = True
    accepted_formats: list[str] = Field(default_factory=list)


class PaginationCheckpoint(BaseModel):
    endpoint: str
    next_offset: int = 0
    page_count: int = 0
    request_count: int = 0
    seen_ids: list[str] = Field(default_factory=list)
    expected_total: int | None = None
    complete: bool = False
    truncated: bool = False
    warnings: list[str] = Field(default_factory=list)


class DomoEvidenceBundle(BaseModel):
    contract_version: Literal["omnikit.domo.evidence.v1"] = "omnikit.domo.evidence.v1"
    mode: DomoMode
    objects: list[DomoObject] = Field(default_factory=list)
    edges: list[DomoEdge] = Field(default_factory=list)
    coverage: list[CoverageRecord] = Field(default_factory=list)
    manual_capture_queue: list[ManualCaptureRequest] = Field(default_factory=list)
    checkpoints: list[PaginationCheckpoint] = Field(default_factory=list)
    diagnostics: list[str] = Field(default_factory=list)
    bundle_fingerprint: str | None = None

    def finalized(self) -> DomoEvidenceBundle:
        copy = self.model_copy(deep=True)
        copy.objects.sort(key=lambda item: item.key)
        copy.edges.sort(key=lambda item: item.key)
        copy.coverage.sort(key=lambda item: item.capability)
        copy.manual_capture_queue.sort(key=lambda item: item.request_id)
        copy.checkpoints.sort(key=lambda item: item.endpoint)
        copy.diagnostics = sorted(set(copy.diagnostics))
        payload = copy.model_dump(mode="json", exclude={"bundle_fingerprint"})
        copy.bundle_fingerprint = f"sha256:{canonical_hash(payload)}"
        return copy


class DomoInventoryDelta(BaseModel):
    from_fingerprint: str
    to_fingerprint: str
    added: list[str] = Field(default_factory=list)
    removed: list[str] = Field(default_factory=list)
    changed: list[str] = Field(default_factory=list)
    coverage_changed: list[str] = Field(default_factory=list)


def compare_bundles(before: DomoEvidenceBundle, after: DomoEvidenceBundle) -> DomoInventoryDelta:
    left = before.finalized()
    right = after.finalized()
    left_objects = {item.key: item.normalized_fingerprint() for item in left.objects}
    right_objects = {item.key: item.normalized_fingerprint() for item in right.objects}
    left_coverage = {item.capability: canonical_hash(item.model_dump(mode="json")) for item in left.coverage}
    right_coverage = {item.capability: canonical_hash(item.model_dump(mode="json")) for item in right.coverage}
    common = set(left_objects) & set(right_objects)
    coverage_keys = set(left_coverage) | set(right_coverage)
    return DomoInventoryDelta(
        from_fingerprint=left.bundle_fingerprint or "",
        to_fingerprint=right.bundle_fingerprint or "",
        added=sorted(set(right_objects) - set(left_objects)),
        removed=sorted(set(left_objects) - set(right_objects)),
        changed=sorted(key for key in common if left_objects[key] != right_objects[key]),
        coverage_changed=sorted(
            key for key in coverage_keys if left_coverage.get(key) != right_coverage.get(key)
        ),
    )

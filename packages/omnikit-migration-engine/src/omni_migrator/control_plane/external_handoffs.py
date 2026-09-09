"""Immutable human-owned assignments for external Domo redesign handoffs.

The contract closes a Phase 1 inventory boundary: every operational side
effect that is intentionally outside the analytic migration has an exact,
human-accepted owner assignment.  An assignment is metadata-only and never
authorizes execution, target writes, promotion, publication, or release.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Literal, Mapping

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from omni_migrator.control_plane.canonical import (
    parse_time,
    sha256_json,
    validate_reference,
)

_SHA256_PATTERN = r"^sha256:[a-f0-9]{64}$"
_STABLE_ID_PATTERN = r"^[a-z0-9][a-z0-9._-]{7,127}$"
_WORK_PACKAGE_ID_PATTERN = r"^wp-[a-f0-9]{20}$"
_HUMAN_REF_PATTERN = r"^(?:human-ref|person-ref):.+$"
_TENANT_REF_PATTERN = r"^tenant-ref:.+$"
_HANDOFF_REF_PATTERN = r"^handoff-ref:.+$"
_DECISION_REF_PATTERN = r"^decision-ref:.+$"

ExternalCapability = Literal[
    "platform_ingestion",
    "application_redesign",
    "operations_governance",
]
SourceObjectType = Literal[
    "page",
    "subpage",
    "card",
    "dataset",
    "dataset_schema",
    "dataflow",
    "magic_etl",
    "sql_dataflow",
    "beast_mode",
    "variable",
    "pdp_policy",
    "schedule",
    "alert",
    "workflow",
    "app_studio_app",
    "custom_app",
    "domo_everywhere_embed",
    "workbench_job",
    "connector_account",
    "file_asset",
    "code_engine_package",
    "publication",
    "user",
    "group",
    "role",
    "other",
]
ExternalSideEffectKind = Literal[
    "external_write",
    "message_delivery",
    "recipient_delivery",
    "code_execution",
    "credential_use",
    "form_submission",
    "embed_identity",
]


def _tupleize_json_arrays(value: Any) -> Any:
    if isinstance(value, list):
        return tuple(_tupleize_json_arrays(item) for item in value)
    if isinstance(value, tuple):
        return tuple(_tupleize_json_arrays(item) for item in value)
    if isinstance(value, Mapping):
        return {key: _tupleize_json_arrays(item) for key, item in value.items()}
    return value


def _raw(value: BaseModel | Mapping[str, Any]) -> dict[str, Any]:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    return deepcopy(dict(value))


class _StrictFrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class ExternalHandoffSourceObject(_StrictFrozenModel):
    """One exact typed Domo portfolio object at its current content hash."""

    object_id: str = Field(pattern=_STABLE_ID_PATTERN)
    object_type: SourceObjectType
    native_id: str = Field(min_length=1, max_length=512)
    object_hash: str = Field(pattern=_SHA256_PATTERN)


class ExternalHandoffAnalyticOutput(_StrictFrozenModel):
    """One exact analytic DataSet output kept separate from side effects."""

    object_id: str = Field(pattern=_STABLE_ID_PATTERN)
    object_type: Literal["dataset"] = "dataset"
    native_id: str = Field(min_length=1, max_length=512)
    object_hash: str = Field(pattern=_SHA256_PATTERN)


class AcceptedExternalHandoffDecision(_StrictFrozenModel):
    """The explicit human decision accepting this owner assignment."""

    status: Literal["accepted"] = "accepted"
    decision_ref: str = Field(pattern=_DECISION_REF_PATTERN)
    accepted_by_ref: str = Field(pattern=_HUMAN_REF_PATTERN)
    accepted_at: str

    @model_validator(mode="after")
    def decision_is_safe_and_clocked(self) -> "AcceptedExternalHandoffDecision":
        validate_reference(self.decision_ref)
        validate_reference(self.accepted_by_ref)
        parse_time(self.accepted_at)
        return self


class ExternalRedesignHandoff(_StrictFrozenModel):
    """Exact, accepted, and non-authorizing external handoff assignment."""

    contract_version: Literal["domo-to-omni.external-redesign-handoff.v1"] = (
        "domo-to-omni.external-redesign-handoff.v1"
    )
    tenant_ref: str = Field(pattern=_TENANT_REF_PATTERN)
    run_id: str = Field(pattern=_STABLE_ID_PATTERN)
    scope_id: str = Field(pattern=_STABLE_ID_PATTERN)
    wave_id: str = Field(pattern=_STABLE_ID_PATTERN)
    migration_unit_id: str = Field(pattern=_STABLE_ID_PATTERN)
    validation_cycle_id: str = Field(pattern=_STABLE_ID_PATTERN)
    handoff_id: str = Field(pattern=_STABLE_ID_PATTERN)
    handoff_ref: str = Field(pattern=_HANDOFF_REF_PATTERN)
    capability: ExternalCapability
    source_objects: tuple[ExternalHandoffSourceObject, ...] = Field(min_length=1)
    analytic_outputs: tuple[ExternalHandoffAnalyticOutput, ...]
    side_effect_kinds: tuple[ExternalSideEffectKind, ...] = Field(min_length=1)
    owner_ref: str = Field(pattern=_HUMAN_REF_PATTERN)
    assignment_work_package_id: str = Field(pattern=_WORK_PACKAGE_ID_PATTERN)
    work_package_id: str = Field(pattern=_WORK_PACKAGE_ID_PATTERN)
    accepted_decision: AcceptedExternalHandoffDecision
    evidence_refs: tuple[str, ...] = Field(min_length=1)
    assignment_only: Literal[True] = True
    authorizes_build: Literal[False] = False
    authorizes_target_write: Literal[False] = False
    authorizes_tenant_acceptance: Literal[False] = False
    authorizes_production_readiness: Literal[False] = False
    authorizes_promotion: Literal[False] = False
    authorizes_publication: Literal[False] = False
    authorizes_cutover: Literal[False] = False
    authorizes_decommissioning: Literal[False] = False
    immutable: Literal[True] = True
    handoff_hash: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def assignment_is_exact_and_canonical(self) -> "ExternalRedesignHandoff":
        for reference in (
            self.tenant_ref,
            self.handoff_ref,
            self.owner_ref,
            *self.evidence_refs,
        ):
            validate_reference(reference)

        source_keys = tuple(
            (item.object_type, item.object_id, item.native_id, item.object_hash)
            for item in self.source_objects
        )
        if source_keys != tuple(sorted(source_keys)):
            raise ValueError("external handoff source objects must be canonically ordered")
        source_identities = tuple(key[:3] for key in source_keys)
        if len(source_identities) != len(set(source_identities)):
            raise ValueError("external handoff source object identities must be unique")
        source_object_ids = {item.object_id for item in self.source_objects}
        if len(source_object_ids) != len(self.source_objects):
            raise ValueError("external handoff source object IDs must be unique")

        output_keys = tuple(
            (item.object_type, item.object_id, item.native_id, item.object_hash)
            for item in self.analytic_outputs
        )
        if output_keys != tuple(sorted(output_keys)):
            raise ValueError("external handoff analytic outputs must be canonically ordered")
        output_identities = tuple(key[:3] for key in output_keys)
        if len(output_identities) != len(set(output_identities)):
            raise ValueError("external handoff analytic output identities must be unique")
        output_object_ids = {item.object_id for item in self.analytic_outputs}
        if len(output_object_ids) != len(self.analytic_outputs):
            raise ValueError("external handoff analytic output IDs must be unique")
        if source_object_ids.intersection(output_object_ids):
            raise ValueError(
                "analytic outputs must remain separate from source side-effect objects"
            )

        if self.side_effect_kinds != tuple(sorted(set(self.side_effect_kinds))):
            raise ValueError("external handoff side-effect kinds must be sorted and unique")
        if self.evidence_refs != tuple(sorted(set(self.evidence_refs))):
            raise ValueError("external handoff evidence references must be sorted and unique")
        if self.assignment_work_package_id == self.work_package_id:
            raise ValueError(
                "external handoff assignment and delivery work packages must be distinct"
            )
        if self.work_package_id != external_redesign_handoff_work_package_id(self):
            raise ValueError("external handoff work package ID is not deterministic")
        if self.handoff_hash != external_redesign_handoff_hash(self):
            raise ValueError("external handoff hash is not canonical")
        return self


def external_redesign_handoff_work_package_id(
    value: ExternalRedesignHandoff | Mapping[str, Any],
) -> str:
    """Return a partitioned deterministic work-package ID for one handoff."""

    raw = _raw(value)
    material = {
        "contract_version": raw.get("contract_version"),
        "tenant_ref": raw.get("tenant_ref"),
        "run_id": raw.get("run_id"),
        "scope_id": raw.get("scope_id"),
        "wave_id": raw.get("wave_id"),
        "migration_unit_id": raw.get("migration_unit_id"),
        "validation_cycle_id": raw.get("validation_cycle_id"),
        "handoff_id": raw.get("handoff_id"),
        "handoff_ref": raw.get("handoff_ref"),
        "capability": raw.get("capability"),
    }
    return f"wp-{sha256_json(material)[:20]}"


def external_redesign_handoff_hash(
    value: ExternalRedesignHandoff | Mapping[str, Any],
) -> str:
    """Return the canonical semantic hash, excluding only its self hash."""

    raw = _raw(value)
    raw.pop("handoff_hash", None)
    return f"sha256:{sha256_json(raw)}"


def external_redesign_handoff_content_sha256(
    value: ExternalRedesignHandoff | Mapping[str, Any],
) -> str:
    """Return the raw artifact-envelope content digest for a finalized handoff."""

    return sha256_json(_raw(value))


def finalize_external_redesign_handoff(
    value: ExternalRedesignHandoff | Mapping[str, Any],
) -> ExternalRedesignHandoff:
    """Canonicalize ordering and finalize deterministic handoff identities."""

    raw = _raw(value)
    raw["source_objects"] = sorted(
        raw.get("source_objects", ()),
        key=lambda item: (
            item["object_type"],
            item["object_id"],
            item["native_id"],
            item["object_hash"],
        ),
    )
    raw["analytic_outputs"] = sorted(
        raw.get("analytic_outputs", ()),
        key=lambda item: (
            item["object_type"],
            item["object_id"],
            item["native_id"],
            item["object_hash"],
        ),
    )
    raw["side_effect_kinds"] = sorted(set(raw.get("side_effect_kinds", ())))
    raw["evidence_refs"] = sorted(set(raw.get("evidence_refs", ())))
    raw["work_package_id"] = external_redesign_handoff_work_package_id(raw)
    raw.pop("handoff_hash", None)
    raw["handoff_hash"] = external_redesign_handoff_hash(raw)
    return ExternalRedesignHandoff.model_validate(_tupleize_json_arrays(raw))


def validate_external_redesign_handoff(
    value: ExternalRedesignHandoff | Mapping[str, Any],
) -> tuple[str, ...]:
    """Return deterministic validation errors without repairing caller input."""

    try:
        ExternalRedesignHandoff.model_validate(_tupleize_json_arrays(_raw(value)))
    except (TypeError, ValueError, ValidationError) as exc:
        if isinstance(exc, ValidationError):
            errors = []
            for item in exc.errors(include_url=False):
                location = ".".join(str(part) for part in item["loc"])
                message = item["msg"]
                errors.append(f"{location}: {message}" if location else message)
            return tuple(sorted(set(errors)))
        return (str(exc),)
    return ()

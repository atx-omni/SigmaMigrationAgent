"""Canonical QA evidence for one successfully promoted target operation.

This module binds an already-completed target operation to exact immutable QA
artifact bindings.  It does not grant promotion, readiness, cutover, or any
other authority.  Persistence and trusted-environment resolution remain control
plane responsibilities.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Literal, Mapping, Protocol

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from omni_migrator.control_plane.canonical import parse_time, sha256_json
from omni_migrator.control_plane.records import ArtifactEnvelope
from omni_migrator.qa.acceptance import (
    EvidenceClass,
    QAArtifactBinding,
    QATargetReadbackBinding,
    QATargetReceiptBinding,
    finalize_qa_artifact_binding,
    qa_artifact_binding_hash,
    qa_target_readback_binding_hash,
    qa_target_receipt_binding_hash,
)
from omni_migrator.targets.contracts import validate_non_secret_ref

_RAW_SHA256_PATTERN = r"^[a-f0-9]{64}$"
_SHA256_PATTERN = r"^sha256:[a-f0-9]{64}$"
_STABLE_ID_PATTERN = r"^[a-z0-9][a-z0-9._-]{7,127}$"
_NON_SECRET_REF_PATTERN = r"^[A-Za-z][A-Za-z0-9+.-]*:.+$"
_ZERO_HASH = "sha256:" + "0" * 64


class _StrictFrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class QATargetOperationOutcome(_StrictFrozenModel):
    """One exact succeeded-and-matched target operation for QA consumption."""

    contract_version: Literal["domo-to-omni.qa-target-operation-outcome.v1"] = (
        "domo-to-omni.qa-target-operation-outcome.v1"
    )
    tenant_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    run_id: str = Field(pattern=_STABLE_ID_PATTERN)
    scope_id: str = Field(pattern=_STABLE_ID_PATTERN)
    wave_id: str = Field(pattern=_STABLE_ID_PATTERN)
    migration_unit_id: str = Field(pattern=_STABLE_ID_PATTERN)
    validation_cycle_id: str = Field(pattern=_STABLE_ID_PATTERN)
    evidence_class: EvidenceClass
    outcome_id: str = Field(pattern=_STABLE_ID_PATTERN)
    outcome_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    target_environment_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    target_environment_tier: Literal["development", "staging", "production"]
    operation_id: str = Field(pattern=_STABLE_ID_PATTERN)
    request_fingerprint: str = Field(pattern=_RAW_SHA256_PATTERN)
    promoted_target_artifact: QAArtifactBinding
    receipt_binding: QATargetReceiptBinding
    readback_binding: QATargetReadbackBinding
    observed_content_fingerprint: str = Field(pattern=_RAW_SHA256_PATTERN)
    observed_target_revision: str = Field(min_length=1, max_length=512)
    success_state: Literal["succeeded_and_matched"] = "succeeded_and_matched"
    recorded_at: str
    outcome_hash: str = Field(pattern=_SHA256_PATTERN)
    authorizes_tenant_acceptance: Literal[False] = False
    authorizes_production_readiness: Literal[False] = False
    authorizes_promotion: Literal[False] = False
    authorizes_cutover: Literal[False] = False
    authorizes_decommissioning: Literal[False] = False
    immutable: Literal[True] = True

    @field_validator("tenant_ref", "outcome_ref", "target_environment_ref")
    @classmethod
    def references_are_non_secret(cls, value: str) -> str:
        return validate_non_secret_ref(value)

    @field_validator("recorded_at")
    @classmethod
    def recorded_time_is_aware(cls, value: str) -> str:
        parse_time(value)
        return value

    @model_validator(mode="after")
    def operation_is_exact_succeeded_and_matched(self) -> "QATargetOperationOutcome":
        expected_tier = {
            "synthetic_local": "development",
            "development": "development",
            "staging": "staging",
            "production": "production",
        }[self.evidence_class]
        if self.target_environment_tier != expected_tier:
            raise ValueError(
                "QA target operation evidence class does not match its trusted "
                "environment tier"
            )

        identity = (
            self.tenant_ref,
            self.run_id,
            self.scope_id,
            self.wave_id,
            self.migration_unit_id,
            self.validation_cycle_id,
            self.evidence_class,
        )
        bindings = (
            self.promoted_target_artifact,
            self.receipt_binding.artifact,
            self.readback_binding.artifact,
        )
        for binding in bindings:
            binding_identity = (
                binding.tenant_ref,
                binding.run_id,
                binding.scope_id,
                binding.wave_id,
                binding.migration_unit_id,
                binding.validation_cycle_id,
                binding.evidence_class,
            )
            if binding_identity != identity:
                raise ValueError(
                    "QA target operation artifact binding crosses its exact partition"
                )

        if (
            self.promoted_target_artifact.binding_hash
            != qa_artifact_binding_hash(self.promoted_target_artifact)
            or self.receipt_binding.binding_hash
            != qa_target_receipt_binding_hash(self.receipt_binding)
            or self.readback_binding.binding_hash
            != qa_target_readback_binding_hash(self.readback_binding)
        ):
            raise ValueError("QA target operation contains a stale artifact binding hash")

        if self.receipt_binding.artifact.artifact_type != "target_write_receipt":
            raise ValueError(
                "QA target operation receipt requires a target_write_receipt artifact"
            )
        accepted_readback_types = {
            "document_readback",
            "dbt_test_evidence",
            "model_validation",
            "semantic_query_evidence",
            "target_visual_fixtures",
            "target_readback",
        }
        if self.readback_binding.artifact.artifact_type not in accepted_readback_types:
            raise ValueError("QA target operation has an unsupported readback artifact")
        if self.receipt_binding.result != "succeeded":
            raise ValueError("QA target operation requires an immutable successful receipt")
        if self.readback_binding.state != "matched":
            raise ValueError("QA target operation requires an immutable matched readback")
        if (
            self.operation_id != self.receipt_binding.operation_id
            or self.operation_id != self.readback_binding.operation_id
        ):
            raise ValueError("QA target operation IDs differ")
        if (
            self.request_fingerprint != self.receipt_binding.request_fingerprint
            or self.request_fingerprint != self.readback_binding.request_fingerprint
        ):
            raise ValueError("QA target operation request fingerprints differ")
        if (
            self.receipt_binding.target_ref != self.readback_binding.target_ref
            or self.receipt_binding.write_receipt_ref
            != self.readback_binding.write_receipt_ref
            or self.receipt_binding.readback_ref
            != self.readback_binding.readback_ref
        ):
            raise ValueError("QA target receipt and matched readback identities differ")
        if (
            self.observed_content_fingerprint
            != self.readback_binding.observed_content_fingerprint
        ):
            raise ValueError(
                "QA target observed content differs from its exact matched readback"
            )
        return self


class TrustedQATargetOperationOutcomeResolver(Protocol):
    """Resolve one current registered outcome from trusted store state."""

    def resolve_current_qa_target_operation_outcome(
        self,
        *,
        tenant_ref: str,
        run_id: str,
        scope_id: str,
        wave_id: str,
        migration_unit_id: str,
        validation_cycle_id: str,
        operation_id: str,
    ) -> QATargetOperationOutcome | None: ...


class QATargetOperationOutcomeSink(Protocol):
    """Append one canonical outcome to a trusted control-plane store."""

    def append_qa_target_operation_outcome(
        self,
        outcome: QATargetOperationOutcome,
        artifact: ArtifactEnvelope | Mapping[str, Any],
        *,
        idempotency_key: str,
    ) -> QATargetOperationOutcome: ...


def _raw(
    value: Mapping[str, Any] | BaseModel,
) -> dict[str, Any]:
    return (
        value.model_dump(mode="json")
        if isinstance(value, BaseModel)
        else deepcopy(dict(value))
    )


def _finalize_receipt_binding(
    value: Mapping[str, Any] | QATargetReceiptBinding,
) -> QATargetReceiptBinding:
    raw = _raw(value)
    raw["artifact"] = finalize_qa_artifact_binding(raw["artifact"]).model_dump(
        mode="json"
    )
    raw["binding_hash"] = _ZERO_HASH
    draft = QATargetReceiptBinding.model_validate(raw)
    raw = draft.model_dump(mode="json")
    raw["binding_hash"] = qa_target_receipt_binding_hash(raw)
    return QATargetReceiptBinding.model_validate(raw)


def _finalize_readback_binding(
    value: Mapping[str, Any] | QATargetReadbackBinding,
) -> QATargetReadbackBinding:
    raw = _raw(value)
    raw["artifact"] = finalize_qa_artifact_binding(raw["artifact"]).model_dump(
        mode="json"
    )
    raw["binding_hash"] = _ZERO_HASH
    draft = QATargetReadbackBinding.model_validate(raw)
    raw = draft.model_dump(mode="json")
    raw["binding_hash"] = qa_target_readback_binding_hash(raw)
    return QATargetReadbackBinding.model_validate(raw)


def qa_target_operation_outcome_hash(
    value: Mapping[str, Any] | QATargetOperationOutcome,
) -> str:
    """Return the canonical semantic hash, excluding only its self hash."""

    raw = _raw(value)
    raw.pop("outcome_hash", None)
    return f"sha256:{sha256_json(raw)}"


def qa_target_operation_outcome_content_sha256(
    value: Mapping[str, Any] | QATargetOperationOutcome,
) -> str:
    """Return the raw content hash expected by an ArtifactEnvelope."""

    return sha256_json(_raw(value))


def finalize_qa_target_operation_outcome(
    value: Mapping[str, Any] | QATargetOperationOutcome,
) -> QATargetOperationOutcome:
    """Canonicalize nested bindings and finalize one immutable outcome hash."""

    raw = _raw(value)
    raw["promoted_target_artifact"] = finalize_qa_artifact_binding(
        raw["promoted_target_artifact"]
    ).model_dump(mode="json")
    raw["receipt_binding"] = _finalize_receipt_binding(
        raw["receipt_binding"]
    ).model_dump(mode="json")
    raw["readback_binding"] = _finalize_readback_binding(
        raw["readback_binding"]
    ).model_dump(mode="json")
    raw["outcome_hash"] = _ZERO_HASH
    draft = QATargetOperationOutcome.model_validate(raw)
    raw = draft.model_dump(mode="json")
    raw["outcome_hash"] = qa_target_operation_outcome_hash(raw)
    return QATargetOperationOutcome.model_validate(raw)

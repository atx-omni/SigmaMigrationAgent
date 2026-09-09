"""Canonical production revalidation report contracts.

The report is metadata-only.  It binds an independently validated production QA
suite to the exact accepted evidence set without carrying source or query-result
payloads and without granting release authority.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Literal, Mapping
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from omni_migrator.control_plane.canonical import parse_time, sha256_json
from omni_migrator.qa.acceptance import (
    QAArtifactBinding,
    QAEvidenceBindings,
    QASuiteValidationRegistration,
    finalize_qa_artifact_binding,
    finalize_qa_evidence_bindings,
    qa_artifact_binding_hash,
    qa_evidence_bindings_hash,
    qa_suite_validation_content_sha256,
    qa_suite_validation_registration_hash,
    qa_target_readback_binding_hash,
    qa_target_receipt_binding_hash,
)


_SHA256_PATTERN = r"^sha256:[a-f0-9]{64}$"
_STABLE_ID_PATTERN = r"^[a-z0-9][a-z0-9._-]{7,127}$"
_NON_SECRET_REF_PATTERN = r"^[A-Za-z][A-Za-z0-9+.-]*:.+$"
_ACTOR_REF_PATTERN = r"^(agent-ref|human-ref|person-ref|person):.+$"
_ZERO_HASH = "sha256:" + "0" * 64


def _safe_reference(reference: str) -> None:
    prohibited = {
        "secret",
        "secret-ref",
        "vault",
        "vault-ref",
        "credential",
        "credential-ref",
    }
    parsed = urlsplit(reference)
    if (
        any(character.isspace() for character in reference)
        or not parsed.scheme
        or parsed.scheme.lower() in prohibited
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.scheme.lower() == "http"
        or (parsed.scheme.lower() == "https" and not parsed.hostname)
        or (not parsed.netloc and not parsed.path)
    ):
        raise ValueError("production validation references must be safe non-secret URIs")


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


def _partition_identity(value: Any) -> tuple[str, ...]:
    return (
        value.tenant_ref,
        value.run_id,
        value.scope_id,
        value.wave_id,
        value.migration_unit_id,
        value.validation_cycle_id,
        value.evidence_class,
    )


class _StrictFrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    @model_validator(mode="after")
    def references_are_safe(self) -> "_StrictFrozenModel":
        for field_name in type(self).model_fields:
            if not (field_name.endswith("_ref") or field_name.endswith("_refs")):
                continue
            value = getattr(self, field_name)
            references = value if isinstance(value, tuple) else (value,)
            for reference in references:
                if isinstance(reference, str):
                    _safe_reference(reference)
        return self


class ProductionQASuiteBinding(_StrictFrozenModel):
    """Exact immutable suite identity plus its registered artifact."""

    suite_id: str = Field(pattern=_STABLE_ID_PATTERN)
    suite_hash: str = Field(pattern=_SHA256_PATTERN)
    bindings_hash: str = Field(pattern=_SHA256_PATTERN)
    evidence_snapshot_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    evidence_snapshot_hash: str = Field(pattern=_SHA256_PATTERN)
    evidence_snapshot_revision: int = Field(ge=1)
    verifier_ref: str = Field(pattern=_ACTOR_REF_PATTERN)
    producer_refs: tuple[str, ...] = Field(min_length=1)
    assembled_at: str
    artifact: QAArtifactBinding

    @model_validator(mode="after")
    def suite_identity_is_exact(self) -> "ProductionQASuiteBinding":
        parse_time(self.assembled_at)
        if self.producer_refs != tuple(sorted(set(self.producer_refs))):
            raise ValueError("production suite producer references must be sorted and unique")
        if self.verifier_ref in self.producer_refs:
            raise ValueError("production suite verifier must be independent of its producers")
        if (
            self.artifact.artifact_type != "qa_acceptance_suite"
            or self.artifact.semantic_hash != self.suite_hash
            or self.artifact.producer_ref != self.verifier_ref
        ):
            raise ValueError("production suite artifact does not bind the exact suite")
        if self.artifact.binding_hash != qa_artifact_binding_hash(self.artifact):
            raise ValueError("production suite artifact binding hash is not canonical")
        return self


class ProductionEvidenceSnapshotBinding(_StrictFrozenModel):
    """Exact metadata identity of the accepted production evidence snapshot."""

    snapshot_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    snapshot_hash: str = Field(pattern=_SHA256_PATTERN)
    revision: int = Field(ge=1)


class ProductionValidationReport(_StrictFrozenModel):
    """Passed production revalidation bound to one exact accepted QA evidence set."""

    contract_version: Literal["domo-to-omni.production-validation-report.v1"] = (
        "domo-to-omni.production-validation-report.v1"
    )
    report_id: str = Field(pattern=_STABLE_ID_PATTERN)
    report_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    tenant_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    run_id: str = Field(pattern=_STABLE_ID_PATTERN)
    scope_id: str = Field(pattern=_STABLE_ID_PATTERN)
    wave_id: str = Field(pattern=_STABLE_ID_PATTERN)
    migration_unit_id: str = Field(pattern=_STABLE_ID_PATTERN)
    validation_cycle_id: str = Field(pattern=_STABLE_ID_PATTERN)
    evidence_class: Literal["production"] = "production"
    suite: ProductionQASuiteBinding
    suite_validation: QASuiteValidationRegistration
    suite_validation_artifact: QAArtifactBinding
    evidence_snapshot: ProductionEvidenceSnapshotBinding
    accepted_evidence_bindings: QAEvidenceBindings
    qa_result_refs: tuple[str, ...] = Field(min_length=1)
    production_evidence_set_hash: str = Field(pattern=_SHA256_PATTERN)
    outcome: Literal["passed"]
    verifier_ref: str = Field(pattern=_ACTOR_REF_PATTERN)
    producer_refs: tuple[str, ...] = Field(min_length=1)
    validation_completed_at: str
    created_at: str
    authorizes_tenant_acceptance: Literal[False] = False
    authorizes_production_readiness: Literal[False] = False
    authorizes_promotion: Literal[False] = False
    authorizes_publication: Literal[False] = False
    authorizes_cutover: Literal[False] = False
    authorizes_decommissioning: Literal[False] = False
    immutable: Literal[True] = True
    report_hash: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def report_is_exact_current_and_non_authorizing(self) -> "ProductionValidationReport":
        identity = (
            self.tenant_ref,
            self.run_id,
            self.scope_id,
            self.wave_id,
            self.migration_unit_id,
            self.validation_cycle_id,
            self.evidence_class,
        )
        if _partition_identity(self.suite.artifact) != identity:
            raise ValueError("production suite artifact crosses the report partition")
        if _partition_identity(self.suite_validation) != identity:
            raise ValueError("production suite validation crosses the report partition")
        if _partition_identity(self.suite_validation_artifact) != identity:
            raise ValueError("production suite validation artifact crosses the report partition")

        all_evidence = self.accepted_evidence_bindings.all_artifacts()
        if any(_partition_identity(item) != identity for item in all_evidence):
            raise ValueError("accepted production evidence crosses the report partition")
        artifact_fields = (
            "topic_blueprints",
            "semantic_profiles",
            "consolidation_decisions",
            "source_evidence",
            "target_artifacts",
            "persona_policies",
            "tolerance_policies",
            "fixture_artifacts",
            "result_artifacts",
        )
        for field_name in artifact_fields:
            values = getattr(self.accepted_evidence_bindings, field_name)
            if values != tuple(
                sorted(
                    values,
                    key=lambda item: (
                        item.artifact_id,
                        item.revision,
                        item.content_sha256,
                    ),
                )
            ):
                raise ValueError("accepted production evidence ordering is not canonical")
        if self.accepted_evidence_bindings.target_receipts != tuple(
            sorted(
                self.accepted_evidence_bindings.target_receipts,
                key=lambda item: item.operation_id,
            )
        ) or self.accepted_evidence_bindings.target_readbacks != tuple(
            sorted(
                self.accepted_evidence_bindings.target_readbacks,
                key=lambda item: item.operation_id,
            )
        ):
            raise ValueError("production target operation ordering is not canonical")
        accepted_refs = {item.artifact_ref for item in all_evidence}
        reserved_refs = {
            self.report_ref,
            self.suite.artifact.artifact_ref,
            self.suite_validation_artifact.artifact_ref,
        }
        if accepted_refs & reserved_refs or any(
            item.artifact_type == "production_validation_report" for item in all_evidence
        ):
            raise ValueError(
                "production report, suite, and validation artifacts cannot be their own accepted evidence"
            )
        if self.accepted_evidence_bindings.bindings_hash != qa_evidence_bindings_hash(
            self.accepted_evidence_bindings
        ):
            raise ValueError("accepted production evidence bindings hash is not canonical")
        if any(item.binding_hash != qa_artifact_binding_hash(item) for item in all_evidence):
            raise ValueError("accepted production artifact binding hash is not canonical")
        if any(
            item.binding_hash != qa_target_receipt_binding_hash(item)
            for item in self.accepted_evidence_bindings.target_receipts
        ):
            raise ValueError("production target receipt binding hash is not canonical")
        if any(
            item.binding_hash != qa_target_readback_binding_hash(item)
            for item in self.accepted_evidence_bindings.target_readbacks
        ):
            raise ValueError("production target readback binding hash is not canonical")

        if self.suite.bindings_hash != self.accepted_evidence_bindings.bindings_hash:
            raise ValueError("production report evidence differs from the exact suite bindings")
        if (
            self.suite.suite_id != self.suite_validation.suite_id
            or self.suite.suite_hash != self.suite_validation.suite_hash
            or self.suite.artifact.artifact_ref != self.suite_validation.suite_artifact_ref
            or self.suite.artifact.content_sha256
            != self.suite_validation.suite_artifact_content_sha256
        ):
            raise ValueError("production suite validation does not bind the exact suite artifact")
        if (
            self.evidence_snapshot.snapshot_ref != self.suite.evidence_snapshot_ref
            or self.evidence_snapshot.snapshot_hash != self.suite.evidence_snapshot_hash
            or self.evidence_snapshot.revision != self.suite.evidence_snapshot_revision
            or self.evidence_snapshot.snapshot_ref != self.suite_validation.evidence_snapshot_ref
            or self.evidence_snapshot.snapshot_hash != self.suite_validation.evidence_snapshot_hash
            or self.evidence_snapshot.revision != self.suite_validation.evidence_snapshot_revision
        ):
            raise ValueError("production report does not bind the exact evidence snapshot")

        if self.suite_validation.registration_hash != qa_suite_validation_registration_hash(
            self.suite_validation
        ):
            raise ValueError("production suite validation registration hash is not canonical")
        if (
            self.suite_validation_artifact.artifact_type != "qa_suite_validation"
            or self.suite_validation_artifact.semantic_hash
            != self.suite_validation.registration_hash
            or self.suite_validation_artifact.content_sha256
            != qa_suite_validation_content_sha256(self.suite_validation)
            or self.suite_validation_artifact.producer_ref != self.verifier_ref
            or self.suite_validation_artifact.binding_hash
            != qa_artifact_binding_hash(self.suite_validation_artifact)
        ):
            raise ValueError(
                "production suite validation artifact does not bind the exact registration"
            )

        expected_result_refs = tuple(
            sorted(item.artifact_ref for item in self.accepted_evidence_bindings.result_artifacts)
        )
        if self.qa_result_refs != expected_result_refs:
            raise ValueError("production QA result references differ from the suite bindings")
        if any(
            item.producer_ref != self.verifier_ref
            for item in self.accepted_evidence_bindings.result_artifacts
        ):
            raise ValueError("production QA result artifacts require the independent verifier")

        expected_producers = tuple(
            sorted(
                {item.producer_ref for item in self.accepted_evidence_bindings.upstream_artifacts()}
            )
        )
        if (
            self.producer_refs != expected_producers
            or self.suite.producer_refs != expected_producers
            or self.verifier_ref in expected_producers
            or self.verifier_ref != self.suite.verifier_ref
            or self.verifier_ref != self.suite_validation.verifier_ref
            or self.verifier_ref != self.suite_validation.checked_by_ref
        ):
            raise ValueError("production verifier and producer identities are not exact")

        validation_time = parse_time(self.validation_completed_at)
        created_time = parse_time(self.created_at)
        assembled_time = parse_time(self.suite.assembled_at)
        checked_time = parse_time(self.suite_validation.checked_at)
        suite_artifact_time = parse_time(self.suite.artifact.created_at)
        validation_artifact_time = parse_time(self.suite_validation_artifact.created_at)
        latest_evidence_time = max(parse_time(item.created_at) for item in all_evidence)
        if self.validation_completed_at != self.suite_validation.checked_at:
            raise ValueError("production report validation time differs from its registration")
        if assembled_time < latest_evidence_time:
            raise ValueError("production suite predates accepted evidence")
        if suite_artifact_time < assembled_time or checked_time < suite_artifact_time:
            raise ValueError("production suite validation predates its suite artifact")
        if validation_artifact_time < checked_time or created_time < validation_artifact_time:
            raise ValueError("production report predates its validation artifact")
        if validation_time != checked_time or created_time < validation_time:
            raise ValueError("production report timestamps are not causally ordered")

        if self.production_evidence_set_hash != production_evidence_set_hash(self):
            raise ValueError("production evidence set hash is not canonical")
        if self.report_hash != production_validation_report_hash(self):
            raise ValueError("production validation report hash is not canonical")
        return self


def production_evidence_set_hash(
    value: ProductionValidationReport | Mapping[str, Any],
) -> str:
    """Hash only the exact accepted production evidence identity set."""

    raw = _raw(value)
    material = {
        "contract_version": raw.get("contract_version"),
        "tenant_ref": raw.get("tenant_ref"),
        "run_id": raw.get("run_id"),
        "scope_id": raw.get("scope_id"),
        "wave_id": raw.get("wave_id"),
        "migration_unit_id": raw.get("migration_unit_id"),
        "validation_cycle_id": raw.get("validation_cycle_id"),
        "evidence_class": raw.get("evidence_class"),
        "suite": raw.get("suite"),
        "suite_validation": raw.get("suite_validation"),
        "suite_validation_artifact": raw.get("suite_validation_artifact"),
        "evidence_snapshot": raw.get("evidence_snapshot"),
        "accepted_evidence_bindings": raw.get("accepted_evidence_bindings"),
        "qa_result_refs": raw.get("qa_result_refs"),
    }
    return f"sha256:{sha256_json(material)}"


def production_validation_report_hash(
    value: ProductionValidationReport | Mapping[str, Any],
) -> str:
    raw = _raw(value)
    raw.pop("report_hash", None)
    return f"sha256:{sha256_json(raw)}"


def production_validation_report_content_sha256(
    value: ProductionValidationReport | Mapping[str, Any],
) -> str:
    """Return the artifact-envelope content hash for the canonical report."""

    return sha256_json(_raw(value))


def finalize_production_validation_report(
    value: ProductionValidationReport | Mapping[str, Any],
) -> ProductionValidationReport:
    """Normalize ordering and finalize both production report hashes."""

    raw = _raw(value)
    suite = dict(raw["suite"])
    suite["producer_refs"] = sorted(set(suite.get("producer_refs", ())))
    suite["artifact"] = finalize_qa_artifact_binding(suite["artifact"]).model_dump(mode="json")
    raw["suite"] = ProductionQASuiteBinding.model_validate(_tupleize_json_arrays(suite)).model_dump(
        mode="json"
    )

    registration = QASuiteValidationRegistration.model_validate(
        _tupleize_json_arrays(raw["suite_validation"])
    )
    raw["suite_validation"] = registration.model_dump(mode="json")
    raw["suite_validation_artifact"] = finalize_qa_artifact_binding(
        raw["suite_validation_artifact"]
    ).model_dump(mode="json")
    raw["accepted_evidence_bindings"] = finalize_qa_evidence_bindings(
        raw["accepted_evidence_bindings"]
    ).model_dump(mode="json")
    raw["qa_result_refs"] = sorted(set(raw.get("qa_result_refs", ())))
    raw["producer_refs"] = sorted(set(raw.get("producer_refs", ())))
    raw["production_evidence_set_hash"] = _ZERO_HASH
    raw["report_hash"] = _ZERO_HASH
    raw["production_evidence_set_hash"] = production_evidence_set_hash(raw)
    raw["report_hash"] = production_validation_report_hash(raw)
    return ProductionValidationReport.model_validate(_tupleize_json_arrays(raw))


def validate_production_validation_report(
    value: ProductionValidationReport | Mapping[str, Any],
) -> tuple[str, ...]:
    """Return deterministic validation errors for one report."""

    try:
        ProductionValidationReport.model_validate(_tupleize_json_arrays(_raw(value)))
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

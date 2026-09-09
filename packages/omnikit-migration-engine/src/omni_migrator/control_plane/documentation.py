"""Accepted-artifact-only documentation package contracts and validation."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from copy import deepcopy
from typing import Any, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, model_validator

from omni_migrator.control_plane.canonical import sha256_json
from omni_migrator.control_plane.records import ArtifactEnvelope

_ENVELOPE_SHA256_PATTERN = r"^[a-f0-9]{64}$"
_SHA256_PATTERN = r"^sha256:[a-f0-9]{64}$"
_STABLE_ID_PATTERN = r"^[a-z0-9][a-z0-9._-]{7,127}$"
_NON_SECRET_REF_PATTERN = r"^[A-Za-z][A-Za-z0-9+.-]*:.+$"
_ZERO_HASH = "sha256:" + "0" * 64

DocumentationOutputType = Literal[
    "change_map",
    "source_target_lineage",
    "user_guide",
    "admin_runbook",
    "training_package",
]
EvidenceClass = Literal["synthetic_local", "development", "staging", "production"]

_REQUIRED_OUTPUT_TYPES: frozenset[str] = frozenset(
    {
        "change_map",
        "source_target_lineage",
        "user_guide",
        "admin_runbook",
        "training_package",
    }
)
_FINAL_TARGET_TYPES: frozenset[str] = frozenset(
    {
        "dbt_changes",
        "dbt_test_evidence",
        "data_reconciliation",
        "target_write_receipt",
        "omni_model_changes",
        "model_validation",
        "semantic_query_evidence",
        "omni_content_artifact",
        "document_readback",
        "target_visual_fixtures",
        "target_readback",
    }
)


class _StrictFrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    @model_validator(mode="after")
    def references_are_safe(self) -> "_StrictFrozenModel":
        prohibited = {
            "secret",
            "secret-ref",
            "vault",
            "vault-ref",
            "credential",
            "credential-ref",
        }
        for field_name in type(self).model_fields:
            if not (field_name.endswith("_ref") or field_name.endswith("_refs")):
                continue
            value = getattr(self, field_name)
            references = value if isinstance(value, tuple) else (value,)
            for reference in references:
                if not isinstance(reference, str):
                    continue
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
                    raise ValueError("documentation references must be safe non-secret URIs")
        return self


class DocumentationArtifactBinding(_StrictFrozenModel):
    artifact_id: str = Field(pattern=_STABLE_ID_PATTERN)
    artifact_type: str = Field(pattern=_STABLE_ID_PATTERN)
    artifact_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    revision: int = Field(ge=1)
    content_sha256: str = Field(pattern=_ENVELOPE_SHA256_PATTERN)
    validation_cycle_id: str = Field(pattern=_STABLE_ID_PATTERN)
    migration_unit_id: str = Field(pattern=_STABLE_ID_PATTERN)


class AcceptedDocumentationInput(DocumentationArtifactBinding):
    accepted_by_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)


class QASuiteValidationBinding(DocumentationArtifactBinding):
    artifact_type: Literal["qa_suite_validation"]
    validation_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    validation_hash: str = Field(pattern=_SHA256_PATTERN)
    status: Literal["validated"]
    evidence_class: EvidenceClass


class ProductionValidationBinding(DocumentationArtifactBinding):
    artifact_type: Literal["production_validation_report"]
    validation_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    validation_hash: str = Field(pattern=_SHA256_PATTERN)
    status: Literal["passed"]


class DocumentationOutputBinding(_StrictFrozenModel):
    output_type: DocumentationOutputType
    artifact_id: str = Field(pattern=_STABLE_ID_PATTERN)
    artifact_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    revision: int = Field(ge=1)
    content_sha256: str = Field(pattern=_ENVELOPE_SHA256_PATTERN)
    input_artifact_refs: tuple[str, ...] = Field(min_length=1)
    accepted_only: Literal[True]
    contains_copied_source_payload: Literal[False]

    @model_validator(mode="after")
    def inputs_are_unique(self) -> "DocumentationOutputBinding":
        if len(self.input_artifact_refs) != len(set(self.input_artifact_refs)):
            raise ValueError("documentation output input references must be unique")
        return self


class ExcludedContentControls(_StrictFrozenModel):
    raw_source_rows_included: Literal[False]
    query_result_rows_included: Literal[False]
    screenshots_included: Literal[False]
    secrets_or_credentials_included: Literal[False]
    unredacted_sensitive_content_included: Literal[False]
    references_and_hashes_only: Literal[True]


class DocumentationAuthorityClaims(_StrictFrozenModel):
    authorizes_promotion: Literal[False]
    authorizes_publication: Literal[False]
    authorizes_tenant_acceptance: Literal[False]
    authorizes_cutover: Literal[False]
    authorizes_source_decommission: Literal[False]


class DocumentationProvenance(_StrictFrozenModel):
    source_system: Literal["control_plane"]
    tenant_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    acquisition_channel: Literal["control_plane"]
    captured_at: str = Field(min_length=1)
    actor_ref: Literal["agent-ref://documentation-training"]
    request_id: str = Field(pattern=_STABLE_ID_PATTERN)
    source_request_ref: str | None = Field(default=None, pattern=_NON_SECRET_REF_PATTERN)
    permission_context_ref: str | None = Field(default=None, pattern=_NON_SECRET_REF_PATTERN)
    extractor_version: str = Field(min_length=1)
    content_hash: str = Field(pattern=_SHA256_PATTERN)


class DocumentationSecurity(_StrictFrozenModel):
    classification: Literal["public", "internal", "confidential", "restricted"]
    contains_sensitive_data: Literal[False]
    data_categories: tuple[Literal["none"], ...] = Field(min_length=1, max_length=1)
    redaction_state: Literal["not_required", "redacted", "tokenized", "restricted_reference_only"]
    tenant_partition_id: str = Field(pattern=_STABLE_ID_PATTERN)
    access_policy_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    retention_policy_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    egress_policy_ref: str | None = Field(default=None, pattern=_NON_SECRET_REF_PATTERN)
    source_pdp_context_ref: str | None = Field(default=None, pattern=_NON_SECRET_REF_PATTERN)


class DocumentationPackage(_StrictFrozenModel):
    contract_version: Literal["domo-to-omni.documentation-package.v1"]
    package_id: str = Field(pattern=_STABLE_ID_PATTERN)
    tenant_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    run_id: str = Field(pattern=_STABLE_ID_PATTERN)
    scope_id: str = Field(pattern=_STABLE_ID_PATTERN)
    wave_id: str = Field(pattern=_STABLE_ID_PATTERN)
    migration_unit_id: str = Field(pattern=_STABLE_ID_PATTERN)
    validation_cycle_id: str = Field(pattern=_STABLE_ID_PATTERN)
    evidence_class: EvidenceClass
    qa_suite_validation: QASuiteValidationBinding
    production_validation_bindings: tuple[ProductionValidationBinding, ...]
    final_target_bindings: tuple[AcceptedDocumentationInput, ...] = Field(min_length=1)
    accepted_input_bindings: tuple[AcceptedDocumentationInput, ...] = Field(min_length=3)
    output_bindings: tuple[DocumentationOutputBinding, ...] = Field(min_length=5, max_length=5)
    excluded_content: ExcludedContentControls
    authority: DocumentationAuthorityClaims
    created_by_ref: Literal["agent-ref://documentation-training"]
    created_at: str = Field(min_length=1)
    package_hash: str = Field(pattern=_SHA256_PATTERN)
    provenance: DocumentationProvenance
    security: DocumentationSecurity

    @model_validator(mode="after")
    def exact_partition_and_lineage(self) -> "DocumentationPackage":
        if self.qa_suite_validation.evidence_class != self.evidence_class:
            raise ValueError("documentation evidence class must match the QA suite validation")
        if self.evidence_class == "production":
            if not self.production_validation_bindings:
                raise ValueError("production documentation requires production validation")
        elif self.production_validation_bindings:
            raise ValueError("non-production documentation cannot claim production validation")

        partitioned = (
            self.qa_suite_validation,
            *self.production_validation_bindings,
            *self.final_target_bindings,
            *self.accepted_input_bindings,
        )
        if any(item.validation_cycle_id != self.validation_cycle_id for item in partitioned):
            raise ValueError("documentation bindings cross validation cycles")
        if any(item.migration_unit_id != self.migration_unit_id for item in partitioned):
            raise ValueError("documentation bindings cross migration units")
        if self.provenance.tenant_ref != self.tenant_ref:
            raise ValueError("documentation provenance crosses tenants")

        outputs = [item.output_type for item in self.output_bindings]
        if set(outputs) != _REQUIRED_OUTPUT_TYPES or len(outputs) != len(set(outputs)):
            raise ValueError("documentation package requires exactly one binding per output type")
        output_refs = [item.artifact_ref for item in self.output_bindings]
        output_ids = [item.artifact_id for item in self.output_bindings]
        if len(output_refs) != len(set(output_refs)) or len(output_ids) != len(set(output_ids)):
            raise ValueError("documentation output identities must be unique")

        input_by_ref = {item.artifact_ref: item for item in self.accepted_input_bindings}
        if len(input_by_ref) != len(self.accepted_input_bindings):
            raise ValueError("accepted documentation input references must be unique")
        coverage_bindings = [
            item
            for item in self.accepted_input_bindings
            if item.artifact_type == "semantic_profile_coverage"
        ]
        if len(coverage_bindings) != 1:
            raise ValueError(
                "documentation accepted inputs require exactly one semantic profile "
                "coverage binding"
            )
        coverage_ref = coverage_bindings[0].artifact_ref
        if any(
            item.artifact_type not in _FINAL_TARGET_TYPES for item in self.final_target_bindings
        ):
            raise ValueError("final target bindings contain a non-target artifact type")

        allowed_acceptance_refs = {
            self.qa_suite_validation.validation_ref,
            *(item.validation_ref for item in self.production_validation_bindings),
        }
        if any(
            item.accepted_by_ref not in allowed_acceptance_refs
            for item in self.accepted_input_bindings
        ):
            raise ValueError("documentation input is not bound to accepted validation evidence")

        required_bindings: tuple[DocumentationArtifactBinding, ...] = (
            self.qa_suite_validation,
            *self.production_validation_bindings,
            *self.final_target_bindings,
        )
        for required in required_bindings:
            candidate = input_by_ref.get(required.artifact_ref)
            if candidate is None or not _same_artifact_binding(candidate, required):
                raise ValueError("documentation accepted inputs omit or alter a required binding")

        accepted_refs = set(input_by_ref)
        qa_artifact_ref = self.qa_suite_validation.artifact_ref
        for output in self.output_bindings:
            if not set(output.input_artifact_refs).issubset(accepted_refs):
                raise ValueError("documentation output references an unaccepted input")
            if qa_artifact_ref not in output.input_artifact_refs:
                raise ValueError("every documentation output must bind the QA validation artifact")
            if coverage_ref not in output.input_artifact_refs:
                raise ValueError(
                    "every documentation output must bind semantic profile coverage"
                )
        return self


def _same_artifact_binding(
    left: DocumentationArtifactBinding, right: DocumentationArtifactBinding
) -> bool:
    fields = (
        "artifact_id",
        "artifact_type",
        "artifact_ref",
        "revision",
        "content_sha256",
        "validation_cycle_id",
        "migration_unit_id",
    )
    return all(getattr(left, field_name) == getattr(right, field_name) for field_name in fields)


def _normalize_documentation_package(value: Mapping[str, Any]) -> dict[str, Any]:
    raw = deepcopy(dict(value))
    for field_name in (
        "production_validation_bindings",
        "final_target_bindings",
        "accepted_input_bindings",
        "output_bindings",
    ):
        raw[field_name] = tuple(raw.get(field_name) or ())
    outputs: list[dict[str, Any]] = []
    for output in raw["output_bindings"]:
        item = deepcopy(dict(output))
        item["input_artifact_refs"] = tuple(item.get("input_artifact_refs") or ())
        outputs.append(item)
    raw["output_bindings"] = tuple(outputs)
    security = raw.get("security")
    if isinstance(security, Mapping):
        normalized_security = deepcopy(dict(security))
        normalized_security["data_categories"] = tuple(
            normalized_security.get("data_categories") or ()
        )
        raw["security"] = normalized_security
    return raw


def documentation_package_hash(value: DocumentationPackage | Mapping[str, Any]) -> str:
    source = (
        value.model_dump(mode="json") if isinstance(value, DocumentationPackage) else dict(value)
    )
    raw = _normalize_documentation_package(source)
    raw.pop("package_hash", None)
    return f"sha256:{sha256_json(raw)}"


def finalize_documentation_package(value: Mapping[str, Any]) -> DocumentationPackage:
    raw = _normalize_documentation_package(value)
    raw["package_hash"] = _ZERO_HASH
    parsed = DocumentationPackage.model_validate(raw)
    raw["package_hash"] = documentation_package_hash(parsed)
    return DocumentationPackage.model_validate(raw)


def validate_documentation_package(
    value: Mapping[str, Any] | DocumentationPackage,
    *,
    expected_tenant_ref: str | None = None,
    expected_run_id: str | None = None,
    expected_validation_cycle_id: str | None = None,
    expected_migration_unit_id: str | None = None,
    artifacts: Sequence[Mapping[str, Any] | ArtifactEnvelope] = (),
    require_registered_artifacts: bool = False,
) -> list[str]:
    """Return deterministic violations for one documentation package."""

    errors: list[str] = []
    try:
        package = (
            value
            if isinstance(value, DocumentationPackage)
            else DocumentationPackage.model_validate(_normalize_documentation_package(value))
        )
    except (TypeError, ValueError) as exc:
        return [f"documentation package is malformed: {exc}"]
    if package.package_hash != documentation_package_hash(package):
        errors.append("documentation package hash is not canonical")
    if expected_tenant_ref is not None and package.tenant_ref != expected_tenant_ref:
        errors.append("documentation package crosses tenants")
    if expected_run_id is not None and package.run_id != expected_run_id:
        errors.append("documentation package crosses runs")
    if (
        expected_validation_cycle_id is not None
        and package.validation_cycle_id != expected_validation_cycle_id
    ):
        errors.append("documentation package belongs to a stale validation cycle")
    if (
        expected_migration_unit_id is not None
        and package.migration_unit_id != expected_migration_unit_id
    ):
        errors.append("documentation package crosses migration units")

    normalized: list[ArtifactEnvelope] = []
    for raw_artifact in artifacts:
        try:
            normalized.append(
                raw_artifact
                if isinstance(raw_artifact, ArtifactEnvelope)
                else ArtifactEnvelope.from_mapping(raw_artifact)
            )
        except (TypeError, ValueError) as exc:
            errors.append(f"documentation artifact registry is malformed: {exc}")
    artifact_by_ref = {artifact.ref: artifact for artifact in normalized}
    bindings: tuple[DocumentationArtifactBinding | DocumentationOutputBinding, ...] = (
        package.qa_suite_validation,
        *package.production_validation_bindings,
        *package.final_target_bindings,
        *package.accepted_input_bindings,
        *package.output_bindings,
    )
    if require_registered_artifacts and not normalized:
        errors.append("documentation package requires registered artifact evidence")
    for binding in bindings:
        artifact = artifact_by_ref.get(binding.artifact_ref)
        if artifact is None:
            if require_registered_artifacts:
                errors.append(
                    f"documentation binding is not a registered artifact: {binding.artifact_ref}"
                )
            continue
        expected_type = (
            binding.output_type
            if isinstance(binding, DocumentationOutputBinding)
            else binding.artifact_type
        )
        if (
            artifact.artifact_id != binding.artifact_id
            or artifact.artifact_type != expected_type
            or artifact.revision != binding.revision
            or artifact.content_sha256 != binding.content_sha256
            or artifact.validation_cycle_id != package.validation_cycle_id
            or artifact.migration_unit_id != package.migration_unit_id
        ):
            errors.append(
                f"documentation binding does not match the registered artifact: "
                f"{binding.artifact_ref}"
            )
        if any(
            candidate.artifact_id == artifact.artifact_id and candidate.revision > artifact.revision
            for candidate in normalized
        ):
            errors.append(
                f"documentation binding uses a superseded artifact: {binding.artifact_ref}"
            )
    return sorted(set(errors))


__all__ = [
    "AcceptedDocumentationInput",
    "DocumentationArtifactBinding",
    "DocumentationAuthorityClaims",
    "DocumentationOutputBinding",
    "DocumentationPackage",
    "ExcludedContentControls",
    "ProductionValidationBinding",
    "QASuiteValidationBinding",
    "documentation_package_hash",
    "finalize_documentation_package",
    "validate_documentation_package",
]

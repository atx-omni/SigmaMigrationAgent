"""Typed contracts for the bounded Sigma Phase-0 capability-spike agent.

These contracts deliberately model development evidence separately from live tenant evidence and
human approval.  Producing a valid bundle never grants target-write, release, cutover, or
decommission authority.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from datetime import datetime
from types import MappingProxyType
from typing import Annotated, Any, Literal
from urllib.parse import quote, urlsplit

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_serializer,
    field_validator,
    model_validator,
)

from omni_migrator.control_plane.canonical import sha256_json
from omni_migrator.extractors.sigma.source_contracts import (
    DataModelSourceBinding,
    normalize_sigma_document_version,
)


EvidenceClassification = Literal[
    "documented_fact",
    "stated_evidence",
    "observed_tenant_behavior",
    "field_pattern",
    "assumption",
    "recommendation",
    "unresolved_gap",
    "synthetic_fixture",
]
CapabilityStatus = Literal[
    "verified_full",
    "verified_partial",
    "manual_required",
    "unavailable",
    "not_applicable",
]
SemanticMigrationMode = Literal["warehouse_first_refactor", "omni_semantic_reconstruction"]
SourceContextSchemaVersion = Literal[
    "sigma-capability-spike-bundle.v1",
    "sigma-data-model-snapshot.v1",
    "sigma-workbook-graph.v1",
    "sigma-behavior-manifest.v1",
    "sigma-api-capability-matrix.v1",
    "sigma-migration-scope.v1",
    "semantic-profile.v1",
    "semantic-profile-coverage.v1",
    "repository-inventory.v1",
]
_SAFE_SIGMA_OBJECT_ID_PATTERN = r"^[A-Za-z0-9_-][A-Za-z0-9._~-]{0,511}$"
_SAFE_SIGMA_OBJECT_ID = re.compile(_SAFE_SIGMA_OBJECT_ID_PATTERN)
_SAFE_PATH_LABEL_PATTERN = r"^[^/\\?#%\x00-\x1f\x7f]+$"
_SAFE_HOST_PATTERN = r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$"
_SAFE_HOST = re.compile(_SAFE_HOST_PATTERN)
_HostName = Annotated[str, Field(pattern=_SAFE_HOST_PATTERN, max_length=253)]


def _add_semantic_route_constraints(schema: dict[str, Any]) -> None:
    """Publish the same route topology and projection enforced by the runtime validator."""

    omni_ref = {"type": "string", "pattern": r"^environment-ref://omni/\S+$"}
    data_layer_ref = {
        "type": "string",
        "pattern": r"^environment-ref://(?:dbt|snowflake|warehouse)/\S+$",
    }
    warehouse_properties: dict[str, Any] = {
        "mode": {"const": "warehouse_first_refactor"},
        "target_environment_refs": {
            "type": "array",
            "minItems": 2,
            "uniqueItems": True,
            "items": {"oneOf": [omni_ref, data_layer_ref]},
            "contains": omni_ref,
            "minContains": 1,
            "maxContains": 1,
            "allOf": [
                {
                    "contains": data_layer_ref,
                    "minContains": 1,
                }
            ],
        },
    }
    direct_properties: dict[str, Any] = {
        "mode": {"const": "omni_semantic_reconstruction"},
        "target_environment_refs": {
            "type": "array",
            "minItems": 1,
            "maxItems": 1,
            "uniqueItems": True,
            "items": omni_ref,
        },
    }
    route_effect_fields: list[str] = []
    if "dbt_route" in schema.get("properties", {}):
        route_effect_fields = [
            "dbt_route",
            "consolidation_route",
            "omni_model_route",
            "semantic_acceptance_objective",
            "required_specialist_ids",
            "skipped_specialist_ids",
        ]
        warehouse_properties.update(
            {
                "dbt_route": {"const": "required_when_approved_blueprint_places_logic_upstream"},
                "consolidation_route": {"const": "evaluate_reuse_merge_parameterize_split"},
                "omni_model_route": {"const": "model_on_accepted_source_and_data_layer_relations"},
                "semantic_acceptance_objective": {
                    "const": "bounded_semantic_equivalence_after_approved_rearchitecture"
                },
                "required_specialist_ids": {
                    "const": [
                        "sigma_analytics_formula",
                        "sigma_semantic_consolidation",
                        "sigma_dbt_analytics_engineer",
                        "sigma_omni_modeler",
                        "sigma_independent_qa",
                    ]
                },
                "skipped_specialist_ids": {"const": []},
            }
        )
        direct_properties.update(
            {
                "dbt_route": {"const": "not_applicable_direct_route"},
                "consolidation_route": {"const": "preserve_source_boundaries_for_direct_route"},
                "omni_model_route": {
                    "const": "reconstruct_semantics_in_omni_over_accepted_warehouse_relations"
                },
                "semantic_acceptance_objective": {
                    "const": "bounded_semantic_equivalence_after_direct_reconstruction"
                },
                "required_specialist_ids": {
                    "const": [
                        "sigma_analytics_formula",
                        "sigma_semantic_consolidation",
                        "sigma_omni_modeler",
                        "sigma_independent_qa",
                    ]
                },
                "skipped_specialist_ids": {"const": ["sigma_dbt_analytics_engineer"]},
            }
        )
    required_fields = ["mode", "target_environment_refs", *route_effect_fields]
    schema.setdefault("allOf", []).append(
        {
            "oneOf": [
                {
                    "title": "Warehouse-first target environments",
                    "properties": warehouse_properties,
                    "required": required_fields,
                },
                {
                    "title": "Direct Omni target environment",
                    "properties": direct_properties,
                    "required": required_fields,
                },
            ]
        }
    )


def _add_semantic_prompt_option_constraints(schema: dict[str, Any]) -> None:
    """Require exactly one option for each supported route in the published prompt schema."""

    options = schema["properties"]["options"]
    options.setdefault("allOf", []).extend(
        [
            {
                "contains": {
                    "type": "object",
                    "properties": {"mode": {"const": "warehouse_first_refactor"}},
                    "required": ["mode"],
                },
                "minContains": 1,
                "maxContains": 1,
            },
            {
                "contains": {
                    "type": "object",
                    "properties": {"mode": {"const": "omni_semantic_reconstruction"}},
                    "required": ["mode"],
                },
                "minContains": 1,
                "maxContains": 1,
            },
        ]
    )


_PHASE0_CAPABILITY_IDS = frozenset(
    {
        "tenant_principal_binding",
        "selected_object_identity",
        "data_model_specification",
        "workbook_structure",
        "formulas",
        "sources",
        "lineage",
        "controls",
        "actions",
        "layout",
        "formatting",
        "security",
        "schedules",
        "materialization_schedules",
        "saved_views",
        "embeds",
        "versions",
        "input_tables",
        "principal_visibility",
        "pagination",
    }
)
_PHASE0_REQUIRED_VERIFIED_FULL = frozenset(
    {"tenant_principal_binding", "selected_object_identity", "pagination"}
)


class _ImmutableMapping(Mapping[str, Any]):
    """Read-only JSON mapping backed by an unreferenced mapping proxy."""

    __slots__ = ("_data",)

    def __init__(self, value: Mapping[str, Any]) -> None:
        if hasattr(self, "_data"):
            raise TypeError("contract values are immutable")
        object.__setattr__(self, "_data", MappingProxyType(dict(value)))

    def __getitem__(self, key: str) -> Any:
        return self._data[key]

    def __iter__(self):
        return iter(self._data)

    def __len__(self) -> int:
        return len(self._data)

    def __setattr__(self, _name: str, _value: object) -> None:
        raise TypeError("contract values are immutable")

    def _immutable(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("contract values are immutable")

    __setitem__ = _immutable
    __delitem__ = _immutable
    clear = _immutable
    pop = _immutable
    popitem = _immutable
    setdefault = _immutable
    update = _immutable

    def __repr__(self) -> str:
        return repr(dict(self._data))

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Mapping):
            return dict(self.items()) == dict(other.items())
        return False


def _deep_freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return _ImmutableMapping({key: _deep_freeze(child) for key, child in value.items()})
    if isinstance(value, list | tuple):
        return tuple(_deep_freeze(child) for child in value)
    if isinstance(value, set | frozenset):
        return frozenset(_deep_freeze(child) for child in value)
    return value


def _serialize_contract_value(value: Any, *, mode: str) -> Any:
    if isinstance(value, Mapping):
        return {key: _serialize_contract_value(child, mode=mode) for key, child in value.items()}
    if isinstance(value, tuple):
        return tuple(_serialize_contract_value(child, mode=mode) for child in value)
    if isinstance(value, frozenset):
        return tuple(
            _serialize_contract_value(child, mode=mode) for child in sorted(value, key=repr)
        )
    if isinstance(value, BaseModel):
        return value.model_dump(mode=mode)
    return value


class _FrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    @model_validator(mode="after")
    def nested_contract_values_are_immutable(self) -> "_FrozenModel":
        for field_name in type(self).model_fields:
            current = getattr(self, field_name)
            frozen = _deep_freeze(current)
            if frozen is not current:
                object.__setattr__(self, field_name, frozen)
        return self


def _require_ref(value: str, *, prefix: str | None = None) -> str:
    if not value or any(character.isspace() for character in value) or "://" not in value:
        raise ValueError("must be a non-secret URI-style reference")
    if prefix is not None and not value.startswith(prefix):
        raise ValueError(f"must start with {prefix}")
    return value


def _require_safe_object_id(value: str) -> str:
    if not _SAFE_SIGMA_OBJECT_ID.fullmatch(value):
        raise ValueError("must be a safe opaque Sigma object ID")
    return value


def _require_safe_path_label(value: str) -> str:
    if (
        value in {".", ".."}
        or any(character in value for character in "/\\?#%")
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ValueError("must be safe for use as one encoded Sigma URL path segment")
    return value


class SourceFreeze(_FrozenModel):
    strategy: Literal["published_version", "version_tag", "documented_alternative"]
    source_reference: str
    workbook_tag_name: str | None = Field(
        default=None,
        min_length=1,
        max_length=512,
        json_schema_extra={"pattern": _SAFE_PATH_LABEL_PATTERN},
    )
    workbook_published_version: int | None = Field(default=None, ge=1)
    data_model_document_version: int = Field(ge=1)
    approved_by_ref: str
    approval_ref: str

    @field_validator("source_reference")
    @classmethod
    def source_reference_is_non_secret(cls, value: str) -> str:
        return _require_ref(value)

    @field_validator("workbook_tag_name")
    @classmethod
    def tag_name_is_one_safe_path_segment(cls, value: str | None) -> str | None:
        return _require_safe_path_label(value) if value is not None else None

    @field_validator("approved_by_ref")
    @classmethod
    def approver_is_human(cls, value: str) -> str:
        return _require_ref(value, prefix="human-ref://")

    @field_validator("approval_ref")
    @classmethod
    def approval_is_human_controlled(cls, value: str) -> str:
        return _require_ref(value, prefix="human-approval-ref://")

    @model_validator(mode="after")
    def selector_matches_strategy(self) -> "SourceFreeze":
        if self.strategy == "version_tag" and self.workbook_tag_name is None:
            raise ValueError("version_tag freeze requires workbook_tag_name")
        if self.strategy == "version_tag" and self.workbook_published_version is not None:
            raise ValueError("version_tag freeze cannot also declare workbook_published_version")
        if self.strategy == "published_version" and self.workbook_published_version is None:
            raise ValueError("published_version freeze requires workbook_published_version")
        if self.strategy == "published_version" and self.workbook_tag_name is not None:
            raise ValueError("published_version freeze cannot also declare workbook_tag_name")
        if self.strategy == "documented_alternative" and (
            self.workbook_tag_name is not None or self.workbook_published_version is not None
        ):
            raise ValueError("documented_alternative freeze cannot declare tag/version selectors")
        return self


class ApprovedExclusion(_FrozenModel):
    property_id: str = Field(min_length=1, max_length=128)
    reason: str = Field(min_length=1, max_length=2_000)
    approved_by_ref: str
    approval_ref: str

    @field_validator("approved_by_ref")
    @classmethod
    def exclusion_approver_is_human(cls, value: str) -> str:
        return _require_ref(value, prefix="human-ref://")

    @field_validator("approval_ref")
    @classmethod
    def exclusion_approval_is_human_controlled(cls, value: str) -> str:
        return _require_ref(value, prefix="human-approval-ref://")


class SigmaCapabilitySpikeRequest(_FrozenModel):
    schema_version: Literal["sigma-capability-spike-request.v1"]
    run_id: str = Field(min_length=3, max_length=160)
    scope_id: str = Field(min_length=3, max_length=160)
    organization_ref: str
    expected_organization_id: str = Field(min_length=1, max_length=512)
    api_base_url: str = Field(json_schema_extra={"format": "uri", "pattern": r"^https://"})
    approved_api_hosts: tuple[_HostName, ...] = Field(min_length=1)
    principal_ref: str
    expected_user_id: str = Field(min_length=1, max_length=512)
    effective_account_type: Literal["admin", "creator", "explorer", "viewer", "unknown"]
    credential_ref: str = Field(json_schema_extra={"pattern": r"^secret-ref://\S+$"})
    authorization_ref: str
    scope_approval_ref: str
    comparison_scope_refs: tuple[str, ...] = Field(min_length=2)
    build_scope_refs: tuple[str, ...] = Field(min_length=1)
    policy_version: str = Field(min_length=1, max_length=128)
    workbook_id: str = Field(
        min_length=1,
        max_length=512,
        json_schema_extra={"pattern": _SAFE_SIGMA_OBJECT_ID_PATTERN},
    )
    data_model_id: str = Field(
        min_length=1,
        max_length=512,
        json_schema_extra={"pattern": _SAFE_SIGMA_OBJECT_ID_PATTERN},
    )
    source_freeze: SourceFreeze
    manual_evidence_owner_ref: str
    privacy_approval_ref: str
    sanitization_policy_ref: str
    retention_policy_ref: str
    data_classification: Literal["public", "internal", "confidential", "restricted"]
    row_data_authorized: Literal[False] = False
    evidence_mode: Literal["live_tenant", "synthetic_fixture"] = "live_tenant"
    request_budget: int = Field(default=100, ge=10, le=250)
    per_endpoint_request_budget: int = Field(default=20, ge=3, le=250)
    approved_exclusions: tuple[ApprovedExclusion, ...] = ()

    @field_validator(
        "organization_ref",
        "principal_ref",
        "authorization_ref",
        "scope_approval_ref",
        "manual_evidence_owner_ref",
        "privacy_approval_ref",
        "sanitization_policy_ref",
        "retention_policy_ref",
    )
    @classmethod
    def operational_refs_are_non_secret(cls, value: str) -> str:
        return _require_ref(value)

    @field_validator("credential_ref")
    @classmethod
    def credential_is_reference_only(cls, value: str) -> str:
        if not value.startswith("secret-ref://"):
            raise ValueError("credential_ref must be a secret-ref:// reference, never a value")
        return _require_ref(value, prefix="secret-ref://")

    @field_validator("workbook_id", "data_model_id")
    @classmethod
    def source_ids_are_safe_opaque_ids(cls, value: str) -> str:
        return _require_safe_object_id(value)

    @field_validator("scope_approval_ref")
    @classmethod
    def scope_approval_is_human_controlled(cls, value: str) -> str:
        return _require_ref(value, prefix="human-approval-ref://")

    @field_validator("privacy_approval_ref")
    @classmethod
    def privacy_approval_is_human_controlled(cls, value: str) -> str:
        return _require_ref(value, prefix="human-approval-ref://")

    @field_validator("manual_evidence_owner_ref")
    @classmethod
    def manual_owner_is_human(cls, value: str) -> str:
        return _require_ref(value, prefix="human-ref://")

    @field_validator("comparison_scope_refs", "build_scope_refs")
    @classmethod
    def refs_are_unique_and_non_secret(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(_require_ref(value) for value in values)
        if len(normalized) != len(set(normalized)):
            raise ValueError("references must be unique")
        return normalized

    @field_validator("approved_api_hosts")
    @classmethod
    def hosts_are_unique(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(value.strip().lower() for value in values)
        if any(
            not _SAFE_HOST.fullmatch(value)
            or ".." in value
            or any(
                not label or len(label) > 63 or label.startswith("-") or label.endswith("-")
                for label in value.split(".")
            )
            for value in normalized
        ):
            raise ValueError("approved_api_hosts must contain host names only")
        if len(normalized) != len(set(normalized)):
            raise ValueError("approved_api_hosts must be unique")
        return normalized

    @model_validator(mode="after")
    def request_is_bounded_and_host_allowlisted(self) -> "SigmaCapabilitySpikeRequest":
        parsed = urlsplit(self.api_base_url)
        if parsed.scheme != "https" or not parsed.hostname:
            raise ValueError("Sigma api_base_url must be an absolute HTTPS URL")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("Sigma api_base_url cannot contain credentials, query, or fragment")
        if parsed.path not in ("", "/"):
            raise ValueError("Sigma api_base_url must not contain an endpoint path")
        try:
            port = parsed.port
        except ValueError as error:
            raise ValueError("Sigma api_base_url contains an invalid port") from error
        if port not in (None, 443):
            raise ValueError("Sigma api_base_url may use only the standard HTTPS port")
        if parsed.hostname.lower() not in self.approved_api_hosts:
            raise ValueError("Sigma API host is not in approved_api_hosts")

        comparison = set(self.comparison_scope_refs)
        if not set(self.build_scope_refs).issubset(comparison):
            raise ValueError("build_scope_refs must be a subset of comparison_scope_refs")
        required = {
            f"sigma://workbooks/{self.workbook_id}",
            f"sigma://dataModels/{self.data_model_id}",
        }
        workbook_refs = {item for item in comparison if item.startswith("sigma://workbooks/")}
        data_model_refs = {item for item in comparison if item.startswith("sigma://dataModels/")}
        if workbook_refs != {f"sigma://workbooks/{self.workbook_id}"}:
            raise ValueError("Phase 0 comparison scope must contain exactly one Sigma workbook")
        if data_model_refs != {f"sigma://dataModels/{self.data_model_id}"}:
            raise ValueError("Phase 0 comparison scope must contain exactly one Sigma data model")
        if not required.issubset(comparison):
            raise ValueError("comparison scope must include the pilot workbook and data model")
        if self.source_freeze.strategy == "version_tag":
            expected_freeze_ref = (
                f"sigma://workbooks/{self.workbook_id}/tags/"
                f"{quote(self.source_freeze.workbook_tag_name or '', safe='-._~')}"
            )
            if self.source_freeze.source_reference != expected_freeze_ref:
                raise ValueError("source_freeze reference must bind the exact workbook and tag")
        elif self.source_freeze.strategy == "published_version":
            expected_freeze_ref = (
                f"sigma://workbooks/{self.workbook_id}/versions/"
                f"{self.source_freeze.workbook_published_version}"
            )
            if self.source_freeze.source_reference != expected_freeze_ref:
                raise ValueError("source_freeze reference must bind the exact workbook version")
        if len({item.property_id for item in self.approved_exclusions}) != len(
            self.approved_exclusions
        ):
            raise ValueError("approved exclusions must use unique property IDs")
        if self.per_endpoint_request_budget > self.request_budget:
            raise ValueError("per_endpoint_request_budget cannot exceed request_budget")
        return self


class ArtifactInput(_FrozenModel):
    artifact_id: str
    content_hash: str = Field(pattern=r"^[a-f0-9]{64}$")


class ArtifactFields(_FrozenModel):
    artifact_id: str
    run_id: str
    scope_id: str
    created_at: datetime
    producer: str
    source_references: tuple[str, ...]
    upstream_hashes: tuple[ArtifactInput, ...]
    content_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    classification: EvidenceClassification
    supersession_state: Literal["current", "superseded"] = "current"
    supersedes_artifact_id: str | None = None
    superseded_by_artifact_id: str | None = None
    immutable: Literal[True] = True

    @field_validator("producer")
    @classmethod
    def producer_is_reference(cls, value: str) -> str:
        return _require_ref(value)

    @field_validator("source_references")
    @classmethod
    def sources_are_refs(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(_require_ref(value) for value in values)
        if len(normalized) != len(set(normalized)):
            raise ValueError("source references must be unique")
        return normalized

    @model_validator(mode="after")
    def supersession_is_explicit(self) -> "ArtifactFields":
        if self.created_at.tzinfo is None or self.created_at.utcoffset() is None:
            raise ValueError("artifact created_at must be timezone-aware")
        if self.supersession_state == "superseded" and self.superseded_by_artifact_id is None:
            raise ValueError("superseded artifacts must name their replacement")
        if self.supersession_state == "current" and self.superseded_by_artifact_id is not None:
            raise ValueError("current artifacts cannot name a replacement")
        return self

    @model_validator(mode="after")
    def declared_content_hash_is_valid(self) -> "ArtifactFields":
        material = self.model_dump(mode="json")
        declared_hash = material.pop("content_hash")
        if declared_hash != sha256_json(material):
            raise ValueError(f"artifact content hash mismatch: {self.artifact_id}")
        return self


class RunManifestPayload(_FrozenModel):
    organization_ref: str
    expected_organization_id: str = Field(min_length=1, max_length=512)
    api_base_url: str = Field(json_schema_extra={"format": "uri", "pattern": r"^https://"})
    approved_api_hosts: tuple[_HostName, ...] = Field(min_length=1)
    principal_ref: str
    expected_user_id: str = Field(min_length=1, max_length=512)
    effective_account_type: Literal["admin", "creator", "explorer", "viewer", "unknown"]
    credential_ref: str = Field(json_schema_extra={"pattern": r"^secret-ref://\S+$"})
    authorization_ref: str
    scope_approval_ref: str
    comparison_scope_refs: tuple[str, ...] = Field(min_length=2)
    build_scope_refs: tuple[str, ...] = Field(min_length=1)
    policy_version: str = Field(min_length=1, max_length=128)
    workbook_id: str = Field(
        min_length=1,
        max_length=512,
        json_schema_extra={"pattern": _SAFE_SIGMA_OBJECT_ID_PATTERN},
    )
    data_model_id: str = Field(
        min_length=1,
        max_length=512,
        json_schema_extra={"pattern": _SAFE_SIGMA_OBJECT_ID_PATTERN},
    )
    source_freeze: SourceFreeze
    manual_evidence_owner_ref: str
    privacy_approval_ref: str
    sanitization_policy_ref: str
    retention_policy_ref: str
    data_classification: Literal["public", "internal", "confidential", "restricted"]
    row_data_authorized: Literal[False]
    evidence_mode: Literal["live_tenant", "synthetic_fixture"]
    request_budget: int = Field(ge=10, le=250)
    per_endpoint_request_budget: int = Field(ge=3, le=250)
    approved_exclusions: tuple[ApprovedExclusion, ...]
    mutation_endpoints_exposed: Literal[False] = False
    target_write_authority: Literal[False] = False
    release_authority: Literal[False] = False
    decommission_authority: Literal[False] = False

    @model_validator(mode="after")
    def mirrors_a_valid_capability_request(self) -> "RunManifestPayload":
        request_fields = {
            field_name: getattr(self, field_name)
            for field_name in SigmaCapabilitySpikeRequest.model_fields
            if field_name not in {"schema_version", "run_id", "scope_id"}
        }
        SigmaCapabilitySpikeRequest.model_validate(
            {
                "schema_version": "sigma-capability-spike-request.v1",
                "run_id": "run.manifest.validation",
                "scope_id": "scope.manifest.validation",
                **request_fields,
            }
        )
        return self


class SigmaRunManifestArtifact(ArtifactFields):
    schema_version: Literal["sigma-run-manifest.v1"]
    payload: RunManifestPayload


class DeclaredSourceContextBinding(_FrozenModel):
    """Exact source artifact plus acceptance metadata awaiting trusted-store resolution."""

    artifact_id: str = Field(min_length=1, max_length=512)
    artifact_schema_version: SourceContextSchemaVersion
    artifact_run_id: str = Field(min_length=3, max_length=160)
    artifact_scope_id: str = Field(min_length=3, max_length=160)
    content_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    artifact_created_at: datetime
    accepted_by_ref: str = Field(json_schema_extra={"pattern": r"^human-ref://\S+$"})
    acceptance_ref: str = Field(json_schema_extra={"pattern": r"^human-approval-ref://\S+$"})
    acceptance_record_revision: str = Field(min_length=1, max_length=128)
    acceptance_record_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    accepted_at: datetime
    acceptance_verification_state: Literal["reference_only"] = "reference_only"

    @field_validator("accepted_by_ref")
    @classmethod
    def source_acceptance_owner_is_human(cls, value: str) -> str:
        return _require_ref(value, prefix="human-ref://")

    @field_validator("acceptance_ref")
    @classmethod
    def source_acceptance_is_human_controlled_reference(cls, value: str) -> str:
        return _require_ref(value, prefix="human-approval-ref://")

    @field_validator("artifact_created_at", "accepted_at")
    @classmethod
    def source_context_times_are_timezone_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("source context timestamps must be timezone-aware")
        return value

    @model_validator(mode="after")
    def acceptance_follows_source_artifact(self) -> "DeclaredSourceContextBinding":
        if self.accepted_at < self.artifact_created_at:
            raise ValueError("source acceptance cannot predate its artifact")
        return self


class SupersededSemanticDecisionBinding(_FrozenModel):
    artifact_id: str = Field(min_length=1, max_length=512)
    content_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    created_at: datetime
    scope_id: str = Field(min_length=3, max_length=160)
    migration_unit_id: str = Field(
        min_length=3,
        max_length=160,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{2,159}$",
    )

    @field_validator("created_at")
    @classmethod
    def previous_decision_time_is_timezone_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("superseded decision created_at must be timezone-aware")
        return value


class WarehouseFirstSemanticRoutingPromptOption(_FrozenModel):
    mode: Literal["warehouse_first_refactor"]
    label: Literal["Warehouse-first refactor"]
    description: Literal[
        "The fully modeled path: preserve accepted semantics while moving approved shared and "
        "persistent transformation logic into the governed data layer before Omni."
    ]


class OmniSemanticReconstructionRoutingPromptOption(_FrozenModel):
    mode: Literal["omni_semantic_reconstruction"]
    label: Literal["Omni semantic reconstruction"]
    description: Literal[
        "The lift-and-shift path: preserve accepted semantics through direct Omni reconstruction "
        "over accepted existing warehouse relations, without requiring data-layer changes."
    ]


SemanticRoutingPromptOption = Annotated[
    WarehouseFirstSemanticRoutingPromptOption | OmniSemanticReconstructionRoutingPromptOption,
    Field(discriminator="mode"),
]


class SigmaSemanticRoutingPrompt(_FrozenModel):
    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        json_schema_extra=_add_semantic_prompt_option_constraints,
    )

    schema_version: Literal["sigma-semantic-routing-prompt.v1"]
    state: Literal["awaiting_human_choice"] = "awaiting_human_choice"
    question: Literal[
        "Which implementation path should this Sigma semantic layer use: warehouse-first "
        "refactoring before Omni, or direct reconstruction in Omni?"
    ]
    shared_guardrail: Literal[
        "Both paths target bounded semantic equivalence with explicit exceptions and the same "
        "closed-denominator QA; neither guarantees one-to-one semantic, behavioral, visual, or "
        "workflow parity."
    ]
    options: tuple[SemanticRoutingPromptOption, ...] = Field(min_length=2, max_length=2)
    default_mode: None = None
    next_required_contract: Literal["sigma-semantic-routing-decision-request.v1"] = (
        "sigma-semantic-routing-decision-request.v1"
    )
    blocks_target_design: Literal[True] = True
    blocks_source_evidence_acquisition: Literal[False] = False

    @model_validator(mode="after")
    def presents_both_modes_once(self) -> "SigmaSemanticRoutingPrompt":
        modes = tuple(item.mode for item in self.options)
        if set(modes) != {"warehouse_first_refactor", "omni_semantic_reconstruction"}:
            raise ValueError("semantic routing prompt must present both supported modes")
        if len(modes) != len(set(modes)):
            raise ValueError("semantic routing prompt modes must be unique")
        return self


class SigmaSemanticRoutingDecisionRequest(_FrozenModel):
    """Required, scope-bound human direction for target semantic architecture.

    This request is deliberately separate from ``SigmaCapabilitySpikeRequest`` so target
    architecture can change without changing or reacquiring source evidence.
    """

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        json_schema_extra=_add_semantic_route_constraints,
    )

    schema_version: Literal["sigma-semantic-routing-decision-request.v1"]
    decision_id: str = Field(
        min_length=3,
        max_length=160,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{2,159}$",
    )
    run_id: str = Field(min_length=3, max_length=160)
    scope_id: str = Field(min_length=3, max_length=160)
    migration_unit_id: str = Field(
        min_length=3,
        max_length=160,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{2,159}$",
    )
    comparison_scope_refs: tuple[str, ...] = Field(min_length=2)
    build_scope_refs: tuple[str, ...] = Field(min_length=1)
    target_environment_refs: tuple[str, ...] = Field(min_length=1)
    mode: SemanticMigrationMode
    decided_by_ref: str = Field(json_schema_extra={"pattern": r"^human-ref://\S+$"})
    decision_ref: str = Field(json_schema_extra={"pattern": r"^human-decision-ref://\S+$"})
    decision_record_revision: str = Field(min_length=1, max_length=128)
    decision_record_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    decided_at: datetime
    rationale: str = Field(min_length=10, max_length=4_000)
    source_context_bindings: tuple[DeclaredSourceContextBinding, ...] = Field(min_length=1)
    supersedes_decision: SupersededSemanticDecisionBinding | None = None
    question_version: Literal["sigma-semantic-migration-question.v1"] = (
        "sigma-semantic-migration-question.v1"
    )

    @field_validator(
        "comparison_scope_refs",
        "build_scope_refs",
        "target_environment_refs",
        mode="after",
    )
    @classmethod
    def routing_scope_values_are_canonical_unique_refs(
        cls, values: tuple[str, ...]
    ) -> tuple[str, ...]:
        normalized = tuple(_require_ref(value) for value in values)
        if len(normalized) != len(set(normalized)):
            raise ValueError("semantic routing references must be unique within each field")
        return tuple(sorted(normalized))

    @field_validator("source_context_bindings", mode="after")
    @classmethod
    def source_context_order_is_canonical(
        cls, values: tuple[DeclaredSourceContextBinding, ...]
    ) -> tuple[DeclaredSourceContextBinding, ...]:
        return tuple(
            sorted(
                values,
                key=lambda item: (
                    item.artifact_id,
                    item.artifact_schema_version,
                    item.content_hash,
                ),
            )
        )

    @field_validator("decided_by_ref")
    @classmethod
    def decision_owner_is_human(cls, value: str) -> str:
        return _require_ref(value, prefix="human-ref://")

    @field_validator("decision_ref")
    @classmethod
    def decision_is_human_controlled_reference(cls, value: str) -> str:
        return _require_ref(value, prefix="human-decision-ref://")

    @field_validator("decided_at")
    @classmethod
    def decision_time_is_timezone_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("decided_at must be timezone-aware")
        return value

    @model_validator(mode="after")
    def build_scope_is_within_comparison_scope(self) -> "SigmaSemanticRoutingDecisionRequest":
        if not set(self.build_scope_refs).issubset(self.comparison_scope_refs):
            raise ValueError("build_scope_refs must be a subset of comparison_scope_refs")
        source_ids = tuple(item.artifact_id for item in self.source_context_bindings)
        if len(source_ids) != len(set(source_ids)):
            raise ValueError("source context artifact IDs must be unique")
        if any(item.artifact_scope_id != self.scope_id for item in self.source_context_bindings):
            raise ValueError("source context artifacts must bind the semantic routing scope")
        if any(item.accepted_at > self.decided_at for item in self.source_context_bindings):
            raise ValueError("semantic routing decision cannot predate source context acceptance")
        omni_targets = tuple(
            value
            for value in self.target_environment_refs
            if value.startswith("environment-ref://omni/")
        )
        data_layer_targets = tuple(
            value
            for value in self.target_environment_refs
            if value.startswith(
                (
                    "environment-ref://dbt/",
                    "environment-ref://snowflake/",
                    "environment-ref://warehouse/",
                )
            )
        )
        if len(omni_targets) != 1:
            raise ValueError("semantic routing requires exactly one Omni target environment")
        if len(omni_targets) + len(data_layer_targets) != len(self.target_environment_refs):
            raise ValueError("semantic routing contains an unsupported target environment type")
        if self.mode == "warehouse_first_refactor" and not data_layer_targets:
            raise ValueError("warehouse-first routing requires a data-layer target environment")
        if self.mode == "omni_semantic_reconstruction" and data_layer_targets:
            raise ValueError(
                "direct Omni reconstruction cannot include a data-layer target; create a "
                "superseding warehouse-first decision"
            )
        provenance_refs = (
            self.decision_ref,
            *(
                value
                for item in self.source_context_bindings
                for value in (f"artifact-ref://{item.artifact_id}", item.acceptance_ref)
            ),
        )
        if self.supersedes_decision is not None:
            if self.supersedes_decision.artifact_id == (
                f"sigma-semantic-routing-decision.{self.decision_id}"
            ):
                raise ValueError("semantic routing decision cannot supersede itself")
            if self.supersedes_decision.scope_id != self.scope_id:
                raise ValueError("superseded decision must bind the same scope")
            if self.supersedes_decision.migration_unit_id != self.migration_unit_id:
                raise ValueError("superseded decision must bind the same migration unit")
            if self.supersedes_decision.created_at >= self.decided_at:
                raise ValueError("superseded decision must predate the replacement decision")
            provenance_refs = (
                *provenance_refs,
                f"artifact-ref://{self.supersedes_decision.artifact_id}",
            )
        if len(provenance_refs) != len(set(provenance_refs)):
            raise ValueError("semantic routing provenance references must be unique")
        return self


class SemanticRoutingPayload(_FrozenModel):
    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        json_schema_extra=_add_semantic_route_constraints,
    )

    decision_id: str = Field(
        min_length=3,
        max_length=160,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{2,159}$",
    )
    run_id: str = Field(min_length=3, max_length=160)
    scope_id: str = Field(min_length=3, max_length=160)
    migration_unit_id: str = Field(
        min_length=3,
        max_length=160,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{2,159}$",
    )
    comparison_scope_refs: tuple[str, ...] = Field(min_length=2)
    build_scope_refs: tuple[str, ...] = Field(min_length=1)
    target_environment_refs: tuple[str, ...] = Field(min_length=1)
    mode: SemanticMigrationMode
    decided_by_ref: str = Field(json_schema_extra={"pattern": r"^human-ref://\S+$"})
    decision_ref: str = Field(json_schema_extra={"pattern": r"^human-decision-ref://\S+$"})
    decision_record_revision: str = Field(min_length=1, max_length=128)
    decision_record_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    decided_at: datetime
    rationale: str = Field(min_length=10, max_length=4_000)
    source_context_bindings: tuple[DeclaredSourceContextBinding, ...] = Field(min_length=1)
    supersedes_decision: SupersededSemanticDecisionBinding | None = None
    question_version: Literal["sigma-semantic-migration-question.v1"]
    decision_verification_state: Literal["reference_only"] = "reference_only"
    dbt_route: Literal[
        "required_when_approved_blueprint_places_logic_upstream",
        "not_applicable_direct_route",
    ]
    consolidation_route: Literal[
        "evaluate_reuse_merge_parameterize_split",
        "preserve_source_boundaries_for_direct_route",
    ]
    omni_model_route: Literal[
        "model_on_accepted_source_and_data_layer_relations",
        "reconstruct_semantics_in_omni_over_accepted_warehouse_relations",
    ]
    semantic_acceptance_objective: Literal[
        "bounded_semantic_equivalence_after_approved_rearchitecture",
        "bounded_semantic_equivalence_after_direct_reconstruction",
    ]
    behavior_route: Literal["separate_behavior_manifest_and_redesign"] = (
        "separate_behavior_manifest_and_redesign"
    )
    required_specialist_ids: tuple[str, ...]
    skipped_specialist_ids: tuple[str, ...]
    independent_qa_required: Literal[True] = True
    automatic_one_to_one_claim_allowed: Literal[False] = False
    target_design_approval_required: Literal[True] = True
    target_write_authority: Literal[False] = False

    @classmethod
    def expected_route(cls, mode: SemanticMigrationMode) -> dict[str, object]:
        return {
            "warehouse_first_refactor": {
                "dbt_route": "required_when_approved_blueprint_places_logic_upstream",
                "consolidation_route": "evaluate_reuse_merge_parameterize_split",
                "omni_model_route": "model_on_accepted_source_and_data_layer_relations",
                "semantic_acceptance_objective": (
                    "bounded_semantic_equivalence_after_approved_rearchitecture"
                ),
                "required_specialist_ids": (
                    "sigma_analytics_formula",
                    "sigma_semantic_consolidation",
                    "sigma_dbt_analytics_engineer",
                    "sigma_omni_modeler",
                    "sigma_independent_qa",
                ),
                "skipped_specialist_ids": (),
            },
            "omni_semantic_reconstruction": {
                "dbt_route": "not_applicable_direct_route",
                "consolidation_route": "preserve_source_boundaries_for_direct_route",
                "omni_model_route": (
                    "reconstruct_semantics_in_omni_over_accepted_warehouse_relations"
                ),
                "semantic_acceptance_objective": (
                    "bounded_semantic_equivalence_after_direct_reconstruction"
                ),
                "required_specialist_ids": (
                    "sigma_analytics_formula",
                    "sigma_semantic_consolidation",
                    "sigma_omni_modeler",
                    "sigma_independent_qa",
                ),
                "skipped_specialist_ids": ("sigma_dbt_analytics_engineer",),
            },
        }[mode]

    @model_validator(mode="after")
    def route_matches_human_choice(self) -> "SemanticRoutingPayload":
        normalized_request = SigmaSemanticRoutingDecisionRequest.model_validate(
            {
                "schema_version": "sigma-semantic-routing-decision-request.v1",
                **{
                    field_name: getattr(self, field_name)
                    for field_name in SigmaSemanticRoutingDecisionRequest.model_fields
                    if field_name != "schema_version"
                },
            }
        )
        for field_name in (
            "comparison_scope_refs",
            "build_scope_refs",
            "target_environment_refs",
            "source_context_bindings",
        ):
            if getattr(self, field_name) != getattr(normalized_request, field_name):
                raise ValueError("semantic routing payload is not canonically ordered")
        expected = self.expected_route(self.mode)
        for field_name, expected_value in expected.items():
            if getattr(self, field_name) != expected_value:
                raise ValueError("semantic route contradicts the human-selected migration mode")
        if len(self.required_specialist_ids) != len(set(self.required_specialist_ids)):
            raise ValueError("required semantic specialists must be unique")
        if len(self.skipped_specialist_ids) != len(set(self.skipped_specialist_ids)):
            raise ValueError("skipped semantic specialists must be unique")
        if set(self.required_specialist_ids).intersection(self.skipped_specialist_ids):
            raise ValueError("a semantic specialist cannot be both required and skipped")
        return self


class SigmaSemanticRoutingArtifact(ArtifactFields):
    schema_version: Literal["sigma-semantic-routing-decision.v1"]
    payload: SemanticRoutingPayload

    @model_validator(mode="after")
    def decision_is_independent_and_scope_bound(self) -> "SigmaSemanticRoutingArtifact":
        if self.run_id != self.payload.run_id or self.scope_id != self.payload.scope_id:
            raise ValueError("semantic routing artifact must bind its declared run and scope")
        if self.classification != "stated_evidence":
            raise ValueError("semantic routing choice is reference-only stated evidence")
        expected_upstreams = tuple(
            ArtifactInput(artifact_id=item.artifact_id, content_hash=item.content_hash)
            for item in self.payload.source_context_bindings
        )
        if self.payload.supersedes_decision is not None:
            expected_upstreams = (
                *expected_upstreams,
                ArtifactInput(
                    artifact_id=self.payload.supersedes_decision.artifact_id,
                    content_hash=self.payload.supersedes_decision.content_hash,
                ),
            )
        if self.upstream_hashes != expected_upstreams:
            raise ValueError("semantic routing must bind the exact source context hashes")
        expected_sources = (
            self.payload.decision_ref,
            *(
                value
                for item in self.payload.source_context_bindings
                for value in (f"artifact-ref://{item.artifact_id}", item.acceptance_ref)
            ),
        )
        expected_supersedes_id = None
        if self.payload.supersedes_decision is not None:
            expected_supersedes_id = self.payload.supersedes_decision.artifact_id
            expected_sources = (
                *expected_sources,
                f"artifact-ref://{self.payload.supersedes_decision.artifact_id}",
            )
        if self.supersedes_artifact_id != expected_supersedes_id:
            raise ValueError("semantic routing supersession does not match the decision payload")
        if self.source_references != expected_sources:
            raise ValueError("semantic routing source references do not match the decision payload")
        if self.created_at < self.payload.decided_at:
            raise ValueError("semantic routing artifact cannot predate the stated decision")
        for item in self.payload.source_context_bindings:
            if item.artifact_created_at >= self.created_at or item.accepted_at >= self.created_at:
                raise ValueError("semantic routing must postdate source context and its acceptance")
        if (
            self.payload.supersedes_decision is not None
            and self.payload.supersedes_decision.created_at >= self.created_at
        ):
            raise ValueError("semantic routing must postdate the superseded decision")
        return self


class ShapePath(_FrozenModel):
    path: str
    types: tuple[str, ...]


class ContinuationEvidence(_FrozenModel):
    present: bool
    kind: str | None
    sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")


class ObservationPayload(_FrozenModel):
    organization_ref: str
    principal_ref: str
    effective_account_type: str
    authorization_ref: str
    version_context: Literal[
        "tenant_principal_binding",
        "data_model_document_version",
        "workbook_tag",
        "lifecycle_bracket",
        "bracketed_unversioned",
        "current_unversioned",
    ]
    version_selector: dict[str, str]
    method: Literal["GET"]
    endpoint: str
    request_query: dict[str, Any]
    status_code: int = Field(ge=100, le=599)
    attempt: int = Field(ge=1)
    retryable: bool
    response_body_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    response_bytes: int = Field(ge=0)
    json_valid: bool
    response_shape: tuple[ShapePath, ...]
    exact_ids: dict[str, tuple[str, ...]]
    exact_id_set_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    primary_ids: dict[str, tuple[str, ...]]
    duplicate_id_count: int = Field(ge=0)
    entry_count: int | None = Field(default=None, ge=0)
    declared_total: int | None = Field(default=None, ge=0)
    continuation: ContinuationEvidence
    diagnostics: tuple[str, ...] = ()
    redaction_state: Literal["structural_only"] = "structural_only"
    row_data_retained: Literal[False] = False

    @field_serializer("version_selector")
    def serialize_version_selector(self, value: Mapping[str, str]) -> dict[str, str]:
        return dict(value)

    @field_serializer("request_query")
    def serialize_request_query(self, value: Mapping[str, Any]) -> dict[str, Any]:
        return _serialize_contract_value(value, mode="json")

    @field_serializer("exact_ids", "primary_ids")
    def serialize_exact_ids(
        self, value: Mapping[str, tuple[str, ...]]
    ) -> dict[str, tuple[str, ...]]:
        return dict(value)

    @model_validator(mode="after")
    def exact_id_hash_matches_values(self) -> "ObservationPayload":
        exact_ids = {key: list(values) for key, values in self.exact_ids.items()}
        if self.exact_id_set_sha256 != sha256_json(exact_ids):
            raise ValueError("observation exact-ID hash does not match its values")
        return self


class SigmaObservationArtifact(ArtifactFields):
    schema_version: Literal["sigma-observation.v1"]
    payload: ObservationPayload


class FallbackPlan(_FrozenModel):
    method: Literal[
        "customer_operated_export",
        "version_bound_render",
        "structured_owner_manifest",
        "host_application_manifest",
        "persona_test",
        "explicit_unsupported_disposition",
    ]
    owner_ref: str
    approval_state: Literal["proposed"] = "proposed"
    approval_ref: Literal[None] = None
    acceptance_test: str = Field(min_length=1, max_length=2_000)

    @field_validator("owner_ref")
    @classmethod
    def owner_is_human(cls, value: str) -> str:
        return _require_ref(value, prefix="human-ref://")


class CapabilityAssessment(_FrozenModel):
    capability_id: str
    object_types: tuple[str, ...] = Field(min_length=1)
    property_names: tuple[str, ...] = Field(min_length=1)
    status: CapabilityStatus
    evidence_refs: tuple[str, ...]
    documentation_refs: tuple[str, ...] = Field(min_length=1)
    observed_shape_paths: tuple[str, ...]
    missing_properties: tuple[str, ...]
    fallback: FallbackPlan | None
    blocks_full_adapter: bool
    rationale: str = Field(min_length=1, max_length=4_000)

    @model_validator(mode="after")
    def status_matches_evidence_and_fallback(self) -> "CapabilityAssessment":
        if self.status == "verified_full":
            if not self.evidence_refs:
                raise ValueError("verified_full capability requires observed evidence")
            if self.missing_properties or self.fallback is not None or self.blocks_full_adapter:
                raise ValueError("verified_full capability cannot carry gaps, fallback, or blocker")
        elif self.status == "verified_partial":
            if not self.evidence_refs:
                raise ValueError("verified_partial capability requires observed evidence")
            if self.fallback is None and not self.blocks_full_adapter:
                raise ValueError("verified_partial capability requires fallback or blocking state")
        elif self.status == "manual_required":
            if not self.missing_properties or self.fallback is None:
                raise ValueError("manual_required capability requires gaps and a fallback")
        elif self.status == "unavailable":
            if not self.missing_properties or not self.blocks_full_adapter:
                raise ValueError("unavailable capability requires gaps and blocking state")
        elif self.status == "not_applicable" and (
            self.missing_properties or self.fallback is not None or self.blocks_full_adapter
        ):
            raise ValueError("not_applicable capability cannot carry gaps, fallback, or blocker")
        return self


class CapabilityMatrixPayload(_FrozenModel):
    workbook_id: str
    data_model_id: str
    assessments: tuple[CapabilityAssessment, ...]
    matrix_status: Literal["ready_for_human_review", "blocked"]
    blocking_capability_ids: tuple[str, ...]
    manual_fallback_capability_ids: tuple[str, ...]
    deprecated_surfaces_encountered: tuple[str, ...]
    live_tenant_evidence: bool
    human_approval_required: Literal[True] = True
    source_adapter_build_authorized: Literal[False] = False

    @model_validator(mode="after")
    def denominator_and_status_are_closed(self) -> "CapabilityMatrixPayload":
        capability_ids = tuple(item.capability_id for item in self.assessments)
        if len(capability_ids) != len(set(capability_ids)) or set(capability_ids) != set(
            _PHASE0_CAPABILITY_IDS
        ):
            raise ValueError("capability matrix denominator is incomplete or duplicated")
        by_id = {item.capability_id: item for item in self.assessments}
        if any(
            by_id[capability_id].status != "verified_full"
            and not by_id[capability_id].blocks_full_adapter
            for capability_id in _PHASE0_REQUIRED_VERIFIED_FULL
        ):
            raise ValueError(
                "required identity or pagination capability must block unless verified_full"
            )
        blocking = tuple(
            sorted(item.capability_id for item in self.assessments if item.blocks_full_adapter)
        )
        if self.blocking_capability_ids != blocking:
            raise ValueError("capability matrix blocking denominator is inconsistent")
        manual = tuple(
            sorted(
                item.capability_id
                for item in self.assessments
                if item.status in {"manual_required", "verified_partial"}
                and item.fallback is not None
            )
        )
        if self.manual_fallback_capability_ids != manual:
            raise ValueError("capability matrix fallback denominator is inconsistent")
        expected_status = "blocked" if blocking else "ready_for_human_review"
        if self.matrix_status != expected_status:
            raise ValueError("capability matrix status is inconsistent")
        return self


class SigmaCapabilityMatrixArtifact(ArtifactFields):
    schema_version: Literal["sigma-api-capability-matrix.v1"]
    payload: CapabilityMatrixPayload


class GraphNode(_FrozenModel):
    node_id: str
    node_type: str
    native_id: str
    parent_node_id: str | None
    properties: dict[str, Any]
    source_refs: tuple[str, ...]

    @field_serializer("properties")
    def serialize_properties(self, value: Mapping[str, Any]) -> dict[str, Any]:
        return _serialize_contract_value(value, mode="json")


class GraphEdge(_FrozenModel):
    from_node_id: str
    to_node_id: str
    relation: str


class WorkbookGraphPayload(_FrozenModel):
    workbook_id: str
    source_freeze: SourceFreeze
    nodes: tuple[GraphNode, ...]
    edges: tuple[GraphEdge, ...]
    exact_node_set_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    unresolved_behavior: tuple[str, ...]
    untrusted_source_content: Literal[True] = True

    @model_validator(mode="after")
    def graph_is_closed_and_hashed(self) -> "WorkbookGraphPayload":
        node_ids = tuple(node.node_id for node in self.nodes)
        if len(node_ids) != len(set(node_ids)):
            raise ValueError("workbook graph node IDs must be unique")
        known = set(node_ids)
        for node in self.nodes:
            if node.parent_node_id is not None and node.parent_node_id not in known:
                raise ValueError("workbook graph contains an orphan parent binding")
        edge_keys = tuple(
            (edge.from_node_id, edge.to_node_id, edge.relation) for edge in self.edges
        )
        if len(edge_keys) != len(set(edge_keys)):
            raise ValueError("workbook graph edges must be unique")
        if any(source not in known or target not in known for source, target, _ in edge_keys):
            raise ValueError("workbook graph contains an orphan edge")
        exact_nodes = [
            {
                "node_id": node.node_id,
                "node_type": node.node_type,
                "native_id": node.native_id,
            }
            for node in self.nodes
        ]
        if self.exact_node_set_sha256 != sha256_json(exact_nodes):
            raise ValueError("workbook graph node-set hash is inconsistent")
        return self


class SigmaWorkbookGraphArtifact(ArtifactFields):
    schema_version: Literal["sigma-workbook-graph.v1"]
    payload: WorkbookGraphPayload


class DataModelSnapshotPayload(_FrozenModel):
    data_model_id: str
    source_freeze: SourceFreeze
    specification_state: Literal["bound", "unavailable"]
    specification_unavailability_reason: (
        Literal["acquisition_unavailable", "identity_mismatch", "version_mismatch"] | None
    ) = None
    sanitized_specification: dict[str, Any]
    source_bindings: tuple[DataModelSourceBinding, ...] = ()
    source_bindings_version_context: Literal["bracketed_unversioned"] = "bracketed_unversioned"
    specification_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    documented_omissions: tuple[str, ...]
    untrusted_source_content: Literal[True] = True

    @field_serializer("sanitized_specification")
    def serialize_sanitized_specification(self, value: Mapping[str, Any]) -> dict[str, Any]:
        return _serialize_contract_value(value, mode="json")

    @model_validator(mode="after")
    def specification_hash_matches_value(self) -> "DataModelSnapshotPayload":
        specification = _serialize_contract_value(
            self.sanitized_specification,
            mode="json",
        )
        if self.specification_sha256 != sha256_json(specification):
            raise ValueError("data-model specification hash is inconsistent")
        source_keys = [
            sha256_json(binding.model_dump(mode="json", exclude_none=True))
            for binding in self.source_bindings
        ]
        if len(source_keys) != len(set(source_keys)):
            raise ValueError("data-model source bindings contain duplicate compound identities")
        if self.specification_state == "unavailable":
            if specification or self.specification_unavailability_reason is None:
                raise ValueError(
                    "unavailable specification must be empty and explain its missing binding"
                )
        else:
            if self.specification_unavailability_reason is not None:
                raise ValueError("bound specification cannot carry an unavailability reason")
            if specification.get("dataModelId") != self.data_model_id:
                raise ValueError(
                    "data-model specification identity does not match the selected model"
                )
            if normalize_sigma_document_version(specification.get("documentVersion")) != str(
                self.source_freeze.data_model_document_version
            ):
                raise ValueError(
                    "data-model specification version does not match the selected version"
                )
        return self


class SigmaDataModelSnapshotArtifact(ArtifactFields):
    schema_version: Literal["sigma-data-model-snapshot.v1"]
    payload: DataModelSnapshotPayload


class BehaviorItem(_FrozenModel):
    behavior_id: str
    behavior_type: Literal[
        "control",
        "action",
        "input_table",
        "schedule",
        "saved_view",
        "embed",
        "layout",
        "formatting",
        "security",
    ]
    source_ref: str
    disposition: Literal[
        "observed",
        "partial",
        "manual_capture_required",
        "external_redesign_required",
    ]
    evidence_refs: tuple[str, ...]
    owner_ref: str | None
    acceptance_test: str
    blocking: bool

    @model_validator(mode="after")
    def disposition_matches_evidence_and_gate_state(self) -> "BehaviorItem":
        if self.disposition == "observed":
            if not self.evidence_refs or self.blocking:
                raise ValueError("observed behavior requires evidence and cannot remain blocking")
        elif self.disposition == "partial":
            if not self.evidence_refs or not self.blocking:
                raise ValueError("partial behavior requires evidence and blocking state")
        elif self.disposition in {"manual_capture_required", "external_redesign_required"}:
            if self.owner_ref is None or not self.blocking:
                raise ValueError("manual behavior requires an owner and blocking state")
            _require_ref(self.owner_ref, prefix="human-ref://")
        return self


class BehaviorManifestPayload(_FrozenModel):
    workbook_id: str
    behaviors: tuple[BehaviorItem, ...]
    closed_denominator: bool
    unresolved_behavior_ids: tuple[str, ...]
    analytical_build_authorized: Literal[False] = False

    @model_validator(mode="after")
    def behavior_denominator_is_closed(self) -> "BehaviorManifestPayload":
        behavior_ids = tuple(item.behavior_id for item in self.behaviors)
        if len(behavior_ids) != len(set(behavior_ids)):
            raise ValueError("behavior IDs must be unique")
        calculated_unresolved = tuple(
            sorted(item.behavior_id for item in self.behaviors if item.blocking)
        )
        if self.unresolved_behavior_ids != calculated_unresolved:
            raise ValueError("behavior unresolved denominator is inconsistent")
        if self.closed_denominator != (not calculated_unresolved):
            raise ValueError("behavior denominator status is inconsistent")
        return self


class SigmaBehaviorManifestArtifact(ArtifactFields):
    schema_version: Literal["sigma-behavior-manifest.v1"]
    payload: BehaviorManifestPayload


class GateRecommendation(_FrozenModel):
    gate_id: str
    state: Literal["blocked", "requires_human_approval"]
    reason: str
    evidence_refs: tuple[str, ...]


class SpikeMetrics(_FrozenModel):
    api_calls: int = Field(ge=0)
    retry_responses: int = Field(ge=0)
    response_bytes_hashed: int = Field(ge=0)
    request_budget: int = Field(ge=1)
    per_endpoint_request_budget: int = Field(ge=1)
    request_budget_exhausted: bool
    row_data_retained: Literal[False] = False
    model_tokens_used: Literal[0] = 0


class SigmaCapabilitySpikeBundle(_FrozenModel):
    schema_version: Literal["sigma-capability-spike-bundle.v1"]
    run_id: str
    scope_id: str
    status: Literal["ready_for_human_review", "blocked"]
    run_manifest: SigmaRunManifestArtifact
    observations: tuple[SigmaObservationArtifact, ...]
    capability_matrix: SigmaCapabilityMatrixArtifact
    workbook_graph: SigmaWorkbookGraphArtifact
    data_model_snapshot: SigmaDataModelSnapshotArtifact
    behavior_manifest: SigmaBehaviorManifestArtifact
    gate_recommendations: tuple[GateRecommendation, ...]
    blockers: tuple[str, ...]
    metrics: SpikeMetrics

    @model_validator(mode="after")
    def bundle_is_closed_and_content_addressed(self) -> "SigmaCapabilitySpikeBundle":
        artifacts: tuple[ArtifactFields, ...] = (
            self.run_manifest,
            *self.observations,
            self.capability_matrix,
            self.workbook_graph,
            self.data_model_snapshot,
            self.behavior_manifest,
        )
        if any(
            artifact.run_id != self.run_id or artifact.scope_id != self.scope_id
            for artifact in artifacts
        ):
            raise ValueError("every artifact must bind the bundle run and scope")

        by_id = {artifact.artifact_id: artifact for artifact in artifacts}
        if len(by_id) != len(artifacts):
            raise ValueError("bundle artifact IDs must be unique")
        expected_upstreams: dict[str, tuple[ArtifactFields, ...]] = {
            self.run_manifest.artifact_id: (),
            **{observation.artifact_id: (self.run_manifest,) for observation in self.observations},
            self.capability_matrix.artifact_id: (self.run_manifest, *self.observations),
            self.workbook_graph.artifact_id: (self.run_manifest, *self.observations),
            self.data_model_snapshot.artifact_id: (self.run_manifest, *self.observations),
            self.behavior_manifest.artifact_id: (
                self.run_manifest,
                self.capability_matrix,
                self.workbook_graph,
            ),
        }
        for artifact in artifacts:
            material = artifact.model_dump(mode="json")
            declared_hash = material.pop("content_hash")
            if declared_hash != sha256_json(material):
                raise ValueError(f"artifact content hash mismatch: {artifact.artifact_id}")
            for upstream in artifact.upstream_hashes:
                resolved = by_id.get(upstream.artifact_id)
                if resolved is None or resolved.content_hash != upstream.content_hash:
                    raise ValueError(f"artifact upstream binding mismatch: {artifact.artifact_id}")
                if resolved.created_at >= artifact.created_at:
                    raise ValueError(f"artifact temporal ordering mismatch: {artifact.artifact_id}")
            declared_upstreams = tuple(
                (item.artifact_id, item.content_hash) for item in artifact.upstream_hashes
            )
            required_upstreams = tuple(
                (item.artifact_id, item.content_hash)
                for item in expected_upstreams[artifact.artifact_id]
            )
            if declared_upstreams != required_upstreams:
                raise ValueError(f"artifact upstream closure mismatch: {artifact.artifact_id}")

        manifest = self.run_manifest.payload
        if (
            self.data_model_snapshot.payload.specification_state != "bound"
            and self.status != "blocked"
        ):
            raise ValueError("unavailable model specification must block the bundle")
        if (
            any(
                value != manifest.workbook_id
                for value in (
                    self.capability_matrix.payload.workbook_id,
                    self.workbook_graph.payload.workbook_id,
                    self.behavior_manifest.payload.workbook_id,
                )
            )
            or self.data_model_snapshot.payload.data_model_id != manifest.data_model_id
        ):
            raise ValueError("bundle artifacts do not bind the manifest source objects")
        if (
            self.workbook_graph.payload.source_freeze != manifest.source_freeze
            or self.data_model_snapshot.payload.source_freeze != manifest.source_freeze
        ):
            raise ValueError("bundle artifacts do not bind the manifest source freeze")
        expected_classification = (
            "observed_tenant_behavior"
            if manifest.evidence_mode == "live_tenant"
            else "synthetic_fixture"
        )
        observed_artifacts = (
            *self.observations,
            self.capability_matrix,
            self.workbook_graph,
            self.data_model_snapshot,
        )
        if any(item.classification != expected_classification for item in observed_artifacts):
            raise ValueError("bundle evidence classification contradicts the run manifest")
        if any(
            (
                observation.payload.organization_ref != manifest.organization_ref
                or observation.payload.principal_ref != manifest.principal_ref
                or observation.payload.effective_account_type != manifest.effective_account_type
                or observation.payload.authorization_ref != manifest.authorization_ref
            )
            for observation in self.observations
        ):
            raise ValueError("bundle observations contradict the run identity")
        if self.capability_matrix.payload.live_tenant_evidence != (
            manifest.evidence_mode == "live_tenant"
        ):
            raise ValueError("capability evidence mode contradicts the run manifest")
        if (
            self.metrics.request_budget != manifest.request_budget
            or self.metrics.per_endpoint_request_budget != manifest.per_endpoint_request_budget
            or self.metrics.api_calls > manifest.request_budget
        ):
            raise ValueError("bundle metrics contradict the approved request budgets")

        matrix = self.capability_matrix.payload
        observation_refs = {
            f"artifact-ref://{observation.artifact_id}" for observation in self.observations
        }
        if any(
            any(reference not in observation_refs for reference in item.evidence_refs)
            for item in matrix.assessments
        ):
            raise ValueError("capability evidence references must resolve to observations")
        if any(
            any(reference not in observation_refs for reference in item.evidence_refs)
            for item in self.behavior_manifest.payload.behaviors
        ):
            raise ValueError("behavior evidence references must resolve to observations")
        capability_ids = tuple(item.capability_id for item in matrix.assessments)
        if len(capability_ids) != len(set(capability_ids)) or set(capability_ids) != set(
            _PHASE0_CAPABILITY_IDS
        ):
            raise ValueError("capability matrix denominator is incomplete or duplicated")
        calculated_blocking = tuple(
            sorted(item.capability_id for item in matrix.assessments if item.blocks_full_adapter)
        )
        if matrix.blocking_capability_ids != calculated_blocking:
            raise ValueError("capability matrix blocking denominator is inconsistent")
        calculated_manual = tuple(
            sorted(
                item.capability_id
                for item in matrix.assessments
                if item.status in {"manual_required", "verified_partial"}
                and item.fallback is not None
            )
        )
        if matrix.manual_fallback_capability_ids != calculated_manual:
            raise ValueError("capability matrix fallback denominator is inconsistent")
        expected_matrix_status = "blocked" if calculated_blocking else "ready_for_human_review"
        if matrix.matrix_status != expected_matrix_status:
            raise ValueError("capability matrix status is inconsistent")
        if self.behavior_manifest.payload.closed_denominator != (
            not self.behavior_manifest.payload.unresolved_behavior_ids
        ):
            raise ValueError("behavior denominator status is inconsistent")

        expected_status = (
            "ready_for_human_review"
            if not self.blockers and matrix.matrix_status == "ready_for_human_review"
            else "blocked"
        )
        if self.status != expected_status:
            raise ValueError("bundle status contradicts its blockers or capability matrix")

        gates = {item.gate_id: item for item in self.gate_recommendations}
        if len(gates) != len(self.gate_recommendations):
            raise ValueError("gate recommendations must use unique gate IDs")
        required_blocked = {
            "source_inventory_complete",
            "artifact_registry_registered",
            "semantic_migration_strategy_selected",
            "semantic_target_design_approved",
            "target_write_authorized",
            "release_authorized",
            "decommission_authorized",
        }
        if any(
            gates.get(gate_id) is None or gates[gate_id].state != "blocked"
            for gate_id in required_blocked
        ):
            raise ValueError("Phase-0 downstream gates must remain blocked")
        capability_gate = gates.get("sigma_api_capability_verified")
        expected_capability_state = (
            "requires_human_approval" if self.status == "ready_for_human_review" else "blocked"
        )
        if capability_gate is None or capability_gate.state != expected_capability_state:
            raise ValueError("Sigma capability gate contradicts the bundle status")
        artifact_refs = {f"artifact-ref://{artifact_id}" for artifact_id in by_id}
        if any(
            not gate.evidence_refs
            or any(reference not in artifact_refs for reference in gate.evidence_refs)
            for gate in self.gate_recommendations
        ):
            raise ValueError("gate evidence references must resolve inside the bundle")
        return self

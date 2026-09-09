"""Typed, immutable records for read-only dbt repository inventory.

The repository inventory is deliberately separate from the migration Bridge IR.  It
captures evidence about an existing dbt project; it does not execute project code or
assert that any resource is a valid target for reuse.
"""

from __future__ import annotations

from collections import Counter
from typing import Any, Literal, Mapping

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from omni_migrator.control_plane.canonical import parse_time, sha256_json, validate_reference


SUPPORTED_ARTIFACT_SCHEMA_VERSIONS: dict[str, frozenset[str]] = {
    "manifest": frozenset(
        {
            "https://schemas.getdbt.com/dbt/manifest/v12.json",
        }
    ),
    "catalog": frozenset({"https://schemas.getdbt.com/dbt/catalog/v1.json"}),
    "run_results": frozenset(
        {
            "https://schemas.getdbt.com/dbt/run-results/v6.json",
        }
    ),
    # dbt documents semantic_manifest.json as an internal integration artifact and
    # does not publish it on schemas.getdbt.com.  Callers therefore must explicitly
    # declare the one parser profile supported here; it is never inferred from shape.
    "semantic_manifest": frozenset({"dbt-semantic-manifest/v1"}),
}

ArtifactType = Literal["manifest", "catalog", "run_results", "semantic_manifest"]
DiagnosticSeverity = Literal["info", "warning", "blocking"]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


def _validate_relative_path(value: str) -> str:
    if not value or value.startswith(("/", "\\")) or "\\" in value:
        raise ValueError("repository paths must be non-empty relative POSIX paths")
    parts = value.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise ValueError("repository paths cannot contain empty, dot, or parent segments")
    return value


def _validate_timestamp(value: str | None) -> str | None:
    if value is not None:
        parse_time(value)
    return value


class RepositoryIdentity(StrictModel):
    repository_ref: str
    git_ref: str = Field(min_length=1, max_length=512)
    commit_sha: str = Field(pattern=r"^(?:[a-f0-9]{40}|[a-f0-9]{64})$")
    identity_evidence_ref: str
    project_name: str = Field(min_length=1, max_length=256)
    project_id: str | None = Field(default=None, min_length=1, max_length=256)
    dbt_version: str = Field(min_length=1, max_length=128)
    worktree_state: Literal["clean"] = "clean"

    @field_validator("repository_ref", "identity_evidence_ref")
    @classmethod
    def non_secret_reference(cls, value: str) -> str:
        validate_reference(value)
        return value

    @field_validator("git_ref")
    @classmethod
    def safe_git_ref(cls, value: str) -> str:
        if value.strip() != value or any(character.isspace() for character in value):
            raise ValueError("git ref cannot contain whitespace")
        if value.startswith("-") or ".." in value or value.endswith((".", "/")):
            raise ValueError("git ref is not a safe pinned reference")
        return value


class ArtifactFileRecord(StrictModel):
    artifact_type: ArtifactType
    relative_path: str
    schema_version: str
    content_hash: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    byte_count: int = Field(ge=1)
    generated_at: str | None = None
    invocation_id: str | None = Field(default=None, min_length=1, max_length=512)

    @field_validator("relative_path")
    @classmethod
    def relative_path_is_safe(cls, value: str) -> str:
        return _validate_relative_path(value)

    @field_validator("generated_at")
    @classmethod
    def generated_at_is_timezone_aware(cls, value: str | None) -> str | None:
        return _validate_timestamp(value)

    @model_validator(mode="after")
    def supported_schema_version(self) -> "ArtifactFileRecord":
        if self.schema_version not in SUPPORTED_ARTIFACT_SCHEMA_VERSIONS[self.artifact_type]:
            raise ValueError(
                f"unsupported {self.artifact_type} schema version: {self.schema_version}"
            )
        return self


class SourceFileRecord(StrictModel):
    relative_path: str
    file_kind: Literal[
        "project_config",
        "sql",
        "yaml",
        "macro",
        "test",
        "exposure",
        "seed",
        "python",
        "markdown",
        "other",
    ]
    content_hash: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    byte_count: int = Field(ge=0)
    referenced_by_unique_ids: list[str] = Field(default_factory=list)

    @field_validator("relative_path")
    @classmethod
    def relative_path_is_safe(cls, value: str) -> str:
        return _validate_relative_path(value)

    @model_validator(mode="after")
    def references_are_ordered(self) -> "SourceFileRecord":
        if self.referenced_by_unique_ids != sorted(set(self.referenced_by_unique_ids)):
            raise ValueError("source-file resource references must be sorted and unique")
        return self


class ColumnRecord(StrictModel):
    name: str = Field(min_length=1, max_length=512)
    data_type: str | None = Field(default=None, min_length=1, max_length=512)
    description: str | None = Field(default=None, max_length=8192)
    ordinal: int | None = Field(default=None, ge=0)


class ResourceRecord(StrictModel):
    unique_id: str = Field(min_length=1, max_length=1024)
    resource_type: str = Field(min_length=1, max_length=128)
    package_name: str = Field(min_length=1, max_length=256)
    name: str = Field(min_length=1, max_length=512)
    original_file_path: str | None = None
    source_file_hash: str | None = Field(default=None, pattern=r"^sha256:[a-f0-9]{64}$")
    definition_hash: str | None = Field(default=None, pattern=r"^sha256:[a-f0-9]{64}$")
    compiled_code_hash: str | None = Field(default=None, pattern=r"^sha256:[a-f0-9]{64}$")
    database: str | None = Field(default=None, max_length=512)
    schema_name: str | None = Field(default=None, max_length=512)
    alias: str | None = Field(default=None, max_length=512)
    relation_name: str | None = Field(default=None, max_length=2048)
    compiled_relation_name: str | None = Field(default=None, max_length=2048)
    materialization: str | None = Field(default=None, max_length=128)
    enabled: bool = True
    owner: str | None = Field(default=None, max_length=1024)
    domain: str | None = Field(default=None, max_length=512)
    group: str | None = Field(default=None, max_length=512)
    tags: list[str] = Field(default_factory=list)
    depends_on_unique_ids: list[str] = Field(default_factory=list)
    test_unique_ids: list[str] = Field(default_factory=list)
    exposure_unique_ids: list[str] = Field(default_factory=list)
    columns: list[ColumnRecord] = Field(default_factory=list)
    run_status: str | None = Field(default=None, max_length=128)
    execution_time_seconds: float | None = Field(default=None, ge=0)
    resource_hash: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")

    @field_validator("original_file_path")
    @classmethod
    def original_path_is_safe(cls, value: str | None) -> str | None:
        return _validate_relative_path(value) if value is not None else None

    @model_validator(mode="after")
    def collections_are_canonical(self) -> "ResourceRecord":
        for label, values in (
            ("tags", self.tags),
            ("dependencies", self.depends_on_unique_ids),
            ("tests", self.test_unique_ids),
            ("exposures", self.exposure_unique_ids),
        ):
            if values != sorted(set(values)):
                raise ValueError(f"resource {label} must be sorted and unique")
        if [column.name for column in self.columns] != sorted(
            {column.name for column in self.columns}
        ):
            raise ValueError("resource columns must be sorted and unique by name")
        if self.resource_hash != resource_record_hash(self.model_dump(mode="json")):
            raise ValueError("resource hash is not canonical")
        return self


class LineageEdgeRecord(StrictModel):
    edge_id: str = Field(pattern=r"^edge\.[a-f0-9]{20}$")
    from_unique_id: str = Field(min_length=1, max_length=1024)
    to_unique_id: str = Field(min_length=1, max_length=1024)
    relationship: Literal["depends_on"] = "depends_on"
    edge_hash: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")

    @model_validator(mode="after")
    def identity_is_canonical(self) -> "LineageEdgeRecord":
        material = {
            "from_unique_id": self.from_unique_id,
            "to_unique_id": self.to_unique_id,
            "relationship": self.relationship,
        }
        if self.edge_id != f"edge.{sha256_json(material)[:20]}":
            raise ValueError("lineage edge ID is not canonical")
        if self.edge_hash != f"sha256:{sha256_json(material)}":
            raise ValueError("lineage edge hash is not canonical")
        return self


class TestRecord(StrictModel):
    unique_id: str = Field(min_length=1, max_length=1024)
    name: str = Field(min_length=1, max_length=512)
    test_type: str = Field(min_length=1, max_length=256)
    target_unique_ids: list[str] = Field(min_length=1)
    column_name: str | None = Field(default=None, max_length=512)
    severity: str | None = Field(default=None, max_length=128)
    status: str | None = Field(default=None, max_length=128)
    original_file_path: str | None = None
    source_file_hash: str | None = Field(default=None, pattern=r"^sha256:[a-f0-9]{64}$")
    definition_hash: str | None = Field(default=None, pattern=r"^sha256:[a-f0-9]{64}$")

    @field_validator("original_file_path")
    @classmethod
    def original_path_is_safe(cls, value: str | None) -> str | None:
        return _validate_relative_path(value) if value is not None else None

    @model_validator(mode="after")
    def targets_are_canonical(self) -> "TestRecord":
        if self.target_unique_ids != sorted(set(self.target_unique_ids)):
            raise ValueError("test targets must be sorted and unique")
        return self


class ConstraintRecord(StrictModel):
    constraint_id: str = Field(pattern=r"^constraint\.[a-f0-9]{20}$")
    resource_unique_id: str = Field(min_length=1, max_length=1024)
    column_name: str | None = Field(default=None, max_length=512)
    constraint_type: str = Field(min_length=1, max_length=128)
    name: str | None = Field(default=None, max_length=512)
    columns: list[str] = Field(default_factory=list)
    expression_hash: str | None = Field(default=None, pattern=r"^sha256:[a-f0-9]{64}$")
    warn_unenforced: bool | None = None
    warn_unsupported: bool | None = None

    @model_validator(mode="after")
    def columns_are_canonical(self) -> "ConstraintRecord":
        if self.columns != sorted(set(self.columns)):
            raise ValueError("constraint columns must be sorted and unique")
        material = self.model_dump(mode="json")
        material.pop("constraint_id")
        if self.constraint_id != f"constraint.{sha256_json(material)[:20]}":
            raise ValueError("constraint ID is not canonical")
        return self


class ExposureRecord(StrictModel):
    unique_id: str = Field(min_length=1, max_length=1024)
    name: str = Field(min_length=1, max_length=512)
    exposure_type: str = Field(min_length=1, max_length=128)
    maturity: str | None = Field(default=None, max_length=128)
    owner_name: str | None = Field(default=None, max_length=1024)
    owner_email_hash: str | None = Field(default=None, pattern=r"^sha256:[a-f0-9]{64}$")
    url: str | None = Field(default=None, max_length=2048)
    depends_on_unique_ids: list[str] = Field(default_factory=list)
    original_file_path: str | None = None
    source_file_hash: str | None = Field(default=None, pattern=r"^sha256:[a-f0-9]{64}$")

    @field_validator("original_file_path")
    @classmethod
    def original_path_is_safe(cls, value: str | None) -> str | None:
        return _validate_relative_path(value) if value is not None else None

    @model_validator(mode="after")
    def dependencies_are_canonical(self) -> "ExposureRecord":
        if self.depends_on_unique_ids != sorted(set(self.depends_on_unique_ids)):
            raise ValueError("exposure dependencies must be sorted and unique")
        return self


class SemanticAssetRecord(StrictModel):
    asset_id: str = Field(pattern=r"^semantic\.[a-z_]+\.[a-f0-9]{20}$")
    asset_type: Literal["semantic_model", "metric", "saved_query"]
    name: str = Field(min_length=1, max_length=512)
    description: str | None = Field(default=None, max_length=8192)
    owner: str | None = Field(default=None, max_length=1024)
    domain: str | None = Field(default=None, max_length=512)
    relation_name: str | None = Field(default=None, max_length=2048)
    related_resource_unique_ids: list[str] = Field(default_factory=list)
    depends_on_asset_ids: list[str] = Field(default_factory=list)
    definition_hash: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")

    @model_validator(mode="after")
    def references_are_canonical(self) -> "SemanticAssetRecord":
        for label, values in (
            ("resource references", self.related_resource_unique_ids),
            ("semantic dependencies", self.depends_on_asset_ids),
        ):
            if values != sorted(set(values)):
                raise ValueError(f"semantic asset {label} must be sorted and unique")
        identity = {"type": self.asset_type, "name": self.name}
        if self.asset_id != f"semantic.{self.asset_type}.{sha256_json(identity)[:20]}":
            raise ValueError("semantic asset ID is not canonical")
        return self


class DiagnosticRecord(StrictModel):
    code: str = Field(pattern=r"^[a-z][a-z0-9_]{2,127}$")
    severity: DiagnosticSeverity
    message: str = Field(min_length=1, max_length=2048)
    subject_refs: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def subjects_are_canonical(self) -> "DiagnosticRecord":
        if self.subject_refs != sorted(set(self.subject_refs)):
            raise ValueError("diagnostic subject references must be sorted and unique")
        return self


class InventorySummary(StrictModel):
    artifact_count: int = Field(ge=1)
    source_file_count: int = Field(ge=0)
    resource_count: int = Field(ge=0)
    model_count: int = Field(ge=0)
    source_count: int = Field(ge=0)
    test_count: int = Field(ge=0)
    constraint_count: int = Field(ge=0)
    exposure_count: int = Field(ge=0)
    semantic_asset_count: int = Field(ge=0)
    diagnostic_count: int = Field(ge=0)


class InventoryProvenance(StrictModel):
    acquisition_method: Literal["read_only_dbt_artifacts"] = "read_only_dbt_artifacts"
    parser_version: Literal["dbt-repository-inventory-v1"] = "dbt-repository-inventory-v1"
    executed_repository_code: Literal[False] = False
    acquired_at: str
    source_artifact_refs: list[str] = Field(min_length=1)

    @field_validator("acquired_at")
    @classmethod
    def acquired_at_is_timezone_aware(cls, value: str) -> str:
        parse_time(value)
        return value

    @model_validator(mode="after")
    def artifact_refs_are_canonical(self) -> "InventoryProvenance":
        if self.source_artifact_refs != sorted(set(self.source_artifact_refs)):
            raise ValueError("source artifact references must be sorted and unique")
        return self


class SecurityMetadata(StrictModel):
    classification: Literal["public", "internal", "confidential", "restricted"]
    contains_sensitive_data: bool
    data_categories: list[
        Literal[
            "none",
            "pii",
            "phi",
            "pci",
            "financial",
            "credentials",
            "customer_confidential",
            "regulated_other",
        ]
    ] = Field(min_length=1)
    redaction_state: Literal[
        "not_required", "redacted", "tokenized", "restricted_reference_only", "pending"
    ]
    tenant_partition_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{7,127}$")
    access_policy_ref: str
    retention_policy_ref: str
    egress_policy_ref: str | None = None

    @field_validator("access_policy_ref", "retention_policy_ref", "egress_policy_ref")
    @classmethod
    def policy_references_are_non_secret(cls, value: str | None) -> str | None:
        if value is not None:
            validate_reference(value)
        return value

    @model_validator(mode="after")
    def sensitivity_is_consistent(self) -> "SecurityMetadata":
        if len(self.data_categories) != len(set(self.data_categories)):
            raise ValueError("security data categories must be unique")
        if self.data_categories != sorted(self.data_categories):
            raise ValueError("security data categories must be sorted")
        if not self.contains_sensitive_data and self.data_categories != ["none"]:
            raise ValueError("non-sensitive inventory must use only the none data category")
        if self.contains_sensitive_data and "none" in self.data_categories:
            raise ValueError("sensitive inventory cannot use the none data category")
        return self


def repository_inventory_hash(value: Mapping[str, Any]) -> str:
    material = dict(value)
    material.pop("inventory_hash", None)
    return f"sha256:{sha256_json(material)}"


def resource_record_hash(value: Mapping[str, Any]) -> str:
    material = dict(value)
    material.pop("resource_hash", None)
    return f"sha256:{sha256_json(material)}"


class RepositoryInventory(StrictModel):
    contract_version: Literal["domo-to-omni.repository-inventory.v1"] = (
        "domo-to-omni.repository-inventory.v1"
    )
    inventory_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{7,127}$")
    run_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{7,127}$")
    repository: RepositoryIdentity
    status: Literal["complete", "partial"]
    artifact_files: list[ArtifactFileRecord] = Field(min_length=1)
    source_files: list[SourceFileRecord] = Field(default_factory=list)
    resources: list[ResourceRecord] = Field(default_factory=list)
    lineage_edges: list[LineageEdgeRecord] = Field(default_factory=list)
    tests: list[TestRecord] = Field(default_factory=list)
    constraints: list[ConstraintRecord] = Field(default_factory=list)
    exposures: list[ExposureRecord] = Field(default_factory=list)
    semantic_assets: list[SemanticAssetRecord] = Field(default_factory=list)
    diagnostics: list[DiagnosticRecord] = Field(default_factory=list)
    summary: InventorySummary
    inventory_hash: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    provenance: InventoryProvenance
    security: SecurityMetadata
    immutable: Literal[True] = True

    @model_validator(mode="after")
    def integrity_is_canonical(self) -> "RepositoryInventory":
        artifacts = [item.artifact_type for item in self.artifact_files]
        if len(artifacts) != len(set(artifacts)):
            raise ValueError("repository inventory artifact types must be unique")
        if "manifest" not in artifacts:
            raise ValueError("a manifest artifact is required")

        ordered_collections = (
            ("artifact files", self.artifact_files, lambda item: item.artifact_type),
            ("source files", self.source_files, lambda item: item.relative_path),
            ("resources", self.resources, lambda item: item.unique_id),
            ("lineage edges", self.lineage_edges, lambda item: item.edge_id),
            ("tests", self.tests, lambda item: item.unique_id),
            ("constraints", self.constraints, lambda item: item.constraint_id),
            ("exposures", self.exposures, lambda item: item.unique_id),
            ("semantic assets", self.semantic_assets, lambda item: item.asset_id),
            (
                "diagnostics",
                self.diagnostics,
                lambda item: (item.severity, item.code, tuple(item.subject_refs), item.message),
            ),
        )
        for label, values, key in ordered_collections:
            keys = [key(item) for item in values]
            if keys != sorted(keys) or len(keys) != len(set(keys)):
                raise ValueError(f"{label} must be sorted with unique identities")

        resource_ids = {item.unique_id for item in self.resources}
        exposure_ids = {item.unique_id for item in self.exposures}
        known_lineage_ids = resource_ids | exposure_ids
        for edge in self.lineage_edges:
            if (
                edge.from_unique_id not in known_lineage_ids
                or edge.to_unique_id not in known_lineage_ids
            ):
                raise ValueError("lineage edge references an unknown resource or exposure")
        for item in self.tests:
            if not set(item.target_unique_ids) <= resource_ids:
                raise ValueError("test references an unknown resource")
        for item in self.constraints:
            if item.resource_unique_id not in resource_ids:
                raise ValueError("constraint references an unknown resource")
        for item in self.exposures:
            if not set(item.depends_on_unique_ids) <= resource_ids:
                raise ValueError("exposure references an unknown resource")

        expected_summary = {
            "artifact_count": len(self.artifact_files),
            "source_file_count": len(self.source_files),
            "resource_count": len(self.resources),
            "model_count": sum(item.resource_type == "model" for item in self.resources),
            "source_count": sum(item.resource_type == "source" for item in self.resources),
            "test_count": len(self.tests),
            "constraint_count": len(self.constraints),
            "exposure_count": len(self.exposures),
            "semantic_asset_count": len(self.semantic_assets),
            "diagnostic_count": len(self.diagnostics),
        }
        if self.summary.model_dump(mode="json") != expected_summary:
            raise ValueError("repository inventory summary does not match its records")
        has_gap = any(item.severity in {"warning", "blocking"} for item in self.diagnostics)
        if self.status != ("partial" if has_gap else "complete"):
            raise ValueError("repository inventory status does not match diagnostics")
        if self.inventory_hash != repository_inventory_hash(self.model_dump(mode="json")):
            raise ValueError("repository inventory hash is not canonical")
        return self


def duplicate_values(values: list[str]) -> list[str]:
    """Return sorted duplicate values for sanitized parser errors."""

    counts = Counter(values)
    return sorted(value for value, count in counts.items() if count > 1)

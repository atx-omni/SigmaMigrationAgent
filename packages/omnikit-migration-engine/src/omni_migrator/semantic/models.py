"""Typed semantic-profile records shared by source and target specialists."""

from __future__ import annotations

import hashlib
from copy import deepcopy
from typing import Any, Literal, Mapping

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from omni_migrator.control_plane.canonical import sha256_json

Sha256 = str
KnowledgeState = Literal["known", "unknown", "conflict", "not_applicable"]
ProfileKind = Literal[
    "dataset_output",
    "transformation",
    "calculation",
    "dashboard_query",
    "security_policy",
    "source_object",
    "workflow_output",
    "dbt_resource",
    "omni_candidate",
]
DomoProfileKind = Literal[
    "dataset_output",
    "transformation",
    "calculation",
    "dashboard_query",
    "security_policy",
    "workflow_output",
]


def semantic_profile_requirement_hash(
    value: Mapping[str, Any] | "SemanticProfileRequirement",
) -> str:
    """Hash the immutable evidence requirement without its self-hash."""

    if isinstance(value, SemanticProfileRequirement):
        material = value.model_dump(mode="json")
    else:
        material = deepcopy(dict(value))
    material.pop("requirement_hash", None)
    return f"sha256:{sha256_json(material)}"


def repository_definition_evidence_hash(
    value: Mapping[str, Any] | "RepositoryDefinitionEvidence",
) -> str:
    """Hash pinned repository definition evidence without its self-hash."""

    if isinstance(value, RepositoryDefinitionEvidence):
        material = value.model_dump(mode="json")
    else:
        material = deepcopy(dict(value))
    material.pop("evidence_hash", None)
    return f"sha256:{sha256_json(material)}"


def repository_definition_content_hash(value: Any) -> str:
    """Use the same raw-text/structured hashes as repository inventory."""

    if isinstance(value, str):
        return f"sha256:{hashlib.sha256(value.encode('utf-8')).hexdigest()}"
    return f"sha256:{sha256_json(value)}"


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class SemanticProfileRequirement(StrictModel):
    """One exact, evidence-derived Domo semantic-profile denominator member."""

    requirement_id: str = Field(min_length=1)
    profile_kind: DomoProfileKind
    base_object_id: str = Field(min_length=1)
    context_id: str = Field(min_length=1)
    context_ref: str = Field(min_length=1)
    context_hash: Sha256 = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    definition_ref: str = Field(min_length=1)
    definition_hash: Sha256 = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    source_revision_hash: Sha256 = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    consumer_object_id: str | None = None
    evidence_refs: list[str] = Field(min_length=1)
    requirement_hash: Sha256 = Field(pattern=r"^sha256:[a-f0-9]{64}$")

    @model_validator(mode="after")
    def requirement_is_self_consistent(self) -> "SemanticProfileRequirement":
        if len(self.evidence_refs) != len(set(self.evidence_refs)):
            raise ValueError("semantic profile requirement evidence_refs must be unique")
        if self.context_id == "base" and self.consumer_object_id is not None:
            raise ValueError("base semantic profile requirements cannot name a consumer")
        if self.requirement_hash != semantic_profile_requirement_hash(self):
            raise ValueError("requirement_hash does not match semantic profile requirement")
        return self


class RepositoryDefinitionEvidence(StrictModel):
    """Exact source/compiled definition evidence for one pinned dbt subject."""

    subject_id: str = Field(min_length=1)
    repository_ref: str = Field(min_length=1)
    commit_sha: str = Field(pattern=r"^(?:[a-f0-9]{40}|[a-f0-9]{64})$")
    inventory_hash: Sha256 = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    relative_path: str | None = None
    source_file_hash: Sha256 | None = Field(
        default=None, pattern=r"^sha256:[a-f0-9]{64}$"
    )
    definition_ref: str = Field(min_length=1)
    definition_kind: Literal["raw", "compiled", "semantic_asset"]
    definition: str | dict[str, Any] | list[Any] | None = None
    definition_hash: Sha256 | None = Field(
        default=None, pattern=r"^sha256:[a-f0-9]{64}$"
    )
    language: Literal["sql", "query", "workflow", "unknown"]
    dialect: str | None = None
    semantic_dimensions: dict[str, Any] = Field(default_factory=dict)
    evidence_refs: list[str] = Field(min_length=1)
    evidence_hash: Sha256 = Field(pattern=r"^sha256:[a-f0-9]{64}$")

    @field_validator("relative_path")
    @classmethod
    def repository_path_is_relative(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if (
            not value
            or value.startswith(("/", "\\"))
            or "\\" in value
            or any(part in {"", ".", ".."} for part in value.split("/"))
        ):
            raise ValueError("repository definition paths must be relative POSIX paths")
        return value

    @model_validator(mode="after")
    def evidence_is_self_consistent(self) -> "RepositoryDefinitionEvidence":
        if self.evidence_refs != sorted(set(self.evidence_refs)):
            raise ValueError("repository definition evidence_refs must be sorted and unique")
        if self.definition is not None:
            if self.definition_hash is None:
                raise ValueError("captured repository definitions require a definition_hash")
            if self.definition_hash != repository_definition_content_hash(self.definition):
                raise ValueError("definition_hash does not match repository definition evidence")
        if self.evidence_hash != repository_definition_evidence_hash(self):
            raise ValueError("evidence_hash does not match repository definition evidence")
        return self


class AssetIdentity(StrictModel):
    system: Literal["domo", "dbt", "snowflake", "omni"]
    kind: ProfileKind
    object_id: str = Field(min_length=1)
    revision_hash: Sha256 = Field(pattern=r"^sha256:[a-f0-9]{64}$")


class DefinitionProfile(StrictModel):
    state: Literal["complete", "partial", "unknown"]
    language: Literal[
        "sql",
        "beast_mode",
        "query",
        "magic_etl",
        "workflow",
        "omni_yaml",
        "unknown",
    ]
    dialect: str | None = None
    runtime: str | None = None
    original_definition: str | dict[str, Any] | list[Any] | None = None
    original_ref: str
    original_hash: Sha256 = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    canonicalizer_version: str
    canonical_state: Literal["supported", "unknown"]
    canonical_form: str | None = None
    canonical_hash: Sha256 | None = Field(default=None, pattern=r"^sha256:[a-f0-9]{64}$")
    translation_refs: list[str] = Field(default_factory=list)
    unsupported_reason: str | None = None

    @model_validator(mode="after")
    def canonical_pair(self) -> "DefinitionProfile":
        if self.canonical_state == "supported":
            if self.canonical_form is None or self.canonical_hash is None:
                raise ValueError("supported canonical definitions require form and hash")
            if self.unsupported_reason is not None:
                raise ValueError("supported canonical definitions cannot carry an unsupported reason")
        else:
            if self.canonical_form is not None or self.canonical_hash is not None:
                raise ValueError("unknown canonical definitions cannot carry a form or hash")
            if not self.unsupported_reason:
                raise ValueError("unknown canonical definitions require a reason")
        return self


class GrainProfile(StrictModel):
    state: KnowledgeState
    description: str | None = None
    key_fields: list[str] = Field(default_factory=list)
    row_universe: str | None = None
    uniqueness_evidence_refs: list[str] = Field(default_factory=list)


class LineageProfile(StrictModel):
    state: KnowledgeState
    authoritative_source_ids: list[str] = Field(default_factory=list)
    upstream_asset_ids: list[str] = Field(default_factory=list)
    relational_operations: list[str] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)


class AggregationProfile(StrictModel):
    state: KnowledgeState
    stage: Literal[
        "row",
        "pre_aggregate",
        "aggregate",
        "post_aggregate",
        "window",
        "fixed_lod",
        "unknown",
        "not_applicable",
    ]
    grouping_fields: list[str] = Field(default_factory=list)
    distinct_mode: Literal["none", "distinct_rows", "distinct_values", "unknown"] = "unknown"
    partition_fields: list[str] = Field(default_factory=list)
    order_fields: list[str] = Field(default_factory=list)
    window_frame: str | None = None
    null_semantics: str | None = None


class FilterProfile(StrictModel):
    state: KnowledgeState
    stage: Literal[
        "source",
        "row",
        "pre_aggregate",
        "post_aggregate",
        "dashboard",
        "mixed",
        "unknown",
        "not_applicable",
    ]
    scope: Literal[
        "global",
        "dataset",
        "card",
        "query",
        "tile",
        "topic",
        "unknown",
        "not_applicable",
    ]
    precedence: list[str] = Field(default_factory=list)
    predicates: list[str] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)


class JoinProfile(StrictModel):
    left_asset_id: str
    right_asset_id: str
    predicates: list[str] = Field(min_length=1)
    declared_cardinality: Literal[
        "one_to_one", "one_to_many", "many_to_one", "many_to_many", "unknown"
    ]
    observed_cardinality: Literal[
        "one_to_one", "one_to_many", "many_to_one", "many_to_many", "unknown"
    ]
    fanout_state: Literal["passed", "failed", "unknown", "not_applicable"]
    evidence_refs: list[str] = Field(default_factory=list)


class TimeProfile(StrictModel):
    state: KnowledgeState
    timezone: str | None = None
    fiscal_calendar_ref: str | None = None
    date_boundary_semantics: str | None = None
    late_arriving_behavior: str | None = None


class SecurityProfile(StrictModel):
    state: KnowledgeState
    security_domain: str | None = None
    pdp_policy_refs: list[str] = Field(default_factory=list)
    masking_policy_refs: list[str] = Field(default_factory=list)
    principal_precedence: list[str] = Field(default_factory=list)
    derived_field_exposure: Literal["safe", "leakage_risk", "unknown", "not_applicable"]
    evidence_refs: list[str] = Field(default_factory=list)


class OperationsProfile(StrictModel):
    state: KnowledgeState
    update_mode: Literal["replace", "append", "upsert", "snapshot", "view", "unknown"]
    watermark_field: str | None = None
    freshness_sla: str | None = None
    history_behavior: str | None = None
    backfill_behavior: str | None = None
    owner_refs: list[str] = Field(default_factory=list)
    sla_ref: str | None = None


class SideEffectProfile(StrictModel):
    kind: str
    description: str
    handoff_ref: str | None = None


class SemanticProfile(StrictModel):
    contract_version: Literal["domo-to-omni.semantic-profile.v1"] = (
        "domo-to-omni.semantic-profile.v1"
    )
    profile_id: str
    run_id: str
    scope_id: str
    identity: AssetIdentity
    status: Literal["ready", "blocked"]
    definition: DefinitionProfile
    grain: GrainProfile
    lineage: LineageProfile
    aggregation: AggregationProfile
    filters: FilterProfile
    joins: list[JoinProfile] = Field(default_factory=list)
    time: TimeProfile
    security: SecurityProfile
    operations: OperationsProfile
    consumers: list[str] = Field(default_factory=list)
    side_effects: list[SideEffectProfile] = Field(default_factory=list)
    unknowns: list[str] = Field(default_factory=list)
    blockers: list[str] = Field(default_factory=list)
    evidence_refs: list[str] = Field(min_length=1)
    dimension_hashes: dict[str, Sha256]
    profile_hash: Sha256 = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    immutable: Literal[True] = True
    provenance: dict[str, Any]
    security_metadata: dict[str, Any]

    @model_validator(mode="after")
    def readiness_is_fail_closed(self) -> "SemanticProfile":
        required_states = {
            self.grain.state,
            self.lineage.state,
            self.aggregation.state,
            self.filters.state,
            self.time.state,
            self.security.state,
            self.operations.state,
        }
        if self.status == "ready":
            if self.blockers or self.unknowns:
                raise ValueError("ready semantic profiles cannot contain blockers or unknowns")
            if self.definition.state != "complete" or self.definition.canonical_state != "supported":
                raise ValueError("ready semantic profiles require a complete supported definition")
            if "unknown" in required_states or "conflict" in required_states:
                raise ValueError("ready semantic profiles require known semantic dimensions")
            if not self.operations.owner_refs:
                raise ValueError("ready semantic profiles require an accountable owner")
            if any(effect.handoff_ref is None for effect in self.side_effects):
                raise ValueError("side effects require explicit external handoffs")
        return self

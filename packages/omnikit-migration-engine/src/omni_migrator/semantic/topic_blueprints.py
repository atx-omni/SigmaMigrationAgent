"""Immutable, proposal-only Topic blueprints and deterministic readiness checks."""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from typing import Any, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field, model_validator

from omni_migrator.control_plane.canonical import sha256_json
from omni_migrator.semantic.consolidation import (
    ConsolidationDecision,
    consolidation_decision_hash,
    consolidation_input_fingerprint,
)
from omni_migrator.semantic.equivalence import (
    AssessmentValidationContext,
    validate_validation_context,
)
from omni_migrator.semantic.models import SemanticProfile
from omni_migrator.semantic.profiles import validate_semantic_profile

_SHA256_PATTERN = r"^sha256:[a-f0-9]{64}$"
_STABLE_ID_PATTERN = r"^[a-z0-9][a-z0-9._-]{7,127}$"
_NON_SECRET_REF_PATTERN = r"^[A-Za-z][A-Za-z0-9+.-]*:.+$"
_ACTOR_REF_PATTERN = r"^(?:agent-ref|human-ref|person-ref|person):.+$"

ViewRole = Literal["base_fact", "dimension", "bridge"]
FieldKind = Literal["identifier", "dimension", "time_dimension", "attribute"]
RelationshipType = Literal["one_to_one", "one_to_many", "many_to_one"]
MeasureAggregation = Literal[
    "sum", "count", "count_distinct", "average", "minimum", "maximum", "custom"
]
LogicKind = Literal[
    "persistent_transformation",
    "shared_transformation",
    "expensive_transformation",
    "cross_consumer_transformation",
    "presentation",
    "exploration",
    "drill",
    "labeling",
    "audience_semantics",
]
PlacementLayer = Literal["dbt", "snowflake", "omni"]
SecurityDisposition = Literal[
    "single_domain", "separate_topics", "approved_secure_design"
]
ExceptionPurpose = Literal[
    "logic_placement",
    "target_layer_ref",
    "security_design",
    "persona_scope",
    "view_grain_key",
    "logic_classification",
]
PersonaAccess = Literal["allowed", "denied"]
DerivedFieldAccess = Literal["visible", "masked", "hidden", "not_applicable"]
_WAREHOUSE_LOGIC = {
    "persistent_transformation",
    "shared_transformation",
    "expensive_transformation",
    "cross_consumer_transformation",
}
_OMNI_LOGIC = {
    "presentation",
    "exploration",
    "drill",
    "labeling",
    "audience_semantics",
}
_TARGET_REF_SCHEMES: dict[PlacementLayer, frozenset[str]] = {
    "dbt": frozenset({"dbt-ref", "dbt-model-ref", "repo-artifact-ref", "repo-ref"}),
    "snowflake": frozenset({"snowflake-ref", "snowflake-query-ref"}),
    "omni": frozenset({"omni-ref", "omni-model-ref"}),
}
UNRESTRICTED_SECURITY_DOMAIN = "unrestricted"
_DISPOSITION_TRANSFORMATIONS: dict[str, frozenset[str]] = {
    "reuse": frozenset({"reused", "translated"}),
    "merge": frozenset({"consolidated", "translated"}),
    "parameterize": frozenset({"parameterized", "translated", "consolidated"}),
    "split": frozenset({"redesigned", "translated"}),
    "retire": frozenset(),
    "manual_review": frozenset(),
}


def _canonical_profile_security_domain(profile: SemanticProfile) -> str | None:
    """Map profile security state to the domain used by Topic policy checks."""

    if profile.security.state == "not_applicable":
        return UNRESTRICTED_SECURITY_DOMAIN
    if profile.security.state == "known":
        return profile.security.security_domain
    return None


class _StrictFrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    @model_validator(mode="after")
    def tuple_items_are_unique(self) -> "_StrictFrozenModel":
        """Mirror JSON Schema ``uniqueItems`` for every contract tuple."""

        for field_name in type(self).model_fields:
            value = getattr(self, field_name)
            if not isinstance(value, tuple):
                continue
            comparable = [
                item.model_dump(mode="json") if isinstance(item, BaseModel) else item
                for item in value
            ]
            if any(
                item == prior
                for index, item in enumerate(comparable)
                for prior in comparable[:index]
            ):
                raise ValueError(f"{field_name} must contain unique items")
        return self

    @model_validator(mode="after")
    def references_are_non_secret(self) -> "_StrictFrozenModel":
        for field_name in type(self).model_fields:
            if not (field_name.endswith("_ref") or field_name.endswith("_refs")):
                continue
            value = getattr(self, field_name)
            references = value if isinstance(value, tuple) else (value,)
            if any(
                isinstance(reference, str)
                and reference.partition(":")[0].lower()
                in {"secret", "secret-ref", "vault", "credential"}
                for reference in references
            ):
                raise ValueError("artifact references cannot contain secret locations")
        return self


class BlueprintDecisionBinding(_StrictFrozenModel):
    decision_id: str = Field(pattern=_STABLE_ID_PATTERN)
    decision_hash: str = Field(pattern=_SHA256_PATTERN)
    input_fingerprint: str = Field(pattern=_SHA256_PATTERN)
    validation_cycle_id: str = Field(min_length=1)
    group_id: str = Field(min_length=1)


class BlueprintProfileBinding(_StrictFrozenModel):
    profile_id: str = Field(pattern=_STABLE_ID_PATTERN)
    system: Literal["domo", "dbt", "snowflake", "omni"]
    asset_id: str = Field(min_length=1)
    profile_hash: str = Field(pattern=_SHA256_PATTERN)


class AcceptedDecisionValidationBinding(_StrictFrozenModel):
    """Control-plane evidence that one exact decision passed governed validation."""

    decision_id: str = Field(pattern=_STABLE_ID_PATTERN)
    decision_hash: str = Field(pattern=_SHA256_PATTERN)
    input_fingerprint: str = Field(pattern=_SHA256_PATTERN)
    validation_context_hash: str = Field(pattern=_SHA256_PATTERN)
    acceptance_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    acceptance_hash: str = Field(pattern=_SHA256_PATTERN)


class AcceptedFanoutValidationBinding(_StrictFrozenModel):
    """Independent acceptance of one exact fanout test result."""

    blueprint_id: str = Field(pattern=_STABLE_ID_PATTERN)
    join_id: str = Field(pattern=_STABLE_ID_PATTERN)
    join_definition_hash: str = Field(pattern=_SHA256_PATTERN)
    observed_relationship_type: RelationshipType
    cardinality_evidence_refs: tuple[str, ...] = Field(min_length=1)
    fixture_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    result_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    result_hash: str = Field(pattern=_SHA256_PATTERN)
    accepted_result_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    validation_context_hash: str = Field(pattern=_SHA256_PATTERN)
    acceptance_hash: str = Field(pattern=_SHA256_PATTERN)


class AcceptedExceptionValidationBinding(_StrictFrozenModel):
    """Control-plane acceptance for one exact exception and purpose."""

    blueprint_id: str = Field(pattern=_STABLE_ID_PATTERN)
    exception_id: str = Field(pattern=_STABLE_ID_PATTERN)
    purpose: ExceptionPurpose
    decision_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    decision_hash: str = Field(pattern=_SHA256_PATTERN)
    approval_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    exception_scope_hash: str = Field(pattern=_SHA256_PATTERN)
    validation_context_hash: str = Field(pattern=_SHA256_PATTERN)
    acceptance_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    acceptance_hash: str = Field(pattern=_SHA256_PATTERN)


class AcceptedBusinessDomainScope(_StrictFrozenModel):
    """Trusted membership boundary for one focused Topic proposal."""

    blueprint_id: str = Field(pattern=_STABLE_ID_PATTERN)
    business_domain_id: str = Field(pattern=_STABLE_ID_PATTERN)
    business_use_case_id: str = Field(pattern=_STABLE_ID_PATTERN)
    audience_id: str = Field(pattern=_STABLE_ID_PATTERN)
    persona_refs: tuple[str, ...] = Field(min_length=1)
    access_purpose: str = Field(min_length=1)
    decision_group_ids: tuple[str, ...] = Field(min_length=1)
    profile_ids: tuple[str, ...] = Field(min_length=1)
    consumer_ids: tuple[str, ...] = Field(min_length=1)
    business_use_case_hash: str = Field(pattern=_SHA256_PATTERN)
    audience_descriptor_hash: str = Field(pattern=_SHA256_PATTERN)
    grouping_scope_hash: str = Field(pattern=_SHA256_PATTERN)
    validation_context_hash: str = Field(pattern=_SHA256_PATTERN)
    evidence_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    evidence_hash: str = Field(pattern=_SHA256_PATTERN)


class AcceptedSplitTargetDesign(_StrictFrozenModel):
    """Accepted per-Topic target produced after an incompatible split decision."""

    blueprint_id: str = Field(pattern=_STABLE_ID_PATTERN)
    blueprint_hash: str = Field(pattern=_SHA256_PATTERN)
    decision_id: str = Field(pattern=_STABLE_ID_PATTERN)
    split_set_id: str = Field(pattern=_STABLE_ID_PATTERN)
    split_set_hash: str = Field(pattern=_SHA256_PATTERN)
    target_profile_id: str = Field(pattern=_STABLE_ID_PATTERN)
    target_profile_hash: str = Field(pattern=_SHA256_PATTERN)
    source_profile_ids: tuple[str, ...] = Field(min_length=1)
    consumer_ids: tuple[str, ...] = Field(min_length=1)
    security_domain: str = Field(min_length=1)
    validation_context_hash: str = Field(pattern=_SHA256_PATTERN)
    acceptance_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    acceptance_hash: str = Field(pattern=_SHA256_PATTERN)


class AcceptedSplitSetPartition(_StrictFrozenModel):
    blueprint_id: str = Field(pattern=_STABLE_ID_PATTERN)
    blueprint_hash: str = Field(pattern=_SHA256_PATTERN)
    target_profile_id: str = Field(pattern=_STABLE_ID_PATTERN)
    target_profile_hash: str = Field(pattern=_SHA256_PATTERN)
    source_profile_ids: tuple[str, ...] = Field(min_length=1)
    consumer_ids: tuple[str, ...] = Field(min_length=1)
    security_domain: str = Field(min_length=1)


class AcceptedSplitSetBinding(_StrictFrozenModel):
    split_set_id: str = Field(pattern=_STABLE_ID_PATTERN)
    decision_id: str = Field(pattern=_STABLE_ID_PATTERN)
    decision_hash: str = Field(pattern=_SHA256_PATTERN)
    partitions: tuple[AcceptedSplitSetPartition, ...] = Field(min_length=2)
    split_set_hash: str = Field(pattern=_SHA256_PATTERN)
    validation_context_hash: str = Field(pattern=_SHA256_PATTERN)
    acceptance_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    acceptance_hash: str = Field(pattern=_SHA256_PATTERN)


class AcceptedSourceMappingEvidence(_StrictFrozenModel):
    blueprint_id: str = Field(pattern=_STABLE_ID_PATTERN)
    mapping_id: str = Field(pattern=_STABLE_ID_PATTERN)
    mapping_hash: str = Field(pattern=_SHA256_PATTERN)
    validation_context_hash: str = Field(pattern=_SHA256_PATTERN)
    evidence_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    evidence_hash: str = Field(pattern=_SHA256_PATTERN)


class AcceptedLogicPlacementEvidence(_StrictFrozenModel):
    blueprint_id: str = Field(pattern=_STABLE_ID_PATTERN)
    placement_id: str = Field(pattern=_STABLE_ID_PATTERN)
    placement_hash: str = Field(pattern=_SHA256_PATTERN)
    target_profile_ids: tuple[str, ...] = Field(min_length=1)
    validation_context_hash: str = Field(pattern=_SHA256_PATTERN)
    evidence_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    evidence_hash: str = Field(pattern=_SHA256_PATTERN)


class AcceptedTopicComponentEvidence(_StrictFrozenModel):
    blueprint_id: str = Field(pattern=_STABLE_ID_PATTERN)
    component_id: str = Field(pattern=_STABLE_ID_PATTERN)
    component_kind: Literal["field", "measure"]
    component_hash: str = Field(pattern=_SHA256_PATTERN)
    source_definition_hashes: tuple[str, ...] = Field(min_length=1)
    validation_context_hash: str = Field(pattern=_SHA256_PATTERN)
    evidence_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    evidence_hash: str = Field(pattern=_SHA256_PATTERN)


class AcceptedSecurityDesignEvidence(_StrictFrozenModel):
    """Authenticated policy evaluation for one exact Topic security design."""

    blueprint_id: str = Field(pattern=_STABLE_ID_PATTERN)
    security_design_hash: str = Field(pattern=_SHA256_PATTERN)
    target_profile_ids: tuple[str, ...] = Field(min_length=1)
    validation_context_hash: str = Field(pattern=_SHA256_PATTERN)
    evidence_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    evidence_hash: str = Field(pattern=_SHA256_PATTERN)


class AcceptedTopicBlueprintBinding(_StrictFrozenModel):
    """Control-plane registration of an exact architect-produced blueprint."""

    blueprint_id: str = Field(pattern=_STABLE_ID_PATTERN)
    blueprint_hash: str = Field(pattern=_SHA256_PATTERN)
    producer_ref: Literal["agent-ref://domo_to_omni_architect"]
    validation_cycle_ids: tuple[str, ...] = Field(min_length=1)
    validation_context_hash: str = Field(pattern=_SHA256_PATTERN)
    registration_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    registration_hash: str = Field(pattern=_SHA256_PATTERN)


class TopicBlueprintEvidenceResolver(Protocol):
    """Trusted control-plane resolver; implementations authenticate returned evidence.

    The validator passes stable identities only. Implementations must resolve from
    immutable registry or audit evidence and must not derive acceptance from the
    proposal payload being validated.
    """

    def resolve_current_validation_context(
        self, *, run_id: str, scope_id: str, blueprint_id: str
    ) -> AssessmentValidationContext | None: ...

    def resolve_accepted_decision(
        self, *, run_id: str, scope_id: str, decision_id: str
    ) -> AcceptedDecisionValidationBinding | None: ...

    def resolve_accepted_fanout(
        self, *, run_id: str, scope_id: str, blueprint_id: str, join_id: str
    ) -> AcceptedFanoutValidationBinding | None: ...

    def resolve_accepted_exception(
        self,
        *,
        run_id: str,
        scope_id: str,
        blueprint_id: str,
        exception_id: str,
        purpose: ExceptionPurpose,
    ) -> AcceptedExceptionValidationBinding | None: ...

    def resolve_business_domain_scope(
        self,
        *,
        run_id: str,
        scope_id: str,
        blueprint_id: str,
        business_domain_id: str,
        business_use_case_id: str,
        audience_id: str,
    ) -> AcceptedBusinessDomainScope | None: ...

    def resolve_accepted_split_target(
        self, *, run_id: str, scope_id: str, blueprint_id: str, decision_id: str
    ) -> AcceptedSplitTargetDesign | None: ...

    def resolve_accepted_split_set(
        self, *, run_id: str, scope_id: str, decision_id: str
    ) -> AcceptedSplitSetBinding | None: ...

    def resolve_accepted_split_peer_hash(
        self, *, run_id: str, scope_id: str, split_set_id: str, blueprint_id: str
    ) -> str | None: ...

    def resolve_source_mapping_evidence(
        self, *, run_id: str, scope_id: str, blueprint_id: str, mapping_id: str
    ) -> AcceptedSourceMappingEvidence | None: ...

    def resolve_logic_placement_evidence(
        self, *, run_id: str, scope_id: str, blueprint_id: str, placement_id: str
    ) -> AcceptedLogicPlacementEvidence | None: ...

    def resolve_topic_component_evidence(
        self,
        *,
        run_id: str,
        scope_id: str,
        blueprint_id: str,
        component_id: str,
        component_kind: Literal["field", "measure"],
    ) -> AcceptedTopicComponentEvidence | None: ...

    def resolve_security_design_evidence(
        self, *, run_id: str, scope_id: str, blueprint_id: str
    ) -> AcceptedSecurityDesignEvidence | None: ...

    def resolve_registered_topic_blueprint(
        self, *, run_id: str, scope_id: str, blueprint_id: str
    ) -> AcceptedTopicBlueprintBinding | None: ...


class BusinessUseCase(_StrictFrozenModel):
    use_case_id: str = Field(pattern=_STABLE_ID_PATTERN)
    name: str = Field(min_length=1)
    description: str = Field(min_length=1)
    business_questions: tuple[str, ...] = Field(min_length=1)
    success_criteria: tuple[str, ...] = Field(min_length=1)


class TopicAudience(_StrictFrozenModel):
    audience_id: str = Field(pattern=_STABLE_ID_PATTERN)
    name: str = Field(min_length=1)
    description: str = Field(min_length=1)
    persona_refs: tuple[str, ...] = Field(min_length=1)
    access_purpose: str = Field(min_length=1)


class BaseFactDesign(_StrictFrozenModel):
    view_id: str = Field(pattern=_STABLE_ID_PATTERN)
    profile_id: str = Field(pattern=_STABLE_ID_PATTERN)
    grain: str = Field(min_length=1)
    primary_key_fields: tuple[str, ...] = Field(min_length=1)
    uniqueness_evidence_refs: tuple[str, ...] = Field(min_length=1)


class ApprovedExceptionBinding(_StrictFrozenModel):
    exception_id: str = Field(pattern=_STABLE_ID_PATTERN)
    decision_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    decision_hash: str = Field(pattern=_SHA256_PATTERN)
    approval_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    rationale: str = Field(min_length=1)


class TopicView(_StrictFrozenModel):
    view_id: str = Field(pattern=_STABLE_ID_PATTERN)
    profile_id: str = Field(pattern=_STABLE_ID_PATTERN)
    role: ViewRole
    label: str = Field(min_length=1)
    description: str = Field(min_length=1)
    grain: str = Field(min_length=1)
    primary_key_fields: tuple[str, ...] = Field(min_length=1)
    key_evidence_refs: tuple[str, ...] = Field(min_length=1)
    grain_key_exception: ApprovedExceptionBinding | None = None


class TopicField(_StrictFrozenModel):
    field_id: str = Field(pattern=_STABLE_ID_PATTERN)
    view_id: str = Field(pattern=_STABLE_ID_PATTERN)
    source_field: str = Field(min_length=1)
    label: str = Field(min_length=1)
    description: str = Field(min_length=1)
    data_type: str = Field(min_length=1)
    field_kind: FieldKind
    nullable: bool
    source_mapping_refs: tuple[str, ...] = Field(min_length=1)


class TopicMeasure(_StrictFrozenModel):
    measure_id: str = Field(pattern=_STABLE_ID_PATTERN)
    view_id: str = Field(pattern=_STABLE_ID_PATTERN)
    label: str = Field(min_length=1)
    description: str = Field(min_length=1)
    expression: str = Field(min_length=1)
    aggregation: MeasureAggregation
    grain: str = Field(min_length=1)
    logic_placement_id: str = Field(pattern=_STABLE_ID_PATTERN)
    source_mapping_refs: tuple[str, ...] = Field(min_length=1)


class JoinPredicate(_StrictFrozenModel):
    left_field_id: str = Field(pattern=_STABLE_ID_PATTERN)
    operator: Literal["="] = "="
    right_field_id: str = Field(pattern=_STABLE_ID_PATTERN)


class FanoutTestBinding(_StrictFrozenModel):
    status: Literal["passed"] = "passed"
    fixture_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    result_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    result_hash: str = Field(pattern=_SHA256_PATTERN)
    accepted_result_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    evidence_refs: tuple[str, ...] = Field(min_length=1)


class TopicJoin(_StrictFrozenModel):
    join_id: str = Field(pattern=_STABLE_ID_PATTERN)
    left_view_id: str = Field(pattern=_STABLE_ID_PATTERN)
    right_view_id: str = Field(pattern=_STABLE_ID_PATTERN)
    predicates: tuple[JoinPredicate, ...] = Field(min_length=1)
    relationship_type: RelationshipType
    left_key_fields: tuple[str, ...] = Field(min_length=1)
    right_key_fields: tuple[str, ...] = Field(min_length=1)
    fanout_test: FanoutTestBinding
    evidence_refs: tuple[str, ...] = Field(min_length=1)


class LogicPlacement(_StrictFrozenModel):
    placement_id: str = Field(pattern=_STABLE_ID_PATTERN)
    logic_kind: LogicKind
    target_layer: PlacementLayer
    target_artifact_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    source_mapping_refs: tuple[str, ...] = Field(min_length=1)
    rationale: str = Field(min_length=1)
    approved_exception: ApprovedExceptionBinding | None


class PersonaAccessExpectation(_StrictFrozenModel):
    persona_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    access: PersonaAccess
    scope_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    derived_field_access: DerivedFieldAccess
    evidence_refs: tuple[str, ...] = Field(min_length=1)


class TopicSecurityDesign(_StrictFrozenModel):
    source_security_domains: tuple[str, ...] = Field(min_length=1)
    target_security_domain: str = Field(min_length=1)
    persona_refs: tuple[str, ...] = Field(min_length=1)
    persona_expectations: tuple[PersonaAccessExpectation, ...] = Field(min_length=1)
    source_policy_refs: tuple[str, ...]
    target_policy_refs: tuple[str, ...]
    principal_precedence: tuple[str, ...]
    derived_field_exposure: Literal["safe"] = "safe"
    boundary_disposition: SecurityDisposition
    separate_topic_refs: tuple[str, ...]
    approved_secure_design: ApprovedExceptionBinding | None
    persona_scope_exception: ApprovedExceptionBinding | None
    evidence_refs: tuple[str, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def disposition_has_required_evidence(self) -> "TopicSecurityDesign":
        unrestricted = set(self.source_security_domains) == {
            UNRESTRICTED_SECURITY_DOMAIN
        } and self.target_security_domain == UNRESTRICTED_SECURITY_DOMAIN
        if unrestricted and (self.source_policy_refs or self.target_policy_refs):
            raise ValueError("unrestricted security cannot carry row or masking policies")
        if not unrestricted and not self.target_policy_refs:
            raise ValueError("governed security domains require target_policy_refs")
        personas = [item.persona_ref for item in self.persona_expectations]
        if len(personas) != len(set(personas)):
            raise ValueError("persona expectations require unique persona_ref values")
        if not set(self.persona_refs).issubset(set(personas)):
            raise ValueError("every Topic persona requires an access expectation")
        allowed_personas = {
            item.persona_ref
            for item in self.persona_expectations
            if item.access == "allowed"
        }
        if allowed_personas != set(self.persona_refs):
            raise ValueError(
                "allowed persona expectations must exactly match Topic persona_refs"
            )
        outcomes = {item.access for item in self.persona_expectations}
        if not unrestricted and outcomes != {"allowed", "denied"}:
            raise ValueError(
                "governed security domains require allowed and denied persona outcomes"
            )
        if unrestricted and any(
            item.access != "allowed" or item.derived_field_access != "not_applicable"
            for item in self.persona_expectations
        ):
            raise ValueError(
                "unrestricted security requires allowed, not-applicable persona outcomes"
            )
        if not unrestricted and not self.principal_precedence:
            raise ValueError("governed security domains require principal precedence")
        if unrestricted and self.principal_precedence:
            raise ValueError("unrestricted security cannot carry principal precedence")
        if self.boundary_disposition == "single_domain":
            if self.separate_topic_refs or self.approved_secure_design is not None:
                raise ValueError("single-domain security cannot carry split or exception evidence")
        elif self.boundary_disposition == "separate_topics":
            if not self.separate_topic_refs or self.approved_secure_design is not None:
                raise ValueError("separate-topic security requires peer Topic references only")
        elif self.approved_secure_design is None or self.separate_topic_refs:
            raise ValueError("approved secure designs require one exact approved exception")
        return self


class TopicFreshnessDesign(_StrictFrozenModel):
    update_mode: Literal["replace", "append", "upsert", "snapshot", "view"]
    watermark_field: str | None
    freshness_sla: str = Field(min_length=1)
    history_behavior: str = Field(min_length=1)
    backfill_behavior: str = Field(min_length=1)
    owner_refs: tuple[str, ...] = Field(min_length=1)
    sla_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    evidence_refs: tuple[str, ...] = Field(min_length=1)


class TopicOwnership(_StrictFrozenModel):
    business_owner_refs: tuple[str, ...] = Field(min_length=1)
    technical_owner_refs: tuple[str, ...] = Field(min_length=1)
    security_owner_refs: tuple[str, ...] = Field(min_length=1)
    operations_owner_refs: tuple[str, ...] = Field(min_length=1)


class SourceMapping(_StrictFrozenModel):
    mapping_id: str = Field(pattern=_STABLE_ID_PATTERN)
    source_profile_id: str = Field(pattern=_STABLE_ID_PATTERN)
    source_profile_hash: str = Field(pattern=_SHA256_PATTERN)
    source_asset_id: str = Field(min_length=1)
    source_component_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    target_kind: Literal["view", "field", "measure", "logic"]
    target_id: str = Field(pattern=_STABLE_ID_PATTERN)
    decision_id: str = Field(pattern=_STABLE_ID_PATTERN)
    transformation: Literal[
        "reused", "translated", "consolidated", "parameterized", "redesigned"
    ]
    evidence_refs: tuple[str, ...] = Field(min_length=1)


class ConsumerDecisionBinding(_StrictFrozenModel):
    decision_id: str = Field(pattern=_STABLE_ID_PATTERN)
    behavior: Literal["preserved", "approved_change"]
    accepted_difference_ref: str | None

    @model_validator(mode="after")
    def change_has_an_approved_difference(self) -> "ConsumerDecisionBinding":
        if self.behavior == "approved_change" and not self.accepted_difference_ref:
            raise ValueError("approved consumer changes require an accepted difference")
        if self.behavior == "preserved" and self.accepted_difference_ref is not None:
            raise ValueError("preserved consumers cannot carry an accepted difference")
        return self


class ConsumerMapping(_StrictFrozenModel):
    source_consumer_id: str = Field(min_length=1)
    target_consumer_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    topic_component_refs: tuple[str, ...] = Field(min_length=1)
    decision_bindings: tuple[ConsumerDecisionBinding, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def decision_bindings_are_unique(self) -> "ConsumerMapping":
        decision_ids = [binding.decision_id for binding in self.decision_bindings]
        if len(decision_ids) != len(set(decision_ids)):
            raise ValueError("consumer decision bindings must have unique decision_id values")
        return self


class UnresolvedTopicException(_StrictFrozenModel):
    exception_id: str = Field(pattern=_STABLE_ID_PATTERN)
    category: Literal[
        "grain",
        "join",
        "security",
        "freshness",
        "ownership",
        "logic_placement",
        "consumer_behavior",
        "other",
    ]
    description: str = Field(min_length=1)
    owner_ref: str = Field(pattern=_ACTOR_REF_PATTERN)
    handoff_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    blocks_readiness: Literal[True] = True


class BlueprintProvenance(_StrictFrozenModel):
    producer_ref: str = Field(pattern=_ACTOR_REF_PATTERN)
    source_refs: tuple[str, ...] = Field(min_length=1)
    evidence_refs: tuple[str, ...] = Field(min_length=1)


class BlueprintSecurityMetadata(_StrictFrozenModel):
    classification: Literal["internal", "confidential", "restricted"]


class TopicBlueprint(_StrictFrozenModel):
    """One focused Topic proposal. It can be ready but never authorizes work."""

    contract_version: Literal["domo-to-omni.topic-blueprint.v1"] = (
        "domo-to-omni.topic-blueprint.v1"
    )
    blueprint_id: str = Field(pattern=_STABLE_ID_PATTERN)
    run_id: str = Field(pattern=_STABLE_ID_PATTERN)
    scope_id: str = Field(pattern=_STABLE_ID_PATTERN)
    business_domain_id: str = Field(pattern=_STABLE_ID_PATTERN)
    topic_name: str = Field(min_length=1)
    topic_description: str = Field(min_length=1)
    business_use_case: BusinessUseCase
    audience: TopicAudience
    decision_bindings: tuple[BlueprintDecisionBinding, ...] = Field(min_length=1)
    profile_bindings: tuple[BlueprintProfileBinding, ...] = Field(min_length=1)
    validation_context: AssessmentValidationContext
    base_fact: BaseFactDesign
    views: tuple[TopicView, ...] = Field(min_length=1)
    fields: tuple[TopicField, ...] = Field(min_length=1)
    measures: tuple[TopicMeasure, ...] = Field(min_length=1)
    joins: tuple[TopicJoin, ...]
    security: TopicSecurityDesign
    freshness: TopicFreshnessDesign
    ownership: TopicOwnership
    source_mappings: tuple[SourceMapping, ...] = Field(min_length=1)
    consumer_mappings: tuple[ConsumerMapping, ...] = Field(min_length=1)
    logic_placements: tuple[LogicPlacement, ...] = Field(min_length=1)
    unresolved_exceptions: tuple[UnresolvedTopicException, ...]
    proposal_only: Literal[True] = True
    authorizes_build: Literal[False] = False
    authorizes_source_decommission: Literal[False] = False
    blueprint_hash: str = Field(pattern=_SHA256_PATTERN)
    immutable: Literal[True] = True
    provenance: BlueprintProvenance
    security_metadata: BlueprintSecurityMetadata

    @model_validator(mode="after")
    def design_references_are_closed(self) -> "TopicBlueprint":
        self._require_unique(self.decision_bindings, "decision_id", "decision_bindings")
        self._require_unique(self.profile_bindings, "profile_id", "profile_bindings")
        self._require_unique(self.views, "view_id", "views")
        self._require_unique(self.fields, "field_id", "fields")
        self._require_unique(self.measures, "measure_id", "measures")
        self._require_unique(self.joins, "join_id", "joins")
        self._require_unique(self.source_mappings, "mapping_id", "source_mappings")
        self._require_unique(
            self.consumer_mappings, "source_consumer_id", "consumer_mappings"
        )
        self._require_unique(
            self.logic_placements, "placement_id", "logic_placements"
        )
        self._require_unique(
            self.unresolved_exceptions, "exception_id", "unresolved_exceptions"
        )

        decision_ids = {item.decision_id for item in self.decision_bindings}
        profiles = {item.profile_id: item for item in self.profile_bindings}
        views = {item.view_id: item for item in self.views}
        fields = {item.field_id: item for item in self.fields}
        placements = {item.placement_id for item in self.logic_placements}
        mappings = {item.mapping_id for item in self.source_mappings}
        components = set(views) | set(fields) | {
            item.measure_id for item in self.measures
        } | placements

        base_views = [item for item in self.views if item.role == "base_fact"]
        if len(base_views) != 1 or base_views[0].view_id != self.base_fact.view_id:
            raise ValueError("a blueprint requires exactly one declared base-fact view")
        base_view = base_views[0]
        if (
            base_view.profile_id != self.base_fact.profile_id
            or base_view.grain != self.base_fact.grain
            or set(base_view.primary_key_fields) != set(self.base_fact.primary_key_fields)
            or set(base_view.key_evidence_refs)
            != set(self.base_fact.uniqueness_evidence_refs)
        ):
            raise ValueError("base-fact view must exactly match the base-fact design")
        if any(view.profile_id not in profiles for view in self.views):
            raise ValueError("every Topic view must bind a current semantic profile")

        fields_by_view: dict[str, set[str]] = {view_id: set() for view_id in views}
        for field in self.fields:
            if field.view_id not in views:
                raise ValueError("fields must reference declared Topic views")
            if any(mapping_ref not in mappings for mapping_ref in field.source_mapping_refs):
                raise ValueError("field source mappings must be declared")
            fields_by_view[field.view_id].add(field.field_id)
        for view in self.views:
            if not set(view.primary_key_fields).issubset(fields_by_view[view.view_id]):
                raise ValueError("every view primary key must reference a field on that view")
            for key_field in view.primary_key_fields:
                field = fields[key_field]
                if field.field_kind != "identifier" or field.nullable:
                    raise ValueError("primary-key fields must be non-null identifiers")

        for measure in self.measures:
            if measure.view_id not in views or measure.logic_placement_id not in placements:
                raise ValueError("measures require a declared view and logic placement")
            if any(mapping_ref not in mappings for mapping_ref in measure.source_mapping_refs):
                raise ValueError("measure source mappings must be declared")

        adjacency: dict[str, set[str]] = {view_id: set() for view_id in views}
        for join in self.joins:
            if (
                join.left_view_id not in views
                or join.right_view_id not in views
                or join.left_view_id == join.right_view_id
            ):
                raise ValueError("joins require two distinct declared views")
            if not set(join.left_key_fields).issubset(fields_by_view[join.left_view_id]):
                raise ValueError("join left keys must reference fields on the left view")
            if not set(join.right_key_fields).issubset(fields_by_view[join.right_view_id]):
                raise ValueError("join right keys must reference fields on the right view")
            for predicate in join.predicates:
                left = fields.get(predicate.left_field_id)
                right = fields.get(predicate.right_field_id)
                if (
                    left is None
                    or right is None
                    or left.view_id != join.left_view_id
                    or right.view_id != join.right_view_id
                ):
                    raise ValueError("join predicates must bind fields from their declared sides")
            self._validate_join_keys(join, views, fields)
            adjacency[join.left_view_id].add(join.right_view_id)
            adjacency[join.right_view_id].add(join.left_view_id)
        if len(views) > 1:
            visited = {self.base_fact.view_id}
            frontier = [self.base_fact.view_id]
            while frontier:
                frontier.extend(adjacency[frontier.pop()].difference(visited))
                visited.update(frontier)
            if visited != set(views):
                raise ValueError("every Topic view must connect to the base fact")

        for mapping in self.source_mappings:
            profile = profiles.get(mapping.source_profile_id)
            if (
                profile is None
                or profile.profile_hash != mapping.source_profile_hash
                or profile.asset_id != mapping.source_asset_id
            ):
                raise ValueError("source mappings must bind exact blueprint profiles")
            if mapping.decision_id not in decision_ids:
                raise ValueError("source mappings must cite a bound consolidation decision")
            if not self._source_component_matches_profile(mapping, profile):
                raise ValueError(
                    "source mapping component references must bind their exact profile or asset"
                )
            if mapping.target_id not in components:
                raise ValueError("source mappings must target a declared Topic component")
            if mapping.target_kind == "view" and mapping.target_id not in views:
                raise ValueError("view mappings must target views")
            if mapping.target_kind == "field" and mapping.target_id not in fields:
                raise ValueError("field mappings must target fields")
            if mapping.target_kind == "measure" and mapping.target_id not in {
                item.measure_id for item in self.measures
            }:
                raise ValueError("measure mappings must target measures")
            if mapping.target_kind == "logic" and mapping.target_id not in placements:
                raise ValueError("logic mappings must target logic placements")
        if {item.source_profile_id for item in self.source_mappings} != set(profiles):
            raise ValueError("source mappings must cover every exact profile binding")

        for placement in self.logic_placements:
            if any(ref not in mappings for ref in placement.source_mapping_refs):
                raise ValueError("logic placements must cite declared source mappings")
        for consumer in self.consumer_mappings:
            if any(
                binding.decision_id not in decision_ids
                for binding in consumer.decision_bindings
            ):
                raise ValueError("consumer mappings must cite a bound consolidation decision")
            if any(ref not in components for ref in consumer.topic_component_refs):
                raise ValueError("consumer mappings must cite declared Topic components")

        for field_name in (
            "business_questions",
            "success_criteria",
        ):
            self._require_scalar_unique(
                getattr(self.business_use_case, field_name), field_name
            )
        self._require_scalar_unique(self.audience.persona_refs, "persona_refs")
        if set(self.freshness.owner_refs) != set(self.ownership.operations_owner_refs):
            raise ValueError("freshness owners must exactly match operations ownership")
        return self

    @staticmethod
    def _require_unique(values: tuple[Any, ...], field: str, name: str) -> None:
        keys = [getattr(item, field) for item in values]
        if len(keys) != len(set(keys)):
            raise ValueError(f"{name} must contain unique {field} values")

    @staticmethod
    def _require_scalar_unique(values: tuple[str, ...], name: str) -> None:
        if len(values) != len(set(values)) or any(not value for value in values):
            raise ValueError(f"{name} must contain unique non-empty values")

    @staticmethod
    def _validate_join_keys(
        join: TopicJoin,
        views: Mapping[str, TopicView],
        fields: Mapping[str, TopicField],
    ) -> None:
        left_primary = set(views[join.left_view_id].primary_key_fields)
        right_primary = set(views[join.right_view_id].primary_key_fields)
        predicate_left = {item.left_field_id for item in join.predicates}
        predicate_right = {item.right_field_id for item in join.predicates}
        if not predicate_left.issubset(set(join.left_key_fields)) or not predicate_right.issubset(
            set(join.right_key_fields)
        ):
            raise ValueError("join predicates must be covered by explicit join key fields")
        if join.relationship_type == "many_to_one":
            if not right_primary.issubset(predicate_right):
                raise ValueError("many-to-one joins must bind the right primary key")
        elif join.relationship_type == "one_to_many":
            if not left_primary.issubset(predicate_left):
                raise ValueError("one-to-many joins must bind the left primary key")
        elif not left_primary.issubset(predicate_left) or not right_primary.issubset(
            predicate_right
        ):
            raise ValueError("one-to-one joins must bind both primary keys")
        if any(fields[field_id].nullable for field_id in right_primary & predicate_right):
            raise ValueError("joined primary keys cannot be nullable")

    @staticmethod
    def _source_component_matches_profile(
        mapping: SourceMapping, profile: BlueprintProfileBinding
    ) -> bool:
        exact_refs = {
            f"profile-ref://{profile.profile_id}",
            f"source-object-ref://{profile.asset_id}",
        }
        component_prefixes = (
            f"profile-component-ref://{profile.profile_id}/",
            f"source-component-ref://{profile.asset_id}/",
        )
        return mapping.source_component_ref in exact_refs or mapping.source_component_ref.startswith(
            component_prefixes
        )


class TopicBlueprintValidation(_StrictFrozenModel):
    valid: bool
    invalidated: bool
    errors: tuple[str, ...]
    invalidation_reasons: tuple[str, ...]
    build_ready: bool
    authorizes_build: Literal[False] = False
    blueprint_fingerprint: str = Field(pattern=_SHA256_PATTERN)


def _sha256(value: Any) -> str:
    return f"sha256:{sha256_json(value)}"


def topic_business_use_case_hash(value: BusinessUseCase) -> str:
    return _sha256(value.model_dump(mode="json"))


def topic_audience_descriptor_hash(value: TopicAudience) -> str:
    return _sha256(
        {
            "audience_id": value.audience_id,
            "name": value.name,
            "description": value.description,
        }
    )


def topic_business_grouping_scope_hash(value: TopicBlueprint) -> str:
    return _sha256(
        {
            "business_domain_id": value.business_domain_id,
            "business_use_case": value.business_use_case.model_dump(mode="json"),
            "audience": value.audience.model_dump(mode="json"),
            "decision_group_ids": sorted(
                binding.group_id for binding in value.decision_bindings
            ),
            "profile_ids": sorted(
                binding.profile_id for binding in value.profile_bindings
            ),
            "consumer_ids": sorted(
                mapping.source_consumer_id for mapping in value.consumer_mappings
            ),
        }
    )


def topic_source_mapping_hash(value: SourceMapping) -> str:
    return _sha256(value.model_dump(mode="json"))


def topic_logic_placement_hash(value: LogicPlacement) -> str:
    return _sha256(value.model_dump(mode="json"))


def topic_component_hash(value: TopicField | TopicMeasure) -> str:
    return _sha256(value.model_dump(mode="json"))


def topic_security_design_hash(value: TopicSecurityDesign) -> str:
    return _sha256(value.model_dump(mode="json"))


def topic_split_set_hash(
    *,
    decision_id: str,
    decision_hash: str,
    partitions: tuple[AcceptedSplitSetPartition, ...],
    validation_context_hash: str,
) -> str:
    return _sha256(
        {
            "decision_id": decision_id,
            "decision_hash": decision_hash,
            "partitions": [
                partition.model_dump(mode="json") for partition in partitions
            ],
            "validation_context_hash": validation_context_hash,
        }
    )


def _sort_records(values: Any, key: str) -> tuple[dict[str, Any], ...]:
    records = [deepcopy(dict(item)) for item in values or ()]
    return tuple(sorted(records, key=lambda item: str(item.get(key, ""))))


def _sorted_scalars(values: Any) -> tuple[str, ...]:
    return tuple(sorted(values or ()))


def _normalize_blueprint(value: Mapping[str, Any]) -> dict[str, Any]:
    result = deepcopy(dict(value))
    use_case = result.get("business_use_case")
    if isinstance(use_case, Mapping):
        use_case = deepcopy(dict(use_case))
        use_case["business_questions"] = _sorted_scalars(use_case.get("business_questions"))
        use_case["success_criteria"] = _sorted_scalars(use_case.get("success_criteria"))
        result["business_use_case"] = use_case
    audience = result.get("audience")
    if isinstance(audience, Mapping):
        audience = deepcopy(dict(audience))
        audience["persona_refs"] = _sorted_scalars(audience.get("persona_refs"))
        result["audience"] = audience

    result["decision_bindings"] = _sort_records(
        result.get("decision_bindings"), "decision_id"
    )
    result["profile_bindings"] = _sort_records(
        result.get("profile_bindings"), "profile_id"
    )

    base_fact = result.get("base_fact")
    if isinstance(base_fact, Mapping):
        base_fact = deepcopy(dict(base_fact))
        base_fact["primary_key_fields"] = _sorted_scalars(
            base_fact.get("primary_key_fields")
        )
        base_fact["uniqueness_evidence_refs"] = _sorted_scalars(
            base_fact.get("uniqueness_evidence_refs")
        )
        result["base_fact"] = base_fact

    views = list(_sort_records(result.get("views"), "view_id"))
    for view in views:
        view["primary_key_fields"] = _sorted_scalars(view.get("primary_key_fields"))
        view["key_evidence_refs"] = _sorted_scalars(view.get("key_evidence_refs"))
    result["views"] = tuple(views)

    fields = list(_sort_records(result.get("fields"), "field_id"))
    for field in fields:
        field["source_mapping_refs"] = _sorted_scalars(field.get("source_mapping_refs"))
    result["fields"] = tuple(fields)

    measures = list(_sort_records(result.get("measures"), "measure_id"))
    for measure in measures:
        measure["source_mapping_refs"] = _sorted_scalars(
            measure.get("source_mapping_refs")
        )
    result["measures"] = tuple(measures)

    joins = list(_sort_records(result.get("joins"), "join_id"))
    for join in joins:
        join["predicates"] = _sort_records(join.get("predicates"), "left_field_id")
        join["left_key_fields"] = _sorted_scalars(join.get("left_key_fields"))
        join["right_key_fields"] = _sorted_scalars(join.get("right_key_fields"))
        join["evidence_refs"] = _sorted_scalars(join.get("evidence_refs"))
        fanout = join.get("fanout_test")
        if isinstance(fanout, Mapping):
            fanout = deepcopy(dict(fanout))
            fanout["evidence_refs"] = _sorted_scalars(fanout.get("evidence_refs"))
            join["fanout_test"] = fanout
    result["joins"] = tuple(joins)

    security = result.get("security")
    if isinstance(security, Mapping):
        security = deepcopy(dict(security))
        for key in (
            "source_security_domains",
            "persona_refs",
            "source_policy_refs",
            "target_policy_refs",
            "separate_topic_refs",
            "evidence_refs",
        ):
            security[key] = _sorted_scalars(security.get(key))
        security["principal_precedence"] = tuple(
            security.get("principal_precedence") or ()
        )
        expectations = list(
            _sort_records(security.get("persona_expectations"), "persona_ref")
        )
        for expectation in expectations:
            expectation["evidence_refs"] = _sorted_scalars(
                expectation.get("evidence_refs")
            )
        security["persona_expectations"] = tuple(expectations)
        result["security"] = security

    freshness = result.get("freshness")
    if isinstance(freshness, Mapping):
        freshness = deepcopy(dict(freshness))
        freshness["owner_refs"] = _sorted_scalars(freshness.get("owner_refs"))
        freshness["evidence_refs"] = _sorted_scalars(freshness.get("evidence_refs"))
        result["freshness"] = freshness

    ownership = result.get("ownership")
    if isinstance(ownership, Mapping):
        ownership = deepcopy(dict(ownership))
        for key in (
            "business_owner_refs",
            "technical_owner_refs",
            "security_owner_refs",
            "operations_owner_refs",
        ):
            ownership[key] = _sorted_scalars(ownership.get(key))
        result["ownership"] = ownership

    source_mappings = list(_sort_records(result.get("source_mappings"), "mapping_id"))
    for mapping in source_mappings:
        mapping["evidence_refs"] = _sorted_scalars(mapping.get("evidence_refs"))
    result["source_mappings"] = tuple(source_mappings)

    consumer_mappings = list(
        _sort_records(result.get("consumer_mappings"), "source_consumer_id")
    )
    for mapping in consumer_mappings:
        mapping["topic_component_refs"] = _sorted_scalars(
            mapping.get("topic_component_refs")
        )
        mapping["decision_bindings"] = _sort_records(
            mapping.get("decision_bindings"), "decision_id"
        )
    result["consumer_mappings"] = tuple(consumer_mappings)

    placements = list(
        _sort_records(result.get("logic_placements"), "placement_id")
    )
    for placement in placements:
        placement["source_mapping_refs"] = _sorted_scalars(
            placement.get("source_mapping_refs")
        )
    result["logic_placements"] = tuple(placements)
    result["unresolved_exceptions"] = _sort_records(
        result.get("unresolved_exceptions"), "exception_id"
    )

    provenance = result.get("provenance")
    if isinstance(provenance, Mapping):
        provenance = deepcopy(dict(provenance))
        provenance["source_refs"] = _sorted_scalars(provenance.get("source_refs"))
        provenance["evidence_refs"] = _sorted_scalars(provenance.get("evidence_refs"))
        result["provenance"] = provenance
    return result


def topic_blueprint_hash(value: Mapping[str, Any] | TopicBlueprint) -> str:
    raw = value.model_dump(mode="json") if isinstance(value, TopicBlueprint) else value
    material = _normalize_blueprint(raw)
    material.pop("blueprint_hash", None)
    return _sha256(material)


def finalize_topic_blueprint(value: Mapping[str, Any] | TopicBlueprint) -> TopicBlueprint:
    """Normalize and hash a proposal without granting any build authority."""

    raw = value.model_dump(mode="json") if isinstance(value, TopicBlueprint) else value
    result = _normalize_blueprint(raw)
    result.setdefault("contract_version", "domo-to-omni.topic-blueprint.v1")
    result["proposal_only"] = True
    result["authorizes_build"] = False
    result["authorizes_source_decommission"] = False
    result["immutable"] = True
    result["blueprint_hash"] = "sha256:" + "0" * 64
    draft = TopicBlueprint.model_validate(result)
    normalized = _normalize_blueprint(draft.model_dump(mode="json"))
    normalized["blueprint_hash"] = topic_blueprint_hash(normalized)
    return TopicBlueprint.model_validate(normalized)


def _decision_binding(decision: ConsolidationDecision) -> BlueprintDecisionBinding:
    return BlueprintDecisionBinding(
        decision_id=decision.decision_id,
        decision_hash=decision.decision_hash,
        input_fingerprint=decision.input_fingerprint,
        validation_cycle_id=decision.validation_cycle_id,
        group_id=decision.group_id,
    )


def _profile_binding(profile: SemanticProfile) -> BlueprintProfileBinding:
    return BlueprintProfileBinding(
        profile_id=profile.profile_id,
        system=profile.identity.system,
        asset_id=profile.identity.object_id,
        profile_hash=profile.profile_hash,
    )


def _model_set(values: tuple[BaseModel, ...] | list[BaseModel]) -> set[str]:
    return {value.model_dump_json() for value in values}


def _resolve_current_context(
    resolver: TopicBlueprintEvidenceResolver,
    blueprint: TopicBlueprint,
) -> AssessmentValidationContext | None:
    try:
        result = resolver.resolve_current_validation_context(
            run_id=blueprint.run_id,
            scope_id=blueprint.scope_id,
            blueprint_id=blueprint.blueprint_id,
        )
    except Exception:
        return None
    return result if isinstance(result, AssessmentValidationContext) else None


def _resolve_accepted_decision(
    resolver: TopicBlueprintEvidenceResolver,
    blueprint: TopicBlueprint,
    decision_id: str,
) -> AcceptedDecisionValidationBinding | None:
    try:
        result = resolver.resolve_accepted_decision(
            run_id=blueprint.run_id,
            scope_id=blueprint.scope_id,
            decision_id=decision_id,
        )
    except Exception:
        return None
    return result if isinstance(result, AcceptedDecisionValidationBinding) else None


def _resolve_accepted_fanout(
    resolver: TopicBlueprintEvidenceResolver,
    blueprint: TopicBlueprint,
    join_id: str,
) -> AcceptedFanoutValidationBinding | None:
    try:
        result = resolver.resolve_accepted_fanout(
            run_id=blueprint.run_id,
            scope_id=blueprint.scope_id,
            blueprint_id=blueprint.blueprint_id,
            join_id=join_id,
        )
    except Exception:
        return None
    return result if isinstance(result, AcceptedFanoutValidationBinding) else None


def _resolve_accepted_split_target(
    resolver: TopicBlueprintEvidenceResolver,
    blueprint: TopicBlueprint,
    decision_id: str,
) -> AcceptedSplitTargetDesign | None:
    try:
        result = resolver.resolve_accepted_split_target(
            run_id=blueprint.run_id,
            scope_id=blueprint.scope_id,
            blueprint_id=blueprint.blueprint_id,
            decision_id=decision_id,
        )
    except Exception:
        return None
    return result if isinstance(result, AcceptedSplitTargetDesign) else None


def _resolve_accepted_split_set(
    resolver: TopicBlueprintEvidenceResolver,
    blueprint: TopicBlueprint,
    decision_id: str,
) -> AcceptedSplitSetBinding | None:
    try:
        result = resolver.resolve_accepted_split_set(
            run_id=blueprint.run_id,
            scope_id=blueprint.scope_id,
            decision_id=decision_id,
        )
    except Exception:
        return None
    return result if isinstance(result, AcceptedSplitSetBinding) else None


def _resolve_accepted_exception(
    resolver: TopicBlueprintEvidenceResolver,
    blueprint: TopicBlueprint,
    exception: ApprovedExceptionBinding,
    purpose: ExceptionPurpose,
    validation_context: AssessmentValidationContext,
    exception_scope_hash: str,
) -> Literal["accepted", "unavailable", "changed"]:
    try:
        result = resolver.resolve_accepted_exception(
            run_id=blueprint.run_id,
            scope_id=blueprint.scope_id,
            blueprint_id=blueprint.blueprint_id,
            exception_id=exception.exception_id,
            purpose=purpose,
        )
    except Exception:
        return "unavailable"
    if not isinstance(result, AcceptedExceptionValidationBinding):
        return "unavailable"
    if (
        result.blueprint_id != blueprint.blueprint_id
        or result.exception_id != exception.exception_id
        or result.purpose != purpose
        or result.decision_ref != exception.decision_ref
        or result.decision_hash != exception.decision_hash
        or result.approval_ref != exception.approval_ref
        or result.exception_scope_hash != exception_scope_hash
        or result.validation_context_hash != validation_context.context_hash
    ):
        return "changed"
    return "accepted"


def _exception_invalidation(
    *,
    resolver: TopicBlueprintEvidenceResolver,
    blueprint: TopicBlueprint,
    exception: ApprovedExceptionBinding,
    purpose: ExceptionPurpose,
    validation_context: AssessmentValidationContext,
    scope_material: Mapping[str, Any],
    prefix: str,
) -> str | None:
    status = _resolve_accepted_exception(
        resolver,
        blueprint,
        exception,
        purpose,
        validation_context,
        _sha256(scope_material),
    )
    if status == "accepted":
        return None
    return f"{prefix}_{status}:{exception.exception_id}:{purpose}"


def topic_join_definition_hash(join: TopicJoin) -> str:
    return _sha256(
        {
            "join_id": join.join_id,
            "left_view_id": join.left_view_id,
            "right_view_id": join.right_view_id,
            "predicates": [
                predicate.model_dump(mode="json") for predicate in join.predicates
            ],
            "relationship_type": join.relationship_type,
            "left_key_fields": list(join.left_key_fields),
            "right_key_fields": list(join.right_key_fields),
        }
    )


def _placement_errors(
    blueprint: TopicBlueprint,
    profiles: Mapping[str, SemanticProfile],
    resolver: TopicBlueprintEvidenceResolver,
    validation_context: AssessmentValidationContext,
) -> tuple[set[str], set[str]]:
    errors: set[str] = set()
    invalidation: set[str] = set()
    source_mappings = {
        mapping.mapping_id: mapping for mapping in blueprint.source_mappings
    }
    required_mapping_ids: set[str] = set()
    placement_coverage = {
        mapping_ref
        for placement in blueprint.logic_placements
        for mapping_ref in placement.source_mapping_refs
    }
    for placement in blueprint.logic_placements:
        expected = (
            {"dbt", "snowflake"}
            if placement.logic_kind in _WAREHOUSE_LOGIC
            else {"omni"}
        )
        violations: list[tuple[ExceptionPurpose, str]] = []
        if placement.target_layer not in expected:
            violations.append(
                (
                    "logic_placement",
                    "logic placement violates dbt-versus-Omni policy: "
                    f"{placement.placement_id}",
                )
            )
        ref_scheme = placement.target_artifact_ref.partition(":")[0]
        if ref_scheme not in _TARGET_REF_SCHEMES[placement.target_layer]:
            violations.append(
                (
                    "target_layer_ref",
                    "target artifact reference does not match its target layer: "
                    f"{placement.placement_id}",
                )
            )
        for mapping_ref in placement.source_mapping_refs:
            mapping = source_mappings[mapping_ref]
            profile = profiles.get(mapping.source_profile_id)
            if profile is None:
                continue
            expected_logic: set[str] | None = None
            if profile.identity.kind in {"transformation", "workflow_output"}:
                expected_logic = set(_WAREHOUSE_LOGIC)
                required_mapping_ids.add(mapping_ref)
            elif profile.identity.kind == "calculation":
                required_mapping_ids.add(mapping_ref)
                expected_logic = (
                    {"shared_transformation", "cross_consumer_transformation"}
                    if len(profile.consumers) > 1
                    else set(_OMNI_LOGIC)
                )
            if expected_logic is not None and placement.logic_kind not in expected_logic:
                violations.append(
                    (
                        "logic_classification",
                        "logic placement classification conflicts with current semantic "
                        f"profile evidence: {placement.placement_id}:{mapping_ref}",
                    )
                )
        if not violations:
            if placement.approved_exception is not None:
                errors.add(
                    f"logic placement carries an exception without a violation: {placement.placement_id}"
                )
            continue
        exception = placement.approved_exception
        if exception is None:
            errors.update(message for _, message in violations)
            continue
        for purpose, _ in violations:
            reason = _exception_invalidation(
                resolver=resolver,
                blueprint=blueprint,
                exception=exception,
                purpose=purpose,
                validation_context=validation_context,
                scope_material={
                    "placement_id": placement.placement_id,
                    "logic_kind": placement.logic_kind,
                    "target_layer": placement.target_layer,
                    "target_artifact_ref": placement.target_artifact_ref,
                    "source_mapping_refs": list(placement.source_mapping_refs),
                },
                prefix="placement_exception",
            )
            if reason is not None:
                invalidation.add(reason)
    for mapping in blueprint.source_mappings:
        profile = profiles.get(mapping.source_profile_id)
        if profile is not None and profile.identity.kind in {
            "transformation",
            "workflow_output",
            "calculation",
        }:
            required_mapping_ids.add(mapping.mapping_id)
    for mapping_id in required_mapping_ids.difference(placement_coverage):
        errors.add(
            f"transformation or calculation source mapping lacks a logic placement: {mapping_id}"
        )
    return errors, invalidation


def _view_errors(
    blueprint: TopicBlueprint,
    profiles: Mapping[str, SemanticProfile],
    resolver: TopicBlueprintEvidenceResolver,
    validation_context: AssessmentValidationContext,
) -> tuple[set[str], set[str]]:
    errors: set[str] = set()
    invalidation: set[str] = set()
    fields = {field.field_id: field for field in blueprint.fields}
    for view in blueprint.views:
        profile = profiles.get(view.profile_id)
        if profile is None:
            continue
        if profile.identity.system not in {"dbt", "snowflake", "omni"}:
            errors.add(f"Topic view must bind an accepted target-side profile: {view.view_id}")
            continue
        grain = profile.grain
        source_keys = {fields[field_id].source_field for field_id in view.primary_key_fields}
        mismatch = (
            grain.state != "known"
            or grain.description != view.grain
            or set(grain.key_fields) != source_keys
            or set(grain.uniqueness_evidence_refs) != set(view.key_evidence_refs)
        )
        if not mismatch:
            if view.grain_key_exception is not None:
                errors.add(f"Topic view carries an unused grain/key exception: {view.view_id}")
            continue
        exception = view.grain_key_exception
        if exception is None:
            errors.add(
                f"Topic view grain, keys, and evidence must match its current target profile: {view.view_id}"
            )
            continue
        reason = _exception_invalidation(
            resolver=resolver,
            blueprint=blueprint,
            exception=exception,
            purpose="view_grain_key",
            validation_context=validation_context,
            scope_material={
                "view_id": view.view_id,
                "profile_id": view.profile_id,
                "grain": view.grain,
                "primary_key_fields": list(view.primary_key_fields),
                "key_evidence_refs": list(view.key_evidence_refs),
            },
            prefix="view_grain_key_exception",
        )
        if reason is not None:
            invalidation.add(reason)
    return errors, invalidation


def _security_errors(
    blueprint: TopicBlueprint,
    profiles: Mapping[str, SemanticProfile],
    target_profile_ids: set[str],
    resolver: TopicBlueprintEvidenceResolver,
    validation_context: AssessmentValidationContext,
) -> tuple[set[str], set[str]]:
    errors: set[str] = set()
    invalidation: set[str] = set()

    source_profiles = {
        profile_id: profile
        for profile_id, profile in profiles.items()
        if profile_id not in target_profile_ids
    }
    target_profiles = {
        profile_id: profile
        for profile_id, profile in profiles.items()
        if profile_id in target_profile_ids
    }

    source_domains = {
        domain
        for profile in source_profiles.values()
        if (domain := _canonical_profile_security_domain(profile)) is not None
    }
    target_domains = {
        domain
        for profile in target_profiles.values()
        if (domain := _canonical_profile_security_domain(profile)) is not None
    }
    source_policies = {
        *(
            policy
            for profile in source_profiles.values()
            for policy in profile.security.pdp_policy_refs
        ),
        *(
            policy
            for profile in source_profiles.values()
            for policy in profile.security.masking_policy_refs
        ),
    }
    target_policies = {
        *(
            policy
            for profile in target_profiles.values()
            for policy in profile.security.pdp_policy_refs
        ),
        *(
            policy
            for profile in target_profiles.values()
            for policy in profile.security.masking_policy_refs
        ),
    }
    target_precedence = {
        tuple(profile.security.principal_precedence)
        for profile in target_profiles.values()
    }
    secure_design_reason: str | None = None
    secure_design_exception_accepted = False
    if (
        blueprint.security.boundary_disposition == "approved_secure_design"
        and blueprint.security.approved_secure_design is not None
    ):
        secure_design_reason = _exception_invalidation(
            resolver=resolver,
            blueprint=blueprint,
            exception=blueprint.security.approved_secure_design,
            purpose="security_design",
            validation_context=validation_context,
            scope_material={
                "source_security_domains": list(
                    blueprint.security.source_security_domains
                ),
                "target_security_domain": blueprint.security.target_security_domain,
                "source_policy_refs": list(blueprint.security.source_policy_refs),
                "target_policy_refs": list(blueprint.security.target_policy_refs),
                "boundary_disposition": blueprint.security.boundary_disposition,
            },
            prefix="security_exception",
        )
        secure_design_exception_accepted = secure_design_reason is None
    if source_domains != set(blueprint.security.source_security_domains):
        invalidation.add("security_profile_domains_changed")
    if (
        target_domains != {blueprint.security.target_security_domain}
        and not secure_design_exception_accepted
    ):
        invalidation.add("security_target_domain_changed")
    if source_policies != set(blueprint.security.source_policy_refs):
        invalidation.add("security_source_policies_changed")
    if (
        target_policies != set(blueprint.security.target_policy_refs)
        and not secure_design_exception_accepted
    ):
        invalidation.add("security_target_policies_changed")
    if (
        target_precedence != {tuple(blueprint.security.principal_precedence)}
        and not secure_design_exception_accepted
    ):
        invalidation.add("security_principal_precedence_changed")

    if any(
        (
            profile.security.state == "known"
            and (
                profile.security.security_domain is None
                or profile.security.derived_field_exposure != "safe"
            )
        )
        or (
            profile.security.state == "not_applicable"
            and (
                profile.security.security_domain is not None
                or profile.security.derived_field_exposure != "not_applicable"
                or profile.security.pdp_policy_refs
                or profile.security.masking_policy_refs
            )
        )
        or profile.security.state not in {"known", "not_applicable"}
        for profile in profiles.values()
    ):
        errors.add("security state or derived-field exposure is unsafe")

    incompatible = len(source_domains) > 1 or (
        len(source_domains) == 1
        and blueprint.security.target_security_domain not in source_domains
    )
    if blueprint.security.boundary_disposition == "separate_topics":
        errors.add("incompatible security domains require separate build-ready blueprints")
    elif incompatible:
        exception = blueprint.security.approved_secure_design
        if blueprint.security.boundary_disposition != "approved_secure_design" or exception is None:
            errors.add("incompatible security domains require an approved secure design")
        elif secure_design_reason is not None:
            invalidation.add(secure_design_reason)
    elif blueprint.security.boundary_disposition == "approved_secure_design":
        exception = blueprint.security.approved_secure_design
        if exception is None:
            invalidation.add("security_exception_unavailable")
        elif secure_design_reason is not None:
            invalidation.add(secure_design_reason)
    elif blueprint.security.boundary_disposition == "single_domain" and (
        len(source_domains) != 1
        or blueprint.security.target_security_domain not in source_domains
    ):
        errors.add("single-domain security must preserve the exact source domain")

    try:
        security_evidence = resolver.resolve_security_design_evidence(
            run_id=blueprint.run_id,
            scope_id=blueprint.scope_id,
            blueprint_id=blueprint.blueprint_id,
        )
    except Exception:
        security_evidence = None
    if not isinstance(security_evidence, AcceptedSecurityDesignEvidence):
        invalidation.add("security_design_evidence_unavailable")
    elif (
        security_evidence.blueprint_id != blueprint.blueprint_id
        or security_evidence.security_design_hash
        != topic_security_design_hash(blueprint.security)
        or set(security_evidence.target_profile_ids) != target_profile_ids
        or security_evidence.validation_context_hash
        != validation_context.context_hash
    ):
        invalidation.add("security_design_evidence_changed")
    return errors, invalidation


def _freshness_errors(
    blueprint: TopicBlueprint,
    profiles: Mapping[str, SemanticProfile],
    decisions: Mapping[str, ConsolidationDecision],
    target_profile_ids: set[str],
) -> set[str]:
    errors: set[str] = set()
    target_signature = (
        blueprint.freshness.update_mode,
        blueprint.freshness.watermark_field,
        blueprint.freshness.freshness_sla,
        blueprint.freshness.history_behavior,
        blueprint.freshness.backfill_behavior,
        blueprint.freshness.sla_ref,
    )
    for profile_id in target_profile_ids:
        profile = profiles.get(profile_id)
        if profile is None:
            errors.add(f"target freshness profile is unavailable: {profile_id}")
            continue
        operations = profile.operations
        target_profile_signature = (
            operations.update_mode,
            operations.watermark_field,
            operations.freshness_sla,
            operations.history_behavior,
            operations.backfill_behavior,
            operations.sla_ref,
        )
        if (
            operations.state not in {"known", "not_applicable"}
            or not operations.owner_refs
            or target_profile_signature != target_signature
            or set(operations.owner_refs) != set(blueprint.freshness.owner_refs)
        ):
            errors.add(
                f"target freshness and ownership must match the current target profile: {profile_id}"
            )

    for profile in profiles.values():
        if profile.profile_id in target_profile_ids:
            continue
        operations = profile.operations
        if operations.state not in {"known", "not_applicable"} or not operations.owner_refs:
            errors.add(f"freshness or ownership is incomplete: {profile.profile_id}")
            continue
        source_signature = (
            operations.update_mode,
            operations.watermark_field,
            operations.freshness_sla,
            operations.history_behavior,
            operations.backfill_behavior,
            operations.sla_ref,
        )
        owner_changed = set(operations.owner_refs) != set(
            blueprint.freshness.owner_refs
        )
        if source_signature == target_signature and not owner_changed:
            continue
        accepted = any(
            any(member.profile_id == profile.profile_id for member in decision.member_profiles)
            and decision.impact.freshness_history_or_sla_changed
            and decision.approvals.operations is not None
            for decision in decisions.values()
        )
        if not accepted:
            errors.add(
                f"freshness or ownership change lacks operations approval: {profile.profile_id}"
            )
    return errors


def validate_topic_blueprint(
    value: Mapping[str, Any] | TopicBlueprint,
    *,
    current_decisions: Mapping[str, ConsolidationDecision],
    current_profiles: Mapping[str, SemanticProfile],
    current_validation_context: AssessmentValidationContext,
    evidence_resolver: TopicBlueprintEvidenceResolver,
) -> TopicBlueprintValidation:
    """Validate exact current evidence and compute readiness without authorizing work."""

    raw = value.model_dump(mode="json") if isinstance(value, TopicBlueprint) else value
    fallback_fingerprint = topic_blueprint_hash(raw)
    try:
        blueprint = TopicBlueprint.model_validate(_normalize_blueprint(raw))
    except ValueError as exc:
        return TopicBlueprintValidation(
            valid=False,
            invalidated=True,
            errors=(f"Topic blueprint is invalid: {exc}",),
            invalidation_reasons=("blueprint_shape_invalid",),
            build_ready=False,
            authorizes_build=False,
            blueprint_fingerprint=fallback_fingerprint,
        )

    errors: set[str] = set()
    invalidation: set[str] = set()
    if blueprint.blueprint_hash != topic_blueprint_hash(blueprint):
        invalidation.add("blueprint_hash_changed")
    if validate_validation_context(current_validation_context):
        invalidation.add("validation_context_integrity_invalid")
    trusted_validation_context = _resolve_current_context(evidence_resolver, blueprint)
    if trusted_validation_context is None:
        invalidation.add("trusted_validation_context_unavailable")
        trusted_validation_context = current_validation_context
    elif validate_validation_context(trusted_validation_context):
        invalidation.add("trusted_validation_context_integrity_invalid")
    elif current_validation_context != trusted_validation_context:
        invalidation.add("current_validation_context_untrusted")
    if blueprint.validation_context != trusted_validation_context:
        invalidation.add("validation_context_changed")
    if trusted_validation_context.inventory_closure.status != "complete":
        errors.add("complete inventory closure is required for Topic readiness")
    try:
        registered_blueprint = evidence_resolver.resolve_registered_topic_blueprint(
            run_id=blueprint.run_id,
            scope_id=blueprint.scope_id,
            blueprint_id=blueprint.blueprint_id,
        )
    except Exception:
        registered_blueprint = None
    expected_cycles = {
        binding.validation_cycle_id for binding in blueprint.decision_bindings
    }
    if not isinstance(registered_blueprint, AcceptedTopicBlueprintBinding):
        invalidation.add("topic_blueprint_registration_unavailable")
    elif (
        registered_blueprint.blueprint_id != blueprint.blueprint_id
        or registered_blueprint.blueprint_hash != blueprint.blueprint_hash
        or registered_blueprint.producer_ref != blueprint.provenance.producer_ref
        or registered_blueprint.producer_ref
        != "agent-ref://domo_to_omni_architect"
        or set(registered_blueprint.validation_cycle_ids) != expected_cycles
        or registered_blueprint.validation_context_hash
        != trusted_validation_context.context_hash
    ):
        invalidation.add("topic_blueprint_registration_changed")

    resolved_decisions: dict[str, ConsolidationDecision] = {}
    for binding in blueprint.decision_bindings:
        decision = current_decisions.get(binding.decision_id)
        if decision is None:
            invalidation.add(f"decision_missing:{binding.decision_id}")
            continue
        resolved_decisions[decision.decision_id] = decision
        if decision.decision_hash != consolidation_decision_hash(decision):
            invalidation.add(f"decision_hash_invalid:{decision.decision_id}")
        if decision.input_fingerprint != consolidation_input_fingerprint(decision):
            invalidation.add(f"decision_input_invalid:{decision.decision_id}")
        if _decision_binding(decision) != binding:
            invalidation.add(f"decision_binding_changed:{decision.decision_id}")
        if decision.run_id != blueprint.run_id or decision.scope_id != blueprint.scope_id:
            invalidation.add(f"decision_partition_changed:{decision.decision_id}")
        if decision.validation_context != trusted_validation_context:
            invalidation.add(f"decision_context_changed:{decision.decision_id}")
        if (
            decision.status != "approved"
            or not decision.authorizes_build
            or decision.invalidated_by
        ):
            errors.add(f"decision is not currently accepted for build: {decision.decision_id}")
        accepted_decision = _resolve_accepted_decision(
            evidence_resolver, blueprint, decision.decision_id
        )
        if accepted_decision is None:
            invalidation.add(f"decision_acceptance_unavailable:{decision.decision_id}")
        elif (
            accepted_decision.decision_id != decision.decision_id
            or accepted_decision.decision_hash != decision.decision_hash
            or accepted_decision.input_fingerprint != decision.input_fingerprint
            or accepted_decision.validation_context_hash
            != trusted_validation_context.context_hash
        ):
            invalidation.add(f"decision_acceptance_changed:{decision.decision_id}")
        business = decision.approvals.business
        if business is None or business.scope_hash != decision.input_fingerprint:
            errors.add(f"decision business approval is stale: {decision.decision_id}")

    split_targets: dict[str, AcceptedSplitTargetDesign] = {}
    effective_target_profile_ids: dict[str, str] = {}
    selected_profile_ids: dict[str, set[str]] = {}
    selected_consumer_ids: dict[str, set[str]] = {}
    for decision in resolved_decisions.values():
        if decision.canonical_target_profile is not None:
            effective_target_profile_ids[decision.decision_id] = (
                decision.canonical_target_profile.profile_id
            )
            selected_profile_ids[decision.decision_id] = {
                member.profile_id for member in decision.member_profiles
            }
            selected_consumer_ids[decision.decision_id] = set(
                decision.affected_consumer_ids
            )
            continue
        if decision.disposition != "split":
            errors.add(
                f"Topic readiness requires an accepted canonical target: {decision.decision_id}"
            )
            continue
        split_target = _resolve_accepted_split_target(
            evidence_resolver, blueprint, decision.decision_id
        )
        if split_target is None:
            invalidation.add(
                f"split_target_acceptance_unavailable:{decision.decision_id}"
            )
            continue
        split_set = _resolve_accepted_split_set(
            evidence_resolver, blueprint, decision.decision_id
        )
        if split_set is None:
            invalidation.add(
                f"split_set_acceptance_unavailable:{decision.decision_id}"
            )
            continue
        target_profile = current_profiles.get(split_target.target_profile_id)
        member_ids = {member.profile_id for member in decision.member_profiles}
        source_counts: dict[str, int] = {}
        consumer_counts: dict[str, int] = {}
        partition_blueprint_ids = [
            partition.blueprint_id for partition in split_set.partitions
        ]
        partition_target_ids = [
            partition.target_profile_id for partition in split_set.partitions
        ]
        peer_targets_current = True
        peer_blueprints_current = True
        for partition in split_set.partitions:
            for profile_id in partition.source_profile_ids:
                source_counts[profile_id] = source_counts.get(profile_id, 0) + 1
            if partition.target_profile_id in member_ids:
                source_counts[partition.target_profile_id] = (
                    source_counts.get(partition.target_profile_id, 0) + 1
                )
            for consumer_id in partition.consumer_ids:
                consumer_counts[consumer_id] = consumer_counts.get(consumer_id, 0) + 1
            peer_target = current_profiles.get(partition.target_profile_id)
            if (
                peer_target is None
                or peer_target.profile_hash != partition.target_profile_hash
                or peer_target.identity.system not in {"dbt", "snowflake", "omni"}
                or _canonical_profile_security_domain(peer_target)
                != partition.security_domain
            ):
                peer_targets_current = False
            try:
                peer_blueprint_hash = (
                    evidence_resolver.resolve_accepted_split_peer_hash(
                        run_id=blueprint.run_id,
                        scope_id=blueprint.scope_id,
                        split_set_id=split_set.split_set_id,
                        blueprint_id=partition.blueprint_id,
                    )
                )
            except Exception:
                peer_blueprint_hash = None
            if peer_blueprint_hash != partition.blueprint_hash:
                peer_blueprints_current = False
        current_partitions = [
            partition
            for partition in split_set.partitions
            if partition.blueprint_id == blueprint.blueprint_id
        ]
        current_partition = current_partitions[0] if len(current_partitions) == 1 else None
        exhaustive_members = set(source_counts) == member_ids and all(
            count == 1 for count in source_counts.values()
        )
        exhaustive_consumers = set(consumer_counts) == set(
            decision.affected_consumer_ids
        ) and all(count == 1 for count in consumer_counts.values())
        split_set_changed = (
            split_set.decision_id != decision.decision_id
            or split_set.decision_hash != decision.decision_hash
            or split_set.validation_context_hash
            != trusted_validation_context.context_hash
            or split_set.split_set_hash
            != topic_split_set_hash(
                decision_id=split_set.decision_id,
                decision_hash=split_set.decision_hash,
                partitions=split_set.partitions,
                validation_context_hash=split_set.validation_context_hash,
            )
            or len(partition_blueprint_ids) != len(set(partition_blueprint_ids))
            or len(partition_target_ids) != len(set(partition_target_ids))
            or not exhaustive_members
            or not exhaustive_consumers
            or not peer_targets_current
            or not peer_blueprints_current
            or current_partition is None
            or split_target.blueprint_id != blueprint.blueprint_id
            or split_target.blueprint_hash != blueprint.blueprint_hash
            or split_target.split_set_id != split_set.split_set_id
            or split_target.split_set_hash != split_set.split_set_hash
            or current_partition.blueprint_hash != blueprint.blueprint_hash
            or current_partition.target_profile_id != split_target.target_profile_id
            or current_partition.target_profile_hash != split_target.target_profile_hash
            or set(current_partition.source_profile_ids)
            != set(split_target.source_profile_ids)
            or set(current_partition.consumer_ids) != set(split_target.consumer_ids)
            or current_partition.security_domain != split_target.security_domain
        )
        if split_set_changed:
            invalidation.add(f"split_set_acceptance_changed:{decision.decision_id}")
            continue
        if (
            split_target.decision_id != decision.decision_id
            or split_target.validation_context_hash
            != trusted_validation_context.context_hash
            or not set(split_target.source_profile_ids).issubset(member_ids)
            or not set(split_target.consumer_ids).issubset(
                set(decision.affected_consumer_ids)
            )
            or target_profile is None
            or target_profile.profile_hash != split_target.target_profile_hash
            or target_profile.identity.system not in {"dbt", "snowflake", "omni"}
            or _canonical_profile_security_domain(target_profile)
            != split_target.security_domain
            or split_target.security_domain
            != blueprint.security.target_security_domain
        ):
            invalidation.add(f"split_target_acceptance_changed:{decision.decision_id}")
            continue
        split_targets[decision.decision_id] = split_target
        effective_target_profile_ids[decision.decision_id] = (
            split_target.target_profile_id
        )
        selected_profile_ids[decision.decision_id] = {
            *split_target.source_profile_ids,
            split_target.target_profile_id,
        }
        selected_consumer_ids[decision.decision_id] = set(
            split_target.consumer_ids
        )

    expected_profile_bindings: list[BlueprintProfileBinding] = []
    for decision in resolved_decisions.values():
        for member in decision.member_profiles:
            profile = current_profiles.get(member.profile_id)
            if profile is None:
                invalidation.add(f"decision_profile_missing:{member.profile_id}")
                continue
            if (
                profile.identity.object_id != member.asset_id
                or profile.profile_hash != member.profile_hash
            ):
                invalidation.add(f"decision_profile_changed:{member.profile_id}")
            if member.profile_id in selected_profile_ids.get(decision.decision_id, set()):
                expected_profile_bindings.append(_profile_binding(profile))
        split_target = split_targets.get(decision.decision_id)
        if split_target is not None:
            target_profile = current_profiles.get(split_target.target_profile_id)
            if target_profile is not None:
                expected_profile_bindings.append(_profile_binding(target_profile))
    if _model_set(expected_profile_bindings) != _model_set(list(blueprint.profile_bindings)):
        invalidation.add("decision_profile_set_changed")

    resolved_profiles: dict[str, SemanticProfile] = {}
    for binding in blueprint.profile_bindings:
        profile = current_profiles.get(binding.profile_id)
        if profile is None:
            invalidation.add(f"profile_missing:{binding.profile_id}")
            continue
        resolved_profiles[profile.profile_id] = profile
        if validate_semantic_profile(profile):
            invalidation.add(f"profile_integrity_invalid:{profile.profile_id}")
        if _profile_binding(profile) != binding:
            invalidation.add(f"profile_binding_changed:{profile.profile_id}")
        if profile.run_id != blueprint.run_id or profile.scope_id != blueprint.scope_id:
            invalidation.add(f"profile_partition_changed:{profile.profile_id}")
        if profile.status != "ready":
            errors.add(f"profile is not semantically ready: {profile.profile_id}")

    base_profile = resolved_profiles.get(blueprint.base_fact.profile_id)
    if base_profile is None:
        errors.add("base fact must bind a current semantic profile")
    elif base_profile.identity.system not in {"dbt", "snowflake", "omni"}:
        errors.add("base fact must use an accepted target-side profile")
    canonical_targets = set(effective_target_profile_ids.values())
    if blueprint.base_fact.profile_id not in canonical_targets:
        errors.add("base fact must be an accepted canonical decision target")
    for view in blueprint.views:
        if view.profile_id not in canonical_targets:
            errors.add(f"Topic view must bind an accepted canonical target: {view.view_id}")

    view_errors, view_invalidation = _view_errors(
        blueprint,
        resolved_profiles,
        evidence_resolver,
        trusted_validation_context,
    )
    errors.update(view_errors)
    invalidation.update(view_invalidation)

    decision_consumer_pairs = {
        (decision_id, consumer_id)
        for decision_id, consumers in selected_consumer_ids.items()
        for consumer_id in consumers
    }
    blueprint_consumer_pairs = {
        (binding.decision_id, mapping.source_consumer_id)
        for mapping in blueprint.consumer_mappings
        for binding in mapping.decision_bindings
    }
    blueprint_consumers = {
        mapping.source_consumer_id for mapping in blueprint.consumer_mappings
    }
    if decision_consumer_pairs != blueprint_consumer_pairs:
        invalidation.add("consumer_decision_pair_set_changed")
    for mapping in blueprint.consumer_mappings:
        for binding in mapping.decision_bindings:
            decision_id = binding.decision_id
            decision = resolved_decisions.get(decision_id)
            if decision is None or mapping.source_consumer_id not in (
                selected_consumer_ids.get(decision_id, set())
            ):
                invalidation.add(
                    "consumer_decision_binding_changed:"
                    f"{decision_id}:{mapping.source_consumer_id}"
                )
                continue
            if (
                binding.accepted_difference_ref is not None
                and binding.accepted_difference_ref
                not in decision.accepted_differences
            ):
                invalidation.add(
                    "consumer_difference_changed:"
                    f"{decision_id}:{mapping.source_consumer_id}"
                )
            if decision.impact.consumer_behavior_changed != (
                binding.behavior == "approved_change"
            ):
                errors.add(
                    "consumer mapping behavior conflicts with the accepted decision impact: "
                    f"{decision_id}:{mapping.source_consumer_id}"
                )

    for mapping in blueprint.source_mappings:
        decision = resolved_decisions.get(mapping.decision_id)
        if decision is None or mapping.source_profile_id not in selected_profile_ids.get(
            mapping.decision_id, set()
        ):
            invalidation.add(f"source_decision_binding_changed:{mapping.mapping_id}")
            continue
        if mapping.transformation not in _DISPOSITION_TRANSFORMATIONS[
            decision.disposition
        ]:
            errors.add(
                "source mapping transformation conflicts with decision disposition: "
                f"{mapping.mapping_id}"
            )
        if (
            decision.canonical_target_profile is not None
            and mapping.source_profile_id
            == decision.canonical_target_profile.profile_id
            and decision.disposition == "reuse"
            and mapping.transformation != "reused"
        ):
            errors.add(
                "reused canonical target profiles must be mapped as reused: "
                f"{mapping.mapping_id}"
            )
        target_profile_id: str | None = None
        if mapping.target_kind == "view":
            target_profile_id = next(
                view.profile_id for view in blueprint.views if view.view_id == mapping.target_id
            )
        elif mapping.target_kind == "field":
            component = next(
                field for field in blueprint.fields if field.field_id == mapping.target_id
            )
            target_profile_id = next(
                view.profile_id for view in blueprint.views if view.view_id == component.view_id
            )
        elif mapping.target_kind == "measure":
            component = next(
                measure
                for measure in blueprint.measures
                if measure.measure_id == mapping.target_id
            )
            target_profile_id = next(
                view.profile_id for view in blueprint.views if view.view_id == component.view_id
            )
        canonical_target_profile_id = effective_target_profile_ids.get(
            decision.decision_id
        )
        if target_profile_id is not None and (
            canonical_target_profile_id is None
            or canonical_target_profile_id != target_profile_id
        ):
            invalidation.add(f"source_target_binding_changed:{mapping.mapping_id}")
        try:
            mapping_evidence = evidence_resolver.resolve_source_mapping_evidence(
                run_id=blueprint.run_id,
                scope_id=blueprint.scope_id,
                blueprint_id=blueprint.blueprint_id,
                mapping_id=mapping.mapping_id,
            )
        except Exception:
            mapping_evidence = None
        if not isinstance(mapping_evidence, AcceptedSourceMappingEvidence):
            invalidation.add(f"source_mapping_evidence_unavailable:{mapping.mapping_id}")
        elif (
            mapping_evidence.blueprint_id != blueprint.blueprint_id
            or mapping_evidence.mapping_id != mapping.mapping_id
            or mapping_evidence.mapping_hash != topic_source_mapping_hash(mapping)
            or mapping_evidence.validation_context_hash
            != trusted_validation_context.context_hash
        ):
            invalidation.add(f"source_mapping_evidence_changed:{mapping.mapping_id}")

    mappings_by_id = {
        mapping.mapping_id: mapping for mapping in blueprint.source_mappings
    }
    for placement in blueprint.logic_placements:
        target_profile_ids = tuple(
            sorted(
                {
                    effective_target_profile_ids[mappings_by_id[ref].decision_id]
                    for ref in placement.source_mapping_refs
                    if mappings_by_id[ref].decision_id
                    in effective_target_profile_ids
                }
            )
        )
        try:
            placement_evidence = evidence_resolver.resolve_logic_placement_evidence(
                run_id=blueprint.run_id,
                scope_id=blueprint.scope_id,
                blueprint_id=blueprint.blueprint_id,
                placement_id=placement.placement_id,
            )
        except Exception:
            placement_evidence = None
        if not isinstance(placement_evidence, AcceptedLogicPlacementEvidence):
            invalidation.add(
                f"logic_placement_evidence_unavailable:{placement.placement_id}"
            )
        elif (
            placement_evidence.blueprint_id != blueprint.blueprint_id
            or placement_evidence.placement_id != placement.placement_id
            or placement_evidence.placement_hash
            != topic_logic_placement_hash(placement)
            or set(placement_evidence.target_profile_ids) != set(target_profile_ids)
            or placement_evidence.validation_context_hash
            != trusted_validation_context.context_hash
        ):
            invalidation.add(
                f"logic_placement_evidence_changed:{placement.placement_id}"
            )

    for component_kind, components in (
        ("field", blueprint.fields),
        ("measure", blueprint.measures),
    ):
        for component in components:
            component_id = (
                component.field_id
                if isinstance(component, TopicField)
                else component.measure_id
            )
            definition_hashes = tuple(
                sorted(
                    {
                        current_profiles[
                            mappings_by_id[mapping_ref].source_profile_id
                        ].definition.original_hash
                        for mapping_ref in component.source_mapping_refs
                        if mappings_by_id[mapping_ref].source_profile_id
                        in current_profiles
                    }
                )
            )
            try:
                component_evidence = (
                    evidence_resolver.resolve_topic_component_evidence(
                        run_id=blueprint.run_id,
                        scope_id=blueprint.scope_id,
                        blueprint_id=blueprint.blueprint_id,
                        component_id=component_id,
                        component_kind=component_kind,
                    )
                )
            except Exception:
                component_evidence = None
            if not isinstance(component_evidence, AcceptedTopicComponentEvidence):
                invalidation.add(
                    f"topic_component_evidence_unavailable:{component_id}"
                )
            elif (
                component_evidence.blueprint_id != blueprint.blueprint_id
                or component_evidence.component_id != component_id
                or component_evidence.component_kind != component_kind
                or component_evidence.component_hash != topic_component_hash(component)
                or set(component_evidence.source_definition_hashes)
                != set(definition_hashes)
                or component_evidence.validation_context_hash
                != trusted_validation_context.context_hash
            ):
                invalidation.add(f"topic_component_evidence_changed:{component_id}")

    try:
        domain_scope = evidence_resolver.resolve_business_domain_scope(
            run_id=blueprint.run_id,
            scope_id=blueprint.scope_id,
            blueprint_id=blueprint.blueprint_id,
            business_domain_id=blueprint.business_domain_id,
            business_use_case_id=blueprint.business_use_case.use_case_id,
            audience_id=blueprint.audience.audience_id,
        )
    except Exception:
        domain_scope = None
    if not isinstance(domain_scope, AcceptedBusinessDomainScope):
        invalidation.add("business_domain_scope_unavailable")
    else:
        core_scope_changed = (
            domain_scope.blueprint_id != blueprint.blueprint_id
            or domain_scope.business_domain_id != blueprint.business_domain_id
            or domain_scope.business_use_case_id
            != blueprint.business_use_case.use_case_id
            or domain_scope.audience_id != blueprint.audience.audience_id
            or domain_scope.business_use_case_hash
            != topic_business_use_case_hash(blueprint.business_use_case)
            or domain_scope.audience_descriptor_hash
            != topic_audience_descriptor_hash(blueprint.audience)
            or set(domain_scope.decision_group_ids)
            != {binding.group_id for binding in blueprint.decision_bindings}
            or set(domain_scope.profile_ids)
            != {binding.profile_id for binding in blueprint.profile_bindings}
            or set(domain_scope.consumer_ids) != blueprint_consumers
            or domain_scope.validation_context_hash
            != trusted_validation_context.context_hash
        )
        if core_scope_changed:
            invalidation.add("business_domain_scope_changed")
        persona_scope_changed = (
            set(domain_scope.persona_refs) != set(blueprint.audience.persona_refs)
            or set(blueprint.audience.persona_refs)
            != set(blueprint.security.persona_refs)
            or domain_scope.access_purpose != blueprint.audience.access_purpose
        )
        persona_exception = blueprint.security.persona_scope_exception
        grouping_scope_changed = (
            domain_scope.grouping_scope_hash
            != topic_business_grouping_scope_hash(blueprint)
        )
        if grouping_scope_changed and not persona_scope_changed:
            invalidation.add("business_domain_scope_changed")
        if persona_scope_changed and persona_exception is None:
            errors.add("Topic personas or access purpose exceed the trusted domain scope")
        elif persona_scope_changed:
            reason = _exception_invalidation(
                resolver=evidence_resolver,
                blueprint=blueprint,
                exception=persona_exception,
                purpose="persona_scope",
                validation_context=trusted_validation_context,
                scope_material={
                    "trusted_persona_refs": list(domain_scope.persona_refs),
                    "trusted_access_purpose": domain_scope.access_purpose,
                    "audience_persona_refs": list(blueprint.audience.persona_refs),
                    "access_purpose": blueprint.audience.access_purpose,
                    "security_persona_refs": list(blueprint.security.persona_refs),
                },
                prefix="persona_scope_exception",
            )
            if reason is not None:
                invalidation.add(reason)
        elif persona_exception is not None:
            errors.add("security carries an unused persona-scope exception")

    for join in blueprint.joins:
        accepted_fanout = _resolve_accepted_fanout(
            evidence_resolver, blueprint, join.join_id
        )
        if accepted_fanout is None:
            invalidation.add(f"fanout_acceptance_unavailable:{join.join_id}")
        elif (
            accepted_fanout.blueprint_id != blueprint.blueprint_id
            or accepted_fanout.join_id != join.join_id
            or accepted_fanout.join_definition_hash != topic_join_definition_hash(join)
            or accepted_fanout.observed_relationship_type != join.relationship_type
            or set(accepted_fanout.cardinality_evidence_refs)
            != set(join.evidence_refs)
            or accepted_fanout.fixture_ref != join.fanout_test.fixture_ref
            or accepted_fanout.result_ref != join.fanout_test.result_ref
            or accepted_fanout.result_hash != join.fanout_test.result_hash
            or accepted_fanout.accepted_result_ref
            != join.fanout_test.accepted_result_ref
            or accepted_fanout.validation_context_hash
            != trusted_validation_context.context_hash
        ):
            invalidation.add(f"fanout_acceptance_changed:{join.join_id}")

    placement_errors, placement_invalidation = _placement_errors(
        blueprint, resolved_profiles, evidence_resolver, trusted_validation_context
    )
    security_errors, security_invalidation = _security_errors(
        blueprint,
        resolved_profiles,
        set(effective_target_profile_ids.values()),
        evidence_resolver,
        trusted_validation_context,
    )
    errors.update(placement_errors)
    errors.update(security_errors)
    errors.update(
        _freshness_errors(
            blueprint,
            resolved_profiles,
            resolved_decisions,
            set(effective_target_profile_ids.values()),
        )
    )
    invalidation.update(placement_invalidation)
    invalidation.update(security_invalidation)
    if blueprint.unresolved_exceptions:
        errors.add("unresolved Topic exceptions block build readiness")

    invalidated = bool(invalidation)
    valid = not errors and not invalidated
    return TopicBlueprintValidation(
        valid=valid,
        invalidated=invalidated,
        errors=tuple(sorted(errors)),
        invalidation_reasons=tuple(sorted(invalidation)),
        build_ready=valid,
        authorizes_build=False,
        blueprint_fingerprint=topic_blueprint_hash(blueprint),
    )


__all__ = [
    "AcceptedBusinessDomainScope",
    "AcceptedDecisionValidationBinding",
    "AcceptedExceptionValidationBinding",
    "AcceptedFanoutValidationBinding",
    "AcceptedLogicPlacementEvidence",
    "AcceptedSecurityDesignEvidence",
    "AcceptedSourceMappingEvidence",
    "AcceptedSplitSetBinding",
    "AcceptedSplitSetPartition",
    "AcceptedSplitTargetDesign",
    "AcceptedTopicBlueprintBinding",
    "AcceptedTopicComponentEvidence",
    "ApprovedExceptionBinding",
    "BaseFactDesign",
    "BlueprintDecisionBinding",
    "BlueprintProfileBinding",
    "BusinessUseCase",
    "ConsumerDecisionBinding",
    "ConsumerMapping",
    "FanoutTestBinding",
    "JoinPredicate",
    "LogicPlacement",
    "PersonaAccessExpectation",
    "SourceMapping",
    "TopicAudience",
    "TopicBlueprint",
    "TopicBlueprintEvidenceResolver",
    "TopicBlueprintValidation",
    "TopicField",
    "TopicFreshnessDesign",
    "TopicJoin",
    "TopicMeasure",
    "TopicOwnership",
    "TopicSecurityDesign",
    "TopicView",
    "UnresolvedTopicException",
    "finalize_topic_blueprint",
    "topic_audience_descriptor_hash",
    "topic_blueprint_hash",
    "topic_business_grouping_scope_hash",
    "topic_business_use_case_hash",
    "topic_component_hash",
    "topic_join_definition_hash",
    "topic_logic_placement_hash",
    "topic_security_design_hash",
    "topic_source_mapping_hash",
    "topic_split_set_hash",
    "validate_topic_blueprint",
]

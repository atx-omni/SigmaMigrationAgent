"""Deterministic, directional semantic-equivalence assessments.

The routines in this module are deliberately conservative.  They compare exactly
two immutable semantic profiles, produce evidence for every semantic dimension,
and never authorize consolidation.  Human-governed consolidation lives in
``semantic.consolidation``.
"""

from __future__ import annotations

from collections.abc import Collection, Mapping
from copy import deepcopy
import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from omni_migrator.control_plane.canonical import sha256_json
from omni_migrator.semantic.models import SemanticProfile
from omni_migrator.semantic.profiles import DIMENSIONS, validate_semantic_profile

DimensionName = Literal[
    "definition",
    "grain",
    "lineage",
    "aggregation",
    "filters",
    "joins",
    "time",
    "security",
    "operations",
    "consumers",
    "side_effects",
]
EquivalenceCategory = Literal[
    "exact_definition",
    "structurally_equivalent",
    "bounded_behavioral_equivalence",
    "approved_semantic_substitution",
    "different",
    "unknown",
]
DimensionVerdict = Literal[
    "exact", "equivalent_with_constraints", "different", "unknown", "not_applicable"
]
EvidenceMethod = Literal[
    "identity_hash",
    "canonical_definition",
    "dimension_hash",
    "bounded_query",
    "specialist_interpretation",
    "human_statement",
]
CandidateMethod = Literal[
    "exact_profile_hash",
    "canonical_definition_hash",
    "dimension_signature",
    "lineage_overlap",
    "consumer_overlap",
    "repository_mapping",
    "bounded_query",
    "specialist_interpretation",
    "human_statement",
]
AssessmentDirection = Literal[
    "bidirectional", "left_substitutes_right", "right_substitutes_left", "none", "unknown"
]
HardVetoCode = Literal[
    "definition_incomplete",
    "dependency_closure_incomplete",
    "grain_unknown_or_incompatible",
    "key_unknown_or_incompatible",
    "cardinality_unknown_or_incompatible",
    "fanout_failed_or_unknown",
    "aggregation_context_mismatch",
    "filter_context_mismatch",
    "time_semantics_mismatch",
    "null_or_distinct_semantics_mismatch",
    "security_domain_mismatch",
    "pdp_or_masking_mismatch",
    "derived_field_leakage_risk",
    "freshness_or_history_mismatch",
    "owner_or_sla_missing",
    "side_effects_present",
    "profile_revision_stale",
    "consumer_behavior_lost",
]

REQUIRED_DIMENSIONS: tuple[str, ...] = DIMENSIONS
_DIMENSION_ORDER = {name: index for index, name in enumerate(DIMENSIONS)}
_SHA256_PATTERN = r"^sha256:[a-f0-9]{64}$"
_STABLE_ID_PATTERN = r"^[a-z0-9][a-z0-9._-]{7,127}$"
_NON_SECRET_REF_PATTERN = r"^[A-Za-z][A-Za-z0-9+.-]*:.+$"


class _FrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ValidationArtifactReference(_FrozenModel):
    """Immutable reference to one exact validation input revision."""

    artifact_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    artifact_hash: str = Field(pattern=_SHA256_PATTERN)
    revision: str = Field(min_length=1)

    @model_validator(mode="after")
    def reference_is_non_secret(self) -> "ValidationArtifactReference":
        if self.artifact_ref.startswith(("secret:", "vault:", "credential:")):
            raise ValueError("validation artifact references cannot contain secret locations")
        return self


class InventoryClosureReference(ValidationArtifactReference):
    status: Literal["complete", "incomplete"]


class AssessmentValidationContext(_FrozenModel):
    """Full evidence context that makes an assessment reproducible and stale-able."""

    inventory_closure: InventoryClosureReference
    source_graph: ValidationArtifactReference
    portfolio_inventory: ValidationArtifactReference
    repository_inventory: ValidationArtifactReference
    target_context: ValidationArtifactReference
    policy_bundle: ValidationArtifactReference
    approval_owner_policy: ValidationArtifactReference
    fixture_bundle: ValidationArtifactReference
    consumer_contract_set: ValidationArtifactReference
    context_hash: str = Field(pattern=_SHA256_PATTERN)


class ProfileReference(_FrozenModel):
    profile_id: str = Field(pattern=_STABLE_ID_PATTERN)
    asset_id: str = Field(min_length=1)
    profile_hash: str = Field(pattern=_SHA256_PATTERN)
    dimension_hashes: dict[str, str]

    @model_validator(mode="after")
    def exact_dimension_fingerprints(self) -> "ProfileReference":
        if set(self.dimension_hashes) != set(DIMENSIONS) or len(self.dimension_hashes) != len(
            DIMENSIONS
        ):
            raise ValueError("profile references require exactly the 11 semantic dimensions")
        for value in self.dimension_hashes.values():
            if re.fullmatch(_SHA256_PATTERN, value) is None:
                raise ValueError("dimension fingerprints must be sha256 values")
        return self


class DimensionAssessment(_FrozenModel):
    dimension: DimensionName
    required: bool = True
    verdict: DimensionVerdict
    confidence: int = Field(ge=0, le=100)
    evidence_methods: tuple[EvidenceMethod, ...] = ()
    evidence_refs: tuple[str, ...] = ()
    counterevidence: tuple[str, ...] = ()
    constraints: tuple[str, ...] = ()

    @model_validator(mode="after")
    def evidence_is_fail_closed(self) -> "DimensionAssessment":
        for field_name in (
            "evidence_methods",
            "evidence_refs",
            "counterevidence",
            "constraints",
        ):
            values = getattr(self, field_name)
            if len(values) != len(set(values)):
                raise ValueError(f"{field_name} must contain unique values")
        for field_name in ("evidence_refs", "counterevidence", "constraints"):
            if any(not value for value in getattr(self, field_name)):
                raise ValueError(f"{field_name} cannot contain empty values")
        if self.verdict in {"exact", "equivalent_with_constraints"} and not self.evidence_refs:
            raise ValueError(f"{self.dimension} equivalence requires evidence")
        if self.verdict in {"different", "unknown"} and not self.counterevidence:
            raise ValueError(f"{self.dimension} {self.verdict} requires counterevidence")
        if self.verdict == "unknown" and self.confidence != 0:
            raise ValueError("unknown dimension verdicts must have zero confidence")
        return self


class ConsumerScope(_FrozenModel):
    left_consumer_ids: tuple[str, ...]
    right_consumer_ids: tuple[str, ...]
    preserved_consumer_ids: tuple[str, ...]
    lost_consumer_ids: tuple[str, ...]

    @model_validator(mode="after")
    def consumer_lists_match_contract(self) -> "ConsumerScope":
        for field_name in (
            "left_consumer_ids",
            "right_consumer_ids",
            "preserved_consumer_ids",
            "lost_consumer_ids",
        ):
            values = getattr(self, field_name)
            if any(not value for value in values):
                raise ValueError(f"{field_name} cannot contain empty values")
            if len(values) != len(set(values)):
                raise ValueError(f"{field_name} must contain unique values")
        return self


class BoundedBehavioralEvidence(_FrozenModel):
    """Bounded execution evidence tied to the exact profiles it evaluated."""

    source_profile_fingerprint: str = Field(pattern=_SHA256_PATTERN)
    target_profile_fingerprint: str = Field(pattern=_SHA256_PATTERN)
    fixture_bundle_hash: str = Field(pattern=_SHA256_PATTERN)
    passed: bool
    confidence: int = Field(default=80, ge=1, le=99)
    evidence_refs: tuple[str, ...] = Field(min_length=1)
    covered_source_consumers: tuple[str, ...] = ()
    constraints: tuple[str, ...] = ()


class RepositoryAssetMapping(_FrozenModel):
    """Reviewed source-to-target identity bindings; names never create mappings."""

    source_profile_fingerprint: str = Field(pattern=_SHA256_PATTERN)
    target_profile_fingerprint: str = Field(pattern=_SHA256_PATTERN)
    bindings: dict[str, str] = Field(min_length=1)
    evidence_refs: tuple[str, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def mapping_is_explicit_and_injective(self) -> "RepositoryAssetMapping":
        if any(not source or not target for source, target in self.bindings.items()):
            raise ValueError("asset mappings require non-empty source and target identities")
        if len(set(self.bindings.values())) != len(self.bindings):
            raise ValueError("asset mappings must be injective")
        return self


class EquivalenceAssessment(_FrozenModel):
    contract_version: Literal["domo-to-omni.equivalence-assessment.v1"] = (
        "domo-to-omni.equivalence-assessment.v1"
    )
    assessment_id: str = Field(pattern=_STABLE_ID_PATTERN)
    run_id: str = Field(pattern=_STABLE_ID_PATTERN)
    scope_id: str = Field(pattern=_STABLE_ID_PATTERN)
    left_profile: ProfileReference
    right_profile: ProfileReference
    direction: AssessmentDirection
    candidate_methods: tuple[CandidateMethod, ...]
    dimensions: tuple[DimensionAssessment, ...]
    overall_category: EquivalenceCategory
    overall_confidence: int = Field(ge=0, le=100)
    hard_vetoes: tuple[HardVetoCode, ...]
    consumer_scope: ConsumerScope
    consumer_map_hash: str = Field(pattern=_SHA256_PATTERN)
    validation_context: AssessmentValidationContext
    proposal_only: Literal[True] = True
    authorizes_consolidation: Literal[False] = False
    assessment_hash: str = Field(pattern=_SHA256_PATTERN)
    immutable: Literal[True] = True
    provenance: dict[str, Any]
    security: dict[str, Any]

    @model_validator(mode="after")
    def assessment_is_pairwise_and_fail_closed(self) -> "EquivalenceAssessment":
        if not self.candidate_methods:
            raise ValueError("candidate_methods must contain at least one method")
        if len(self.candidate_methods) != len(set(self.candidate_methods)):
            raise ValueError("candidate_methods must contain unique values")
        names = [item.dimension for item in self.dimensions]
        if len(names) != len(DIMENSIONS) or set(names) != set(DIMENSIONS):
            raise ValueError("assessments require each of the 11 semantic dimensions exactly once")
        required = [item.confidence for item in self.dimensions if item.required]
        if not required:
            raise ValueError("at least one semantic dimension must be required")
        if self.overall_confidence != min(required):
            raise ValueError("overall confidence must equal the lowest required dimension")
        if len(self.hard_vetoes) != len(set(self.hard_vetoes)):
            raise ValueError("hard vetoes must be unique")
        if self.overall_category == "approved_semantic_substitution":
            raise ValueError("deterministic assessment cannot grant semantic substitution")
        if self.hard_vetoes and self.overall_category not in {"different", "unknown"}:
            raise ValueError("hard vetoes require a different or unknown result")
        if self.validation_context.context_hash != validation_context_hash(
            self.validation_context
        ):
            raise ValueError("validation context hash does not match validation inputs")
        closure_veto = "dependency_closure_incomplete" in self.hard_vetoes
        if (self.validation_context.inventory_closure.status == "incomplete") != closure_veto:
            raise ValueError(
                "inventory closure status and dependency-closure veto must agree"
            )
        return self


def _sha256(value: Any) -> str:
    return f"sha256:{sha256_json(value)}"


def validation_context_hash(
    value: Mapping[str, Any] | AssessmentValidationContext,
) -> str:
    raw = (
        value.model_dump(mode="json")
        if isinstance(value, AssessmentValidationContext)
        else deepcopy(dict(value))
    )
    raw.pop("context_hash", None)
    return _sha256(raw)


def finalize_validation_context(
    value: Mapping[str, Any] | AssessmentValidationContext,
) -> AssessmentValidationContext:
    """Hash and strictly validate an immutable assessment context."""

    raw = (
        value.model_dump(mode="json")
        if isinstance(value, AssessmentValidationContext)
        else deepcopy(dict(value))
    )
    raw["context_hash"] = validation_context_hash(raw)
    return AssessmentValidationContext.model_validate(raw)


def validate_validation_context(
    value: Mapping[str, Any] | AssessmentValidationContext,
) -> list[str]:
    raw = (
        value.model_dump(mode="json")
        if isinstance(value, AssessmentValidationContext)
        else dict(value)
    )
    try:
        context = AssessmentValidationContext.model_validate(raw)
    except ValueError as exc:
        return [f"assessment validation context is invalid: {exc}"]
    if context.context_hash != validation_context_hash(context):
        return ["validation context hash does not match validation inputs"]
    return []


def consumer_map_hash(value: Mapping[str, str | None]) -> str:
    """Bind the exact directional source-to-target consumer disposition."""

    return _sha256(dict(sorted(value.items())))


def _profile_reference(profile: SemanticProfile) -> ProfileReference:
    return ProfileReference(
        profile_id=profile.profile_id,
        asset_id=profile.identity.object_id,
        profile_hash=profile.profile_hash,
        dimension_hashes=dict(profile.dimension_hashes),
    )


def _assessment_material(value: Mapping[str, Any]) -> dict[str, Any]:
    material = deepcopy(dict(value))
    material.pop("assessment_hash", None)
    return material


def equivalence_assessment_hash(
    value: Mapping[str, Any] | EquivalenceAssessment,
) -> str:
    raw = value.model_dump(mode="json") if isinstance(value, EquivalenceAssessment) else value
    return _sha256(_assessment_material(raw))


def _normalized_assessment(value: Mapping[str, Any]) -> dict[str, Any]:
    raw = deepcopy(dict(value))
    raw["candidate_methods"] = sorted(set(raw.get("candidate_methods", [])))
    raw["hard_vetoes"] = sorted(set(raw.get("hard_vetoes", [])))
    dimensions = []
    for item in raw.get("dimensions", []):
        dimension = deepcopy(dict(item))
        for key in ("evidence_methods", "evidence_refs", "counterevidence", "constraints"):
            dimension[key] = sorted(set(dimension.get(key, [])))
        dimensions.append(dimension)
    raw["dimensions"] = sorted(
        dimensions,
        key=lambda item: _DIMENSION_ORDER.get(str(item.get("dimension")), len(DIMENSIONS)),
    )
    consumer_scope = deepcopy(dict(raw.get("consumer_scope", {})))
    for key in (
        "left_consumer_ids",
        "right_consumer_ids",
        "preserved_consumer_ids",
        "lost_consumer_ids",
    ):
        consumer_scope[key] = sorted(set(consumer_scope.get(key, [])))
    raw["consumer_scope"] = consumer_scope
    return raw


def finalize_equivalence_assessment(
    value: Mapping[str, Any] | EquivalenceAssessment,
) -> EquivalenceAssessment:
    """Normalize, hash, and strictly validate one immutable pairwise assessment."""

    raw = value.model_dump(mode="json") if isinstance(value, EquivalenceAssessment) else value
    result = _normalized_assessment(raw)
    result.setdefault("contract_version", "domo-to-omni.equivalence-assessment.v1")
    result["assessment_hash"] = _sha256(_assessment_material(result))
    assessment = EquivalenceAssessment.model_validate(result)
    errors = validate_equivalence_assessment(assessment)
    if errors:
        raise ValueError("; ".join(errors))
    return assessment


def _derive_overall_category(
    dimensions: tuple[DimensionAssessment, ...],
    hard_vetoes: tuple[HardVetoCode, ...],
    candidate_methods: tuple[CandidateMethod, ...],
) -> EquivalenceCategory:
    required = [item for item in dimensions if item.required]
    if any(item.verdict == "unknown" for item in required):
        return "unknown"
    if hard_vetoes or any(item.verdict == "different" for item in required):
        return "different"
    definition = next(item for item in dimensions if item.dimension == "definition")
    if "bounded_query" in candidate_methods and definition.verdict == "equivalent_with_constraints":
        return "bounded_behavioral_equivalence"
    if definition.verdict == "exact":
        return "exact_definition"
    return "structurally_equivalent"


def validate_equivalence_assessment(
    value: Mapping[str, Any] | EquivalenceAssessment,
    *,
    current_validation_context: AssessmentValidationContext | Mapping[str, Any] | None = None,
) -> list[str]:
    """Return deterministic integrity and semantic-consistency errors."""

    raw = value.model_dump(mode="json") if isinstance(value, EquivalenceAssessment) else dict(value)
    errors: list[str] = []
    try:
        assessment = EquivalenceAssessment.model_validate(raw)
    except ValueError as exc:
        return [f"equivalence assessment is invalid: {exc}"]
    if assessment.assessment_hash != equivalence_assessment_hash(assessment):
        errors.append("assessment_hash does not match assessment content")
    errors.extend(validate_validation_context(assessment.validation_context))
    expected_category = _derive_overall_category(
        assessment.dimensions, assessment.hard_vetoes, assessment.candidate_methods
    )
    if assessment.overall_category != expected_category:
        errors.append(
            "overall_category does not match required dimension verdicts and hard vetoes"
        )
    if assessment.overall_confidence != min(
        item.confidence for item in assessment.dimensions if item.required
    ):
        errors.append("overall_confidence is not the lowest required dimension confidence")
    if assessment.overall_category == "bounded_behavioral_equivalence":
        if "bounded_query" not in assessment.candidate_methods:
            errors.append("bounded behavioral equivalence requires bounded-query evidence")
    if assessment.direction in {"left_substitutes_right", "right_substitutes_left"}:
        if assessment.overall_category in {"different", "unknown"}:
            errors.append("a failed assessment cannot claim a substitution direction")
    if assessment.consumer_scope.lost_consumer_ids and (
        "consumer_behavior_lost" not in assessment.hard_vetoes
    ):
        errors.append("lost source consumers require a consumer_behavior_lost veto")
    if current_validation_context is not None:
        reasons = equivalence_assessment_invalidation_reasons(
            assessment, current_validation_context
        )
        errors.extend(f"validation context changed: {reason}" for reason in reasons)
    return errors


def equivalence_assessment_invalidation_reasons(
    assessment: EquivalenceAssessment,
    current_validation_context: AssessmentValidationContext | Mapping[str, Any],
) -> tuple[str, ...]:
    """Identify exact validation inputs whose current revision differs."""

    current = finalize_validation_context(current_validation_context)
    recorded = assessment.validation_context
    reasons: list[str] = []
    for field_name in (
        "inventory_closure",
        "source_graph",
        "portfolio_inventory",
        "repository_inventory",
        "target_context",
        "policy_bundle",
        "approval_owner_policy",
        "fixture_bundle",
        "consumer_contract_set",
    ):
        if getattr(recorded, field_name) != getattr(current, field_name):
            reasons.append(f"{field_name}_revision_changed")
    return tuple(reasons)


def _refs_for_dimension(profile: SemanticProfile, dimension: str) -> tuple[str, ...]:
    refs: list[str] = []
    if dimension == "definition":
        refs = [profile.definition.original_ref, *profile.definition.translation_refs]
    elif dimension == "grain":
        refs = list(profile.grain.uniqueness_evidence_refs)
    elif dimension == "lineage":
        refs = list(profile.lineage.evidence_refs)
    elif dimension == "filters":
        refs = list(profile.filters.evidence_refs)
    elif dimension == "joins":
        refs = [ref for join in profile.joins for ref in join.evidence_refs]
    elif dimension == "security":
        refs = list(profile.security.evidence_refs)
    elif dimension == "operations" and profile.operations.sla_ref:
        refs = [profile.operations.sla_ref]
    elif dimension == "side_effects":
        refs = [effect.handoff_ref for effect in profile.side_effects if effect.handoff_ref]
    if not refs:
        refs = list(profile.evidence_refs)
    return tuple(sorted(set(refs)))


def _combined_refs(left: SemanticProfile, right: SemanticProfile, dimension: str) -> tuple[str, ...]:
    return tuple(sorted(set(_refs_for_dimension(left, dimension) + _refs_for_dimension(right, dimension))))


def _assessment(
    *,
    dimension: str,
    required: bool,
    verdict: DimensionVerdict,
    confidence: int,
    methods: Collection[EvidenceMethod],
    evidence_refs: Collection[str],
    counterevidence: Collection[str] = (),
    constraints: Collection[str] = (),
) -> DimensionAssessment:
    return DimensionAssessment(
        dimension=dimension,
        required=required,
        verdict=verdict,
        confidence=confidence,
        evidence_methods=tuple(sorted(set(methods))),
        evidence_refs=tuple(sorted(set(evidence_refs))),
        counterevidence=tuple(sorted(set(counterevidence))),
        constraints=tuple(sorted(set(constraints))),
    )


def _definition_assessment(
    left: SemanticProfile,
    right: SemanticProfile,
    *,
    required: bool,
    bounded: BoundedBehavioralEvidence | None,
    mapping: RepositoryAssetMapping | None,
) -> tuple[DimensionAssessment, bool]:
    refs = _combined_refs(left, right, "definition")
    if mapping is not None:
        refs = tuple(sorted(set(refs + mapping.evidence_refs)))
    incomplete = any(
        (
            profile.definition.state != "complete"
            or profile.definition.canonical_state != "supported"
            or profile.definition.canonical_hash is None
        )
        for profile in (left, right)
    )
    if incomplete:
        return (
            _assessment(
                dimension="definition",
                required=required,
                verdict="unknown",
                confidence=0,
                methods=("canonical_definition",),
                evidence_refs=refs,
                counterevidence=("definition is incomplete or not deterministically canonicalized",),
            ),
            False,
        )
    same_runtime = (
        left.definition.language,
        left.definition.dialect,
        left.definition.runtime,
    ) == (
        right.definition.language,
        right.definition.dialect,
        right.definition.runtime,
    )
    if (
        same_runtime
        and left.definition.original_hash == right.definition.original_hash
        and left.definition.canonical_hash == right.definition.canonical_hash
    ):
        return (
            _assessment(
                dimension="definition",
                required=required,
                verdict="exact",
                confidence=100,
                methods=("identity_hash", "canonical_definition"),
                evidence_refs=refs,
            ),
            False,
        )
    structurally_compatible_runtime = same_runtime or bool(
        mapping and left.definition.language == right.definition.language
    )
    if (
        structurally_compatible_runtime
        and left.definition.canonical_hash == right.definition.canonical_hash
    ):
        return (
            _assessment(
                dimension="definition",
                required=required,
                verdict="equivalent_with_constraints",
                confidence=95,
                methods=("canonical_definition",),
                evidence_refs=refs,
                counterevidence=("preserved source definitions have different fingerprints",),
                constraints=("equivalence is limited to the canonicalized definition and runtime",),
            ),
            False,
        )
    bounded_is_current = bool(
        bounded
        and bounded.source_profile_fingerprint == left.profile_hash
        and bounded.target_profile_fingerprint == right.profile_hash
    )
    bounded_covers_consumers = bool(
        bounded
        and set(left.consumers).issubset(set(bounded.covered_source_consumers))
    )
    if bounded and bounded.passed and bounded_is_current and bounded_covers_consumers:
        return (
            _assessment(
                dimension="definition",
                required=required,
                verdict="equivalent_with_constraints",
                confidence=bounded.confidence,
                methods=("bounded_query",),
                evidence_refs=tuple(refs) + bounded.evidence_refs,
                counterevidence=("canonical definitions differ",),
                constraints=bounded.constraints
                or ("equivalence is bounded to the exercised source consumers",),
            ),
            True,
        )
    counterevidence = ["canonical definitions or their execution runtimes differ"]
    if bounded and not bounded_is_current:
        counterevidence.append("bounded evidence is stale for the assessed profile fingerprints")
    if bounded and bounded.passed and not bounded_covers_consumers:
        counterevidence.append("bounded evidence does not cover every source consumer")
    return (
        _assessment(
            dimension="definition",
            required=required,
            verdict="different",
            confidence=100,
            methods=("canonical_definition",),
            evidence_refs=refs,
            counterevidence=counterevidence,
        ),
        False,
    )


def _mapped(value: str, mapping: RepositoryAssetMapping | None, *, source: bool) -> str:
    if source and mapping is not None:
        return mapping.bindings.get(value, value)
    return value


def _semantic_dimension_value(
    profile: SemanticProfile,
    dimension: str,
    *,
    mapping: RepositoryAssetMapping | None = None,
    source: bool = False,
) -> Any:
    """Return semantic material without evidence-location or provenance noise."""

    value = getattr(profile, dimension)
    if dimension == "grain":
        result = profile.grain.model_dump(mode="json")
        result.pop("uniqueness_evidence_refs", None)
        return result
    if dimension == "lineage":
        return {
            "state": profile.lineage.state,
            "authoritative_source_ids": sorted(
                _mapped(item, mapping, source=source)
                for item in profile.lineage.authoritative_source_ids
            ),
            "upstream_asset_ids": sorted(
                _mapped(item, mapping, source=source)
                for item in profile.lineage.upstream_asset_ids
            ),
            "relational_operations": sorted(profile.lineage.relational_operations),
        }
    if dimension == "filters":
        result = profile.filters.model_dump(mode="json")
        result.pop("evidence_refs", None)
        return result
    if dimension == "joins":
        joins = []
        for join in profile.joins:
            item = join.model_dump(mode="json")
            item.pop("evidence_refs", None)
            item["left_asset_id"] = _mapped(item["left_asset_id"], mapping, source=source)
            item["right_asset_id"] = _mapped(item["right_asset_id"], mapping, source=source)
            joins.append(item)
        return sorted(joins, key=sha256_json)
    if dimension == "security":
        result = profile.security.model_dump(mode="json")
        result.pop("evidence_refs", None)
        result["pdp_policy_refs"] = sorted(
            _mapped(item, mapping, source=source) for item in result["pdp_policy_refs"]
        )
        result["masking_policy_refs"] = sorted(
            _mapped(item, mapping, source=source) for item in result["masking_policy_refs"]
        )
        return result
    if dimension == "operations":
        result = profile.operations.model_dump(mode="json")
        result.pop("sla_ref", None)
        return result
    if dimension == "side_effects":
        return sorted(
            (
                {"kind": item.kind, "description": item.description}
                for item in profile.side_effects
            ),
            key=sha256_json,
        )
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, list):
        return [
            item.model_dump(mode="json") if isinstance(item, BaseModel) else item for item in value
        ]
    return value


def _unknown_dimension_reasons(profile: SemanticProfile, dimension: str) -> tuple[str, ...]:
    reasons: list[str] = []
    value = getattr(profile, dimension)
    state = getattr(value, "state", None)
    if state in {"unknown", "conflict"}:
        reasons.append(f"{profile.profile_id} has {dimension} state {state}")
    if dimension == "aggregation":
        if profile.aggregation.stage == "unknown":
            reasons.append(f"{profile.profile_id} has unknown aggregation stage")
        if profile.aggregation.distinct_mode == "unknown":
            reasons.append(f"{profile.profile_id} has unknown distinct semantics")
        if not profile.aggregation.null_semantics:
            reasons.append(f"{profile.profile_id} has unknown null semantics")
    elif dimension == "filters":
        if profile.filters.stage == "unknown" or profile.filters.scope == "unknown":
            reasons.append(f"{profile.profile_id} has unknown filter context")
    elif dimension == "joins":
        for join in profile.joins:
            if "unknown" in {join.declared_cardinality, join.observed_cardinality}:
                reasons.append(f"{profile.profile_id} has unknown join cardinality")
            if join.fanout_state == "unknown":
                reasons.append(f"{profile.profile_id} has unknown fanout behavior")
    elif dimension == "time":
        if not profile.time.timezone or not profile.time.date_boundary_semantics:
            reasons.append(f"{profile.profile_id} has incomplete time semantics")
    elif dimension == "security":
        if profile.security.derived_field_exposure == "unknown":
            reasons.append(f"{profile.profile_id} has unknown derived-field exposure")
    elif dimension == "operations":
        if profile.operations.update_mode == "unknown" or not profile.operations.owner_refs:
            reasons.append(f"{profile.profile_id} has incomplete operational semantics")
    return tuple(sorted(set(reasons)))


def _generic_dimension_assessment(
    left: SemanticProfile,
    right: SemanticProfile,
    *,
    dimension: str,
    required: bool,
    mapping: RepositoryAssetMapping | None,
) -> DimensionAssessment:
    refs = _combined_refs(left, right, dimension)
    if mapping is not None and dimension in {"lineage", "joins", "security"}:
        refs = tuple(sorted(set(refs + mapping.evidence_refs)))
    unknowns = _unknown_dimension_reasons(left, dimension) + _unknown_dimension_reasons(
        right, dimension
    )
    if unknowns:
        return _assessment(
            dimension=dimension,
            required=required,
            verdict="unknown",
            confidence=0,
            methods=("dimension_hash",),
            evidence_refs=refs,
            counterevidence=unknowns,
        )
    if left.dimension_hashes[dimension] == right.dimension_hashes[dimension]:
        return _assessment(
            dimension=dimension,
            required=required,
            verdict="exact",
            confidence=100,
            methods=("dimension_hash",),
            evidence_refs=refs,
        )
    left_semantics = _semantic_dimension_value(
        left, dimension, mapping=mapping, source=True
    )
    right_semantics = _semantic_dimension_value(right, dimension, mapping=mapping)
    if left_semantics == right_semantics:
        return _assessment(
            dimension=dimension,
            required=required,
            verdict="equivalent_with_constraints",
            confidence=95,
            methods=("dimension_hash",),
            evidence_refs=refs,
            counterevidence=(f"{dimension} evidence provenance or source identities differ",),
            constraints=(
                "structural comparison ignores evidence locations while profile revisions remain bound",
            ),
        )
    return _assessment(
        dimension=dimension,
        required=required,
        verdict="different",
        confidence=100,
        methods=("dimension_hash",),
        evidence_refs=refs,
        counterevidence=(f"{dimension} fingerprints and preserved semantics differ",),
    )


def _consumer_assessment(
    left: SemanticProfile,
    right: SemanticProfile,
    *,
    consumer_map: Mapping[str, str | None],
    required: bool,
) -> tuple[DimensionAssessment, ConsumerScope]:
    left_consumers = tuple(sorted(set(left.consumers)))
    right_consumers = tuple(sorted(set(right.consumers)))
    right_set = set(right_consumers)
    preserved: list[str] = []
    lost: list[str] = []
    for consumer in left_consumers:
        target = consumer_map.get(consumer)
        if target and target in right_set:
            preserved.append(consumer)
        else:
            lost.append(consumer)
    scope = ConsumerScope(
        left_consumer_ids=left_consumers,
        right_consumer_ids=right_consumers,
        preserved_consumer_ids=tuple(preserved),
        lost_consumer_ids=tuple(lost),
    )
    refs = _combined_refs(left, right, "consumers")
    if lost:
        return (
            _assessment(
                dimension="consumers",
                required=required,
                verdict="different",
                confidence=100,
                methods=("dimension_hash",),
                evidence_refs=refs,
                counterevidence=tuple(f"source consumer is not preserved: {item}" for item in lost),
            ),
            scope,
        )
    return (
        _assessment(
            dimension="consumers",
            required=required,
            verdict="exact",
            confidence=100,
            methods=("dimension_hash",),
            evidence_refs=refs,
            constraints=("consumer equivalence is directional from left/source to right/target",),
        ),
        scope,
    )


def _join_vetoes(
    left: SemanticProfile,
    right: SemanticProfile,
    mapping: RepositoryAssetMapping | None,
) -> set[HardVetoCode]:
    vetoes: set[HardVetoCode] = set()
    for profile in (left, right):
        for join in profile.joins:
            if (
                join.declared_cardinality == "unknown"
                or join.observed_cardinality == "unknown"
                or join.declared_cardinality != join.observed_cardinality
            ):
                vetoes.add("cardinality_unknown_or_incompatible")
            if join.fanout_state in {"failed", "unknown"}:
                vetoes.add("fanout_failed_or_unknown")
    if _semantic_dimension_value(
        left, "joins", mapping=mapping, source=True
    ) != _semantic_dimension_value(right, "joins", mapping=mapping):
        vetoes.add("cardinality_unknown_or_incompatible")
    return vetoes


def _hard_vetoes(
    left: SemanticProfile,
    right: SemanticProfile,
    *,
    dependency_closure_complete: bool,
    consumer_scope: ConsumerScope,
    left_validation_errors: Collection[str],
    right_validation_errors: Collection[str],
    expected_left_profile_fingerprint: str,
    expected_right_profile_fingerprint: str,
    bounded: BoundedBehavioralEvidence | None,
    validation_context: AssessmentValidationContext,
    asset_mapping: RepositoryAssetMapping | None,
) -> tuple[HardVetoCode, ...]:
    vetoes: set[HardVetoCode] = set()
    if left_validation_errors or right_validation_errors:
        vetoes.add("profile_revision_stale")
    if (
        left.profile_hash != expected_left_profile_fingerprint
        or right.profile_hash != expected_right_profile_fingerprint
    ):
        vetoes.add("profile_revision_stale")
    if bounded and (
        bounded.source_profile_fingerprint != left.profile_hash
        or bounded.target_profile_fingerprint != right.profile_hash
        or bounded.fixture_bundle_hash != validation_context.fixture_bundle.artifact_hash
    ):
        vetoes.add("profile_revision_stale")
    if asset_mapping and (
        asset_mapping.source_profile_fingerprint != left.profile_hash
        or asset_mapping.target_profile_fingerprint != right.profile_hash
    ):
        vetoes.add("profile_revision_stale")
    if not dependency_closure_complete:
        vetoes.add("dependency_closure_incomplete")
    if any(
        profile.definition.state != "complete"
        or profile.definition.canonical_state != "supported"
        for profile in (left, right)
    ):
        vetoes.add("definition_incomplete")

    for profile in (left, right):
        if (
            profile.grain.state != "known"
            or not profile.grain.description
            or not profile.grain.row_universe
        ):
            vetoes.add("grain_unknown_or_incompatible")
        if not profile.grain.key_fields or not profile.grain.uniqueness_evidence_refs:
            vetoes.add("key_unknown_or_incompatible")
    if (
        left.grain.description != right.grain.description
        or left.grain.row_universe != right.grain.row_universe
    ):
        vetoes.add("grain_unknown_or_incompatible")
    if left.grain.key_fields != right.grain.key_fields:
        vetoes.add("key_unknown_or_incompatible")

    vetoes.update(_join_vetoes(left, right, asset_mapping))

    for profile in (left, right):
        if profile.aggregation.state in {"unknown", "conflict"} or profile.aggregation.stage in {
            "unknown",
        }:
            vetoes.add("aggregation_context_mismatch")
        if profile.aggregation.distinct_mode == "unknown" or not profile.aggregation.null_semantics:
            vetoes.add("null_or_distinct_semantics_mismatch")
    aggregation_context = (
        "stage",
        "grouping_fields",
        "partition_fields",
        "order_fields",
        "window_frame",
    )
    if any(
        getattr(left.aggregation, field) != getattr(right.aggregation, field)
        for field in aggregation_context
    ):
        vetoes.add("aggregation_context_mismatch")
    if (
        left.aggregation.distinct_mode != right.aggregation.distinct_mode
        or left.aggregation.null_semantics != right.aggregation.null_semantics
    ):
        vetoes.add("null_or_distinct_semantics_mismatch")

    for profile in (left, right):
        if profile.filters.state in {"unknown", "conflict"} or profile.filters.stage == "unknown":
            vetoes.add("filter_context_mismatch")
        if profile.filters.scope == "unknown":
            vetoes.add("filter_context_mismatch")
    if _semantic_dimension_value(left, "filters") != _semantic_dimension_value(
        right, "filters"
    ):
        vetoes.add("filter_context_mismatch")

    for profile in (left, right):
        if (
            profile.time.state in {"unknown", "conflict"}
            or not profile.time.timezone
            or not profile.time.date_boundary_semantics
            or not profile.time.late_arriving_behavior
        ):
            vetoes.add("time_semantics_mismatch")
    if _semantic_dimension_value(left, "time") != _semantic_dimension_value(right, "time"):
        vetoes.add("time_semantics_mismatch")

    for profile in (left, right):
        if profile.security.state in {"unknown", "conflict"}:
            vetoes.add("security_domain_mismatch")
        if profile.security.state == "known" and not profile.security.security_domain:
            vetoes.add("security_domain_mismatch")
        if profile.security.derived_field_exposure == "leakage_risk":
            vetoes.add("derived_field_leakage_risk")
        if profile.security.derived_field_exposure == "unknown":
            vetoes.add("security_domain_mismatch")
    if left.security.security_domain != right.security.security_domain:
        vetoes.add("security_domain_mismatch")
    left_security = _semantic_dimension_value(
        left, "security", mapping=asset_mapping, source=True
    )
    right_security = _semantic_dimension_value(right, "security", mapping=asset_mapping)
    if (
        left_security["pdp_policy_refs"] != right_security["pdp_policy_refs"]
        or left_security["masking_policy_refs"] != right_security["masking_policy_refs"]
        or left_security["principal_precedence"] != right_security["principal_precedence"]
    ):
        vetoes.add("pdp_or_masking_mismatch")
    if left.security.derived_field_exposure != right.security.derived_field_exposure:
        vetoes.add("derived_field_leakage_risk")

    for profile in (left, right):
        operations = profile.operations
        if (
            operations.state in {"unknown", "conflict"}
            or operations.update_mode == "unknown"
            or not operations.freshness_sla
            or not operations.history_behavior
            or not operations.backfill_behavior
        ):
            vetoes.add("freshness_or_history_mismatch")
        if not operations.owner_refs or not operations.sla_ref:
            vetoes.add("owner_or_sla_missing")
    operational_fields = (
        "update_mode",
        "watermark_field",
        "freshness_sla",
        "history_behavior",
        "backfill_behavior",
    )
    if any(
        getattr(left.operations, field) != getattr(right.operations, field)
        for field in operational_fields
    ):
        vetoes.add("freshness_or_history_mismatch")
    if left.operations.owner_refs != right.operations.owner_refs:
        vetoes.add("owner_or_sla_missing")

    if left.side_effects or right.side_effects:
        vetoes.add("side_effects_present")
    if consumer_scope.lost_consumer_ids:
        vetoes.add("consumer_behavior_lost")
    return tuple(sorted(vetoes))


def assess_pairwise_equivalence(
    source: SemanticProfile,
    target: SemanticProfile,
    *,
    expected_source_profile_fingerprint: str,
    expected_target_profile_fingerprint: str,
    validation_context: AssessmentValidationContext | Mapping[str, Any],
    consumer_map: Mapping[str, str | None],
    bounded_behavioral_evidence: BoundedBehavioralEvidence | None = None,
    asset_mapping: RepositoryAssetMapping | None = None,
    required_dimensions: Collection[str] = REQUIRED_DIMENSIONS,
    provenance: Mapping[str, Any] | None = None,
    security: Mapping[str, Any] | None = None,
) -> EquivalenceAssessment:
    """Assess whether ``target`` can replace ``source`` for the declared consumer scope.

    The assessment is pairwise and directional.  It is not a union operation and
    intentionally exposes no API for transitive clustering.
    """

    required = set(required_dimensions)
    unknown_dimensions = required.difference(DIMENSIONS)
    if unknown_dimensions:
        raise ValueError(f"unknown required dimensions: {sorted(unknown_dimensions)}")
    if source.run_id != target.run_id or source.scope_id != target.scope_id:
        raise ValueError("pairwise profiles must belong to the same run and scope")
    source_consumers = set(source.consumers)
    if set(consumer_map) != source_consumers:
        raise ValueError("consumer_map must bind every and only source consumer")
    target_consumers = set(target.consumers)
    if any(value is not None and value not in target_consumers for value in consumer_map.values()):
        raise ValueError("consumer_map targets must be current target consumers or null")
    mapped_targets = [value for value in consumer_map.values() if value is not None]
    if len(mapped_targets) != len(set(mapped_targets)):
        raise ValueError(
            "consumer_map must be injective unless a separately approved many-to-one "
            "consumer redesign is represented as distinct target contracts"
        )
    context = finalize_validation_context(validation_context)
    effective_mapping = asset_mapping
    if asset_mapping and (
        asset_mapping.source_profile_fingerprint != source.profile_hash
        or asset_mapping.target_profile_fingerprint != target.profile_hash
    ):
        effective_mapping = None

    left_errors = validate_semantic_profile(source)
    right_errors = validate_semantic_profile(target)
    dimensions: list[DimensionAssessment] = []
    effective_bounded_evidence = bounded_behavioral_evidence
    if bounded_behavioral_evidence and (
        bounded_behavioral_evidence.fixture_bundle_hash
        != context.fixture_bundle.artifact_hash
    ):
        effective_bounded_evidence = None
    definition, used_bounded_evidence = _definition_assessment(
        source,
        target,
        required="definition" in required,
        bounded=effective_bounded_evidence,
        mapping=effective_mapping,
    )
    dimensions.append(definition)
    for dimension in (
        "grain",
        "lineage",
        "aggregation",
        "filters",
        "joins",
        "time",
        "security",
        "operations",
    ):
        dimensions.append(
            _generic_dimension_assessment(
                source,
                target,
                dimension=dimension,
                required=dimension in required,
                mapping=effective_mapping,
            )
        )
    consumers, consumer_scope = _consumer_assessment(
        source,
        target,
        consumer_map=consumer_map,
        required="consumers" in required,
    )
    dimensions.append(consumers)
    dimensions.append(
        _generic_dimension_assessment(
            source,
            target,
            dimension="side_effects",
            required="side_effects" in required,
            mapping=effective_mapping,
        )
    )
    ordered_dimensions = tuple(
        sorted(dimensions, key=lambda item: _DIMENSION_ORDER[item.dimension])
    )
    vetoes = _hard_vetoes(
        source,
        target,
        dependency_closure_complete=context.inventory_closure.status == "complete",
        consumer_scope=consumer_scope,
        left_validation_errors=left_errors,
        right_validation_errors=right_errors,
        expected_left_profile_fingerprint=expected_source_profile_fingerprint,
        expected_right_profile_fingerprint=expected_target_profile_fingerprint,
        bounded=bounded_behavioral_evidence,
        validation_context=context,
        asset_mapping=asset_mapping,
    )
    methods: set[CandidateMethod] = {
        "canonical_definition_hash",
        "dimension_signature",
        "consumer_overlap",
    }
    if source.profile_hash == target.profile_hash:
        methods.add("exact_profile_hash")
    if _semantic_dimension_value(
        source, "lineage", mapping=effective_mapping, source=True
    ) == _semantic_dimension_value(target, "lineage", mapping=effective_mapping):
        methods.add("lineage_overlap")
    if effective_mapping is not None:
        methods.add("repository_mapping")
    if used_bounded_evidence:
        methods.add("bounded_query")
    category = _derive_overall_category(ordered_dimensions, vetoes, tuple(sorted(methods)))
    confidence = min(item.confidence for item in ordered_dimensions if item.required)
    if category in {"different", "unknown"}:
        direction: AssessmentDirection = "none" if category == "different" else "unknown"
    elif source.profile_hash == target.profile_hash:
        direction = "bidirectional"
    else:
        direction = "right_substitutes_left"
    seed = {
        "run_id": source.run_id,
        "scope_id": source.scope_id,
        "left_profile_hash": source.profile_hash,
        "right_profile_hash": target.profile_hash,
        "direction": direction,
        "consumer_scope": consumer_scope.model_dump(mode="json"),
        "consumer_map_hash": consumer_map_hash(consumer_map),
        "validation_context_hash": context.context_hash,
        "asset_mapping": (
            effective_mapping.model_dump(mode="json") if effective_mapping is not None else None
        ),
    }
    draft: dict[str, Any] = {
        "assessment_id": f"eqv-{sha256_json(seed)[:24]}",
        "run_id": source.run_id,
        "scope_id": source.scope_id,
        "left_profile": _profile_reference(source).model_dump(mode="json"),
        "right_profile": _profile_reference(target).model_dump(mode="json"),
        "direction": direction,
        "candidate_methods": sorted(methods),
        "dimensions": [item.model_dump(mode="json") for item in ordered_dimensions],
        "overall_category": category,
        "overall_confidence": confidence,
        "hard_vetoes": list(vetoes),
        "consumer_scope": consumer_scope.model_dump(mode="json"),
        "consumer_map_hash": consumer_map_hash(consumer_map),
        "validation_context": context.model_dump(mode="json"),
        "proposal_only": True,
        "authorizes_consolidation": False,
        "assessment_hash": "sha256:" + "0" * 64,
        "immutable": True,
        "provenance": dict(provenance or {}),
        "security": dict(security or {}),
    }
    return finalize_equivalence_assessment(draft)


def reproduce_equivalence_assessment(
    assessment: EquivalenceAssessment,
    *,
    source: SemanticProfile,
    target: SemanticProfile,
    consumer_map: Mapping[str, str | None],
    current_validation_context: AssessmentValidationContext | Mapping[str, Any],
    bounded_behavioral_evidence: BoundedBehavioralEvidence | None = None,
    asset_mapping: RepositoryAssetMapping | None = None,
) -> EquivalenceAssessment:
    """Recompute an assessment from current deterministic inputs.

    Callers must resolve repository mappings and bounded fixtures from the
    current validation context; persisted verdicts are never treated as proof.
    The recorded provenance/security metadata is retained because it is not an
    equivalence input, while every semantic verdict, veto, direction, evidence
    binding, identity, and hash is regenerated.
    """

    required_dimensions = tuple(
        item.dimension for item in assessment.dimensions if item.required
    )
    return assess_pairwise_equivalence(
        source,
        target,
        expected_source_profile_fingerprint=source.profile_hash,
        expected_target_profile_fingerprint=target.profile_hash,
        validation_context=current_validation_context,
        consumer_map=consumer_map,
        bounded_behavioral_evidence=bounded_behavioral_evidence,
        asset_mapping=asset_mapping,
        required_dimensions=required_dimensions,
        provenance=assessment.provenance,
        security=assessment.security,
    )


__all__ = [
    "AssessmentValidationContext",
    "AssessmentDirection",
    "BoundedBehavioralEvidence",
    "CandidateMethod",
    "ConsumerScope",
    "DimensionAssessment",
    "DimensionName",
    "DimensionVerdict",
    "EquivalenceAssessment",
    "EquivalenceCategory",
    "EvidenceMethod",
    "HardVetoCode",
    "InventoryClosureReference",
    "ProfileReference",
    "ValidationArtifactReference",
    "REQUIRED_DIMENSIONS",
    "RepositoryAssetMapping",
    "assess_pairwise_equivalence",
    "consumer_map_hash",
    "equivalence_assessment_invalidation_reasons",
    "equivalence_assessment_hash",
    "finalize_validation_context",
    "finalize_equivalence_assessment",
    "reproduce_equivalence_assessment",
    "validate_equivalence_assessment",
    "validate_validation_context",
    "validation_context_hash",
]

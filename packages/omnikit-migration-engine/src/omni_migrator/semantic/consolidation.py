"""Proposal and human-decision controls for semantic consolidation."""

from __future__ import annotations

from collections.abc import Collection, Mapping
from copy import deepcopy
from datetime import datetime, timezone
import re
from typing import Any, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field, model_validator

from omni_migrator.control_plane.canonical import sha256_json
from omni_migrator.semantic.equivalence import (
    AssessmentValidationContext,
    BoundedBehavioralEvidence,
    EquivalenceAssessment,
    EquivalenceCategory,
    HardVetoCode,
    REQUIRED_DIMENSIONS,
    RepositoryAssetMapping,
    consumer_map_hash,
    reproduce_equivalence_assessment,
    validate_validation_context,
    validate_equivalence_assessment,
)
from omni_migrator.semantic.models import SemanticProfile
from omni_migrator.semantic.profiles import validate_semantic_profile

ApprovalRole = Literal["business", "security", "operations"]
DecisionStatus = Literal["proposed", "approved", "rejected", "superseded", "invalidated"]
Disposition = Literal["reuse", "merge", "parameterize", "split", "retire", "manual_review"]
RetirementState = Literal[
    "not_applicable",
    "candidate_only",
    "replacement_accepted",
    "cutover_complete",
    "hypercare_complete",
]
_ROLE_ORDER = {"business": 0, "security": 1, "operations": 2}
_SHA256_PATTERN = r"^sha256:[a-f0-9]{64}$"
_STABLE_ID_PATTERN = r"^[a-z0-9][a-z0-9._-]{7,127}$"
_ACTOR_REF_PATTERN = r"^(?:agent-ref|human-ref|person-ref|person):.+$"
_HUMAN_REF_PATTERN = r"^(?:human-ref|person-ref|person):.+$"
_REFERENCE_PATTERN = r"^[A-Za-z][A-Za-z0-9+.-]*:.+$"
_SECRET_REF_PREFIXES = ("secret:", "vault:", "credential:")


def _assert_non_secret_ref(value: str, field_name: str) -> None:
    if value.lower().startswith(_SECRET_REF_PREFIXES):
        raise ValueError(f"{field_name} must be a non-secret reference")


class _FrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ConsolidationCandidate(_FrozenModel):
    """Internal, non-authorizing output from one directional assessment."""

    contract_version: Literal["domo-to-omni.consolidation-candidate.v1"] = (
        "domo-to-omni.consolidation-candidate.v1"
    )
    candidate_id: str = Field(pattern=_STABLE_ID_PATTERN)
    run_id: str = Field(pattern=_STABLE_ID_PATTERN)
    scope_id: str = Field(pattern=_STABLE_ID_PATTERN)
    scope_ref: str = Field(pattern=_REFERENCE_PATTERN)
    assessment_id: str = Field(pattern=_STABLE_ID_PATTERN)
    assessment_fingerprint: str = Field(pattern=_SHA256_PATTERN)
    assessment_category: EquivalenceCategory
    assessment_confidence: int = Field(ge=0, le=100)
    source_profile_id: str = Field(pattern=_STABLE_ID_PATTERN)
    target_profile_id: str = Field(pattern=_STABLE_ID_PATTERN)
    source_profile_fingerprint: str = Field(pattern=_SHA256_PATTERN)
    target_profile_fingerprint: str = Field(pattern=_SHA256_PATTERN)
    consumer_map: dict[str, str | None]
    hard_vetoes: tuple[HardVetoCode, ...]
    proposed_by_ref: str = Field(pattern=_ACTOR_REF_PATTERN)
    eligible_for_decision: bool
    proposal_only: Literal[True] = True
    authorizes_build: Literal[False] = False
    authorizes_source_decommission: Literal[False] = False
    candidate_hash: str = Field(pattern=_SHA256_PATTERN)
    immutable: Literal[True] = True

    @model_validator(mode="after")
    def proposal_never_authorizes_work(self) -> "ConsolidationCandidate":
        _assert_non_secret_ref(self.scope_ref, "scope_ref")
        expected = not self.hard_vetoes and self.assessment_category != "unknown"
        if self.eligible_for_decision != expected:
            raise ValueError("candidate eligibility must be derived from vetoes and assessment state")
        if len(self.hard_vetoes) != len(set(self.hard_vetoes)):
            raise ValueError("candidate hard vetoes must be unique")
        if self.assessment_category == "approved_semantic_substitution":
            raise ValueError("a candidate cannot pre-approve a semantic substitution")
        return self


class DecisionProfileRef(_FrozenModel):
    profile_id: str = Field(pattern=_STABLE_ID_PATTERN)
    asset_id: str = Field(min_length=1)
    profile_hash: str = Field(pattern=_SHA256_PATTERN)


class DecisionAssessmentRef(_FrozenModel):
    assessment_id: str = Field(pattern=_STABLE_ID_PATTERN)
    assessment_hash: str = Field(pattern=_SHA256_PATTERN)
    overall_category: EquivalenceCategory


class DecisionCandidateRef(_FrozenModel):
    """Immutable binding from a decision to one exact pairwise proposal."""

    candidate_id: str = Field(pattern=_STABLE_ID_PATTERN)
    candidate_hash: str = Field(pattern=_SHA256_PATTERN)
    assessment_id: str = Field(pattern=_STABLE_ID_PATTERN)
    assessment_hash: str = Field(pattern=_SHA256_PATTERN)
    source_profile_hash: str = Field(pattern=_SHA256_PATTERN)
    target_profile_hash: str = Field(pattern=_SHA256_PATTERN)
    consumer_map_hash: str = Field(pattern=_SHA256_PATTERN)
    scope_ref: str = Field(pattern=_REFERENCE_PATTERN)

    @model_validator(mode="after")
    def scope_is_non_secret(self) -> "DecisionCandidateRef":
        _assert_non_secret_ref(self.scope_ref, "scope_ref")
        return self


class DecisionImpact(_FrozenModel):
    business_semantics_changed: bool
    security_changed: bool
    freshness_history_or_sla_changed: bool
    side_effects_changed: bool
    consumer_behavior_changed: bool


class DecisionApproval(_FrozenModel):
    role: ApprovalRole
    decision_ref: str = Field(pattern=_REFERENCE_PATTERN)
    approver_ref: str = Field(pattern=_HUMAN_REF_PATTERN)
    canonical_actor_ref: str = Field(pattern=_HUMAN_REF_PATTERN)
    issuer_ref: str = Field(pattern=_ACTOR_REF_PATTERN)
    approval_receipt_ref: str = Field(pattern=_REFERENCE_PATTERN)
    approval_receipt_hash: str = Field(pattern=_SHA256_PATTERN)
    authority_policy_ref: str = Field(pattern=_REFERENCE_PATTERN)
    authority_policy_hash: str = Field(pattern=_SHA256_PATTERN)
    approved_at: datetime
    scope_hash: str = Field(pattern=_SHA256_PATTERN)
    validation_cycle_id: str = Field(pattern=_STABLE_ID_PATTERN)

    @model_validator(mode="after")
    def approval_is_human_and_clocked(self) -> "DecisionApproval":
        if self.approved_at.tzinfo is None:
            raise ValueError("approval timestamp must include a timezone")
        _assert_non_secret_ref(self.decision_ref, "decision_ref")
        _assert_non_secret_ref(self.approval_receipt_ref, "approval_receipt_ref")
        _assert_non_secret_ref(self.authority_policy_ref, "authority_policy_ref")
        return self


class ApprovalReceipt(_FrozenModel):
    """Content-addressed approval payload; authenticity requires a verifier."""

    contract_version: Literal["domo-to-omni.approval-receipt.v1"] = (
        "domo-to-omni.approval-receipt.v1"
    )
    approval_receipt_ref: str = Field(pattern=_REFERENCE_PATTERN)
    role: ApprovalRole
    decision_ref: str = Field(pattern=_REFERENCE_PATTERN)
    approver_ref: str = Field(pattern=_HUMAN_REF_PATTERN)
    canonical_actor_ref: str = Field(pattern=_HUMAN_REF_PATTERN)
    issuer_ref: str = Field(pattern=_ACTOR_REF_PATTERN)
    approved_at: datetime
    scope_hash: str = Field(pattern=_SHA256_PATTERN)
    validation_cycle_id: str = Field(pattern=_STABLE_ID_PATTERN)
    authority_policy_ref: str = Field(pattern=_REFERENCE_PATTERN)
    authority_policy_hash: str = Field(pattern=_SHA256_PATTERN)
    receipt_hash: str = Field(pattern=_SHA256_PATTERN)
    immutable: Literal[True] = True

    @model_validator(mode="after")
    def receipt_is_human_and_clocked(self) -> "ApprovalReceipt":
        if self.approved_at.tzinfo is None:
            raise ValueError("approval receipt timestamp must include a timezone")
        _assert_non_secret_ref(self.approval_receipt_ref, "approval_receipt_ref")
        _assert_non_secret_ref(self.decision_ref, "decision_ref")
        _assert_non_secret_ref(self.authority_policy_ref, "authority_policy_ref")
        return self


class ApprovalAuthorityPolicy(_FrozenModel):
    """Signed owner and identity policy resolved independently of a decision."""

    contract_version: Literal["domo-to-omni.approval-authority-policy.v1"] = (
        "domo-to-omni.approval-authority-policy.v1"
    )
    policy_ref: str = Field(pattern=_REFERENCE_PATTERN)
    revision: str = Field(min_length=1)
    role_owners: dict[ApprovalRole, tuple[str, ...]]
    canonical_actor_aliases: dict[str, str]
    trusted_issuer_refs: tuple[str, ...] = Field(min_length=1)
    policy_hash: str = Field(pattern=_SHA256_PATTERN)
    immutable: Literal[True] = True

    @model_validator(mode="after")
    def policy_is_complete_and_canonical(self) -> "ApprovalAuthorityPolicy":
        _assert_non_secret_ref(self.policy_ref, "policy_ref")
        if set(self.role_owners) != {"business", "security", "operations"}:
            raise ValueError("authority policy requires exactly the three approval roles")
        known_owners: set[str] = set()
        for role, owners in self.role_owners.items():
            if not owners or len(owners) != len(set(owners)):
                raise ValueError(f"authority policy owners must be non-empty and unique: {role}")
            if any(re.fullmatch(_HUMAN_REF_PATTERN, owner) is None for owner in owners):
                raise ValueError(f"authority policy owners must be human identities: {role}")
            known_owners.update(owners)
        if len(self.trusted_issuer_refs) != len(set(self.trusted_issuer_refs)):
            raise ValueError("trusted approval issuers must be unique")
        if any(not alias or not canonical for alias, canonical in self.canonical_actor_aliases.items()):
            raise ValueError("canonical actor aliases cannot be empty")
        if any(
            re.fullmatch(_HUMAN_REF_PATTERN, alias) is None
            or re.fullmatch(_HUMAN_REF_PATTERN, canonical) is None
            for alias, canonical in self.canonical_actor_aliases.items()
        ):
            raise ValueError("canonical actor aliases must bind human identities")
        if any(canonical not in known_owners for canonical in self.canonical_actor_aliases.values()):
            raise ValueError("canonical actor aliases must resolve to an authorized owner")
        aliases = set(self.canonical_actor_aliases)
        if aliases.intersection(self.canonical_actor_aliases.values()):
            raise ValueError("canonical actor aliases cannot contain chains or cycles")
        if aliases.intersection(known_owners):
            raise ValueError("alias identities cannot also be canonical approval owners")
        return self


class ApprovalAuthorityTrustAnchor(_FrozenModel):
    """Control-plane trust root supplied independently from decision evidence."""

    contract_version: Literal["domo-to-omni.approval-authority-trust-anchor.v1"] = (
        "domo-to-omni.approval-authority-trust-anchor.v1"
    )
    anchor_ref: str = Field(pattern=_REFERENCE_PATTERN)
    authority_policy_ref: str = Field(pattern=_REFERENCE_PATTERN)
    authority_policy_hash: str = Field(pattern=_SHA256_PATTERN)
    authority_policy_revision: str = Field(min_length=1)
    trusted_issuer_refs: tuple[str, ...] = Field(min_length=1)
    anchor_hash: str = Field(pattern=_SHA256_PATTERN)
    immutable: Literal[True] = True

    @model_validator(mode="after")
    def trust_anchor_is_canonical(self) -> "ApprovalAuthorityTrustAnchor":
        _assert_non_secret_ref(self.anchor_ref, "anchor_ref")
        _assert_non_secret_ref(self.authority_policy_ref, "authority_policy_ref")
        if len(self.trusted_issuer_refs) != len(set(self.trusted_issuer_refs)):
            raise ValueError("trust-anchor issuers must be unique")
        if any(
            re.fullmatch(_ACTOR_REF_PATTERN, issuer_ref) is None
            for issuer_ref in self.trusted_issuer_refs
        ):
            raise ValueError("trust-anchor issuers must be actor references")
        return self


class AssessmentEvidenceResolver(Protocol):
    """Trusted registry resolver for current execution and actor evidence.

    Implementations are control-plane dependencies.  They must resolve actor
    identities from immutable registry/audit evidence keyed by the stable
    artifact identity and validation context, never from the artifact payload
    being validated.
    """

    def resolve_repository_mapping(
        self,
        *,
        source: SemanticProfile,
        target: SemanticProfile,
        validation_context: AssessmentValidationContext,
    ) -> RepositoryAssetMapping | None: ...

    def resolve_bounded_behavioral_evidence(
        self,
        *,
        source: SemanticProfile,
        target: SemanticProfile,
        validation_context: AssessmentValidationContext,
    ) -> BoundedBehavioralEvidence | None: ...

    def resolve_consumer_map(
        self,
        *,
        source: SemanticProfile,
        target: SemanticProfile,
        validation_context: AssessmentValidationContext,
    ) -> Mapping[str, str | None] | None:
        """Return the exact map accepted by the current consumer-contract set."""
        ...

    def resolve_assessment_producer_refs(
        self,
        *,
        source: SemanticProfile,
        target: SemanticProfile,
        validation_context: AssessmentValidationContext,
    ) -> Collection[str] | None:
        """Return producer identities from trusted assessment-registry evidence."""
        ...

    def resolve_profile_producer_refs(
        self,
        *,
        profile_id: str,
        validation_context: AssessmentValidationContext,
    ) -> Collection[str] | None:
        """Return profile producers from trusted artifact-registry evidence."""
        ...

    def resolve_candidate_proposer_refs(
        self,
        *,
        candidate_id: str,
        validation_context: AssessmentValidationContext,
    ) -> Collection[str] | None:
        """Return candidate proposers from trusted artifact-registry evidence."""
        ...

    def resolve_decision_proposer_refs(
        self,
        *,
        decision_id: str,
        validation_context: AssessmentValidationContext,
    ) -> Collection[str] | None:
        """Return decision proposers from trusted artifact-registry evidence."""
        ...


class ApprovalReceiptVerifier(Protocol):
    """Trusted ledger or signature verifier; never supplied by a decision producer."""

    def resolve_verified_receipt(
        self,
        *,
        receipt_ref: str,
        expected_receipt_hash: str,
        expected_issuer_ref: str,
    ) -> ApprovalReceipt | None:
        """Return current ledger evidence only after authenticity verification."""
        ...


class DecisionApprovals(_FrozenModel):
    business: DecisionApproval | None
    security: DecisionApproval | None
    operations: DecisionApproval | None


class ConsolidationDecision(_FrozenModel):
    """Runtime model matching ``consolidation-decision.v1.schema.json`` exactly."""

    contract_version: Literal["domo-to-omni.consolidation-decision.v1"] = (
        "domo-to-omni.consolidation-decision.v1"
    )
    decision_id: str = Field(pattern=_STABLE_ID_PATTERN)
    run_id: str = Field(pattern=_STABLE_ID_PATTERN)
    scope_id: str = Field(pattern=_STABLE_ID_PATTERN)
    validation_cycle_id: str = Field(pattern=_STABLE_ID_PATTERN)
    group_id: str = Field(pattern=_STABLE_ID_PATTERN)
    status: DecisionStatus
    disposition: Disposition
    classification: EquivalenceCategory
    member_profiles: tuple[DecisionProfileRef, ...] = Field(min_length=1)
    candidate_refs: tuple[DecisionCandidateRef, ...] = Field(min_length=1)
    assessment_refs: tuple[DecisionAssessmentRef, ...]
    canonical_target_profile: DecisionProfileRef | None
    affected_consumer_ids: tuple[str, ...]
    accepted_differences: tuple[str, ...]
    impact: DecisionImpact
    approvals: DecisionApprovals
    validation_context: AssessmentValidationContext
    proposed_by_ref: str = Field(pattern=_ACTOR_REF_PATTERN)
    input_fingerprint: str = Field(pattern=_SHA256_PATTERN)
    decision_hash: str = Field(pattern=_SHA256_PATTERN)
    retirement_state: RetirementState
    authorizes_build: bool
    authorizes_source_decommission: Literal[False] = False
    invalidated_by: tuple[str, ...]
    rollback_plan: str = Field(min_length=1)
    residual_risks: tuple[str, ...]
    immutable: Literal[True] = True
    provenance: dict[str, Any]
    security: dict[str, Any]

    @model_validator(mode="after")
    def contract_invariants(self) -> "ConsolidationDecision":
        members = [item.model_dump_json() for item in self.member_profiles]
        candidates = [item.model_dump_json() for item in self.candidate_refs]
        assessments = [item.model_dump_json() for item in self.assessment_refs]
        if len(members) != len(set(members)):
            raise ValueError("member_profiles must be unique")
        if len(candidates) != len(set(candidates)):
            raise ValueError("candidate_refs must be unique")
        if len({item.candidate_id for item in self.candidate_refs}) != len(
            self.candidate_refs
        ):
            raise ValueError("candidate_refs must bind unique candidate IDs")
        if len(assessments) != len(set(assessments)):
            raise ValueError("assessment_refs must be unique")
        for field_name in (
            "affected_consumer_ids",
            "accepted_differences",
            "invalidated_by",
            "residual_risks",
        ):
            values = getattr(self, field_name)
            if len(values) != len(set(values)):
                raise ValueError(f"{field_name} must be unique")
        if self.status == "approved" and self.approvals.business is None:
            raise ValueError("approved decisions require business approval")
        for role, approval in (
            ("business", self.approvals.business),
            ("security", self.approvals.security),
            ("operations", self.approvals.operations),
        ):
            if approval is not None and approval.role != role:
                raise ValueError(f"approval role does not match its slot: {role}")
        if self.status != "approved" and self.authorizes_build:
            raise ValueError("only approved decisions may authorize a build")
        if self.validation_context.inventory_closure.status != "complete" and (
            self.status == "approved" or self.authorizes_build
        ):
            raise ValueError(
                "incomplete inventory closure cannot be approved or authorize a build"
            )
        if self.status == "approved" and self.invalidated_by:
            raise ValueError("approved decisions cannot carry invalidation reasons")
        if self.status in {"invalidated", "superseded"} and not self.invalidated_by:
            raise ValueError("invalidated or superseded decisions require a reason")
        if self.disposition == "manual_review" and (
            self.status == "approved" or self.authorizes_build
        ):
            raise ValueError("manual-review decisions cannot authorize a build")
        if self.disposition == "retire":
            if self.retirement_state != "candidate_only":
                raise ValueError("retire decisions remain candidate-only")
        elif self.retirement_state != "not_applicable":
            raise ValueError("non-retire decisions require not_applicable retirement state")
        if self.disposition == "retire" and self.authorizes_build:
            raise ValueError("retire decisions cannot authorize a build")
        if self.classification == "approved_semantic_substitution":
            if not self.accepted_differences:
                raise ValueError("semantic substitution requires accepted differences")
        if self.classification == "exact_definition" and self.accepted_differences:
            raise ValueError("exact definitions cannot carry accepted differences")
        if self.status == "approved" and self.disposition in {
            "reuse",
            "merge",
            "parameterize",
        }:
            if self.classification in {"different", "unknown"}:
                raise ValueError("an approved consolidation needs a positive classification")
        if self.status == "approved" and self.impact.security_changed:
            if self.approvals.security is None:
                raise ValueError("security changes require security approval")
        if self.status == "approved" and (
            self.impact.freshness_history_or_sla_changed or self.impact.side_effects_changed
        ):
            if self.approvals.operations is None:
                raise ValueError("operational changes require operations approval")
        return self


class ConsolidationDecisionValidation(_FrozenModel):
    valid: bool
    invalidated: bool
    errors: tuple[str, ...]
    invalidation_reasons: tuple[str, ...]
    required_roles: tuple[ApprovalRole, ...]
    approved_roles: tuple[ApprovalRole, ...]
    resolved_category: EquivalenceCategory | None
    authorizes_build: bool
    decision_fingerprint: str = Field(pattern=_SHA256_PATTERN)


def _sha256(value: Any) -> str:
    return f"sha256:{sha256_json(value)}"


def _without(value: Mapping[str, Any], *fields: str) -> dict[str, Any]:
    material = deepcopy(dict(value))
    for field in fields:
        material.pop(field, None)
    return material


def consolidation_candidate_hash(
    value: Mapping[str, Any] | ConsolidationCandidate,
) -> str:
    raw = value.model_dump(mode="json") if isinstance(value, ConsolidationCandidate) else value
    return _sha256(_without(raw, "candidate_hash"))


def consolidation_candidate_id(
    value: Mapping[str, Any] | ConsolidationCandidate,
) -> str:
    """Derive candidate identity from every decision-relevant immutable input."""

    raw = value.model_dump(mode="json") if isinstance(value, ConsolidationCandidate) else value
    seed = {
        "assessment_fingerprint": raw.get("assessment_fingerprint"),
        "source_profile_fingerprint": raw.get("source_profile_fingerprint"),
        "target_profile_fingerprint": raw.get("target_profile_fingerprint"),
        "consumer_map_hash": consumer_map_hash(raw.get("consumer_map", {})),
        "scope_ref": raw.get("scope_ref"),
    }
    return f"con-{sha256_json(seed)[:24]}"


def approval_authority_policy_hash(
    value: Mapping[str, Any] | ApprovalAuthorityPolicy,
) -> str:
    raw = value.model_dump(mode="json") if isinstance(value, ApprovalAuthorityPolicy) else value
    return _sha256(_without(raw, "policy_hash"))


def finalize_approval_authority_policy(
    value: Mapping[str, Any] | ApprovalAuthorityPolicy,
) -> ApprovalAuthorityPolicy:
    raw = value.model_dump(mode="json") if isinstance(value, ApprovalAuthorityPolicy) else value
    result = deepcopy(dict(raw))
    result.setdefault("contract_version", "domo-to-omni.approval-authority-policy.v1")
    result["role_owners"] = {
        role: sorted(set(owners))
        for role, owners in sorted(result.get("role_owners", {}).items())
    }
    result["canonical_actor_aliases"] = dict(
        sorted(result.get("canonical_actor_aliases", {}).items())
    )
    result["trusted_issuer_refs"] = sorted(set(result.get("trusted_issuer_refs", [])))
    result["policy_hash"] = approval_authority_policy_hash(result)
    return ApprovalAuthorityPolicy.model_validate(result)


def approval_authority_trust_anchor_hash(
    value: Mapping[str, Any] | ApprovalAuthorityTrustAnchor,
) -> str:
    raw = (
        value.model_dump(mode="json")
        if isinstance(value, ApprovalAuthorityTrustAnchor)
        else value
    )
    return _sha256(_without(raw, "anchor_hash"))


def finalize_approval_authority_trust_anchor(
    value: Mapping[str, Any] | ApprovalAuthorityTrustAnchor,
) -> ApprovalAuthorityTrustAnchor:
    raw = (
        value.model_dump(mode="json")
        if isinstance(value, ApprovalAuthorityTrustAnchor)
        else value
    )
    result = deepcopy(dict(raw))
    result.setdefault(
        "contract_version", "domo-to-omni.approval-authority-trust-anchor.v1"
    )
    result["trusted_issuer_refs"] = sorted(set(result.get("trusted_issuer_refs", [])))
    result["anchor_hash"] = approval_authority_trust_anchor_hash(result)
    return ApprovalAuthorityTrustAnchor.model_validate(result)


def approval_receipt_hash(value: Mapping[str, Any] | ApprovalReceipt) -> str:
    raw = value.model_dump(mode="json") if isinstance(value, ApprovalReceipt) else value
    return _sha256(_without(raw, "receipt_hash"))


def finalize_approval_receipt(
    value: Mapping[str, Any] | ApprovalReceipt,
) -> ApprovalReceipt:
    """Normalize a receipt content hash; this does not sign or authenticate it."""
    raw = value.model_dump(mode="json") if isinstance(value, ApprovalReceipt) else value
    result = deepcopy(dict(raw))
    result.setdefault("contract_version", "domo-to-omni.approval-receipt.v1")
    result["receipt_hash"] = "sha256:" + "0" * 64
    normalized = ApprovalReceipt.model_validate(result).model_dump(mode="json")
    normalized["receipt_hash"] = approval_receipt_hash(normalized)
    return ApprovalReceipt.model_validate(normalized)


def consolidation_input_fingerprint(
    value: Mapping[str, Any] | ConsolidationDecision,
) -> str:
    """Bind exact approved action and inputs while excluding only approval receipts."""

    raw = value.model_dump(mode="json") if isinstance(value, ConsolidationDecision) else dict(value)
    raw = _normalize_decision(raw)
    keys = (
        "contract_version",
        "decision_id",
        "run_id",
        "scope_id",
        "validation_cycle_id",
        "group_id",
        "status",
        "disposition",
        "classification",
        "member_profiles",
        "candidate_refs",
        "assessment_refs",
        "canonical_target_profile",
        "affected_consumer_ids",
        "accepted_differences",
        "impact",
        "validation_context",
        "proposed_by_ref",
        "retirement_state",
        "authorizes_build",
        "authorizes_source_decommission",
        "rollback_plan",
        "residual_risks",
        "provenance",
        "security",
    )
    return _sha256({key: raw.get(key) for key in keys})


def consolidation_decision_hash(
    value: Mapping[str, Any] | ConsolidationDecision,
) -> str:
    raw = value.model_dump(mode="json") if isinstance(value, ConsolidationDecision) else value
    return _sha256(_without(raw, "decision_hash"))


def finalize_consolidation_candidate(
    value: Mapping[str, Any] | ConsolidationCandidate,
) -> ConsolidationCandidate:
    raw = value.model_dump(mode="json") if isinstance(value, ConsolidationCandidate) else value
    result = deepcopy(dict(raw))
    result.setdefault("contract_version", "domo-to-omni.consolidation-candidate.v1")
    result["consumer_map"] = dict(sorted(result.get("consumer_map", {}).items()))
    result["hard_vetoes"] = sorted(set(result.get("hard_vetoes", [])))
    result["candidate_hash"] = consolidation_candidate_hash(result)
    candidate = ConsolidationCandidate.model_validate(result)
    errors = validate_consolidation_candidate(candidate)
    if errors:
        raise ValueError("; ".join(errors))
    return candidate


def validate_consolidation_candidate(
    value: Mapping[str, Any] | ConsolidationCandidate,
) -> list[str]:
    raw = value.model_dump(mode="json") if isinstance(value, ConsolidationCandidate) else value
    try:
        candidate = ConsolidationCandidate.model_validate(raw)
    except ValueError as exc:
        return [f"consolidation candidate is invalid: {exc}"]
    if candidate.candidate_hash != consolidation_candidate_hash(candidate):
        return ["candidate_hash does not match candidate content"]
    if candidate.candidate_id != consolidation_candidate_id(candidate):
        return ["candidate_id does not match candidate inputs"]
    return []


def propose_consolidation_candidate(
    assessment: EquivalenceAssessment,
    *,
    consumer_map: Mapping[str, str | None],
    proposed_by_ref: str,
    scope_ref: str,
) -> ConsolidationCandidate:
    """Create a proposal only; this function never authorizes build or retirement."""

    assessment_errors = validate_equivalence_assessment(assessment)
    if assessment_errors:
        raise ValueError("invalid equivalence assessment: " + "; ".join(assessment_errors))
    source_consumers = set(assessment.consumer_scope.left_consumer_ids)
    if set(consumer_map) != source_consumers:
        raise ValueError("consumer_map must bind every and only assessed source consumer")
    if consumer_map_hash(consumer_map) != assessment.consumer_map_hash:
        raise ValueError("consumer_map must match the map bound into the assessment")
    target_consumers = set(assessment.consumer_scope.right_consumer_ids)
    for source_consumer in assessment.consumer_scope.preserved_consumer_ids:
        if consumer_map.get(source_consumer) not in target_consumers:
            raise ValueError("consumer_map contradicts preserved consumer evidence")
    for source_consumer in assessment.consumer_scope.lost_consumer_ids:
        if consumer_map.get(source_consumer) in target_consumers:
            raise ValueError("consumer_map contradicts lost consumer evidence")
    draft: dict[str, Any] = {
        "candidate_id": "pending",
        "run_id": assessment.run_id,
        "scope_id": assessment.scope_id,
        "scope_ref": scope_ref,
        "assessment_id": assessment.assessment_id,
        "assessment_fingerprint": assessment.assessment_hash,
        "assessment_category": assessment.overall_category,
        "assessment_confidence": assessment.overall_confidence,
        "source_profile_id": assessment.left_profile.profile_id,
        "target_profile_id": assessment.right_profile.profile_id,
        "source_profile_fingerprint": assessment.left_profile.profile_hash,
        "target_profile_fingerprint": assessment.right_profile.profile_hash,
        "consumer_map": dict(consumer_map),
        "hard_vetoes": list(assessment.hard_vetoes),
        "proposed_by_ref": proposed_by_ref,
        "eligible_for_decision": not assessment.hard_vetoes
        and assessment.overall_category != "unknown",
        "proposal_only": True,
        "authorizes_build": False,
        "authorizes_source_decommission": False,
        "candidate_hash": "sha256:" + "0" * 64,
        "immutable": True,
    }
    draft["candidate_id"] = consolidation_candidate_id(draft)
    return finalize_consolidation_candidate(draft)


def _normalize_decision(value: Mapping[str, Any]) -> dict[str, Any]:
    result = deepcopy(dict(value))
    result["member_profiles"] = sorted(
        result.get("member_profiles", []),
        key=lambda item: (str(item.get("profile_id")), str(item.get("profile_hash"))),
    )
    result["candidate_refs"] = sorted(
        result.get("candidate_refs", []),
        key=lambda item: (str(item.get("candidate_id")), str(item.get("candidate_hash"))),
    )
    result["assessment_refs"] = sorted(
        result.get("assessment_refs", []),
        key=lambda item: (str(item.get("assessment_id")), str(item.get("assessment_hash"))),
    )
    for key in (
        "affected_consumer_ids",
        "accepted_differences",
        "invalidated_by",
        "residual_risks",
    ):
        result[key] = sorted(set(result.get(key, [])))
    return result


def finalize_consolidation_decision(
    value: Mapping[str, Any] | ConsolidationDecision,
) -> ConsolidationDecision:
    """Normalize and bind a schema-compatible decision to its exact inputs."""

    raw = value.model_dump(mode="json") if isinstance(value, ConsolidationDecision) else value
    result = _normalize_decision(raw)
    result.setdefault("contract_version", "domo-to-omni.consolidation-decision.v1")
    result["input_fingerprint"] = consolidation_input_fingerprint(result)
    result["decision_hash"] = "sha256:" + "0" * 64
    normalized = ConsolidationDecision.model_validate(result).model_dump(mode="json")
    normalized["decision_hash"] = consolidation_decision_hash(normalized)
    return ConsolidationDecision.model_validate(normalized)


def validate_consolidation_decision_integrity(
    value: Mapping[str, Any] | ConsolidationDecision,
) -> list[str]:
    raw = value.model_dump(mode="json") if isinstance(value, ConsolidationDecision) else value
    try:
        decision = ConsolidationDecision.model_validate(raw)
    except ValueError as exc:
        return [f"consolidation decision is invalid: {exc}"]
    errors: list[str] = []
    if decision.input_fingerprint != consolidation_input_fingerprint(decision):
        errors.append("input_fingerprint does not match decision inputs")
    if decision.decision_hash != consolidation_decision_hash(decision):
        errors.append("decision_hash does not match decision content")
    errors.extend(validate_validation_context(decision.validation_context))
    expected_decision_ref = f"decision-ref://{decision.decision_id}"
    receipt_refs: set[str] = set()
    for role, approval in _approval_items(decision).items():
        if approval is None:
            continue
        if approval.approval_receipt_ref in receipt_refs:
            errors.append(f"approval receipt cannot be reused across roles: {role}")
        receipt_refs.add(approval.approval_receipt_ref)
        if approval.decision_ref != expected_decision_ref:
            errors.append(f"approval decision reference does not match: {role}")
        if approval.scope_hash != decision.input_fingerprint:
            errors.append(f"approval scope fingerprint is stale: {role}")
        if approval.validation_cycle_id != decision.validation_cycle_id:
            errors.append(f"approval validation cycle is stale: {role}")
        if approval.approver_ref == decision.proposed_by_ref:
            errors.append(f"producer or proposer cannot self-approve: {role}")
        owner_policy = decision.validation_context.approval_owner_policy
        if (
            approval.authority_policy_ref != owner_policy.artifact_ref
            or approval.authority_policy_hash != owner_policy.artifact_hash
        ):
            errors.append(f"approval authority policy binding is stale: {role}")
    missing_roles = [
        role
        for role in required_approval_roles(decision)
        if _approval_items(decision)[role] is None
    ]
    errors.extend(f"missing required human approval: {role}" for role in missing_roles)
    if (
        decision.status == "approved"
        and decision.disposition != "retire"
        and not decision.authorizes_build
    ):
        errors.append("approved decision must explicitly request build authorization")
    return errors


def required_approval_roles(decision: ConsolidationDecision) -> tuple[ApprovalRole, ...]:
    roles: list[ApprovalRole] = ["business"]
    if decision.impact.security_changed:
        roles.append("security")
    if (
        decision.impact.freshness_history_or_sla_changed
        or decision.impact.side_effects_changed
        or decision.disposition == "retire"
    ):
        roles.append("operations")
    return tuple(roles)


def _derived_impact_requirements(
    decision: ConsolidationDecision,
    assessments: Collection[EquivalenceAssessment],
) -> DecisionImpact:
    materially_changed: set[str] = set()
    vetoes: set[str] = set()
    for assessment in assessments:
        materially_changed.update(
            item.dimension
            for item in assessment.dimensions
            if item.verdict in {
                "equivalent_with_constraints",
                "different",
                "unknown",
            }
        )
        vetoes.update(assessment.hard_vetoes)
    accepted = tuple(item.lower() for item in decision.accepted_differences)
    security_changed = bool(
        "security" in materially_changed
        or vetoes.intersection(
            {
                "security_domain_mismatch",
                "pdp_or_masking_mismatch",
                "derived_field_leakage_risk",
            }
        )
        or any(item.startswith(("security:", "pdp:", "masking:")) for item in accepted)
    )
    freshness_changed = bool(
        "operations" in materially_changed
        or vetoes.intersection({"freshness_or_history_mismatch", "owner_or_sla_missing"})
        or any(
            item.startswith(("freshness:", "history:", "owner:", "sla:"))
            for item in accepted
        )
    )
    side_effects_changed = bool(
        "side_effects" in materially_changed
        or "side_effects_present" in vetoes
        or any(item.startswith("side_effect:") for item in accepted)
    )
    consumer_changed = bool(
        "consumers" in materially_changed
        or "consumer_behavior_lost" in vetoes
        or any(item.startswith("consumer_disposition:") for item in accepted)
    )
    business_changed = bool(
        decision.classification == "approved_semantic_substitution"
        or materially_changed.intersection(
            {"definition", "grain", "lineage", "aggregation", "filters", "joins", "time"}
        )
        or any(
            item.startswith(
                (
                    "definition:",
                    "grain:",
                    "lineage:",
                    "aggregation:",
                    "filter:",
                    "join:",
                    "time:",
                )
            )
            for item in accepted
        )
    )
    return DecisionImpact(
        business_semantics_changed=business_changed,
        security_changed=security_changed,
        freshness_history_or_sla_changed=freshness_changed,
        side_effects_changed=side_effects_changed,
        consumer_behavior_changed=consumer_changed,
    )


def _evidence_required_approval_roles(
    decision: ConsolidationDecision,
    assessments: Collection[EquivalenceAssessment],
) -> tuple[ApprovalRole, ...]:
    derived = _derived_impact_requirements(decision, assessments)
    roles: list[ApprovalRole] = ["business"]
    if decision.impact.security_changed or derived.security_changed:
        roles.append("security")
    if (
        decision.impact.freshness_history_or_sla_changed
        or decision.impact.side_effects_changed
        or derived.freshness_history_or_sla_changed
        or derived.side_effects_changed
        or decision.disposition == "retire"
    ):
        roles.append("operations")
    return tuple(roles)


def _profile_ref(profile: SemanticProfile) -> DecisionProfileRef:
    return DecisionProfileRef(
        profile_id=profile.profile_id,
        asset_id=profile.identity.object_id,
        profile_hash=profile.profile_hash,
    )


def _producer_refs(value: Any) -> set[str]:
    producer_keys = {
        "actor_ref",
        "agent_ref",
        "created_by_ref",
        "generated_by_ref",
        "produced_by_ref",
        "producer_ref",
    }
    found: set[str] = set()

    def visit(value: Any, key: str | None = None) -> None:
        if isinstance(value, Mapping):
            for child_key, child_value in value.items():
                visit(child_value, str(child_key))
        elif isinstance(value, (list, tuple)):
            for child in value:
                visit(child, key)
        elif key in producer_keys and isinstance(value, str):
            found.add(value)

    visit(value)
    return found


def _approval_items(decision: ConsolidationDecision) -> dict[ApprovalRole, DecisionApproval | None]:
    return {
        "business": decision.approvals.business,
        "security": decision.approvals.security,
        "operations": decision.approvals.operations,
    }


def _candidate_ref(candidate: ConsolidationCandidate) -> DecisionCandidateRef:
    return DecisionCandidateRef(
        candidate_id=candidate.candidate_id,
        candidate_hash=candidate.candidate_hash,
        assessment_id=candidate.assessment_id,
        assessment_hash=candidate.assessment_fingerprint,
        source_profile_hash=candidate.source_profile_fingerprint,
        target_profile_hash=candidate.target_profile_fingerprint,
        consumer_map_hash=consumer_map_hash(candidate.consumer_map),
        scope_ref=candidate.scope_ref,
    )


def _assessment_ref(assessment: EquivalenceAssessment) -> DecisionAssessmentRef:
    return DecisionAssessmentRef(
        assessment_id=assessment.assessment_id,
        assessment_hash=assessment.assessment_hash,
        overall_category=assessment.overall_category,
    )


def _candidate_matches_assessment(
    candidate: ConsolidationCandidate,
    assessment: EquivalenceAssessment,
) -> bool:
    expected_eligible = not assessment.hard_vetoes and assessment.overall_category != "unknown"
    return all(
        (
            candidate.assessment_id == assessment.assessment_id,
            candidate.assessment_fingerprint == assessment.assessment_hash,
            candidate.assessment_category == assessment.overall_category,
            candidate.assessment_confidence == assessment.overall_confidence,
            candidate.run_id == assessment.run_id,
            candidate.scope_id == assessment.scope_id,
            candidate.source_profile_id == assessment.left_profile.profile_id,
            candidate.target_profile_id == assessment.right_profile.profile_id,
            candidate.source_profile_fingerprint == assessment.left_profile.profile_hash,
            candidate.target_profile_fingerprint == assessment.right_profile.profile_hash,
            tuple(sorted(candidate.hard_vetoes)) == tuple(sorted(assessment.hard_vetoes)),
            candidate.eligible_for_decision == expected_eligible,
            consumer_map_hash(candidate.consumer_map) == assessment.consumer_map_hash,
            set(candidate.consumer_map) == set(assessment.consumer_scope.left_consumer_ids),
        )
    )


def _assessment_reproduces_from_current_evidence(
    assessment: EquivalenceAssessment,
    *,
    candidate: ConsolidationCandidate,
    source: SemanticProfile,
    target: SemanticProfile,
    validation_context: AssessmentValidationContext,
    evidence_resolver: AssessmentEvidenceResolver,
) -> bool:
    required = tuple(
        item.dimension for item in assessment.dimensions if item.required
    )
    if len(required) != len(REQUIRED_DIMENSIONS) or set(required) != set(
        REQUIRED_DIMENSIONS
    ):
        return False
    try:
        asset_mapping = evidence_resolver.resolve_repository_mapping(
            source=source,
            target=target,
            validation_context=validation_context,
        )
        bounded_evidence = evidence_resolver.resolve_bounded_behavioral_evidence(
            source=source,
            target=target,
            validation_context=validation_context,
        )
        resolved_consumer_map = _trusted_consumer_map(
            source=source,
            target=target,
            validation_context=validation_context,
            evidence_resolver=evidence_resolver,
        )
        if resolved_consumer_map is None:
            return False
        if resolved_consumer_map != dict(sorted(candidate.consumer_map.items())):
            return False
        reproduced = reproduce_equivalence_assessment(
            assessment,
            source=source,
            target=target,
            consumer_map=resolved_consumer_map,
            current_validation_context=validation_context,
            bounded_behavioral_evidence=bounded_evidence,
            asset_mapping=asset_mapping,
        )
    except Exception:
        return False
    return reproduced == assessment


def _normalized_trusted_actor_refs(refs: Collection[str] | None) -> set[str] | None:
    if refs is None or isinstance(refs, str):
        return None
    resolved = set(refs)
    if not resolved or any(
        not isinstance(ref, str) or re.fullmatch(_ACTOR_REF_PATTERN, ref) is None
        for ref in resolved
    ):
        return None
    return resolved


def _trusted_assessment_producer_refs(
    *,
    source: SemanticProfile,
    target: SemanticProfile,
    validation_context: AssessmentValidationContext,
    evidence_resolver: AssessmentEvidenceResolver,
) -> set[str] | None:
    try:
        refs = evidence_resolver.resolve_assessment_producer_refs(
            source=source,
            target=target,
            validation_context=validation_context,
        )
    except Exception:
        return None
    return _normalized_trusted_actor_refs(refs)


def _trusted_profile_producer_refs(
    *,
    profile_id: str,
    validation_context: AssessmentValidationContext,
    evidence_resolver: AssessmentEvidenceResolver,
) -> set[str] | None:
    try:
        refs = evidence_resolver.resolve_profile_producer_refs(
            profile_id=profile_id,
            validation_context=validation_context,
        )
    except Exception:
        return None
    return _normalized_trusted_actor_refs(refs)


def _trusted_candidate_proposer_refs(
    *,
    candidate_id: str,
    validation_context: AssessmentValidationContext,
    evidence_resolver: AssessmentEvidenceResolver,
) -> set[str] | None:
    try:
        refs = evidence_resolver.resolve_candidate_proposer_refs(
            candidate_id=candidate_id,
            validation_context=validation_context,
        )
    except Exception:
        return None
    return _normalized_trusted_actor_refs(refs)


def _trusted_decision_proposer_refs(
    *,
    decision_id: str,
    validation_context: AssessmentValidationContext,
    evidence_resolver: AssessmentEvidenceResolver,
) -> set[str] | None:
    try:
        refs = evidence_resolver.resolve_decision_proposer_refs(
            decision_id=decision_id,
            validation_context=validation_context,
        )
    except Exception:
        return None
    return _normalized_trusted_actor_refs(refs)


def _trusted_consumer_map(
    *,
    source: SemanticProfile,
    target: SemanticProfile,
    validation_context: AssessmentValidationContext,
    evidence_resolver: AssessmentEvidenceResolver,
) -> dict[str, str | None] | None:
    try:
        resolved = evidence_resolver.resolve_consumer_map(
            source=source,
            target=target,
            validation_context=validation_context,
        )
    except Exception:
        return None
    if not isinstance(resolved, Mapping):
        return None
    normalized = dict(sorted(resolved.items()))
    if set(normalized) != set(source.consumers):
        return None
    target_consumers = set(target.consumers)
    if any(
        not isinstance(source_consumer, str)
        or target_consumer is not None
        and (
            not isinstance(target_consumer, str)
            or target_consumer not in target_consumers
        )
        for source_consumer, target_consumer in normalized.items()
    ):
        return None
    mapped_targets = [value for value in normalized.values() if value is not None]
    if len(mapped_targets) != len(set(mapped_targets)):
        return None
    return normalized


def _model_dump_set(values: Collection[BaseModel]) -> set[str]:
    return {item.model_dump_json() for item in values}


def _canonical_actor(
    policy: ApprovalAuthorityPolicy,
    actor_ref: str,
) -> str | None:
    if re.fullmatch(_HUMAN_REF_PATTERN, actor_ref) is None:
        return actor_ref
    canonical_owners = {
        owner for owners in policy.role_owners.values() for owner in owners
    }
    if actor_ref in canonical_owners:
        return actor_ref
    return policy.canonical_actor_aliases.get(actor_ref)


def _resolved_assessment_category(
    assessments: Collection[EquivalenceAssessment],
) -> EquivalenceCategory | None:
    categories = {item.overall_category for item in assessments}
    for category in (
        "unknown",
        "different",
        "bounded_behavioral_equivalence",
        "structurally_equivalent",
        "exact_definition",
    ):
        if category in categories:
            return category  # type: ignore[return-value]
    return None


def _receipt_matches_approval(
    receipt: ApprovalReceipt,
    approval: DecisionApproval,
) -> bool:
    return all(
        (
            receipt.role == approval.role,
            receipt.decision_ref == approval.decision_ref,
            receipt.approver_ref == approval.approver_ref,
            receipt.canonical_actor_ref == approval.canonical_actor_ref,
            receipt.issuer_ref == approval.issuer_ref,
            receipt.approved_at == approval.approved_at,
            receipt.scope_hash == approval.scope_hash,
            receipt.validation_cycle_id == approval.validation_cycle_id,
            receipt.authority_policy_ref == approval.authority_policy_ref,
            receipt.authority_policy_hash == approval.authority_policy_hash,
            receipt.approval_receipt_ref == approval.approval_receipt_ref,
            receipt.receipt_hash == approval.approval_receipt_hash,
        )
    )


def _resolve_verified_receipt(
    verifier: ApprovalReceiptVerifier,
    approval: DecisionApproval,
) -> ApprovalReceipt | None:
    try:
        return verifier.resolve_verified_receipt(
            receipt_ref=approval.approval_receipt_ref,
            expected_receipt_hash=approval.approval_receipt_hash,
            expected_issuer_ref=approval.issuer_ref,
        )
    except Exception:
        return None


def _has_consumer_disposition(
    accepted_differences: Collection[str],
    consumer_id: str,
) -> bool:
    exact = f"consumer_disposition:{consumer_id}"
    return any(item == exact or item.startswith(f"{exact}:") for item in accepted_differences)


def consolidation_invalidation_reasons(
    decision: ConsolidationDecision,
    *,
    now: datetime,
    current_candidates: Mapping[str, ConsolidationCandidate],
    current_assessments: Mapping[str, EquivalenceAssessment],
    current_profiles: Mapping[str, SemanticProfile],
    current_validation_context: AssessmentValidationContext,
    assessment_evidence_resolver: AssessmentEvidenceResolver,
    approval_receipt_verifier: ApprovalReceiptVerifier,
    authority_policy: ApprovalAuthorityPolicy,
    authority_trust_anchor: ApprovalAuthorityTrustAnchor,
) -> tuple[str, ...]:
    """Expose staleness rather than silently carrying a decision across revisions."""

    reasons: set[str] = set()
    if now.tzinfo is None:
        reasons.add("current_clock_is_timezone_naive")
    if validate_consolidation_decision_integrity(decision):
        reasons.add("decision_fingerprint_invalid")
    if validate_validation_context(current_validation_context):
        reasons.add("validation_context_integrity_invalid")
    if current_validation_context != decision.validation_context:
        reasons.add("validation_context_changed")
    if authority_policy.policy_hash != approval_authority_policy_hash(authority_policy):
        reasons.add("approval_authority_policy_integrity_invalid")
    if authority_trust_anchor.anchor_hash != approval_authority_trust_anchor_hash(
        authority_trust_anchor
    ):
        reasons.add("approval_authority_trust_anchor_integrity_invalid")
    if (
        authority_policy.policy_ref != authority_trust_anchor.authority_policy_ref
        or authority_policy.policy_hash != authority_trust_anchor.authority_policy_hash
        or authority_policy.revision != authority_trust_anchor.authority_policy_revision
        or set(authority_policy.trusted_issuer_refs)
        != set(authority_trust_anchor.trusted_issuer_refs)
    ):
        reasons.add("approval_authority_policy_untrusted")
    owner_policy_ref = decision.validation_context.approval_owner_policy
    if (
        authority_policy.policy_ref != owner_policy_ref.artifact_ref
        or authority_policy.policy_hash != owner_policy_ref.artifact_hash
        or authority_policy.revision != owner_policy_ref.revision
    ):
        reasons.add("approval_authority_policy_changed")

    trusted_decision_proposers = _trusted_decision_proposer_refs(
        decision_id=decision.decision_id,
        validation_context=current_validation_context,
        evidence_resolver=assessment_evidence_resolver,
    )
    if trusted_decision_proposers is None:
        reasons.add("decision_proposer_evidence_unavailable")
    else:
        recorded_decision_proposers = {
            decision.proposed_by_ref,
            *_producer_refs(decision.provenance),
        }
        if recorded_decision_proposers != trusted_decision_proposers:
            reasons.add("decision_proposer_evidence_changed")

    resolved_candidates: list[ConsolidationCandidate] = []
    resolved_assessments: list[EquivalenceAssessment] = []
    for candidate_ref in decision.candidate_refs:
        candidate = current_candidates.get(candidate_ref.candidate_id)
        if candidate is None:
            reasons.add("candidate_missing")
            continue
        resolved_candidates.append(candidate)
        if validate_consolidation_candidate(candidate):
            reasons.add("candidate_fingerprint_invalid")
        if _candidate_ref(candidate) != candidate_ref:
            reasons.add("candidate_binding_changed")
        if candidate.run_id != decision.run_id or candidate.scope_id != decision.scope_id:
            reasons.add("candidate_partition_changed")
        trusted_candidate_proposers = _trusted_candidate_proposer_refs(
            candidate_id=candidate.candidate_id,
            validation_context=current_validation_context,
            evidence_resolver=assessment_evidence_resolver,
        )
        if trusted_candidate_proposers is None:
            reasons.add("candidate_proposer_evidence_unavailable")
        elif {candidate.proposed_by_ref} != trusted_candidate_proposers:
            reasons.add("candidate_proposer_evidence_changed")

        assessment = current_assessments.get(candidate_ref.assessment_id)
        if assessment is None:
            reasons.add("assessment_missing")
            continue
        resolved_assessments.append(assessment)
        if validate_equivalence_assessment(assessment):
            reasons.add("assessment_fingerprint_invalid")
        if _assessment_ref(assessment) not in decision.assessment_refs:
            reasons.add("assessment_binding_changed")
        if (
            assessment.assessment_hash != candidate_ref.assessment_hash
            or assessment.assessment_hash != candidate.assessment_fingerprint
        ):
            reasons.add("assessment_revision_changed")
        if (
            assessment.left_profile.profile_hash != candidate.source_profile_fingerprint
            or assessment.right_profile.profile_hash != candidate.target_profile_fingerprint
        ):
            reasons.add("assessment_endpoint_changed")
        if assessment.consumer_map_hash != consumer_map_hash(candidate.consumer_map):
            reasons.add("consumer_scope_changed")
        if assessment.validation_context != decision.validation_context:
            reasons.add("assessment_validation_context_changed")
        if not _candidate_matches_assessment(candidate, assessment):
            reasons.add("candidate_assessment_evidence_changed")

        for profile_id, profile_hash, endpoint in (
            (candidate.source_profile_id, candidate.source_profile_fingerprint, "source"),
            (candidate.target_profile_id, candidate.target_profile_fingerprint, "target"),
        ):
            profile = current_profiles.get(profile_id)
            if profile is None:
                reasons.add(f"{endpoint}_profile_missing")
                continue
            if validate_semantic_profile(profile):
                reasons.add(f"{endpoint}_profile_integrity_invalid")
            if profile.profile_hash != profile_hash:
                reasons.add(f"{endpoint}_profile_revision_changed")
            if profile.run_id != decision.run_id:
                reasons.add("decision_run_partition_changed")
            if profile.scope_id != decision.scope_id:
                reasons.add("decision_scope_partition_changed")
            trusted_profile_producers = _trusted_profile_producer_refs(
                profile_id=profile.profile_id,
                validation_context=current_validation_context,
                evidence_resolver=assessment_evidence_resolver,
            )
            if trusted_profile_producers is None:
                reasons.add(f"{endpoint}_profile_producer_evidence_unavailable")
            else:
                recorded_profile_producers = _producer_refs(profile.provenance)
                if (
                    recorded_profile_producers
                    and recorded_profile_producers != trusted_profile_producers
                ):
                    reasons.add(f"{endpoint}_profile_producer_evidence_changed")
        source_profile = current_profiles.get(candidate.source_profile_id)
        target_profile = current_profiles.get(candidate.target_profile_id)
        if source_profile is not None and target_profile is not None:
            resolved_consumer_map = _trusted_consumer_map(
                source=source_profile,
                target=target_profile,
                validation_context=current_validation_context,
                evidence_resolver=assessment_evidence_resolver,
            )
            if resolved_consumer_map is None:
                reasons.add("consumer_contract_mapping_unavailable")
            elif resolved_consumer_map != dict(sorted(candidate.consumer_map.items())):
                reasons.add("consumer_contract_mapping_changed")
            if not _assessment_reproduces_from_current_evidence(
                assessment,
                candidate=candidate,
                source=source_profile,
                target=target_profile,
                validation_context=current_validation_context,
                evidence_resolver=assessment_evidence_resolver,
            ):
                reasons.add("assessment_deterministic_reproduction_failed")
            trusted_producers = _trusted_assessment_producer_refs(
                source=source_profile,
                target=target_profile,
                validation_context=current_validation_context,
                evidence_resolver=assessment_evidence_resolver,
            )
            if trusted_producers is None:
                reasons.add("assessment_producer_evidence_unavailable")
            else:
                recorded_producers = _producer_refs(assessment.provenance)
                if recorded_producers and recorded_producers != trusted_producers:
                    reasons.add("assessment_producer_evidence_changed")

    expected_candidates = _model_dump_set([_candidate_ref(item) for item in resolved_candidates])
    if expected_candidates != _model_dump_set(decision.candidate_refs):
        reasons.add("candidate_set_changed")
    expected_assessments = _model_dump_set(
        [_assessment_ref(item) for item in resolved_assessments]
    )
    if expected_assessments != _model_dump_set(decision.assessment_refs):
        reasons.add("assessment_set_changed")

    resolved_profile_refs: list[DecisionProfileRef] = []
    for candidate in resolved_candidates:
        for profile_id in (candidate.source_profile_id, candidate.target_profile_id):
            profile = current_profiles.get(profile_id)
            if profile is not None:
                resolved_profile_refs.append(_profile_ref(profile))
    if _model_dump_set(resolved_profile_refs) != _model_dump_set(decision.member_profiles):
        reasons.add("profile_membership_changed")

    current = (
        now.astimezone(timezone.utc)
        if now.tzinfo is not None
        else now.replace(tzinfo=timezone.utc)
    )
    for role, approval in _approval_items(decision).items():
        if approval and approval.approved_at.astimezone(timezone.utc) > current:
            reasons.add(f"approval_from_future_clock:{role}")
        if approval and approval.scope_hash != decision.input_fingerprint:
            reasons.add(f"approval_scope_stale:{role}")
        if approval and approval.validation_cycle_id != decision.validation_cycle_id:
            reasons.add(f"approval_validation_cycle_stale:{role}")
        if approval:
            receipt = _resolve_verified_receipt(approval_receipt_verifier, approval)
            if not isinstance(receipt, ApprovalReceipt):
                reasons.add(f"approval_receipt_unverified:{role}")
            elif (
                receipt.receipt_hash != approval_receipt_hash(receipt)
                or not _receipt_matches_approval(receipt, approval)
            ):
                reasons.add(f"approval_receipt_changed:{role}")
    return tuple(sorted(reasons))


def validate_consolidation_decision(
    value: Mapping[str, Any] | ConsolidationDecision,
    *,
    now: datetime,
    current_candidates: Mapping[str, ConsolidationCandidate],
    current_assessments: Mapping[str, EquivalenceAssessment],
    current_profiles: Mapping[str, SemanticProfile],
    current_validation_context: AssessmentValidationContext,
    assessment_evidence_resolver: AssessmentEvidenceResolver,
    approval_receipt_verifier: ApprovalReceiptVerifier,
    authority_policy: ApprovalAuthorityPolicy,
    authority_trust_anchor: ApprovalAuthorityTrustAnchor,
) -> ConsolidationDecisionValidation:
    """Validate exact evidence and authority against a control-plane trust anchor.

    The evidence resolver, receipt verifier, and ``authority_trust_anchor`` are
    trusted control-plane dependencies, never artifacts supplied by the decision
    producer or approval caller.
    """

    raw = value.model_dump(mode="json") if isinstance(value, ConsolidationDecision) else value
    try:
        decision = ConsolidationDecision.model_validate(raw)
    except ValueError as exc:
        fingerprint = _sha256(_without(dict(raw), "decision_hash"))
        return ConsolidationDecisionValidation(
            valid=False,
            invalidated=True,
            errors=(f"consolidation decision is invalid: {exc}",),
            invalidation_reasons=("decision_shape_invalid",),
            required_roles=("business",),
            approved_roles=(),
            resolved_category=None,
            authorizes_build=False,
            decision_fingerprint=fingerprint,
        )

    errors: set[str] = set()
    invalidation = set(
        consolidation_invalidation_reasons(
            decision,
            now=now,
            current_candidates=current_candidates,
            current_assessments=current_assessments,
            current_profiles=current_profiles,
            current_validation_context=current_validation_context,
            assessment_evidence_resolver=assessment_evidence_resolver,
            approval_receipt_verifier=approval_receipt_verifier,
            authority_policy=authority_policy,
            authority_trust_anchor=authority_trust_anchor,
        )
    )
    approvals = _approval_items(decision)
    candidates = [
        current_candidates[item.candidate_id]
        for item in decision.candidate_refs
        if item.candidate_id in current_candidates
    ]
    assessments = [
        current_assessments[item.assessment_id]
        for item in decision.assessment_refs
        if item.assessment_id in current_assessments
    ]
    roles = _evidence_required_approval_roles(decision, assessments)
    profiles = {
        profile_id: current_profiles[profile_id]
        for candidate in candidates
        for profile_id in (candidate.source_profile_id, candidate.target_profile_id)
        if profile_id in current_profiles
    }
    trusted_artifact_producers: set[str] = set()
    trusted_decision_proposers = _trusted_decision_proposer_refs(
        decision_id=decision.decision_id,
        validation_context=current_validation_context,
        evidence_resolver=assessment_evidence_resolver,
    )
    if trusted_decision_proposers is None:
        errors.add("trusted decision proposer evidence is required")
    else:
        trusted_artifact_producers.update(trusted_decision_proposers)
    for candidate in candidates:
        trusted_candidate_proposers = _trusted_candidate_proposer_refs(
            candidate_id=candidate.candidate_id,
            validation_context=current_validation_context,
            evidence_resolver=assessment_evidence_resolver,
        )
        if trusted_candidate_proposers is None:
            errors.add("trusted candidate proposer evidence is required")
        else:
            trusted_artifact_producers.update(trusted_candidate_proposers)
    for profile in profiles.values():
        trusted_profile_producers = _trusted_profile_producer_refs(
            profile_id=profile.profile_id,
            validation_context=current_validation_context,
            evidence_resolver=assessment_evidence_resolver,
        )
        if trusted_profile_producers is None:
            errors.add("trusted profile producer evidence is required")
        else:
            trusted_artifact_producers.update(trusted_profile_producers)
    for candidate in candidates:
        source = profiles.get(candidate.source_profile_id)
        target = profiles.get(candidate.target_profile_id)
        if source is None or target is None:
            continue
        trusted_producers = _trusted_assessment_producer_refs(
            source=source,
            target=target,
            validation_context=current_validation_context,
            evidence_resolver=assessment_evidence_resolver,
        )
        if trusted_producers is None:
            errors.add("trusted assessment producer evidence is required")
            continue
        trusted_artifact_producers.update(trusted_producers)
    producers = {
        decision.proposed_by_ref,
        *(candidate.proposed_by_ref for candidate in candidates),
        *trusted_artifact_producers,
        *_producer_refs(decision.provenance),
        *(ref for assessment in assessments for ref in _producer_refs(assessment.provenance)),
        *(ref for profile in profiles.values() for ref in _producer_refs(profile.provenance)),
    }
    if any(re.fullmatch(_ACTOR_REF_PATTERN, producer) is None for producer in producers):
        errors.add("producer and proposer identities must use trusted actor references")
    resolved_producers = {
        producer: _canonical_actor(authority_policy, producer)
        for producer in producers
    }
    unresolved_human_producers = {
        producer
        for producer, canonical in resolved_producers.items()
        if re.fullmatch(_HUMAN_REF_PATTERN, producer) is not None and canonical is None
    }
    if unresolved_human_producers:
        errors.add("human producers or proposers require trusted canonical identities")
    canonical_producers = {
        canonical for canonical in resolved_producers.values() if canonical is not None
    }
    approved_roles: list[ApprovalRole] = []
    consolidating = decision.disposition in {"reuse", "merge", "parameterize"}
    splitting = decision.disposition == "split"

    if any(candidate.proposed_by_ref != decision.proposed_by_ref for candidate in candidates):
        errors.add("decision proposer does not match every candidate proposer")

    expected_candidate_refs = [_candidate_ref(item) for item in candidates]
    if _model_dump_set(expected_candidate_refs) != _model_dump_set(decision.candidate_refs):
        errors.add("decision must bind every and only exact current candidate reference")
    expected_assessment_refs = [_assessment_ref(item) for item in assessments]
    if _model_dump_set(expected_assessment_refs) != _model_dump_set(decision.assessment_refs):
        errors.add("decision must bind every and only exact current assessment reference")
    assessments_by_id = {item.assessment_id: item for item in assessments}
    if any(
        candidate.assessment_id not in assessments_by_id
        or not _candidate_matches_assessment(
            candidate, assessments_by_id[candidate.assessment_id]
        )
        for candidate in candidates
    ):
        errors.add("candidate evidence must exactly match its current bound assessment")
    expected_profile_refs = [_profile_ref(item) for item in profiles.values()]
    if _model_dump_set(expected_profile_refs) != _model_dump_set(decision.member_profiles):
        errors.add("decision members must equal the exact candidate endpoint union")
    expected_consumers = {
        consumer_id for candidate in candidates for consumer_id in candidate.consumer_map
    }
    if set(decision.affected_consumer_ids) != expected_consumers:
        errors.add("affected consumers must equal the exact candidate consumer union")

    derived_impact = _derived_impact_requirements(decision, assessments)
    for field_name in (
        "business_semantics_changed",
        "security_changed",
        "freshness_history_or_sla_changed",
        "side_effects_changed",
        "consumer_behavior_changed",
    ):
        if getattr(derived_impact, field_name) and not getattr(decision.impact, field_name):
            errors.add(
                f"decision impact omits evidence-derived change: {field_name}"
            )

    derived_category = _resolved_assessment_category(assessments)
    if splitting:
        if decision.canonical_target_profile is not None:
            errors.add("split decisions cannot designate a canonical target")
        if decision.classification != derived_category:
            errors.add("split decisions must preserve the assessed incompatibility classification")
        connected_members = {
            profile_id
            for candidate in candidates
            for profile_id in (candidate.source_profile_id, candidate.target_profile_id)
        }
        if connected_members != {item.profile_id for item in decision.member_profiles}:
            errors.add("split decisions must exhaustively bind every member")
        lost_consumers = {
            consumer_id
            for candidate in candidates
            for consumer_id, target_consumer in candidate.consumer_map.items()
            if target_consumer is None
        }
        if any(
            not _has_consumer_disposition(decision.accepted_differences, consumer_id)
            for consumer_id in lost_consumers
        ):
            errors.add("split decisions must safely disposition every lost consumer")
    elif decision.classification == "approved_semantic_substitution":
        if derived_category != "different" or any(candidate.hard_vetoes for candidate in candidates):
            errors.add("substitution can only resolve explicit non-vetoed differences")
        if not decision.accepted_differences:
            errors.add("semantic substitution requires explicit accepted differences")
    elif decision.classification != derived_category:
        errors.add("decision classification does not match its bound assessments")

    if consolidating:
        if len(decision.member_profiles) < 2 or decision.canonical_target_profile is None:
            errors.add("consolidation requires at least two members and one canonical target")
        if any(not candidate.eligible_for_decision or candidate.hard_vetoes for candidate in candidates):
            errors.add("hard vetoes or unknown evidence prohibit consolidation")
        if any(candidate.assessment_category == "unknown" for candidate in candidates):
            errors.add("unknown equivalence cannot be approved")
        if decision.canonical_target_profile is not None:
            target_id = decision.canonical_target_profile.profile_id
            non_targets = {
                item.profile_id
                for item in decision.member_profiles
                if item.profile_id != target_id
            }
            edges = [(item.source_profile_id, item.target_profile_id) for item in candidates]
            expected_edges = {(source_id, target_id) for source_id in non_targets}
            if len(edges) != len(set(edges)) or set(edges) != expected_edges:
                errors.add(
                    "consolidation requires exact direct star coverage from every non-target member"
                )
            target_profile = profiles.get(target_id)
            if target_profile is None or _profile_ref(target_profile) != (
                decision.canonical_target_profile
            ):
                errors.add("canonical target must resolve to the exact current target profile")

    if decision.disposition == "retire" and expected_consumers:
        if any(
            not _has_consumer_disposition(decision.accepted_differences, consumer_id)
            for consumer_id in expected_consumers
        ):
            errors.add(
                "retire decisions require an approved disposition for every live consumer"
            )

    for role in roles:
        approval = approvals[role]
        if approval is None:
            errors.add(f"missing required human approval: {role}")
            continue
        role_error_count = len(errors)
        receipt_invalidation = {
            f"approval_receipt_unverified:{role}",
            f"approval_receipt_changed:{role}",
        }.intersection(invalidation)
        if receipt_invalidation:
            errors.add(f"approval receipt is not authentically verified: {role}")
        canonical_actor = _canonical_actor(authority_policy, approval.approver_ref)
        if canonical_actor is None:
            errors.add(f"approval human identity is not canonically trusted: {role}")
        if approval.canonical_actor_ref != canonical_actor:
            errors.add(f"approval canonical actor binding is invalid: {role}")
        authorized_owners = set(authority_policy.role_owners.get(role, ()))
        if not authorized_owners or canonical_actor not in authorized_owners:
            errors.add(f"approver is not an authorized {role} owner")
        if approval.canonical_actor_ref in canonical_producers:
            errors.add(f"producer or proposer cannot self-approve: {role}")
        if (
            approval.issuer_ref not in authority_policy.trusted_issuer_refs
            or approval.issuer_ref not in authority_trust_anchor.trusted_issuer_refs
        ):
            errors.add(f"approval issuer is not trusted: {role}")
        if (
            approval.authority_policy_ref != authority_policy.policy_ref
            or approval.authority_policy_hash != authority_policy.policy_hash
        ):
            errors.add(f"approval authority policy is stale: {role}")
        if approval.decision_ref != f"decision-ref://{decision.decision_id}":
            errors.add(f"approval decision reference does not match: {role}")
        if approval.scope_hash != decision.input_fingerprint:
            errors.add(f"approval scope fingerprint is stale: {role}")
        if approval.validation_cycle_id != decision.validation_cycle_id:
            errors.add(f"approval validation cycle is stale: {role}")
        if approval.approved_at.astimezone(timezone.utc) > now.astimezone(timezone.utc):
            errors.add(f"approval decision is from the future: {role}")
        if len(errors) == role_error_count:
            approved_roles.append(role)

    if decision.status != "approved":
        errors.add("only an approved decision can authorize consolidation")
    if (
        decision.status == "approved"
        and not decision.authorizes_build
        and decision.disposition != "retire"
    ):
        errors.add("approved decision must explicitly request build authorization")
    if decision.disposition == "manual_review":
        errors.add("manual review is not a build-authorizing disposition")
    if invalidation:
        errors.add("decision inputs or approvals have been invalidated")

    is_valid = not errors and not invalidation and set(approved_roles) == set(roles)
    return ConsolidationDecisionValidation(
        valid=is_valid,
        invalidated=bool(invalidation),
        errors=tuple(sorted(errors)),
        invalidation_reasons=tuple(sorted(invalidation)),
        required_roles=roles,
        approved_roles=tuple(sorted(approved_roles, key=_ROLE_ORDER.__getitem__)),
        resolved_category=decision.classification if is_valid else None,
        authorizes_build=is_valid and decision.authorizes_build,
        decision_fingerprint=decision.decision_hash,
    )


candidate_invalidation_reasons = consolidation_invalidation_reasons
HumanApproval = DecisionApproval


__all__ = [
    "ApprovalReceiptVerifier",
    "ApprovalAuthorityPolicy",
    "ApprovalAuthorityTrustAnchor",
    "ApprovalReceipt",
    "ApprovalRole",
    "AssessmentEvidenceResolver",
    "ConsolidationCandidate",
    "ConsolidationDecision",
    "ConsolidationDecisionValidation",
    "DecisionApproval",
    "DecisionApprovals",
    "DecisionAssessmentRef",
    "DecisionCandidateRef",
    "DecisionImpact",
    "DecisionProfileRef",
    "DecisionStatus",
    "Disposition",
    "HumanApproval",
    "RetirementState",
    "candidate_invalidation_reasons",
    "approval_authority_policy_hash",
    "approval_authority_trust_anchor_hash",
    "approval_receipt_hash",
    "consolidation_candidate_hash",
    "consolidation_candidate_id",
    "consolidation_decision_hash",
    "consolidation_input_fingerprint",
    "consolidation_invalidation_reasons",
    "finalize_consolidation_candidate",
    "finalize_consolidation_decision",
    "finalize_approval_authority_policy",
    "finalize_approval_authority_trust_anchor",
    "finalize_approval_receipt",
    "propose_consolidation_candidate",
    "required_approval_roles",
    "validate_consolidation_candidate",
    "validate_consolidation_decision",
    "validate_consolidation_decision_integrity",
]

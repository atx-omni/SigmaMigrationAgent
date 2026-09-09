"""Build route-bound Sigma proposal work on the shared deterministic work-package model.

The coordinator must verify source acceptance and the current decision in its trusted
store before invoking this planner. These plans cannot authorize target operations,
claim parity, satisfy independent QA, or replace human acceptance.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from omni_migrator.control_plane.canonical import parse_time, sha256_json, validate_reference
from omni_migrator.control_plane.gates import required_gate_ids_for_work_phase
from omni_migrator.extractors.sigma.capability_contracts import SigmaSemanticRoutingArtifact
from omni_migrator.extractors.sigma.semantic_routing import route_sigma_semantic_specialists
from omni_migrator.orchestration.planner import (
    AGENT_DEFAULT_TOOL_PROFILES,
    AGENT_TOOL_ALLOWLISTS,
    PlannedAgentAssignee,
    PlannedAuthority,
    PlannedSigmaRoutingBinding,
    PlannedSourceScope,
    PlannedTimestamps,
    PlannedValidationRequirement,
    PlannedWorkPackage,
    WorkPhase,
    validate_work_graph,
)


class SigmaPlanningContext(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_system: Literal["sigma"] = "sigma"
    tenant_ref: str
    run_id: str
    migration_unit_id: str
    validation_cycle_id: str = Field(min_length=1)
    created_at: str
    decision: SigmaSemanticRoutingArtifact

    @model_validator(mode="after")
    def context_matches_its_current_decision(self) -> "SigmaPlanningContext":
        validate_reference(self.tenant_ref, allowed_schemes={"tenant-ref"})
        if self.run_id != self.decision.run_id:
            raise ValueError("Sigma planning run must match its semantic decision")
        if self.migration_unit_id != self.decision.payload.migration_unit_id:
            raise ValueError("Sigma planning migration unit must match its semantic decision")
        if parse_time(self.created_at) < self.decision.created_at:
            raise ValueError("Sigma planning cannot predate its semantic decision")
        route_sigma_semantic_specialists(self.decision)
        return self


_PLANNING_STEPS: dict[str, tuple[WorkPhase, str, str]] = {
    "sigma_analytics_formula": (
        "sigma_formula_planning",
        "sigma_formula_plan",
        "Interpret supplied Sigma formulas, grain, filters, relationships, and security. "
        "Preserve source IDs and evaluation context; propose explicit exceptions for unknown semantics.",
    ),
    "sigma_semantic_consolidation": (
        "sigma_commonality_planning",
        "sigma_commonality_plan",
        "Assess common semantics across the comparison scope. Propose reuse and consolidation "
        "for warehouse-first or a preserve-boundary disposition for direct Omni reconstruction.",
    ),
    "sigma_dbt_analytics_engineer": (
        "sigma_dbt_planning",
        "sigma_dbt_plan",
        "Propose governed data-layer placement and dbt changes only for approved upstream logic. "
        "Return inert SQL and test proposals; identify the approvals and live validation still needed.",
    ),
    "sigma_omni_modeler": (
        "sigma_omni_planning",
        "sigma_omni_model_plan",
        "Propose Omni semantics over the route's accepted warehouse relations. Preserve the "
        "accepted formula, grain, relationship, filter, security, and labeling boundaries. "
        "Direct reconstruction must not introduce dbt or warehouse changes.",
    ),
    "sigma_independent_qa": (
        "sigma_qa_planning",
        "sigma_independent_qa_plan",
        "Plan independent source-to-target semantic and behavioral comparisons against the full "
        "agreed denominator, including identity, filters, security, aggregates, nulls, and timezones. "
        "Record required paired evidence and explicit exceptions; never invent comparison results.",
    ),
    "sigma_documentation_training": (
        "sigma_documentation_planning",
        "sigma_documentation_plan",
        "Draft the route-specific lineage, change guide, training, and operating-document plan. "
        "Label all proposed content as drafts and identify missing QA and human acceptance.",
    ),
}


def build_sigma_work_graph(
    decision: SigmaSemanticRoutingArtifact,
    *,
    tenant_ref: str,
    validation_cycle_id: str,
    created_at: datetime | str,
) -> list[PlannedWorkPackage]:
    """Return deterministic, non-writing proposals for exactly the selected semantic route."""

    context = SigmaPlanningContext(
        tenant_ref=tenant_ref,
        run_id=decision.run_id,
        migration_unit_id=decision.payload.migration_unit_id,
        validation_cycle_id=validation_cycle_id,
        created_at=created_at.isoformat() if isinstance(created_at, datetime) else created_at,
        decision=decision,
    )
    decision = context.decision
    decision_ref = f"artifact-ref://{decision.artifact_id}"
    source_hashes = {
        item.artifact_id: item.content_hash for item in decision.payload.source_context_bindings
    }
    binding = PlannedSigmaRoutingBinding(
        mode=decision.payload.mode,
        decision_ref=decision_ref,
        decision_hash=decision.content_hash,
        scope_id=decision.scope_id,
        comparison_scope_refs=list(decision.payload.comparison_scope_refs),
        build_scope_refs=list(decision.payload.build_scope_refs),
        target_environment_refs=list(decision.payload.target_environment_refs),
        source_artifact_hashes=source_hashes,
    )
    source_scope = [
        PlannedSourceScope(
            system="sigma",
            object_type=item.artifact_schema_version,
            object_id=item.artifact_id,
            fingerprint=item.content_hash,
        )
        for item in decision.payload.source_context_bindings
    ]
    input_refs = [decision_ref, *(f"artifact-ref://{item}" for item in source_hashes)]
    roles = (*route_sigma_semantic_specialists(decision), "sigma_documentation_training")
    packages: list[PlannedWorkPackage] = []
    for index, role in enumerate(roles):
        phase, artifact_type, objective = _PLANNING_STEPS[role]
        digest = sha256_json(
            {
                "tenant_ref": tenant_ref,
                "run_id": context.run_id,
                "migration_unit_id": context.migration_unit_id,
                "validation_cycle_id": validation_cycle_id,
                "decision_hash": decision.content_hash,
                "phase": phase,
                "assignee": role,
            }
        )[:20]
        work_id = f"wp-{digest}"
        validation_method = (
            "Validate proposal schema, input citations, source coverage, and chosen route."
        )
        if role == "sigma_independent_qa":
            prerequisites = required_gate_ids_for_work_phase(
                "production_qa", sigma_semantic_mode=binding.mode
            )
            validation_method += (
                " Future production QA requires "
                + ", ".join(prerequisites)
                + "; this planning artifact is not a QA result or gate approval."
            )
        packages.append(
            PlannedWorkPackage(
                tenant_ref=tenant_ref,
                work_package_id=work_id,
                run_id=context.run_id,
                migration_unit_id=context.migration_unit_id,
                validation_cycle_id=validation_cycle_id,
                phase=phase,
                assignee=PlannedAgentAssignee(agent_id=role),
                objective=objective,
                tool_profile=AGENT_DEFAULT_TOOL_PROFILES[role],
                scope_purpose="comparison" if index < 2 else "migration",
                source_scope=source_scope,
                sigma_routing=binding,
                depends_on=[packages[-1].work_package_id] if packages else [],
                input_refs=input_refs,
                expected_artifacts=[artifact_type],
                authority=PlannedAuthority(
                    mode="read_only" if role == "sigma_independent_qa" else "proposal_only",
                    allowed_tools=AGENT_TOOL_ALLOWLISTS[role],
                    forbidden_actions=[
                        "write_source_or_target_systems",
                        "approve_own_work",
                        "expand_scope_or_authority",
                        "claim_qa_or_acceptance_from_proposals",
                        "cutover_or_decommission_source",
                    ],
                ),
                completion_criteria=[
                    "Produce a source-cited proposal covering every expected artifact.",
                    "Record unresolved semantics, evidence gaps, and required human decisions.",
                    "Proposal completion does not approve target operations or establish migration parity.",
                ],
                validation_requirements=[
                    PlannedValidationRequirement(
                        validation_id=f"validate-{digest}",
                        method=validation_method,
                        required_evidence=[artifact_type],
                    )
                ],
                timestamps=PlannedTimestamps(
                    created_at=context.created_at, updated_at=context.created_at
                ),
            )
        )
    return validate_work_graph(packages)

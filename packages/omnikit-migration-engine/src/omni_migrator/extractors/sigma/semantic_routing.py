"""Create and execute the human-selected Sigma semantic migration route.

The route is a target-architecture decision, not source evidence. It intentionally accepts no
Sigma client and grants no source or target write authority.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

from omni_migrator.control_plane.canonical import sha256_json
from omni_migrator.extractors.sigma.capability_contracts import (
    ArtifactInput,
    SemanticRoutingPayload,
    SigmaSemanticRoutingArtifact,
    SigmaSemanticRoutingDecisionRequest,
    SigmaSemanticRoutingPrompt,
)


SEMANTIC_MIGRATION_QUESTION = (
    "Which implementation path should this Sigma semantic layer use: warehouse-first "
    "refactoring before Omni, or direct reconstruction in Omni?"
)

SEMANTIC_MIGRATION_GUARDRAIL = (
    "Both paths target bounded semantic equivalence with explicit exceptions and the same "
    "closed-denominator QA; neither guarantees one-to-one semantic, behavioral, visual, or "
    "workflow parity."
)

SEMANTIC_MIGRATION_OPTIONS = {
    "warehouse_first_refactor": (
        "The fully modeled path: preserve accepted semantics while moving approved shared and "
        "persistent transformation logic into the governed data layer before Omni."
    ),
    "omni_semantic_reconstruction": (
        "The lift-and-shift path: preserve accepted semantics through direct Omni reconstruction "
        "over accepted existing warehouse relations, without requiring data-layer changes."
    ),
}


def prompt_for_sigma_semantic_route() -> SigmaSemanticRoutingPrompt:
    """Return the required two-option prompt while leaving source acquisition unblocked."""

    return SigmaSemanticRoutingPrompt(
        schema_version="sigma-semantic-routing-prompt.v1",
        question=SEMANTIC_MIGRATION_QUESTION,
        shared_guardrail=SEMANTIC_MIGRATION_GUARDRAIL,
        options=(
            {
                "mode": "warehouse_first_refactor",
                "label": "Warehouse-first refactor",
                "description": SEMANTIC_MIGRATION_OPTIONS["warehouse_first_refactor"],
            },
            {
                "mode": "omni_semantic_reconstruction",
                "label": "Omni semantic reconstruction",
                "description": SEMANTIC_MIGRATION_OPTIONS["omni_semantic_reconstruction"],
            },
        ),
    )


def create_sigma_semantic_routing_decision(
    value: SigmaSemanticRoutingDecisionRequest | Mapping[str, Any],
    *,
    created_at: datetime | None = None,
) -> SigmaSemanticRoutingArtifact:
    """Create one immutable, scope-bound routing artifact with no implicit default."""

    request = (
        value
        if isinstance(value, SigmaSemanticRoutingDecisionRequest)
        else SigmaSemanticRoutingDecisionRequest.model_validate(value)
    )
    route = SemanticRoutingPayload.expected_route(request.mode)
    payload = SemanticRoutingPayload(
        decision_id=request.decision_id,
        run_id=request.run_id,
        scope_id=request.scope_id,
        migration_unit_id=request.migration_unit_id,
        comparison_scope_refs=request.comparison_scope_refs,
        build_scope_refs=request.build_scope_refs,
        target_environment_refs=request.target_environment_refs,
        mode=request.mode,
        decided_by_ref=request.decided_by_ref,
        decision_ref=request.decision_ref,
        decision_record_revision=request.decision_record_revision,
        decision_record_sha256=request.decision_record_sha256,
        decided_at=request.decided_at,
        rationale=request.rationale,
        source_context_bindings=request.source_context_bindings,
        supersedes_decision=request.supersedes_decision,
        question_version=request.question_version,
        **route,
    )
    material: dict[str, Any] = {
        "artifact_id": f"sigma-semantic-routing-decision.{request.decision_id}",
        "schema_version": "sigma-semantic-routing-decision.v1",
        "run_id": request.run_id,
        "scope_id": request.scope_id,
        "created_at": created_at or datetime.now(UTC),
        "producer": "agent-ref://sigma-to-omni-architect",
        "source_references": (
            request.decision_ref,
            *(
                source_ref
                for item in request.source_context_bindings
                for source_ref in (f"artifact-ref://{item.artifact_id}", item.acceptance_ref)
            ),
            *(
                (f"artifact-ref://{request.supersedes_decision.artifact_id}",)
                if request.supersedes_decision is not None
                else ()
            ),
        ),
        "upstream_hashes": (
            *(
                ArtifactInput(artifact_id=item.artifact_id, content_hash=item.content_hash)
                for item in request.source_context_bindings
            ),
            *(
                (
                    ArtifactInput(
                        artifact_id=request.supersedes_decision.artifact_id,
                        content_hash=request.supersedes_decision.content_hash,
                    ),
                )
                if request.supersedes_decision is not None
                else ()
            ),
        ),
        "classification": "stated_evidence",
        "supersession_state": "current",
        "supersedes_artifact_id": (
            request.supersedes_decision.artifact_id
            if request.supersedes_decision is not None
            else None
        ),
        "superseded_by_artifact_id": None,
        "immutable": True,
        "payload": payload,
    }
    draft = SigmaSemanticRoutingArtifact.model_construct(**material, content_hash="0" * 64)
    canonical_material = draft.model_dump(mode="json")
    canonical_material.pop("content_hash")
    return SigmaSemanticRoutingArtifact.model_validate(
        {**canonical_material, "content_hash": sha256_json(canonical_material)}
    )


def advance_sigma_semantic_routing(
    value: SigmaSemanticRoutingDecisionRequest | Mapping[str, Any] | None = None,
    *,
    created_at: datetime | None = None,
) -> SigmaSemanticRoutingPrompt | SigmaSemanticRoutingArtifact:
    """Prompt on a missing/unknown mode; otherwise record the complete, validated decision."""

    if value is None:
        return prompt_for_sigma_semantic_route()
    if isinstance(value, SigmaSemanticRoutingDecisionRequest):
        return create_sigma_semantic_routing_decision(value, created_at=created_at)
    if value.get("mode") not in SEMANTIC_MIGRATION_OPTIONS:
        return prompt_for_sigma_semantic_route()
    return create_sigma_semantic_routing_decision(value, created_at=created_at)


def route_sigma_semantic_specialists(
    decision: SigmaSemanticRoutingArtifact,
) -> tuple[str, ...]:
    """Return a locally current route; callers must verify trusted-store currentness."""

    validated = SigmaSemanticRoutingArtifact.model_validate(decision.model_dump(mode="json"))
    if validated.supersession_state != "current":
        raise ValueError("superseded Sigma semantic routing decisions cannot route specialist work")
    return validated.payload.required_specialist_ids

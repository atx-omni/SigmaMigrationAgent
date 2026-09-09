"""Cross-record policy evaluation for Domo-to-Omni migration runs."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping, Sequence
from urllib.parse import urlsplit

from omni_migrator.control_plane.canonical import (
    DEFAULT_REFERENCE_SCHEMES,
    SECRET_SCHEME,
    parse_time,
    sha256_json,
    utc_now,
    validate_reference,
)
from omni_migrator.control_plane.contract_integrity import (
    validate_migration_lifecycle,
    validate_qa_result,
)
from omni_migrator.control_plane.gates import (
    INDEPENDENT_GATE_IDS,
    PRE_BUILD_SEMANTIC_GATE_IDS,
    REQUIRED_GATE_IDS_BY_WORK_PHASE,
    WRITE_ACTION_BY_WORK_PHASE,
    GateRecordResolver,
    gate_id_from_ref,
    required_gate_ids_for_work_phase,
)
from omni_migrator.control_plane.records import (
    ArtifactEnvelope,
    RecordValidationError,
    downstream_artifact_ids,
    validate_artifact_identity_series,
)
from omni_migrator.control_plane.store import (
    AppendOnlyConflict,
    AppendOnlyControlPlaneStore,
    VerifiedControlPlaneLedger,
)


PHASE_ORDER = [
    "intake",
    "capability_preflight",
    "portfolio_inventoried",
    "scope_approved",
    "acquired",
    "inventoried",
    "dependency_closed",
    "semantic_profiled",
    "equivalence_assessed",
    "consolidation_approved",
    "topic_ready",
    "dashboard_planned",
    "architecture_approved",
    "build_authorized",
    "data_ready",
    "model_ready",
    "dashboard_ready",
    "qa_accepted",
    "docs_ready",
    "dbt_promotion_authorized",
    "dbt_promoted_and_read_back",
    "omni_revalidated",
    "omni_promotion_authorized",
    "omni_promoted_and_read_back",
    "production_revalidated",
    "parallel_run",
    "cutover_authorized",
    "cutover_accepted",
    "hypercare",
    "hypercare_accepted",
    "source_decommission_authorized",
    "source_decommissioned",
]

# Legacy status order remains public for the existing CLI and tests.
STATUS_ORDER = [
    phase
    for phase in PHASE_ORDER
    if phase
    not in {
        "capability_preflight",
        "portfolio_inventoried",
        "scope_approved",
        "dependency_closed",
        "hypercare",
        "hypercare_accepted",
    }
]

REQUIRED_GATE_BY_PHASE: dict[str, list[str]] = {
    "inventoried": ["source_completeness"],
    "dependency_closed": ["source_completeness"],
    "semantic_profiled": ["semantic_profile_complete"],
    "equivalence_assessed": ["target_semantic_profile_ready", "equivalence_assessed"],
    "consolidation_approved": ["consolidation_approved"],
    "topic_ready": [
        "grain_fanout_validated",
        "security_disposition_approved",
        "freshness_ownership_accepted",
    ],
    "dashboard_planned": ["dashboard_plan_ready"],
    "architecture_approved": ["architecture"],
    "build_authorized": ["build_authorization"],
    "data_ready": ["data"],
    "model_ready": ["model"],
    "dashboard_ready": ["content"],
    "qa_accepted": [
        "qa_suite_accepted",
        "query_parity",
        "visual_interaction",
        "security",
        "operations",
    ],
    "docs_ready": ["documentation_training"],
    "dbt_promotion_authorized": ["dbt_promotion"],
    "dbt_promoted_and_read_back": ["dbt_readback"],
    "omni_revalidated": ["omni_revalidation"],
    "omni_promotion_authorized": ["omni_promotion"],
    "omni_promoted_and_read_back": ["omni_readback"],
    "production_revalidated": ["production_validation"],
    "parallel_run": ["parallel_run"],
    "cutover_accepted": ["cutover"],
    "hypercare_accepted": ["hypercare"],
    "source_decommission_authorized": ["hypercare"],
    "source_decommissioned": ["source_decommission"],
}

REQUIRED_ACTIONS_BY_PHASE: dict[str, set[str]] = {
    "dbt_promotion_authorized": {"merge_dbt", "materialize_dbt"},
    "omni_promotion_authorized": {"merge_model_branch", "publish_content"},
    "cutover_authorized": {"cutover"},
    "source_decommission_authorized": {"decommission_source"},
}

HUMAN_GATES = {
    "consolidation_approved",
    "security_disposition_approved",
    "freshness_ownership_accepted",
    "architecture",
    "build_authorization",
    "dbt_promotion",
    "omni_promotion",
    "parallel_run",
    "cutover",
    "hypercare",
    "source_decommission",
}

QA_GATES = {
    "semantic_profile_complete",
    "equivalence_assessed",
    "grain_fanout_validated",
    "dashboard_plan_ready",
    "data",
    "model",
    "content",
    "query_parity",
    "visual_interaction",
    "security",
    "operations",
    "omni_revalidation",
    "production_validation",
    "qa_suite_accepted",
}

NON_WAIVABLE_GATES = {
    *PRE_BUILD_SEMANTIC_GATE_IDS,
    "dashboard_plan_ready",
    "qa_suite_accepted",
    "security",
    "production_validation",
}

REQUIRED_PACKAGE_GATE_IDS_BY_WORK_PHASE: dict[str, frozenset[str]] = {
    phase: frozenset(gate_ids) for phase, gate_ids in REQUIRED_GATE_IDS_BY_WORK_PHASE.items()
}

REQUIRED_COMPLETED_WORK_BY_PHASE: dict[str, dict[tuple[str, str], frozenset[str]]] = {
    "semantic_profiled": {
        ("domo_bi_developer", "source_interpretation"): frozenset({"semantic_profile"}),
        ("domo_analytics_engineer", "source_interpretation"): frozenset({"semantic_profile"}),
        ("dbt_analytics_engineer", "repository_inventory"): frozenset(
            {"repository_inventory", "semantic_profile"}
        ),
        ("domo_to_omni_architect", "target_semantic_design"): frozenset(
            {"target_semantic_profile"}
        ),
        ("domo_to_omni_architect", "semantic_profiling"): frozenset(
            {"semantic_profile_coverage"}
        ),
    },
    "equivalence_assessed": {
        ("semantic_consolidation", "semantic_consolidation"): frozenset(
            {
                "equivalence_assessment",
                "consolidation_candidate",
                "consolidation_decision",
            }
        ),
    },
    "topic_ready": {
        ("domo_to_omni_architect", "topic_design"): frozenset({"topic_blueprint"}),
    },
    "dashboard_planned": {
        ("domo_to_omni_architect", "dashboard_planning"): frozenset({"dashboard_rebuild_plan"}),
    },
    "architecture_approved": {
        ("domo_to_omni_architect", "architecture"): frozenset(
            {
                "target_architecture",
                "work_package_dag",
                "validation_matrix",
                "persona_policy",
                "tolerance_policy",
            }
        ),
    },
    "data_ready": {
        ("dbt_analytics_engineer", "data_build"): frozenset(
            {
                "dbt_changes",
                "dbt_test_evidence",
                "data_reconciliation",
                "target_write_receipt",
            }
        ),
    },
    "model_ready": {
        ("omni_modeler", "semantic_build"): frozenset(
            {
                "omni_model_changes",
                "model_validation",
                "semantic_query_evidence",
                "target_write_receipt",
            }
        ),
    },
    "dashboard_ready": {
        ("omni_bi_developer", "content_build"): frozenset(
            {
                "omni_content_artifact",
                "target_write_receipt",
                "document_readback",
                "target_visual_fixtures",
            }
        ),
    },
    "qa_accepted": {
        ("migration_qa", "development_qa"): frozenset(
            {
                "qa_result",
                "qa_acceptance_suite",
                "qa_suite_validation",
                "validation_report",
                "defect_ledger",
                "independent_verdict",
            }
        ),
    },
    "docs_ready": {
        ("documentation_training", "documentation"): frozenset(
            {
                "change_map",
                "source_target_lineage",
                "user_guide",
                "admin_runbook",
                "training_package",
                "documentation_package",
            }
        ),
    },
    "production_revalidated": {
        ("migration_qa", "production_qa"): frozenset(
            {
                "qa_result",
                "qa_acceptance_suite",
                "qa_suite_validation",
                "qa_target_operation_outcome",
                "production_validation_report",
                "independent_verdict",
            }
        ),
    },
}

LINEAGE_REQUIRED_ARTIFACT_TYPES = frozenset(
    artifact_type
    for threshold, requirements in REQUIRED_COMPLETED_WORK_BY_PHASE.items()
    for artifact_types in requirements.values()
    for artifact_type in artifact_types
)

RELEASE_ACTIONS = {
    "merge_dbt",
    "materialize_dbt",
    "merge_model_branch",
    "publish_content",
    "cutover",
    "decommission_source",
}

LEGACY_TOOL_PROFILES: dict[str, set[str]] = {
    "orchestrator_read_delegate_and_manifest_write": {
        "artifact_registry_read",
        "artifact_registry_write",
        "control_plane_validate",
        "domo_evidence_broker_invoke",
        "local_draft_write",
        "specialist_delegate",
    },
    "domo_content_metadata_and_bounded_visual_read": {
        "artifact_registry_read",
        "domo_card_read",
        "domo_metadata_read",
        "domo_page_read",
        "domo_query_read",
        "domo_visual_read",
        "local_draft_write",
    },
    "domo_dataflow_dataset_and_sql_read": {
        "artifact_registry_read",
        "domo_dataflow_read",
        "domo_dataset_read",
        "domo_metadata_read",
        "domo_query_read",
        "local_draft_write",
        "source_sql_read",
    },
    "read_only_dbt_repository_inventory": {
        "artifact_registry_read",
        "artifact_registry_write",
        "control_plane_validate",
        "dbt_branch_read",
        "local_draft_write",
    },
    "semantic_evidence_read_and_proposal_only": {
        "artifact_registry_read",
        "artifact_registry_write",
        "control_plane_validate",
        "local_draft_write",
    },
    "authorized_dbt_branch_and_snowflake_development": {
        "artifact_registry_read",
        "artifact_registry_write",
        "dbt_branch_read",
        "dbt_branch_write",
        "dbt_build",
        "dbt_compile",
        "dbt_test",
        "local_draft_write",
        "snowflake_bounded_query",
    },
    "authorized_omni_model_branch_checksum_write_and_validate": {
        "artifact_registry_read",
        "artifact_registry_write",
        "omni_content_validate",
        "omni_model_read",
        "omni_model_validate",
        "omni_model_write",
        "omni_query_read",
    },
    "authorized_documents_v2_quarantine_create": {
        "artifact_registry_read",
        "artifact_registry_write",
        "omni_document_create_quarantine",
        "omni_document_read",
    },
    "authorized_documents_v2_draft_update": {
        "artifact_registry_read",
        "artifact_registry_write",
        "omni_document_draft_write",
        "omni_document_read",
        "omni_query_read",
        "omni_visual_read",
    },
    "bounded_queries_validators_downloads_and_persona_tests": {
        "artifact_registry_read",
        "artifact_registry_write",
        "control_plane_validate",
        "domo_query_read",
        "domo_visual_read",
        "omni_content_validate",
        "omni_query_read",
        "omni_visual_read",
        "persona_test_read",
        "snowflake_bounded_query",
    },
    "accepted_artifact_read_and_document_draft_write": {
        "artifact_registry_read",
        "local_draft_write",
    },
}


@dataclass(frozen=True)
class PolicyContext:
    """Optional records needed for production-strength validation.

    The legacy one-file validator sets ``strict=False``. Production callers should
    set ``strict=True`` and provide every referenced record.
    """

    strict: bool = False
    now: datetime = field(default_factory=utc_now)
    work_packages: Sequence[Mapping[str, Any]] = ()
    artifacts: Sequence[Mapping[str, Any] | ArtifactEnvelope] = ()
    events: Sequence[Mapping[str, Any]] = ()
    verified_event_ledger: VerifiedControlPlaneLedger | None = None
    qa_results: Sequence[Mapping[str, Any]] = ()
    qa_fixtures_v2: Sequence[Mapping[str, Any]] = ()
    qa_results_v2: Sequence[Mapping[str, Any]] = ()
    qa_suites: Sequence[Mapping[str, Any]] = ()
    qa_suite_validations: Sequence[Mapping[str, Any]] = ()
    production_validation_reports: Sequence[Mapping[str, Any]] = ()
    documentation_packages: Sequence[Mapping[str, Any]] = ()
    lifecycle: Mapping[str, Any] | None = None
    agent_registry: Mapping[str, Any] | None = None
    artifact_registry: Mapping[str, Any] | None = None
    actor_kinds: Mapping[str, str] = field(default_factory=dict)
    allowed_reference_schemes: frozenset[str] = DEFAULT_REFERENCE_SCHEMES
    allowed_hosts: frozenset[str] = frozenset()


def _required_package_gate_ids_for_work_package(
    work_package: Mapping[str, Any], context: PolicyContext
) -> frozenset[str]:
    """Apply Sigma route prerequisites only after checking its exact registered choice."""

    phase = str(work_package.get("phase", ""))
    sigma_scoped = any(
        isinstance(item, Mapping) and item.get("system") == "sigma"
        for item in work_package.get("source_scope", [])
    )
    if not sigma_scoped and work_package.get("sigma_routing") is None:
        return REQUIRED_PACKAGE_GATE_IDS_BY_WORK_PHASE.get(phase, frozenset())

    # A mode hint cannot waive a lifecycle prerequisite. Validate the complete
    # shared package and resolve its exact route selection from the canonical ledger.
    from omni_migrator.extractors.sigma.capability_contracts import SigmaSemanticRoutingArtifact
    from omni_migrator.extractors.sigma.semantic_routing import route_sigma_semantic_specialists
    from omni_migrator.orchestration.planner import PlannedWorkPackage

    package = PlannedWorkPackage.model_validate(work_package)
    binding = package.sigma_routing
    ledger = context.verified_event_ledger
    if (
        binding is None or type(ledger) is not VerifiedControlPlaneLedger
        or ledger.tenant_ref != package.tenant_ref or ledger.run_id != package.run_id
    ):
        raise ValueError("Sigma work prerequisites require the verified route ledger")
    selections = [
        record["payload"] for record in ledger.records
        if record.get("record_type") == "event"
        and record.get("payload", {}).get("event_type") in {
            "sigma_route_selected", "sigma_route_revoked"
        }
        and record["payload"].get("migration_unit_id") == package.migration_unit_id
    ]
    current = selections[-1] if selections else {}
    if (
        current.get("event_type") != "sigma_route_selected"
        or current.get("validation_cycle_id") != package.validation_cycle_id
        or current.get("decision_ref") != binding.decision_ref
        or current.get("decision_hash") != binding.decision_hash
        or current.get("mode") != binding.mode
    ):
        raise ValueError("Sigma work does not bind the current registered semantic route")
    decision = SigmaSemanticRoutingArtifact.model_validate(current.get("decision"))
    route_sigma_semantic_specialists(decision)
    if decision.content_hash != binding.decision_hash or (
        f"artifact-ref://{decision.artifact_id}" != binding.decision_ref
    ):
        raise ValueError("Sigma work does not bind the registered full decision artifact")
    subject = decision.payload.model_dump(mode="json")
    expected_subject = {
        "run_id": package.run_id,
        "scope_id": binding.scope_id,
        "migration_unit_id": package.migration_unit_id,
        "mode": binding.mode,
        "comparison_scope_refs": binding.comparison_scope_refs,
        "build_scope_refs": binding.build_scope_refs,
        "target_environment_refs": binding.target_environment_refs,
    }
    if any(subject.get(key) != value for key, value in expected_subject.items()):
        raise ValueError("Sigma work scope differs from the registered human route decision")
    registered_sources = {
        item["artifact_id"]: item["content_hash"]
        for item in subject.get("source_context_bindings", [])
    }
    if registered_sources != binding.source_artifact_hashes:
        raise ValueError("Sigma work source hashes differ from the registered decision")
    hashes = {**binding.source_artifact_hashes, decision.artifact_id: binding.decision_hash}
    latest: dict[str, Mapping[str, Any]] = {}
    for record in ledger.records:
        if record.get("record_type") != "artifact":
            continue
        artifact = record["payload"]
        artifact_id = artifact["artifact_id"]
        previous = latest.get(artifact_id)
        if previous is None or artifact["revision"] > previous["revision"]:
            latest[artifact_id] = artifact
    if any(
        artifact_id not in latest or latest[artifact_id].get("content_sha256") != digest
        or latest[artifact_id].get("ref") != f"artifact-ref://{artifact_id}"
        or latest[artifact_id].get("migration_unit_id") != package.migration_unit_id
        or latest[artifact_id].get("validation_cycle_id") != package.validation_cycle_id
        for artifact_id, digest in hashes.items()
    ):
        raise ValueError("Sigma work source or decision artifacts are stale or unregistered")
    return frozenset(required_gate_ids_for_work_phase(phase, sigma_semantic_mode=binding.mode))


def _phase_index(phase: str) -> int:
    try:
        return PHASE_ORDER.index(phase)
    except ValueError:
        return -1


def reached(phase: str, threshold: str) -> bool:
    phase_index = _phase_index(phase)
    threshold_index = _phase_index(threshold)
    return phase_index >= 0 and threshold_index >= 0 and phase_index >= threshold_index


def _manifest_phase_health(
    manifest: Mapping[str, Any], errors: list[str], strict: bool
) -> tuple[str, str]:
    status = str(manifest.get("status", ""))
    phase = str(manifest.get("phase") or manifest.get("runtime", {}).get("phase") or status)
    health = str(manifest.get("health") or manifest.get("runtime", {}).get("health") or "active")
    if status == "blocked":
        health = "blocked"
        if phase == "blocked":
            if strict:
                errors.append(
                    "blocked run must preserve its lifecycle phase separately from health"
                )
            phase = "intake"
    elif status in {"cancelled", "canceled"}:
        health = "cancelled"
    elif status == "source_decommissioned":
        health = "complete"
    if _phase_index(phase) < 0:
        errors.append(f"unknown lifecycle phase: {phase}")
    if health not in {"active", "blocked", "cancelled", "complete"}:
        errors.append(f"unknown run health: {health}")
    return phase, health


def _reference_identity(reference: str) -> str:
    parsed = urlsplit(reference)
    return "/".join(part for part in (parsed.netloc, parsed.path.strip("/")) if part)


def _is_human(reference: str | None, context: PolicyContext) -> bool:
    if not reference:
        return False
    if context.actor_kinds.get(reference) == "human":
        return True
    if context.strict:
        return False
    return urlsplit(reference).scheme.lower() in {"human-ref", "person-ref"}


def _is_qa(reference: str | None, context: PolicyContext) -> bool:
    if not reference:
        return False
    if _is_human(reference, context):
        return True
    if context.actor_kinds.get(reference) == "independent_qa":
        return True
    if context.strict:
        return False
    parsed = urlsplit(reference)
    identity = _reference_identity(reference).replace("-", "_")
    return parsed.scheme.lower() == "agent-ref" and identity == "migration_qa"


def _payload(event: Mapping[str, Any]) -> Mapping[str, Any]:
    payload = event.get("payload")
    return payload if isinstance(payload, Mapping) else event


def _validate_references(
    value: Any, context: PolicyContext, errors: list[str], path: str = "manifest"
) -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            child_path = f"{path}.{key}"
            if key in {"credential_ref", "credential_refs"}:
                candidates = child if isinstance(child, list) else [child]
                for candidate in candidates:
                    if candidate is None:
                        continue
                    try:
                        if urlsplit(str(candidate)).scheme.lower() != SECRET_SCHEME:
                            raise ValueError("credential fields require an opaque secret-ref URI")
                        validate_reference(
                            str(candidate),
                            allowed_schemes=context.allowed_reference_schemes,
                            allowed_hosts=context.allowed_hosts,
                            allow_secret=True,
                        )
                    except ValueError as exc:
                        errors.append(f"invalid secret reference at {child_path}: {exc}")
            elif key == "ref" or key.endswith("_ref") or key.endswith("_refs"):
                candidates = child if isinstance(child, list) else [child]
                for candidate in candidates:
                    if candidate is None:
                        continue
                    if not isinstance(candidate, str):
                        _validate_references(candidate, context, errors, child_path)
                        continue
                    try:
                        validate_reference(
                            candidate,
                            allowed_schemes=context.allowed_reference_schemes,
                            allowed_hosts=context.allowed_hosts,
                            require_known_scheme=context.strict,
                        )
                    except ValueError as exc:
                        errors.append(f"invalid reference at {child_path}: {exc}")
            else:
                _validate_references(child, context, errors, child_path)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _validate_references(child, context, errors, f"{path}[{index}]")


def _duplicates(values: Iterable[str]) -> set[str]:
    seen: set[str] = set()
    duplicate: set[str] = set()
    for value in values:
        if value in seen:
            duplicate.add(value)
        seen.add(value)
    return duplicate


def _required_gates(phase: str) -> set[str]:
    required: set[str] = set()
    for threshold, gate_ids in REQUIRED_GATE_BY_PHASE.items():
        if reached(phase, threshold):
            required.update(gate_ids)
    return required


def _event_type(event: Mapping[str, Any]) -> str:
    return str(_payload(event).get("event_type", event.get("event_type", "")))


def _validate_event_history(
    manifest: Mapping[str, Any], phase: str, context: PolicyContext, errors: list[str]
) -> None:
    if not context.events:
        return
    tenant_ref = str(manifest["source"]["tenant_ref"])
    run_id = str(manifest["run_id"])
    sequences: list[int] = []
    transition_phase: str | None = None
    transition_health = "active"
    ordered_events = sorted(context.events, key=lambda item: int(item.get("sequence", 0)))
    ledger_records = [item for item in ordered_events if "record_hash" in item]
    if context.strict and len(ledger_records) != len(ordered_events):
        errors.append("strict event history requires canonical hash-chained records")
    if ledger_records and len(ledger_records) != len(ordered_events):
        errors.append("event history cannot mix hash-chained and unchained records")
    previous_hash: str | None = None
    for ledger_record in ledger_records:
        if ledger_record.get("previous_hash") != previous_hash:
            errors.append("event ledger hash chain is broken")
        previous_hash = str(ledger_record.get("record_hash", ""))
    for event in ordered_events:
        if context.strict and event.get("tenant_ref") != tenant_ref:
            errors.append("event is missing or crosses tenant partition")
        elif event.get("tenant_ref") not in {None, tenant_ref}:
            errors.append("event crosses tenant partition")
        if context.strict and event.get("run_id") != run_id:
            errors.append("event is missing or crosses run partition")
        elif event.get("run_id") not in {None, run_id}:
            errors.append("event crosses run partition")
        if context.strict and "record_hash" in event:
            material = {key: value for key, value in event.items() if key != "record_hash"}
            if event.get("record_hash") != sha256_json(material):
                errors.append("event ledger record hash is invalid")
            payload = event.get("payload", {})
            if event.get("payload_sha256") != sha256_json(payload):
                errors.append("event ledger payload hash is invalid")
        if "sequence" in event:
            sequences.append(int(event["sequence"]))
        payload = _payload(event)
        if _event_type(event) != "state_transition":
            continue
        from_phase = str(payload.get("from_phase", transition_phase or ""))
        to_phase = str(payload.get("to_phase", ""))
        from_health = str(payload.get("from_health", transition_health))
        to_health = str(payload.get("to_health", from_health))
        reason = str(payload.get("reason", "normal"))
        if transition_phase is not None and from_phase != transition_phase:
            errors.append("state transition does not continue from the prior recorded phase")
        if from_health != transition_health:
            errors.append("state transition does not continue from the prior recorded health")
        from_index = _phase_index(from_phase)
        to_index = _phase_index(to_phase)
        if from_index < 0 or to_index < 0:
            errors.append("state transition uses an unknown phase")
        elif reason in {"invalidation", "rollback"}:
            if to_index >= from_index:
                errors.append("invalidation or rollback transition must move to an earlier phase")
            if not payload.get("evidence_refs"):
                errors.append("invalidation or rollback transition requires evidence")
        elif to_index not in {from_index, from_index + 1}:
            errors.append(f"illegal phase transition: {from_phase} -> {to_phase}")
        allowed_health = {
            "active": {"active", "blocked", "cancelled", "complete"},
            "blocked": {"blocked", "active", "cancelled"},
            "cancelled": {"cancelled"},
            "complete": {"complete"},
        }
        if to_health not in allowed_health.get(from_health, set()):
            errors.append(f"illegal health transition: {from_health} -> {to_health}")
        transition_phase = to_phase
        transition_health = to_health
    if sequences and sequences != list(range(1, len(sequences) + 1)):
        errors.append("event sequence must be contiguous and start at one")
    if context.strict and transition_phase is not None and transition_phase != phase:
        errors.append("manifest phase does not match latest state-transition event")

    verified = context.verified_event_ledger
    invalid_verified_capability = (
        verified is not None and type(verified) is not VerifiedControlPlaneLedger
    )
    if invalid_verified_capability:
        errors.append(
            "verified event ledger is not the exact runtime capability issued by the "
            "canonical control-plane store"
        )
        verified = None
    if verified is not None:
        if verified.tenant_ref != tenant_ref or verified.run_id != run_id:
            errors.append("verified event ledger crosses the manifest partition")
        if verified.record_count != len(ordered_events):
            errors.append("verified event ledger record count differs from policy input")
        if list(verified.records) != ordered_events:
            errors.append("policy events differ from the verified canonical store ledger")
        if not ordered_events or verified.ledger_head != ordered_events[-1].get("record_hash"):
            errors.append("verified event ledger head differs from policy input")
    if (
        context.strict
        and reached(phase, "semantic_profiled")
        and verified is None
        and not invalid_verified_capability
    ):
        errors.append(
            "semantic profiling or later requires a ledger issued by the canonical control-plane store"
        )


def _registered_agents(context: PolicyContext) -> dict[str, Mapping[str, Any]]:
    registry = context.agent_registry or {}
    return {
        str(agent["id"]): agent
        for agent in registry.get("agents", [])
        if isinstance(agent, Mapping) and agent.get("id")
    }


def _tool_profiles(context: PolicyContext) -> dict[str, set[str]]:
    profiles = (
        {} if context.strict else {key: set(value) for key, value in LEGACY_TOOL_PROFILES.items()}
    )
    registry = context.agent_registry or {}
    raw_profiles = registry.get("tool_profiles", {})
    if isinstance(raw_profiles, Mapping):
        for name, value in raw_profiles.items():
            if isinstance(value, Mapping):
                tools = value.get("allowed_tools", [])
            else:
                tools = value
            if isinstance(tools, Sequence) and not isinstance(tools, (str, bytes)):
                profiles[str(name)] = {str(tool) for tool in tools}
    elif isinstance(raw_profiles, Sequence):
        for value in raw_profiles:
            if isinstance(value, Mapping) and value.get("id"):
                profiles[str(value["id"])] = {str(tool) for tool in value.get("allowed_tools", [])}
    return profiles


def _artifact_producers(context: PolicyContext) -> dict[str, set[str]]:
    registry = context.artifact_registry or {}
    return {
        str(artifact["id"]): {str(producer) for producer in artifact.get("producers", [])}
        for artifact in registry.get("artifact_types", [])
        if isinstance(artifact, Mapping) and artifact.get("id")
    }


def _normalize_artifacts(
    manifest: Mapping[str, Any], context: PolicyContext, errors: list[str]
) -> list[ArtifactEnvelope]:
    tenant_ref = str(manifest["source"]["tenant_ref"])
    run_id = str(manifest["run_id"])
    artifacts: list[ArtifactEnvelope] = []
    identities: set[tuple[str, int]] = set()
    refs: set[str] = set()
    producers_by_type = _artifact_producers(context)
    for raw in context.artifacts:
        try:
            artifact = (
                raw if isinstance(raw, ArtifactEnvelope) else ArtifactEnvelope.from_mapping(raw)
            )
            artifact.validate(expected_tenant_ref=tenant_ref, expected_run_id=run_id)
        except (KeyError, TypeError, ValueError, RecordValidationError) as exc:
            errors.append(f"invalid artifact envelope: {exc}")
            continue
        identity = (artifact.artifact_id, artifact.revision)
        if identity in identities:
            errors.append(
                f"duplicate artifact revision: {artifact.artifact_id}@{artifact.revision}"
            )
        identities.add(identity)
        if artifact.ref in refs:
            errors.append(f"duplicate artifact reference: {artifact.ref}")
        refs.add(artifact.ref)
        allowed_producers = producers_by_type.get(artifact.artifact_type)
        if context.strict and producers_by_type and allowed_producers is None:
            errors.append(f"unregistered artifact type: {artifact.artifact_type}")
        if allowed_producers is not None:
            producer_identity = _reference_identity(artifact.producer_ref).replace("-", "_")
            if producer_identity not in allowed_producers:
                errors.append(
                    f"producer {producer_identity} cannot create artifact type {artifact.artifact_type}"
                )
        artifacts.append(artifact)
    try:
        validate_artifact_identity_series(artifacts)
    except RecordValidationError as exc:
        errors.append(f"invalid artifact identity series: {exc}")
    by_revision = {(item.artifact_id, item.revision): item for item in artifacts}
    for artifact in artifacts:
        for input_item in artifact.input_artifacts:
            key = (str(input_item.get("artifact_id")), int(input_item.get("revision", 0)))
            parent = by_revision.get(key)
            if parent is None:
                errors.append(
                    f"artifact {artifact.artifact_id} references a missing input revision: {key}"
                )
            elif str(input_item.get("content_sha256")) != parent.content_sha256:
                errors.append(
                    f"artifact {artifact.artifact_id} input hash does not match registered input"
                )
    return artifacts


def _validate_store_attested_artifact_envelopes(
    phase: str,
    context: PolicyContext,
    artifacts: list[ArtifactEnvelope],
    errors: list[str],
) -> None:
    """Bind readiness-critical context artifacts to exact trusted store records."""

    if not context.strict or not reached(phase, "qa_accepted"):
        return

    from omni_migrator.qa.acceptance import finalize_qa_acceptance_suite

    trusted_refs: set[str] = set()
    for raw in context.qa_suites:
        try:
            suite = finalize_qa_acceptance_suite(raw)
        except (TypeError, ValueError):
            continue
        trusted_refs.update(item.artifact_ref for item in suite.bindings.all_artifacts())

    readiness_artifact_types = {
        "qa_acceptance_suite",
        "qa_suite_validation",
        "qa_target_operation_outcome",
        "production_validation_report",
    }
    current_context_by_id = {
        artifact.artifact_id: max(
            (item for item in artifacts if item.artifact_id == artifact.artifact_id),
            key=lambda item: item.revision,
        )
        for artifact in artifacts
    }
    trusted_context = [
        item
        for item in current_context_by_id.values()
        if item.ref in trusted_refs or item.artifact_type in readiness_artifact_types
    ]

    stored_by_id: dict[str, ArtifactEnvelope] = {}
    for record in context.events:
        if record.get("record_type") != "artifact":
            continue
        payload = record.get("payload")
        if not isinstance(payload, Mapping):
            continue
        try:
            stored = ArtifactEnvelope.from_mapping(payload)
        except (TypeError, ValueError, RecordValidationError):
            continue
        current = stored_by_id.get(stored.artifact_id)
        if current is None or stored.revision > current.revision:
            stored_by_id[stored.artifact_id] = stored

    for artifact in trusted_context:
        stored = stored_by_id.get(artifact.artifact_id)
        if stored is None or stored.to_mapping() != artifact.to_mapping():
            errors.append(
                f"readiness artifact is not the exact trusted store envelope: {artifact.ref}"
            )


def _stale_artifact_ids(
    artifacts: list[ArtifactEnvelope], events: Sequence[Mapping[str, Any]]
) -> set[str]:
    latest_revision: dict[str, int] = {}
    stale_roots: set[str] = set()
    for artifact in artifacts:
        latest_revision[artifact.artifact_id] = max(
            artifact.revision, latest_revision.get(artifact.artifact_id, 0)
        )
    for artifact in artifacts:
        for input_item in artifact.input_artifacts:
            parent_id = str(input_item.get("artifact_id"))
            if int(input_item.get("revision", 0)) < latest_revision.get(parent_id, 0):
                stale_roots.add(artifact.artifact_id)
    for event in events:
        payload = _payload(event)
        if _event_type(event) == "artifact_invalidated" and payload.get("artifact_id"):
            stale_roots.add(str(payload["artifact_id"]))
    return downstream_artifact_ids(artifacts, stale_roots)


def _validate_strict_run_evidence(
    phase: str,
    context: PolicyContext,
    artifacts: list[ArtifactEnvelope],
    errors: list[str],
) -> None:
    """Prevent phase advancement from trusting manifest summary flags alone."""

    if not context.strict or not reached(phase, "capability_preflight"):
        return
    if not context.events:
        errors.append("strict phase advancement requires append-only lifecycle events")
    if not context.work_packages:
        errors.append("strict phase advancement requires registered work-package records")
    required_types: set[str] = set()
    if reached(phase, "acquired"):
        required_types.update(
            {
                "source_object_graph",
                "evidence_bundle",
                "coverage_ledger",
                "domo_inventory_observation",
            }
        )
    if reached(phase, "inventoried"):
        required_types.update({"inventory_snapshot", "domo_portfolio_inventory"})
    if reached(phase, "dependency_closed"):
        required_types.add("migration_scope")
    actual_types = {artifact.artifact_type for artifact in artifacts}
    if missing := required_types - actual_types:
        errors.append(f"strict phase advancement lacks registered artifacts: {sorted(missing)}")


def _validate_domo_inventory_registrations(
    phase: str,
    context: PolicyContext,
    artifacts: list[ArtifactEnvelope],
    errors: list[str],
) -> None:
    """Require content-bound source observations and portfolios before semantics."""

    if not context.strict or not reached(phase, "acquired"):
        return

    from omni_migrator.control_plane.store import (
        _registered_domo_observations,
        _registered_domo_portfolio,
    )

    records = [dict(item) for item in context.events]
    event_payloads = [
        item.get("payload", item)
        for item in records
        if isinstance(item.get("payload", item), Mapping)
    ]
    observation_scopes = {
        str(payload.get("observation", {}).get("scope_id", ""))
        for payload in event_payloads
        if payload.get("event_type") == "domo_inventory_observation_registered"
        and isinstance(payload.get("observation"), Mapping)
    }
    portfolio_scopes = {
        str(payload.get("portfolio", {}).get("scope_id", ""))
        for payload in event_payloads
        if payload.get("event_type") == "domo_portfolio_inventory_registered"
        and isinstance(payload.get("portfolio"), Mapping)
    }
    scopes = (observation_scopes | portfolio_scopes) - {""}
    if not scopes:
        errors.append(
            "strict acquired source evidence lacks typed Domo observation registrations"
        )
        return

    tenant_ref = str(
        next(
            (
                artifact.tenant_ref
                for artifact in artifacts
                if artifact.artifact_type == "domo_inventory_observation"
            ),
            "",
        )
    )
    run_id = str(
        next(
            (
                artifact.run_id
                for artifact in artifacts
                if artifact.artifact_type == "domo_inventory_observation"
            ),
            "",
        )
    )
    registered_observation_refs: set[str] = set()
    registered_portfolio_refs: set[str] = set()
    for payload in event_payloads:
        artifact = payload.get("artifact")
        if not isinstance(artifact, Mapping):
            continue
        if payload.get("event_type") == "domo_inventory_observation_registered":
            registered_observation_refs.add(str(artifact.get("ref", "")))
        elif payload.get("event_type") == "domo_portfolio_inventory_registered":
            registered_portfolio_refs.add(str(artifact.get("ref", "")))

    try:
        for scope_id in sorted(scopes):
            observations = _registered_domo_observations(
                records,
                tenant_ref=tenant_ref,
                run_id=run_id,
                scope_id=scope_id,
            )
            if not observations:
                errors.append(
                    f"Domo inventory scope lacks registered observations: {scope_id}"
                )
            if reached(phase, "inventoried"):
                portfolio = _registered_domo_portfolio(
                    records,
                    tenant_ref=tenant_ref,
                    run_id=run_id,
                    scope_id=scope_id,
                )
                if portfolio is None:
                    errors.append(
                        f"Domo inventory scope lacks a registered portfolio: {scope_id}"
                    )
                elif portfolio.get("summary", {}).get("catalog_state") != "complete":
                    errors.append(
                        f"Domo inventory portfolio is not complete: {scope_id}"
                    )
    except AppendOnlyConflict as exc:
        errors.append(f"invalid typed Domo inventory registration: {exc}")

    current_by_id = {
        artifact.artifact_id: max(
            (
                item
                for item in artifacts
                if item.artifact_id == artifact.artifact_id
            ),
            key=lambda item: item.revision,
        )
        for artifact in artifacts
    }
    current_observation_refs = {
        artifact.ref
        for artifact in current_by_id.values()
        if artifact.artifact_type == "domo_inventory_observation"
    }
    if current_observation_refs != registered_observation_refs:
        errors.append(
            "current Domo observation artifacts do not exactly match typed registrations"
        )
    if reached(phase, "inventoried"):
        current_portfolio_refs = {
            artifact.ref
            for artifact in current_by_id.values()
            if artifact.artifact_type == "domo_portfolio_inventory"
        }
        if current_portfolio_refs != registered_portfolio_refs:
            errors.append(
                "current Domo portfolio artifacts do not exactly match typed registrations"
            )


def _validate_external_handoff_registrations(
    phase: str,
    context: PolicyContext,
    errors: list[str],
) -> None:
    """Bind every portfolio redesign reference to its accepted planned assignment."""

    if not context.strict or not reached(phase, "architecture_approved"):
        return

    from omni_migrator.control_plane.store import (
        _registered_domo_portfolio,
        _registered_external_redesign_handoffs,
    )

    records = [dict(item) for item in context.events]
    portfolio_scopes = {
        str(record.get("payload", {}).get("portfolio", {}).get("scope_id", ""))
        for record in records
        if record.get("record_type") == "event"
        and record.get("payload", {}).get("event_type")
        == "domo_portfolio_inventory_registered"
    } - {""}
    if not portfolio_scopes:
        return

    work_packages_by_id: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for work_package in context.work_packages:
        work_packages_by_id[str(work_package.get("work_package_id", ""))].append(
            work_package
        )

    required_refs_seen: set[str] = set()
    registered_refs_seen: set[str] = set()
    try:
        for scope_id in sorted(portfolio_scopes):
            portfolio = _registered_domo_portfolio(
                records,
                tenant_ref=str(
                    next(
                        (
                            record.get("tenant_ref")
                            for record in records
                            if record.get("record_type") == "event"
                            and record.get("payload", {}).get("portfolio", {}).get(
                                "scope_id"
                            )
                            == scope_id
                        ),
                        "",
                    )
                ),
                run_id=str(
                    next(
                        (
                            record.get("run_id")
                            for record in records
                            if record.get("record_type") == "event"
                            and record.get("payload", {}).get("portfolio", {}).get(
                                "scope_id"
                            )
                            == scope_id
                        ),
                        "",
                    )
                ),
                scope_id=scope_id,
            )
            if portfolio is None:
                continue
            tenant_ref = str(portfolio.get("source_tenant_ref", ""))
            run_id = str(portfolio.get("run_id", ""))
            required_refs = {
                str(reference)
                for item in portfolio.get("objects", [])
                if item.get("external_handoff_required") is True
                for reference in item.get("redesign_handoff_refs", [])
            }
            duplicate_required = required_refs_seen.intersection(required_refs)
            if duplicate_required:
                errors.append(
                    "external redesign handoff references cannot span portfolio scopes: "
                    f"{sorted(duplicate_required)}"
                )
            required_refs_seen.update(required_refs)

            handoffs = _registered_external_redesign_handoffs(
                records,
                tenant_ref=tenant_ref,
                run_id=run_id,
                scope_id=scope_id,
            )
            registered_refs = {item.handoff_ref for item in handoffs}
            registered_refs_seen.update(registered_refs)
            if registered_refs != required_refs:
                errors.append(
                    "portfolio redesign handoff references do not exactly match accepted "
                    f"registrations for scope {scope_id}: "
                    f"missing={sorted(required_refs - registered_refs)}, "
                    f"extra={sorted(registered_refs - required_refs)}"
                )

            for handoff in handoffs:
                assignment_packages = work_packages_by_id.get(
                    handoff.assignment_work_package_id, []
                )
                if len(assignment_packages) != 1:
                    errors.append(
                        "external redesign handoff requires exactly one architect assignment "
                        f"work package: {handoff.handoff_ref}"
                    )
                else:
                    assignment_package = assignment_packages[0]
                    assignment_assignee = assignment_package.get("assignee", {})
                    if (
                        assignment_package.get("tenant_ref") != handoff.tenant_ref
                        or assignment_package.get("run_id") != handoff.run_id
                        or assignment_package.get("migration_unit_id")
                        != handoff.migration_unit_id
                        or assignment_package.get("validation_cycle_id")
                        != handoff.validation_cycle_id
                        or assignment_package.get("phase") != "architecture"
                        or assignment_assignee.get("kind") != "agent"
                        or assignment_assignee.get("agent_id")
                        != "domo_to_omni_architect"
                    ):
                        errors.append(
                            "external redesign assignment producer work package is not exact: "
                            f"{handoff.handoff_ref}"
                        )
                    if "external_redesign_assignment" not in {
                        str(item)
                        for item in assignment_package.get("expected_artifacts", [])
                    }:
                        errors.append(
                            "architect work package must expect the external redesign assignment: "
                            f"{handoff.handoff_ref}"
                        )
                    if _result_artifact_refs(assignment_package).count(
                        handoff.handoff_ref
                    ) != 1:
                        errors.append(
                            "architect work package must return its exact external redesign "
                            f"assignment once: {handoff.handoff_ref}"
                        )

                packages = work_packages_by_id.get(handoff.work_package_id, [])
                if len(packages) != 1:
                    errors.append(
                        "external redesign handoff requires exactly one registered work "
                        f"package: {handoff.handoff_ref}"
                    )
                    continue
                work_package = packages[0]
                assignee = work_package.get("assignee", {})
                if (
                    work_package.get("tenant_ref") != handoff.tenant_ref
                    or work_package.get("run_id") != handoff.run_id
                    or work_package.get("migration_unit_id")
                    != handoff.migration_unit_id
                    or work_package.get("validation_cycle_id")
                    != handoff.validation_cycle_id
                    or assignee.get("kind") != "external_team"
                    or assignee.get("capability") != handoff.capability
                    or assignee.get("owner_ref") != handoff.owner_ref
                ):
                    errors.append(
                        "external redesign handoff work-package assignment is not exact: "
                        f"{handoff.handoff_ref}"
                    )
                input_refs = [str(item) for item in work_package.get("input_refs", [])]
                if input_refs.count(handoff.handoff_ref) != 1:
                    errors.append(
                        "external redesign handoff work package must consume its exact "
                        f"handoff reference once: {handoff.handoff_ref}"
                    )
                external_result_refs = {
                    *_result_artifact_refs(work_package),
                    *_result_evidence_refs(work_package),
                }
                if handoff.handoff_ref in external_result_refs:
                    errors.append(
                        "external redesign assignment artifact cannot satisfy external "
                        f"completion: {handoff.handoff_ref}"
                    )
                expected_scope = {
                    (
                        "domo",
                        item.object_type,
                        item.object_id,
                        item.object_hash.removeprefix("sha256:"),
                    )
                    for item in handoff.source_objects
                }
                actual_scope = {
                    (
                        str(item.get("system", "")),
                        str(item.get("object_type", "")),
                        str(item.get("object_id", "")),
                        str(item.get("fingerprint", "")),
                    )
                    for item in work_package.get("source_scope", [])
                    if isinstance(item, Mapping)
                }
                if actual_scope != expected_scope:
                    errors.append(
                        "external redesign handoff work package has a mismatched exact "
                        f"source scope: {handoff.handoff_ref}"
                    )
    except AppendOnlyConflict as exc:
        errors.append(f"invalid typed external redesign handoff registration: {exc}")

    if registered_refs_seen - required_refs_seen:
        errors.append(
            "external redesign handoff registrations include unassigned references: "
            f"{sorted(registered_refs_seen - required_refs_seen)}"
        )


def _work_package_id(work_package: Mapping[str, Any]) -> str:
    return str(work_package.get("work_package_id", ""))


def _result_artifact_refs(work_package: Mapping[str, Any]) -> list[str]:
    refs: list[str] = []
    for value in work_package.get("result", {}).get("artifact_refs", []):
        if isinstance(value, str):
            refs.append(value)
        elif isinstance(value, Mapping) and value.get("ref"):
            refs.append(str(value["ref"]))
    return refs


def _result_evidence_refs(work_package: Mapping[str, Any]) -> list[str]:
    refs: list[str] = []
    for value in work_package.get("result", {}).get("evidence_refs", []):
        if isinstance(value, str):
            refs.append(value)
        elif isinstance(value, Mapping) and value.get("ref"):
            refs.append(str(value["ref"]))
    return refs


def _validate_work_packages(
    manifest: Mapping[str, Any],
    phase: str,
    context: PolicyContext,
    artifacts: list[ArtifactEnvelope],
    errors: list[str],
) -> None:
    manifest_ids = [str(value) for value in manifest.get("work_package_ids", [])]
    if context.strict and manifest_ids and not context.work_packages:
        errors.append("strict validation requires every referenced work-package record")
        return
    by_id: dict[str, Mapping[str, Any]] = {}
    tenant_ref = str(manifest["source"]["tenant_ref"])
    run_id = str(manifest["run_id"])
    agents = _registered_agents(context)
    profiles = _tool_profiles(context)
    artifact_by_ref = {artifact.ref: artifact for artifact in artifacts}
    evidence_refs = {str(item.get("ref")) for item in manifest.get("evidence", [])}
    authorizations = {
        str(item.get("authorization_id")): item
        for item in manifest.get("authorities", {}).get("active_authorizations", [])
    }
    cycle_id = str(manifest["revision_set"]["validation_cycle_id"])
    gate_resolver = GateRecordResolver.from_control_plane_records(
        tenant_ref=tenant_ref,
        run_id=run_id,
        validation_cycle_id=cycle_id,
        gates=list(manifest.get("gates", [])),
        artifacts=artifacts,
        actor_kinds=context.actor_kinds,
        strict_actor_resolution=context.strict,
        now=context.now,
        authorizations=list(manifest.get("authorities", {}).get("active_authorizations", [])),
        approval_evidence_refs=[
            str(item.get("ref"))
            for item in manifest.get("evidence", [])
            if item.get("kind") == "approval"
        ],
        action_scope_refs=_target_write_scope_map(manifest),
        authorization_artifact_fingerprint=str(
            manifest.get("source", {}).get("acquisition", {}).get("source_fingerprint", "")
        ),
        dashboard_evidence_snapshots=[
            _payload(event)
            for event in context.events
            if _event_type(event) == "dashboard_evidence_snapshot_registered"
        ],
        dashboard_plan_validations=[
            _payload(event)
            for event in context.events
            if _event_type(event) == "dashboard_plan_validated"
        ],
        qa_evidence_snapshots=[
            _payload(event)
            for event in context.events
            if _event_type(event) == "qa_evidence_snapshot_registered"
        ],
        qa_suite_validations=[
            _payload(event)
            for event in context.events
            if _event_type(event) == "qa_suite_validated"
        ],
        semantic_profile_coverages=[
            _payload(event)
            for event in context.events
            if _event_type(event) == "semantic_profile_coverage_registered"
        ],
        verified_event_ledger=context.verified_event_ledger,
    )
    work_packages: list[Mapping[str, Any]] = []
    for raw_work_package in context.work_packages:
        if not context.strict:
            work_packages.append(raw_work_package)
            continue
        try:
            # Lazy import avoids a package-initialization cycle while still making the
            # published runtime contract authoritative for persisted records.
            from omni_migrator.orchestration.planner import PlannedWorkPackage

            parsed = PlannedWorkPackage.model_validate(raw_work_package)
        except (TypeError, ValueError) as exc:
            errors.append(f"invalid persisted work package contract: {exc}")
            work_packages.append(raw_work_package)
            continue
        work_packages.append(parsed.model_dump(mode="json"))
    for work_package in work_packages:
        work_package_id = _work_package_id(work_package)
        if not work_package_id:
            errors.append("work package is missing an ID")
            continue
        if work_package_id in by_id:
            errors.append(f"duplicate work package ID: {work_package_id}")
        by_id[work_package_id] = work_package
        if str(work_package.get("run_id")) != run_id:
            errors.append(f"work package {work_package_id} crosses run partition")
        embedded_tenant = work_package.get("tenant_ref")
        if context.strict and embedded_tenant is None:
            errors.append(f"work package {work_package_id} lacks an explicit tenant partition")
        elif embedded_tenant is not None and str(embedded_tenant) != tenant_ref:
            errors.append(f"work package {work_package_id} crosses tenant partition")
        if str(work_package.get("validation_cycle_id", "")) != cycle_id:
            errors.append(f"work package {work_package_id} belongs to a stale validation cycle")
        status = str(work_package.get("status"))
        result_state = str(work_package.get("result", {}).get("state"))
        expected_state = {
            "pending": "not_started",
            "ready": "not_started",
            "in_progress": "not_started",
            "completed": "completed",
            "blocked": "blocked",
        }.get(status)
        if expected_state is not None and result_state != expected_state:
            errors.append(
                f"work package {work_package_id} status/result mismatch: {status}/{result_state}"
            )
        work_phase = str(work_package.get("phase", ""))
        gate_refs = [str(value) for value in work_package.get("gate_refs", [])]
        parsed_gate_ids = [gate_id_from_ref(reference) for reference in gate_refs]
        if any(gate_id is None for gate_id in parsed_gate_ids):
            errors.append(f"work package {work_package_id} has a noncanonical gate reference")
        gate_ids = {gate_id for gate_id in parsed_gate_ids if gate_id is not None}
        try:
            required_package_gates = _required_package_gate_ids_for_work_package(work_package, context)
        except (TypeError, ValueError, KeyError) as exc:
            errors.append(f"work package {work_package_id} has invalid Sigma routing evidence: {exc}")
            required_package_gates = REQUIRED_PACKAGE_GATE_IDS_BY_WORK_PHASE.get(
                work_phase, frozenset()
            )
        missing_gate_ids = set(required_package_gates) - gate_ids
        if missing_gate_ids:
            errors.append(
                f"work package {work_package_id} lacks required gates: {sorted(missing_gate_ids)}"
            )
        if status in {"ready", "in_progress", "completed"}:
            bound_inputs = set(work_package.get("input_refs", []))
            migration_unit_id = str(work_package.get("migration_unit_id", ""))
            for gate_id in sorted(gate_ids):
                reference = f"gate-ref://{gate_id}"
                for violation in gate_resolver.violations_for_ref(
                    reference,
                    migration_unit_id=migration_unit_id,
                    require_unit_match=True,
                ):
                    errors.append(
                        f"work package {work_package_id} cannot consume {reference}: {violation}"
                    )
                typed_refs = gate_resolver.typed_evidence_refs_for_ref(
                    reference,
                    migration_unit_id=migration_unit_id,
                )
                if not typed_refs or not typed_refs.issubset(bound_inputs):
                    errors.append(
                        f"work package {work_package_id} does not bind every current typed "
                        f"evidence artifact for {reference} in input_refs"
                    )
                for violation in gate_resolver.bound_artifact_coverage_violations_for_ref(
                    reference,
                    bound_input_refs=work_package.get("input_refs", []),
                    migration_unit_id=migration_unit_id,
                ):
                    errors.append(
                        f"work package {work_package_id} cannot consume {reference}: {violation}"
                    )
            for violation in gate_resolver.authorization_violations(
                authorization_ref=work_package.get("authority", {}).get("authorization_ref"),
                work_phase=work_phase,
                authority_mode=str(work_package.get("authority", {}).get("mode", "")),
                intended_change_set_fingerprint=work_package.get("authority", {}).get(
                    "intended_change_set_fingerprint"
                ),
                target_scope_refs=work_package.get("authority", {}).get("target_scope_refs", []),
            ):
                errors.append(
                    f"work package {work_package_id} cannot use its write authority: {violation}"
                )
        assignee = work_package.get("assignee", {})
        if assignee.get("kind") == "agent":
            agent_id = str(assignee.get("agent_id", ""))
            agent = agents.get(agent_id)
            if context.strict and agent is None:
                errors.append(
                    f"work package {work_package_id} names an unregistered agent: {agent_id}"
                )
            if agent is not None:
                phase_name = str(work_package.get("phase", ""))
                work_profiles = agent.get("work_profiles", {})
                profile_name = str(
                    work_profiles.get(phase_name, agent.get("tool_profile", ""))
                    if isinstance(work_profiles, Mapping)
                    else agent.get("tool_profile", "")
                )
                actual_profile = str(work_package.get("tool_profile", ""))
                if actual_profile != profile_name:
                    errors.append(
                        f"work package {work_package_id} tool profile differs from registry: "
                        f"expected={profile_name}, actual={actual_profile}"
                    )
                registry_tools = profiles.get(profile_name)
                if registry_tools is None:
                    registry_tools = agent.get("allowed_tools")
                if context.strict and registry_tools is None:
                    errors.append(f"agent {agent_id} has no registry-defined tool allowlist")
                elif registry_tools is None and work_package.get("authority", {}).get(
                    "allowed_tools"
                ):
                    errors.append(f"agent {agent_id} has no enforceable tool allowlist")
                elif registry_tools is not None:
                    actual_tools = set(work_package.get("authority", {}).get("allowed_tools", []))
                    expected_tools = set(registry_tools)
                    if actual_tools != expected_tools:
                        errors.append(
                            f"work package {work_package_id} tool allowlist differs from agent profile: "
                            f"missing={sorted(expected_tools - actual_tools)}, "
                            f"extra={sorted(actual_tools - expected_tools)}"
                        )
                permitted_outputs = set(agent.get("required_outputs", [])) | {
                    "risk_or_decision_request"
                }
                unexpected_outputs = (
                    set(work_package.get("expected_artifacts", [])) - permitted_outputs
                )
                if unexpected_outputs:
                    errors.append(
                        f"work package {work_package_id} expects outputs outside agent registry: {sorted(unexpected_outputs)}"
                    )
        authority = work_package.get("authority", {})
        if authority.get("mode") in {
            "branch_write",
            "document_create_write",
            "document_draft_write",
        }:
            authorization_ref = authority.get("authorization_ref")
            if not authorization_ref:
                errors.append(
                    f"write work package {work_package_id} lacks an authorization reference"
                )
            elif context.strict:
                authorization_id = _reference_identity(str(authorization_ref))
                if authorization_id not in authorizations:
                    errors.append(
                        f"work package {work_package_id} references an unknown authorization"
                    )
        if context.strict:
            for input_ref in work_package.get("input_refs", []):
                if input_ref not in artifact_by_ref and input_ref not in evidence_refs:
                    errors.append(
                        f"work package {work_package_id} references an unregistered input: {input_ref}"
                    )
        if status == "completed":
            result_refs = _result_artifact_refs(work_package)
            if context.strict and not result_refs:
                errors.append(f"completed work package {work_package_id} has no artifact results")
            result_types = {
                artifact_by_ref[ref].artifact_type for ref in result_refs if ref in artifact_by_ref
            }
            missing_types = set(work_package.get("expected_artifacts", [])) - result_types
            if context.strict and missing_types:
                errors.append(
                    f"completed work package {work_package_id} lacks expected artifact types: {sorted(missing_types)}"
                )
            for result_ref in result_refs:
                artifact = artifact_by_ref.get(result_ref)
                if artifact is None:
                    continue
                if artifact.producer_work_package_id != work_package_id:
                    errors.append(
                        f"completed work package {work_package_id} does not own result artifact {result_ref}"
                    )
            blocking_issues = [
                issue
                for issue in work_package.get("result", {}).get("issues", [])
                if issue.get("severity") == "blocking"
            ]
            if blocking_issues:
                errors.append(f"completed work package {work_package_id} contains blocking issues")
    missing_records = set(manifest_ids) - set(by_id)
    if context.strict and missing_records:
        errors.append(f"missing referenced work packages: {sorted(missing_records)}")
    extras = set(by_id) - set(manifest_ids)
    if context.strict and extras:
        errors.append(f"unregistered work packages supplied to run: {sorted(extras)}")
    for work_package_id, work_package in by_id.items():
        for dependency in work_package.get("depends_on", []):
            dependency_id = str(dependency)
            if dependency_id == work_package_id:
                errors.append(f"work package {work_package_id} depends on itself")
            elif dependency_id not in by_id:
                errors.append(
                    f"work package {work_package_id} depends on missing package {dependency_id}"
                )
            elif (
                work_package.get("status") in {"ready", "in_progress", "completed"}
                and by_id[dependency_id].get("status") != "completed"
            ):
                errors.append(
                    f"work package {work_package_id} advanced before dependency {dependency_id} completed"
                )
    if (
        context.strict
        and manifest.get("target", {}).get("omni", {}).get("content_operation") == "create_new"
    ):
        document_create_by_unit: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
        for work_package in by_id.values():
            if work_package.get("phase") == "document_create":
                document_create_by_unit[str(work_package.get("migration_unit_id", ""))].append(
                    work_package
                )
        for content_package in by_id.values():
            if content_package.get("phase") != "content_build":
                continue
            content_id = _work_package_id(content_package)
            unit_id = str(content_package.get("migration_unit_id", ""))
            create_packages = document_create_by_unit.get(unit_id, [])
            if len(create_packages) != 1:
                errors.append(
                    f"new-document content work {content_id} requires exactly one "
                    "same-unit document-create package"
                )
                continue
            create_package = create_packages[0]
            create_id = _work_package_id(create_package)
            if create_id not in {str(value) for value in content_package.get("depends_on", [])}:
                errors.append(
                    f"new-document content work {content_id} does not depend on its "
                    f"exact document-create package {create_id}"
                )
            if content_package.get("status") not in {
                "ready",
                "in_progress",
                "completed",
            }:
                continue
            create_results = _result_artifact_refs(create_package)
            shell_refs = {
                reference
                for reference in create_results
                if reference in artifact_by_ref
                and artifact_by_ref[reference].artifact_type == "omni_document_shell"
            }
            readback_refs = {
                reference
                for reference in create_results
                if reference in artifact_by_ref
                and artifact_by_ref[reference].artifact_type == "document_readback"
            }
            content_inputs = {str(value) for value in content_package.get("input_refs", [])}
            if len(shell_refs) != 1 or not shell_refs.issubset(content_inputs):
                errors.append(
                    f"new-document content work {content_id} does not consume the "
                    "exact created document shell"
                )
            if len(readback_refs) != 1 or not readback_refs.issubset(content_inputs):
                errors.append(
                    f"new-document content work {content_id} does not consume the "
                    "exact document-create readback"
                )
            manifest_readback = str(
                manifest.get("target", {}).get("omni", {}).get("document_create_readback_ref") or ""
            )
            if readback_refs != {manifest_readback}:
                errors.append(
                    f"new-document content work {content_id} uses a readback that "
                    "differs from the target manifest"
                )
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(work_package_id: str) -> None:
        if work_package_id in visiting:
            errors.append(f"work-package DAG contains a cycle at {work_package_id}")
            return
        if work_package_id in visited or work_package_id not in by_id:
            return
        visiting.add(work_package_id)
        for dependency in by_id[work_package_id].get("depends_on", []):
            visit(str(dependency))
        visiting.remove(work_package_id)
        visited.add(work_package_id)

    for work_package_id in by_id:
        visit(work_package_id)
    if context.strict:
        required_work: dict[tuple[str, str], set[str]] = defaultdict(set)
        for threshold, requirements in REQUIRED_COMPLETED_WORK_BY_PHASE.items():
            if not reached(phase, threshold):
                continue
            for identity, artifact_types in requirements.items():
                if reached(phase, "production_revalidated") and identity == (
                    "migration_qa",
                    "development_qa",
                ):
                    # Production QA is a distinct validation cycle. Its work
                    # package must bind the accepted development suite and
                    # validation as immutable baseline inputs; it must not
                    # recreate development QA outputs in the production cycle.
                    continue
                required_work[identity].update(artifact_types)
        if (
            reached(phase, "dashboard_ready")
            and manifest.get("target", {}).get("omni", {}).get("content_operation") == "create_new"
        ):
            required_work[("omni_bi_developer", "document_create")].update(
                {"omni_document_shell", "target_write_receipt", "document_readback"}
            )
        for (agent_id, work_phase), required_types in sorted(required_work.items()):
            candidates = [
                work_package
                for work_package in by_id.values()
                if work_package.get("status") == "completed"
                and work_package.get("phase") == work_phase
                and work_package.get("assignee", {}).get("kind") == "agent"
                and work_package.get("assignee", {}).get("agent_id") == agent_id
            ]
            if not candidates:
                errors.append(f"phase {phase} lacks completed work package {agent_id}/{work_phase}")
                continue
            candidate_ids = {_work_package_id(item) for item in candidates}
            result_refs = {
                reference for item in candidates for reference in _result_artifact_refs(item)
            }
            for artifact_type in sorted(required_types):
                matching_artifacts = [
                    artifact
                    for artifact in artifacts
                    if artifact.artifact_type == artifact_type
                    and artifact.producer_work_package_id in candidate_ids
                    and artifact.ref in result_refs
                    and artifact.validation_cycle_id == cycle_id
                    and any(
                        artifact.migration_unit_id == str(item.get("migration_unit_id", ""))
                        for item in candidates
                        if _work_package_id(item) == artifact.producer_work_package_id
                    )
                ]
                if not matching_artifacts:
                    errors.append(
                        f"completed work {agent_id}/{work_phase} lacks linked current artifact type: "
                        f"{artifact_type}"
                    )
                    continue
                if artifact_type in LINEAGE_REQUIRED_ARTIFACT_TYPES and any(
                    not artifact.input_artifacts for artifact in matching_artifacts
                ):
                    errors.append(f"phase artifact {artifact_type} lacks immutable input lineage")
    external = [
        work_package
        for work_package in by_id.values()
        if work_package.get("assignee", {}).get("kind") == "external_team"
    ]
    for work_package in external:
        capability = str(work_package.get("assignee", {}).get("capability", ""))
        threshold = "data_ready" if capability == "platform_ingestion" else "cutover_authorized"
        if reached(phase, threshold) and work_package.get("status") != "completed":
            errors.append(
                f"unresolved external handoff blocks {threshold}: {_work_package_id(work_package)}"
            )


def _validate_qa_results(
    manifest: Mapping[str, Any],
    phase: str,
    context: PolicyContext,
    artifacts: list[ArtifactEnvelope],
    errors: list[str],
) -> None:
    """Validate legacy v1 QA records when supplied, without granting readiness.

    Canonical readiness is closed exclusively by the store-attested v2 acceptance
    suite in ``_validate_qa_acceptance_suites``.  Keeping v1 parsing here supports
    historical manifests without forcing a duplicate legacy authority path.
    """

    if not reached(phase, "qa_accepted"):
        return
    if not context.qa_results:
        return
    tenant_ref = str(manifest["source"]["tenant_ref"])
    run_id = str(manifest["run_id"])
    cycle_id = str(manifest["revision_set"]["validation_cycle_id"])
    source_environment_ref = tenant_ref
    target_environment_ref = str(manifest["target"]["omni"]["organization_ref"])
    promotion_fingerprint = manifest["revision_set"].get("promotion_bundle_fingerprint")
    for result in context.qa_results:
        result_id = str(result.get("qa_result_id") or "unknown")
        _validate_references(result, context, errors, f"qa_result.{result_id}")
        result_errors = validate_qa_result(
            result,
            now=context.now,
            expected_tenant_ref=tenant_ref,
            expected_run_id=run_id,
            expected_validation_cycle_id=cycle_id,
            expected_source_environment_ref=source_environment_ref,
            expected_target_environment_ref=target_environment_ref,
            expected_promotion_bundle_fingerprint=promotion_fingerprint,
            artifacts=artifacts,
            require_registered_artifacts=context.strict,
            require_typed_watermarks=context.strict,
        )
        errors.extend(result_errors)


def _validate_qa_acceptance_suites(
    manifest: Mapping[str, Any],
    phase: str,
    context: PolicyContext,
    artifacts: list[ArtifactEnvelope],
    errors: list[str],
) -> None:
    """Require exactly one current, store-attested v2 QA suite per selected unit."""

    if not reached(phase, "qa_accepted"):
        return
    if not context.strict:
        return
    if not context.qa_suites:
        errors.append("QA-accepted run requires one typed QA acceptance suite per unit")
        return
    if not context.qa_suite_validations:
        errors.append("QA-accepted run requires store-backed QA suite validations")
        return

    from omni_migrator.qa.acceptance import (
        QASuiteValidationRegistration,
        finalize_qa_acceptance_suite,
        finalize_qa_fixture,
        finalize_qa_result,
        qa_acceptance_suite_content_sha256,
        qa_fixture_content_sha256,
        qa_fixture_hash,
        qa_result_content_sha256,
        qa_result_hash,
        qa_suite_validation_content_sha256,
        qa_suite_validation_registration_hash,
        validate_qa_acceptance_suite,
    )
    from omni_migrator.qa.store import RecordBackedQAEvidenceResolver

    tenant_ref = str(manifest["source"]["tenant_ref"])
    run_id = str(manifest["run_id"])
    cycle_id = str(manifest["revision_set"]["validation_cycle_id"])
    selected_unit_records = {
        str(item.get("migration_unit_id", "")): item
        for item in manifest.get("migration_units", [])
        if item.get("migration_unit_id")
    }
    selected_units = set(selected_unit_records)
    if not selected_units:
        errors.append("QA acceptance requires a non-empty migration-unit denominator")
        return

    latest_by_id = {
        artifact.artifact_id: max(
            (item for item in artifacts if item.artifact_id == artifact.artifact_id),
            key=lambda item: item.revision,
        )
        for artifact in artifacts
    }
    current_artifacts = tuple(latest_by_id.values())
    resolver = RecordBackedQAEvidenceResolver(records=list(context.events))

    fixture_payloads = []
    if not context.qa_fixtures_v2:
        errors.append(
            "QA acceptance requires canonical qa-fixture.v2 payloads; "
            "legacy v1 QA results cannot close an acceptance suite"
        )
    for raw_value in context.qa_fixtures_v2:
        try:
            raw = (
                raw_value.model_dump(mode="json")
                if hasattr(raw_value, "model_dump")
                else dict(raw_value)
            )
            fixture = finalize_qa_fixture(raw)
        except (AttributeError, TypeError, ValueError) as exc:
            errors.append(f"canonical qa-fixture.v2 payload is malformed: {exc}")
            continue
        if (
            raw.get("contract_version") != "domo-to-omni.qa-fixture.v2"
            or raw.get("fixture_hash") != fixture.fixture_hash
            or fixture.fixture_hash != qa_fixture_hash(fixture)
        ):
            errors.append(f"qa-fixture.v2 payload hash is not canonical: {fixture.fixture_ref}")
        fixture_payloads.append(fixture)

    result_payloads = []
    if not context.qa_results_v2:
        errors.append(
            "QA acceptance requires canonical qa-result.v2 payloads; "
            "legacy v1 QA results cannot close an acceptance suite"
        )
    for raw_value in context.qa_results_v2:
        try:
            raw = (
                raw_value.model_dump(mode="json")
                if hasattr(raw_value, "model_dump")
                else dict(raw_value)
            )
            result = finalize_qa_result(raw)
        except (AttributeError, TypeError, ValueError) as exc:
            errors.append(f"canonical qa-result.v2 payload is malformed: {exc}")
            continue
        if (
            raw.get("contract_version") != "domo-to-omni.qa-result.v2"
            or raw.get("result_hash") != result.result_hash
            or result.result_hash != qa_result_hash(result)
        ):
            errors.append(f"qa-result.v2 payload hash is not canonical: {result.result_ref}")
        result_payloads.append(result)

    for label, values in (
        (
            "qa-fixture.v2 payloads",
            [(item.migration_unit_id, item.case_id, item.fixture_ref) for item in fixture_payloads],
        ),
        (
            "qa-result.v2 payloads",
            [(item.migration_unit_id, item.case_id, item.result_ref) for item in result_payloads],
        ),
    ):
        duplicates = sorted(value for value in set(values) if values.count(value) > 1)
        if duplicates:
            errors.append(f"{label} repeat exact case bindings: {duplicates}")

    suites = []
    for raw in context.qa_suites:
        try:
            suite = finalize_qa_acceptance_suite(raw)
        except (TypeError, ValueError) as exc:
            errors.append(f"QA acceptance suite is malformed: {exc}")
            continue
        if raw.get("suite_hash") != suite.suite_hash:
            errors.append(f"QA acceptance suite hash is not canonical: {suite.suite_id}")
        suites.append(suite)

    fixture_refs = [item.fixture_ref for item in fixture_payloads]
    result_refs = [item.result_ref for item in result_payloads]
    for label, values in (
        ("qa-fixture.v2 references", fixture_refs),
        ("qa-result.v2 references", result_refs),
    ):
        duplicates = sorted(value for value in set(values) if values.count(value) > 1)
        if duplicates:
            errors.append(f"{label} are duplicated: {duplicates}")
    fixture_by_ref = {item.fixture_ref: item for item in fixture_payloads}
    result_by_ref = {item.result_ref: item for item in result_payloads}
    expected_fixture_refs = {
        binding.artifact_ref for suite in suites for binding in suite.bindings.fixture_artifacts
    }
    expected_result_refs = {
        binding.artifact_ref for suite in suites for binding in suite.bindings.result_artifacts
    }
    for label, expected, actual in (
        ("qa-fixture.v2", expected_fixture_refs, set(fixture_refs)),
        ("qa-result.v2", expected_result_refs, set(result_refs)),
    ):
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        if missing or extra:
            errors.append(
                f"{label} payloads must exactly match suite artifact bindings: "
                f"missing={missing}, extra={extra}"
            )

    registrations = []
    for raw in context.qa_suite_validations:
        try:
            registration = QASuiteValidationRegistration.model_validate(raw)
        except (TypeError, ValueError) as exc:
            errors.append(f"QA suite validation registration is malformed: {exc}")
            continue
        if registration.registration_hash != qa_suite_validation_registration_hash(registration):
            errors.append(
                "QA suite validation registration hash is not canonical: "
                f"{registration.registration_ref}"
            )
        registrations.append(registration)

    event_registrations = {
        str(_payload(item).get("registration_hash")): _payload(item)
        for item in context.events
        if _event_type(item) == "qa_suite_validated"
    }
    for registration in registrations:
        stored = event_registrations.get(registration.registration_hash)
        if stored is None or {
            key: value for key, value in stored.items() if key != "event_type"
        } != registration.model_dump(mode="json"):
            errors.append(
                "QA suite validation is not the exact store-emitted attestation: "
                f"{registration.registration_ref}"
            )

    suite_units = [item.migration_unit_id for item in suites]
    registration_units = [item.migration_unit_id for item in registrations]
    for label, values in (
        ("QA suites", suite_units),
        ("QA suite validations", registration_units),
    ):
        duplicates = sorted(value for value in set(values) if values.count(value) > 1)
        if duplicates:
            errors.append(f"{label} repeat migration units: {duplicates}")
        missing = sorted(selected_units - set(values))
        extra = sorted(set(values) - selected_units)
        if missing or extra:
            errors.append(
                f"{label} must exactly match selected migration units: "
                f"missing={missing}, extra={extra}"
            )

    registration_by_unit = {item.migration_unit_id: item for item in registrations}
    validation_artifact_refs: set[str] = set()
    evidence_classes: set[str] = set()
    for suite in suites:
        if (
            suite.tenant_ref != tenant_ref
            or suite.run_id != run_id
            or suite.validation_cycle_id != cycle_id
        ):
            errors.append(f"QA acceptance suite crosses the run partition: {suite.suite_id}")
        evidence_classes.add(suite.evidence_class)
        suite_identity = (
            suite.tenant_ref,
            suite.run_id,
            suite.scope_id,
            suite.wave_id,
            suite.migration_unit_id,
            suite.validation_cycle_id,
            suite.evidence_class,
        )
        resolver_identity = {
            "tenant_ref": suite.tenant_ref,
            "run_id": suite.run_id,
            "scope_id": suite.scope_id,
            "wave_id": suite.wave_id,
            "migration_unit_id": suite.migration_unit_id,
            "validation_cycle_id": suite.validation_cycle_id,
        }
        for binding in suite.bindings.fixture_artifacts:
            fixture = fixture_by_ref.get(binding.artifact_ref)
            if fixture is None:
                continue
            fixture_identity = (
                fixture.tenant_ref,
                fixture.run_id,
                fixture.scope_id,
                fixture.wave_id,
                fixture.migration_unit_id,
                fixture.validation_cycle_id,
                fixture.evidence_class,
            )
            if (
                fixture_identity != suite_identity
                or fixture.fixture_hash != binding.semantic_hash
                or qa_fixture_content_sha256(fixture) != binding.content_sha256
                or fixture.producer_ref != binding.producer_ref
            ):
                errors.append(
                    "qa-fixture.v2 payload does not match its exact suite binding: "
                    f"{binding.artifact_ref}"
                )
            current = [
                item
                for item in current_artifacts
                if item.artifact_type == "qa_fixture"
                and item.ref == binding.artifact_ref
                and item.content_sha256 == binding.content_sha256
                and item.producer_ref == binding.producer_ref
                and item.migration_unit_id == suite.migration_unit_id
                and item.validation_cycle_id == suite.validation_cycle_id
            ]
            resolved = resolver.resolve_current_qa_fixture_v2(
                **resolver_identity,
                artifact_ref=binding.artifact_ref,
            )
            if len(current) != 1 or resolved != fixture:
                errors.append(
                    "qa-fixture.v2 payload is absent, stale, or not exact registered "
                    f"current evidence: {binding.artifact_ref}"
                )

        for binding in suite.bindings.result_artifacts:
            result = result_by_ref.get(binding.artifact_ref)
            if result is None:
                continue
            result_identity = (
                result.tenant_ref,
                result.run_id,
                result.scope_id,
                result.wave_id,
                result.migration_unit_id,
                result.validation_cycle_id,
                result.evidence_class,
            )
            if (
                result_identity != suite_identity
                or result.result_hash != binding.semantic_hash
                or qa_result_content_sha256(result) != binding.content_sha256
                or result.verifier_ref != binding.producer_ref
            ):
                errors.append(
                    "qa-result.v2 payload does not match its exact suite binding: "
                    f"{binding.artifact_ref}"
                )
            fixture = fixture_by_ref.get(result.fixture_ref)
            if fixture is None or (
                result.fixture_hash != fixture.fixture_hash
                or result.source_observation != fixture.source_observation
                or result.target_observation != fixture.target_observation
                or result.source_context != fixture.source_context
                or result.target_context != fixture.target_context
            ):
                errors.append(
                    "qa-result.v2 payload does not consume its exact canonical fixture: "
                    f"{binding.artifact_ref}"
                )
            current = [
                item
                for item in current_artifacts
                if item.artifact_type == "qa_result"
                and item.ref == binding.artifact_ref
                and item.content_sha256 == binding.content_sha256
                and item.producer_ref == binding.producer_ref
                and item.migration_unit_id == suite.migration_unit_id
                and item.validation_cycle_id == suite.validation_cycle_id
            ]
            resolved = resolver.resolve_current_qa_result_v2(
                **resolver_identity,
                artifact_ref=binding.artifact_ref,
            )
            if len(current) != 1 or resolved != result:
                errors.append(
                    "qa-result.v2 payload is absent, stale, or not exact registered "
                    f"current evidence: {binding.artifact_ref}"
                )

        expected_qa_phase = (
            "production_qa" if suite.evidence_class == "production" else "development_qa"
        )
        qa_work_packages = [
            item
            for item in context.work_packages
            if item.get("status") == "completed"
            and item.get("phase") == expected_qa_phase
            and item.get("migration_unit_id") == suite.migration_unit_id
            and item.get("validation_cycle_id") == suite.validation_cycle_id
            and item.get("assignee", {}).get("kind") == "agent"
            and item.get("assignee", {}).get("agent_id") == "migration_qa"
        ]
        if len(qa_work_packages) != 1:
            errors.append(
                f"QA suite requires exactly one completed migration_qa/{expected_qa_phase} "
                f"work package with exact inputs: {suite.migration_unit_id}"
            )
        else:
            expected_inputs = {item.artifact_ref for item in suite.bindings.upstream_artifacts()}
            actual_inputs = [str(item) for item in qa_work_packages[0].get("input_refs", [])]
            if suite.evidence_class == "production":
                baseline_artifacts = [
                    item
                    for item in current_artifacts
                    if item.ref in set(actual_inputs)
                    and item.artifact_type in {"qa_acceptance_suite", "qa_suite_validation"}
                    and item.validation_cycle_id != suite.validation_cycle_id
                ]
                baseline_types = [item.artifact_type for item in baseline_artifacts]
                baseline_cycles = {item.validation_cycle_id for item in baseline_artifacts}
                if (
                    sorted(baseline_types) != ["qa_acceptance_suite", "qa_suite_validation"]
                    or len(baseline_cycles) != 1
                ):
                    errors.append(
                        "production_qa work package requires one exact prior-cycle "
                        "development suite and validation baseline: "
                        f"{suite.migration_unit_id}"
                    )
                expected_inputs.update(item.ref for item in baseline_artifacts)
            actual_input_set = set(actual_inputs)
            missing_inputs = sorted(expected_inputs - actual_input_set)
            extra_inputs = sorted(actual_input_set - expected_inputs)
            if len(actual_inputs) != len(set(actual_inputs)) or missing_inputs or extra_inputs:
                errors.append(
                    f"{expected_qa_phase} work package inputs must exactly bind the accepted "
                    f"QA suite: {suite.migration_unit_id}: "
                    f"missing={missing_inputs}, extra={extra_inputs}"
                )
        suite_artifacts = [
            item
            for item in current_artifacts
            if item.artifact_type == "qa_acceptance_suite"
            and item.migration_unit_id == suite.migration_unit_id
            and item.validation_cycle_id == cycle_id
            and item.content_sha256 == qa_acceptance_suite_content_sha256(suite)
        ]
        if len(suite_artifacts) != 1:
            errors.append(f"QA suite {suite.suite_id} requires one exact current artifact")
            suite_artifact = None
        else:
            suite_artifact = suite_artifacts[0]
            unit_record = selected_unit_records.get(suite.migration_unit_id, {})
            if unit_record.get("qa_acceptance_suite_ref") != suite_artifact.ref:
                errors.append(
                    "migration unit does not bind its exact current QA suite artifact: "
                    f"{suite.migration_unit_id}"
                )
        registration = registration_by_unit.get(suite.migration_unit_id)
        if registration is None:
            continue
        if (
            registration.tenant_ref != tenant_ref
            or registration.run_id != run_id
            or registration.validation_cycle_id != cycle_id
            or registration.scope_id != suite.scope_id
            or registration.wave_id != suite.wave_id
            or registration.suite_id != suite.suite_id
            or registration.suite_hash != suite.suite_hash
            or registration.evidence_class != suite.evidence_class
        ):
            errors.append(f"QA suite validation does not bind its exact suite: {suite.suite_id}")
        if suite_artifact is not None and (
            registration.suite_artifact_ref != suite_artifact.ref
            or registration.suite_artifact_content_sha256 != suite_artifact.content_sha256
        ):
            errors.append(f"QA suite validation binds a stale suite artifact: {suite.suite_id}")
        validation_artifacts = [
            item
            for item in current_artifacts
            if item.artifact_type == "qa_suite_validation"
            and item.migration_unit_id == suite.migration_unit_id
            and item.validation_cycle_id == cycle_id
            and item.content_sha256 == qa_suite_validation_content_sha256(registration)
        ]
        if len(validation_artifacts) != 1:
            errors.append(
                f"QA suite {suite.suite_id} requires one exact current validation artifact"
            )
        else:
            validation_artifact = validation_artifacts[0]
            validation_artifact_refs.add(validation_artifact.ref)
            unit_record = selected_unit_records.get(suite.migration_unit_id, {})
            if unit_record.get("qa_suite_validation_ref") != validation_artifact.ref:
                errors.append(
                    "migration unit does not bind its exact current QA validation "
                    f"artifact: {suite.migration_unit_id}"
                )

        validation = validate_qa_acceptance_suite(
            suite,
            evidence_resolver=resolver,
        )
        if not validation.valid or not validation.qa_suite_ready:
            errors.extend(
                f"QA suite {suite.suite_id}: {reason}"
                for reason in (
                    *validation.errors,
                    *validation.invalidation_reasons,
                )
            )

    qa_gate = next(
        (item for item in manifest.get("gates", []) if item.get("gate_id") == "qa_suite_accepted"),
        None,
    )
    if qa_gate is not None:
        gate_refs = {str(item) for item in qa_gate.get("required_evidence_refs", [])}
        if gate_refs != validation_artifact_refs:
            errors.append(
                "qa_suite_accepted must exactly bind every current QA validation "
                f"artifact: expected={sorted(validation_artifact_refs)}, "
                f"actual={sorted(gate_refs)}"
            )

    if (
        manifest.get("run_purpose") == "customer_migration"
        and "synthetic_local" in evidence_classes
    ):
        errors.append("customer migrations cannot use synthetic-local QA acceptance")
    if reached(phase, "dbt_promotion_authorized") and "synthetic_local" in evidence_classes:
        errors.append("synthetic-local QA cannot advance to promotion or production phases")
    if reached(phase, "production_revalidated") and evidence_classes != {"production"}:
        errors.append("production revalidation requires production-class QA suites")


def _validate_production_validation_reports(
    manifest: Mapping[str, Any],
    phase: str,
    context: PolicyContext,
    artifacts: list[ArtifactEnvelope],
    errors: list[str],
) -> None:
    """Require one exact downstream store report for every production QA suite."""

    if not reached(phase, "production_revalidated"):
        if context.strict and context.production_validation_reports:
            errors.append("production validation reports cannot precede production revalidation")
        return
    if not context.strict:
        return
    if not context.production_validation_reports:
        errors.append(
            "production-revalidated run requires one typed production validation report per unit"
        )
        return

    from omni_migrator.qa.acceptance import (
        QASuiteValidationRegistration,
        finalize_qa_acceptance_suite,
    )
    from omni_migrator.qa.production import (
        finalize_production_validation_report,
        production_validation_report_content_sha256,
        production_validation_report_hash,
    )
    from omni_migrator.qa.store import RecordBackedQAEvidenceResolver

    tenant_ref = str(manifest["source"]["tenant_ref"])
    run_id = str(manifest["run_id"])
    cycle_id = str(manifest["revision_set"]["validation_cycle_id"])
    units = {
        str(item.get("migration_unit_id", "")): item
        for item in manifest.get("migration_units", [])
        if item.get("migration_unit_id")
    }
    reports = []
    for raw_value in context.production_validation_reports:
        try:
            raw = (
                raw_value.model_dump(mode="json")
                if hasattr(raw_value, "model_dump")
                else dict(raw_value)
            )
            report = finalize_production_validation_report(raw)
        except (AttributeError, TypeError, ValueError) as exc:
            errors.append(f"production validation report is malformed: {exc}")
            continue
        if raw.get(
            "report_hash"
        ) != report.report_hash or report.report_hash != production_validation_report_hash(report):
            errors.append(f"production validation report hash is not canonical: {report.report_id}")
        reports.append(report)

    report_units = [item.migration_unit_id for item in reports]
    duplicates = sorted(value for value in set(report_units) if report_units.count(value) > 1)
    if duplicates:
        errors.append(f"production validation reports repeat units: {duplicates}")
    missing = sorted(set(units) - set(report_units))
    extra = sorted(set(report_units) - set(units))
    if missing or extra:
        errors.append(
            "production validation reports must exactly match selected migration units: "
            f"missing={missing}, extra={extra}"
        )

    current_by_id = {
        artifact.artifact_id: max(
            (item for item in artifacts if item.artifact_id == artifact.artifact_id),
            key=lambda item: item.revision,
        )
        for artifact in artifacts
    }
    current_artifacts = tuple(current_by_id.values())
    suites_by_unit: dict[str, list[Any]] = {}
    for raw in context.qa_suites:
        try:
            suite = finalize_qa_acceptance_suite(raw)
        except (TypeError, ValueError):
            continue
        suites_by_unit.setdefault(suite.migration_unit_id, []).append(suite)
    validations_by_unit: dict[str, list[Any]] = {}
    for raw in context.qa_suite_validations:
        try:
            registration = QASuiteValidationRegistration.model_validate(raw)
        except (TypeError, ValueError):
            continue
        validations_by_unit.setdefault(registration.migration_unit_id, []).append(registration)
    resolver = RecordBackedQAEvidenceResolver(records=list(context.events))
    report_artifact_refs: set[str] = set()
    validation_artifact_refs: set[str] = set()
    for report in reports:
        if (
            report.tenant_ref != tenant_ref
            or report.run_id != run_id
            or report.validation_cycle_id != cycle_id
        ):
            errors.append(
                f"production validation report crosses the run partition: {report.report_id}"
            )
        unit_suites = suites_by_unit.get(report.migration_unit_id, [])
        unit_validations = validations_by_unit.get(report.migration_unit_id, [])
        if len(unit_suites) != 1 or len(unit_validations) != 1:
            errors.append(
                "production report requires exactly one current suite and validation: "
                f"{report.migration_unit_id}"
            )
            continue
        suite = unit_suites[0]
        registration = unit_validations[0]
        if (
            suite.evidence_class != "production"
            or report.suite.suite_id != suite.suite_id
            or report.suite.suite_hash != suite.suite_hash
            or report.suite.bindings_hash != suite.bindings.bindings_hash
            or report.suite.evidence_snapshot_ref != suite.evidence_snapshot_ref
            or report.suite.evidence_snapshot_hash != suite.evidence_snapshot_hash
            or report.suite.evidence_snapshot_revision != suite.evidence_snapshot_revision
            or report.suite.verifier_ref != suite.verifier_ref
            or report.suite.producer_refs != suite.producer_refs
            or report.suite.assembled_at != suite.assembled_at
            or report.accepted_evidence_bindings != suite.bindings
            or report.suite_validation != registration
        ):
            errors.append(
                "production report does not bind the exact accepted production suite: "
                f"{report.report_id}"
            )
        report_artifacts = [
            item
            for item in current_artifacts
            if item.artifact_type == "production_validation_report"
            and item.ref == report.report_ref
            and item.content_sha256 == production_validation_report_content_sha256(report)
            and item.migration_unit_id == report.migration_unit_id
            and item.validation_cycle_id == cycle_id
        ]
        if len(report_artifacts) != 1:
            errors.append(f"production report {report.report_id} lacks one exact current artifact")
            continue
        report_artifact = report_artifacts[0]
        report_artifact_refs.add(report_artifact.ref)
        validation_artifact_refs.add(report.suite_validation_artifact.artifact_ref)
        registered_report_artifacts = [
            _payload(item).get("artifact")
            for item in context.events
            if _event_type(item) == "production_validation_report_registered"
            and _payload(item).get("report", {}).get("report_ref") == report.report_ref
        ]
        try:
            registered_report_artifact = (
                ArtifactEnvelope.from_mapping(registered_report_artifacts[0])
                if len(registered_report_artifacts) == 1
                and isinstance(registered_report_artifacts[0], Mapping)
                else None
            )
        except (TypeError, ValueError, RecordValidationError):
            registered_report_artifact = None
        if registered_report_artifact != report_artifact:
            errors.append(
                "production validation report artifact is not the exact trusted "
                f"store envelope: {report.report_id}"
            )
        resolved = resolver.resolve_current_production_validation_report(
            tenant_ref=report.tenant_ref,
            run_id=report.run_id,
            scope_id=report.scope_id,
            wave_id=report.wave_id,
            migration_unit_id=report.migration_unit_id,
            validation_cycle_id=report.validation_cycle_id,
            report_ref=report.report_ref,
        )
        if resolved != report:
            errors.append(
                "production validation report is not the exact trusted store record: "
                f"{report.report_id}"
            )
        unit = units.get(report.migration_unit_id, {})
        if unit.get("production_validation_report_ref") != report_artifact.ref:
            errors.append(
                "migration unit does not bind its exact current production report: "
                f"{report.migration_unit_id}"
            )

    production_gate = next(
        (
            item
            for item in manifest.get("gates", [])
            if item.get("gate_id") == "production_validation"
        ),
        None,
    )
    if production_gate is not None:
        actual_refs = {str(item) for item in production_gate.get("required_evidence_refs", [])}
        expected_refs = report_artifact_refs | validation_artifact_refs
        if actual_refs != expected_refs:
            errors.append(
                "production_validation must exactly bind every current QA validation "
                f"and report artifact: expected={sorted(expected_refs)}, "
                f"actual={sorted(actual_refs)}"
            )


def _validate_documentation_packages(
    manifest: Mapping[str, Any],
    phase: str,
    context: PolicyContext,
    artifacts: list[ArtifactEnvelope],
    errors: list[str],
) -> None:
    if not reached(phase, "docs_ready") or not context.strict:
        return
    if not context.documentation_packages:
        errors.append(
            "docs-ready run requires one accepted-artifact documentation package per unit"
        )
        return

    from omni_migrator.control_plane.documentation import (
        ProductionValidationBinding,
        finalize_documentation_package,
        validate_documentation_package,
    )
    from omni_migrator.qa.acceptance import (
        QASuiteValidationRegistration,
        finalize_qa_acceptance_suite,
        qa_suite_validation_content_sha256,
        qa_suite_validation_registration_hash,
    )
    from omni_migrator.qa.production import finalize_production_validation_report

    tenant_ref = str(manifest["source"]["tenant_ref"])
    run_id = str(manifest["run_id"])
    cycle_id = str(manifest["revision_set"]["validation_cycle_id"])
    selected_units = {
        str(item.get("migration_unit_id", ""))
        for item in manifest.get("migration_units", [])
        if item.get("migration_unit_id")
    }
    packages = []
    for raw in context.documentation_packages:
        try:
            package = finalize_documentation_package(raw)
        except (TypeError, ValueError) as exc:
            errors.append(f"documentation package is malformed: {exc}")
            continue
        if raw.get("package_hash") != package.package_hash:
            errors.append(f"documentation package hash is not canonical: {package.package_id}")
        packages.append(package)
    units = [item.migration_unit_id for item in packages]
    duplicates = sorted(value for value in set(units) if units.count(value) > 1)
    if duplicates:
        errors.append(f"documentation packages repeat migration units: {duplicates}")
    missing = sorted(selected_units - set(units))
    extra = sorted(set(units) - selected_units)
    if missing or extra:
        errors.append(
            "documentation packages must exactly match selected migration units: "
            f"missing={missing}, extra={extra}"
        )

    current_by_id = {
        artifact.artifact_id: max(
            (item for item in artifacts if item.artifact_id == artifact.artifact_id),
            key=lambda item: item.revision,
        )
        for artifact in artifacts
    }
    current_artifacts = tuple(current_by_id.values())
    suites_by_unit: dict[str, list[Any]] = {}
    for raw in context.qa_suites:
        try:
            suite = finalize_qa_acceptance_suite(raw)
        except (TypeError, ValueError):
            continue
        suites_by_unit.setdefault(suite.migration_unit_id, []).append(suite)
    registrations_by_unit: dict[str, list[Any]] = {}
    for raw in context.qa_suite_validations:
        try:
            registration = QASuiteValidationRegistration.model_validate(raw)
        except (TypeError, ValueError):
            continue
        registrations_by_unit.setdefault(registration.migration_unit_id, []).append(registration)
    reports_by_unit: dict[str, list[Any]] = {}
    for raw in context.production_validation_reports:
        try:
            report = finalize_production_validation_report(raw)
        except (TypeError, ValueError):
            continue
        reports_by_unit.setdefault(report.migration_unit_id, []).append(report)

    for package in packages:
        errors.extend(
            validate_documentation_package(
                package,
                expected_tenant_ref=tenant_ref,
                expected_run_id=run_id,
                expected_validation_cycle_id=cycle_id,
                expected_migration_unit_id=package.migration_unit_id,
                artifacts=artifacts,
                require_registered_artifacts=True,
            )
        )
        documentation_work_packages = [
            item
            for item in context.work_packages
            if item.get("status") == "completed"
            and item.get("phase") == "documentation"
            and item.get("assignee", {}).get("kind") == "agent"
            and item.get("assignee", {}).get("agent_id") == "documentation_training"
            and item.get("migration_unit_id") == package.migration_unit_id
            and item.get("validation_cycle_id") == package.validation_cycle_id
        ]
        if len(documentation_work_packages) != 1:
            errors.append(
                "documentation package requires exactly one completed documentation "
                f"work package: {package.migration_unit_id}"
            )
        else:
            expected_work_input_refs = {
                item.artifact_ref for item in package.accepted_input_bindings
            }
            work_input_refs = [
                str(item) for item in documentation_work_packages[0].get("input_refs", [])
            ]
            if (
                len(work_input_refs) != len(set(work_input_refs))
                or set(work_input_refs) != expected_work_input_refs
            ):
                errors.append(
                    "documentation work package inputs must exactly match accepted "
                    f"package inputs: {package.package_id}"
                )
        unit_suites = suites_by_unit.get(package.migration_unit_id, [])
        unit_registrations = registrations_by_unit.get(package.migration_unit_id, [])
        if len(unit_suites) != 1 or len(unit_registrations) != 1:
            errors.append(
                "documentation package requires exactly one accepted QA suite and "
                f"store validation: {package.migration_unit_id}"
            )
        else:
            suite = unit_suites[0]
            registration = unit_registrations[0]
            qa_binding = package.qa_suite_validation
            if (
                registration.registration_hash
                != qa_suite_validation_registration_hash(registration)
                or qa_binding.validation_ref != registration.registration_ref
                or qa_binding.validation_hash != registration.registration_hash
                or qa_binding.evidence_class != registration.evidence_class
                or qa_binding.content_sha256 != qa_suite_validation_content_sha256(registration)
                or registration.suite_id != suite.suite_id
                or registration.suite_hash != suite.suite_hash
                or registration.status != "valid"
                or not registration.qa_suite_ready
            ):
                errors.append(
                    "documentation package does not bind the exact accepted QA "
                    f"validation: {package.package_id}"
                )

            expected_target_bindings = {
                item.artifact_ref: item
                for item in (
                    *suite.bindings.target_artifacts,
                    *(item.artifact for item in suite.bindings.target_receipts),
                    *(item.artifact for item in suite.bindings.target_readbacks),
                )
            }
            actual_target_bindings = {
                item.artifact_ref: item for item in package.final_target_bindings
            }
            if set(actual_target_bindings) != set(expected_target_bindings):
                errors.append(
                    "documentation package final targets differ from the accepted "
                    f"QA suite: {package.package_id}"
                )
            else:
                for artifact_ref, expected in expected_target_bindings.items():
                    actual = actual_target_bindings[artifact_ref]
                    if (
                        actual.artifact_id != expected.artifact_id
                        or actual.revision != expected.revision
                        or actual.content_sha256 != expected.content_sha256
                        or actual.artifact_type != expected.artifact_type
                    ):
                        errors.append(
                            "documentation package alters an accepted final target "
                            f"binding: {artifact_ref}"
                        )

            suite_bindings = {item.artifact_ref: item for item in suite.bindings.all_artifacts()}
            expected_production_bindings: dict[str, Any] = {}
            if package.evidence_class == "production":
                unit_reports = reports_by_unit.get(package.migration_unit_id, [])
                if len(unit_reports) != 1:
                    errors.append(
                        "production documentation requires exactly one downstream "
                        f"registered production report: {package.package_id}"
                    )
                else:
                    report = unit_reports[0]
                    report_artifacts = [
                        item
                        for item in current_artifacts
                        if item.artifact_type == "production_validation_report"
                        and item.ref == report.report_ref
                        and item.migration_unit_id == package.migration_unit_id
                        and item.validation_cycle_id == package.validation_cycle_id
                    ]
                    if len(report_artifacts) != 1:
                        errors.append(
                            "production documentation cannot resolve its exact current "
                            f"report artifact: {package.package_id}"
                        )
                    else:
                        report_artifact = report_artifacts[0]
                        expected = ProductionValidationBinding(
                            artifact_id=report_artifact.artifact_id,
                            artifact_type="production_validation_report",
                            artifact_ref=report_artifact.ref,
                            revision=report_artifact.revision,
                            content_sha256=report_artifact.content_sha256,
                            validation_cycle_id=report_artifact.validation_cycle_id,
                            migration_unit_id=str(report_artifact.migration_unit_id),
                            validation_ref=report.report_ref,
                            validation_hash=report.report_hash,
                            status="passed",
                        )
                        expected_production_bindings[expected.artifact_ref] = expected
            allowed_input_bindings = {
                qa_binding.artifact_ref: qa_binding,
                **suite_bindings,
                **expected_production_bindings,
            }
            accepted_inputs = {item.artifact_ref: item for item in package.accepted_input_bindings}
            unexpected_input_refs = sorted(set(accepted_inputs) - set(allowed_input_bindings))
            if unexpected_input_refs:
                errors.append(
                    "documentation accepted inputs are not limited to the current "
                    f"accepted QA suite: {package.package_id}: {unexpected_input_refs}"
                )
            if package.evidence_class == "production":
                missing_production_inputs = sorted(
                    set(allowed_input_bindings) - set(accepted_inputs)
                )
                if missing_production_inputs:
                    errors.append(
                        "production documentation must exactly consume the full "
                        "accepted production evidence set: "
                        f"{package.package_id}: missing={missing_production_inputs}"
                    )

            production_bindings = {
                item.artifact_ref: item for item in package.production_validation_bindings
            }
            for artifact_ref, actual in accepted_inputs.items():
                expected = allowed_input_bindings.get(artifact_ref)
                if expected is None:
                    continue
                if (
                    actual.artifact_id != expected.artifact_id
                    or actual.artifact_type != expected.artifact_type
                    or actual.revision != expected.revision
                    or actual.content_sha256 != expected.content_sha256
                    or actual.validation_cycle_id != expected.validation_cycle_id
                    or actual.migration_unit_id != expected.migration_unit_id
                ):
                    errors.append(
                        "documentation accepted input alters a current QA suite "
                        f"binding: {artifact_ref}"
                    )
                authoritative_acceptance_refs = {registration.registration_ref}
                production_binding = production_bindings.get(artifact_ref)
                if production_binding is not None:
                    authoritative_acceptance_refs.add(production_binding.validation_ref)
                if actual.accepted_by_ref not in authoritative_acceptance_refs:
                    errors.append(
                        "documentation accepted input does not use authoritative "
                        f"validation: {artifact_ref}"
                    )

            if package.evidence_class == "production":
                if set(production_bindings) != set(expected_production_bindings):
                    errors.append(
                        "documentation production validation evidence differs from "
                        f"the downstream registered report: {package.package_id}"
                    )
                else:
                    for artifact_ref, expected in expected_production_bindings.items():
                        actual = production_bindings[artifact_ref]
                        if (
                            actual.artifact_id != expected.artifact_id
                            or actual.artifact_type != expected.artifact_type
                            or actual.revision != expected.revision
                            or actual.content_sha256 != expected.content_sha256
                            or actual.validation_cycle_id != expected.validation_cycle_id
                            or actual.migration_unit_id != expected.migration_unit_id
                            or actual.validation_ref != expected.validation_ref
                            or actual.validation_hash != expected.validation_hash
                        ):
                            errors.append(
                                "documentation production validation is not an "
                                f"exact downstream report: {artifact_ref}"
                            )
            elif production_bindings or any(
                item.artifact_type == "production_validation_report"
                for item in package.accepted_input_bindings
            ):
                errors.append(
                    "non-production documentation cannot consume production "
                    f"validation evidence: {package.package_id}"
                )

        current_by_ref = {item.ref: item for item in current_artifacts}
        accepted_input_by_ref = {
            item.artifact_ref: item for item in package.accepted_input_bindings
        }
        for output in package.output_bindings:
            output_artifact = current_by_ref.get(output.artifact_ref)
            if output_artifact is None:
                continue
            expected_lineage = {
                (
                    accepted_input_by_ref[reference].artifact_id,
                    accepted_input_by_ref[reference].revision,
                    accepted_input_by_ref[reference].content_sha256,
                )
                for reference in output.input_artifact_refs
                if reference in accepted_input_by_ref
            }
            actual_lineage = {
                (
                    str(item.get("artifact_id")),
                    int(item.get("revision", 0)),
                    str(item.get("content_sha256")),
                )
                for item in output_artifact.input_artifacts
            }
            if (
                len(expected_lineage) != len(output.input_artifact_refs)
                or actual_lineage != expected_lineage
            ):
                errors.append(
                    "documentation output artifact lineage must exactly match "
                    f"accepted input bindings: {output.artifact_ref}"
                )

        package_artifacts = [
            item
            for item in current_artifacts
            if item.artifact_type == "documentation_package"
            and item.migration_unit_id == package.migration_unit_id
            and item.validation_cycle_id == cycle_id
            and item.content_sha256 == sha256_json(package.model_dump(mode="json"))
        ]
        if len(package_artifacts) != 1:
            errors.append(
                f"documentation package {package.package_id} lacks one exact current artifact"
            )
        else:
            expected_input_refs = {
                *(item.artifact_ref for item in package.accepted_input_bindings),
                *(item.artifact_ref for item in package.output_bindings),
            }
            expected_input_keys = {
                (
                    current_by_ref[reference].artifact_id,
                    current_by_ref[reference].revision,
                    current_by_ref[reference].content_sha256,
                )
                for reference in expected_input_refs
                if reference in current_by_ref
            }
            if len(expected_input_keys) != len(expected_input_refs):
                errors.append(
                    "documentation package artifact inputs include an unregistered "
                    f"binding: {package.package_id}"
                )
            actual_input_keys = {
                (
                    str(item.get("artifact_id")),
                    int(item.get("revision", 0)),
                    str(item.get("content_sha256")),
                )
                for item in package_artifacts[0].input_artifacts
            }
            if actual_input_keys != expected_input_keys:
                errors.append(
                    "documentation package artifact lineage must exactly bind QA, "
                    f"final targets, production evidence, and outputs: {package.package_id}"
                )


def _validate_lifecycle(
    manifest: Mapping[str, Any], phase: str, context: PolicyContext, errors: list[str]
) -> None:
    if context.lifecycle is None:
        if context.strict and reached(phase, "parallel_run"):
            errors.append("parallel-run or later phase requires a migration lifecycle record")
        return
    lifecycle = context.lifecycle
    _validate_references(lifecycle, context, errors, "migration_lifecycle")
    errors.extend(
        validate_migration_lifecycle(
            lifecycle,
            now=context.now,
            expected_run_id=str(manifest["run_id"]),
            expected_source_fingerprint=manifest["source"]["acquisition"].get("source_fingerprint"),
            expected_artifact_fingerprint=manifest["revision_set"].get(
                "promotion_bundle_fingerprint"
            ),
        )
    )
    parallel_status = str(lifecycle.get("parallel_run", {}).get("status", ""))
    cutover_status = str(lifecycle.get("cutover", {}).get("status", ""))
    hypercare_status = str(lifecycle.get("hypercare", {}).get("status", ""))
    decommission_status = str(lifecycle.get("source_decommission", {}).get("status", ""))
    if phase == "parallel_run" and parallel_status not in {"active", "completed"}:
        errors.append("parallel_run phase requires an active or completed parallel run")
    if reached(phase, "cutover_authorized") and cutover_status not in {
        "authorized",
        "executing",
        "accepted",
    }:
        errors.append("cutover_authorized phase lacks lifecycle authorization")
    if reached(phase, "cutover_accepted") and cutover_status != "accepted":
        errors.append("cutover_accepted phase lacks lifecycle acceptance")
    if phase == "hypercare" and hypercare_status not in {"active", "extended", "completed"}:
        errors.append("hypercare phase requires active lifecycle hypercare")
    if reached(phase, "hypercare_accepted") and hypercare_status != "completed":
        errors.append("hypercare_accepted phase lacks lifecycle acceptance")
    if reached(phase, "source_decommission_authorized") and decommission_status not in {
        "authorized",
        "completed",
    }:
        errors.append("source decommission phase lacks lifecycle authorization")
    if reached(phase, "source_decommissioned") and decommission_status != "completed":
        errors.append("source_decommissioned phase lacks lifecycle completion evidence")


def _expected_scope_refs(manifest: Mapping[str, Any], action: str) -> set[str]:
    source = manifest["source"]
    target = manifest["target"]
    run_id = manifest["run_id"]
    if action == "acquire_source":
        return {str(source["tenant_ref"])}
    if action in {"create_dbt_branch_changes", "merge_dbt", "materialize_dbt"}:
        return {str(target["dbt"]["repository_ref"])}
    if action == "create_omni_document_in_quarantine":
        return {
            str(target["omni"]["organization_ref"]),
            str(target["omni"]["content_parent_ref"]),
        }
    if action == "create_omni_content_draft":
        scopes = {str(target["omni"]["organization_ref"])}
        if target["omni"].get("target_document_ref"):
            scopes.add(str(target["omni"]["target_document_ref"]))
        return scopes
    if action in {
        "create_omni_model_branch_changes",
        "create_omni_model_branch",
        "refresh_omni_schema",
        "set_omni_branch_dbt_environment",
        "merge_model_branch",
        "publish_content",
        "change_security",
        "change_operations",
    }:
        return {str(target["omni"]["organization_ref"])}
    if action == "cutover":
        return {f"run-ref://{run_id}"}
    if action == "decommission_source":
        return {str(source["tenant_ref"])}
    return set()


def _target_write_scope_map(
    manifest: Mapping[str, Any],
) -> dict[str, list[str]]:
    return {
        action: sorted(_expected_scope_refs(manifest, action))
        for action in WRITE_ACTION_BY_WORK_PHASE.values()
    }


def _validate_write_retry_history(events: Sequence[Mapping[str, Any]], errors: list[str]) -> None:
    """Reconstruct retry eligibility from ordered, append-only write events."""

    ordered: list[tuple[int, Mapping[str, Any], str]] = []
    for position, event in enumerate(events):
        payload = _payload(event)
        try:
            order = int(event.get("sequence", position + 1))
        except (TypeError, ValueError):
            order = position + 1
        ordered.append((order, payload, _event_type(event)))
    ordered.sort(key=lambda item: item[0])

    writes: dict[str, tuple[int, Mapping[str, Any]]] = {}
    reconciliations: dict[str, list[tuple[int, Mapping[str, Any]]]] = defaultdict(list)
    for order, payload, event_type in ordered:
        if event_type == "write_result":
            operation_id = str(payload.get("operation_id", ""))
            if not operation_id:
                errors.append("write result is missing an operation ID")
            elif operation_id in writes:
                errors.append(f"duplicate write operation ID: {operation_id}")
            else:
                writes[operation_id] = (order, payload)
        elif event_type == "write_reconciliation":
            operation_id = str(payload.get("operation_id", ""))
            if not operation_id:
                errors.append("write reconciliation is missing an operation ID")
            else:
                reconciliations[operation_id].append((order, payload))

    for operation_id, records in reconciliations.items():
        if len(records) > 1:
            errors.append(f"write operation has duplicate reconciliations: {operation_id}")
        prior = writes.get(operation_id)
        for reconciliation_order, reconciliation in records:
            if prior is None or prior[0] >= reconciliation_order:
                errors.append(f"write reconciliation references no prior operation: {operation_id}")
                continue
            prior_payload = prior[1]
            if prior_payload.get("result") != "ambiguous":
                errors.append(
                    f"write reconciliation references a non-ambiguous operation: {operation_id}"
                )
            if reconciliation.get("target_ref") != prior_payload.get("target_ref"):
                errors.append(
                    f"write reconciliation target differs from prior write: {operation_id}"
                )
            if reconciliation.get("outcome") not in {
                "applied",
                "not_applied",
                "indeterminate",
            }:
                errors.append(f"write reconciliation has an invalid outcome: {operation_id}")

    for operation_id, (order, write) in writes.items():
        try:
            attempt = int(write.get("attempt", 1))
        except (TypeError, ValueError):
            attempt = 0
        retry_of = write.get("retry_of_operation_id")
        if attempt < 1:
            errors.append(f"write attempt must be positive: {operation_id}")
            continue
        if attempt == 1:
            if retry_of is not None:
                errors.append(f"first write attempt cannot name a retry operation: {operation_id}")
            continue
        if not retry_of:
            errors.append(f"retry attempt lacks a prior operation ID: {operation_id}")
            continue
        retry_of_id = str(retry_of)
        if retry_of_id == operation_id:
            errors.append(f"write retry references itself: {operation_id}")
            continue
        prior = writes.get(retry_of_id)
        if prior is None or prior[0] >= order:
            errors.append(f"write retry references no prior operation: {operation_id}")
            continue
        _prior_order, prior_write = prior
        prior_result = prior_write.get("result")
        if prior_result not in {"failed", "ambiguous"}:
            errors.append(f"write retry references a non-retryable prior result: {operation_id}")
        try:
            prior_attempt = int(prior_write.get("attempt", 1))
        except (TypeError, ValueError):
            prior_attempt = 0
        if attempt != prior_attempt + 1:
            errors.append(f"write retry attempt is not sequential: {operation_id}")
        if write.get("target_ref") != prior_write.get("target_ref"):
            errors.append(f"write retry target differs from prior write: {operation_id}")
        if write.get("action") != prior_write.get("action"):
            errors.append(f"write retry action differs from prior write: {operation_id}")
        if write.get("intended_fingerprint") != prior_write.get("intended_fingerprint"):
            errors.append(f"write retry fingerprint differs from prior write: {operation_id}")
        if prior_result == "ambiguous":
            eligible_reconciliations = [
                reconciliation
                for reconciliation_order, reconciliation in reconciliations.get(retry_of_id, [])
                if reconciliation_order < order
                and reconciliation.get("target_ref") == prior_write.get("target_ref")
                and reconciliation.get("outcome") == "not_applied"
            ]
            if not eligible_reconciliations:
                errors.append(
                    f"ambiguous write lacks a matching not-applied reconciliation before retry: {operation_id}"
                )


def _validate_authorizations(
    manifest: Mapping[str, Any],
    phase: str,
    context: PolicyContext,
    evidence_by_ref: Mapping[str, Any],
    errors: list[str],
) -> None:
    authorizations = list(manifest.get("authorities", {}).get("active_authorizations", []))
    duplicate_ids = _duplicates(str(item.get("authorization_id")) for item in authorizations)
    if duplicate_ids:
        errors.append(f"duplicate authorization IDs: {sorted(duplicate_ids)}")
    cycle_id = str(manifest["revision_set"]["validation_cycle_id"])
    promotion_fingerprint = manifest["revision_set"].get("promotion_bundle_fingerprint")
    source_fingerprint = manifest["source"]["acquisition"]["source_fingerprint"]
    by_id = {str(item.get("authorization_id")): item for item in authorizations}
    actions = {str(item.get("action")) for item in authorizations}
    target_write_actions = set(WRITE_ACTION_BY_WORK_PHASE.values())
    package_bindings: dict[str, tuple[str, str, frozenset[str]]] = {}
    for work_package in context.work_packages:
        authority = work_package.get("authority", {})
        authorization_ref = authority.get("authorization_ref")
        if not authorization_ref:
            continue
        work_phase = str(work_package.get("phase", ""))
        expected_action = WRITE_ACTION_BY_WORK_PHASE.get(work_phase)
        if expected_action is None:
            continue
        authorization_id = _reference_identity(str(authorization_ref))
        fingerprint = str(authority.get("intended_change_set_fingerprint") or "")
        target_scopes = frozenset(
            str(value) for value in authority.get("target_scope_refs", []) if value
        )
        binding = (expected_action, fingerprint, target_scopes)
        prior = package_bindings.get(authorization_id)
        if prior is not None and prior != binding:
            errors.append(
                "one target authorization is bound to conflicting work-package change sets: "
                f"{authorization_id}"
            )
        package_bindings[authorization_id] = binding
    now = context.now.astimezone(timezone.utc)
    for authorization in authorizations:
        authorization_id = str(authorization.get("authorization_id"))
        actor_ref = str(authorization.get("actor_ref", ""))
        if not _is_human(actor_ref, context):
            errors.append(f"authorization {authorization_id} is not issued by a human principal")
        try:
            approved_at = parse_time(str(authorization["approved_at"]))
            expires_at = parse_time(str(authorization["expires_at"]))
            if expires_at <= approved_at:
                errors.append(f"authorization expires before approval: {authorization_id}")
            if approved_at > now:
                errors.append(f"authorization approval is in the future: {authorization_id}")
            if expires_at <= now:
                errors.append(f"active authorization is expired: {authorization_id}")
        except (KeyError, ValueError) as exc:
            errors.append(f"authorization {authorization_id} has invalid timestamps: {exc}")
        if str(authorization.get("validation_cycle_id")) != cycle_id:
            errors.append(f"authorization belongs to a stale validation cycle: {authorization_id}")
        evidence_ref = authorization.get("evidence_ref")
        evidence = evidence_by_ref.get(str(evidence_ref))
        if context.strict and (evidence is None or evidence.get("kind") != "approval"):
            errors.append(f"authorization {authorization_id} lacks registered approval evidence")
        action = str(authorization.get("action"))
        package_binding = package_bindings.get(authorization_id)
        if package_binding is not None:
            expected_action, expected_fingerprint, expected_scopes = package_binding
            if action != expected_action:
                errors.append(
                    f"authorization {authorization_id} action differs from its work package"
                )
        else:
            expected_scopes = frozenset(_expected_scope_refs(manifest, action))
            expected_fingerprint = (
                promotion_fingerprint if action in RELEASE_ACTIONS else source_fingerprint
            )
            if context.strict and action in target_write_actions:
                errors.append(
                    f"target authorization {authorization_id} is not bound to a work package"
                )
        actual_scopes = {str(value) for value in authorization.get("scope_refs", [])}
        if context.strict and (not expected_scopes or frozenset(actual_scopes) != expected_scopes):
            errors.append(
                f"authorization {authorization_id} does not exactly match the action target scope"
            )
        if (
            expected_fingerprint
            and authorization.get("artifact_fingerprint") != expected_fingerprint
        ):
            errors.append(
                f"authorization {authorization_id} is bound to the wrong change-set fingerprint"
            )
    for threshold, required_actions in REQUIRED_ACTIONS_BY_PHASE.items():
        if reached(phase, threshold):
            missing = required_actions - actions
            if missing:
                errors.append(f"phase {phase} lacks authorizations: {sorted(missing)}")
            if manifest["revision_set"].get("promotion_bundle_fingerprint") is None:
                errors.append(f"phase {phase} requires a promotion bundle fingerprint")
    consumed: dict[str, int] = defaultdict(int)
    write_events: list[Mapping[str, Any]] = []
    _validate_write_retry_history(context.events, errors)
    for event in context.events:
        payload = _payload(event)
        if _event_type(event) == "authorization_consumed":
            consumed[str(payload.get("authorization_id"))] += 1
        elif _event_type(event) == "write_result":
            write_events.append(payload)
    for authorization_id, count in consumed.items():
        if authorization_id not in by_id:
            errors.append(f"consumption references unknown authorization: {authorization_id}")
        if count > 1:
            errors.append(f"one-time authorization consumed more than once: {authorization_id}")
    for event in write_events:
        authorization_id = str(event.get("authorization_id"))
        authorization = by_id.get(authorization_id)
        if authorization is None:
            errors.append(f"write event references unknown authorization: {authorization_id}")
            continue
        if context.strict and consumed.get(authorization_id) != 1:
            errors.append(f"write authorization was not consumed exactly once: {authorization_id}")
        if str(event.get("action")) != str(authorization.get("action")):
            errors.append(f"write event action differs from authorization: {authorization_id}")
        if event.get("target_ref") not in authorization.get("scope_refs", []):
            errors.append(f"write target is outside authorization scope: {authorization_id}")
        if event.get("intended_fingerprint") != authorization.get("artifact_fingerprint"):
            errors.append(f"write fingerprint differs from authorization: {authorization_id}")
        result = event.get("result")
        if result == "succeeded" and (
            not event.get("write_receipt_ref") or not event.get("readback_ref")
        ):
            errors.append(f"successful write lacks receipt/readback: {authorization_id}")
        if result == "ambiguous" and not event.get("readback_ref"):
            errors.append(f"ambiguous write lacks reconciliation readback: {authorization_id}")


def _validate_decisions_and_gates(
    manifest: Mapping[str, Any],
    phase: str,
    context: PolicyContext,
    stale_artifact_ids: set[str],
    artifacts: list[ArtifactEnvelope],
    errors: list[str],
) -> None:
    evidence = list(manifest.get("evidence", []))
    evidence_ids = [str(item.get("evidence_id")) for item in evidence]
    evidence_refs = [str(item.get("ref")) for item in evidence]
    if duplicates := _duplicates(evidence_ids):
        errors.append(f"duplicate evidence IDs: {sorted(duplicates)}")
    if duplicates := _duplicates(evidence_refs):
        errors.append(f"duplicate evidence references: {sorted(duplicates)}")
    evidence_by_ref = {str(item.get("ref")): item for item in evidence}
    for item in evidence:
        if item.get("sensitivity") in {
            "confidential",
            "restricted",
            "highly_restricted",
        } and item.get("redaction_status") not in {"applied", "verified"}:
            errors.append(
                f"sensitive evidence is not redacted or verified: {item.get('evidence_id')}"
            )
    decisions = list(manifest.get("decisions", []))
    decision_ids = [str(item.get("decision_id")) for item in decisions]
    if duplicates := _duplicates(decision_ids):
        errors.append(f"duplicate decision IDs: {sorted(duplicates)}")
    decision_by_id = {str(item.get("decision_id")): item for item in decisions}
    source_fingerprint = str(manifest["source"]["acquisition"]["source_fingerprint"])
    promotion_fingerprint = manifest["revision_set"].get("promotion_bundle_fingerprint")
    for decision in decisions:
        status = decision.get("status")
        if status not in {"approved", "rejected", "waived"}:
            continue
        resolution = decision.get("human_resolution")
        if not isinstance(resolution, Mapping):
            errors.append(
                f"resolved decision lacks human resolution: {decision.get('decision_id')}"
            )
            continue
        if not _is_human(str(resolution.get("actor_ref", "")), context):
            errors.append(f"decision resolution is not human: {decision.get('decision_id')}")
        resolution_fingerprint = resolution.get("artifact_fingerprint")
        if resolution_fingerprint not in {source_fingerprint, promotion_fingerprint}:
            errors.append(
                f"decision resolution is bound to a stale or unknown artifact fingerprint: {decision.get('decision_id')}"
            )
        if status == "waived" and context.strict:
            if not decision.get("impact"):
                errors.append(f"waiver lacks impact statement: {decision.get('decision_id')}")
            if not decision.get("compensating_controls"):
                errors.append(f"waiver lacks compensating controls: {decision.get('decision_id')}")
            if str(
                decision.get("validation_cycle_id", manifest["revision_set"]["validation_cycle_id"])
            ) != str(manifest["revision_set"]["validation_cycle_id"]):
                errors.append(
                    f"waiver belongs to a stale validation cycle: {decision.get('decision_id')}"
                )
    gates = list(manifest.get("gates", []))
    gate_ids = [str(item.get("gate_id")) for item in gates]
    if duplicates := _duplicates(gate_ids):
        errors.append(f"gate IDs must be unique: {sorted(duplicates)}")
    gate_by_id = {str(item.get("gate_id")): item for item in gates}
    for gate_id, gate in gate_by_id.items():
        if gate_id in NON_WAIVABLE_GATES and gate.get("state") == "waived":
            errors.append(f"required semantic gate cannot be waived: {gate_id}")
    artifact_by_ref = {artifact.ref: artifact for artifact in artifacts}
    registered_evidence_refs = set(evidence_by_ref) | set(artifact_by_ref)
    required_gates = _required_gates(phase)
    cycle_id = str(manifest["revision_set"]["validation_cycle_id"])
    gate_resolver = GateRecordResolver.from_control_plane_records(
        tenant_ref=str(manifest["source"]["tenant_ref"]),
        run_id=str(manifest["run_id"]),
        validation_cycle_id=cycle_id,
        gates=gates,
        artifacts=artifacts,
        actor_kinds=context.actor_kinds,
        strict_actor_resolution=context.strict,
        now=context.now,
        authorizations=list(manifest.get("authorities", {}).get("active_authorizations", [])),
        approval_evidence_refs=[
            str(item.get("ref"))
            for item in manifest.get("evidence", [])
            if item.get("kind") == "approval"
        ],
        action_scope_refs=_target_write_scope_map(manifest),
        authorization_artifact_fingerprint=str(
            manifest.get("source", {}).get("acquisition", {}).get("source_fingerprint", "")
        ),
        dashboard_evidence_snapshots=[
            _payload(event)
            for event in context.events
            if _event_type(event) == "dashboard_evidence_snapshot_registered"
        ],
        dashboard_plan_validations=[
            _payload(event)
            for event in context.events
            if _event_type(event) == "dashboard_plan_validated"
        ],
        qa_evidence_snapshots=[
            _payload(event)
            for event in context.events
            if _event_type(event) == "qa_evidence_snapshot_registered"
        ],
        qa_suite_validations=[
            _payload(event)
            for event in context.events
            if _event_type(event) == "qa_suite_validated"
        ],
        semantic_profile_coverages=[
            _payload(event)
            for event in context.events
            if _event_type(event) == "semantic_profile_coverage_registered"
        ],
        verified_event_ledger=context.verified_event_ledger,
    )
    for gate_id in required_gates:
        gate = gate_by_id.get(gate_id)
        if gate is None:
            errors.append(f"missing required gate: {gate_id}")
            continue
        if gate.get("state") not in {"passed", "waived"}:
            errors.append(f"required gate is not passed or waived: {gate_id}")
        required_refs = [str(value) for value in gate.get("required_evidence_refs", [])]
        if not required_refs:
            errors.append(f"required gate has no evidence: {gate_id}")
        missing_refs = set(required_refs) - registered_evidence_refs
        if missing_refs:
            errors.append(
                f"gate {gate_id} references unregistered evidence: {sorted(missing_refs)}"
            )
        if str(gate.get("validation_cycle_id")) != cycle_id:
            errors.append(f"gate {gate_id} belongs to a stale validation cycle")
        try:
            checked_at = parse_time(str(gate.get("checked_at", "")))
            if checked_at > context.now.astimezone(timezone.utc):
                errors.append(f"gate {gate_id} has a future checked_at timestamp")
        except (TypeError, ValueError):
            errors.append(f"gate {gate_id} has an invalid checked_at timestamp")
        checked_by = str(gate.get("checked_by_ref", ""))
        if gate_id in HUMAN_GATES and not _is_human(checked_by, context):
            errors.append(f"gate {gate_id} requires a true human approver")
        if gate_id in INDEPENDENT_GATE_IDS and not _is_qa(checked_by, context):
            errors.append(f"gate {gate_id} requires independent QA or a human reviewer")
        elif (
            gate_id in QA_GATES
            and reached(phase, "qa_accepted")
            and not _is_qa(checked_by, context)
        ):
            errors.append(f"gate {gate_id} requires independent QA or a human reviewer")
        if gate_id in PRE_BUILD_SEMANTIC_GATE_IDS or (
            context.strict and gate_id == "source_completeness"
        ):
            errors.extend(
                gate_resolver.violations_for_gate_id(
                    gate_id,
                    migration_unit_id=None,
                    require_unit_match=False,
                )
            )
        if gate.get("state") == "waived":
            waiver_id = str(gate.get("waiver_decision_id", ""))
            decision = decision_by_id.get(waiver_id)
            if decision is None:
                errors.append(f"gate {gate_id} references a nonexistent waiver decision")
            elif decision.get("status") != "waived" or not decision.get("human_resolution"):
                errors.append(f"gate {gate_id} waiver is not human-resolved")
            else:
                subjects = {str(value) for value in decision.get("subject_refs", [])}
                if context.strict and f"gate-ref://{gate_id}" not in subjects:
                    errors.append(f"gate {gate_id} waiver decision is not scoped to the gate")
        for evidence_ref in required_refs:
            artifact = artifact_by_ref.get(evidence_ref)
            if artifact is not None and artifact.artifact_id in stale_artifact_ids:
                errors.append(
                    f"gate {gate_id} relies on an invalidated artifact: {artifact.artifact_id}"
                )
        if manifest.get("run_purpose") == "customer_migration":
            synthetic_refs = [
                ref
                for ref in required_refs
                if evidence_by_ref.get(ref, {}).get("classification") == "synthetic_fixture"
            ]
            if synthetic_refs:
                errors.append(
                    f"customer gate {gate_id} relies on synthetic evidence: {synthetic_refs}"
                )
    _validate_authorizations(manifest, phase, context, evidence_by_ref, errors)


def _validate_revision_and_release(
    manifest: Mapping[str, Any],
    phase: str,
    context: PolicyContext,
    artifacts: list[ArtifactEnvelope],
    errors: list[str],
) -> None:
    revisions = manifest["revision_set"]
    if reached(phase, "architecture_approved"):
        target = manifest.get("target", {})
        required_identities = {
            "warehouse.account_ref": target.get("warehouse", {}).get("account_ref"),
            "warehouse.database": target.get("warehouse", {}).get("database"),
            "warehouse.development_schema": target.get("warehouse", {}).get("development_schema"),
            "dbt.repository_ref": target.get("dbt", {}).get("repository_ref"),
            "dbt.project_name": target.get("dbt", {}).get("project_name"),
            "dbt.branch": target.get("dbt", {}).get("branch"),
            "omni.organization_ref": target.get("omni", {}).get("organization_ref"),
            "omni.connection_id": target.get("omni", {}).get("connection_id"),
            "omni.model_id": target.get("omni", {}).get("model_id"),
            "omni.development_branch": target.get("omni", {}).get("development_branch"),
            "omni.content_parent_ref": target.get("omni", {}).get("content_parent_ref"),
            "omni.content_operation": target.get("omni", {}).get("content_operation"),
            "omni.content_environment": target.get("omni", {}).get("content_environment"),
        }
        missing_identities = sorted(
            name
            for name, value in required_identities.items()
            if not isinstance(value, str) or not value.strip()
        )
        if missing_identities:
            errors.append(f"target identity is incomplete: {missing_identities}")
        omni_target = target.get("omni", {})
        if omni_target.get("content_environment") not in {
            "restricted_quarantine",
            "isolated_non_production",
        }:
            errors.append(
                "Omni content target must be a verified restricted quarantine or isolated non-production environment"
            )
        content_operation = omni_target.get("content_operation")
        if content_operation not in {"create_new", "update_existing"}:
            errors.append("Omni content operation must distinguish create from update")
        if content_operation == "update_existing" and not omni_target.get("target_document_ref"):
            errors.append("existing-document updates require an exact target document reference")
        if reached(phase, "dashboard_ready"):
            if not omni_target.get("target_document_ref"):
                errors.append("dashboard readiness requires exact Omni document readback identity")
            if content_operation == "create_new" and not omni_target.get(
                "document_create_readback_ref"
            ):
                errors.append(
                    "new-document dashboard readiness requires separate creation readback"
                )
    if (
        revisions.get("source_bundle_fingerprint")
        != manifest["source"]["acquisition"]["source_fingerprint"]
    ):
        errors.append("revision_set source fingerprint does not match acquired source")
    if (
        reached(phase, "dbt_promotion_authorized")
        and manifest.get("run_purpose") != "customer_migration"
    ):
        errors.append("dry-run and synthetic manifests cannot enter promotion states")
    if reached(phase, "dbt_promotion_authorized") and revisions.get("dbt_commit_sha") is None:
        errors.append("dbt promotion requires an immutable dbt commit SHA")
    if (
        reached(phase, "dbt_promoted_and_read_back")
        and revisions.get("dbt_materialization_ref") is None
    ):
        errors.append("dbt promoted status requires materialization readback")
    if reached(phase, "omni_revalidated") and revisions.get("omni_model_fingerprint") is None:
        errors.append("Omni revalidation requires an Omni model fingerprint")
    if (
        reached(phase, "omni_promoted_and_read_back")
        and revisions.get("omni_document_revision_ref") is None
        and not revisions.get("omni_document_revision_refs")
    ):
        errors.append("Omni promoted status requires document revision readback")
    if reached(phase, "source_decommission_authorized"):
        gate_ids = {
            str(gate.get("gate_id"))
            for gate in manifest.get("gates", [])
            if gate.get("state") in {"passed", "waived"}
        }
        if "hypercare" not in gate_ids:
            errors.append("source decommission requires an accepted hypercare gate")
    units = manifest.get("migration_units") or []
    unit_ids = [str(unit.get("migration_unit_id", "")) for unit in units]
    if duplicates := _duplicates(unit_ids):
        errors.append(f"migration unit IDs must be unique: {sorted(duplicates)}")
    if context.strict and reached(phase, "dashboard_planned"):
        if not units:
            errors.append(
                "every dashboard migration requires an explicit migration unit before dashboard planning"
            )
        latest_by_id: dict[str, ArtifactEnvelope] = {}
        for artifact in artifacts:
            current = latest_by_id.get(artifact.artifact_id)
            if current is None or artifact.revision > current.revision:
                latest_by_id[artifact.artifact_id] = artifact
        current_artifacts = {
            artifact.ref: artifact
            for artifact in latest_by_id.values()
            if artifact.validation_cycle_id == str(manifest["revision_set"]["validation_cycle_id"])
        }
        document_artifacts = [
            artifact
            for artifact in current_artifacts.values()
            if artifact.artifact_type == "omni_content_artifact"
        ]
        topic_artifacts_by_ref = {
            artifact.ref: artifact
            for artifact in current_artifacts.values()
            if artifact.artifact_type == "topic_blueprint"
        }
        dashboard_plans_by_ref = {
            artifact.ref: artifact
            for artifact in current_artifacts.values()
            if artifact.artifact_type == "dashboard_rebuild_plan"
        }
        from omni_migrator.dashboards.rebuild_plan import (
            DashboardPlanValidationRegistration,
        )

        current_plan_validations: list[DashboardPlanValidationRegistration] = []
        for event in context.events:
            if _event_type(event) != "dashboard_plan_validated":
                continue
            raw = {key: value for key, value in _payload(event).items() if key != "event_type"}
            try:
                registration = DashboardPlanValidationRegistration.model_validate(raw)
            except (TypeError, ValueError):
                continue
            if (
                registration.validation_cycle_id
                == str(manifest["revision_set"]["validation_cycle_id"])
                and registration.plan_artifact_ref in dashboard_plans_by_ref
            ):
                current_plan_validations.append(registration)
        selected_page_keys: list[tuple[str, str]] = []
        for unit in units:
            unit_id = str(unit.get("migration_unit_id", ""))
            selected_pages = []
            for reference in unit.get("source_object_refs", []):
                parsed = urlsplit(str(reference))
                if parsed.scheme.lower() == "domo-object-ref" and (parsed.netloc.lower() == "page"):
                    page_id = parsed.path.strip("/")
                    if page_id:
                        selected_pages.append(page_id)
            if len(selected_pages) != 1:
                errors.append(
                    "each dashboard migration unit must select exactly one Domo Page: "
                    f"{unit_id}:{sorted(selected_pages)}"
                )
            else:
                selected_page_keys.append((unit_id, selected_pages[0]))
            topic_refs = {
                str(reference) for reference in unit.get("topic_blueprint_refs", []) if reference
            }
            if not topic_refs:
                errors.append(
                    f"migration unit lacks accepted Topic blueprint references: {unit_id}"
                )
                continue
            missing_topics = sorted(topic_refs - set(topic_artifacts_by_ref))
            if missing_topics:
                errors.append(
                    f"migration unit references unregistered current Topic blueprints: "
                    f"{unit_id}:{missing_topics}"
                )
            wrong_unit_topics = sorted(
                reference
                for reference in topic_refs.intersection(topic_artifacts_by_ref)
                if topic_artifacts_by_ref[reference].migration_unit_id != unit_id
            )
            if wrong_unit_topics:
                errors.append(
                    f"migration unit references Topic blueprints from another unit: "
                    f"{unit_id}:{wrong_unit_topics}"
                )
            dashboard_plan_ref = str(unit.get("dashboard_plan_ref") or "")
            dashboard_plan = dashboard_plans_by_ref.get(dashboard_plan_ref)
            if dashboard_plan is None:
                errors.append(
                    "migration unit lacks a registered current dashboard rebuild plan: "
                    f"{unit_id}:{dashboard_plan_ref or '<missing>'}"
                )
            elif dashboard_plan.migration_unit_id != unit_id:
                errors.append(
                    "migration unit references a dashboard rebuild plan from another unit: "
                    f"{unit_id}:{dashboard_plan_ref}"
                )
            elif len(selected_pages) == 1:
                matching_validations = [
                    item
                    for item in current_plan_validations
                    if item.migration_unit_id == unit_id
                    and item.page_id == selected_pages[0]
                    and item.plan_artifact_ref == dashboard_plan_ref
                ]
                if len(matching_validations) != 1:
                    errors.append(
                        "selected Page lacks exactly one current validated dashboard plan: "
                        f"{unit_id}:{selected_pages[0]}:{dashboard_plan_ref}"
                    )
        duplicate_pages = sorted(
            page_id
            for page_id in {page_id for _, page_id in selected_page_keys}
            if sum(1 for _, candidate_page_id in selected_page_keys if candidate_page_id == page_id)
            > 1
        )
        if duplicate_pages:
            errors.append(
                f"selected Domo Pages cannot be repeated across migration units: {duplicate_pages}"
            )
        current_validation_keys = [
            (item.migration_unit_id, item.page_id) for item in current_plan_validations
        ]
        duplicated_validation_pages = sorted(
            key for key in set(current_validation_keys) if current_validation_keys.count(key) > 1
        )
        if duplicated_validation_pages:
            errors.append(
                "selected Pages have duplicate current dashboard plans: "
                f"{duplicated_validation_pages}"
            )
        unselected_plan_pages = sorted(set(current_validation_keys) - set(selected_page_keys))
        if unselected_plan_pages:
            errors.append(
                "current dashboard plans exist outside the selected Page denominator: "
                f"{unselected_plan_pages}"
            )
        if reached(phase, "dashboard_ready"):
            incomplete_units = sorted(
                str(unit.get("migration_unit_id", ""))
                for unit in units
                if unit.get("status") not in {"built", "validated"}
            )
            if incomplete_units:
                errors.append(f"migration units are not built or validated: {incomplete_units}")
            declared_unit_ids = set(unit_ids)
            covered_units = {
                artifact.migration_unit_id
                for artifact in document_artifacts
                if artifact.migration_unit_id
            }
            if declared_unit_ids and declared_unit_ids - covered_units:
                errors.append(
                    "migration units lack current Omni content artifacts: "
                    f"{sorted(declared_unit_ids - covered_units)}"
                )
        if reached(phase, "qa_accepted"):
            unvalidated_units = sorted(
                str(unit.get("migration_unit_id", ""))
                for unit in units
                if unit.get("status") != "validated"
            )
            if unvalidated_units:
                errors.append(
                    "QA acceptance requires every migration unit to be validated: "
                    f"{unvalidated_units}"
                )


def validate_manifest_policy(
    manifest: Mapping[str, Any], context: PolicyContext | None = None
) -> list[str]:
    """Return every deterministic policy violation for a run and its records."""

    policy_context = context or PolicyContext()
    errors: list[str] = []
    try:
        phase, _health = _manifest_phase_health(manifest, errors, policy_context.strict)
        _validate_references(manifest, policy_context, errors)
        acquisition = manifest["source"]["acquisition"]
        if reached(phase, "acquired"):
            if acquisition.get("mode") not in {"saved_api", "manual_files", "hybrid"}:
                errors.append("acquired or later phase requires a supported acquisition mode")
            for field_name in ("acquired_at", "source_fingerprint", "evidence_bundle_ref"):
                value = acquisition.get(field_name)
                if not isinstance(value, str) or not value.strip():
                    errors.append(
                        f"acquired or later phase requires non-empty acquisition {field_name}"
                    )
            try:
                if parse_time(str(acquisition["acquired_at"])) > policy_context.now.astimezone(
                    timezone.utc
                ):
                    errors.append("source acquisition timestamp is in the future")
            except (KeyError, ValueError):
                errors.append("source acquisition timestamp is invalid")
        if reached(phase, "inventoried") and acquisition.get("coverage_status") != "complete":
            errors.append("inventoried or later phase requires complete source coverage")
        _validate_event_history(manifest, phase, policy_context, errors)
        artifacts = _normalize_artifacts(manifest, policy_context, errors)
        _validate_store_attested_artifact_envelopes(phase, policy_context, artifacts, errors)
        _validate_strict_run_evidence(phase, policy_context, artifacts, errors)
        _validate_domo_inventory_registrations(
            phase, policy_context, artifacts, errors
        )
        _validate_external_handoff_registrations(
            phase, policy_context, errors
        )
        stale_artifacts = _stale_artifact_ids(artifacts, policy_context.events)
        _validate_work_packages(manifest, phase, policy_context, artifacts, errors)
        _validate_decisions_and_gates(
            manifest, phase, policy_context, stale_artifacts, artifacts, errors
        )
        _validate_qa_results(manifest, phase, policy_context, artifacts, errors)
        _validate_qa_acceptance_suites(manifest, phase, policy_context, artifacts, errors)
        _validate_production_validation_reports(manifest, phase, policy_context, artifacts, errors)
        _validate_documentation_packages(manifest, phase, policy_context, artifacts, errors)
        _validate_lifecycle(manifest, phase, policy_context, errors)
        _validate_revision_and_release(manifest, phase, policy_context, artifacts, errors)
    except (KeyError, TypeError, ValueError) as exc:
        errors.append(f"manifest policy evaluation failed safely: {exc}")
    return errors


def validate_manifest_policy_from_store(
    manifest: Mapping[str, Any],
    *,
    store: AppendOnlyControlPlaneStore,
    context: PolicyContext,
) -> list[str]:
    """Evaluate strict readiness from one application-configured store partition.

    The embedding application owns the store configuration and its trust anchor.
    This entry point ignores caller-supplied work packages, events, artifact
    envelopes, and QA registrations, replacing them with the exact partition read
    and verified by that store. Suite and documentation bodies remain caller inputs,
    but policy binds them to the current store-attested artifact and registration
    hashes.
    """

    if type(store) is not AppendOnlyControlPlaneStore:
        return [
            "strict readiness requires the exact application-configured "
            "AppendOnlyControlPlaneStore implementation"
        ]
    if not context.strict:
        return ["canonical-store policy evaluation requires a strict policy context"]
    try:
        tenant_ref = str(manifest["source"]["tenant_ref"])
        run_id = str(manifest["run_id"])
        verified = store.verified_ledger(tenant_ref, run_id)
    except (AppendOnlyConflict, KeyError, TypeError, ValueError) as exc:
        return [f"canonical control-plane store partition is unavailable: {exc}"]

    records = tuple(verified.records)
    artifact_payloads = tuple(
        record["payload"]
        for record in records
        if record.get("record_type") == "artifact" and isinstance(record.get("payload"), Mapping)
    )
    work_package_payloads = tuple(
        record["payload"]
        for record in records
        if record.get("record_type") == "work_package"
        and isinstance(record.get("payload"), Mapping)
    )
    event_payloads = tuple(
        record["payload"]
        for record in records
        if record.get("record_type") == "event" and isinstance(record.get("payload"), Mapping)
    )

    def nested_payloads(event_type: str, field_name: str) -> tuple[Mapping[str, Any], ...]:
        return tuple(
            payload[field_name]
            for payload in event_payloads
            if payload.get("event_type") == event_type
            and isinstance(payload.get(field_name), Mapping)
        )

    qa_suite_validations = tuple(
        {key: value for key, value in payload.items() if key != "event_type"}
        for payload in event_payloads
        if payload.get("event_type") == "qa_suite_validated"
    )
    trusted_context = replace(
        context,
        work_packages=work_package_payloads,
        artifacts=artifact_payloads,
        events=records,
        verified_event_ledger=verified,
        qa_fixtures_v2=nested_payloads("qa_fixture_v2_registered", "fixture"),
        qa_results_v2=nested_payloads("qa_result_v2_registered", "result"),
        qa_suite_validations=qa_suite_validations,
        production_validation_reports=nested_payloads(
            "production_validation_report_registered", "report"
        ),
    )
    return validate_manifest_policy(manifest, trusted_context)

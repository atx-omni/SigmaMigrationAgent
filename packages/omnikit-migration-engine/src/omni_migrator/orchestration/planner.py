"""Create a stable specialist DAG without granting execution authority.

The architecture manager decides scope and supplies approved artifact references. This
module converts that decision into a deterministic dependency graph. It does not call
models, resolve credentials, approve gates, or execute tools.
"""

from __future__ import annotations

import hashlib
from collections import defaultdict, deque
from typing import Any, Literal, Mapping
from urllib.parse import urlsplit

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_serializer, model_validator

from omni_migrator.control_plane.canonical import sha256_json
from omni_migrator.control_plane.external_handoffs import ExternalRedesignHandoff
from omni_migrator.control_plane.gates import (
    ARCHITECTURE_GATE_ID,
    BUILD_AUTHORIZATION_GATE_ID,
    CONSOLIDATION_GATE_ID,
    DASHBOARD_PLAN_GATE_ID,
    EQUIVALENCE_GATE_ID,
    PRE_BUILD_SEMANTIC_GATE_IDS,
    SEMANTIC_PROFILE_GATE_ID,
    TARGET_SEMANTIC_PROFILE_GATE_ID,
    TARGET_BUILD_GATE_IDS,
    GateRecordResolver,
    gate_ref,
    required_gate_ids_for_work_phase,
)
WorkPhase = Literal[
    "intake",
    "source_acquisition",
    "inventory",
    "repository_inventory",
    "semantic_profiling",
    "source_interpretation",
    "semantic_consolidation",
    "target_semantic_design",
    "topic_design",
    "dashboard_planning",
    "architecture",
    "data_acquisition",
    "data_build",
    "semantic_build",
    "document_create",
    "content_build",
    "development_qa",
    "production_qa",
    "documentation",
    "sigma_formula_planning",
    "sigma_commonality_planning",
    "sigma_dbt_planning",
    "sigma_omni_planning",
    "sigma_qa_planning",
    "sigma_documentation_planning",
]
ScopePurpose = Literal["comparison", "migration"]
AuthorityMode = Literal[
    "read_only",
    "proposal_only",
    "branch_write",
    "document_create_write",
    "document_draft_write",
]
ExternalCapability = Literal[
    "platform_ingestion", "application_redesign", "operations_governance"
]

AGENT_TOOL_ALLOWLISTS: dict[str, list[str]] = {
    "domo_to_omni_architect": [
        "artifact_registry_read", "artifact_registry_write", "control_plane_validate",
        "domo_evidence_broker_invoke", "local_draft_write", "specialist_delegate",
    ],
    "inventory_intake": [
        "artifact_registry_read", "artifact_registry_write", "control_plane_validate",
        "local_draft_write",
    ],
    "data_acquisition_ingestion": [
        "artifact_registry_read", "artifact_registry_write", "control_plane_validate",
        "domo_card_read", "domo_dataflow_read", "domo_dataset_read",
        "domo_evidence_broker_invoke", "domo_metadata_read", "domo_page_read",
        "domo_query_read", "local_draft_write", "source_sql_read",
    ],
    "domo_bi_developer": [
        "artifact_registry_read", "domo_card_read", "domo_metadata_read", "domo_page_read",
        "domo_query_read", "domo_visual_read", "local_draft_write",
    ],
    "domo_analytics_engineer": [
        "artifact_registry_read", "domo_dataflow_read", "domo_dataset_read",
        "domo_metadata_read", "domo_query_read", "local_draft_write", "source_sql_read",
    ],
    "semantic_consolidation": [
        "artifact_registry_read", "artifact_registry_write", "control_plane_validate",
        "local_draft_write",
    ],
    "dbt_analytics_engineer": [
        "artifact_registry_read", "artifact_registry_write", "dbt_branch_read",
        "dbt_branch_write", "dbt_build", "dbt_compile", "dbt_test", "local_draft_write",
        "snowflake_bounded_query",
    ],
    "omni_modeler": [
        "artifact_registry_read", "artifact_registry_write", "omni_content_validate",
        "omni_model_read", "omni_model_validate", "omni_model_write", "omni_query_read",
    ],
    "omni_bi_developer": [
        "artifact_registry_read", "artifact_registry_write", "omni_document_draft_write",
        "omni_document_read", "omni_query_read", "omni_visual_read",
    ],
    "migration_qa": [
        "artifact_registry_read", "artifact_registry_write", "control_plane_validate",
        "domo_query_read", "domo_visual_read",
        "omni_content_validate", "omni_query_read", "omni_visual_read", "persona_test_read",
        "snowflake_bounded_query",
    ],
    "documentation_training": ["artifact_registry_read", "local_draft_write"],
}

AGENT_DEFAULT_TOOL_PROFILES: dict[str, str] = {
    "domo_to_omni_architect": "orchestrator_read_delegate_and_manifest_write",
    "inventory_intake": "intake_validation_inventory_reconciliation_and_scope_proposal",
    "data_acquisition_ingestion": (
        "deterministic_source_acquisition_graph_normalization_and_ingestion_handoff"
    ),
    "domo_bi_developer": "domo_content_metadata_and_bounded_visual_read",
    "domo_analytics_engineer": "domo_dataflow_dataset_and_sql_read",
    "semantic_consolidation": "semantic_evidence_read_and_proposal_only",
    "dbt_analytics_engineer": "authorized_dbt_branch_and_snowflake_development",
    "omni_modeler": "authorized_omni_model_branch_checksum_write_and_validate",
    "omni_bi_developer": "authorized_documents_v2_draft_update",
    "migration_qa": "bounded_queries_validators_downloads_and_persona_tests",
    "documentation_training": "accepted_artifact_read_and_document_draft_write",
}

# Sigma planning is bounded to supplied artifacts and inert proposals. Target
# execution profiles from the role catalog are deliberately not inherited here.
SIGMA_PLANNING_TOOL_ALLOWLISTS: dict[str, list[str]] = {
    "sigma_analytics_formula": ["artifact_registry_read", "local_draft_write"],
    "sigma_semantic_consolidation": ["artifact_registry_read", "local_draft_write"],
    "sigma_dbt_analytics_engineer": ["artifact_registry_read", "local_draft_write"],
    "sigma_omni_modeler": ["artifact_registry_read", "local_draft_write"],
    "sigma_independent_qa": ["artifact_registry_read", "local_draft_write"],
    "sigma_documentation_training": ["artifact_registry_read", "local_draft_write"],
}
AGENT_TOOL_ALLOWLISTS.update(SIGMA_PLANNING_TOOL_ALLOWLISTS)
AGENT_DEFAULT_TOOL_PROFILES.update(
    {agent: "sigma_bound_artifact_proposal" for agent in SIGMA_PLANNING_TOOL_ALLOWLISTS}
)

DBT_REPOSITORY_READ_ONLY_TOOLS = [
    "artifact_registry_read",
    "artifact_registry_write",
    "control_plane_validate",
    "dbt_branch_read",
    "local_draft_write",
]

OMNI_DOCUMENT_CREATE_TOOLS = [
    "artifact_registry_read",
    "artifact_registry_write",
    "omni_document_create_quarantine",
    "omni_document_read",
]

OMNI_CONTENT_DRAFT_TOOLS = [
    "artifact_registry_read",
    "artifact_registry_write",
    "omni_document_draft_write",
    "omni_document_read",
    "omni_query_read",
    "omni_visual_read",
]

SEMANTIC_PROFILE_GATE_REF = gate_ref(SEMANTIC_PROFILE_GATE_ID)
TARGET_SEMANTIC_PROFILE_GATE_REF = gate_ref(TARGET_SEMANTIC_PROFILE_GATE_ID)
EQUIVALENCE_GATE_REF = gate_ref(EQUIVALENCE_GATE_ID)
CONSOLIDATION_GATE_REF = gate_ref(CONSOLIDATION_GATE_ID)
ARCHITECTURE_GATE_REF = gate_ref(ARCHITECTURE_GATE_ID)
BUILD_AUTHORIZATION_GATE_REF = gate_ref(BUILD_AUTHORIZATION_GATE_ID)
DASHBOARD_PLAN_GATE_REF = gate_ref(DASHBOARD_PLAN_GATE_ID)
PRE_BUILD_SEMANTIC_GATE_REFS = [gate_ref(gate_id) for gate_id in PRE_BUILD_SEMANTIC_GATE_IDS]
TARGET_BUILD_GATE_REFS = [gate_ref(gate_id) for gate_id in TARGET_BUILD_GATE_IDS]
INPUT_BOUND_GATE_REFS = {
    gate_ref("source_completeness"),
    *PRE_BUILD_SEMANTIC_GATE_REFS,
    DASHBOARD_PLAN_GATE_REF,
    ARCHITECTURE_GATE_REF,
    BUILD_AUTHORIZATION_GATE_REF,
}
class PlannedSourceScope(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    system: Literal["domo", "sigma", "dbt", "snowflake", "omni"] = "domo"
    object_type: str
    object_id: str
    fingerprint: str = Field(pattern=r"^[a-f0-9]{64}$")


def planned_cross_scope_exception_hash(exception: Mapping[str, Any]) -> str:
    """Return the canonical hash binding a planned exception and its approval."""

    material = dict(exception)
    material.pop("exception_hash", None)
    return f"sha256:{sha256_json(material)}"


class PlannedCrossScopeException(BaseModel):
    """One immutable human-approved migration-only source revision."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    exception_id: str = Field(
        min_length=8,
        max_length=128,
        pattern=r"^[a-z0-9][a-z0-9._-]*$",
    )
    source_object: PlannedSourceScope
    approval_ref: str = Field(min_length=4, max_length=2048)
    approved_by_ref: str = Field(min_length=4, max_length=2048)
    approved_at: AwareDatetime
    reason: str = Field(min_length=1, max_length=4096)
    immutable: Literal[True] = True
    exception_hash: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")

    @model_validator(mode="after")
    def human_and_hash_binding(self) -> "PlannedCrossScopeException":
        if urlsplit(self.approved_by_ref).scheme.lower() not in {
            "human-ref",
            "person-ref",
            "person",
        }:
            raise ValueError("cross-scope exception approval must identify a human actor")
        if not urlsplit(self.approval_ref).scheme:
            raise ValueError("cross-scope exception requires a typed approval reference")
        expected = planned_cross_scope_exception_hash(self.model_dump(mode="json"))
        if self.exception_hash != expected:
            raise ValueError("cross-scope exception hash does not bind its exact approval")
        return self


class PlannedAgentAssignee(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: Literal["agent"] = "agent"
    agent_id: str


class PlannedExternalAssignee(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: Literal["external_team"] = "external_team"
    capability: ExternalCapability
    owner_ref: str


class PlannedAuthority(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mode: AuthorityMode | Literal["human_handoff"]
    authorization_ref: str | None = None
    intended_change_set_fingerprint: str | None = Field(
        default=None,
        pattern=r"^[a-f0-9]{64}$",
    )
    target_scope_refs: list[str] = Field(default_factory=list)
    allowed_tools: list[str] = Field(default_factory=list)
    forbidden_actions: list[str] = Field(min_length=1)


class PlannedValidationRequirement(BaseModel):
    model_config = ConfigDict(extra="forbid")

    validation_id: str
    method: str
    required_evidence: list[str] = Field(min_length=1)


class PlannedResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    state: Literal["not_started", "completed", "blocked"] = "not_started"
    artifact_refs: list[str] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)
    decision_requests: list[str] = Field(default_factory=list)
    issues: list[dict] = Field(default_factory=list)


class PlannedTimestamps(BaseModel):
    model_config = ConfigDict(extra="forbid")

    created_at: str
    updated_at: str


class MigrationPlanningContext(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_ref: str
    run_id: str
    migration_unit_id: str
    validation_cycle_id: str
    source_object_refs: list[str] = Field(min_length=1)
    source_scope: list[PlannedSourceScope] = Field(min_length=1)
    comparison_scope: list[PlannedSourceScope] | None = None
    cross_scope_exceptions: list[PlannedCrossScopeException] = Field(default_factory=list)
    created_at: str
    inventory_snapshot_ref: str
    source_object_graph_ref: str
    coverage_ledger_ref: str
    evidence_bundle_ref: str
    domo_inventory_observation_refs: list[str] = Field(default_factory=list)
    domo_portfolio_inventory_ref: str | None = None
    migration_scope_ref: str | None = None
    dependency_closure_gate_ref: str = "gate-ref://source_completeness"
    semantic_profile_refs: list[str] = Field(default_factory=list)
    target_semantic_profile_refs: list[str] = Field(default_factory=list)
    repository_inventory_ref: str | None = None
    semantic_profile_coverage_ref: str | None = None
    equivalence_assessment_refs: list[str] = Field(default_factory=list)
    consolidation_decision_refs: list[str] = Field(default_factory=list)
    topic_blueprint_refs: list[str] = Field(default_factory=list)
    dashboard_rebuild_plan_ref: str | None = None
    architecture_artifact_ref: str | None = None
    architecture_approval_ref: str | None = None
    build_authorization_ref: str | None = None
    dbt_build_authorization_ref: str | None = None
    dbt_change_set_fingerprint: str | None = Field(
        default=None,
        pattern=r"^[a-f0-9]{64}$",
    )
    dbt_target_scope_refs: list[str] = Field(default_factory=list)
    omni_model_authorization_ref: str | None = None
    omni_model_change_set_fingerprint: str | None = Field(
        default=None,
        pattern=r"^[a-f0-9]{64}$",
    )
    omni_model_target_scope_refs: list[str] = Field(default_factory=list)
    omni_document_operation: Literal["create_new", "update_existing"] = "create_new"
    omni_document_create_authorization_ref: str | None = None
    omni_document_create_change_set_fingerprint: str | None = Field(
        default=None,
        pattern=r"^[a-f0-9]{64}$",
    )
    omni_document_create_target_scope_refs: list[str] = Field(default_factory=list)
    omni_document_ref: str | None = None
    omni_document_shell_ref: str | None = None
    omni_document_create_readback_ref: str | None = None
    omni_content_authorization_ref: str | None = None
    omni_content_change_set_fingerprint: str | None = Field(
        default=None,
        pattern=r"^[a-f0-9]{64}$",
    )
    omni_content_target_scope_refs: list[str] = Field(default_factory=list)
    qa_fixture_refs: list[str] = Field(default_factory=list)
    target_artifact_refs: list[str] = Field(default_factory=list)
    target_operation_receipt_refs: list[str] = Field(default_factory=list)
    target_readback_refs: list[str] = Field(default_factory=list)
    qa_persona_policy_refs: list[str] = Field(default_factory=list)
    qa_tolerance_policy_refs: list[str] = Field(default_factory=list)
    qa_acceptance_suite_ref: str | None = None
    qa_suite_validation_ref: str | None = None
    production_target_artifact_refs: list[str] = Field(default_factory=list)
    production_dashboard_rebuild_plan_ref: str | None = None
    production_topic_blueprint_refs: list[str] = Field(default_factory=list)
    production_semantic_profile_refs: list[str] = Field(default_factory=list)
    production_consolidation_decision_refs: list[str] = Field(default_factory=list)
    production_source_evidence_refs: list[str] = Field(default_factory=list)
    production_qa_fixture_refs: list[str] = Field(default_factory=list)
    production_target_operation_receipt_refs: list[str] = Field(default_factory=list)
    production_target_readback_refs: list[str] = Field(default_factory=list)
    production_qa_persona_policy_refs: list[str] = Field(default_factory=list)
    production_qa_tolerance_policy_refs: list[str] = Field(default_factory=list)
    production_qa_result_refs: list[str] = Field(default_factory=list)
    production_qa_acceptance_suite_ref: str | None = None
    production_qa_suite_validation_ref: str | None = None
    production_validation_report_ref: str | None = None
    planning_mode: Literal["development", "production_revalidation"] = "development"
    ingestion_required: bool = True
    include_production_revalidation: Literal[True] = True
    external_handoffs: list[ExternalRedesignHandoff] = Field(default_factory=list)
    dbt_repository_ref: str | None = None

    @model_validator(mode="after")
    def approval_dependencies(self) -> "MigrationPlanningContext":
        reference_sets = {
            "semantic profile": self.semantic_profile_refs,
            "target semantic profile": self.target_semantic_profile_refs,
            "equivalence assessment": self.equivalence_assessment_refs,
            "consolidation decision": self.consolidation_decision_refs,
            "Topic blueprint": self.topic_blueprint_refs,
            "QA fixture": self.qa_fixture_refs,
            "target artifact": self.target_artifact_refs,
            "target operation receipt": self.target_operation_receipt_refs,
            "target readback": self.target_readback_refs,
            "QA persona policy": self.qa_persona_policy_refs,
            "QA tolerance policy": self.qa_tolerance_policy_refs,
            "production target artifact": self.production_target_artifact_refs,
            "production Topic blueprint": self.production_topic_blueprint_refs,
            "production semantic profile": self.production_semantic_profile_refs,
            "production consolidation decision": self.production_consolidation_decision_refs,
            "production source evidence": self.production_source_evidence_refs,
            "production QA fixture": self.production_qa_fixture_refs,
            "production target operation receipt": self.production_target_operation_receipt_refs,
            "production target readback": self.production_target_readback_refs,
            "production QA persona policy": self.production_qa_persona_policy_refs,
            "production QA tolerance policy": self.production_qa_tolerance_policy_refs,
            "production QA result": self.production_qa_result_refs,
        }
        for label, references in reference_sets.items():
            if len(references) != len(set(references)):
                raise ValueError(f"{label} references must be unique")
        if len(self.domo_inventory_observation_refs) != len(
            set(self.domo_inventory_observation_refs)
        ):
            raise ValueError("Domo inventory observation references must be unique")
        inventory_control_groups: tuple[object, ...] = (
            self.domo_inventory_observation_refs,
            self.domo_portfolio_inventory_ref,
            self.migration_scope_ref,
        )
        if any(inventory_control_groups) and not all(inventory_control_groups):
            raise ValueError(
                "Domo inventory control inputs require observations, the canonical "
                "portfolio, and the exact migration scope together"
            )
        semantic_profiles_ready = self.semantic_profile_refs[0] if self.semantic_profile_refs else None
        target_profiles_ready = (
            self.target_semantic_profile_refs[0]
            if self.target_semantic_profile_refs
            else None
        )
        repository_inventory_ready = self.repository_inventory_ref
        semantic_profile_coverage_ready = self.semantic_profile_coverage_ref
        equivalence_ready = (
            self.equivalence_assessment_refs[0]
            if self.equivalence_assessment_refs
            else None
        )
        decisions_ready = (
            self.consolidation_decision_refs[0]
            if self.consolidation_decision_refs
            else None
        )
        topics_ready = self.topic_blueprint_refs[0] if self.topic_blueprint_refs else None
        dashboard_plan_ready = self.dashboard_rebuild_plan_ref
        selected_pages = [
            item
            for item in self.source_scope
            if item.system == "domo" and item.object_type.lower() == "page"
        ]
        if dashboard_plan_ready and len(selected_pages) != 1:
            raise ValueError(
                "each dashboard rebuild plan requires exactly one selected Domo Page "
                "per migration unit"
            )
        migration_by_key = {
            (item.system, item.object_type, item.object_id): item
            for item in self.source_scope
        }
        if len(migration_by_key) != len(self.source_scope):
            raise ValueError("migration source scope contains duplicate object identities")
        comparison = self.comparison_scope or self.source_scope
        comparison_by_key = {
            (item.system, item.object_type, item.object_id): item
            for item in comparison
        }
        if len(comparison_by_key) != len(comparison):
            raise ValueError("comparison scope contains duplicate object identities")
        exception_ids = [item.exception_id for item in self.cross_scope_exceptions]
        if len(exception_ids) != len(set(exception_ids)):
            raise ValueError("cross-scope exception IDs must be unique")
        exception_by_key = {
            (
                item.source_object.system,
                item.source_object.object_type,
                item.source_object.object_id,
            ): item
            for item in self.cross_scope_exceptions
        }
        if len(exception_by_key) != len(self.cross_scope_exceptions):
            raise ValueError("cross-scope exception source identities must be unique")
        migration_only = set(migration_by_key) - set(comparison_by_key)
        missing_exceptions = migration_only - set(exception_by_key)
        if missing_exceptions:
            raise ValueError(
                "migration source scope must be a subset of comparison scope or have "
                "an exact approved cross-scope exception"
            )
        unused_exceptions = set(exception_by_key) - migration_only
        if unused_exceptions:
            raise ValueError(
                "cross-scope exceptions must identify migration-only source objects"
            )
        if any(
            exception_by_key[key].source_object.fingerprint
            != migration_by_key[key].fingerprint
            for key in migration_only
        ):
            raise ValueError(
                "cross-scope exception fingerprints must match the exact migration "
                "source revision"
            )
        if any(
            comparison_by_key[key].fingerprint != item.fingerprint
            for key, item in migration_by_key.items()
            if key in comparison_by_key
        ):
            raise ValueError(
                "comparison and migration scope fingerprints must match for shared objects"
            )
        staged_requirements = (
            (
                target_profiles_ready,
                (semantic_profiles_ready,),
                "a proposed target semantic profile requires accepted source and repository semantic profiles",
            ),
            (
                semantic_profile_coverage_ready,
                (
                    semantic_profiles_ready,
                    target_profiles_ready,
                    repository_inventory_ready,
                    self.domo_portfolio_inventory_ref,
                    self.migration_scope_ref,
                ),
                "semantic-profile coverage requires the exact source, repository, target, portfolio, and migration-scope revisions",
            ),
            (
                equivalence_ready,
                (
                    semantic_profiles_ready,
                    target_profiles_ready,
                    semantic_profile_coverage_ready,
                ),
                "equivalence assessments require accepted source and target semantic profiles plus exact semantic-profile coverage",
            ),
            (
                decisions_ready,
                (
                    semantic_profiles_ready,
                    target_profiles_ready,
                    semantic_profile_coverage_ready,
                    equivalence_ready,
                ),
                "a consolidation decision requires accepted source and target profiles plus equivalence assessments",
            ),
            (
                topics_ready,
                (
                    decisions_ready,
                    target_profiles_ready,
                ),
                "a Topic blueprint requires an accepted consolidation decision and target semantic profile",
            ),
            (
                dashboard_plan_ready,
                (topics_ready,),
                "a dashboard rebuild plan requires an accepted Topic blueprint",
            ),
            (
                self.architecture_artifact_ref,
                (dashboard_plan_ready,),
                "a target architecture requires an accepted dashboard rebuild plan",
            ),
            (
                self.architecture_approval_ref,
                (self.architecture_artifact_ref,),
                "architecture approval requires the exact target architecture artifact",
            ),
            (
                self.build_authorization_ref,
                (
                    semantic_profiles_ready,
                    equivalence_ready,
                    decisions_ready,
                    target_profiles_ready,
                    topics_ready,
                    dashboard_plan_ready,
                    self.architecture_artifact_ref,
                    self.architecture_approval_ref,
                ),
                "build authorization requires the accepted semantic, Topic, dashboard-plan, and architecture chain",
            ),
        )
        for supplied, prerequisites, message in staged_requirements:
            if supplied is not None and any(value is None for value in prerequisites):
                raise ValueError(message)
        action_authorizations = (
            self.dbt_build_authorization_ref,
            self.omni_model_authorization_ref,
            self.omni_document_create_authorization_ref,
            self.omni_content_authorization_ref,
        )
        if any(value is not None for value in action_authorizations) and not self.build_authorization_ref:
            raise ValueError(
                "phase-specific write authorizations require an accepted build authorization"
            )
        if self.build_authorization_ref and not all(inventory_control_groups):
            raise ValueError(
                "build authorization requires the exact Domo observation ledger, "
                "canonical portfolio, and migration scope"
            )
        write_bindings = (
            (
                "dbt build",
                self.dbt_build_authorization_ref,
                self.dbt_change_set_fingerprint,
                self.dbt_target_scope_refs,
            ),
            (
                "Omni model",
                self.omni_model_authorization_ref,
                self.omni_model_change_set_fingerprint,
                self.omni_model_target_scope_refs,
            ),
            (
                "Omni document create",
                self.omni_document_create_authorization_ref,
                self.omni_document_create_change_set_fingerprint,
                self.omni_document_create_target_scope_refs,
            ),
            (
                "Omni content draft",
                self.omni_content_authorization_ref,
                self.omni_content_change_set_fingerprint,
                self.omni_content_target_scope_refs,
            ),
        )
        for label, authorization_ref, fingerprint, scope_refs in write_bindings:
            if authorization_ref and (not fingerprint or not scope_refs):
                raise ValueError(
                    f"{label} authorization requires an exact change-set fingerprint "
                    "and target scope"
                )
            if not authorization_ref and (fingerprint or scope_refs):
                raise ValueError(
                    f"{label} change set and target scope require their exact authorization"
                )
            if len(scope_refs) != len(set(scope_refs)):
                raise ValueError(f"{label} target scope references must be unique")
        if self.omni_model_authorization_ref and not self.dbt_build_authorization_ref:
            raise ValueError("Omni model authorization requires the authorized dbt build stage")
        if (
            self.omni_document_create_authorization_ref
            and not self.omni_model_authorization_ref
        ):
            raise ValueError(
                "Omni document creation authorization requires the authorized model stage"
            )
        if self.omni_document_operation == "update_existing":
            if not self.omni_document_ref:
                raise ValueError("an existing-document update requires the exact document reference")
            if any(
                value
                for value in (
                    self.omni_document_create_authorization_ref,
                    self.omni_document_create_change_set_fingerprint,
                    *self.omni_document_create_target_scope_refs,
                    self.omni_document_shell_ref,
                    self.omni_document_create_readback_ref,
                )
            ):
                raise ValueError(
                    "an existing-document update cannot carry document-create authority"
                )
        elif self.omni_document_ref and (
            not self.omni_document_shell_ref
            or not self.omni_document_create_readback_ref
        ):
            raise ValueError(
                "a newly created document reference requires its exact shell and creation readback"
            )
        if self.omni_content_authorization_ref:
            if not self.omni_model_authorization_ref:
                raise ValueError("Omni content authorization requires the authorized model stage")
            if not self.omni_document_ref:
                raise ValueError(
                    "Omni content authorization requires an exact existing or created document reference"
                )
            if (
                self.omni_document_operation == "create_new"
                and not self.omni_document_create_authorization_ref
            ):
                raise ValueError(
                    "content for a new document requires separate document-create authority"
                )
            if self.omni_document_operation == "create_new" and (
                not self.omni_document_shell_ref
                or not self.omni_document_create_readback_ref
            ):
                raise ValueError(
                    "content for a new document requires its exact created shell and readback"
                )
        development_qa_groups: tuple[object, ...] = (
            self.qa_fixture_refs,
            self.target_artifact_refs,
            self.target_operation_receipt_refs,
            self.target_readback_refs,
            self.qa_persona_policy_refs,
            self.qa_tolerance_policy_refs,
        )
        if any(development_qa_groups) and not all(development_qa_groups):
            raise ValueError(
                "development QA requires exact fixtures, target artifacts, operation "
                "receipts, readbacks, persona policies, and tolerance policies"
            )
        if all(development_qa_groups) and (
            not dashboard_plan_ready
            or not topics_ready
            or not self.omni_content_authorization_ref
        ):
            raise ValueError(
                "development QA inputs require the accepted dashboard plan, Topics, "
                "and completed target-build chain"
            )
        if self.qa_acceptance_suite_ref and not all(development_qa_groups):
            raise ValueError(
                "a QA acceptance suite requires the exact development QA input set"
            )
        if self.qa_suite_validation_ref and not self.qa_acceptance_suite_ref:
            raise ValueError(
                "QA suite validation requires the exact acceptance-suite reference"
            )
        production_groups: tuple[object, ...] = (
            self.production_dashboard_rebuild_plan_ref,
            self.production_topic_blueprint_refs,
            self.production_semantic_profile_refs,
            self.production_consolidation_decision_refs,
            self.production_source_evidence_refs,
            self.production_qa_fixture_refs,
            self.production_target_artifact_refs,
            self.production_target_operation_receipt_refs,
            self.production_target_readback_refs,
            self.production_qa_persona_policy_refs,
            self.production_qa_tolerance_policy_refs,
        )
        if any(production_groups) and not all(production_groups):
            raise ValueError(
                "production QA requires exact current semantic coverage, dashboard, "
                "Topic, semantic, decision, source, fixture, promoted target, receipt, "
                "readback, persona, and tolerance evidence"
            )
        if any(production_groups) and not self.semantic_profile_coverage_ref:
            raise ValueError(
                "production QA requires the exact current semantic profile coverage"
            )
        if all(production_groups) and not self.qa_suite_validation_ref:
            raise ValueError(
                "production QA requires the exact accepted development QA suite validation"
            )
        production_qa_outputs: tuple[object, ...] = (
            self.production_qa_result_refs,
            self.production_qa_acceptance_suite_ref,
            self.production_qa_suite_validation_ref,
            self.production_validation_report_ref,
        )
        if any(production_qa_outputs) and not all(production_qa_outputs):
            raise ValueError(
                "production QA outputs require exact results, a production acceptance "
                "suite, its trusted validation, and the downstream validation report"
            )
        if all(production_qa_outputs) and (
            not all(production_groups) or not self.qa_suite_validation_ref
        ):
            raise ValueError(
                "production QA outputs require promoted target readbacks and the "
                "accepted development QA suite"
            )
        if self.planning_mode == "production_revalidation" and not all(
            production_groups
        ):
            raise ValueError(
                "production-revalidation planning requires the complete production QA input set"
            )
        if self.planning_mode == "development" and any(production_groups):
            raise ValueError(
                "production QA inputs require planning_mode=production_revalidation"
            )
        handoff_refs = [item.handoff_ref for item in self.external_handoffs]
        if len(handoff_refs) != len(set(handoff_refs)):
            raise ValueError("external handoff references must be unique")
        handoff_work_package_ids = [
            item.work_package_id for item in self.external_handoffs
        ]
        if len(handoff_work_package_ids) != len(set(handoff_work_package_ids)):
            raise ValueError("external handoff work-package IDs must be unique")
        if any(
            item.tenant_ref != self.tenant_ref
            or item.run_id != self.run_id
            or item.migration_unit_id != self.migration_unit_id
            or item.validation_cycle_id != self.validation_cycle_id
            for item in self.external_handoffs
        ):
            raise ValueError(
                "external handoff assignments must match the exact planning partition"
            )
        platform_assignments = [
            item for item in self.external_handoffs
            if item.capability == "platform_ingestion"
        ]
        if self.build_authorization_ref and self.ingestion_required and len(
            platform_assignments
        ) != 1:
            raise ValueError(
                "an authorized build that requires ingestion must name exactly one "
                "platform_ingestion assignment"
            )
        return self


class PlannedSigmaRoutingBinding(BaseModel):
    """Declared route and source hashes; the coordinator resolves them in its trusted store."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    mode: Literal["warehouse_first_refactor", "omni_semantic_reconstruction"]
    decision_ref: str = Field(pattern=r"^artifact-ref://[^\s?#]+$")
    decision_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    scope_id: str = Field(min_length=3)
    comparison_scope_refs: list[str] = Field(min_length=1)
    build_scope_refs: list[str] = Field(min_length=1)
    target_environment_refs: list[str] = Field(min_length=1)
    source_artifact_hashes: dict[str, str] = Field(min_length=1)
    include_dependency_results: Literal[True] = True

    @model_validator(mode="after")
    def route_has_exact_source_and_target_bindings(self) -> "PlannedSigmaRoutingBinding":
        for references in (
            self.comparison_scope_refs, self.build_scope_refs, self.target_environment_refs
        ):
            if references != sorted(set(references)) or any(
                not urlsplit(ref).scheme or any(character.isspace() for character in ref)
                for ref in references
            ):
                raise ValueError("Sigma routing scopes must contain canonical unique references")
        if not set(self.build_scope_refs).issubset(self.comparison_scope_refs):
            raise ValueError("Sigma build scope must be within its comparison scope")
        for artifact_id, content_hash in self.source_artifact_hashes.items():
            if not artifact_id or any(character.isspace() for character in artifact_id):
                raise ValueError("Sigma source artifact IDs must be nonempty opaque IDs")
            if len(content_hash) != 64 or any(c not in "0123456789abcdef" for c in content_hash):
                raise ValueError("Sigma source artifact hashes must be exact SHA-256 hashes")
        omni_targets = [
            ref for ref in self.target_environment_refs if ref.startswith("environment-ref://omni/")
        ]
        data_targets = [
            ref for ref in self.target_environment_refs
            if ref.startswith(("environment-ref://dbt/", "environment-ref://snowflake/",
                               "environment-ref://warehouse/"))
        ]
        if len(omni_targets) != 1 or len(omni_targets) + len(data_targets) != len(
            self.target_environment_refs
        ):
            raise ValueError("Sigma route requires one Omni target and supported data-layer targets")
        if self.mode == "omni_semantic_reconstruction" and data_targets:
            raise ValueError("direct Sigma routing cannot include data-layer targets")
        if self.mode == "warehouse_first_refactor" and not data_targets:
            raise ValueError("warehouse-first Sigma routing requires a data-layer target")
        return self


class PlannedWorkPackage(BaseModel):
    model_config = ConfigDict(extra="forbid")

    contract_version: Literal["domo-to-omni.work-package.v1"] = "domo-to-omni.work-package.v1"
    tenant_ref: str
    work_package_id: str
    run_id: str
    migration_unit_id: str
    validation_cycle_id: str
    phase: WorkPhase
    assignee: PlannedAgentAssignee | PlannedExternalAssignee
    status: Literal["pending", "ready", "in_progress", "completed", "blocked", "superseded"] = "pending"
    objective: str
    tool_profile: str
    scope_purpose: ScopePurpose
    source_scope: list[PlannedSourceScope] = Field(min_length=1)
    sigma_routing: PlannedSigmaRoutingBinding | None = None
    depends_on: list[str] = Field(default_factory=list)
    gate_refs: list[str] = Field(default_factory=list)
    input_refs: list[str] = Field(default_factory=list)
    expected_artifacts: list[str] = Field(default_factory=list)
    authority: PlannedAuthority
    completion_criteria: list[str] = Field(min_length=1)
    validation_requirements: list[PlannedValidationRequirement] = Field(min_length=1)
    result: PlannedResult = Field(default_factory=PlannedResult)
    timestamps: PlannedTimestamps

    @model_serializer(mode="wrap")
    def preserve_legacy_serialization(self, handler):
        value = handler(self)
        if self.sigma_routing is None:
            value.pop("sigma_routing", None)
        return value

    @model_validator(mode="after")
    def target_work_requires_semantic_gates(self) -> "PlannedWorkPackage":
        sigma_sources = [item for item in self.source_scope if item.system == "sigma"]
        sigma_assignee = (
            isinstance(self.assignee, PlannedAgentAssignee)
            and self.assignee.agent_id.startswith("sigma_")
        )
        if sigma_sources or sigma_assignee or self.phase.startswith("sigma_"):
            if not sigma_sources or self.sigma_routing is None:
                raise ValueError("Sigma work requires explicit source scope and semantic routing bindings")
            binding = self.sigma_routing
            if self.phase.startswith("sigma_") and (
                self.authority.mode not in {"read_only", "proposal_only"}
                or self.authority.authorization_ref is not None
                or not sigma_assignee
                or not set(self.authority.allowed_tools).issubset(
                    SIGMA_PLANNING_TOOL_ALLOWLISTS.get(self.assignee.agent_id, ())
                )
            ):
                raise ValueError("Sigma planning packages cannot grant execution or approval authority")
            required_inputs = {
                binding.decision_ref,
                *(f"artifact-ref://{artifact_id}" for artifact_id in binding.source_artifact_hashes),
            }
            if not required_inputs.issubset(self.input_refs):
                raise ValueError("Sigma work must bind its decision and every source artifact input")
            if {item.object_id: item.fingerprint for item in sigma_sources} != (
                binding.source_artifact_hashes
            ):
                raise ValueError("Sigma source scope does not match its exact source artifact hashes")
            if binding.mode == "omni_semantic_reconstruction" and (
                self.phase in {"data_build", "sigma_dbt_planning"}
                or (isinstance(self.assignee, PlannedAgentAssignee)
                    and self.assignee.agent_id in {"dbt_analytics_engineer", "sigma_dbt_analytics_engineer"})
                or any(tool.startswith("dbt_") for tool in self.authority.allowed_tools)
            ):
                raise ValueError("direct Sigma routing cannot schedule dbt work")
        elif self.sigma_routing is not None:
            raise ValueError("Sigma routing bindings require Sigma source scope")
        if len(self.depends_on) != len(set(self.depends_on)):
            raise ValueError("work package dependencies must be unique")
        if len(self.gate_refs) != len(set(self.gate_refs)):
            raise ValueError("work package gate references must be unique")
        expected_result = {
            "pending": "not_started",
            "ready": "not_started",
            "in_progress": "not_started",
            "completed": "completed",
            "blocked": "blocked",
            "superseded": "not_started",
        }[self.status]
        if self.result.state != expected_result:
            raise ValueError(
                f"work package status/result mismatch: {self.status}/{self.result.state}"
            )
        write_modes = {
            "branch_write",
            "document_create_write",
            "document_draft_write",
        }
        if self.authority.mode in write_modes:
            if not self.authority.authorization_ref:
                raise ValueError("write work package requires an authorization reference")
            if not self.authority.intended_change_set_fingerprint:
                raise ValueError(
                    "write work package requires an intended change-set fingerprint"
                )
            if not self.authority.target_scope_refs:
                raise ValueError("write work package requires an exact target scope")
        elif (
            self.authority.intended_change_set_fingerprint
            or self.authority.target_scope_refs
        ):
            raise ValueError(
                "non-write work package cannot carry a target change set or target scope"
            )
        if len(self.authority.target_scope_refs) != len(
            set(self.authority.target_scope_refs)
        ):
            raise ValueError("work package target scope references must be unique")
        required_gate_refs = {
            gate_ref(gate_id)
            for gate_id in required_gate_ids_for_work_phase(
                self.phase,
                sigma_semantic_mode=self.sigma_routing.mode if self.sigma_routing else None,
            )
        }
        if required_gate_refs:
            missing = required_gate_refs - set(self.gate_refs)
            if missing:
                raise ValueError(
                    "work package lacks required lifecycle gates: "
                    f"{sorted(missing)}"
                )
        return self


def _work_id(
    run_id: str,
    unit_id: str,
    validation_cycle_id: str,
    phase: WorkPhase,
    assignee: str,
    package_key: str = "",
) -> str:
    digest = hashlib.sha256(
        f"{run_id}|{unit_id}|{validation_cycle_id}|{phase}|{assignee}|{package_key}".encode()
    ).hexdigest()[:20]
    return f"wp-{digest}"


def _forbidden_actions(mode: AuthorityMode | Literal["human_handoff"]) -> list[str]:
    common = [
        "approve_own_work",
        "expand_scope_or_authority",
        "cutover_or_decommission_source",
    ]
    if mode in {"read_only", "proposal_only"}:
        return [*common, "write_source_or_target_systems"]
    if mode == "human_handoff":
        return [*common, "act_without_separate_named_owner_authorization"]
    return [*common, "write_outside_authorized_development_scope", "promote_without_human_approval"]


def _package(
    context: MigrationPlanningContext,
    *,
    phase: WorkPhase,
    assignee: str,
    objective: str,
    depends_on: list[str] | None = None,
    gate_refs: list[str] | None = None,
    input_refs: list[str] | None = None,
    expected_artifacts: list[str],
    authority_mode: AuthorityMode,
    authorization_ref: str | None = None,
    intended_change_set_fingerprint: str | None = None,
    target_scope_refs: list[str] | None = None,
    scope_purpose: ScopePurpose = "migration",
    source_scope: list[PlannedSourceScope] | None = None,
    tool_profile: str | None = None,
    allowed_tools: list[str] | None = None,
    package_key: str | None = None,
) -> PlannedWorkPackage:
    work_package_id = _work_id(
        context.run_id,
        context.migration_unit_id,
        context.validation_cycle_id,
        phase,
        assignee,
        package_key or ",".join(sorted(expected_artifacts)),
    )
    resolved_input_refs = list(input_refs or [])
    if scope_purpose == "comparison":
        resolved_input_refs.extend(
            sorted(item.approval_ref for item in context.cross_scope_exceptions)
        )
    resolved_input_refs = list(dict.fromkeys(resolved_input_refs))
    return PlannedWorkPackage(
        tenant_ref=context.tenant_ref,
        work_package_id=work_package_id,
        run_id=context.run_id,
        migration_unit_id=context.migration_unit_id,
        validation_cycle_id=context.validation_cycle_id,
        phase=phase,
        assignee=PlannedAgentAssignee(agent_id=assignee),
        tool_profile=tool_profile or AGENT_DEFAULT_TOOL_PROFILES[assignee],
        scope_purpose=scope_purpose,
        source_scope=source_scope or context.source_scope,
        objective=objective,
        depends_on=depends_on or [],
        gate_refs=gate_refs or [],
        input_refs=resolved_input_refs,
        expected_artifacts=expected_artifacts,
        authority=PlannedAuthority(
            mode=authority_mode,
            authorization_ref=authorization_ref,
            intended_change_set_fingerprint=intended_change_set_fingerprint,
            target_scope_refs=target_scope_refs or [],
            allowed_tools=allowed_tools or AGENT_TOOL_ALLOWLISTS[assignee],
            forbidden_actions=_forbidden_actions(authority_mode),
        ),
        completion_criteria=[
            "Every expected artifact is registered with immutable provenance and lineage.",
            "No blocking issue or unresolved required decision is hidden by completion.",
            "Required validation evidence is attached to the current source and target revisions.",
        ],
        validation_requirements=[PlannedValidationRequirement(
            validation_id=f"validate-{work_package_id[3:]}",
            method="Validate schemas, lineage, authority, dependency gates, and acceptance evidence.",
            required_evidence=expected_artifacts,
        )],
        timestamps=PlannedTimestamps(
            created_at=context.created_at,
            updated_at=context.created_at,
        ),
    )


def _external_package(
    context: MigrationPlanningContext,
    *,
    handoff: ExternalRedesignHandoff,
    phase: WorkPhase,
    objective: str,
    depends_on: list[str],
    input_refs: list[str],
    expected_artifacts: list[str],
) -> PlannedWorkPackage:
    work_package_id = handoff.work_package_id
    return PlannedWorkPackage(
        tenant_ref=context.tenant_ref,
        work_package_id=work_package_id,
        run_id=context.run_id,
        migration_unit_id=context.migration_unit_id,
        validation_cycle_id=context.validation_cycle_id,
        phase=phase,
        assignee=PlannedExternalAssignee(
            capability=handoff.capability,
            owner_ref=handoff.owner_ref,
        ),
        tool_profile="human_handoff",
        scope_purpose="migration",
        source_scope=[
            PlannedSourceScope(
                system="domo",
                object_type=item.object_type,
                object_id=item.object_id,
                fingerprint=item.object_hash.removeprefix("sha256:"),
            )
            for item in handoff.source_objects
        ],
        objective=objective,
        depends_on=depends_on,
        gate_refs=[
            *TARGET_BUILD_GATE_REFS,
        ],
        input_refs=[*input_refs, handoff.handoff_ref],
        expected_artifacts=expected_artifacts,
        authority=PlannedAuthority(
            mode="human_handoff",
            authorization_ref=None,
            allowed_tools=[],
            forbidden_actions=_forbidden_actions("human_handoff"),
        ),
        completion_criteria=[
            "The named external owner returns the accepted deliverable and immutable evidence.",
            "No unresolved dependency, security decision, or blocking acceptance issue remains.",
            "The manager registers the handoff result against the current validation cycle.",
        ],
        validation_requirements=[
            PlannedValidationRequirement(
                validation_id=f"validate-{work_package_id[3:]}",
                method="Validate named ownership, scope, acceptance evidence, and current revision identity.",
                required_evidence=expected_artifacts,
            )
        ],
        timestamps=PlannedTimestamps(
            created_at=context.created_at,
            updated_at=context.created_at,
        ),
    )


def build_migration_work_graph(context: MigrationPlanningContext) -> list[PlannedWorkPackage]:
    """Build source-only packages or the full approved build graph.

    Without all architecture/build approval references, the function intentionally emits
    only inventory, source-interpretation, and architecture-proposal work. Target write
    packages cannot be created accidentally from a source-only intake.
    """

    comparison_scope = list(context.comparison_scope or context.source_scope)
    comparison_keys = {
        (item.system, item.object_type, item.object_id) for item in comparison_scope
    }
    exception_keys = {
        (
            item.source_object.system,
            item.source_object.object_type,
            item.source_object.object_id,
        )
        for item in context.cross_scope_exceptions
    }
    comparison_scope.extend(
        item
        for item in context.source_scope
        if (item.system, item.object_type, item.object_id) in exception_keys
        and (item.system, item.object_type, item.object_id) not in comparison_keys
    )
    inventory_control_refs = [
        context.coverage_ledger_ref,
        *context.domo_inventory_observation_refs,
        *[
            reference
            for reference in (
                context.domo_portfolio_inventory_ref,
                context.migration_scope_ref,
            )
            if reference
        ],
    ]
    intake = _package(
        context,
        phase="intake",
        assignee="inventory_intake",
        objective=(
            "Validate the source-only request, owners, authority, privacy boundary, and "
            "entry scope without requiring target credentials."
        ),
        input_refs=context.source_object_refs,
        expected_artifacts=["migration_intake"],
        authority_mode="read_only",
        scope_purpose="comparison",
        source_scope=comparison_scope,
    )
    acquisition = _package(
        context,
        phase="source_acquisition",
        assignee="data_acquisition_ingestion",
        objective=(
            "Run capability preflight, acquire approved Domo evidence, and construct the "
            "source object graph and coverage ledger."
        ),
        depends_on=[intake.work_package_id],
        input_refs=context.source_object_refs,
        expected_artifacts=[
            "capability_preflight",
            "source_object_graph",
            "domo_inventory_observation",
            "evidence_bundle",
            "coverage_ledger",
            "qa_fixture",
        ],
        authority_mode="read_only",
        scope_purpose="comparison",
        source_scope=comparison_scope,
    )
    dbt_repository = _package(
        context,
        phase="repository_inventory",
        assignee="dbt_analytics_engineer",
        objective=(
            "Inventory the pinned dbt repository, bind each repository subject to exact "
            "definition evidence, then build its attested semantic profile without "
            "executing project code or granting branch-write, compile, build, or test "
            "authority."
        ),
        depends_on=[intake.work_package_id],
        input_refs=[context.dbt_repository_ref or "repo-ref://not-configured"],
        expected_artifacts=[
            "repository_inventory",
            "repository_definition_evidence",
            "semantic_profile",
        ],
        authority_mode="read_only",
        scope_purpose="comparison",
        source_scope=comparison_scope,
        tool_profile="read_only_dbt_repository_inventory",
        allowed_tools=DBT_REPOSITORY_READ_ONLY_TOOLS,
    )
    inventory = _package(
        context,
        phase="inventory",
        assignee="inventory_intake",
        objective="Reconcile portfolio inventory and prove selected-scope dependency closure.",
        depends_on=[acquisition.work_package_id],
        input_refs=[
            context.source_object_graph_ref,
            context.coverage_ledger_ref,
            context.evidence_bundle_ref,
        ],
        expected_artifacts=[
            "inventory_snapshot",
            "domo_portfolio_inventory",
            "migration_scope",
        ],
        authority_mode="read_only",
        scope_purpose="comparison",
        source_scope=comparison_scope,
    )
    domo_bi = _package(
        context,
        phase="source_interpretation",
        assignee="domo_bi_developer",
        objective="Recover the accepted Page/Card query, interaction, and presentation contract.",
        depends_on=[inventory.work_package_id],
        input_refs=[
            context.source_object_graph_ref,
            context.coverage_ledger_ref,
            context.evidence_bundle_ref,
        ],
        expected_artifacts=[
            "experience_spec",
            "query_and_interaction_fixtures",
            "semantic_profile",
        ],
        authority_mode="read_only",
        scope_purpose="comparison",
        source_scope=comparison_scope,
    )
    domo_data = _package(
        context,
        phase="source_interpretation",
        assignee="domo_analytics_engineer",
        objective="Recover data lineage, transformation semantics, dialect risks, and target handoff.",
        depends_on=[inventory.work_package_id],
        input_refs=[
            context.source_object_graph_ref,
            context.coverage_ledger_ref,
            context.evidence_bundle_ref,
        ],
        expected_artifacts=[
            "transformation_spec",
            "dialect_risk_ledger",
            "dbt_handoff",
            "semantic_profile",
        ],
        authority_mode="read_only",
        scope_purpose="comparison",
        source_scope=comparison_scope,
    )
    target_semantic_design = _package(
        context,
        phase="target_semantic_design",
        assignee="domo_to_omni_architect",
        objective=(
            "Create a proposal-only target semantic profile from accepted source and "
            "repository profiles, including the no-existing-dbt-target path, without "
            "writing dbt or Omni."
        ),
        depends_on=[
            domo_bi.work_package_id,
            domo_data.work_package_id,
            dbt_repository.work_package_id,
        ],
        gate_refs=[
            context.dependency_closure_gate_ref,
        ],
        input_refs=[
            context.inventory_snapshot_ref,
            context.source_object_graph_ref,
            *inventory_control_refs,
            context.dbt_repository_ref or "repo-ref://not-configured",
            *context.semantic_profile_refs,
        ],
        expected_artifacts=["target_semantic_profile"],
        authority_mode="proposal_only",
        scope_purpose="comparison",
        source_scope=comparison_scope,
    )
    semantic_profile_coverage = _package(
        context,
        phase="semantic_profiling",
        assignee="domo_to_omni_architect",
        objective=(
            "Derive the immutable exact semantic-profile subject denominator from the "
            "current portfolio, scope, repository, source-profile, and target-proposal "
            "revisions; resolve every subject to one current profile or owned blocker."
        ),
        depends_on=[target_semantic_design.work_package_id],
        gate_refs=[context.dependency_closure_gate_ref],
        input_refs=[
            context.inventory_snapshot_ref,
            context.source_object_graph_ref,
            *inventory_control_refs,
            *[
                reference
                for reference in (
                    context.repository_inventory_ref,
                    *context.semantic_profile_refs,
                    *context.target_semantic_profile_refs,
                )
                if reference
            ],
        ],
        expected_artifacts=["semantic_profile_coverage"],
        authority_mode="proposal_only",
        scope_purpose="comparison",
        source_scope=comparison_scope,
        package_key="exact-semantic-profile-coverage",
    )
    semantic_consolidation = _package(
        context,
        phase="semantic_consolidation",
        assignee="semantic_consolidation",
        objective=(
            "Deterministically compare current Domo and repository semantic profiles, "
            "produce proposal-only equivalence assessments and consolidation candidates, "
            "and preserve every veto or unresolved consumer behavior for human decision."
        ),
        depends_on=[
            semantic_profile_coverage.work_package_id,
        ],
        gate_refs=[
            context.dependency_closure_gate_ref,
            SEMANTIC_PROFILE_GATE_REF,
            TARGET_SEMANTIC_PROFILE_GATE_REF,
        ],
        input_refs=[
            context.inventory_snapshot_ref,
            context.source_object_graph_ref,
            *inventory_control_refs,
            context.dbt_repository_ref or "repo-ref://not-configured",
            *[
                reference
                for reference in (
                    *context.semantic_profile_refs,
                    *context.target_semantic_profile_refs,
                    context.semantic_profile_coverage_ref,
                )
                if reference
            ],
        ],
        expected_artifacts=[
            "equivalence_assessment",
            "consolidation_candidate",
            "consolidation_decision",
        ],
        authority_mode="proposal_only",
        scope_purpose="comparison",
        source_scope=comparison_scope,
    )
    topic_design = _package(
        context,
        phase="topic_design",
        assignee="domo_to_omni_architect",
        objective=(
            "Design audience- and use-case-focused Omni Topic blueprints from current "
            "human-approved consolidation decisions without authorizing a target write."
        ),
        depends_on=[semantic_consolidation.work_package_id],
        gate_refs=[EQUIVALENCE_GATE_REF, CONSOLIDATION_GATE_REF],
        input_refs=[
            context.inventory_snapshot_ref,
            context.source_object_graph_ref,
            context.coverage_ledger_ref,
            *[
                reference
                for reference in (
                    *context.semantic_profile_refs,
                    context.semantic_profile_coverage_ref,
                    *context.equivalence_assessment_refs,
                    *context.consolidation_decision_refs,
                    *context.target_semantic_profile_refs,
                )
                if reference
            ],
        ],
        expected_artifacts=["topic_blueprint"],
        authority_mode="proposal_only",
        scope_purpose="comparison",
        source_scope=comparison_scope,
    )
    dashboard_planning = _package(
        context,
        phase="dashboard_planning",
        assignee="domo_to_omni_architect",
        objective=(
            "Account for every source Page, Card, query, and behavior exactly once in a "
            "proposal-only dashboard rebuild plan bound to current accepted Topics."
        ),
        depends_on=[topic_design.work_package_id],
        gate_refs=[
            context.dependency_closure_gate_ref,
            *PRE_BUILD_SEMANTIC_GATE_REFS,
        ],
        input_refs=[
            context.inventory_snapshot_ref,
            context.source_object_graph_ref,
            *inventory_control_refs,
            context.evidence_bundle_ref,
            *[
                reference
                for reference in (
                    *context.semantic_profile_refs,
                    context.semantic_profile_coverage_ref,
                    *context.equivalence_assessment_refs,
                    *context.consolidation_decision_refs,
                    *context.target_semantic_profile_refs,
                    *context.topic_blueprint_refs,
                )
                if reference
            ],
        ],
        expected_artifacts=["dashboard_rebuild_plan"],
        authority_mode="proposal_only",
        scope_purpose="comparison",
        source_scope=comparison_scope,
    )
    architecture = _package(
        context,
        phase="architecture",
        assignee="domo_to_omni_architect",
        objective=(
            "Reconcile source behavior and lineage into the end-to-end target architecture, "
            "acceptance plan, and typed specialist work graph."
        ),
        depends_on=[dashboard_planning.work_package_id],
        gate_refs=[
            context.dependency_closure_gate_ref,
            *PRE_BUILD_SEMANTIC_GATE_REFS,
            DASHBOARD_PLAN_GATE_REF,
        ],
        input_refs=[
            context.inventory_snapshot_ref,
            context.source_object_graph_ref,
            *inventory_control_refs,
            *[
                reference
                for reference in (
                    *context.semantic_profile_refs,
                    context.semantic_profile_coverage_ref,
                    *context.equivalence_assessment_refs,
                    *context.consolidation_decision_refs,
                    *context.target_semantic_profile_refs,
                    *context.topic_blueprint_refs,
                    context.dashboard_rebuild_plan_ref,
                )
                if reference
            ],
        ],
        expected_artifacts=[
            "target_architecture",
            "work_package_dag",
            "validation_matrix",
            "persona_policy",
            "tolerance_policy",
            *(
                ["external_redesign_assignment"]
                if context.external_handoffs
                else []
            ),
        ],
        authority_mode="proposal_only",
        scope_purpose="comparison",
        source_scope=comparison_scope,
        package_key="architecture",
    )
    if any(
        handoff.assignment_work_package_id != architecture.work_package_id
        for handoff in context.external_handoffs
    ):
        raise ValueError(
            "external handoff assignments must be produced by the exact architecture work package"
        )
    packages = [
        intake,
        acquisition,
        dbt_repository,
        inventory,
        domo_bi,
        domo_data,
        target_semantic_design,
        semantic_profile_coverage,
        semantic_consolidation,
        topic_design,
        dashboard_planning,
        architecture,
    ]

    if context.planning_mode == "production_revalidation":
        production_qa_inputs = [
            context.qa_acceptance_suite_ref,
            context.qa_suite_validation_ref,
            context.semantic_profile_coverage_ref,
            context.production_dashboard_rebuild_plan_ref,
            *context.production_topic_blueprint_refs,
            *context.production_semantic_profile_refs,
            *context.production_consolidation_decision_refs,
            *context.production_source_evidence_refs,
            *context.production_qa_fixture_refs,
            *context.production_target_artifact_refs,
            *context.production_target_operation_receipt_refs,
            *context.production_target_readback_refs,
            *context.production_qa_persona_policy_refs,
            *context.production_qa_tolerance_policy_refs,
        ]
        prod_qa = _package(
            context,
            phase="production_qa",
            assignee="migration_qa",
            objective=(
                "Independently revalidate the exact promoted production evidence set "
                "against its accepted non-production baseline."
            ),
            gate_refs=[gate_ref("dbt_readback"), gate_ref("omni_readback")],
            input_refs=[reference for reference in production_qa_inputs if reference],
            expected_artifacts=[
                "qa_result",
                "qa_acceptance_suite",
                "qa_suite_validation",
                "qa_target_operation_outcome",
                "production_validation_report",
                "independent_verdict",
            ],
            authority_mode="read_only",
            package_key="production-revalidation",
        )
        packages.append(prod_qa)

        production_outputs_ready = all(
            (
                context.production_qa_result_refs,
                context.production_qa_acceptance_suite_ref,
                context.production_qa_suite_validation_ref,
                context.production_validation_report_ref,
            )
        )
        if not production_outputs_ready:
            return validate_work_graph(packages)

        production_docs_inputs = [
            context.production_qa_suite_validation_ref,
            context.production_validation_report_ref,
            context.semantic_profile_coverage_ref,
            *context.production_qa_result_refs,
            context.production_dashboard_rebuild_plan_ref,
            *context.production_topic_blueprint_refs,
            *context.production_semantic_profile_refs,
            *context.production_consolidation_decision_refs,
            *context.production_source_evidence_refs,
            *context.production_qa_fixture_refs,
            *context.production_target_artifact_refs,
            *context.production_target_operation_receipt_refs,
            *context.production_target_readback_refs,
            *context.production_qa_persona_policy_refs,
            *context.production_qa_tolerance_policy_refs,
        ]
        packages.append(
            _package(
                context,
                phase="documentation",
                assignee="documentation_training",
                objective=(
                    "Create production-validated change, lineage, user, administrator, "
                    "and training guidance from the exact accepted production evidence set."
                ),
                depends_on=[prod_qa.work_package_id],
                gate_refs=[
                    gate_ref("qa_suite_accepted"),
                    gate_ref("production_validation"),
                ],
                input_refs=[
                    reference for reference in production_docs_inputs if reference
                ],
                expected_artifacts=[
                    "change_map",
                    "source_target_lineage",
                    "user_guide",
                    "admin_runbook",
                    "training_package",
                    "documentation_package",
                ],
                authority_mode="proposal_only",
                package_key="production",
            )
        )
        return validate_work_graph(packages)

    if not context.build_authorization_ref:
        return validate_work_graph(packages)

    architecture_inputs = [
        reference
        for reference in (
            *inventory_control_refs,
            *context.semantic_profile_refs,
            context.semantic_profile_coverage_ref,
            *context.equivalence_assessment_refs,
            *context.consolidation_decision_refs,
            *context.target_semantic_profile_refs,
            *context.topic_blueprint_refs,
            context.dashboard_rebuild_plan_ref,
            context.architecture_artifact_ref,
            context.architecture_approval_ref,
            context.build_authorization_ref,
            context.dbt_build_authorization_ref,
            context.omni_model_authorization_ref,
            context.omni_document_create_authorization_ref,
            context.omni_content_authorization_ref,
        )
        if reference
    ]
    build_gates = [*TARGET_BUILD_GATE_REFS]

    upstream_ids = [architecture.work_package_id]
    ingestion: PlannedWorkPackage | None = None
    if context.ingestion_required:
        ingestion = _package(
            context,
            phase="data_acquisition",
            assignee="data_acquisition_ingestion",
            objective="Implement or close the approved authoritative-source ingestion/backfill contract.",
            depends_on=[architecture.work_package_id],
            gate_refs=build_gates,
            input_refs=architecture_inputs,
            expected_artifacts=["ingestion_handoff", "ingestion_acceptance_evidence"],
            authority_mode="proposal_only",
            authorization_ref=None,
        )
        packages.append(ingestion)
        upstream_ids = [ingestion.work_package_id]

    external_packages: list[PlannedWorkPackage] = []
    for handoff in sorted(
        context.external_handoffs,
        key=lambda item: (item.capability, item.handoff_ref),
    ):
        if handoff.capability == "platform_ingestion":
            phase: WorkPhase = "data_acquisition"
            objective = (
                "Execute the approved authoritative-source ingestion and return load, backfill, "
                "freshness, observability, and reconciliation acceptance evidence."
            )
            dependencies = [
                ingestion.work_package_id if ingestion is not None else architecture.work_package_id
            ]
            expected = ["ingestion_acceptance_evidence"]
        elif handoff.capability == "application_redesign":
            phase = "content_build"
            objective = (
                "Implement and validate the owned replacement for Domo application, workflow, "
                "embed, form, scripting, or writeback behavior."
            )
            dependencies = [architecture.work_package_id]
            expected = ["application_redesign_handoff"]
        else:
            phase = "content_build"
            objective = (
                "Implement and validate the owned security, schedule, alert, publication, "
                "recipient, embed-access, or operational disposition."
            )
            dependencies = [architecture.work_package_id]
            expected = ["operations_governance_handoff"]
        external_package = _external_package(
            context,
            handoff=handoff,
            phase=phase,
            objective=objective,
            depends_on=dependencies,
            input_refs=architecture_inputs,
            expected_artifacts=expected,
        )
        external_packages.append(external_package)
        packages.append(external_package)

    platform_packages = [
        package
        for package in external_packages
        if package.assignee.kind == "external_team"
        and package.assignee.capability == "platform_ingestion"
    ]
    if platform_packages:
        upstream_ids = [platform_packages[0].work_package_id]

    if not context.dbt_build_authorization_ref:
        return validate_work_graph(packages)

    dbt = _package(
        context,
        phase="data_build",
        assignee="dbt_analytics_engineer",
        objective="Build accepted Snowflake-targeted dbt models, tests, contracts, and reconciliation evidence.",
        depends_on=upstream_ids,
        gate_refs=build_gates,
        input_refs=architecture_inputs,
        expected_artifacts=[
            "dbt_changes",
            "dbt_test_evidence",
            "data_reconciliation",
            "target_write_receipt",
        ],
        authority_mode="branch_write",
        authorization_ref=context.dbt_build_authorization_ref,
        intended_change_set_fingerprint=context.dbt_change_set_fingerprint,
        target_scope_refs=context.dbt_target_scope_refs,
    )
    packages.append(dbt)

    if not context.omni_model_authorization_ref:
        return validate_work_graph(packages)

    model = _package(
        context,
        phase="semantic_build",
        assignee="omni_modeler",
        objective="Build and validate governed Omni model artifacts on the approved branch.",
        depends_on=[dbt.work_package_id],
        gate_refs=build_gates,
        input_refs=architecture_inputs,
        expected_artifacts=[
            "omni_model_changes",
            "model_validation",
            "semantic_query_evidence",
            "target_write_receipt",
        ],
        authority_mode="branch_write",
        authorization_ref=context.omni_model_authorization_ref,
        intended_change_set_fingerprint=context.omni_model_change_set_fingerprint,
        target_scope_refs=context.omni_model_target_scope_refs,
    )
    packages.append(model)

    content_dependencies = [model.work_package_id, domo_bi.work_package_id]
    if context.omni_document_operation == "create_new":
        if not context.omni_document_create_authorization_ref:
            return validate_work_graph(packages)
        document_create = _package(
            context,
            phase="document_create",
            assignee="omni_bi_developer",
            objective=(
                "Create one new Omni document shell only in the authorized restricted "
                "quarantine or isolated non-production parent and verify its exact readback."
            ),
            depends_on=[model.work_package_id],
            gate_refs=build_gates,
            input_refs=architecture_inputs,
            expected_artifacts=[
                "omni_document_shell",
                "target_write_receipt",
                "document_readback",
            ],
            authority_mode="document_create_write",
            authorization_ref=context.omni_document_create_authorization_ref,
            intended_change_set_fingerprint=(
                context.omni_document_create_change_set_fingerprint
            ),
            target_scope_refs=context.omni_document_create_target_scope_refs,
            tool_profile="authorized_documents_v2_quarantine_create",
            allowed_tools=OMNI_DOCUMENT_CREATE_TOOLS,
        )
        packages.append(document_create)
        content_dependencies.append(document_create.work_package_id)
        if (
            not context.omni_document_ref
            or not context.omni_document_shell_ref
            or not context.omni_document_create_readback_ref
        ):
            return validate_work_graph(packages)

    if not context.omni_content_authorization_ref:
        return validate_work_graph(packages)

    content_inputs = list(architecture_inputs)
    if context.omni_document_operation == "create_new":
        content_inputs.extend(
            [
                context.omni_document_shell_ref,
                context.omni_document_create_readback_ref,
            ]
        )

    content = _package(
        context,
        phase="content_build",
        assignee="omni_bi_developer",
        objective="Build the accepted Omni dashboard experience in the authorized quarantine/draft scope.",
        depends_on=content_dependencies,
        gate_refs=build_gates,
        input_refs=[reference for reference in content_inputs if reference],
        expected_artifacts=[
            "omni_content_artifact",
            "target_write_receipt",
            "document_readback",
            "target_visual_fixtures",
        ],
        authority_mode="document_draft_write",
        authorization_ref=context.omni_content_authorization_ref,
        intended_change_set_fingerprint=context.omni_content_change_set_fingerprint,
        target_scope_refs=context.omni_content_target_scope_refs,
        tool_profile="authorized_documents_v2_draft_update",
        allowed_tools=OMNI_CONTENT_DRAFT_TOOLS,
    )
    packages.append(content)
    development_qa_inputs_ready = all(
        (
            context.qa_fixture_refs,
            context.target_artifact_refs,
            context.target_operation_receipt_refs,
            context.target_readback_refs,
            context.qa_persona_policy_refs,
            context.qa_tolerance_policy_refs,
        )
    )
    if not development_qa_inputs_ready:
        return validate_work_graph(packages)

    qa_inputs = [
        context.dashboard_rebuild_plan_ref,
        *context.topic_blueprint_refs,
        *context.semantic_profile_refs,
        context.semantic_profile_coverage_ref,
        *context.target_semantic_profile_refs,
        *context.equivalence_assessment_refs,
        *context.consolidation_decision_refs,
        *context.qa_fixture_refs,
        *context.target_artifact_refs,
        *context.target_operation_receipt_refs,
        *context.target_readback_refs,
        *context.qa_persona_policy_refs,
        *context.qa_tolerance_policy_refs,
    ]
    dev_qa = _package(
        context,
        phase="development_qa",
        assignee="migration_qa",
        objective="Independently validate development data, semantics, visuals, interactions, security, and operations.",
        depends_on=[
            dbt.work_package_id,
            model.work_package_id,
            content.work_package_id,
            *[
                package.work_package_id
                for package in external_packages
                if package.assignee.kind == "external_team"
                and package.assignee.capability != "platform_ingestion"
            ],
        ],
        input_refs=[reference for reference in qa_inputs if reference],
        expected_artifacts=[
            "qa_result",
            "qa_acceptance_suite",
            "qa_suite_validation",
            "validation_report",
            "defect_ledger",
            "independent_verdict",
        ],
        authority_mode="read_only",
    )
    packages.append(dev_qa)

    if not context.qa_acceptance_suite_ref or not context.qa_suite_validation_ref:
        return validate_work_graph(packages)

    packages.append(
        _package(
            context,
            phase="documentation",
            assignee="documentation_training",
            objective=(
                "Create the locally accepted change map, lineage, user guide, runbook, "
                "and training package without implying production readiness."
            ),
            depends_on=[dev_qa.work_package_id],
            gate_refs=[gate_ref("qa_suite_accepted")],
            input_refs=[
                context.qa_suite_validation_ref,
                context.semantic_profile_coverage_ref,
                *context.target_artifact_refs,
                *context.target_operation_receipt_refs,
                *context.target_readback_refs,
            ],
            expected_artifacts=[
                "change_map",
                "source_target_lineage",
                "user_guide",
                "admin_runbook",
                "training_package",
                "documentation_package",
            ],
            authority_mode="proposal_only",
            package_key="development",
        )
    )
    return validate_work_graph(packages)


def validate_work_graph(packages: list[PlannedWorkPackage]) -> list[PlannedWorkPackage]:
    """Reject duplicate IDs, dangling/self dependencies, or cycles."""

    packages = [
        PlannedWorkPackage.model_validate(package.model_dump(mode="json"))
        for package in packages
    ]
    sigma_bindings: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    for package in packages:
        if package.sigma_routing is None:
            continue
        context_key = (
            package.tenant_ref, package.run_id, package.migration_unit_id, package.validation_cycle_id
        )
        binding = package.sigma_routing.model_dump(mode="json")
        if context_key in sigma_bindings and sigma_bindings[context_key] != binding:
            raise ValueError("Sigma work graph contains conflicting routing or source bindings")
        sigma_bindings[context_key] = binding
    package_ids = [package.work_package_id for package in packages]
    if len(package_ids) != len(set(package_ids)):
        raise ValueError("work graph contains duplicate package IDs")
    known = set(package_ids)
    incoming: dict[str, int] = {package_id: 0 for package_id in package_ids}
    downstream: dict[str, list[str]] = defaultdict(list)
    for package in packages:
        if package.work_package_id in package.depends_on:
            raise ValueError(f"work package {package.work_package_id} depends on itself")
        missing = set(package.depends_on) - known
        if missing:
            raise ValueError(f"work package {package.work_package_id} has dangling dependencies: {sorted(missing)}")
        incoming[package.work_package_id] = len(package.depends_on)
        for dependency in package.depends_on:
            downstream[dependency].append(package.work_package_id)

    queue = deque(sorted(package_id for package_id, count in incoming.items() if count == 0))
    visited: list[str] = []
    while queue:
        package_id = queue.popleft()
        visited.append(package_id)
        for child in sorted(downstream[package_id]):
            incoming[child] -= 1
            if incoming[child] == 0:
                queue.append(child)
    if len(visited) != len(packages):
        raise ValueError("work graph contains a dependency cycle")
    return packages


def ready_work_package_ids(
    packages: list[PlannedWorkPackage],
    *,
    completed_ids: set[str],
    gate_resolver: GateRecordResolver | None = None,
) -> list[str]:
    """Return ready packages from validated records, never asserted gate booleans."""

    packages = validate_work_graph(packages)
    if gate_resolver is not None and type(gate_resolver) is not GateRecordResolver:
        raise TypeError("gate_resolver must be the canonical control-plane record resolver")
    known = {package.work_package_id for package in packages}
    unknown_completed = completed_ids - known
    if unknown_completed:
        raise ValueError(f"completed work package IDs are unknown: {sorted(unknown_completed)}")
    ready: list[str] = []
    for package in packages:
        if package.status not in {"pending", "ready"}:
            continue
        if package.work_package_id in completed_ids:
            continue
        if not set(package.depends_on) <= completed_ids:
            continue
        if package.gate_refs:
            if gate_resolver is None:
                continue
            if gate_resolver.unresolved_artifact_input_refs(package.input_refs):
                continue
            if not all(
                gate_resolver.is_gate_satisfied(
                    gate_ref_value=gate_ref,
                    tenant_ref=package.tenant_ref,
                    run_id=package.run_id,
                    validation_cycle_id=package.validation_cycle_id,
                    migration_unit_id=package.migration_unit_id,
                )
                for gate_ref in package.gate_refs
            ):
                continue
            bound_inputs = set(package.input_refs)
            if any(
                not gate_resolver.typed_evidence_refs_for_ref(
                    gate_ref_value,
                    migration_unit_id=package.migration_unit_id,
                ).issubset(bound_inputs)
                for gate_ref_value in package.gate_refs
                if gate_ref_value in INPUT_BOUND_GATE_REFS
            ):
                continue
            if any(
                gate_resolver.bound_artifact_coverage_violations_for_ref(
                    gate_ref_value,
                    bound_input_refs=package.input_refs,
                    migration_unit_id=package.migration_unit_id,
                )
                for gate_ref_value in package.gate_refs
            ):
                continue
        if gate_resolver is not None and gate_resolver.authorization_violations(
            authorization_ref=package.authority.authorization_ref,
            work_phase=package.phase,
            authority_mode=package.authority.mode,
            intended_change_set_fingerprint=(
                package.authority.intended_change_set_fingerprint
            ),
            target_scope_refs=package.authority.target_scope_refs,
        ):
            continue
        ready.append(package.work_package_id)
    return sorted(ready)

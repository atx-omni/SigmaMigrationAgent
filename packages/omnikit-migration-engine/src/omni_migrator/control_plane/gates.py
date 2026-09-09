"""Fail-closed resolution of control-plane gate records.

The resolver deliberately accepts records, not caller-supplied booleans.  It is shared
by orchestration readiness and persisted-manifest policy so both paths apply the same
cycle, actor, evidence-type, producer, run, tenant, and migration-unit checks.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from itertools import pairwise
from typing import Any
from urllib.parse import urlsplit

from omni_migrator.control_plane.canonical import canonical_json, parse_time, utc_now
from omni_migrator.control_plane.records import (
    ArtifactEnvelope,
    validate_artifact_identity_series,
)


SEMANTIC_PROFILE_GATE_ID = "semantic_profile_complete"
TARGET_SEMANTIC_PROFILE_GATE_ID = "target_semantic_profile_ready"
EQUIVALENCE_GATE_ID = "equivalence_assessed"
CONSOLIDATION_GATE_ID = "consolidation_approved"
GRAIN_FANOUT_GATE_ID = "grain_fanout_validated"
SECURITY_DISPOSITION_GATE_ID = "security_disposition_approved"
FRESHNESS_OWNERSHIP_GATE_ID = "freshness_ownership_accepted"
ARCHITECTURE_GATE_ID = "architecture"
BUILD_AUTHORIZATION_GATE_ID = "build_authorization"
DASHBOARD_PLAN_GATE_ID = "dashboard_plan_ready"
QA_SUITE_GATE_ID = "qa_suite_accepted"
DOCUMENTATION_GATE_ID = "documentation_training"
PRODUCTION_VALIDATION_GATE_ID = "production_validation"

PRE_BUILD_SEMANTIC_GATE_IDS = (
    SEMANTIC_PROFILE_GATE_ID,
    TARGET_SEMANTIC_PROFILE_GATE_ID,
    EQUIVALENCE_GATE_ID,
    CONSOLIDATION_GATE_ID,
    GRAIN_FANOUT_GATE_ID,
    SECURITY_DISPOSITION_GATE_ID,
    FRESHNESS_OWNERSHIP_GATE_ID,
)
TARGET_BUILD_GATE_IDS = (
    "source_completeness",
    *PRE_BUILD_SEMANTIC_GATE_IDS,
    DASHBOARD_PLAN_GATE_ID,
    ARCHITECTURE_GATE_ID,
    BUILD_AUTHORIZATION_GATE_ID,
)
EXACT_BOUND_GATE_IDS = frozenset(
    {
        "source_completeness",
        *PRE_BUILD_SEMANTIC_GATE_IDS,
        DASHBOARD_PLAN_GATE_ID,
        ARCHITECTURE_GATE_ID,
        BUILD_AUTHORIZATION_GATE_ID,
        DOCUMENTATION_GATE_ID,
        PRODUCTION_VALIDATION_GATE_ID,
    }
)

REQUIRED_GATE_IDS_BY_WORK_PHASE: dict[str, tuple[str, ...]] = {
    "target_semantic_design": (
        "source_completeness",
    ),
    "semantic_profiling": ("source_completeness",),
    "semantic_consolidation": (
        "source_completeness",
        SEMANTIC_PROFILE_GATE_ID,
        TARGET_SEMANTIC_PROFILE_GATE_ID,
    ),
    "topic_design": (
        EQUIVALENCE_GATE_ID,
        CONSOLIDATION_GATE_ID,
    ),
    "dashboard_planning": (
        "source_completeness",
        *PRE_BUILD_SEMANTIC_GATE_IDS,
    ),
    "architecture": (
        "source_completeness",
        *PRE_BUILD_SEMANTIC_GATE_IDS,
        DASHBOARD_PLAN_GATE_ID,
    ),
    "data_acquisition": TARGET_BUILD_GATE_IDS,
    "data_build": TARGET_BUILD_GATE_IDS,
    "semantic_build": TARGET_BUILD_GATE_IDS,
    "document_create": TARGET_BUILD_GATE_IDS,
    "content_build": TARGET_BUILD_GATE_IDS,
    "production_qa": ("dbt_readback", "omni_readback"),
    "documentation": (QA_SUITE_GATE_ID,),
}


def required_gate_ids_for_work_phase(
    phase: str, *, sigma_semantic_mode: str | None = None
) -> tuple[str, ...]:
    """Keep existing prerequisites except for explicitly bound direct Sigma QA."""

    if sigma_semantic_mode not in {
        None,
        "warehouse_first_refactor",
        "omni_semantic_reconstruction",
    }:
        raise ValueError("unknown Sigma semantic migration mode")
    required = REQUIRED_GATE_IDS_BY_WORK_PHASE.get(phase, ())
    if phase == "production_qa" and sigma_semantic_mode == "omni_semantic_reconstruction":
        return tuple(gate_id for gate_id in required if gate_id != "dbt_readback")
    return required


GATE_EVIDENCE_TYPES: dict[str, frozenset[str]] = {
    "source_completeness": frozenset(
        {
            "coverage_ledger",
            "domo_inventory_observation",
            "domo_portfolio_inventory",
            "migration_scope",
        }
    ),
    SEMANTIC_PROFILE_GATE_ID: frozenset({"semantic_profile_coverage"}),
    TARGET_SEMANTIC_PROFILE_GATE_ID: frozenset({"target_semantic_profile"}),
    EQUIVALENCE_GATE_ID: frozenset({"equivalence_assessment"}),
    CONSOLIDATION_GATE_ID: frozenset({"consolidation_decision"}),
    GRAIN_FANOUT_GATE_ID: frozenset({"topic_blueprint"}),
    SECURITY_DISPOSITION_GATE_ID: frozenset({"topic_blueprint"}),
    FRESHNESS_OWNERSHIP_GATE_ID: frozenset({"topic_blueprint"}),
    DASHBOARD_PLAN_GATE_ID: frozenset({"dashboard_rebuild_plan"}),
    ARCHITECTURE_GATE_ID: frozenset({"target_architecture"}),
    BUILD_AUTHORIZATION_GATE_ID: frozenset({"target_architecture"}),
    QA_SUITE_GATE_ID: frozenset({"qa_suite_validation"}),
    PRODUCTION_VALIDATION_GATE_ID: frozenset(
        {"qa_suite_validation", "production_validation_report"}
    ),
    DOCUMENTATION_GATE_ID: frozenset({"documentation_package"}),
    "dbt_readback": frozenset(
        {"dbt_changes", "dbt_test_evidence", "target_write_receipt", "target_readback"}
    ),
    "omni_readback": frozenset(
        {
            "omni_model_changes",
            "document_readback",
            "omni_content_artifact",
            "target_write_receipt",
            "target_readback",
        }
    ),
}

GATE_EVIDENCE_PRODUCERS: dict[str, frozenset[str]] = {
    "coverage_ledger": frozenset({"data_acquisition_ingestion"}),
    "domo_inventory_observation": frozenset({"data_acquisition_ingestion"}),
    "domo_portfolio_inventory": frozenset(
        {"inventory_intake", "domo_to_omni_architect"}
    ),
    "migration_scope": frozenset({"inventory_intake", "domo_to_omni_architect"}),
    "semantic_profile": frozenset(
        {
            "domo_bi_developer",
            "domo_analytics_engineer",
            "dbt_analytics_engineer",
            "omni_modeler",
        }
    ),
    "semantic_profile_coverage": frozenset({"domo_to_omni_architect"}),
    "target_semantic_profile": frozenset({"domo_to_omni_architect"}),
    "equivalence_assessment": frozenset({"semantic_consolidation"}),
    "consolidation_decision": frozenset(
        {"semantic_consolidation", "domo_to_omni_architect"}
    ),
    "topic_blueprint": frozenset({"domo_to_omni_architect"}),
    "dashboard_rebuild_plan": frozenset({"domo_to_omni_architect"}),
    "target_architecture": frozenset({"domo_to_omni_architect"}),
    "dbt_changes": frozenset({"dbt_analytics_engineer"}),
    "dbt_test_evidence": frozenset({"dbt_analytics_engineer"}),
    "omni_model_changes": frozenset({"omni_modeler"}),
    "document_readback": frozenset({"omni_bi_developer"}),
    "production_validation_report": frozenset(
        {"migration_qa"}
    ),
    "target_write_receipt": frozenset(
        {"dbt_analytics_engineer", "omni_modeler", "omni_bi_developer"}
    ),
    "target_readback": frozenset(
        {"dbt_analytics_engineer", "omni_modeler", "omni_bi_developer"}
    ),
    "qa_suite_validation": frozenset({"migration_qa"}),
    "documentation_package": frozenset({"documentation_training"}),
}

GATE_REQUIRED_EVIDENCE_PRODUCERS: dict[str, frozenset[str]] = {
    PRODUCTION_VALIDATION_GATE_ID: frozenset({"migration_qa"}),
}

GATE_REQUIRED_EVIDENCE_TYPES: dict[str, frozenset[str]] = {
    "source_completeness": frozenset(
        {
            "coverage_ledger",
            "domo_inventory_observation",
            "domo_portfolio_inventory",
            "migration_scope",
        }
    ),
    SEMANTIC_PROFILE_GATE_ID: frozenset({"semantic_profile_coverage"}),
    PRODUCTION_VALIDATION_GATE_ID: frozenset(
        {"qa_suite_validation", "production_validation_report"}
    ),
}

HUMAN_GATE_IDS = frozenset(
    {
        CONSOLIDATION_GATE_ID,
        SECURITY_DISPOSITION_GATE_ID,
        FRESHNESS_OWNERSHIP_GATE_ID,
        ARCHITECTURE_GATE_ID,
        BUILD_AUTHORIZATION_GATE_ID,
    }
)
INDEPENDENT_GATE_IDS = frozenset(
    {
        SEMANTIC_PROFILE_GATE_ID,
        TARGET_SEMANTIC_PROFILE_GATE_ID,
        EQUIVALENCE_GATE_ID,
        GRAIN_FANOUT_GATE_ID,
        DASHBOARD_PLAN_GATE_ID,
        QA_SUITE_GATE_ID,
        DOCUMENTATION_GATE_ID,
        "dbt_readback",
        "omni_readback",
        PRODUCTION_VALIDATION_GATE_ID,
    }
)

WRITE_ACTION_BY_WORK_PHASE = {
    "data_build": "create_dbt_branch_changes",
    "semantic_build": "create_omni_model_branch_changes",
    "document_create": "create_omni_document_in_quarantine",
    "content_build": "create_omni_content_draft",
}


def gate_ref(gate_id: str) -> str:
    """Return the canonical reference for a manifest gate identifier."""

    return f"gate-ref://{gate_id}"


def gate_id_from_ref(reference: str) -> str | None:
    """Return an exact gate identifier, rejecting paths, queries, and fragments."""

    parsed = urlsplit(reference)
    if (
        parsed.scheme.lower() != "gate-ref"
        or not parsed.netloc
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        return None
    return parsed.netloc


def _actor_identity(reference: str) -> tuple[str, str]:
    parsed = urlsplit(reference)
    identity = "/".join(
        part for part in (parsed.netloc, parsed.path.strip("/")) if part
    ).replace("-", "_")
    return parsed.scheme.lower(), identity


def _reference_identity(reference: str) -> str:
    parsed = urlsplit(reference)
    return "/".join(
        part for part in (parsed.netloc, parsed.path.strip("/")) if part
    )


def _is_human(reference: str) -> bool:
    return _actor_identity(reference)[0] in {"human-ref", "person-ref"}


def _is_independent_reviewer(reference: str) -> bool:
    scheme, identity = _actor_identity(reference)
    return _is_human(reference) or (
        scheme == "agent-ref" and identity == "migration_qa"
    )


@dataclass(frozen=True)
class GateRecordResolver:
    """Resolve readiness exclusively from canonical gates and artifact envelopes."""

    tenant_ref: str
    run_id: str
    validation_cycle_id: str
    gates: tuple[Mapping[str, Any], ...]
    artifacts: tuple[ArtifactEnvelope, ...]
    actor_kinds: Mapping[str, str]
    strict_actor_resolution: bool
    now: datetime
    authorizations: tuple[Mapping[str, Any], ...]
    approval_evidence_refs: frozenset[str]
    action_scope_refs: Mapping[str, frozenset[str]]
    authorization_artifact_fingerprint: str | None
    dashboard_evidence_snapshots: tuple[Mapping[str, Any], ...]
    dashboard_plan_validations: tuple[Mapping[str, Any], ...]
    qa_evidence_snapshots: tuple[Mapping[str, Any], ...]
    qa_suite_validations: tuple[Mapping[str, Any], ...]
    semantic_profile_coverages: tuple[Mapping[str, Any], ...]
    verified_event_ledger: Any | None

    @classmethod
    def from_control_plane_records(
        cls,
        *,
        tenant_ref: str,
        run_id: str,
        validation_cycle_id: str,
        gates: Sequence[Mapping[str, Any]],
        artifacts: Sequence[Mapping[str, Any] | ArtifactEnvelope],
        actor_kinds: Mapping[str, str] | None = None,
        strict_actor_resolution: bool = True,
        now: datetime | None = None,
        authorizations: Sequence[Mapping[str, Any]] = (),
        approval_evidence_refs: Sequence[str] = (),
        action_scope_refs: Mapping[str, Sequence[str]] | None = None,
        authorization_artifact_fingerprint: str | None = None,
        dashboard_evidence_snapshots: Sequence[Mapping[str, Any]] = (),
        dashboard_plan_validations: Sequence[Mapping[str, Any]] = (),
        qa_evidence_snapshots: Sequence[Mapping[str, Any]] = (),
        qa_suite_validations: Sequence[Mapping[str, Any]] = (),
        semantic_profile_coverages: Sequence[Mapping[str, Any]] = (),
        verified_event_ledger: Any | None = None,
    ) -> "GateRecordResolver":
        """Validate immutable artifact envelopes before constructing the resolver."""

        normalized: list[ArtifactEnvelope] = []
        for raw in artifacts:
            artifact = (
                raw
                if isinstance(raw, ArtifactEnvelope)
                else ArtifactEnvelope.from_mapping(raw)
            )
            artifact.validate(
                expected_tenant_ref=tenant_ref,
                expected_run_id=run_id,
            )
            normalized.append(artifact)
        validate_artifact_identity_series(normalized)
        current_clock = now or utc_now()
        if current_clock.tzinfo is None:
            raise ValueError("gate resolver clock must be timezone-aware")
        return cls(
            tenant_ref=tenant_ref,
            run_id=run_id,
            validation_cycle_id=validation_cycle_id,
            gates=tuple(dict(item) for item in gates),
            artifacts=tuple(normalized),
            actor_kinds=dict(actor_kinds or {}),
            strict_actor_resolution=strict_actor_resolution,
            now=current_clock,
            authorizations=tuple(dict(item) for item in authorizations),
            approval_evidence_refs=frozenset(approval_evidence_refs),
            action_scope_refs={
                action: frozenset(refs)
                for action, refs in (action_scope_refs or {}).items()
            },
            authorization_artifact_fingerprint=authorization_artifact_fingerprint,
            dashboard_evidence_snapshots=tuple(
                dict(item) for item in dashboard_evidence_snapshots
            ),
            dashboard_plan_validations=tuple(
                dict(item) for item in dashboard_plan_validations
            ),
            qa_evidence_snapshots=tuple(
                dict(item) for item in qa_evidence_snapshots
            ),
            qa_suite_validations=tuple(
                dict(item) for item in qa_suite_validations
            ),
            semantic_profile_coverages=tuple(
                dict(item) for item in semantic_profile_coverages
            ),
            verified_event_ledger=verified_event_ledger,
        )

    def _is_trusted_human(self, reference: str) -> bool:
        if self.actor_kinds.get(reference) == "human":
            return True
        return not self.strict_actor_resolution and _is_human(reference)

    def _is_trusted_independent_reviewer(self, reference: str) -> bool:
        kind = self.actor_kinds.get(reference)
        if kind in {"human", "independent_qa"}:
            return True
        return not self.strict_actor_resolution and _is_independent_reviewer(reference)

    def _newer_revision(self, artifact: ArtifactEnvelope) -> ArtifactEnvelope | None:
        """Return the latest superseding revision for a run-scoped artifact ID."""

        newer = [
            candidate
            for candidate in self.artifacts
            if candidate.artifact_id == artifact.artifact_id
            and candidate.revision > artifact.revision
        ]
        return max(newer, key=lambda candidate: candidate.revision, default=None)

    def violations_for_ref(
        self,
        reference: str,
        *,
        migration_unit_id: str | None,
        require_unit_match: bool,
    ) -> list[str]:
        """Return deterministic reasons a gate cannot authorize this unit."""

        gate_id = gate_id_from_ref(reference)
        if gate_id is None:
            return [f"gate reference is not canonical: {reference}"]
        return self.violations_for_gate_id(
            gate_id,
            migration_unit_id=migration_unit_id,
            require_unit_match=require_unit_match,
        )

    def _semantic_profile_coverage_violations(
        self,
        *,
        artifacts: Sequence[ArtifactEnvelope],
        migration_unit_id: str | None,
        gate_checked_at: datetime | None,
    ) -> list[str]:
        """Require one current, canonical, complete typed coverage registration."""

        from omni_migrator.semantic.coverage import (
            SemanticProfileCoverage,
            semantic_profile_coverage_content_sha256,
            validate_semantic_profile_coverage,
        )

        violations: list[str] = []
        from omni_migrator.control_plane.store import (
            VerifiedControlPlaneLedger,
            _registered_semantic_profile_coverages,
        )

        if type(self.verified_event_ledger) is not VerifiedControlPlaneLedger:
            return [
                "semantic-profile completeness requires the exact canonical-store ledger capability"
            ]
        if (
            self.verified_event_ledger.tenant_ref != self.tenant_ref
            or self.verified_event_ledger.run_id != self.run_id
        ):
            return ["semantic-profile coverage ledger crosses the requested partition"]
        trusted_event_payloads = [
            record.get("payload", {})
            for record in self.verified_event_ledger.records
            if record.get("record_type") == "event"
        ]
        trusted_artifact_payloads = [
            record.get("payload", {})
            for record in self.verified_event_ledger.records
            if record.get("record_type") == "artifact"
        ]
        registrations: list[tuple[ArtifactEnvelope, SemanticProfileCoverage]] = []
        for raw in self.semantic_profile_coverages:
            if raw not in trusted_event_payloads:
                violations.append(
                    "semantic-profile coverage registration is not in the canonical ledger"
                )
                continue
            if set(raw) != {"event_type", "artifact", "coverage"} or raw.get(
                "event_type"
            ) != "semantic_profile_coverage_registered":
                violations.append(
                    "semantic-profile coverage registration has an invalid shape"
                )
                continue
            try:
                envelope = ArtifactEnvelope.from_mapping(raw["artifact"])
                envelope.validate(
                    expected_tenant_ref=self.tenant_ref,
                    expected_run_id=self.run_id,
                )
                coverage = SemanticProfileCoverage.model_validate_json(
                    canonical_json(raw["coverage"])
                )
            except (KeyError, TypeError, ValueError):
                violations.append("semantic-profile coverage registration is malformed")
                continue
            if coverage.validation_cycle_id != self.validation_cycle_id or (
                migration_unit_id is not None
                and coverage.migration_unit_id != migration_unit_id
            ):
                continue
            try:
                current_coverages = _registered_semantic_profile_coverages(
                    list(self.verified_event_ledger.records),
                    tenant_ref=self.tenant_ref,
                    run_id=self.run_id,
                    scope_id=coverage.scope_id,
                    migration_unit_id=coverage.migration_unit_id,
                    validation_cycle_id=coverage.validation_cycle_id,
                )
            except (RuntimeError, TypeError, ValueError):
                violations.append(
                    "semantic-profile coverage no longer resolves against current "
                    "canonical upstream registrations"
                )
                continue
            if len(current_coverages) != 1 or current_coverages[0] != (
                envelope,
                coverage,
            ):
                violations.append(
                    "semantic-profile coverage is stale or is not the one current "
                    "canonical registration"
                )
                continue
            integrity_errors = validate_semantic_profile_coverage(
                coverage,
                validation_context=None,
            )
            if integrity_errors != (
                "trusted store-backed semantic-profile coverage context is required",
            ):
                violations.append(
                    "semantic-profile coverage registration is not canonically hashed"
                )
            if (
                envelope.artifact_type != "semantic_profile_coverage"
                or envelope.artifact_id != coverage.coverage_id
                or envelope.content_sha256
                != semantic_profile_coverage_content_sha256(coverage)
                or envelope.producer_ref != coverage.producer_ref
                or envelope.migration_unit_id != coverage.migration_unit_id
                or envelope.validation_cycle_id != coverage.validation_cycle_id
                or coverage.tenant_ref != self.tenant_ref
                or coverage.run_id != self.run_id
            ):
                violations.append(
                    "semantic-profile coverage registration is not exactly artifact-bound"
                )
            if coverage.status != "complete":
                violations.append("semantic-profile coverage is blocked")
            if gate_checked_at is not None and parse_time(coverage.assembled_at) > gate_checked_at:
                violations.append(
                    "semantic-profile coverage gate was checked before coverage assembly"
                )
            registrations.append((envelope, coverage))

        for artifact in artifacts:
            if not any(
                ArtifactEnvelope.from_mapping(item).to_mapping()
                == artifact.to_mapping()
                for item in trusted_artifact_payloads
            ):
                violations.append(
                    f"semantic-profile coverage artifact is not in the canonical ledger: {artifact.ref}"
                )
            matching = [
                item
                for item in registrations
                if item[0].to_mapping() == artifact.to_mapping()
            ]
            if len(matching) != 1:
                violations.append(
                    f"semantic-profile coverage {artifact.ref} requires exactly one "
                    "current trusted registration"
                )
        if len(artifacts) != 1:
            violations.append(
                "semantic-profile completeness requires exactly one current coverage manifest"
            )
        return violations

    def _source_completeness_violations(
        self,
        *,
        artifacts: Sequence[ArtifactEnvelope],
        migration_unit_id: str | None,
        gate_checked_at: datetime | None,
    ) -> list[str]:
        """Require the source gate to resolve from current canonical registrations.

        Artifact envelopes alone attest neither the Domo denominator nor its state.
        In particular, a caller can label a legacy inventory snapshot complete while
        the newer portfolio is partial, blocked, or absent.  Resolve the exact
        portfolio, observations, and migration scope from the store-issued ledger,
        then treat the portfolio catalog state as authoritative.
        """

        from omni_migrator.control_plane.store import (
            AppendOnlyConflict,
            VerifiedControlPlaneLedger,
            _artifact_envelope_is_exactly_current,
            _registered_domo_observations,
            _registered_domo_portfolio,
            _registered_migration_scopes,
        )

        if type(self.verified_event_ledger) is not VerifiedControlPlaneLedger:
            return [
                "source completeness requires the exact canonical-store ledger capability"
            ]
        if (
            self.verified_event_ledger.tenant_ref != self.tenant_ref
            or self.verified_event_ledger.run_id != self.run_id
        ):
            return ["source completeness ledger crosses the requested partition"]

        violations: list[str] = []
        records = list(self.verified_event_ledger.records)
        for artifact in artifacts:
            if not _artifact_envelope_is_exactly_current(records, artifact):
                violations.append(
                    "source completeness evidence is not the exact current canonical "
                    f"artifact: {artifact.ref}"
                )

        artifacts_by_type: dict[str, list[ArtifactEnvelope]] = {}
        for artifact in artifacts:
            artifacts_by_type.setdefault(artifact.artifact_type, []).append(artifact)
        for artifact_type in (
            "coverage_ledger",
            "domo_portfolio_inventory",
            "migration_scope",
        ):
            if len(artifacts_by_type.get(artifact_type, [])) != 1:
                violations.append(
                    "source completeness requires exactly one current "
                    f"{artifact_type} artifact"
                )
        observation_artifacts = artifacts_by_type.get(
            "domo_inventory_observation", []
        )
        if not observation_artifacts:
            violations.append(
                "source completeness requires current registered Domo observations"
            )
        portfolio_artifacts = artifacts_by_type.get("domo_portfolio_inventory", [])
        scope_artifacts = artifacts_by_type.get("migration_scope", [])
        coverage_artifacts = artifacts_by_type.get("coverage_ledger", [])
        if len(portfolio_artifacts) != 1:
            return violations

        portfolio_artifact = portfolio_artifacts[0]
        portfolio_registrations = [
            record.get("payload", {})
            for record in records
            if record.get("record_type") == "event"
            and record.get("payload", {}).get("event_type")
            == "domo_portfolio_inventory_registered"
            and record.get("payload", {}).get("artifact")
            == portfolio_artifact.to_mapping()
        ]
        if len(portfolio_registrations) != 1:
            violations.append(
                "source completeness requires exactly one current canonical Domo "
                "portfolio registration"
            )
            return violations
        raw_portfolio = portfolio_registrations[0].get("portfolio")
        if not isinstance(raw_portfolio, Mapping):
            violations.append("source completeness Domo portfolio registration is malformed")
            return violations
        scope_id = str(raw_portfolio.get("scope_id", ""))

        try:
            portfolio = _registered_domo_portfolio(
                records,
                tenant_ref=self.tenant_ref,
                run_id=self.run_id,
                scope_id=scope_id,
            )
            observations = _registered_domo_observations(
                records,
                tenant_ref=self.tenant_ref,
                run_id=self.run_id,
                scope_id=scope_id,
            )
        except (AppendOnlyConflict, TypeError, ValueError) as exc:
            violations.append(
                "source completeness canonical Domo inventory is invalid: " + str(exc)
            )
            return violations
        if portfolio is None or dict(raw_portfolio) != portfolio:
            violations.append(
                "source completeness evidence does not resolve to the current "
                "canonical Domo portfolio"
            )
            return violations
        portfolio_summary = portfolio.get("summary")
        if not isinstance(portfolio_summary, Mapping) or (
            portfolio_summary.get("catalog_state") != "complete"
        ):
            violations.append(
                "source completeness canonical Domo portfolio catalog is not complete"
            )

        registered_observation_artifacts = {
            str(record.get("payload", {}).get("artifact", {}).get("ref", ""))
            for record in records
            if record.get("record_type") == "event"
            and record.get("payload", {}).get("event_type")
            == "domo_inventory_observation_registered"
            and record.get("payload", {}).get("observation", {}).get("scope_id")
            == scope_id
        }
        gate_observation_artifacts = {
            artifact.ref for artifact in observation_artifacts
        }
        if (
            not observations
            or registered_observation_artifacts != gate_observation_artifacts
        ):
            violations.append(
                "source completeness gate does not bind the exact current canonical "
                "Domo observation set"
            )
        if len(coverage_artifacts) == 1 and (
            coverage_artifacts[0].ref != portfolio.get("coverage_ledger_ref")
        ):
            violations.append(
                "source completeness coverage ledger differs from the canonical "
                "Domo portfolio binding"
            )

        if len(scope_artifacts) == 1:
            effective_unit_id = migration_unit_id or scope_artifacts[0].migration_unit_id
            if not effective_unit_id:
                violations.append(
                    "source completeness cannot resolve a migration unit for its scope"
                )
            else:
                try:
                    scopes = _registered_migration_scopes(
                        records,
                        tenant_ref=self.tenant_ref,
                        run_id=self.run_id,
                        scope_id=scope_id,
                        migration_unit_id=effective_unit_id,
                        validation_cycle_id=self.validation_cycle_id,
                    )
                except (AppendOnlyConflict, TypeError, ValueError) as exc:
                    violations.append(
                        "source completeness canonical migration scope is invalid: "
                        + str(exc)
                    )
                else:
                    matching_scopes = [
                        scope
                        for envelope, scope in scopes
                        if envelope.to_mapping() == scope_artifacts[0].to_mapping()
                    ]
                    if len(matching_scopes) != 1:
                        violations.append(
                            "source completeness requires exactly one current canonical "
                            "migration-scope registration"
                        )
                    elif (
                        matching_scopes[0].get("inventory_snapshot_ref")
                        != portfolio.get("inventory_snapshot_ref")
                    ):
                        violations.append(
                            "source completeness migration scope and Domo portfolio bind "
                            "different inventory snapshots"
                        )

        if gate_checked_at is not None:
            try:
                if parse_time(str(portfolio.get("as_of", ""))) > gate_checked_at:
                    violations.append(
                        "source completeness gate was checked before portfolio assembly"
                    )
                if any(
                    parse_time(str(observation.get("observed_at", "")))
                    > gate_checked_at
                    for observation in observations
                ):
                    violations.append(
                        "source completeness gate was checked before observation capture"
                    )
            except (TypeError, ValueError):
                violations.append(
                    "source completeness canonical inventory timestamps are invalid"
                )
        return violations

    def _dashboard_validation_violations(
        self,
        *,
        artifacts: Sequence[ArtifactEnvelope],
        migration_unit_id: str | None,
        gate_checker_ref: str,
        gate_checked_at: datetime | None,
    ) -> list[str]:
        from omni_migrator.dashboards.rebuild_plan import (
            DashboardEvidenceSnapshot,
            DashboardPlanValidationRegistration,
            dashboard_evidence_snapshot_hash,
            dashboard_plan_validation_registration_hash,
            finalize_dashboard_evidence_snapshot,
        )
        from omni_migrator.control_plane.store import (
            AppendOnlyConflict,
            VerifiedControlPlaneLedger,
            _assert_dashboard_snapshot_current_registrations,
        )

        violations: list[str] = []
        if type(self.verified_event_ledger) is not VerifiedControlPlaneLedger:
            return [
                "dashboard plan readiness requires the exact canonical-store ledger capability"
            ]
        if (
            self.verified_event_ledger.tenant_ref != self.tenant_ref
            or self.verified_event_ledger.run_id != self.run_id
        ):
            return ["dashboard plan readiness ledger crosses the requested partition"]
        trusted_records = list(self.verified_event_ledger.records)
        trusted_events = [
            record.get("payload", {})
            for record in trusted_records
            if record.get("record_type") == "event"
        ]
        snapshots: list[DashboardEvidenceSnapshot] = []
        for raw in self.dashboard_evidence_snapshots:
            if raw not in trusted_events:
                violations.append(
                    "dashboard evidence snapshot is not in the canonical ledger"
                )
                continue
            value = {key: item for key, item in raw.items() if key != "event_type"}
            try:
                snapshot = finalize_dashboard_evidence_snapshot(value)
            except (TypeError, ValueError):
                violations.append("dashboard evidence snapshot registration is malformed")
                continue
            if (
                snapshot.tenant_ref == self.tenant_ref
                and snapshot.run_id == self.run_id
                and snapshot.validation_cycle_id == self.validation_cycle_id
            ):
                if (
                    value.get("snapshot_hash") != snapshot.snapshot_hash
                    or snapshot.snapshot_hash
                    != dashboard_evidence_snapshot_hash(snapshot)
                ):
                    violations.append("dashboard evidence snapshot hash is not canonical")
                try:
                    _assert_dashboard_snapshot_current_registrations(
                        trusted_records, snapshot
                    )
                except (AppendOnlyConflict, TypeError, ValueError):
                    violations.append(
                        "dashboard evidence snapshot prerequisites are missing or stale"
                    )
                snapshots.append(snapshot)

        validations: list[DashboardPlanValidationRegistration] = []
        for raw in self.dashboard_plan_validations:
            if raw not in trusted_events:
                violations.append(
                    "dashboard plan validation is not in the canonical ledger"
                )
                continue
            value = {key: item for key, item in raw.items() if key != "event_type"}
            try:
                registration = DashboardPlanValidationRegistration.model_validate(value)
            except (TypeError, ValueError):
                violations.append("dashboard plan validation registration is malformed")
                continue
            if (
                registration.tenant_ref == self.tenant_ref
                and registration.run_id == self.run_id
                and registration.validation_cycle_id == self.validation_cycle_id
            ):
                if (
                    registration.registration_hash
                    != dashboard_plan_validation_registration_hash(registration)
                ):
                    violations.append(
                        "dashboard plan validation registration hash is not canonical"
                    )
                validations.append(registration)

        for artifact in artifacts:
            matching = [
                item
                for item in validations
                if item.plan_artifact_ref == artifact.ref
                and item.plan_artifact_content_sha256 == artifact.content_sha256
                and item.migration_unit_id == artifact.migration_unit_id
            ]
            if len(matching) != 1:
                violations.append(
                    f"dashboard plan {artifact.ref} requires exactly one current "
                    "trusted validation registration"
                )
                continue
            registration = matching[0]
            if migration_unit_id is not None and (
                registration.migration_unit_id != migration_unit_id
            ):
                violations.append(
                    f"dashboard plan validation crosses migration unit: {artifact.ref}"
                )
            if not self._is_trusted_independent_reviewer(
                registration.checked_by_ref
            ):
                violations.append(
                    f"dashboard plan validation lacks independent review: {artifact.ref}"
                )
            if registration.checked_by_ref != gate_checker_ref:
                violations.append(
                    f"dashboard plan validation checker differs from gate checker: "
                    f"{artifact.ref}"
                )
            try:
                validation_time = parse_time(registration.checked_at)
            except (TypeError, ValueError):
                validation_time = None
                violations.append(
                    f"dashboard plan validation time is invalid: {artifact.ref}"
                )
            matching_snapshots = [
                item
                for item in snapshots
                if item.scope_id == registration.scope_id
                and item.wave_id == registration.wave_id
                and item.migration_unit_id == registration.migration_unit_id
            ]
            if not matching_snapshots:
                violations.append(
                    f"dashboard plan validation lacks its evidence snapshot: {artifact.ref}"
                )
                continue
            snapshot_ids = {item.snapshot_id for item in matching_snapshots}
            ordered_snapshots = sorted(
                matching_snapshots, key=lambda item: item.revision
            )
            latest = ordered_snapshots[-1]
            revisions = [item.revision for item in ordered_snapshots]
            if len(snapshot_ids) != 1 or revisions != list(range(1, len(revisions) + 1)):
                violations.append(
                    f"dashboard plan evidence snapshot chain is ambiguous: {artifact.ref}"
                )
            if any(
                current.supersedes_snapshot_hash != prior.snapshot_hash
                for prior, current in pairwise(ordered_snapshots)
            ):
                violations.append(
                    f"dashboard plan evidence snapshot chain is broken: {artifact.ref}"
                )
            if (
                registration.evidence_snapshot_ref != latest.snapshot_ref
                or registration.evidence_snapshot_hash != latest.snapshot_hash
                or registration.evidence_snapshot_revision != latest.revision
            ):
                violations.append(
                    f"dashboard plan validation uses stale evidence: {artifact.ref}"
                )
            matching_plan_registrations = [
                item
                for item in latest.plan_registrations
                if item.plan_id == registration.plan_id
                and item.plan_hash == registration.plan_hash
                and item.migration_unit_id == registration.migration_unit_id
                and item.page_id == registration.page_id
                and item.validation_cycle_id == registration.validation_cycle_id
            ]
            if len(matching_plan_registrations) != 1:
                violations.append(
                    "dashboard plan validation does not match its current snapshot "
                    f"registration: {artifact.ref}"
                )
            if validation_time is not None and (
                validation_time < parse_time(artifact.created_at)
                or validation_time < parse_time(latest.registered_at)
                or validation_time > self.now.astimezone(timezone.utc)
                or (
                    gate_checked_at is not None
                    and validation_time > gate_checked_at
                )
            ):
                violations.append(
                    f"dashboard plan validation chronology is invalid: {artifact.ref}"
                )
        return violations

    def _qa_suite_validation_violations(
        self,
        *,
        artifacts: Sequence[ArtifactEnvelope],
        migration_unit_id: str | None,
        gate_checker_ref: str,
        gate_checked_at: datetime | None,
    ) -> list[str]:
        """Require a current store-emitted QA attestation for the readiness gate."""

        from omni_migrator.qa.acceptance import (
            QAEvidenceSnapshot,
            QASuiteValidationRegistration,
            finalize_qa_evidence_snapshot,
            qa_evidence_snapshot_hash,
            qa_suite_validation_content_sha256,
            qa_suite_validation_registration_hash,
        )

        violations: list[str] = []
        snapshots: list[QAEvidenceSnapshot] = []
        for raw in self.qa_evidence_snapshots:
            value = {key: item for key, item in raw.items() if key != "event_type"}
            try:
                snapshot = finalize_qa_evidence_snapshot(value)
            except (TypeError, ValueError):
                violations.append("QA evidence snapshot registration is malformed")
                continue
            if (
                snapshot.tenant_ref == self.tenant_ref
                and snapshot.run_id == self.run_id
                and snapshot.validation_cycle_id == self.validation_cycle_id
                and (
                    migration_unit_id is None
                    or snapshot.migration_unit_id == migration_unit_id
                )
            ):
                if (
                    value.get("snapshot_hash") != snapshot.snapshot_hash
                    or snapshot.snapshot_hash != qa_evidence_snapshot_hash(snapshot)
                ):
                    violations.append("QA evidence snapshot hash is not canonical")
                snapshots.append(snapshot)

        registrations: list[QASuiteValidationRegistration] = []
        for raw in self.qa_suite_validations:
            value = {key: item for key, item in raw.items() if key != "event_type"}
            try:
                registration = QASuiteValidationRegistration.model_validate(value)
            except (TypeError, ValueError):
                violations.append("QA suite validation registration is malformed")
                continue
            if (
                registration.tenant_ref == self.tenant_ref
                and registration.run_id == self.run_id
                and registration.validation_cycle_id == self.validation_cycle_id
                and (
                    migration_unit_id is None
                    or registration.migration_unit_id == migration_unit_id
                )
            ):
                if (
                    registration.registration_hash
                    != qa_suite_validation_registration_hash(registration)
                ):
                    violations.append(
                        "QA suite validation registration hash is not canonical"
                    )
                registrations.append(registration)

        artifact_by_ref = {artifact.ref: artifact for artifact in self.artifacts}
        latest_by_id = {
            artifact.artifact_id: max(
                (
                    item
                    for item in self.artifacts
                    if item.artifact_id == artifact.artifact_id
                ),
                key=lambda item: item.revision,
            )
            for artifact in self.artifacts
        }
        for evidence_artifact in artifacts:
            matching = [
                item
                for item in registrations
                if item.migration_unit_id == evidence_artifact.migration_unit_id
                and item.validation_cycle_id == evidence_artifact.validation_cycle_id
                and qa_suite_validation_content_sha256(item)
                == evidence_artifact.content_sha256
            ]
            if len(matching) != 1:
                violations.append(
                    f"QA validation {evidence_artifact.ref} requires exactly one "
                    "current store-emitted registration"
                )
                continue
            registration = matching[0]
            if registration.checked_by_ref != gate_checker_ref:
                violations.append(
                    "QA validation checker differs from gate checker: "
                    f"{evidence_artifact.ref}"
                )
            if not self._is_trusted_independent_reviewer(
                registration.checked_by_ref
            ):
                violations.append(
                    f"QA validation lacks independent review: {evidence_artifact.ref}"
                )
            matching_snapshots = [
                item
                for item in snapshots
                if item.scope_id == registration.scope_id
                and item.wave_id == registration.wave_id
                and item.migration_unit_id == registration.migration_unit_id
            ]
            if not matching_snapshots:
                violations.append(
                    f"QA validation lacks its evidence snapshot: {evidence_artifact.ref}"
                )
                continue
            snapshot_ids = {item.snapshot_id for item in matching_snapshots}
            ordered = sorted(matching_snapshots, key=lambda item: item.revision)
            revisions = [item.revision for item in ordered]
            if len(snapshot_ids) != 1 or revisions != list(
                range(1, len(revisions) + 1)
            ):
                violations.append(
                    f"QA evidence snapshot chain is ambiguous: {evidence_artifact.ref}"
                )
            if any(
                current.supersedes_snapshot_hash != prior.snapshot_hash
                for prior, current in pairwise(ordered)
            ):
                violations.append(
                    f"QA evidence snapshot chain is broken: {evidence_artifact.ref}"
                )
            latest_snapshot = ordered[-1]
            if (
                registration.evidence_snapshot_ref != latest_snapshot.snapshot_ref
                or registration.evidence_snapshot_hash != latest_snapshot.snapshot_hash
                or registration.evidence_snapshot_revision
                != latest_snapshot.revision
            ):
                violations.append(
                    f"QA validation uses stale evidence: {evidence_artifact.ref}"
                )

            suite_artifact = artifact_by_ref.get(registration.suite_artifact_ref)
            if (
                suite_artifact is None
                or suite_artifact.artifact_type != "qa_acceptance_suite"
                or suite_artifact.content_sha256
                != registration.suite_artifact_content_sha256
                or suite_artifact.migration_unit_id
                != registration.migration_unit_id
                or suite_artifact.validation_cycle_id
                != registration.validation_cycle_id
                or latest_by_id.get(suite_artifact.artifact_id) != suite_artifact
            ):
                violations.append(
                    f"QA validation does not bind the current suite artifact: "
                    f"{evidence_artifact.ref}"
                )
            for binding in latest_snapshot.bindings.all_artifacts():
                bound = artifact_by_ref.get(binding.artifact_ref)
                if (
                    bound is None
                    or bound.artifact_id != binding.artifact_id
                    or bound.artifact_type != binding.artifact_type
                    or bound.revision != binding.revision
                    or bound.content_sha256 != binding.content_sha256
                    or bound.producer_ref != binding.producer_ref
                    or bound.migration_unit_id != binding.migration_unit_id
                    or bound.validation_cycle_id != binding.validation_cycle_id
                    or latest_by_id.get(bound.artifact_id) != bound
                ):
                    violations.append(
                        "QA validation contains a stale bound artifact: "
                        f"{binding.artifact_ref}"
                    )
            try:
                validation_time = parse_time(registration.checked_at)
            except (TypeError, ValueError):
                validation_time = None
                violations.append(
                    f"QA validation time is invalid: {evidence_artifact.ref}"
                )
            if validation_time is not None and (
                validation_time < parse_time(latest_snapshot.registered_at)
                or (
                    suite_artifact is not None
                    and validation_time < parse_time(suite_artifact.created_at)
                )
                or validation_time > self.now.astimezone(timezone.utc)
                or (
                    gate_checked_at is not None
                    and validation_time > gate_checked_at
                )
            ):
                violations.append(
                    f"QA validation chronology is invalid: {evidence_artifact.ref}"
                )
        return violations

    def violations_for_gate_id(
        self,
        gate_id: str,
        *,
        migration_unit_id: str | None,
        require_unit_match: bool,
    ) -> list[str]:
        """Return deterministic gate-record, actor, and evidence violations."""

        violations: list[str] = []
        matching = [item for item in self.gates if str(item.get("gate_id")) == gate_id]
        if len(matching) != 1:
            return [f"gate {gate_id} must have exactly one current record"]
        gate = matching[0]
        if gate.get("state") != "passed":
            violations.append(f"gate {gate_id} is not passed")
        if str(gate.get("validation_cycle_id", "")) != self.validation_cycle_id:
            violations.append(f"gate {gate_id} belongs to a stale validation cycle")
        checked_by = str(gate.get("checked_by_ref", ""))
        if not checked_by:
            violations.append(f"gate {gate_id} has no checker")
        elif gate_id in HUMAN_GATE_IDS and not self._is_trusted_human(checked_by):
            violations.append(f"gate {gate_id} requires a trusted human approver")
        elif gate_id in INDEPENDENT_GATE_IDS and not self._is_trusted_independent_reviewer(
            checked_by
        ):
            violations.append(f"gate {gate_id} requires independent QA or human review")
        try:
            checked_at = parse_time(str(gate.get("checked_at", "")))
        except (TypeError, ValueError):
            checked_at = None
            violations.append(f"gate {gate_id} has an invalid checked_at timestamp")
        if checked_at is not None and checked_at > self.now.astimezone(timezone.utc):
            violations.append(f"gate {gate_id} has a future checked_at timestamp")

        required_refs = [
            str(value) for value in gate.get("required_evidence_refs", []) if value
        ]
        if not required_refs:
            violations.append(f"gate {gate_id} has no evidence")
            return violations
        if duplicates := sorted(
            reference
            for reference, count in Counter(required_refs).items()
            if count > 1
        ):
            violations.append(f"gate {gate_id} repeats evidence references: {duplicates}")

        artifact_by_ref = {artifact.ref: artifact for artifact in self.artifacts}
        missing = sorted(set(required_refs) - set(artifact_by_ref))
        if missing:
            violations.append(
                f"gate {gate_id} lacks registered typed artifact evidence: {missing}"
            )
        evidence = [
            artifact_by_ref[reference]
            for reference in required_refs
            if reference in artifact_by_ref
        ]
        current = [
            artifact
            for artifact in evidence
            if artifact.validation_cycle_id == self.validation_cycle_id
        ]
        if len(current) != len(evidence):
            violations.append(f"gate {gate_id} uses stale artifact evidence")
        if require_unit_match:
            unit_evidence = [
                artifact
                for artifact in current
                if artifact.migration_unit_id == migration_unit_id
            ]
            if not unit_evidence:
                violations.append(
                    f"gate {gate_id} has no evidence for migration unit {migration_unit_id}"
                )
        else:
            unit_evidence = current

        expected_types = GATE_EVIDENCE_TYPES.get(gate_id)
        typed_evidence = [
            artifact
            for artifact in unit_evidence
            if expected_types is None or artifact.artifact_type in expected_types
        ]
        if expected_types is not None and not typed_evidence:
            violations.append(
                f"gate {gate_id} lacks required artifact type: {sorted(expected_types)}"
            )
        actual_types = {artifact.artifact_type for artifact in typed_evidence}
        required_types = GATE_REQUIRED_EVIDENCE_TYPES.get(gate_id, frozenset())
        if missing_types := sorted(required_types - actual_types):
            violations.append(
                f"gate {gate_id} lacks required evidence types: {missing_types}"
            )
        if gate_id == "source_completeness":
            expected_current_refs = {
                artifact.ref
                for artifact in self.artifacts
                if artifact.artifact_type in required_types
                and artifact.validation_cycle_id == self.validation_cycle_id
                and (
                    not require_unit_match
                    or artifact.migration_unit_id == migration_unit_id
                )
                and self._newer_revision(artifact) is None
            }
            actual_current_refs = {artifact.ref for artifact in typed_evidence}
            if actual_current_refs != expected_current_refs:
                violations.append(
                    "gate source_completeness does not bind the exact current "
                    "coverage, observation, portfolio, and migration-scope evidence set"
                )
        superseded = [
            (artifact, newer)
            for artifact in typed_evidence
            if (newer := self._newer_revision(artifact)) is not None
        ]
        if superseded:
            violations.append(
                f"gate {gate_id} uses superseded artifact revisions: "
                + ", ".join(
                    f"{artifact.ref} (revision {artifact.revision}; "
                    f"latest revision {newer.revision})"
                    for artifact, newer in sorted(
                        superseded,
                        key=lambda item: (
                            item[0].artifact_id,
                            item[0].artifact_type,
                            item[0].migration_unit_id or "",
                            item[0].revision,
                        ),
                    )
                )
            )
        if checked_at is not None and any(
            parse_time(artifact.created_at) > checked_at for artifact in typed_evidence
        ):
            violations.append(f"gate {gate_id} was checked before its typed evidence existed")
        for artifact in typed_evidence:
            allowed_producers = GATE_EVIDENCE_PRODUCERS.get(artifact.artifact_type)
            if allowed_producers is None:
                continue
            _scheme, producer = _actor_identity(artifact.producer_ref)
            if producer not in allowed_producers:
                violations.append(
                    f"gate {gate_id} evidence {artifact.ref} has an unauthorized producer"
                )
        required_producers = GATE_REQUIRED_EVIDENCE_PRODUCERS.get(gate_id, frozenset())
        actual_producers = {
            _actor_identity(artifact.producer_ref)[1] for artifact in typed_evidence
        }
        if missing_producers := sorted(required_producers - actual_producers):
            violations.append(
                f"gate {gate_id} lacks required producer evidence: {missing_producers}"
            )
        if gate_id == "source_completeness" and typed_evidence:
            violations.extend(
                self._source_completeness_violations(
                    artifacts=typed_evidence,
                    migration_unit_id=migration_unit_id,
                    gate_checked_at=checked_at,
                )
            )
        if gate_id == SEMANTIC_PROFILE_GATE_ID and typed_evidence:
            violations.extend(
                self._semantic_profile_coverage_violations(
                    artifacts=typed_evidence,
                    migration_unit_id=migration_unit_id,
                    gate_checked_at=checked_at,
                )
            )
        if gate_id == DASHBOARD_PLAN_GATE_ID and typed_evidence:
            violations.extend(
                self._dashboard_validation_violations(
                    artifacts=typed_evidence,
                    migration_unit_id=migration_unit_id,
                    gate_checker_ref=checked_by,
                    gate_checked_at=checked_at,
                )
            )
        if gate_id == QA_SUITE_GATE_ID and typed_evidence:
            violations.extend(
                self._qa_suite_validation_violations(
                    artifacts=typed_evidence,
                    migration_unit_id=migration_unit_id,
                    gate_checker_ref=checked_by,
                    gate_checked_at=checked_at,
                )
            )
        return violations

    def is_gate_satisfied(
        self,
        *,
        gate_ref_value: str,
        tenant_ref: str,
        run_id: str,
        validation_cycle_id: str,
        migration_unit_id: str,
    ) -> bool:
        """Return true only for current typed evidence in the requested partition."""

        if (
            tenant_ref != self.tenant_ref
            or run_id != self.run_id
            or validation_cycle_id != self.validation_cycle_id
        ):
            return False
        return not self.violations_for_ref(
            gate_ref_value,
            migration_unit_id=migration_unit_id,
            require_unit_match=True,
        )

    def typed_evidence_refs_for_ref(
        self,
        reference: str,
        *,
        migration_unit_id: str,
    ) -> frozenset[str]:
        """Return current, unit-scoped evidence refs of the gate's required types."""

        gate_id = gate_id_from_ref(reference)
        if gate_id is None:
            return frozenset()
        matching = [item for item in self.gates if str(item.get("gate_id")) == gate_id]
        if len(matching) != 1:
            return frozenset()
        required_refs = {
            str(value)
            for value in matching[0].get("required_evidence_refs", [])
            if value
        }
        expected_types = GATE_EVIDENCE_TYPES.get(gate_id)
        return frozenset(
            artifact.ref
            for artifact in self.artifacts
            if artifact.ref in required_refs
            and artifact.validation_cycle_id == self.validation_cycle_id
            and artifact.migration_unit_id == migration_unit_id
            and (expected_types is None or artifact.artifact_type in expected_types)
            and self._newer_revision(artifact) is None
        )

    def bound_artifact_coverage_violations_for_ref(
        self,
        reference: str,
        *,
        bound_input_refs: Sequence[str],
        migration_unit_id: str,
    ) -> list[str]:
        """Require each input-bound gate to cover the package's exact typed set.

        A gate being valid in isolation is not sufficient for plural source,
        profile, equivalence, decision, Topic, or architecture inputs. Every bound
        artifact of the gate's accepted types must participate, and unrelated typed
        evidence must not be smuggled into the gate. Registered-but-stale or
        cross-unit inputs intentionally remain in ``bound_artifacts`` so the
        exact-set comparison fails closed.
        """

        gate_id = gate_id_from_ref(reference)
        if gate_id not in EXACT_BOUND_GATE_IDS:
            return []
        expected_types = GATE_EVIDENCE_TYPES.get(gate_id)
        if not expected_types:
            return [f"gate {gate_id} has no registered evidence-type contract"]
        bound = frozenset(str(value) for value in bound_input_refs if value)
        bound_artifacts = frozenset(
            artifact.ref
            for artifact in self.artifacts
            if artifact.ref in bound and artifact.artifact_type in expected_types
        )
        gate_artifacts = self.typed_evidence_refs_for_ref(
            reference,
            migration_unit_id=migration_unit_id,
        )
        if gate_artifacts == bound_artifacts and bound_artifacts:
            return []
        missing = sorted(bound_artifacts - gate_artifacts)
        extra = sorted(gate_artifacts - bound_artifacts)
        violations = [
            f"gate {gate_id} must exactly cover every bound artifact of types "
            f"{sorted(expected_types)}: missing={missing}, extra={extra}"
        ]
        if not bound_artifacts:
            violations.append(
                f"gate {gate_id} cannot authorize work without a bound typed artifact"
            )
        return violations

    def unresolved_artifact_input_refs(
        self, bound_input_refs: Sequence[str]
    ) -> frozenset[str]:
        """Return artifact references that do not resolve in this run registry.

        Planner inputs are still plain references, so an unregistered semantic ref
        has no trustworthy caller-supplied type. Requiring every ``artifact-ref``
        input to resolve prevents that ambiguity from bypassing exact gate coverage.
        """

        registered = {artifact.ref for artifact in self.artifacts}
        return frozenset(
            str(value)
            for value in bound_input_refs
            if value
            and urlsplit(str(value)).scheme.lower() == "artifact-ref"
            and str(value) not in registered
        )

    def authorization_violations(
        self,
        *,
        authorization_ref: str | None,
        work_phase: str,
        authority_mode: str,
        intended_change_set_fingerprint: str | None = None,
        target_scope_refs: Sequence[str] = (),
    ) -> list[str]:
        """Validate the exact active authorization before a write package is routed."""

        if authority_mode not in {
            "branch_write",
            "document_create_write",
            "document_draft_write",
        }:
            return []
        if not authorization_ref:
            return ["write package has no authorization reference"]
        authorization_id = _reference_identity(authorization_ref)
        matching = [
            item
            for item in self.authorizations
            if str(item.get("authorization_id")) == authorization_id
        ]
        if len(matching) != 1:
            return ["write authorization must resolve to exactly one active record"]
        authorization = matching[0]
        violations: list[str] = []
        actor_ref = str(authorization.get("actor_ref", ""))
        if not self._is_trusted_human(actor_ref):
            violations.append("write authorization is not issued by a trusted human")
        expected_action = WRITE_ACTION_BY_WORK_PHASE.get(work_phase)
        action = str(authorization.get("action", ""))
        if expected_action is None or action != expected_action:
            violations.append(
                f"write authorization action does not match work phase {work_phase}"
            )
        if str(authorization.get("validation_cycle_id", "")) != self.validation_cycle_id:
            violations.append("write authorization belongs to a stale validation cycle")
        try:
            approved_at = parse_time(str(authorization.get("approved_at", "")))
            expires_at = parse_time(str(authorization.get("expires_at", "")))
            current = self.now.astimezone(timezone.utc)
            if approved_at > current:
                violations.append("write authorization approval is in the future")
            if expires_at <= approved_at or expires_at <= current:
                violations.append("write authorization is expired or has an invalid lifetime")
        except (TypeError, ValueError):
            violations.append("write authorization has invalid timestamps")
        expected_scopes = (
            frozenset(str(value) for value in target_scope_refs if value)
            or self.action_scope_refs.get(action, frozenset())
        )
        actual_scopes = {
            str(value) for value in authorization.get("scope_refs", []) if value
        }
        if not expected_scopes or expected_scopes != actual_scopes:
            violations.append(
                "write authorization does not exactly match the configured target scope"
            )
        expected_fingerprint = (
            intended_change_set_fingerprint
            or self.authorization_artifact_fingerprint
        )
        if (
            not expected_fingerprint
            or authorization.get("artifact_fingerprint")
            != expected_fingerprint
        ):
            violations.append("write authorization is bound to the wrong change-set fingerprint")
        if str(authorization.get("evidence_ref", "")) not in self.approval_evidence_refs:
            violations.append("write authorization lacks registered approval evidence")
        return violations

"""A small durable append-only store for control-plane evidence.

This is intentionally a local reference implementation, not a distributed database.
It demonstrates the required invariants: tenant/run partitioning, hash chaining,
idempotent appends, immutable artifacts, leases, and write/readback receipts.
"""

from __future__ import annotations

import fcntl
import json
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping

from omni_migrator.control_plane.canonical import (
    canonical_json,
    parse_time,
    partition_key,
    sha256_json,
    utc_now,
    validate_reference,
    validate_run_id,
)
from omni_migrator.control_plane.records import ArtifactEnvelope


class AppendOnlyConflict(RuntimeError):
    """A natural key or idempotency key was reused for different content."""


class LeaseConflict(RuntimeError):
    """A mutable target is already leased by another worker."""


_VERIFIED_LEDGER_CAPABILITY = object()

_RESERVED_TYPED_EVENT_TYPES = frozenset(
    {
        "target_execution_request_registered",
        "target_work_package_state",
        "sigma_route_selected",
        "sigma_route_revoked",
        "dashboard_evidence_snapshot_registered",
        "dashboard_plan_payload_registered",
        "dashboard_plan_validated",
        "dashboard_source_acceptance_registered",
        "dashboard_topic_blueprint_registered",
        "dashboard_topic_readiness_registered",
        "dashboard_topic_component_registered",
        "dashboard_behavior_acceptance_registered",
        "dashboard_query_disposition_registered",
        "dashboard_query_mapping_registered",
        "dashboard_plan_acceptance_registered",
        "qa_fixture_v2_registered",
        "qa_result_v2_registered",
        "target_environment_registered",
        "qa_target_operation_outcome_registered",
        "qa_evidence_snapshot_registered",
        "qa_suite_validated",
        "production_validation_report_registered",
        "documentation_package_registered",
        "domo_inventory_observation_registered",
        "domo_portfolio_inventory_registered",
        "migration_scope_registered",
        "repository_inventory_registered",
        "repository_definition_evidence_registered",
        "semantic_profile_registered",
        "semantic_profile_coverage_registered",
        "equivalence_assessment_registered",
        "consolidation_candidate_registered",
        "consolidation_decision_registered",
        "external_redesign_handoff_registered",
    }
)

_MIGRATION_SCOPE_FIELDS = frozenset(
    {
        "contract_version",
        "scope_id",
        "run_id",
        "inventory_snapshot_ref",
        "name",
        "status",
        "inclusion_rules",
        "exclusion_rules",
        "comparison_scope",
        "migration_scope",
        "cross_scope_exceptions",
        "waves",
        "architecture_decision_ref",
        "scope_hash",
        "provenance",
        "security",
    }
)


@dataclass(frozen=True, init=False)
class VerifiedControlPlaneLedger:
    """One immutable view read and verified at the canonical store boundary.

    The constructor is intentionally store-internal.  Loose JSON exports can be
    structurally valid, and callers can recompute their hashes, but they do not
    receive this runtime trust object.
    """

    tenant_ref: str
    run_id: str
    records: tuple[Mapping[str, Any], ...]
    ledger_head: str
    record_count: int

    def __init__(
        self,
        *,
        tenant_ref: str,
        run_id: str,
        records: tuple[Mapping[str, Any], ...],
        ledger_head: str,
        record_count: int,
        _capability: object,
    ) -> None:
        if _capability is not _VERIFIED_LEDGER_CAPABILITY:
            raise TypeError(
                "verified control-plane ledgers can only be issued by the canonical store"
            )
        object.__setattr__(self, "tenant_ref", tenant_ref)
        object.__setattr__(self, "run_id", run_id)
        object.__setattr__(self, "records", records)
        object.__setattr__(self, "ledger_head", ledger_head)
        object.__setattr__(self, "record_count", record_count)


Guard = Callable[[list[dict[str, Any]]], None]


def _current_artifact_payload(
    records: list[dict[str, Any]],
    *,
    artifact_id: str,
) -> Mapping[str, Any] | None:
    """Return the latest immutable revision for one artifact identity."""

    revisions = [
        record.get("payload", {})
        for record in records
        if record.get("record_type") == "artifact"
        and record.get("payload", {}).get("artifact_id") == artifact_id
    ]
    if not revisions:
        return None
    return max(revisions, key=lambda item: int(item.get("revision", 0)))


def _qa_binding_matches_current_artifact(
    records: list[dict[str, Any]],
    binding: Any,
) -> bool:
    """Match a QA binding to the exact latest registered artifact revision."""

    artifact = _current_artifact_payload(records, artifact_id=binding.artifact_id)
    return artifact is not None and all(
        (
            artifact.get("artifact_type") == binding.artifact_type,
            artifact.get("ref") == binding.artifact_ref,
            int(artifact.get("revision", 0)) == binding.revision,
            artifact.get("content_sha256") == binding.content_sha256,
            artifact.get("producer_ref") == binding.producer_ref,
            artifact.get("migration_unit_id") == binding.migration_unit_id,
            artifact.get("validation_cycle_id") == binding.validation_cycle_id,
        )
    )


def _artifact_envelope_is_exactly_current(
    records: list[dict[str, Any]], envelope: ArtifactEnvelope
) -> bool:
    current = _current_artifact_payload(records, artifact_id=envelope.artifact_id)
    if current is None:
        return False
    try:
        current_envelope = ArtifactEnvelope.from_mapping(current)
        current_envelope.validate(
            expected_tenant_ref=envelope.tenant_ref,
            expected_run_id=envelope.run_id,
        )
    except (TypeError, ValueError):
        return False
    return current_envelope.to_mapping() == envelope.to_mapping()


def _registered_domo_observations(
    records: list[dict[str, Any]],
    *,
    tenant_ref: str,
    run_id: str,
    scope_id: str,
) -> tuple[dict[str, Any], ...]:
    from omni_migrator.control_plane.domo_inventory import (
        inventory_observation_content_sha256,
        validate_inventory_observation,
    )

    observations: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for record in records:
        payload = record.get("payload", {})
        if (
            record.get("record_type") != "event"
            or payload.get("event_type")
            != "domo_inventory_observation_registered"
        ):
            continue
        if set(payload) != {"event_type", "artifact", "observation"}:
            raise AppendOnlyConflict(
                "Domo inventory observation registration has an invalid shape"
            )
        raw_artifact = payload.get("artifact")
        raw_observation = payload.get("observation")
        if not isinstance(raw_artifact, Mapping) or not isinstance(
            raw_observation, Mapping
        ):
            raise AppendOnlyConflict(
                "Domo inventory observation registration is malformed"
            )
        observation = dict(raw_observation)
        if observation.get("scope_id") != scope_id:
            continue
        try:
            envelope = ArtifactEnvelope.from_mapping(raw_artifact)
            envelope.validate(
                expected_tenant_ref=tenant_ref,
                expected_run_id=run_id,
            )
        except (TypeError, ValueError) as exc:
            raise AppendOnlyConflict(
                "Domo inventory observation artifact envelope is invalid"
            ) from exc
        observation_id = str(observation.get("observation_id", ""))
        if (
            observation.get("contract_version")
            != "domo-to-omni.inventory-observation.v1"
            or observation.get("source_tenant_ref") != tenant_ref
            or observation.get("run_id") != run_id
            or observation.get("immutable") is not True
            or validate_inventory_observation(observation)
            or envelope.artifact_type != "domo_inventory_observation"
            or envelope.content_sha256
            != inventory_observation_content_sha256(observation)
            or envelope.producer_ref
            != "agent-ref://data-acquisition-ingestion"
            or not _artifact_envelope_is_exactly_current(records, envelope)
        ):
            raise AppendOnlyConflict(
                "Domo inventory observation registration is not canonical or current"
            )
        if observation_id in seen_ids:
            raise AppendOnlyConflict(
                "Domo inventory observation ID is registered more than once"
            )
        seen_ids.add(observation_id)
        observations.append(observation)
    return tuple(sorted(observations, key=lambda item: item["observation_id"]))


def _registered_domo_portfolio(
    records: list[dict[str, Any]],
    *,
    tenant_ref: str,
    run_id: str,
    scope_id: str,
) -> dict[str, Any] | None:
    from omni_migrator.control_plane.domo_inventory import (
        portfolio_inventory_content_sha256,
        validate_portfolio_inventory,
    )

    matching: list[dict[str, Any]] = []
    for record in records:
        payload = record.get("payload", {})
        if (
            record.get("record_type") != "event"
            or payload.get("event_type") != "domo_portfolio_inventory_registered"
        ):
            continue
        if set(payload) != {"event_type", "artifact", "portfolio"}:
            raise AppendOnlyConflict(
                "Domo portfolio inventory registration has an invalid shape"
            )
        raw_artifact = payload.get("artifact")
        raw_portfolio = payload.get("portfolio")
        if not isinstance(raw_artifact, Mapping) or not isinstance(
            raw_portfolio, Mapping
        ):
            raise AppendOnlyConflict(
                "Domo portfolio inventory registration is malformed"
            )
        portfolio = dict(raw_portfolio)
        if portfolio.get("scope_id") != scope_id:
            continue
        try:
            envelope = ArtifactEnvelope.from_mapping(raw_artifact)
            envelope.validate(
                expected_tenant_ref=tenant_ref,
                expected_run_id=run_id,
            )
        except (TypeError, ValueError) as exc:
            raise AppendOnlyConflict(
                "Domo portfolio inventory artifact envelope is invalid"
            ) from exc
        observations = _registered_domo_observations(
            records,
            tenant_ref=tenant_ref,
            run_id=run_id,
            scope_id=scope_id,
        )
        current_artifacts = {
            str(item.get("artifact_id")): item
            for item in (
                record.get("payload", {})
                for record in records
                if record.get("record_type") == "artifact"
            )
            if _current_artifact_payload(
                records, artifact_id=str(item.get("artifact_id", ""))
            )
            == item
        }
        root_binding_fields = {
            "source_object_graph_ref": "source_object_graph",
            "evidence_bundle_ref": "evidence_bundle",
            "coverage_ledger_ref": "coverage_ledger",
            "inventory_snapshot_ref": "inventory_snapshot",
        }
        root_bindings_match = True
        for field_name, artifact_type in root_binding_fields.items():
            candidates = [
                item
                for item in current_artifacts.values()
                if item.get("artifact_type") == artifact_type
            ]
            if (
                len(candidates) != 1
                or candidates[0].get("ref") != portfolio.get(field_name)
            ):
                root_bindings_match = False
        if (
            portfolio.get("contract_version")
            != "domo-to-omni.portfolio-inventory.v1"
            or portfolio.get("source_tenant_ref") != tenant_ref
            or portfolio.get("run_id") != run_id
            or portfolio.get("immutable") is not True
            or validate_portfolio_inventory(
                portfolio, observations=observations
            )
            or envelope.artifact_type != "domo_portfolio_inventory"
            or envelope.content_sha256
            != portfolio_inventory_content_sha256(portfolio)
            or envelope.producer_ref
            not in {
                "agent-ref://inventory-intake",
                "agent-ref://domo-to-omni-architect",
            }
            or not root_bindings_match
            or not _artifact_envelope_is_exactly_current(records, envelope)
        ):
            raise AppendOnlyConflict(
                "Domo portfolio inventory registration is not canonical or current"
            )
        matching.append(portfolio)
    if len(matching) > 1:
        raise AppendOnlyConflict(
            "Domo portfolio inventory scope is registered more than once"
        )
    return matching[0] if matching else None


def _assert_current_domo_profile_builder_attestation(
    records: list[dict[str, Any]],
    *,
    tenant_ref: str,
    run_id: str,
    profile: Any,
    envelope: ArtifactEnvelope,
) -> bool:
    """Bind one denominator Domo profile to its current builder expectation.

    A Domo profile can exist outside the portfolio denominator (for example, a
    later diagnostic or descendant profile).  Denominator membership is
    therefore detected by the stable semantic object identity without trusting
    the caller's revision.  Any explicit requirement-ID/hash claim also opts
    into this check and must resolve to exactly one current portfolio member.
    """

    from omni_migrator.semantic.profiles import DOMO_PROFILE_BUILDER_VERSION

    if profile.identity.system != "domo":
        return False

    provenance = profile.provenance
    declares_requirement = any(
        field in provenance
        for field in (
            "semantic_profile_requirement_id",
            "semantic_profile_requirement_hash",
        )
    )
    portfolio = _registered_domo_portfolio(
        records,
        tenant_ref=tenant_ref,
        run_id=run_id,
        scope_id=profile.scope_id,
    )
    if portfolio is None:
        if declares_requirement:
            raise AppendOnlyConflict(
                "Domo semantic profile builder attestation requires the current "
                "registered portfolio in the same tenant, run, and scope"
            )
        return False

    candidates: list[tuple[Mapping[str, Any], Mapping[str, Any], Mapping[str, Any]]] = []
    claimed_requirement_id = provenance.get("semantic_profile_requirement_id")
    claimed_requirement_hash = provenance.get("semantic_profile_requirement_hash")
    for item in portfolio.get("objects", []):
        if not isinstance(item, Mapping):
            continue
        for requirement in item.get("semantic_profile_requirements", []):
            if not isinstance(requirement, Mapping):
                continue
            context_id = str(requirement.get("context_id", ""))
            context_hash = str(requirement.get("context_hash", ""))
            base_object_id = str(requirement.get("base_object_id", ""))
            expected_object_id = (
                base_object_id
                if context_id == "base"
                else f"{base_object_id}.context.{context_hash.removeprefix('sha256:')[:16]}"
            )
            identity_matches = profile.identity.object_id == expected_object_id
            requirement_claim_matches = (
                claimed_requirement_id == requirement.get("requirement_id")
                or claimed_requirement_hash == requirement.get("requirement_hash")
            )
            if not identity_matches and not requirement_claim_matches:
                continue
            expectations = [
                expectation
                for expectation in item.get("semantic_profile_expectations", [])
                if isinstance(expectation, Mapping)
                and expectation.get("requirement_id")
                == requirement.get("requirement_id")
            ]
            if len(expectations) != 1:
                raise AppendOnlyConflict(
                    "Domo semantic profile requires one exact current builder expectation"
                )
            candidates.append((item, requirement, expectations[0]))

    if not candidates:
        if declares_requirement:
            raise AppendOnlyConflict(
                "Domo semantic profile builder attestation names a foreign or stale "
                "portfolio requirement"
            )
        return False
    if len(candidates) != 1:
        raise AppendOnlyConflict(
            "Domo semantic profile builder attestation is ambiguous across portfolio "
            "requirements"
        )

    item, requirement, expectation = candidates[0]
    identity = item.get("identity", {})
    context_id = str(requirement.get("context_id", ""))
    context_hash = str(requirement.get("context_hash", ""))
    base_object_id = str(requirement.get("base_object_id", ""))
    expected_object_id = (
        base_object_id
        if context_id == "base"
        else f"{base_object_id}.context.{context_hash.removeprefix('sha256:')[:16]}"
    )
    expected_provenance = {
        "producer_ref": (
            "agent-ref://domo-bi-developer"
            if requirement.get("profile_kind") == "dashboard_query"
            else "agent-ref://domo-analytics-engineer"
        ),
        "source_system": "domo",
        "source_object_type": identity.get("object_type"),
        "source_native_id": identity.get("native_id"),
        "source_revision_hash": requirement.get("source_revision_hash"),
        "semantic_profile_requirement_id": requirement.get("requirement_id"),
        "semantic_profile_requirement_hash": requirement.get("requirement_hash"),
        "base_object_id": base_object_id,
        "context_id": context_id,
        "context_ref": requirement.get("context_ref"),
        "context_hash": context_hash,
        "consumer_object_id": requirement.get("consumer_object_id"),
        "builder_version": DOMO_PROFILE_BUILDER_VERSION,
    }
    mismatched_provenance = sorted(
        field
        for field, expected in expected_provenance.items()
        if field not in provenance or provenance.get(field) != expected
    )
    identity_matches_exactly = all(
        (
            profile.identity.kind == requirement.get("profile_kind"),
            profile.identity.object_id == expected_object_id,
            profile.identity.revision_hash == requirement.get("requirement_hash"),
        )
    )
    definition_matches_exactly = all(
        (
            profile.definition.original_ref == requirement.get("definition_ref"),
            profile.definition.original_hash == requirement.get("definition_hash"),
        )
    )
    expectation_matches_requirement = all(
        (
            expectation.get("requirement_id") == requirement.get("requirement_id"),
            expectation.get("requirement_hash")
            == requirement.get("requirement_hash"),
        )
    )
    if (
        mismatched_provenance
        or envelope.producer_ref != provenance.get("producer_ref")
        or not identity_matches_exactly
        or not definition_matches_exactly
        or not expectation_matches_requirement
        or expectation.get("builder_version") != DOMO_PROFILE_BUILDER_VERSION
        or profile.profile_hash != expectation.get("expected_profile_hash")
    ):
        details = (
            f"; provenance mismatches: {', '.join(mismatched_provenance)}"
            if mismatched_provenance
            else ""
        )
        raise AppendOnlyConflict(
            "Domo semantic profile does not match its exact current portfolio "
            f"requirement and builder expectation{details}"
        )
    return True


def _current_artifact_envelope_by_ref(
    records: list[dict[str, Any]],
    *,
    artifact_ref: str,
) -> ArtifactEnvelope | None:
    matches: list[ArtifactEnvelope] = []
    for record in records:
        if record.get("record_type") != "artifact":
            continue
        payload = record.get("payload", {})
        if payload.get("ref") != artifact_ref:
            continue
        try:
            envelope = ArtifactEnvelope.from_mapping(payload)
        except (TypeError, ValueError):
            continue
        if _artifact_envelope_is_exactly_current(records, envelope):
            matches.append(envelope)
    if len(matches) > 1:
        raise AppendOnlyConflict(
            f"artifact reference identifies multiple current revisions: {artifact_ref}"
        )
    return matches[0] if matches else None


def _registered_migration_scopes(
    records: list[dict[str, Any]],
    *,
    tenant_ref: str,
    run_id: str,
    scope_id: str,
    migration_unit_id: str,
    validation_cycle_id: str,
) -> tuple[tuple[ArtifactEnvelope, dict[str, Any]], ...]:
    from omni_migrator.control_plane.contract_integrity import validate_migration_scope

    matches: list[tuple[ArtifactEnvelope, dict[str, Any]]] = []
    for record in records:
        payload = record.get("payload", {})
        if record.get("record_type") != "event" or payload.get(
            "event_type"
        ) != "migration_scope_registered":
            continue
        if set(payload) != {"event_type", "artifact", "scope"}:
            raise AppendOnlyConflict("migration scope registration has an invalid shape")
        if not isinstance(payload.get("artifact"), Mapping) or not isinstance(
            payload.get("scope"), Mapping
        ):
            raise AppendOnlyConflict("migration scope registration is malformed")
        raw = dict(payload["scope"])
        if raw.get("scope_id") != scope_id:
            continue
        try:
            envelope = ArtifactEnvelope.from_mapping(payload["artifact"])
            envelope.validate(
                expected_tenant_ref=tenant_ref,
                expected_run_id=run_id,
            )
        except (TypeError, ValueError) as exc:
            raise AppendOnlyConflict("migration scope artifact envelope is invalid") from exc
        unit_ids = {
            str(unit.get("migration_unit_id"))
            for wave in raw.get("waves", [])
            if isinstance(wave, Mapping)
            for unit in wave.get("units", [])
            if isinstance(unit, Mapping)
        }
        if (
            set(raw) != _MIGRATION_SCOPE_FIELDS
            or raw.get("status")
            not in {
                "proposed",
                "accepted",
                "in_progress",
                "completed",
                "blocked",
                "superseded",
            }
            or raw.get("contract_version") != "domo-to-omni.migration-scope.v1"
            or raw.get("run_id") != run_id
            or migration_unit_id not in unit_ids
            or validate_migration_scope(raw)
            or envelope.artifact_type != "migration_scope"
            or envelope.content_sha256 != sha256_json(raw)
            or envelope.producer_ref
            not in {
                "agent-ref://inventory-intake",
                "agent-ref://domo-to-omni-architect",
            }
            or envelope.validation_cycle_id != validation_cycle_id
            or envelope.migration_unit_id not in {None, migration_unit_id}
        ):
            raise AppendOnlyConflict("migration scope registration is not canonical")
        if not _artifact_envelope_is_exactly_current(records, envelope):
            continue
        matches.append((envelope, raw))
    return tuple(matches)


def _registered_repository_inventories(
    records: list[dict[str, Any]],
    *,
    tenant_ref: str,
    run_id: str,
    migration_unit_id: str,
    validation_cycle_id: str,
) -> tuple[tuple[ArtifactEnvelope, dict[str, Any]], ...]:
    from omni_migrator.repositories.dbt.models import RepositoryInventory

    matches: list[tuple[ArtifactEnvelope, dict[str, Any]]] = []
    for record in records:
        payload = record.get("payload", {})
        if record.get("record_type") != "event" or payload.get(
            "event_type"
        ) != "repository_inventory_registered":
            continue
        if set(payload) != {"event_type", "artifact", "inventory"}:
            raise AppendOnlyConflict(
                "repository inventory registration has an invalid shape"
            )
        if not isinstance(payload.get("artifact"), Mapping) or not isinstance(
            payload.get("inventory"), Mapping
        ):
            raise AppendOnlyConflict("repository inventory registration is malformed")
        raw = dict(payload["inventory"])
        try:
            inventory = RepositoryInventory.model_validate(raw)
            envelope = ArtifactEnvelope.from_mapping(payload["artifact"])
            envelope.validate(
                expected_tenant_ref=tenant_ref,
                expected_run_id=run_id,
            )
        except (TypeError, ValueError) as exc:
            raise AppendOnlyConflict(
                "repository inventory registration is invalid"
            ) from exc
        if (
            envelope.validation_cycle_id != validation_cycle_id
            or envelope.migration_unit_id not in {None, migration_unit_id}
        ):
            continue
        if (
            inventory.run_id != run_id
            or envelope.artifact_type != "repository_inventory"
            or envelope.content_sha256 != sha256_json(raw)
            or envelope.producer_ref != "agent-ref://dbt-analytics-engineer"
        ):
            raise AppendOnlyConflict(
                "repository inventory registration is not canonically artifact-bound"
            )
        if not _artifact_envelope_is_exactly_current(records, envelope):
            continue
        matches.append((envelope, raw))
    return tuple(matches)


def _repository_subject_for_evidence(inventory: Any, subject_id: str) -> Any:
    matches = [
        *(
            item
            for item in inventory.resources
            if item.unique_id == subject_id
        ),
        *(
            item
            for item in inventory.semantic_assets
            if item.asset_id == subject_id
        ),
    ]
    if len(matches) != 1:
        raise AppendOnlyConflict(
            "repository definition evidence must resolve one exact inventory subject"
        )
    return matches[0]


def _repository_definition_attestation_sha256(
    *,
    scope_id: str,
    evidence: Mapping[str, Any],
    expected_profile_hash: str,
) -> str:
    return sha256_json(
        {
            "scope_id": scope_id,
            "evidence": dict(evidence),
            "expected_profile_hash": expected_profile_hash,
        }
    )


def _registered_repository_definition_evidence(
    records: list[dict[str, Any]],
    *,
    tenant_ref: str,
    run_id: str,
    scope_id: str,
    migration_unit_id: str,
    validation_cycle_id: str,
) -> tuple[tuple[ArtifactEnvelope, Any, str, Any], ...]:
    from omni_migrator.semantic.models import RepositoryDefinitionEvidence
    from omni_migrator.semantic.profiles import build_dbt_semantic_profile

    inventories = _registered_repository_inventories(
        records,
        tenant_ref=tenant_ref,
        run_id=run_id,
        migration_unit_id=migration_unit_id,
        validation_cycle_id=validation_cycle_id,
    )
    matching_events = [
        record.get("payload", {})
        for record in records
        if record.get("record_type") == "event"
        and record.get("payload", {}).get("event_type")
        == "repository_definition_evidence_registered"
        and record.get("payload", {}).get("scope_id") == scope_id
    ]
    if not matching_events:
        return ()
    if len(inventories) != 1:
        raise AppendOnlyConflict(
            "repository definition evidence requires one exact current repository inventory"
        )
    inventory_envelope, inventory_raw = inventories[0]
    from omni_migrator.repositories.dbt.models import RepositoryInventory

    inventory = RepositoryInventory.model_validate(inventory_raw)
    resolved: list[tuple[ArtifactEnvelope, Any, str, Any]] = []
    seen_subjects: set[str] = set()
    for payload in matching_events:
        if set(payload) != {
            "event_type",
            "scope_id",
            "artifact",
            "evidence",
            "expected_profile_hash",
        }:
            raise AppendOnlyConflict(
                "repository definition evidence registration has an invalid shape"
            )
        if not isinstance(payload.get("artifact"), Mapping) or not isinstance(
            payload.get("evidence"), Mapping
        ):
            raise AppendOnlyConflict(
                "repository definition evidence registration is malformed"
            )
        try:
            envelope = ArtifactEnvelope.from_mapping(payload["artifact"])
            envelope.validate(
                expected_tenant_ref=tenant_ref,
                expected_run_id=run_id,
            )
            evidence = RepositoryDefinitionEvidence.model_validate(
                payload["evidence"]
            )
        except (TypeError, ValueError) as exc:
            raise AppendOnlyConflict(
                "repository definition evidence registration is invalid"
            ) from exc
        if (
            envelope.migration_unit_id != migration_unit_id
            or envelope.validation_cycle_id != validation_cycle_id
        ):
            continue
        expected_profile_hash = str(payload.get("expected_profile_hash", ""))
        subject = _repository_subject_for_evidence(inventory, evidence.subject_id)
        try:
            profile = build_dbt_semantic_profile(
                inventory,
                subject,
                evidence,
                run_id=run_id,
                scope_id=scope_id,
            )
        except (TypeError, ValueError) as exc:
            raise AppendOnlyConflict(
                "repository definition evidence is foreign to its current inventory"
            ) from exc
        if (
            envelope.artifact_type != "repository_definition_evidence"
            or envelope.content_sha256
            != _repository_definition_attestation_sha256(
                scope_id=scope_id,
                evidence=evidence.model_dump(mode="json"),
                expected_profile_hash=expected_profile_hash,
            )
            or envelope.producer_ref != "agent-ref://dbt-analytics-engineer"
            or expected_profile_hash != profile.profile_hash
            or not _artifact_envelope_is_exactly_current(records, envelope)
        ):
            raise AppendOnlyConflict(
                "repository definition evidence is not canonically current and profile-bound"
            )
        _require_semantic_dependency_lineage(
            envelope,
            (inventory_envelope,),
            dependency_kind="repository definition evidence",
        )
        if evidence.subject_id in seen_subjects:
            raise AppendOnlyConflict(
                "repository definition evidence subject is registered more than once"
            )
        seen_subjects.add(evidence.subject_id)
        resolved.append((envelope, evidence, expected_profile_hash, profile))
    return tuple(resolved)


def _assert_current_dbt_profile_builder_attestation(
    records: list[dict[str, Any]],
    *,
    tenant_ref: str,
    run_id: str,
    profile: Any,
    envelope: ArtifactEnvelope,
) -> bool:
    from omni_migrator.repositories.dbt.models import RepositoryInventory

    if profile.identity.system != "dbt":
        return False
    inventories = _registered_repository_inventories(
        records,
        tenant_ref=tenant_ref,
        run_id=run_id,
        migration_unit_id=str(envelope.migration_unit_id),
        validation_cycle_id=envelope.validation_cycle_id,
    )
    claims_evidence = any(
        field in profile.provenance
        for field in (
            "repository_definition_evidence_hash",
            "repository_inventory_hash",
            "subject_id",
        )
    )
    if len(inventories) != 1:
        if claims_evidence:
            raise AppendOnlyConflict(
                "dbt semantic profile attestation requires one current repository inventory"
            )
        return False
    _inventory_envelope, inventory_raw = inventories[0]
    inventory = RepositoryInventory.model_validate(inventory_raw)
    denominator_ids = {
        *(item.unique_id for item in inventory.resources),
        *(item.asset_id for item in inventory.semantic_assets),
    }
    if profile.identity.object_id not in denominator_ids:
        if claims_evidence:
            raise AppendOnlyConflict(
                "dbt semantic profile attestation names a foreign repository subject"
            )
        return False
    registrations = [
        item
        for item in _registered_repository_definition_evidence(
            records,
            tenant_ref=tenant_ref,
            run_id=run_id,
            scope_id=profile.scope_id,
            migration_unit_id=str(envelope.migration_unit_id),
            validation_cycle_id=envelope.validation_cycle_id,
        )
        if item[1].subject_id == profile.identity.object_id
    ]
    if len(registrations) != 1:
        raise AppendOnlyConflict(
            "dbt denominator profile requires one exact current repository definition attestation"
        )
    evidence_envelope, _evidence, expected_profile_hash, expected_profile = (
        registrations[0]
    )
    if (
        profile != expected_profile
        or profile.profile_hash != expected_profile_hash
        or envelope.producer_ref != profile.provenance.get("producer_ref")
    ):
        raise AppendOnlyConflict(
            "dbt semantic profile does not match its exact current repository builder attestation"
        )
    _require_semantic_dependency_lineage(
        envelope,
        (evidence_envelope,),
        dependency_kind="dbt semantic profile",
    )
    return True


def _registered_semantic_profiles(
    records: list[dict[str, Any]],
    *,
    tenant_ref: str,
    run_id: str,
    scope_id: str,
    migration_unit_id: str,
    validation_cycle_id: str,
) -> tuple[tuple[ArtifactEnvelope, Any], ...]:
    from omni_migrator.semantic.models import SemanticProfile
    from omni_migrator.semantic.profiles import validate_semantic_profile

    matches: list[tuple[ArtifactEnvelope, Any]] = []
    allowed_source_producers = {
        "agent-ref://domo-bi-developer",
        "agent-ref://domo-analytics-engineer",
        "agent-ref://dbt-analytics-engineer",
        "agent-ref://omni-modeler",
    }
    for record in records:
        payload = record.get("payload", {})
        if record.get("record_type") != "event" or payload.get(
            "event_type"
        ) != "semantic_profile_registered":
            continue
        if set(payload) != {"event_type", "artifact", "profile"}:
            raise AppendOnlyConflict("semantic profile registration has an invalid shape")
        if not isinstance(payload.get("artifact"), Mapping) or not isinstance(
            payload.get("profile"), Mapping
        ):
            raise AppendOnlyConflict("semantic profile registration is malformed")
        try:
            profile = SemanticProfile.model_validate(payload["profile"])
            envelope = ArtifactEnvelope.from_mapping(payload["artifact"])
            envelope.validate(
                expected_tenant_ref=tenant_ref,
                expected_run_id=run_id,
            )
        except (TypeError, ValueError) as exc:
            raise AppendOnlyConflict("semantic profile registration is invalid") from exc
        allowed = (
            {"agent-ref://domo-to-omni-architect"}
            if envelope.artifact_type == "target_semantic_profile"
            else allowed_source_producers
        )
        raw = profile.model_dump(mode="json")
        if (
            profile.scope_id != scope_id
            or envelope.validation_cycle_id != validation_cycle_id
            or envelope.migration_unit_id != migration_unit_id
        ):
            continue
        if (
            profile.run_id != run_id
            or validate_semantic_profile(profile)
            or envelope.artifact_type
            not in {"semantic_profile", "target_semantic_profile"}
            or envelope.content_sha256 != sha256_json(raw)
            or envelope.producer_ref not in allowed
        ):
            raise AppendOnlyConflict(
                "semantic profile registration is not canonically artifact-bound"
            )
        if not _artifact_envelope_is_exactly_current(records, envelope):
            continue
        _assert_current_domo_profile_builder_attestation(
            records,
            tenant_ref=tenant_ref,
            run_id=run_id,
            profile=profile,
            envelope=envelope,
        )
        _assert_current_dbt_profile_builder_attestation(
            records,
            tenant_ref=tenant_ref,
            run_id=run_id,
            profile=profile,
            envelope=envelope,
        )
        matches.append((envelope, profile))
    return tuple(matches)


def _semantic_analysis_registration_contract(event_type: str) -> tuple[Any, ...]:
    """Return the exact runtime contract for one semantic-analysis registration."""

    if event_type == "equivalence_assessment_registered":
        from omni_migrator.semantic.equivalence import (
            EquivalenceAssessment,
            finalize_equivalence_assessment,
            validate_equivalence_assessment,
        )

        return (
            "assessment",
            "assessment_id",
            "equivalence_assessment",
            EquivalenceAssessment,
            finalize_equivalence_assessment,
            validate_equivalence_assessment,
        )
    if event_type == "consolidation_candidate_registered":
        from omni_migrator.semantic.consolidation import (
            ConsolidationCandidate,
            finalize_consolidation_candidate,
            validate_consolidation_candidate,
        )

        return (
            "candidate",
            "candidate_id",
            "consolidation_candidate",
            ConsolidationCandidate,
            finalize_consolidation_candidate,
            validate_consolidation_candidate,
        )
    if event_type == "consolidation_decision_registered":
        from omni_migrator.semantic.consolidation import (
            ConsolidationDecision,
            finalize_consolidation_decision,
            validate_consolidation_decision_integrity,
        )

        return (
            "decision",
            "decision_id",
            "consolidation_decision",
            ConsolidationDecision,
            finalize_consolidation_decision,
            validate_consolidation_decision_integrity,
        )
    raise ValueError(f"unsupported semantic-analysis event type: {event_type}")


def _registered_semantic_analysis_payloads(
    records: list[dict[str, Any]],
    *,
    event_type: str,
    tenant_ref: str,
    run_id: str,
    scope_id: str,
    migration_unit_id: str,
    validation_cycle_id: str,
) -> tuple[tuple[ArtifactEnvelope, Any], ...]:
    """Resolve current canonical semantic-analysis payloads from typed events."""

    (
        payload_field,
        _identity_field,
        artifact_type,
        model_type,
        finalizer,
        validator,
    ) = _semantic_analysis_registration_contract(event_type)
    matches: list[tuple[ArtifactEnvelope, Any]] = []
    for record in records:
        payload = record.get("payload", {})
        if (
            record.get("record_type") != "event"
            or payload.get("event_type") != event_type
        ):
            continue
        if set(payload) != {"event_type", "artifact", payload_field}:
            raise AppendOnlyConflict(
                f"{artifact_type} registration has an invalid shape"
            )
        if not isinstance(payload.get("artifact"), Mapping) or not isinstance(
            payload.get(payload_field), Mapping
        ):
            raise AppendOnlyConflict(f"{artifact_type} registration is malformed")
        try:
            value = model_type.model_validate(payload[payload_field])
            finalized = finalizer(payload[payload_field])
            envelope = ArtifactEnvelope.from_mapping(payload["artifact"])
            envelope.validate(
                expected_tenant_ref=tenant_ref,
                expected_run_id=run_id,
            )
        except (TypeError, ValueError) as exc:
            raise AppendOnlyConflict(
                f"{artifact_type} registration is invalid"
            ) from exc
        raw = value.model_dump(mode="json")
        if (
            value.scope_id != scope_id
            or envelope.validation_cycle_id != validation_cycle_id
            or envelope.migration_unit_id != migration_unit_id
        ):
            continue
        if (
            finalized.model_dump(mode="json") != raw
            or validator(value)
            or value.run_id != run_id
            or envelope.artifact_type != artifact_type
            or envelope.content_sha256 != sha256_json(raw)
            or envelope.producer_ref
            not in {
                "agent-ref://semantic-consolidation",
                "agent-ref://semantic_consolidation",
            }
            or (
                event_type == "consolidation_decision_registered"
                and value.validation_cycle_id != validation_cycle_id
            )
        ):
            raise AppendOnlyConflict(
                f"{artifact_type} registration is not canonically artifact-bound"
            )
        if not _artifact_envelope_is_exactly_current(records, envelope):
            continue
        _assert_semantic_analysis_dependencies_current(
            records,
            event_type=event_type,
            tenant_ref=tenant_ref,
            run_id=run_id,
            scope_id=scope_id,
            migration_unit_id=migration_unit_id,
            validation_cycle_id=validation_cycle_id,
            value=value,
            envelope=envelope,
        )
        matches.append((envelope, value))
    return tuple(matches)


def _semantic_dependency_input(envelope: ArtifactEnvelope) -> tuple[str, int, str]:
    return (envelope.artifact_id, envelope.revision, envelope.content_sha256)


def _require_semantic_dependency_lineage(
    envelope: ArtifactEnvelope,
    dependencies: Iterable[ArtifactEnvelope],
    *,
    dependency_kind: str,
) -> None:
    actual = {
        (
            str(item.get("artifact_id", "")),
            int(item.get("revision", 0)),
            str(item.get("content_sha256", "")),
        )
        for item in envelope.input_artifacts
    }
    expected = {_semantic_dependency_input(item) for item in dependencies}
    if expected != actual:
        raise AppendOnlyConflict(
            f"{dependency_kind} does not have the exact current semantic dependency lineage"
        )


def _resolve_semantic_profile_dependency(
    records: list[dict[str, Any]],
    *,
    tenant_ref: str,
    run_id: str,
    scope_id: str,
    migration_unit_id: str,
    validation_cycle_id: str,
    profile_id: str,
    profile_hash: str,
    asset_id: str | None = None,
    dimension_hashes: Mapping[str, str] | None = None,
) -> tuple[ArtifactEnvelope, Any]:
    matches = [
        (envelope, profile)
        for envelope, profile in _registered_semantic_profiles(
            records,
            tenant_ref=tenant_ref,
            run_id=run_id,
            scope_id=scope_id,
            migration_unit_id=migration_unit_id,
            validation_cycle_id=validation_cycle_id,
        )
        if profile.profile_id == profile_id
        and profile.profile_hash == profile_hash
        and (asset_id is None or profile.identity.object_id == asset_id)
        and (
            dimension_hashes is None
            or dict(profile.dimension_hashes) == dict(dimension_hashes)
        )
    ]
    if len(matches) != 1:
        raise AppendOnlyConflict(
            "semantic analysis requires one exact current registered endpoint profile"
        )
    return matches[0]


def _resolve_semantic_analysis_dependency(
    records: list[dict[str, Any]],
    *,
    event_type: str,
    tenant_ref: str,
    run_id: str,
    scope_id: str,
    migration_unit_id: str,
    validation_cycle_id: str,
    identity_field: str,
    identity: str,
    content_hash_field: str,
    content_hash: str,
) -> tuple[ArtifactEnvelope, Any]:
    matches = [
        (envelope, value)
        for envelope, value in _registered_semantic_analysis_payloads(
            records,
            event_type=event_type,
            tenant_ref=tenant_ref,
            run_id=run_id,
            scope_id=scope_id,
            migration_unit_id=migration_unit_id,
            validation_cycle_id=validation_cycle_id,
        )
        if getattr(value, identity_field) == identity
        and getattr(value, content_hash_field) == content_hash
    ]
    if len(matches) != 1:
        dependency = event_type.removesuffix("_registered").replace("_", " ")
        raise AppendOnlyConflict(
            f"semantic analysis requires one exact current registered {dependency}"
        )
    return matches[0]


def _semantic_profile_is_covered(coverage: Any, profile: Any) -> bool:
    """Return whether a profile is an exact coverage resolution or valid descendant."""

    for resolution in coverage.resolutions:
        binding = resolution.profile
        if (
            resolution.disposition == "profile"
            and binding is not None
            and binding.profile_id == profile.profile_id
            and binding.profile_hash == profile.profile_hash
            and binding.identity == profile.identity
        ):
            return True
    lineage = profile.provenance.get("semantic_coverage_lineage")
    if not isinstance(lineage, Mapping) or set(lineage) != {
        "subject_ref",
        "subject_hash",
        "base_profile_id",
        "base_profile_hash",
    }:
        return False
    subjects = {subject.subject_ref: subject for subject in coverage.subjects}
    resolutions = {
        resolution.subject_ref: resolution for resolution in coverage.resolutions
    }
    subject_ref = str(lineage["subject_ref"])
    subject = subjects.get(subject_ref)
    resolution = resolutions.get(subject_ref)
    base = resolution.profile if resolution is not None else None
    upstream_ids = {
        *profile.lineage.authoritative_source_ids,
        *profile.lineage.upstream_asset_ids,
    }
    return bool(
        subject is not None
        and resolution is not None
        and resolution.disposition == "profile"
        and base is not None
        and str(lineage["subject_hash"]) == subject.subject_hash
        and str(lineage["base_profile_id"]) == base.profile_id
        and str(lineage["base_profile_hash"]) == base.profile_hash
        and subject.profile_identity.object_id in upstream_ids
    )


def _assert_semantic_analysis_dependencies_current(
    records: list[dict[str, Any]],
    *,
    event_type: str,
    tenant_ref: str,
    run_id: str,
    scope_id: str,
    migration_unit_id: str,
    validation_cycle_id: str,
    value: Any,
    envelope: ArtifactEnvelope,
) -> None:
    from omni_migrator.semantic.equivalence import consumer_map_hash

    partition = {
        "tenant_ref": tenant_ref,
        "run_id": run_id,
        "scope_id": scope_id,
        "migration_unit_id": migration_unit_id,
        "validation_cycle_id": validation_cycle_id,
    }
    if event_type == "equivalence_assessment_registered":
        profile_dependencies = [
            _resolve_semantic_profile_dependency(
                records,
                **partition,
                profile_id=profile_ref.profile_id,
                profile_hash=profile_ref.profile_hash,
                asset_id=profile_ref.asset_id,
                dimension_hashes=profile_ref.dimension_hashes,
            )
            for profile_ref in (value.left_profile, value.right_profile)
        ]
        if len(
            {
                _semantic_dependency_input(item)
                for item, _profile in profile_dependencies
            }
        ) != 2:
            raise AppendOnlyConflict(
                "equivalence assessment endpoints must be two distinct current profiles"
            )
        coverage_matches = _registered_semantic_profile_coverages(
            records,
            **partition,
        )
        if len(coverage_matches) != 1 or coverage_matches[0][1].status != "complete":
            raise AppendOnlyConflict(
                "equivalence assessment requires one exact current complete semantic-profile coverage"
            )
        coverage_envelope, coverage = coverage_matches[0]
        if not all(
            _semantic_profile_is_covered(coverage, profile)
            for _profile_envelope, profile in profile_dependencies
        ):
            raise AppendOnlyConflict(
                "equivalence assessment endpoint is outside accepted semantic-profile coverage"
            )
        _require_semantic_dependency_lineage(
            envelope,
            (
                coverage_envelope,
                *(item for item, _profile in profile_dependencies),
            ),
            dependency_kind="equivalence assessment",
        )
        return

    if event_type == "consolidation_candidate_registered":
        assessment_envelope, assessment = _resolve_semantic_analysis_dependency(
            records,
            event_type="equivalence_assessment_registered",
            **partition,
            identity_field="assessment_id",
            identity=value.assessment_id,
            content_hash_field="assessment_hash",
            content_hash=value.assessment_fingerprint,
        )
        relationship_matches = all(
            (
                value.assessment_category == assessment.overall_category,
                value.assessment_confidence == assessment.overall_confidence,
                value.source_profile_id == assessment.left_profile.profile_id,
                value.target_profile_id == assessment.right_profile.profile_id,
                value.source_profile_fingerprint
                == assessment.left_profile.profile_hash,
                value.target_profile_fingerprint
                == assessment.right_profile.profile_hash,
                tuple(sorted(value.hard_vetoes))
                == tuple(sorted(assessment.hard_vetoes)),
                consumer_map_hash(value.consumer_map)
                == assessment.consumer_map_hash,
                set(value.consumer_map)
                == set(assessment.consumer_scope.left_consumer_ids),
            )
        )
        if not relationship_matches:
            raise AppendOnlyConflict(
                "consolidation candidate does not exactly bind its current assessment"
            )
        _require_semantic_dependency_lineage(
            envelope,
            (assessment_envelope,),
            dependency_kind="consolidation candidate",
        )
        return

    if event_type != "consolidation_decision_registered":
        raise AppendOnlyConflict(
            f"unsupported semantic-analysis dependency contract: {event_type}"
        )

    candidate_dependencies: list[tuple[ArtifactEnvelope, Any]] = []
    for candidate_ref in value.candidate_refs:
        candidate_envelope, candidate = _resolve_semantic_analysis_dependency(
            records,
            event_type="consolidation_candidate_registered",
            **partition,
            identity_field="candidate_id",
            identity=candidate_ref.candidate_id,
            content_hash_field="candidate_hash",
            content_hash=candidate_ref.candidate_hash,
        )
        expected_ref = {
            "candidate_id": candidate.candidate_id,
            "candidate_hash": candidate.candidate_hash,
            "assessment_id": candidate.assessment_id,
            "assessment_hash": candidate.assessment_fingerprint,
            "source_profile_hash": candidate.source_profile_fingerprint,
            "target_profile_hash": candidate.target_profile_fingerprint,
            "consumer_map_hash": consumer_map_hash(candidate.consumer_map),
            "scope_ref": candidate.scope_ref,
        }
        if candidate_ref.model_dump(mode="json") != expected_ref:
            raise AppendOnlyConflict(
                "consolidation decision binds a substituted current candidate"
            )
        candidate_dependencies.append((candidate_envelope, candidate))

    assessment_dependencies: list[tuple[ArtifactEnvelope, Any]] = []
    for assessment_ref in value.assessment_refs:
        assessment_envelope, assessment = _resolve_semantic_analysis_dependency(
            records,
            event_type="equivalence_assessment_registered",
            **partition,
            identity_field="assessment_id",
            identity=assessment_ref.assessment_id,
            content_hash_field="assessment_hash",
            content_hash=assessment_ref.assessment_hash,
        )
        expected_ref = {
            "assessment_id": assessment.assessment_id,
            "assessment_hash": assessment.assessment_hash,
            "overall_category": assessment.overall_category,
        }
        if assessment_ref.model_dump(mode="json") != expected_ref:
            raise AppendOnlyConflict(
                "consolidation decision binds a substituted current assessment"
            )
        assessment_dependencies.append((assessment_envelope, assessment))

    candidate_assessment_ids = {
        candidate.assessment_id for _envelope, candidate in candidate_dependencies
    }
    if candidate_assessment_ids != {
        assessment.assessment_id
        for _envelope, assessment in assessment_dependencies
    }:
        raise AppendOnlyConflict(
            "consolidation decision assessment set is not the exact candidate set"
        )
    if any(
        assessment.validation_context != value.validation_context
        for _envelope, assessment in assessment_dependencies
    ):
        raise AppendOnlyConflict(
            "consolidation decision validation context differs from its assessments"
        )
    expected_consumers = {
        consumer_id
        for _envelope, candidate in candidate_dependencies
        for consumer_id in candidate.consumer_map
    }
    if set(value.affected_consumer_ids) != expected_consumers:
        raise AppendOnlyConflict(
            "consolidation decision affected consumers are not the exact candidate union"
        )

    profile_dependencies = [
        _resolve_semantic_profile_dependency(
            records,
            **partition,
            profile_id=profile_ref.profile_id,
            profile_hash=profile_ref.profile_hash,
            asset_id=profile_ref.asset_id,
        )
        for profile_ref in value.member_profiles
    ]
    expected_member_keys = {
        (
            assessment.left_profile.profile_id,
            assessment.left_profile.asset_id,
            assessment.left_profile.profile_hash,
        )
        for _envelope, assessment in assessment_dependencies
    } | {
        (
            assessment.right_profile.profile_id,
            assessment.right_profile.asset_id,
            assessment.right_profile.profile_hash,
        )
        for _envelope, assessment in assessment_dependencies
    }
    actual_member_keys = {
        (item.profile_id, item.asset_id, item.profile_hash)
        for item in value.member_profiles
    }
    if actual_member_keys != expected_member_keys:
        raise AppendOnlyConflict(
            "consolidation decision members are not the exact assessment endpoints"
        )
    target_endpoint_keys = {
        (
            assessment.right_profile.profile_id,
            assessment.right_profile.asset_id,
            assessment.right_profile.profile_hash,
        )
        for _envelope, assessment in assessment_dependencies
    }
    if value.canonical_target_profile is not None and (
        (
            value.canonical_target_profile.profile_id,
            value.canonical_target_profile.asset_id,
            value.canonical_target_profile.profile_hash,
        )
        not in target_endpoint_keys
    ):
        raise AppendOnlyConflict(
            "consolidation decision canonical target is not a current target endpoint"
        )
    _require_semantic_dependency_lineage(
        envelope,
        (
            *(item for item, _value in candidate_dependencies),
            *(item for item, _value in assessment_dependencies),
            *(item for item, _value in profile_dependencies),
        ),
        dependency_kind="consolidation decision",
    )


_DASHBOARD_PREREQUISITE_EVENT_TYPES = frozenset(
    {
        "dashboard_source_acceptance_registered",
        "dashboard_topic_blueprint_registered",
        "dashboard_topic_readiness_registered",
        "dashboard_topic_component_registered",
        "dashboard_behavior_acceptance_registered",
        "dashboard_query_disposition_registered",
        "dashboard_query_mapping_registered",
        "dashboard_plan_acceptance_registered",
    }
)


def _dashboard_prerequisite_contract(event_type: str) -> tuple[Any, ...]:
    from omni_migrator.dashboards.rebuild_plan import (
        AcceptedBehaviorResolutionEvidence,
        AcceptedDashboardPlanRegistration,
        AcceptedDashboardTopicComponent,
        AcceptedDashboardTopicEvidence,
        AcceptedQueryDispositionEvidence,
        AcceptedQueryMappingEvidence,
        AcceptedSourceDashboardEvidence,
        RegisteredDashboardTopicEvidence,
    )

    contracts: dict[str, tuple[Any, ...]] = {
        "dashboard_source_acceptance_registered": (
            AcceptedSourceDashboardEvidence,
            lambda item: f"{item.migration_unit_id}:{item.page_id}",
            True,
        ),
        "dashboard_topic_blueprint_registered": (
            RegisteredDashboardTopicEvidence,
            lambda item: item.blueprint_id,
            True,
        ),
        "dashboard_topic_readiness_registered": (
            AcceptedDashboardTopicEvidence,
            lambda item: item.blueprint_id,
            False,
        ),
        "dashboard_topic_component_registered": (
            AcceptedDashboardTopicComponent,
            lambda item: (
                f"{item.blueprint_id}:{item.component_kind}:{item.component_id}"
            ),
            False,
        ),
        "dashboard_behavior_acceptance_registered": (
            AcceptedBehaviorResolutionEvidence,
            lambda item: f"{item.plan_id}:{item.resolution_id}",
            False,
        ),
        "dashboard_query_disposition_registered": (
            AcceptedQueryDispositionEvidence,
            lambda item: f"{item.plan_id}:{item.query_id}",
            False,
        ),
        "dashboard_query_mapping_registered": (
            AcceptedQueryMappingEvidence,
            lambda item: f"{item.plan_id}:{item.query_id}",
            False,
        ),
        "dashboard_plan_acceptance_registered": (
            AcceptedDashboardPlanRegistration,
            lambda item: item.plan_id,
            True,
        ),
    }
    if event_type not in contracts:
        raise ValueError(f"unsupported dashboard prerequisite event: {event_type}")
    return contracts[event_type]


def _dashboard_registration_hash(payload: Mapping[str, Any]) -> str:
    material = dict(payload)
    material.pop("registration_hash", None)
    return f"sha256:{sha256_json(material)}"


def _parse_dashboard_prerequisite_event(
    record: Mapping[str, Any],
) -> tuple[dict[str, Any], Any, ArtifactEnvelope | None]:
    """Validate one typed dashboard prerequisite registration from the ledger."""

    payload = record.get("payload", {})
    event_type = str(payload.get("event_type", ""))
    model_type, natural_key, artifact_required = _dashboard_prerequisite_contract(
        event_type
    )
    required = {
        "event_type",
        "tenant_ref",
        "run_id",
        "scope_id",
        "wave_id",
        "migration_unit_id",
        "validation_cycle_id",
        "natural_key",
        "evidence",
        "evidence_hash",
        "topic_blueprint",
        "artifact",
        "registration_revision",
        "supersedes_registration_hash",
        "registered_by_ref",
        "registered_at",
        "registration_hash",
    }
    if set(payload) != required:
        raise AppendOnlyConflict(
            f"{event_type} dashboard prerequisite registration has an invalid shape"
        )
    evidence_raw = payload.get("evidence")
    if not isinstance(evidence_raw, Mapping):
        raise AppendOnlyConflict(f"{event_type} dashboard evidence is malformed")
    try:
        evidence = model_type.model_validate_json(canonical_json(evidence_raw))
        parse_time(str(payload.get("registered_at", "")))
        validate_reference(str(payload.get("tenant_ref", "")))
        validate_reference(str(payload.get("registered_by_ref", "")))
    except (TypeError, ValueError) as exc:
        raise AppendOnlyConflict(
            f"{event_type} dashboard prerequisite registration is invalid"
        ) from exc
    if (
        record.get("tenant_ref") != payload.get("tenant_ref")
        or record.get("run_id") != payload.get("run_id")
        or evidence.model_dump(mode="json") != dict(evidence_raw)
        or evidence.run_id != payload.get("run_id")
        or evidence.scope_id != payload.get("scope_id")
        or str(payload.get("natural_key")) != natural_key(evidence)
        or payload.get("evidence_hash")
        != f"sha256:{sha256_json(evidence.model_dump(mode='json'))}"
        or payload.get("registration_hash") != _dashboard_registration_hash(payload)
        or not str(payload.get("wave_id", ""))
        or not str(payload.get("migration_unit_id", ""))
        or not str(payload.get("validation_cycle_id", ""))
        or not str(payload.get("registered_by_ref", "")).startswith(
            ("agent-ref://", "human-ref://", "person-ref://", "person://")
        )
    ):
        raise AppendOnlyConflict(
            f"{event_type} dashboard prerequisite registration is not canonical"
        )
    revision = int(payload.get("registration_revision", 0))
    predecessor = payload.get("supersedes_registration_hash")
    if revision < 1 or (revision == 1) != (predecessor is None):
        raise AppendOnlyConflict(
            f"{event_type} dashboard prerequisite revision chain is invalid"
        )
    if event_type == "dashboard_source_acceptance_registered" and (
        evidence.migration_unit_id != payload.get("migration_unit_id")
    ):
        raise AppendOnlyConflict("dashboard source acceptance crosses migration unit")
    if event_type == "dashboard_topic_blueprint_registered" and (
        evidence.validation_cycle_id != payload.get("validation_cycle_id")
    ):
        raise AppendOnlyConflict("dashboard Topic registration crosses validation cycle")
    if event_type == "dashboard_topic_readiness_registered" and (
        payload.get("validation_cycle_id") not in evidence.validation_cycle_ids
    ):
        raise AppendOnlyConflict("dashboard Topic readiness crosses validation cycle")
    if event_type == "dashboard_plan_acceptance_registered" and (
        evidence.migration_unit_id != payload.get("migration_unit_id")
        or evidence.validation_cycle_id != payload.get("validation_cycle_id")
    ):
        raise AppendOnlyConflict("dashboard plan acceptance crosses its partition")

    raw_topic = payload.get("topic_blueprint")
    if event_type == "dashboard_topic_blueprint_registered":
        from omni_migrator.semantic.topic_blueprints import TopicBlueprint

        if not isinstance(raw_topic, Mapping):
            raise AppendOnlyConflict(
                "dashboard Topic registration is missing its typed blueprint payload"
            )
        try:
            topic = TopicBlueprint.model_validate_json(canonical_json(raw_topic))
        except (TypeError, ValueError) as exc:
            raise AppendOnlyConflict(
                "dashboard Topic registration blueprint payload is invalid"
            ) from exc
        if (
            topic.model_dump(mode="json") != dict(raw_topic)
            or topic.run_id != evidence.run_id
            or topic.scope_id != evidence.scope_id
            or topic.blueprint_id != evidence.blueprint_id
            or topic.blueprint_hash != evidence.blueprint_hash
        ):
            raise AppendOnlyConflict(
                "dashboard Topic registration blueprint payload is not exact"
            )
    elif raw_topic is not None:
        raise AppendOnlyConflict(
            f"{event_type} cannot carry a dashboard Topic blueprint payload"
        )

    raw_artifact = payload.get("artifact")
    if artifact_required != isinstance(raw_artifact, Mapping):
        raise AppendOnlyConflict(
            f"{event_type} dashboard prerequisite artifact binding is invalid"
        )
    envelope: ArtifactEnvelope | None = None
    if isinstance(raw_artifact, Mapping):
        try:
            envelope = ArtifactEnvelope.from_mapping(raw_artifact)
            envelope.validate(
                expected_tenant_ref=str(payload["tenant_ref"]),
                expected_run_id=str(payload["run_id"]),
            )
        except (TypeError, ValueError) as exc:
            raise AppendOnlyConflict(
                f"{event_type} dashboard prerequisite artifact is invalid"
            ) from exc
        if (
            envelope.migration_unit_id != payload.get("migration_unit_id")
            or envelope.validation_cycle_id != payload.get("validation_cycle_id")
        ):
            raise AppendOnlyConflict(
                f"{event_type} dashboard prerequisite artifact crosses its partition"
            )
    return dict(payload), evidence, envelope


def _current_dashboard_prerequisite_events(
    records: list[dict[str, Any]],
    *,
    event_type: str,
    tenant_ref: str,
    run_id: str,
    scope_id: str,
    wave_id: str,
    migration_unit_id: str,
    validation_cycle_id: str,
) -> dict[str, tuple[dict[str, Any], Any, ArtifactEnvelope | None]]:
    """Resolve one exact partition's latest, contiguous typed registrations."""

    by_key: dict[str, list[tuple[dict[str, Any], Any, ArtifactEnvelope | None]]] = {}
    for record in records:
        payload = record.get("payload", {})
        if (
            record.get("record_type") != "event"
            or payload.get("event_type") != event_type
        ):
            continue
        parsed = _parse_dashboard_prerequisite_event(record)
        registration = parsed[0]
        if (
            registration["tenant_ref"] != tenant_ref
            or registration["run_id"] != run_id
            or registration["scope_id"] != scope_id
            or registration["wave_id"] != wave_id
            or registration["migration_unit_id"] != migration_unit_id
            or registration["validation_cycle_id"] != validation_cycle_id
        ):
            continue
        by_key.setdefault(str(registration["natural_key"]), []).append(parsed)
    current: dict[str, tuple[dict[str, Any], Any, ArtifactEnvelope | None]] = {}
    for natural_key, registrations in by_key.items():
        registrations.sort(key=lambda item: int(item[0]["registration_revision"]))
        if [int(item[0]["registration_revision"]) for item in registrations] != list(
            range(1, len(registrations) + 1)
        ):
            raise AppendOnlyConflict(
                f"{event_type} dashboard prerequisite revisions are not contiguous"
            )
        for index, registration in enumerate(registrations):
            predecessor = registrations[index - 1][0] if index else None
            expected = predecessor["registration_hash"] if predecessor else None
            if registration[0]["supersedes_registration_hash"] != expected:
                raise AppendOnlyConflict(
                    f"{event_type} dashboard prerequisite predecessor is stale"
                )
        current[natural_key] = registrations[-1]
    return current


def _dashboard_prerequisite_is_current(
    records: list[dict[str, Any]],
    *,
    event_type: str,
    registration: Mapping[str, Any],
    evidence: Any,
    artifact: ArtifactEnvelope | None,
) -> bool:
    if artifact is not None and not _artifact_envelope_is_exactly_current(
        records, artifact
    ):
        return False
    if event_type == "dashboard_source_acceptance_registered":
        artifact_is_current_source = bool(
            artifact
            and artifact.artifact_type
            in {
                "source_object_graph",
                "inventory_snapshot",
                "domo_portfolio_inventory",
                "evidence_bundle",
            }
            and artifact.ref == evidence.source_artifact_ref
            and artifact.content_sha256 == evidence.source_artifact_content_sha256
        )
        if not artifact_is_current_source:
            return False
        return _dashboard_source_acceptance_matches_canonical_domo(
            records,
            registration=registration,
            evidence=evidence,
        )
    if event_type == "dashboard_topic_blueprint_registered":
        return bool(
            artifact
            and artifact.artifact_type == "topic_blueprint"
            and artifact.ref == evidence.artifact_ref
            and artifact.producer_ref
            in {
                "agent-ref://domo-to-omni-architect",
                "agent-ref://domo_to_omni_architect",
            }
            and artifact.content_sha256
            == sha256_json(registration["topic_blueprint"])
        )
    if event_type == "dashboard_plan_acceptance_registered":
        if not artifact or artifact.artifact_type != "dashboard_rebuild_plan":
            return False
        from omni_migrator.dashboards.rebuild_plan import (
            DashboardRebuildPlan,
            dashboard_plan_content_sha256,
        )

        plans = []
        for record in records:
            payload = record.get("payload", {})
            if (
                record.get("record_type") != "event"
                or payload.get("event_type") != "dashboard_plan_payload_registered"
                or not isinstance(payload.get("plan"), Mapping)
            ):
                continue
            try:
                plan = DashboardRebuildPlan.model_validate_json(
                    canonical_json(payload["plan"])
                )
            except (TypeError, ValueError):
                return False
            if plan.plan_id == evidence.plan_id:
                plans.append(plan)
        return bool(
            len(plans) == 1
            and plans[0].plan_hash == evidence.plan_hash
            and dashboard_plan_content_sha256(plans[0]) == artifact.content_sha256
        )
    return artifact is None


def _dashboard_source_acceptance_matches_canonical_domo(
    records: list[dict[str, Any]],
    *,
    registration: Mapping[str, Any],
    evidence: Any,
) -> bool:
    """Bind profile-aware dashboard acceptance to the canonical Domo denominator.

    Older acceptance records did not carry a Page semantic-profile binding.  Keep
    those records readable under their original envelope-only contract.  Once a
    caller supplies that binding, fail closed unless the accepted Page and Card
    set is the exact current Page lineage in the canonical portfolio, every
    dashboard-query requirement resolves its evidence-built profile, and one
    registered plan binds the accepted query IDs to those Card profiles.
    """

    if evidence.page_profile_id is None:
        return True

    tenant_ref = str(registration.get("tenant_ref", ""))
    run_id = str(registration.get("run_id", ""))
    scope_id = str(registration.get("scope_id", ""))
    migration_unit_id = str(registration.get("migration_unit_id", ""))
    validation_cycle_id = str(registration.get("validation_cycle_id", ""))
    portfolio = _registered_domo_portfolio(
        records,
        tenant_ref=tenant_ref,
        run_id=run_id,
        scope_id=scope_id,
    )
    if (
        portfolio is None
        or portfolio.get("summary", {}).get("catalog_state") != "complete"
    ):
        return False

    objects = [
        item for item in portfolio.get("objects", []) if isinstance(item, Mapping)
    ]
    page_matches = [
        item
        for item in objects
        if item.get("identity", {}).get("object_type") == "page"
        and item.get("identity", {}).get("native_id") == evidence.page_id
    ]
    if len(page_matches) != 1:
        return False
    page = page_matches[0]
    card_by_object_id = {
        str(item.get("identity", {}).get("object_id")): item
        for item in objects
        if item.get("identity", {}).get("object_type") == "card"
    }
    page_card_object_ids = {
        str(object_id)
        for object_id in page.get("lineage", {}).get("consumer_object_ids", [])
        if str(object_id) in card_by_object_id
    }
    cards = [card_by_object_id[object_id] for object_id in page_card_object_ids]
    if (
        len(cards) != len(evidence.card_ids)
        or {item.get("identity", {}).get("native_id") for item in cards}
        != set(evidence.card_ids)
    ):
        return False

    requirements_by_native_id: dict[str, Mapping[str, Any]] = {}
    for item in (page, *cards):
        requirements = [
            requirement
            for requirement in item.get("semantic_profile_requirements", [])
            if isinstance(requirement, Mapping)
            and requirement.get("profile_kind") == "dashboard_query"
        ]
        if len(requirements) != 1:
            return False
        requirements_by_native_id[
            str(item.get("identity", {}).get("native_id", ""))
        ] = requirements[0]

    profiles = _registered_semantic_profiles(
        records,
        tenant_ref=tenant_ref,
        run_id=run_id,
        scope_id=scope_id,
        migration_unit_id=migration_unit_id,
        validation_cycle_id=validation_cycle_id,
    )
    profiles_by_native_id: dict[str, Any] = {}
    for native_id, requirement in requirements_by_native_id.items():
        matches = [
            profile
            for envelope, profile in profiles
            if envelope.artifact_type == "semantic_profile"
            and profile.identity.system == "domo"
            and profile.identity.kind == "dashboard_query"
            and profile.provenance.get("source_native_id") == native_id
            and profile.provenance.get("semantic_profile_requirement_id")
            == requirement.get("requirement_id")
            and profile.provenance.get("semantic_profile_requirement_hash")
            == requirement.get("requirement_hash")
        ]
        if len(matches) != 1:
            return False
        profiles_by_native_id[native_id] = matches[0]

    page_profile = profiles_by_native_id[evidence.page_id]
    if (
        page_profile.profile_id != evidence.page_profile_id
        or page_profile.profile_hash != evidence.page_profile_hash
        or page_profile.identity.object_id != evidence.page_profile_asset_id
    ):
        return False

    from omni_migrator.dashboards.rebuild_plan import DashboardRebuildPlan

    for record in records:
        payload = record.get("payload", {})
        if (
            record.get("record_type") != "event"
            or payload.get("event_type") != "dashboard_plan_payload_registered"
            or not isinstance(payload.get("plan"), Mapping)
        ):
            continue
        try:
            plan = DashboardRebuildPlan.model_validate_json(
                canonical_json(payload["plan"])
            )
        except (TypeError, ValueError):
            return False
        if (
            plan.run_id != run_id
            or plan.scope_id != scope_id
            or plan.migration_unit_id != migration_unit_id
            or plan.validation_cycle_id != validation_cycle_id
            or plan.source.page.object_id != evidence.page_id
            or plan.source.page_profile_id != evidence.page_profile_id
            or plan.source.page_profile_hash != evidence.page_profile_hash
            or plan.source.page_profile_asset_id != evidence.page_profile_asset_id
            or {item.card.object_id for item in plan.source.cards}
            != set(evidence.card_ids)
            or {item.placement_id for item in plan.source.placements}
            != set(evidence.placement_ids)
            or {item.query.object_id for item in plan.source.queries}
            != set(evidence.query_ids)
            or plan.source.context.context_hash != evidence.source_context_hash
            or plan.source.denominator_hash != evidence.denominator_hash
        ):
            continue
        queries_by_card: dict[str, list[Any]] = {}
        for query in plan.source.queries:
            queries_by_card.setdefault(query.card_id, []).append(query)
        if all(
            all(
                query.source_profile_id == profiles_by_native_id[card_id].profile_id
                and query.source_profile_hash
                == profiles_by_native_id[card_id].profile_hash
                and query.source_profile_asset_id
                == profiles_by_native_id[card_id].identity.object_id
                for query in queries_by_card.get(card_id, [])
            )
            for card_id in evidence.card_ids
        ):
            return True
    return False


def _assert_dashboard_snapshot_current_registrations(
    records: list[dict[str, Any]], snapshot: Any
) -> tuple[ArtifactEnvelope, ...]:
    """Fail closed unless every snapshot claim equals one current typed event."""

    partition = {
        "tenant_ref": snapshot.tenant_ref,
        "run_id": snapshot.run_id,
        "scope_id": snapshot.scope_id,
        "wave_id": snapshot.wave_id,
        "migration_unit_id": snapshot.migration_unit_id,
        "validation_cycle_id": snapshot.validation_cycle_id,
    }
    families = (
        ("dashboard_source_acceptance_registered", snapshot.source_dashboards),
        ("dashboard_topic_blueprint_registered", snapshot.registered_topics),
        ("dashboard_topic_readiness_registered", snapshot.accepted_topics),
        ("dashboard_topic_component_registered", snapshot.topic_components),
        ("dashboard_behavior_acceptance_registered", snapshot.behavior_resolutions),
        ("dashboard_query_disposition_registered", snapshot.query_dispositions),
        ("dashboard_query_mapping_registered", snapshot.query_mappings),
        ("dashboard_plan_acceptance_registered", snapshot.plan_registrations),
    )
    required_artifacts: list[ArtifactEnvelope] = []
    family_current: dict[
        str, dict[str, tuple[dict[str, Any], Any, ArtifactEnvelope | None]]
    ] = {}
    for event_type, expected_values in families:
        model_type, natural_key, _artifact_required = _dashboard_prerequisite_contract(
            event_type
        )
        current = _current_dashboard_prerequisite_events(
            records, event_type=event_type, **partition
        )
        family_current[event_type] = current
        for expected in expected_values:
            value = (
                expected
                if isinstance(expected, model_type)
                else model_type.model_validate_json(canonical_json(expected))
            )
            resolved = current.get(natural_key(value))
            if (
                resolved is None
                or resolved[1].model_dump(mode="json")
                != value.model_dump(mode="json")
                or not _dashboard_prerequisite_is_current(
                    records,
                    event_type=event_type,
                    registration=resolved[0],
                    evidence=resolved[1],
                    artifact=resolved[2],
                )
                or parse_time(resolved[0]["registered_at"])
                > parse_time(snapshot.registered_at)
            ):
                raise AppendOnlyConflict(
                    f"dashboard snapshot lacks exact current {event_type} evidence"
                )
            if resolved[2] is not None:
                required_artifacts.append(resolved[2])

    topics = {item.blueprint_id: item for item in snapshot.topic_blueprints}
    for registration in snapshot.registered_topics:
        topic = topics.get(registration.blueprint_id)
        resolved = family_current["dashboard_topic_blueprint_registered"].get(
            registration.blueprint_id
        )
        if (
            topic is None
            or resolved is None
            or resolved[2] is None
            or resolved[2].content_sha256
            != sha256_json(topic.model_dump(mode="json"))
            or topic.blueprint_hash != registration.blueprint_hash
        ):
            raise AppendOnlyConflict(
                "dashboard Topic blueprint is not its exact current typed registration"
            )

    profiles = {
        profile.profile_id: (artifact, profile)
        for artifact, profile in _registered_semantic_profiles(
            records,
            tenant_ref=snapshot.tenant_ref,
            run_id=snapshot.run_id,
            scope_id=snapshot.scope_id,
            migration_unit_id=snapshot.migration_unit_id,
            validation_cycle_id=snapshot.validation_cycle_id,
        )
    }
    for expected in snapshot.profiles:
        resolved = profiles.get(expected.profile_id)
        if (
            resolved is None
            or resolved[1].model_dump(mode="json")
            != expected.model_dump(mode="json")
        ):
            raise AppendOnlyConflict(
                "dashboard snapshot semantic profile is unregistered or stale: "
                f"{expected.profile_id}"
            )
        required_artifacts.append(resolved[0])

    decisions = {
        decision.decision_id: (artifact, decision)
        for artifact, decision in _registered_semantic_analysis_payloads(
            records,
            event_type="consolidation_decision_registered",
            tenant_ref=snapshot.tenant_ref,
            run_id=snapshot.run_id,
            scope_id=snapshot.scope_id,
            migration_unit_id=snapshot.migration_unit_id,
            validation_cycle_id=snapshot.validation_cycle_id,
        )
    }
    for expected in snapshot.decisions:
        resolved = decisions.get(expected.decision_id)
        if resolved is None or resolved[1] != expected:
            raise AppendOnlyConflict(
                "dashboard snapshot consolidation decision is unregistered or stale"
            )
        required_artifacts.append(resolved[0])

    identities = [
        (item.artifact_id, item.revision, item.content_sha256)
        for item in required_artifacts
    ]
    if len(identities) != len(set(identities)):
        raise AppendOnlyConflict(
            "dashboard snapshot resolves duplicate upstream artifact registrations"
        )
    return tuple(required_artifacts)


def _semantic_profile_coverage_context(
    records: list[dict[str, Any]],
    coverage: Any,
) -> tuple[Any, tuple[ArtifactEnvelope, ...]]:
    from omni_migrator.semantic.coverage import (
        CurrentSemanticProfileEvidence,
        CoverageRevisionBindings,
        SemanticProfileCoverageValidationContext,
        coverage_artifact_revision_binding,
        derive_semantic_profile_subject_denominator,
    )

    portfolio = _registered_domo_portfolio(
        records,
        tenant_ref=coverage.tenant_ref,
        run_id=coverage.run_id,
        scope_id=coverage.scope_id,
    )
    if portfolio is None:
        raise AppendOnlyConflict(
            "semantic-profile coverage requires a registered current Domo portfolio"
        )
    portfolio_events = [
        record.get("payload", {})
        for record in records
        if record.get("record_type") == "event"
        and record.get("payload", {}).get("event_type")
        == "domo_portfolio_inventory_registered"
        and record.get("payload", {}).get("portfolio") == portfolio
    ]
    if len(portfolio_events) != 1:
        raise AppendOnlyConflict(
            "semantic-profile coverage requires exactly one portfolio registration"
        )
    portfolio_envelope = ArtifactEnvelope.from_mapping(portfolio_events[0]["artifact"])
    source_snapshot_envelope = _current_artifact_envelope_by_ref(
        records,
        artifact_ref=str(portfolio["inventory_snapshot_ref"]),
    )
    if source_snapshot_envelope is None:
        raise AppendOnlyConflict(
            "semantic-profile coverage source snapshot is unavailable or stale"
        )
    scopes = _registered_migration_scopes(
        records,
        tenant_ref=coverage.tenant_ref,
        run_id=coverage.run_id,
        scope_id=coverage.scope_id,
        migration_unit_id=coverage.migration_unit_id,
        validation_cycle_id=coverage.validation_cycle_id,
    )
    repositories = _registered_repository_inventories(
        records,
        tenant_ref=coverage.tenant_ref,
        run_id=coverage.run_id,
        migration_unit_id=coverage.migration_unit_id,
        validation_cycle_id=coverage.validation_cycle_id,
    )
    profiles = _registered_semantic_profiles(
        records,
        tenant_ref=coverage.tenant_ref,
        run_id=coverage.run_id,
        scope_id=coverage.scope_id,
        migration_unit_id=coverage.migration_unit_id,
        validation_cycle_id=coverage.validation_cycle_id,
    )
    if len(scopes) != 1 or len(repositories) != 1:
        raise AppendOnlyConflict(
            "semantic-profile coverage requires exactly one current scope and repository inventory"
        )
    target_profiles = [
        item
        for item in profiles
        if item[0].artifact_type == "target_semantic_profile"
    ]
    if not target_profiles:
        raise AppendOnlyConflict(
            "semantic-profile coverage requires at least one current target proposal"
        )
    target_profiles.sort(
        key=lambda item: (
            item[1].profile_id,
            item[0].artifact_id,
            item[0].revision,
        )
    )
    scope_envelope, scope = scopes[0]
    repository_envelope, repository = repositories[0]
    bindings = CoverageRevisionBindings(
        source_snapshot=coverage_artifact_revision_binding(
            source_snapshot_envelope,
            scope_id=coverage.scope_id,
            migration_unit_id=coverage.migration_unit_id,
            semantic_hash=f"sha256:{source_snapshot_envelope.content_sha256}",
        ),
        portfolio=coverage_artifact_revision_binding(
            portfolio_envelope,
            scope_id=coverage.scope_id,
            migration_unit_id=coverage.migration_unit_id,
            semantic_hash=str(portfolio["portfolio_hash"]),
        ),
        migration_scope=coverage_artifact_revision_binding(
            scope_envelope,
            scope_id=coverage.scope_id,
            migration_unit_id=coverage.migration_unit_id,
            semantic_hash=str(scope["scope_hash"]),
        ),
        repository=coverage_artifact_revision_binding(
            repository_envelope,
            scope_id=coverage.scope_id,
            migration_unit_id=coverage.migration_unit_id,
            semantic_hash=str(repository["inventory_hash"]),
        ),
        target_proposals=tuple(
            coverage_artifact_revision_binding(
                target_envelope,
                scope_id=coverage.scope_id,
                migration_unit_id=coverage.migration_unit_id,
                semantic_hash=target_profile.profile_hash,
            )
            for target_envelope, target_profile in target_profiles
        ),
    )
    subjects = derive_semantic_profile_subject_denominator(
        portfolio=portfolio,
        migration_scope=scope,
        repository_inventory=repository,
        target_profiles=[profile for _envelope, profile in target_profiles],
        revision_bindings=bindings,
        migration_unit_id=coverage.migration_unit_id,
    )
    subjects_by_identity = {
        subject.profile_identity: subject for subject in subjects
    }
    subjects_by_ref = {subject.subject_ref: subject for subject in subjects}
    resolutions_by_ref = {
        resolution.subject_ref: resolution for resolution in coverage.resolutions
    }
    current_profiles: list[CurrentSemanticProfileEvidence] = []
    for envelope, profile in profiles:
        subject = subjects_by_identity.get(profile.identity)
        if subject is None:
            lineage = profile.provenance.get("semantic_coverage_lineage")
            if not isinstance(lineage, Mapping) or set(lineage) != {
                "subject_ref",
                "subject_hash",
                "base_profile_id",
                "base_profile_hash",
            }:
                raise AppendOnlyConflict(
                    "current semantic profile is outside the derived coverage denominator "
                    "and lacks exact semantic-coverage lineage"
                )
            base_subject = subjects_by_ref.get(str(lineage["subject_ref"]))
            resolution = resolutions_by_ref.get(str(lineage["subject_ref"]))
            base_profile = resolution.profile if resolution is not None else None
            upstream_ids = {
                *profile.lineage.authoritative_source_ids,
                *profile.lineage.upstream_asset_ids,
            }
            if (
                base_subject is None
                or str(lineage["subject_hash"]) != base_subject.subject_hash
                or resolution is None
                or resolution.subject_hash != base_subject.subject_hash
                or resolution.disposition != "profile"
                or base_profile is None
                or str(lineage["base_profile_id"]) != base_profile.profile_id
                or str(lineage["base_profile_hash"]) != base_profile.profile_hash
                or base_subject.profile_identity.object_id not in upstream_ids
            ):
                raise AppendOnlyConflict(
                    "semantic profile descendant does not resolve to one exact covered subject"
                )
            continue
        current_profiles.append(
            CurrentSemanticProfileEvidence(
                subject_ref=subject.subject_ref,
                artifact=coverage_artifact_revision_binding(
                    envelope,
                    scope_id=coverage.scope_id,
                    migration_unit_id=coverage.migration_unit_id,
                    semantic_hash=profile.profile_hash,
                ),
                profile=profile,
            )
        )
    context = SemanticProfileCoverageValidationContext(
        tenant_ref=coverage.tenant_ref,
        run_id=coverage.run_id,
        scope_id=coverage.scope_id,
        migration_unit_id=coverage.migration_unit_id,
        validation_cycle_id=coverage.validation_cycle_id,
        revision_bindings=bindings,
        expected_subjects=subjects,
        current_profiles=tuple(current_profiles),
    )
    upstream = (
        source_snapshot_envelope,
        portfolio_envelope,
        scope_envelope,
        repository_envelope,
        *(envelope for envelope, _profile in profiles),
    )
    deduplicated = {
        (item.artifact_id, item.revision, item.content_sha256): item
        for item in upstream
    }
    return context, tuple(deduplicated.values())


def _registered_semantic_profile_coverages(
    records: list[dict[str, Any]],
    *,
    tenant_ref: str,
    run_id: str,
    scope_id: str,
    migration_unit_id: str,
    validation_cycle_id: str,
) -> tuple[tuple[ArtifactEnvelope, Any], ...]:
    from omni_migrator.semantic.coverage import (
        SemanticProfileCoverage,
        semantic_profile_coverage_content_sha256,
        validate_semantic_profile_coverage,
    )

    matches: list[tuple[ArtifactEnvelope, Any]] = []
    all_coverages: list[tuple[ArtifactEnvelope, Any]] = []
    for record in records:
        payload = record.get("payload", {})
        if record.get("record_type") != "event" or payload.get(
            "event_type"
        ) != "semantic_profile_coverage_registered":
            continue
        if set(payload) != {"event_type", "artifact", "coverage"}:
            raise AppendOnlyConflict(
                "semantic-profile coverage registration has an invalid shape"
            )
        if not isinstance(payload.get("artifact"), Mapping) or not isinstance(
            payload.get("coverage"), Mapping
        ):
            raise AppendOnlyConflict("semantic-profile coverage registration is malformed")
        try:
            coverage = SemanticProfileCoverage.model_validate_json(
                canonical_json(payload["coverage"])
            )
            envelope = ArtifactEnvelope.from_mapping(payload["artifact"])
            envelope.validate(
                expected_tenant_ref=tenant_ref,
                expected_run_id=run_id,
            )
        except (TypeError, ValueError) as exc:
            raise AppendOnlyConflict(
                "semantic-profile coverage registration is invalid"
            ) from exc
        if (
            coverage.tenant_ref != tenant_ref
            or coverage.run_id != run_id
            or envelope.artifact_type != "semantic_profile_coverage"
            or envelope.artifact_id != coverage.coverage_id
            or envelope.revision != coverage.coverage_revision
            or envelope.content_sha256
            != semantic_profile_coverage_content_sha256(coverage)
            or envelope.producer_ref != coverage.producer_ref
            or envelope.migration_unit_id != coverage.migration_unit_id
            or envelope.validation_cycle_id != coverage.validation_cycle_id
        ):
            raise AppendOnlyConflict(
                "semantic-profile coverage registration is not canonically artifact-bound"
            )
        all_coverages.append((envelope, coverage))
        if (
            coverage.scope_id != scope_id
            or coverage.migration_unit_id != migration_unit_id
            or coverage.validation_cycle_id != validation_cycle_id
            or not _artifact_envelope_is_exactly_current(records, envelope)
        ):
            continue
        context, upstream = _semantic_profile_coverage_context(records, coverage)
        errors = validate_semantic_profile_coverage(
            coverage,
            validation_context=context,
        )
        expected_lineage = {
            (item.artifact_id, item.revision, item.content_sha256)
            for item in upstream
        }
        actual_lineage = {
            (
                str(item.get("artifact_id", "")),
                int(item.get("revision", 0)),
                str(item.get("content_sha256", "")),
            )
            for item in envelope.input_artifacts
        }
        if errors or actual_lineage != expected_lineage:
            raise AppendOnlyConflict(
                "semantic-profile coverage registration is stale or incomplete: "
                + "; ".join(errors)
            )
        if coverage.coverage_revision > 1:
            prior = [
                item
                for prior_envelope, item in all_coverages
                if prior_envelope.artifact_id == envelope.artifact_id
                and prior_envelope.revision == envelope.revision - 1
            ]
            if len(prior) != 1 or coverage.supersedes_coverage_hash != prior[0].coverage_hash:
                raise AppendOnlyConflict(
                    "semantic-profile coverage revision chain is broken"
                )
        matches.append((envelope, coverage))
    if len(matches) > 1:
        raise AppendOnlyConflict(
            "more than one current semantic-profile coverage is registered for the unit and cycle"
        )
    return tuple(matches)


def _registered_external_redesign_handoffs(
    records: list[dict[str, Any]],
    *,
    tenant_ref: str,
    run_id: str,
    scope_id: str,
) -> tuple[Any, ...]:
    from omni_migrator.control_plane.external_handoffs import (
        external_redesign_handoff_content_sha256,
        finalize_external_redesign_handoff,
        validate_external_redesign_handoff,
    )

    portfolio = _registered_domo_portfolio(
        records,
        tenant_ref=tenant_ref,
        run_id=run_id,
        scope_id=scope_id,
    )
    portfolio_objects = (
        {
            item["identity"]["object_id"]: item
            for item in portfolio.get("objects", [])
        }
        if portfolio is not None
        else {}
    )
    portfolio_artifacts = [
        ArtifactEnvelope.from_mapping(record.get("payload", {}).get("artifact", {}))
        for record in records
        if record.get("record_type") == "event"
        and record.get("payload", {}).get("event_type")
        == "domo_portfolio_inventory_registered"
        and record.get("payload", {}).get("portfolio", {}).get("scope_id")
        == scope_id
    ]
    if portfolio is not None and len(portfolio_artifacts) != 1:
        raise AppendOnlyConflict(
            "external redesign handoff requires one exact registered portfolio artifact"
        )
    portfolio_artifact = portfolio_artifacts[0] if portfolio_artifacts else None
    resolved: list[Any] = []
    seen_refs: set[str] = set()
    for record in records:
        payload = record.get("payload", {})
        if (
            record.get("record_type") != "event"
            or payload.get("event_type") != "external_redesign_handoff_registered"
        ):
            continue
        if set(payload) != {"event_type", "artifact", "handoff"}:
            raise AppendOnlyConflict(
                "external redesign handoff registration has an invalid shape"
            )
        raw_artifact = payload.get("artifact")
        raw_handoff = payload.get("handoff")
        if not isinstance(raw_artifact, Mapping) or not isinstance(
            raw_handoff, Mapping
        ):
            raise AppendOnlyConflict(
                "external redesign handoff registration is malformed"
            )
        if raw_handoff.get("scope_id") != scope_id:
            continue
        if validate_external_redesign_handoff(raw_handoff):
            raise AppendOnlyConflict(
                "external redesign handoff registration is not canonical"
            )
        handoff = finalize_external_redesign_handoff(raw_handoff)
        if handoff.model_dump(mode="json") != dict(raw_handoff):
            raise AppendOnlyConflict(
                "external redesign handoff registration was not pre-finalized"
            )
        try:
            envelope = ArtifactEnvelope.from_mapping(raw_artifact)
            envelope.validate(
                expected_tenant_ref=tenant_ref,
                expected_run_id=run_id,
            )
        except (TypeError, ValueError) as exc:
            raise AppendOnlyConflict(
                "external redesign handoff artifact envelope is invalid"
            ) from exc
        if (
            handoff.tenant_ref != tenant_ref
            or handoff.run_id != run_id
            or envelope.artifact_type != "external_redesign_assignment"
            or envelope.ref != handoff.handoff_ref
            or envelope.content_sha256
            != external_redesign_handoff_content_sha256(handoff)
            or envelope.producer_ref
            != "agent-ref://domo-to-omni-architect"
            or envelope.producer_work_package_id
            != handoff.assignment_work_package_id
            or envelope.migration_unit_id != handoff.migration_unit_id
            or envelope.validation_cycle_id != handoff.validation_cycle_id
            or not _artifact_envelope_is_exactly_current(records, envelope)
        ):
            raise AppendOnlyConflict(
                "external redesign handoff artifact binding is not exact or current"
            )
        if portfolio is None:
            raise AppendOnlyConflict(
                "external redesign handoff requires the current registered portfolio"
            )
        portfolio_input = (
            {
                "artifact_id": portfolio_artifact.artifact_id,
                "revision": portfolio_artifact.revision,
                "content_sha256": portfolio_artifact.content_sha256,
            }
            if portfolio_artifact is not None
            else None
        )
        if portfolio_input not in [dict(item) for item in envelope.input_artifacts]:
            raise AppendOnlyConflict(
                "external redesign handoff lacks exact current portfolio artifact lineage"
            )
        expected_source_ids = {
            object_id
            for object_id, item in portfolio_objects.items()
            if handoff.handoff_ref in item.get("redesign_handoff_refs", [])
        }
        actual_source_ids = {item.object_id for item in handoff.source_objects}
        if actual_source_ids != expected_source_ids:
            raise AppendOnlyConflict(
                "external redesign handoff does not cover its exact portfolio object set"
            )
        for source in handoff.source_objects:
            item = portfolio_objects.get(source.object_id)
            if (
                item is None
                or item.get("identity", {}).get("object_type")
                != source.object_type
                or item.get("identity", {}).get("native_id") != source.native_id
                or item.get("object_hash") != source.object_hash
                or item.get("external_handoff_required") is not True
                or handoff.handoff_ref not in item.get("redesign_handoff_refs", [])
            ):
                raise AppendOnlyConflict(
                    "external redesign handoff does not match its exact portfolio objects"
                )
        for output in handoff.analytic_outputs:
            item = portfolio_objects.get(output.object_id)
            if (
                item is None
                or item.get("identity", {}).get("object_type") != "dataset"
                or item.get("identity", {}).get("native_id") != output.native_id
                or item.get("object_hash") != output.object_hash
            ):
                raise AppendOnlyConflict(
                    "external redesign handoff analytic output does not match the portfolio"
                )
        declared_output_ids: set[str] = set()
        declared_side_effects: set[str] = set()
        for source in handoff.source_objects:
            item = portfolio_objects[source.object_id]
            profile = item.get("commonality", {}).get("profile", {})
            if profile.get("profile_type") == "workflow":
                declared_output_ids.update(profile.get("output_object_ids", []))
                declared_side_effects.update(
                    value
                    for value in profile.get("side_effects", [])
                    if value != "none"
                )
        if declared_output_ids != {item.object_id for item in handoff.analytic_outputs}:
            raise AppendOnlyConflict(
                "external redesign handoff does not preserve declared workflow outputs"
            )
        if declared_side_effects and declared_side_effects != set(
            handoff.side_effect_kinds
        ):
            raise AppendOnlyConflict(
                "external redesign handoff does not preserve declared workflow side effects"
            )
        if handoff.handoff_ref in seen_refs:
            raise AppendOnlyConflict(
                "external redesign handoff reference is registered more than once"
            )
        seen_refs.add(handoff.handoff_ref)
        resolved.append(handoff)
    return tuple(sorted(resolved, key=lambda item: item.handoff_ref))


def _current_registered_qa_v2_payload(
    records: list[dict[str, Any]],
    *,
    artifact_ref: str,
    artifact_type: str,
) -> Any | None:
    """Return one canonical v2 QA payload bound to the exact current artifact.

    The artifact ledger intentionally stores metadata rather than raw QA payloads.
    A separate registration event therefore binds the complete canonical payload
    to the published ``ArtifactEnvelope``.  Resolution fails closed when either
    side is absent, duplicated, malformed, non-canonical, or stale.
    """

    if artifact_type == "qa_fixture":
        from omni_migrator.qa.acceptance import (
            finalize_qa_fixture,
            qa_fixture_content_sha256,
            qa_fixture_hash,
        )

        event_type = "qa_fixture_v2_registered"
        payload_key = "fixture"
        contract_version = "domo-to-omni.qa-fixture.v2"
        reference_field = "fixture_ref"
        hash_field = "fixture_hash"
        producer_field = "producer_ref"
        finalizer = finalize_qa_fixture
        semantic_hash = qa_fixture_hash
        content_hash = qa_fixture_content_sha256
    elif artifact_type == "qa_result":
        from omni_migrator.qa.acceptance import (
            finalize_qa_result,
            qa_result_content_sha256,
            qa_result_hash,
        )

        event_type = "qa_result_v2_registered"
        payload_key = "result"
        contract_version = "domo-to-omni.qa-result.v2"
        reference_field = "result_ref"
        hash_field = "result_hash"
        producer_field = "verifier_ref"
        finalizer = finalize_qa_result
        semantic_hash = qa_result_hash
        content_hash = qa_result_content_sha256
    else:
        return None

    artifact_records = [
        record.get("payload", {})
        for record in records
        if record.get("record_type") == "artifact"
        and record.get("payload", {}).get("ref") == artifact_ref
    ]
    if len(artifact_records) != 1:
        return None
    current = artifact_records[0]
    if (
        current.get("artifact_type") != artifact_type
        or _current_artifact_payload(
            records, artifact_id=str(current.get("artifact_id", ""))
        )
        != current
    ):
        return None

    registrations = [
        record
        for record in records
        if record.get("record_type") == "event"
        and record.get("payload", {}).get("event_type") == event_type
        and isinstance(record.get("payload", {}).get("artifact"), Mapping)
        and record.get("payload", {}).get("artifact", {}).get("ref")
        == artifact_ref
    ]
    if len(registrations) != 1:
        return None
    record = registrations[0]
    registration = record.get("payload", {})
    if set(registration) != {"event_type", "artifact", payload_key}:
        return None
    raw_payload = registration.get(payload_key)
    raw_artifact = registration.get("artifact")
    if not isinstance(raw_payload, Mapping) or not isinstance(raw_artifact, Mapping):
        return None

    try:
        envelope = ArtifactEnvelope.from_mapping(raw_artifact)
        envelope.validate(
            expected_tenant_ref=str(record.get("tenant_ref", "")),
            expected_run_id=str(record.get("run_id", "")),
        )
        current_envelope = ArtifactEnvelope.from_mapping(current)
        current_envelope.validate(
            expected_tenant_ref=envelope.tenant_ref,
            expected_run_id=envelope.run_id,
        )
        finalized = finalizer(raw_payload)
    except (TypeError, ValueError):
        return None

    if (
        envelope.to_mapping() != current_envelope.to_mapping()
        or envelope.artifact_type != artifact_type
        or raw_payload.get("contract_version") != contract_version
        or raw_payload.get(hash_field) != getattr(finalized, hash_field)
        or getattr(finalized, hash_field) != semantic_hash(finalized)
        or getattr(finalized, reference_field) != envelope.ref
        or content_hash(finalized) != envelope.content_sha256
        or getattr(finalized, producer_field) != envelope.producer_ref
        or finalized.tenant_ref != envelope.tenant_ref
        or finalized.run_id != envelope.run_id
        or finalized.migration_unit_id != envelope.migration_unit_id
        or finalized.validation_cycle_id != envelope.validation_cycle_id
    ):
        return None
    return finalized


def _qa_v2_payload_matches_current_artifact(
    records: list[dict[str, Any]],
    binding: Any,
) -> bool:
    """Match a QA binding to one exact canonical registered v2 payload."""

    if binding.artifact_type not in {"qa_fixture", "qa_result"}:
        return False
    if not _qa_binding_matches_current_artifact(records, binding):
        return False
    value = _current_registered_qa_v2_payload(
        records,
        artifact_ref=binding.artifact_ref,
        artifact_type=binding.artifact_type,
    )
    if value is None:
        return False
    semantic_field = "fixture_hash" if binding.artifact_type == "qa_fixture" else "result_hash"
    producer_field = "producer_ref" if binding.artifact_type == "qa_fixture" else "verifier_ref"
    return all(
        (
            value.tenant_ref == binding.tenant_ref,
            value.run_id == binding.run_id,
            value.scope_id == binding.scope_id,
            value.wave_id == binding.wave_id,
            value.migration_unit_id == binding.migration_unit_id,
            value.validation_cycle_id == binding.validation_cycle_id,
            value.evidence_class == binding.evidence_class,
            getattr(value, semantic_field) == binding.semantic_hash,
            getattr(value, producer_field) == binding.producer_ref,
        )
    )


def _current_registered_qa_target_operation_outcome(
    records: list[dict[str, Any]],
    *,
    operation_id: str,
) -> Any | None:
    """Resolve one canonical target outcome through exact store registrations."""

    from omni_migrator.qa.target_outcomes import (
        finalize_qa_target_operation_outcome,
        qa_target_operation_outcome_content_sha256,
        qa_target_operation_outcome_hash,
    )

    registrations = [
        record
        for record in records
        if record.get("record_type") == "event"
        and record.get("payload", {}).get("event_type")
        == "qa_target_operation_outcome_registered"
        and record.get("payload", {}).get("outcome", {}).get("operation_id")
        == operation_id
    ]
    if len(registrations) != 1:
        return None
    record = registrations[0]
    payload = record.get("payload", {})
    if set(payload) != {"event_type", "artifact", "outcome"}:
        return None
    raw_artifact = payload.get("artifact")
    raw_outcome = payload.get("outcome")
    if not isinstance(raw_artifact, Mapping) or not isinstance(raw_outcome, Mapping):
        return None
    try:
        artifact = ArtifactEnvelope.from_mapping(raw_artifact)
        artifact.validate(
            expected_tenant_ref=str(record.get("tenant_ref", "")),
            expected_run_id=str(record.get("run_id", "")),
        )
        outcome = finalize_qa_target_operation_outcome(raw_outcome)
    except (TypeError, ValueError):
        return None
    current_artifact = _current_artifact_payload(
        records, artifact_id=artifact.artifact_id
    )
    try:
        current_envelope = (
            ArtifactEnvelope.from_mapping(current_artifact)
            if current_artifact is not None
            else None
        )
    except (TypeError, ValueError):
        return None
    if (
        raw_outcome.get("outcome_hash") != outcome.outcome_hash
        or outcome.outcome_hash != qa_target_operation_outcome_hash(outcome)
        or current_envelope is None
        or current_envelope.to_mapping() != artifact.to_mapping()
        or artifact.artifact_type != "qa_target_operation_outcome"
        or artifact.ref != outcome.outcome_ref
        or artifact.content_sha256
        != qa_target_operation_outcome_content_sha256(outcome)
        or artifact.producer_ref != "agent-ref://migration-qa"
        or artifact.migration_unit_id != outcome.migration_unit_id
        or artifact.validation_cycle_id != outcome.validation_cycle_id
        or any(
            not _qa_binding_matches_current_artifact(records, binding)
            for binding in (
                outcome.promoted_target_artifact,
                outcome.receipt_binding.artifact,
                outcome.readback_binding.artifact,
            )
        )
    ):
        return None
    expected_lineage = {
        (
            binding.artifact_id,
            binding.revision,
            binding.content_sha256,
        )
        for binding in (
            outcome.promoted_target_artifact,
            outcome.receipt_binding.artifact,
            outcome.readback_binding.artifact,
        )
    }
    actual_lineage = {
        (
            str(item.get("artifact_id", "")),
            int(item.get("revision", 0)),
            str(item.get("content_sha256", "")),
        )
        for item in artifact.input_artifacts
    }
    if actual_lineage != expected_lineage:
        return None
    environments = [
        item.get("payload", {})
        for item in records
        if item.get("record_type") == "event"
        and item.get("payload", {}).get("event_type")
        == "target_environment_registered"
        and item.get("payload", {}).get("environment_ref")
        == outcome.target_environment_ref
    ]
    if len(environments) != 1:
        return None
    environment = environments[0]
    if (
        environment.get("environment_tier") != outcome.target_environment_tier
        or outcome.receipt_binding.target_ref
        not in set(environment.get("target_refs", []))
    ):
        return None
    return outcome


def _current_registered_production_validation_report(
    records: list[dict[str, Any]],
    *,
    report_ref: str,
) -> Any | None:
    """Resolve one downstream production report from exact trusted evidence."""

    from omni_migrator.qa.production import (
        finalize_production_validation_report,
        production_validation_report_content_sha256,
        production_validation_report_hash,
    )

    registrations = [
        record
        for record in records
        if record.get("record_type") == "event"
        and record.get("payload", {}).get("event_type")
        == "production_validation_report_registered"
        and record.get("payload", {}).get("report", {}).get("report_ref")
        == report_ref
    ]
    if len(registrations) != 1:
        return None
    record = registrations[0]
    payload = record.get("payload", {})
    if set(payload) != {"event_type", "artifact", "report"}:
        return None
    raw_artifact = payload.get("artifact")
    raw_report = payload.get("report")
    if not isinstance(raw_artifact, Mapping) or not isinstance(raw_report, Mapping):
        return None
    try:
        artifact = ArtifactEnvelope.from_mapping(raw_artifact)
        artifact.validate(
            expected_tenant_ref=str(record.get("tenant_ref", "")),
            expected_run_id=str(record.get("run_id", "")),
        )
        report = finalize_production_validation_report(raw_report)
        current_raw = _current_artifact_payload(
            records, artifact_id=artifact.artifact_id
        )
        current_artifact = (
            ArtifactEnvelope.from_mapping(current_raw)
            if current_raw is not None
            else None
        )
    except (TypeError, ValueError):
        return None
    bound_evidence = (
        report.suite.artifact,
        report.suite_validation_artifact,
        *report.accepted_evidence_bindings.all_artifacts(),
    )
    if (
        raw_report.get("report_hash") != report.report_hash
        or report.report_hash != production_validation_report_hash(report)
        or current_artifact is None
        or current_artifact.to_mapping() != artifact.to_mapping()
        or artifact.artifact_type != "production_validation_report"
        or artifact.ref != report.report_ref
        or artifact.content_sha256
        != production_validation_report_content_sha256(report)
        or artifact.producer_ref != "agent-ref://migration-qa"
        or artifact.migration_unit_id != report.migration_unit_id
        or artifact.validation_cycle_id != report.validation_cycle_id
        or any(
            not _qa_binding_matches_current_artifact(records, binding)
            for binding in bound_evidence
        )
    ):
        return None
    validation_events = [
        item.get("payload", {})
        for item in records
        if item.get("record_type") == "event"
        and item.get("payload", {}).get("event_type") == "qa_suite_validated"
        and item.get("payload", {}).get("registration_ref")
        == report.suite_validation.registration_ref
    ]
    if len(validation_events) != 1 or {
        key: value
        for key, value in validation_events[0].items()
        if key != "event_type"
    } != report.suite_validation.model_dump(mode="json"):
        return None
    receipts = report.accepted_evidence_bindings.target_receipts
    readbacks = {
        item.operation_id: item
        for item in report.accepted_evidence_bindings.target_readbacks
    }
    target_refs: set[str] = set()
    for receipt in receipts:
        outcome = _current_registered_qa_target_operation_outcome(
            records, operation_id=receipt.operation_id
        )
        readback = readbacks.get(receipt.operation_id)
        if (
            outcome is None
            or readback is None
            or outcome.receipt_binding != receipt
            or outcome.readback_binding != readback
            or outcome.target_environment_tier != "production"
        ):
            return None
        target_refs.add(outcome.promoted_target_artifact.artifact_ref)
    if target_refs != {
        item.artifact_ref
        for item in report.accepted_evidence_bindings.target_artifacts
    }:
        return None
    expected_lineage = {
        (binding.artifact_id, binding.revision, binding.content_sha256)
        for binding in bound_evidence
    }
    actual_lineage = {
        (
            str(item.get("artifact_id", "")),
            int(item.get("revision", 0)),
            str(item.get("content_sha256", "")),
        )
        for item in artifact.input_artifacts
    }
    return report if actual_lineage == expected_lineage else None


def _documentation_artifact_identity(
    artifact: ArtifactEnvelope,
) -> tuple[str, int, str]:
    return artifact.artifact_id, artifact.revision, artifact.content_sha256


def _documentation_binding_identity(binding: Any) -> tuple[str, int, str]:
    return binding.artifact_id, binding.revision, binding.content_sha256


def _documentation_raw_binding_identity(
    binding: Mapping[str, Any],
) -> tuple[str, int, str]:
    return (
        str(binding.get("artifact_id", "")),
        int(binding.get("revision", 0)),
        str(binding.get("content_sha256", "")),
    )


def _current_documentation_binding_artifact(
    records: list[dict[str, Any]],
    *,
    binding: Any,
    artifact_type: str,
    tenant_ref: str,
    run_id: str,
    migration_unit_id: str,
    validation_cycle_id: str,
) -> ArtifactEnvelope | None:
    raw = _current_artifact_payload(records, artifact_id=binding.artifact_id)
    if raw is None:
        return None
    try:
        artifact = ArtifactEnvelope.from_mapping(raw)
        artifact.validate(
            expected_tenant_ref=tenant_ref,
            expected_run_id=run_id,
        )
    except (TypeError, ValueError):
        return None
    if (
        artifact.artifact_type != artifact_type
        or artifact.ref != binding.artifact_ref
        or artifact.revision != binding.revision
        or artifact.content_sha256 != binding.content_sha256
        or artifact.migration_unit_id != migration_unit_id
        or artifact.validation_cycle_id != validation_cycle_id
    ):
        return None
    return artifact


def _current_raw_documentation_binding_artifact(
    records: list[dict[str, Any]],
    *,
    binding: Mapping[str, Any],
    tenant_ref: str,
    run_id: str,
    migration_unit_id: str,
    validation_cycle_id: str,
) -> ArtifactEnvelope | None:
    raw = _current_artifact_payload(
        records,
        artifact_id=str(binding.get("artifact_id", "")),
    )
    if raw is None:
        return None
    try:
        artifact = ArtifactEnvelope.from_mapping(raw)
        artifact.validate(
            expected_tenant_ref=tenant_ref,
            expected_run_id=run_id,
        )
    except (TypeError, ValueError):
        return None
    if (
        artifact.artifact_type != binding.get("artifact_type")
        or artifact.ref != binding.get("artifact_ref")
        or artifact.revision != int(binding.get("revision", 0))
        or artifact.content_sha256 != binding.get("content_sha256")
        or artifact.producer_ref != binding.get("producer_ref")
        or artifact.migration_unit_id != migration_unit_id
        or artifact.validation_cycle_id != validation_cycle_id
    ):
        return None
    return artifact


def _documentation_snapshot_bindings(
    snapshot: Mapping[str, Any],
) -> tuple[tuple[Mapping[str, Any], ...], tuple[Mapping[str, Any], ...]] | None:
    """Extract accepted and final-target bindings from one typed QA snapshot."""

    raw_bindings = snapshot.get("bindings")
    if not isinstance(raw_bindings, Mapping):
        return None
    singular_fields = ("dashboard_plan", "semantic_profile_coverage")
    sequence_fields = (
        "topic_blueprints",
        "semantic_profiles",
        "consolidation_decisions",
        "source_evidence",
        "target_artifacts",
        "persona_policies",
        "tolerance_policies",
        "fixture_artifacts",
        "result_artifacts",
    )
    accepted: list[Mapping[str, Any]] = []
    for field_name in singular_fields:
        value = raw_bindings.get(field_name)
        if not isinstance(value, Mapping):
            return None
        accepted.append(value)
    for field_name in sequence_fields:
        values = raw_bindings.get(field_name)
        if not isinstance(values, (list, tuple)):
            return None
        if any(not isinstance(item, Mapping) for item in values):
            return None
        accepted.extend(values)
    target_artifacts = tuple(
        item
        for item in raw_bindings.get("target_artifacts", ())
        if isinstance(item, Mapping)
    )
    target_operation_artifacts: list[Mapping[str, Any]] = []
    for field_name in ("target_receipts", "target_readbacks"):
        values = raw_bindings.get(field_name)
        if not isinstance(values, (list, tuple)):
            return None
        for item in values:
            if not isinstance(item, Mapping) or not isinstance(
                item.get("artifact"), Mapping
            ):
                return None
            target_operation_artifacts.append(item["artifact"])
    accepted.extend(target_operation_artifacts)
    final_targets = (*target_artifacts, *target_operation_artifacts)
    accepted_refs = [str(item.get("artifact_ref", "")) for item in accepted]
    accepted_identities = [_documentation_raw_binding_identity(item) for item in accepted]
    if (
        any(not reference for reference in accepted_refs)
        or len(accepted_refs) != len(set(accepted_refs))
        or len(accepted_identities) != len(set(accepted_identities))
    ):
        return None
    return tuple(accepted), tuple(final_targets)


def _current_documentation_qa_context(
    records: list[dict[str, Any]],
    *,
    package: Any,
) -> tuple[Any, tuple[Mapping[str, Any], ...], tuple[Mapping[str, Any], ...]] | None:
    """Resolve the one still-current typed QA attestation used by documentation."""

    from omni_migrator.qa.acceptance import (
        QASuiteValidationRegistration,
        qa_suite_validation_registration_hash,
    )

    identity_fields = {
        "tenant_ref": package.tenant_ref,
        "run_id": package.run_id,
        "scope_id": package.scope_id,
        "wave_id": package.wave_id,
        "migration_unit_id": package.migration_unit_id,
        "validation_cycle_id": package.validation_cycle_id,
    }
    matches: list[Any] = []
    for record in records:
        payload = record.get("payload", {})
        if (
            record.get("record_type") != "event"
            or payload.get("event_type") != "qa_suite_validated"
            or any(payload.get(key) != value for key, value in identity_fields.items())
        ):
            continue
        raw = {key: value for key, value in payload.items() if key != "event_type"}
        try:
            registration = QASuiteValidationRegistration.model_validate(raw)
        except (TypeError, ValueError):
            return None
        if (
            raw != registration.model_dump(mode="json")
            or registration.registration_hash
            != qa_suite_validation_registration_hash(registration)
            or registration.status != "valid"
            or not registration.qa_suite_ready
        ):
            return None
        matches.append(registration)
    if len(matches) != 1:
        return None
    registration = matches[0]

    snapshots = [
        record.get("payload", {})
        for record in records
        if record.get("record_type") == "event"
        and record.get("payload", {}).get("event_type")
        == "qa_evidence_snapshot_registered"
        and all(
            record.get("payload", {}).get(key) == value
            for key, value in identity_fields.items()
        )
    ]
    if not snapshots:
        return None
    latest_snapshot = max(snapshots, key=lambda item: int(item.get("revision", 0)))
    if (
        latest_snapshot.get("snapshot_ref") != registration.evidence_snapshot_ref
        or latest_snapshot.get("snapshot_hash") != registration.evidence_snapshot_hash
        or int(latest_snapshot.get("revision", 0))
        != registration.evidence_snapshot_revision
    ):
        return None
    extracted = _documentation_snapshot_bindings(latest_snapshot)
    if extracted is None:
        return None
    accepted_bindings, final_target_bindings = extracted
    if any(
        _current_raw_documentation_binding_artifact(
            records,
            binding=binding,
            tenant_ref=package.tenant_ref,
            run_id=package.run_id,
            migration_unit_id=package.migration_unit_id,
            validation_cycle_id=package.validation_cycle_id,
        )
        is None
        for binding in accepted_bindings
    ):
        return None

    current_suite_artifacts: list[ArtifactEnvelope] = []
    suite_artifact_ids = {
        str(record.get("payload", {}).get("artifact_id", ""))
        for record in records
        if record.get("record_type") == "artifact"
        and record.get("payload", {}).get("artifact_type") == "qa_acceptance_suite"
        and record.get("payload", {}).get("migration_unit_id")
        == package.migration_unit_id
        and record.get("payload", {}).get("validation_cycle_id")
        == package.validation_cycle_id
    }
    for artifact_id in suite_artifact_ids:
        raw = _current_artifact_payload(records, artifact_id=artifact_id)
        try:
            artifact = ArtifactEnvelope.from_mapping(raw) if raw is not None else None
        except (TypeError, ValueError):
            return None
        if artifact is not None and artifact.artifact_type == "qa_acceptance_suite":
            current_suite_artifacts.append(artifact)
    exact_suite = [
        artifact
        for artifact in current_suite_artifacts
        if artifact.ref == registration.suite_artifact_ref
        and artifact.content_sha256 == registration.suite_artifact_content_sha256
        and artifact.producer_ref == registration.verifier_ref
        and artifact.migration_unit_id == package.migration_unit_id
        and artifact.validation_cycle_id == package.validation_cycle_id
    ]
    if len(current_suite_artifacts) != 1 or len(exact_suite) != 1:
        return None
    return registration, accepted_bindings, final_target_bindings


def _documentation_registration_errors(
    records: list[dict[str, Any]],
    *,
    package: Any,
    package_artifact: ArtifactEnvelope,
) -> tuple[str, ...]:
    from omni_migrator.control_plane.documentation import (
        validate_documentation_package,
    )
    from omni_migrator.qa.acceptance import qa_suite_validation_content_sha256

    errors: list[str] = []
    artifact_mappings = [
        record.get("payload", {})
        for record in records
        if record.get("record_type") == "artifact"
    ]
    errors.extend(
        validate_documentation_package(
            package,
            expected_tenant_ref=package.tenant_ref,
            expected_run_id=package.run_id,
            expected_validation_cycle_id=package.validation_cycle_id,
            expected_migration_unit_id=package.migration_unit_id,
            artifacts=artifact_mappings,
            require_registered_artifacts=True,
        )
    )

    current_package_artifact = _current_artifact_payload(
        records,
        artifact_id=package_artifact.artifact_id,
    )
    try:
        current_package_envelope = (
            ArtifactEnvelope.from_mapping(current_package_artifact)
            if current_package_artifact is not None
            else None
        )
    except (TypeError, ValueError):
        current_package_envelope = None
    if (
        current_package_envelope is None
        or current_package_envelope.to_mapping() != package_artifact.to_mapping()
        or package_artifact.artifact_type != "documentation_package"
        or package_artifact.content_sha256
        != sha256_json(package.model_dump(mode="json"))
        or package_artifact.producer_ref != "agent-ref://documentation-training"
        or package_artifact.migration_unit_id != package.migration_unit_id
        or package_artifact.validation_cycle_id != package.validation_cycle_id
    ):
        errors.append(
            "documentation package requires its exact current documentation-training artifact"
        )

    qa_context = _current_documentation_qa_context(records, package=package)
    if qa_context is None:
        errors.append("documentation package lacks one exact current QA validation")
        return tuple(sorted(set(errors)))
    registration, qa_bindings, qa_target_bindings = qa_context
    qa_artifact = _current_documentation_binding_artifact(
        records,
        binding=package.qa_suite_validation,
        artifact_type="qa_suite_validation",
        tenant_ref=package.tenant_ref,
        run_id=package.run_id,
        migration_unit_id=package.migration_unit_id,
        validation_cycle_id=package.validation_cycle_id,
    )
    if (
        qa_artifact is None
        or qa_artifact.producer_ref != "agent-ref://migration-qa"
        or package.qa_suite_validation.validation_ref != registration.registration_ref
        or package.qa_suite_validation.validation_hash != registration.registration_hash
        or package.qa_suite_validation.evidence_class != registration.evidence_class
        or package.qa_suite_validation.content_sha256
        != qa_suite_validation_content_sha256(registration)
    ):
        errors.append(
            "documentation package does not bind the exact current QA validation artifact"
        )

    expected_targets = {
        str(item.get("artifact_ref")): item for item in qa_target_bindings
    }
    actual_targets = {
        item.artifact_ref: item for item in package.final_target_bindings
    }
    if set(expected_targets) != set(actual_targets):
        errors.append(
            "documentation final targets differ from the exact current QA target set"
        )
    else:
        for artifact_ref, binding in actual_targets.items():
            expected = expected_targets[artifact_ref]
            if (
                _documentation_binding_identity(binding)
                != _documentation_raw_binding_identity(expected)
                or binding.artifact_type != expected.get("artifact_type")
                or _current_documentation_binding_artifact(
                    records,
                    binding=binding,
                    artifact_type=binding.artifact_type,
                    tenant_ref=package.tenant_ref,
                    run_id=package.run_id,
                    migration_unit_id=package.migration_unit_id,
                    validation_cycle_id=package.validation_cycle_id,
                )
                is None
            ):
                errors.append(
                    f"documentation final target is stale or altered: {artifact_ref}"
                )

    allowed_inputs: dict[str, Any] = {
        package.qa_suite_validation.artifact_ref: package.qa_suite_validation,
        **{str(item.get("artifact_ref")): item for item in qa_bindings},
    }
    expected_production_inputs: dict[str, Any] = {}
    if package.evidence_class == "production":
        if len(package.production_validation_bindings) != 1:
            errors.append(
                "production documentation requires exactly one current production report"
            )
        else:
            production_binding = package.production_validation_bindings[0]
            report = _current_registered_production_validation_report(
                records,
                report_ref=production_binding.validation_ref,
            )
            production_artifact = _current_documentation_binding_artifact(
                records,
                binding=production_binding,
                artifact_type="production_validation_report",
                tenant_ref=package.tenant_ref,
                run_id=package.run_id,
                migration_unit_id=package.migration_unit_id,
                validation_cycle_id=package.validation_cycle_id,
            )
            if (
                report is None
                or production_artifact is None
                or report.report_ref != production_binding.validation_ref
                or report.report_hash != production_binding.validation_hash
                or report.outcome != "passed"
            ):
                errors.append(
                    "production documentation lacks its exact current registered report"
                )
            else:
                expected_production_inputs[production_binding.artifact_ref] = (
                    production_binding
                )
                allowed_inputs.update(expected_production_inputs)
    elif package.production_validation_bindings:
        errors.append("non-production documentation cannot bind production reports")

    accepted_inputs = {
        item.artifact_ref: item for item in package.accepted_input_bindings
    }
    unexpected = sorted(set(accepted_inputs) - set(allowed_inputs))
    if unexpected:
        errors.append(
            "documentation accepted inputs are outside the exact current QA evidence: "
            f"{unexpected}"
        )
    if package.evidence_class == "production" and set(accepted_inputs) != set(
        allowed_inputs
    ):
        errors.append(
            "production documentation must consume the complete current accepted evidence set"
        )
    for artifact_ref, binding in accepted_inputs.items():
        expected = allowed_inputs.get(artifact_ref)
        if expected is None:
            continue
        if isinstance(expected, Mapping):
            expected_identity = _documentation_raw_binding_identity(expected)
            expected_type = str(expected.get("artifact_type", ""))
        else:
            expected_identity = _documentation_binding_identity(expected)
            expected_type = expected.artifact_type
        if (
            _documentation_binding_identity(binding) != expected_identity
            or binding.artifact_type != expected_type
            or _current_documentation_binding_artifact(
                records,
                binding=binding,
                artifact_type=binding.artifact_type,
                tenant_ref=package.tenant_ref,
                run_id=package.run_id,
                migration_unit_id=package.migration_unit_id,
                validation_cycle_id=package.validation_cycle_id,
            )
            is None
        ):
            errors.append(
                f"documentation accepted input is stale or altered: {artifact_ref}"
            )
            continue
        authoritative_refs = {registration.registration_ref}
        if artifact_ref in expected_production_inputs:
            authoritative_refs.add(
                expected_production_inputs[artifact_ref].validation_ref
            )
        if binding.accepted_by_ref not in authoritative_refs:
            errors.append(
                f"documentation accepted input lacks authoritative validation: {artifact_ref}"
            )

    accepted_by_ref = {
        item.artifact_ref: item for item in package.accepted_input_bindings
    }
    output_artifacts: list[ArtifactEnvelope] = []
    for output in package.output_bindings:
        artifact = _current_documentation_binding_artifact(
            records,
            binding=output,
            artifact_type=output.output_type,
            tenant_ref=package.tenant_ref,
            run_id=package.run_id,
            migration_unit_id=package.migration_unit_id,
            validation_cycle_id=package.validation_cycle_id,
        )
        if artifact is None or artifact.producer_ref != (
            "agent-ref://documentation-training"
        ):
            errors.append(
                f"documentation output is not exact and current: {output.artifact_ref}"
            )
            continue
        expected_lineage = {
            _documentation_binding_identity(accepted_by_ref[reference])
            for reference in output.input_artifact_refs
            if reference in accepted_by_ref
        }
        actual_lineage = {
            (
                str(item.get("artifact_id", "")),
                int(item.get("revision", 0)),
                str(item.get("content_sha256", "")),
            )
            for item in artifact.input_artifacts
        }
        if (
            len(expected_lineage) != len(output.input_artifact_refs)
            or actual_lineage != expected_lineage
        ):
            errors.append(
                "documentation output lineage does not exactly match accepted inputs: "
                f"{output.artifact_ref}"
            )
        output_artifacts.append(artifact)

    expected_package_lineage = {
        *(
            _documentation_binding_identity(item)
            for item in package.accepted_input_bindings
        ),
        *(_documentation_artifact_identity(item) for item in output_artifacts),
    }
    actual_package_lineage = {
        (
            str(item.get("artifact_id", "")),
            int(item.get("revision", 0)),
            str(item.get("content_sha256", "")),
        )
        for item in package_artifact.input_artifacts
    }
    if (
        len(output_artifacts) != len(package.output_bindings)
        or actual_package_lineage != expected_package_lineage
    ):
        errors.append(
            "documentation package artifact lineage must exactly bind accepted inputs and outputs"
        )
    return tuple(sorted(set(errors)))


def _current_registered_documentation_package(
    records: list[dict[str, Any]],
    *,
    tenant_ref: str,
    run_id: str,
    scope_id: str,
    wave_id: str,
    migration_unit_id: str,
    validation_cycle_id: str,
    package_id: str | None = None,
) -> Any | None:
    from omni_migrator.control_plane.documentation import (
        documentation_package_hash,
        finalize_documentation_package,
    )

    candidates: list[tuple[Any, ArtifactEnvelope]] = []
    for record in records:
        payload = record.get("payload", {})
        if (
            record.get("record_type") != "event"
            or payload.get("event_type") != "documentation_package_registered"
            or set(payload) != {"event_type", "artifact", "package"}
            or not isinstance(payload.get("artifact"), Mapping)
            or not isinstance(payload.get("package"), Mapping)
        ):
            continue
        raw_package = dict(payload["package"])
        try:
            package = finalize_documentation_package(raw_package)
            artifact = ArtifactEnvelope.from_mapping(payload["artifact"])
            artifact.validate(
                expected_tenant_ref=tenant_ref,
                expected_run_id=run_id,
            )
        except (TypeError, ValueError):
            return None
        if (
            raw_package != package.model_dump(mode="json")
            or package.package_hash != documentation_package_hash(package)
            or package.tenant_ref != tenant_ref
            or package.run_id != run_id
            or package.scope_id != scope_id
            or package.wave_id != wave_id
            or package.migration_unit_id != migration_unit_id
            or package.validation_cycle_id != validation_cycle_id
            or (package_id is not None and package.package_id != package_id)
        ):
            continue
        candidates.append((package, artifact))
    if len(candidates) != 1:
        return None
    package, artifact = candidates[0]
    try:
        errors = _documentation_registration_errors(
            records,
            package=package,
            package_artifact=artifact,
        )
    except (AppendOnlyConflict, TypeError, ValueError):
        return None
    return package if not errors else None


class AppendOnlyControlPlaneStore:
    """Hash-chained JSONL store partitioned by tenant and run."""

    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def _partition_path(self, tenant_ref: str, run_id: str) -> Path:
        validate_reference(tenant_ref)
        validate_run_id(run_id)
        partition = self.root / partition_key(tenant_ref, run_id)
        partition.mkdir(mode=0o700, parents=True, exist_ok=True)
        return partition / "ledger.jsonl"

    @staticmethod
    def _load_locked(handle: Any) -> list[dict[str, Any]]:
        handle.seek(0)
        records: list[dict[str, Any]] = []
        previous_hash: str | None = None
        for line_number, raw_line in enumerate(handle, start=1):
            if not raw_line.strip():
                continue
            record = json.loads(raw_line)
            if record.get("sequence") != len(records) + 1:
                raise AppendOnlyConflict(f"non-contiguous ledger sequence at line {line_number}")
            if record.get("previous_hash") != previous_hash:
                raise AppendOnlyConflict(f"broken ledger hash chain at line {line_number}")
            if record.get("payload_sha256") != sha256_json(record.get("payload")):
                raise AppendOnlyConflict(
                    f"ledger payload hash mismatch at line {line_number}"
                )
            material = {key: value for key, value in record.items() if key != "record_hash"}
            expected_hash = sha256_json(material)
            if record.get("record_hash") != expected_hash:
                raise AppendOnlyConflict(f"ledger record hash mismatch at line {line_number}")
            previous_hash = expected_hash
            records.append(record)
        return records

    def _append(
        self,
        *,
        tenant_ref: str,
        run_id: str,
        record_type: str,
        record_id: str,
        payload: Mapping[str, Any],
        idempotency_key: str,
        occurred_at: datetime | None = None,
        guard: Guard | None = None,
    ) -> dict[str, Any]:
        path = self._partition_path(tenant_ref, run_id)
        when = (occurred_at or utc_now()).astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        path.touch(mode=0o600, exist_ok=True)
        with path.open("r+", encoding="utf-8") as handle:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            records = self._load_locked(handle)
            payload_hash = sha256_json(payload)
            for record in records:
                if record.get("idempotency_key") != idempotency_key:
                    continue
                if (
                    record.get("record_type") == record_type
                    and record.get("record_id") == record_id
                    and record.get("payload_sha256") == payload_hash
                ):
                    return record
                raise AppendOnlyConflict("idempotency key was reused for different content")
            for record in records:
                if record.get("record_type") == record_type and record.get("record_id") == record_id:
                    raise AppendOnlyConflict("append-only record identity already exists")
            if guard is not None:
                guard(records)
            base = {
                "tenant_ref": tenant_ref,
                "run_id": run_id,
                "sequence": len(records) + 1,
                "record_type": record_type,
                "record_id": record_id,
                "occurred_at": when,
                "idempotency_key": idempotency_key,
                "payload_sha256": payload_hash,
                "payload": dict(payload),
                "previous_hash": records[-1]["record_hash"] if records else None,
            }
            record = {**base, "record_hash": sha256_json(base)}
            handle.seek(0, os.SEEK_END)
            handle.write(canonical_json(record) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
            return record

    def records(self, tenant_ref: str, run_id: str) -> list[dict[str, Any]]:
        path = self._partition_path(tenant_ref, run_id)
        if not path.exists():
            return []
        path.touch(mode=0o600, exist_ok=True)
        with path.open("r", encoding="utf-8") as handle:
            fcntl.flock(handle.fileno(), fcntl.LOCK_SH)
            return self._load_locked(handle)

    def verified_ledger(
        self, tenant_ref: str, run_id: str
    ) -> VerifiedControlPlaneLedger:
        """Read one non-empty partition and issue its runtime trust object."""

        records = self.records(tenant_ref, run_id)
        if not records:
            raise AppendOnlyConflict("canonical control-plane ledger partition is empty")
        if any(
            record.get("tenant_ref") != tenant_ref or record.get("run_id") != run_id
            for record in records
        ):
            raise AppendOnlyConflict("control-plane ledger crosses its requested partition")
        return VerifiedControlPlaneLedger(
            tenant_ref=tenant_ref,
            run_id=run_id,
            records=tuple(records),
            ledger_head=str(records[-1]["record_hash"]),
            record_count=len(records),
            _capability=_VERIFIED_LEDGER_CAPABILITY,
        )

    def append_event(
        self,
        tenant_ref: str,
        run_id: str,
        *,
        event_id: str,
        event_type: str,
        payload: Mapping[str, Any],
        idempotency_key: str,
        occurred_at: datetime | None = None,
    ) -> dict[str, Any]:
        if "event_type" in payload:
            raise AppendOnlyConflict("generic event payload cannot override event_type")
        if event_type in _RESERVED_TYPED_EVENT_TYPES:
            raise AppendOnlyConflict(
                "typed control-plane events require their dedicated validated append method"
            )
        return self._append(
            tenant_ref=tenant_ref,
            run_id=run_id,
            record_type="event",
            record_id=event_id,
            payload={"event_type": event_type, **dict(payload)},
            idempotency_key=idempotency_key,
            occurred_at=occurred_at,
        )

    def _append_dashboard_prerequisite_registration(
        self,
        evidence: Mapping[str, Any] | Any,
        *,
        event_type: str,
        tenant_ref: str,
        wave_id: str,
        migration_unit_id: str,
        validation_cycle_id: str,
        registered_by_ref: str,
        registered_at: str,
        idempotency_key: str,
        artifact: ArtifactEnvelope | Mapping[str, Any] | None = None,
        topic_blueprint: Mapping[str, Any] | Any | None = None,
        registration_revision: int = 1,
        supersedes_registration_hash: str | None = None,
    ) -> dict[str, Any]:
        """Append one typed, partitioned, revision-chained dashboard prerequisite."""

        model_type, natural_key_fn, artifact_required = (
            _dashboard_prerequisite_contract(event_type)
        )
        value = (
            evidence
            if isinstance(evidence, model_type)
            else model_type.model_validate_json(canonical_json(evidence))
        )
        raw = value.model_dump(mode="json")
        envelope = None
        if artifact is not None:
            envelope = (
                artifact
                if isinstance(artifact, ArtifactEnvelope)
                else ArtifactEnvelope.from_mapping(artifact)
            )
        try:
            validate_reference(tenant_ref)
            validate_reference(registered_by_ref)
            validate_run_id(value.run_id)
            validate_run_id(value.scope_id)
            validate_run_id(wave_id)
            validate_run_id(migration_unit_id)
            validate_run_id(validation_cycle_id)
            parse_time(registered_at)
            if envelope is not None:
                envelope.validate(
                    expected_tenant_ref=tenant_ref,
                    expected_run_id=value.run_id,
                )
        except (TypeError, ValueError) as exc:
            raise AppendOnlyConflict(
                f"{event_type} dashboard prerequisite registration is invalid"
            ) from exc
        if artifact_required != (envelope is not None):
            raise AppendOnlyConflict(
                f"{event_type} dashboard prerequisite artifact binding is required"
            )
        if not registered_by_ref.startswith(
            ("agent-ref://", "human-ref://", "person-ref://", "person://")
        ):
            raise AppendOnlyConflict(
                "dashboard prerequisite registration requires an agent or human actor"
            )
        payload = {
            "event_type": event_type,
            "tenant_ref": tenant_ref,
            "run_id": value.run_id,
            "scope_id": value.scope_id,
            "wave_id": wave_id,
            "migration_unit_id": migration_unit_id,
            "validation_cycle_id": validation_cycle_id,
            "natural_key": natural_key_fn(value),
            "evidence": raw,
            "evidence_hash": f"sha256:{sha256_json(raw)}",
            "topic_blueprint": (
                topic_blueprint.model_dump(mode="json")
                if hasattr(topic_blueprint, "model_dump")
                else (dict(topic_blueprint) if topic_blueprint is not None else None)
            ),
            "artifact": envelope.to_mapping() if envelope is not None else None,
            "registration_revision": registration_revision,
            "supersedes_registration_hash": supersedes_registration_hash,
            "registered_by_ref": registered_by_ref,
            "registered_at": registered_at,
            "registration_hash": "sha256:" + "0" * 64,
        }
        payload["registration_hash"] = _dashboard_registration_hash(payload)
        synthetic_record = {
            "record_type": "event",
            "tenant_ref": tenant_ref,
            "run_id": value.run_id,
            "payload": payload,
        }
        _parse_dashboard_prerequisite_event(synthetic_record)

        def guard(records: list[dict[str, Any]]) -> None:
            current = _current_dashboard_prerequisite_events(
                records,
                event_type=event_type,
                tenant_ref=tenant_ref,
                run_id=value.run_id,
                scope_id=value.scope_id,
                wave_id=wave_id,
                migration_unit_id=migration_unit_id,
                validation_cycle_id=validation_cycle_id,
            ).get(str(payload["natural_key"]))
            expected_revision = (
                int(current[0]["registration_revision"]) + 1 if current else 1
            )
            expected_predecessor = current[0]["registration_hash"] if current else None
            if (
                registration_revision != expected_revision
                or supersedes_registration_hash != expected_predecessor
            ):
                raise AppendOnlyConflict(
                    f"{event_type} dashboard prerequisite does not supersede its exact current registration"
                )
            if envelope is not None and not _artifact_envelope_is_exactly_current(
                records, envelope
            ):
                raise AppendOnlyConflict(
                    f"{event_type} requires its exact current artifact"
                )
            if not _dashboard_prerequisite_is_current(
                records,
                event_type=event_type,
                registration=payload,
                evidence=value,
                artifact=envelope,
            ):
                raise AppendOnlyConflict(
                    f"{event_type} dashboard prerequisite is not current"
                )

        return self._append(
            tenant_ref=tenant_ref,
            run_id=value.run_id,
            record_type="event",
            record_id=(
                f"{event_type.removesuffix('_registered').replace('_', '-')}:"
                f"{sha256_json([value.scope_id, wave_id, migration_unit_id, validation_cycle_id, payload['natural_key']])}:"
                f"{registration_revision}"
            ),
            payload=payload,
            idempotency_key=idempotency_key,
            occurred_at=parse_time(registered_at),
            guard=guard,
        )

    def append_dashboard_source_acceptance(
        self, evidence: Mapping[str, Any] | Any, artifact: ArtifactEnvelope | Mapping[str, Any], **kwargs: Any
    ) -> dict[str, Any]:
        return self._append_dashboard_prerequisite_registration(
            evidence,
            event_type="dashboard_source_acceptance_registered",
            artifact=artifact,
            **kwargs,
        )

    def append_dashboard_topic_blueprint_registration(
        self,
        topic_blueprint: Mapping[str, Any] | Any,
        registration: Mapping[str, Any] | Any,
        artifact: ArtifactEnvelope | Mapping[str, Any],
        **kwargs: Any,
    ) -> dict[str, Any]:
        from omni_migrator.dashboards.rebuild_plan import RegisteredDashboardTopicEvidence
        from omni_migrator.semantic.topic_blueprints import TopicBlueprint

        topic = (
            topic_blueprint
            if isinstance(topic_blueprint, TopicBlueprint)
            else TopicBlueprint.model_validate_json(canonical_json(topic_blueprint))
        )
        value = (
            registration
            if isinstance(registration, RegisteredDashboardTopicEvidence)
            else RegisteredDashboardTopicEvidence.model_validate_json(
                canonical_json(registration)
            )
        )
        envelope = (
            artifact
            if isinstance(artifact, ArtifactEnvelope)
            else ArtifactEnvelope.from_mapping(artifact)
        )
        if (
            topic.run_id != value.run_id
            or topic.scope_id != value.scope_id
            or topic.blueprint_id != value.blueprint_id
            or topic.blueprint_hash != value.blueprint_hash
            or envelope.artifact_type != "topic_blueprint"
            or envelope.ref != value.artifact_ref
            or envelope.content_sha256 != sha256_json(topic.model_dump(mode="json"))
        ):
            raise AppendOnlyConflict(
                "dashboard Topic registration does not bind its exact blueprint artifact"
            )
        return self._append_dashboard_prerequisite_registration(
            value,
            event_type="dashboard_topic_blueprint_registered",
            artifact=envelope,
            topic_blueprint=topic,
            **kwargs,
        )

    def append_dashboard_topic_readiness(
        self, evidence: Mapping[str, Any] | Any, **kwargs: Any
    ) -> dict[str, Any]:
        return self._append_dashboard_prerequisite_registration(
            evidence, event_type="dashboard_topic_readiness_registered", **kwargs
        )

    def append_dashboard_topic_component_acceptance(
        self, evidence: Mapping[str, Any] | Any, **kwargs: Any
    ) -> dict[str, Any]:
        return self._append_dashboard_prerequisite_registration(
            evidence, event_type="dashboard_topic_component_registered", **kwargs
        )

    def append_dashboard_behavior_acceptance(
        self, evidence: Mapping[str, Any] | Any, **kwargs: Any
    ) -> dict[str, Any]:
        return self._append_dashboard_prerequisite_registration(
            evidence, event_type="dashboard_behavior_acceptance_registered", **kwargs
        )

    def append_dashboard_query_disposition_acceptance(
        self, evidence: Mapping[str, Any] | Any, **kwargs: Any
    ) -> dict[str, Any]:
        return self._append_dashboard_prerequisite_registration(
            evidence, event_type="dashboard_query_disposition_registered", **kwargs
        )

    def append_dashboard_query_mapping_acceptance(
        self, evidence: Mapping[str, Any] | Any, **kwargs: Any
    ) -> dict[str, Any]:
        return self._append_dashboard_prerequisite_registration(
            evidence, event_type="dashboard_query_mapping_registered", **kwargs
        )

    def append_dashboard_plan_acceptance(
        self, evidence: Mapping[str, Any] | Any, artifact: ArtifactEnvelope | Mapping[str, Any], **kwargs: Any
    ) -> dict[str, Any]:
        return self._append_dashboard_prerequisite_registration(
            evidence,
            event_type="dashboard_plan_acceptance_registered",
            artifact=artifact,
            **kwargs,
        )

    def build_dashboard_evidence_snapshot_from_store(self, proposal: Any) -> Any:
        """Project a snapshot from current typed registrations using proposal keys only."""

        from omni_migrator.dashboards.rebuild_plan import (
            DashboardEvidenceSnapshot,
            DashboardRebuildPlan,
            finalize_dashboard_evidence_snapshot,
        )

        proposed = finalize_dashboard_evidence_snapshot(
            proposal.model_dump(mode="json")
            if isinstance(proposal, DashboardEvidenceSnapshot)
            else dict(proposal)
        )
        records = self.records(proposed.tenant_ref, proposed.run_id)
        partition = {
            "tenant_ref": proposed.tenant_ref,
            "run_id": proposed.run_id,
            "scope_id": proposed.scope_id,
            "wave_id": proposed.wave_id,
            "migration_unit_id": proposed.migration_unit_id,
            "validation_cycle_id": proposed.validation_cycle_id,
        }
        plan_events = _current_dashboard_prerequisite_events(
            records,
            event_type="dashboard_plan_acceptance_registered",
            **partition,
        )
        requested_plan_ids = {item.plan_id for item in proposed.plan_registrations}
        if not requested_plan_ids:
            raise AppendOnlyConflict("dashboard snapshot requires a registered plan key")
        plan_acceptances = []
        plans: list[Any] = []
        for plan_id in sorted(requested_plan_ids):
            accepted = plan_events.get(plan_id)
            if accepted is None or not _dashboard_prerequisite_is_current(
                records,
                event_type="dashboard_plan_acceptance_registered",
                registration=accepted[0],
                evidence=accepted[1],
                artifact=accepted[2],
            ):
                raise AppendOnlyConflict(
                    "dashboard snapshot plan key is not currently registered"
                )
            plan_acceptances.append(accepted[1])
            matching_plans = []
            for record in records:
                payload = record.get("payload", {})
                if (
                    record.get("record_type") == "event"
                    and payload.get("event_type")
                    == "dashboard_plan_payload_registered"
                    and isinstance(payload.get("plan"), Mapping)
                ):
                    candidate = DashboardRebuildPlan.model_validate_json(
                        canonical_json(payload["plan"])
                    )
                    if candidate.plan_id == plan_id:
                        matching_plans.append(candidate)
            if len(matching_plans) != 1:
                raise AppendOnlyConflict(
                    "dashboard snapshot plan key is missing one typed plan payload"
                )
            plans.append(matching_plans[0])

        def current_values(
            event_type: str, natural_keys: Iterable[str]
        ) -> list[Any]:
            current = _current_dashboard_prerequisite_events(
                records, event_type=event_type, **partition
            )
            values = []
            for natural_key in sorted(set(natural_keys)):
                resolved = current.get(natural_key)
                if resolved is None or not _dashboard_prerequisite_is_current(
                    records,
                    event_type=event_type,
                    registration=resolved[0],
                    evidence=resolved[1],
                    artifact=resolved[2],
                ):
                    raise AppendOnlyConflict(
                        f"dashboard snapshot key lacks current {event_type} evidence"
                    )
                values.append(resolved[1])
            return values

        topic_ids = {
            binding.blueprint_id for plan in plans for binding in plan.topic_bindings
        }
        topic_events = _current_dashboard_prerequisite_events(
            records,
            event_type="dashboard_topic_blueprint_registered",
            **partition,
        )
        topics = []
        topic_registrations = []
        from omni_migrator.semantic.topic_blueprints import TopicBlueprint

        for topic_id in sorted(topic_ids):
            resolved = topic_events.get(topic_id)
            if resolved is None or not _dashboard_prerequisite_is_current(
                records,
                event_type="dashboard_topic_blueprint_registered",
                registration=resolved[0],
                evidence=resolved[1],
                artifact=resolved[2],
            ):
                raise AppendOnlyConflict(
                    "dashboard snapshot Topic key is not currently registered"
                )
            topics.append(
                TopicBlueprint.model_validate_json(
                    canonical_json(resolved[0]["topic_blueprint"])
                )
            )
            topic_registrations.append(resolved[1])

        profile_ids = {
            binding.profile_id for plan in plans for binding in plan.profile_bindings
        }
        registered_profiles = {
            profile.profile_id: profile
            for _artifact, profile in _registered_semantic_profiles(
                records,
                tenant_ref=proposed.tenant_ref,
                run_id=proposed.run_id,
                scope_id=proposed.scope_id,
                migration_unit_id=proposed.migration_unit_id,
                validation_cycle_id=proposed.validation_cycle_id,
            )
        }
        if not profile_ids.issubset(registered_profiles):
            raise AppendOnlyConflict(
                "dashboard snapshot profile keys are unregistered or stale"
            )
        decision_ids = {
            binding.decision_id for plan in plans for binding in plan.decision_bindings
        }
        decision_ids.update(
            decision.decision_id
            for decision in proposed.decisions
            if decision.classification in {"different", "unknown"}
            and not decision.authorizes_build
        )
        registered_decisions = {
            decision.decision_id: decision
            for _artifact, decision in _registered_semantic_analysis_payloads(
                records,
                event_type="consolidation_decision_registered",
                tenant_ref=proposed.tenant_ref,
                run_id=proposed.run_id,
                scope_id=proposed.scope_id,
                migration_unit_id=proposed.migration_unit_id,
                validation_cycle_id=proposed.validation_cycle_id,
            )
        }
        if not decision_ids.issubset(registered_decisions):
            raise AppendOnlyConflict(
                "dashboard snapshot decision keys are unregistered or stale"
            )
        component_keys = [
            f"{topic.blueprint_id}:field:{field.field_id}"
            for topic in topics
            for field in topic.fields
        ] + [
            f"{topic.blueprint_id}:measure:{measure.measure_id}"
            for topic in topics
            for measure in topic.measures
        ]
        source_keys = [
            f"{plan.migration_unit_id}:{plan.source.page.object_id}" for plan in plans
        ]
        behavior_keys = [
            f"{plan.plan_id}:{resolution.resolution_id}"
            for plan in plans
            for resolution in plan.behavior_resolutions
            if resolution.disposition != "blocked"
        ]
        query_mapping_keys = [
            f"{plan.plan_id}:{mapping.query_id}"
            for plan in plans
            for mapping in plan.query_mappings
            if mapping.outcome == "mapped"
        ]
        query_disposition_keys = [
            f"{plan.plan_id}:{mapping.query_id}"
            for plan in plans
            for mapping in plan.query_mappings
            if mapping.outcome == "approved_exception"
        ]
        contexts = {plan.validation_context.context_hash: plan.validation_context for plan in plans}
        if len(contexts) != 1:
            raise AppendOnlyConflict(
                "dashboard snapshot plans do not share one current validation context"
            )
        projected = proposed.model_dump(mode="json")
        projected.update(
            validation_context=next(iter(contexts.values())).model_dump(mode="json"),
            source_dashboards=[
                item.model_dump(mode="json")
                for item in current_values(
                    "dashboard_source_acceptance_registered", source_keys
                )
            ],
            topic_blueprints=[item.model_dump(mode="json") for item in topics],
            registered_topics=[
                item.model_dump(mode="json") for item in topic_registrations
            ],
            accepted_topics=[
                item.model_dump(mode="json")
                for item in current_values(
                    "dashboard_topic_readiness_registered", topic_ids
                )
            ],
            topic_components=[
                item.model_dump(mode="json")
                for item in current_values(
                    "dashboard_topic_component_registered", component_keys
                )
            ],
            profiles=[
                registered_profiles[item].model_dump(mode="json")
                for item in sorted(profile_ids)
            ],
            decisions=[
                registered_decisions[item].model_dump(mode="json")
                for item in sorted(decision_ids)
            ],
            behavior_resolutions=[
                item.model_dump(mode="json")
                for item in current_values(
                    "dashboard_behavior_acceptance_registered", behavior_keys
                )
            ],
            query_dispositions=[
                item.model_dump(mode="json")
                for item in current_values(
                    "dashboard_query_disposition_registered", query_disposition_keys
                )
            ],
            query_mappings=[
                item.model_dump(mode="json")
                for item in current_values(
                    "dashboard_query_mapping_registered", query_mapping_keys
                )
            ],
            plan_registrations=[
                item.model_dump(mode="json") for item in plan_acceptances
            ],
            snapshot_hash="sha256:" + "0" * 64,
        )
        return finalize_dashboard_evidence_snapshot(projected)

    def assert_dashboard_evidence_snapshot_current(self, snapshot: Any) -> Any:
        """Revalidate a stored snapshot and every typed prerequisite on each read."""

        from omni_migrator.dashboards.rebuild_plan import (
            DashboardEvidenceSnapshot,
            dashboard_evidence_snapshot_content_sha256,
            dashboard_evidence_snapshot_hash,
        )

        value = (
            snapshot
            if isinstance(snapshot, DashboardEvidenceSnapshot)
            else DashboardEvidenceSnapshot.model_validate_json(canonical_json(snapshot))
        )
        if value.snapshot_hash != dashboard_evidence_snapshot_hash(value):
            raise AppendOnlyConflict("dashboard evidence snapshot hash is not canonical")
        records = self.records(value.tenant_ref, value.run_id)
        candidates = [
            record.get("payload", {})
            for record in records
            if record.get("record_type") == "event"
            and record.get("payload", {}).get("event_type")
            == "dashboard_evidence_snapshot_registered"
            and record.get("payload", {}).get("scope_id") == value.scope_id
            and record.get("payload", {}).get("wave_id") == value.wave_id
            and record.get("payload", {}).get("migration_unit_id")
            == value.migration_unit_id
            and record.get("payload", {}).get("validation_cycle_id")
            == value.validation_cycle_id
        ]
        if not candidates:
            raise AppendOnlyConflict("dashboard evidence snapshot is not registered")
        latest = max(candidates, key=lambda item: int(item.get("revision", 0)))
        expected = {"event_type": "dashboard_evidence_snapshot_registered", **value.model_dump(mode="json")}
        if latest != expected:
            raise AppendOnlyConflict("dashboard evidence snapshot is not current")
        snapshot_artifacts = [
            item
            for item in (
                record.get("payload", {})
                for record in records
                if record.get("record_type") == "artifact"
            )
            if item.get("artifact_type") == "dashboard_evidence_snapshot"
            and item.get("ref") == value.snapshot_ref
            and item.get("content_sha256")
            == dashboard_evidence_snapshot_content_sha256(value)
            and item.get("migration_unit_id") == value.migration_unit_id
            and item.get("validation_cycle_id") == value.validation_cycle_id
            and _current_artifact_payload(
                records, artifact_id=str(item.get("artifact_id", ""))
            )
            == item
        ]
        if len(snapshot_artifacts) != 1:
            raise AppendOnlyConflict(
                "dashboard evidence snapshot artifact is missing or stale"
            )
        _assert_dashboard_snapshot_current_registrations(records, value)
        return value

    def append_dashboard_evidence_snapshot(
        self,
        snapshot: Any,
        artifact: ArtifactEnvelope | Mapping[str, Any],
        *,
        idempotency_key: str,
    ) -> dict[str, Any]:
        """Register one artifact-backed dashboard-evidence snapshot revision."""

        from omni_migrator.dashboards.rebuild_plan import (
            DashboardEvidenceSnapshot,
            dashboard_evidence_snapshot_content_sha256,
            dashboard_evidence_snapshot_hash,
            finalize_dashboard_evidence_snapshot,
        )

        raw = (
            snapshot.model_dump(mode="json")
            if isinstance(snapshot, DashboardEvidenceSnapshot)
            else dict(snapshot)
        )
        finalized = finalize_dashboard_evidence_snapshot(raw)
        if raw.get("snapshot_hash") != finalized.snapshot_hash:
            raise AppendOnlyConflict("dashboard evidence snapshot hash is not canonical")
        if finalized.snapshot_hash != dashboard_evidence_snapshot_hash(finalized):
            raise AppendOnlyConflict("dashboard evidence snapshot failed hash validation")
        envelope = (
            artifact
            if isinstance(artifact, ArtifactEnvelope)
            else ArtifactEnvelope.from_mapping(artifact)
        )
        try:
            envelope.validate(
                expected_tenant_ref=finalized.tenant_ref,
                expected_run_id=finalized.run_id,
            )
        except (TypeError, ValueError) as exc:
            raise AppendOnlyConflict(
                "dashboard evidence snapshot artifact envelope is invalid"
            ) from exc
        migration_unit_ids = {
            item.migration_unit_id for item in finalized.source_dashboards
        }
        if (
            len(migration_unit_ids) != 1
            or migration_unit_ids != {finalized.migration_unit_id}
            or envelope.artifact_type != "dashboard_evidence_snapshot"
            or envelope.ref != finalized.snapshot_ref
            or envelope.content_sha256
            != dashboard_evidence_snapshot_content_sha256(finalized)
            or envelope.producer_ref
            not in {"agent-ref://migration-qa", "agent-ref://migration_qa"}
            or envelope.validation_cycle_id != finalized.validation_cycle_id
            or envelope.migration_unit_id != next(iter(migration_unit_ids))
            or parse_time(envelope.created_at) > parse_time(finalized.registered_at)
        ):
            raise AppendOnlyConflict(
                "dashboard evidence snapshot artifact binding is not exact"
            )
        payload = {
            "event_type": "dashboard_evidence_snapshot_registered",
            **finalized.model_dump(mode="json"),
        }

        def guard(records: list[dict[str, Any]]) -> None:
            if not _artifact_envelope_is_exactly_current(records, envelope):
                raise AppendOnlyConflict(
                    "dashboard evidence snapshot artifact is unregistered or stale"
                )

            required_inputs = list(
                _assert_dashboard_snapshot_current_registrations(records, finalized)
            )

            required_identities = {
                (
                    item.artifact_id,
                    item.revision,
                    item.content_sha256,
                )
                for item in required_inputs
            }
            declared_identities = {
                (
                    str(item.get("artifact_id")),
                    int(item.get("revision", 0)),
                    str(item.get("content_sha256")),
                )
                for item in envelope.input_artifacts
            }
            if declared_identities != required_identities:
                raise AppendOnlyConflict(
                    "dashboard evidence snapshot lineage is not its exact upstream set"
                )
            if any(
                parse_time(item.created_at) > parse_time(envelope.created_at)
                for item in required_inputs
            ):
                raise AppendOnlyConflict(
                    "dashboard evidence snapshot predates an upstream artifact"
                )

            prior = [
                record.get("payload", {})
                for record in records
                if record.get("record_type") == "event"
                and record.get("payload", {}).get("event_type")
                == "dashboard_evidence_snapshot_registered"
                and record.get("payload", {}).get("scope_id") == finalized.scope_id
                and record.get("payload", {}).get("wave_id") == finalized.wave_id
                and record.get("payload", {}).get("migration_unit_id")
                == finalized.migration_unit_id
                and record.get("payload", {}).get("validation_cycle_id")
                == finalized.validation_cycle_id
            ]
            identities = {str(item.get("snapshot_id")) for item in prior}
            if identities and identities != {finalized.snapshot_id}:
                raise AppendOnlyConflict(
                    "dashboard evidence scope cannot change snapshot identity"
                )
            revisions = [int(item.get("revision", 0)) for item in prior]
            if revisions and finalized.revision != max(revisions) + 1:
                raise AppendOnlyConflict(
                    "dashboard evidence snapshot revisions must advance by one"
                )
            if not revisions and finalized.revision != 1:
                raise AppendOnlyConflict(
                    "first dashboard evidence snapshot revision must be one"
                )
            if revisions:
                latest = max(prior, key=lambda item: int(item.get("revision", 0)))
                if finalized.supersedes_snapshot_hash != latest.get("snapshot_hash"):
                    raise AppendOnlyConflict(
                        "dashboard evidence snapshot must supersede the exact current hash"
                    )

        return self._append(
            tenant_ref=finalized.tenant_ref,
            run_id=finalized.run_id,
            record_type="event",
            record_id=(
                f"dashboard-evidence-snapshot:{finalized.scope_id}:"
                f"{finalized.wave_id}:{finalized.migration_unit_id}:"
                f"{finalized.validation_cycle_id}:{finalized.revision}"
            ),
            payload=payload,
            idempotency_key=idempotency_key,
            occurred_at=parse_time(finalized.registered_at),
            guard=guard,
        )

    def append_dashboard_plan_payload(
        self,
        plan: Any,
        artifact: ArtifactEnvelope | Mapping[str, Any],
        *,
        idempotency_key: str,
    ) -> dict[str, Any]:
        """Persist one canonical full plan payload bound to its current artifact."""

        from omni_migrator.dashboards.rebuild_plan import (
            DashboardRebuildPlan,
            dashboard_plan_content_sha256,
            dashboard_rebuild_plan_hash,
            finalize_dashboard_rebuild_plan,
        )

        raw = (
            plan.model_dump(mode="json")
            if isinstance(plan, DashboardRebuildPlan)
            else dict(plan)
        )
        value = finalize_dashboard_rebuild_plan(raw)
        if (
            raw != value.model_dump(mode="json")
            or value.plan_hash != dashboard_rebuild_plan_hash(value)
        ):
            raise AppendOnlyConflict("dashboard plan payload is not canonical")
        envelope = (
            artifact
            if isinstance(artifact, ArtifactEnvelope)
            else ArtifactEnvelope.from_mapping(artifact)
        )
        try:
            envelope.validate(
                expected_tenant_ref=envelope.tenant_ref,
                expected_run_id=value.run_id,
            )
        except (TypeError, ValueError) as exc:
            raise AppendOnlyConflict("dashboard plan artifact envelope is invalid") from exc
        if (
            envelope.artifact_type != "dashboard_rebuild_plan"
            or envelope.content_sha256 != dashboard_plan_content_sha256(value)
            or envelope.producer_ref
            not in {
                "agent-ref://domo-to-omni-architect",
                "agent-ref://domo_to_omni_architect",
            }
            or envelope.migration_unit_id != value.migration_unit_id
            or envelope.validation_cycle_id != value.validation_cycle_id
        ):
            raise AppendOnlyConflict(
                "dashboard plan payload does not bind its exact architect artifact"
            )

        payload = {
            "event_type": "dashboard_plan_payload_registered",
            "plan": value.model_dump(mode="json"),
        }

        def guard(records: list[dict[str, Any]]) -> None:
            if not _artifact_envelope_is_exactly_current(records, envelope):
                raise AppendOnlyConflict(
                    "dashboard plan payload artifact is unregistered or stale"
                )
            prior = [
                record.get("payload", {}).get("plan")
                for record in records
                if record.get("record_type") == "event"
                and record.get("payload", {}).get("event_type")
                == "dashboard_plan_payload_registered"
                and record.get("payload", {}).get("plan", {}).get("plan_id")
                == value.plan_id
            ]
            if prior:
                raise AppendOnlyConflict(
                    "dashboard plan payload identity is already registered"
                )

        return self._append(
            tenant_ref=envelope.tenant_ref,
            run_id=value.run_id,
            record_type="event",
            record_id=(
                f"dashboard-plan-payload:{value.scope_id}:{value.plan_id}:"
                f"{value.plan_hash.removeprefix('sha256:')}"
            ),
            payload=payload,
            idempotency_key=idempotency_key,
            occurred_at=parse_time(envelope.created_at),
            guard=guard,
        )

    def append_dashboard_plan_validation(
        self,
        registration: Any,
        *,
        idempotency_key: str,
    ) -> dict[str, Any]:
        """Persist one typed plan-validation attestation after exact store checks."""

        from omni_migrator.dashboards.rebuild_plan import (
            DashboardPlanValidationRegistration,
            dashboard_plan_validation_registration_hash,
        )

        value = (
            registration
            if isinstance(registration, DashboardPlanValidationRegistration)
            else DashboardPlanValidationRegistration.model_validate(registration)
        )
        if value.registration_hash != dashboard_plan_validation_registration_hash(value):
            raise AppendOnlyConflict("dashboard plan validation hash is not canonical")
        payload = {
            "event_type": "dashboard_plan_validated",
            **value.model_dump(mode="json"),
        }

        def guard(records: list[dict[str, Any]]) -> None:
            from omni_migrator.dashboards.rebuild_plan import DashboardEvidenceSnapshot

            snapshots = [
                record.get("payload", {})
                for record in records
                if record.get("record_type") == "event"
                and record.get("payload", {}).get("event_type")
                == "dashboard_evidence_snapshot_registered"
                and record.get("payload", {}).get("scope_id") == value.scope_id
                and record.get("payload", {}).get("wave_id") == value.wave_id
                and record.get("payload", {}).get("migration_unit_id")
                == value.migration_unit_id
                and record.get("payload", {}).get("validation_cycle_id")
                == value.validation_cycle_id
            ]
            if not snapshots:
                raise AppendOnlyConflict(
                    "dashboard validation requires a current evidence snapshot"
                )
            latest = max(snapshots, key=lambda item: int(item.get("revision", 0)))
            try:
                current_snapshot = DashboardEvidenceSnapshot.model_validate_json(
                    canonical_json(
                        {key: item for key, item in latest.items() if key != "event_type"}
                    )
                )
                _assert_dashboard_snapshot_current_registrations(
                    records, current_snapshot
                )
            except (AppendOnlyConflict, TypeError, ValueError) as exc:
                raise AppendOnlyConflict(
                    "dashboard validation requires current typed snapshot prerequisites"
                ) from exc
            if (
                latest.get("snapshot_ref") != value.evidence_snapshot_ref
                or latest.get("snapshot_hash") != value.evidence_snapshot_hash
                or int(latest.get("revision", 0)) != value.evidence_snapshot_revision
            ):
                raise AppendOnlyConflict(
                    "dashboard validation references a stale evidence snapshot"
                )
            matching_plan_registrations = [
                item
                for item in latest.get("plan_registrations", [])
                if item.get("plan_id") == value.plan_id
                and item.get("plan_hash") == value.plan_hash
                and item.get("migration_unit_id") == value.migration_unit_id
                and item.get("page_id") == value.page_id
                and item.get("validation_cycle_id") == value.validation_cycle_id
            ]
            if len(matching_plan_registrations) != 1:
                raise AppendOnlyConflict(
                    "dashboard validation does not match the current snapshot plan registration"
                )
            artifacts = [
                record.get("payload", {})
                for record in records
                if record.get("record_type") == "artifact"
                and record.get("payload", {}).get("ref") == value.plan_artifact_ref
            ]
            if len(artifacts) != 1:
                raise AppendOnlyConflict(
                    "dashboard validation requires one registered plan artifact"
                )
            artifact = artifacts[0]
            if (
                artifact.get("artifact_type") != "dashboard_rebuild_plan"
                or artifact.get("content_sha256")
                != value.plan_artifact_content_sha256
                or artifact.get("validation_cycle_id") != value.validation_cycle_id
                or artifact.get("migration_unit_id") != value.migration_unit_id
            ):
                raise AppendOnlyConflict(
                    "dashboard validation does not match the registered plan artifact"
                )

        return self._append(
            tenant_ref=value.tenant_ref,
            run_id=value.run_id,
            record_type="event",
            record_id=(
                f"dashboard-plan-validation:{value.scope_id}:{value.wave_id}:"
                f"{value.migration_unit_id}:{value.plan_id}:"
                f"{value.plan_hash.removeprefix('sha256:')}"
            ),
            payload=payload,
            idempotency_key=idempotency_key,
            occurred_at=parse_time(value.checked_at),
            guard=guard,
        )

    def append_qa_fixture_v2(
        self,
        fixture: Any,
        artifact: ArtifactEnvelope | Mapping[str, Any],
        *,
        idempotency_key: str,
    ) -> Any:
        """Register one canonical v2 fixture against its current artifact."""

        from omni_migrator.qa.acceptance import (
            QAFixtureV2,
            finalize_qa_fixture,
            qa_fixture_content_sha256,
            qa_fixture_hash,
        )

        raw = (
            fixture.model_dump(mode="json")
            if isinstance(fixture, QAFixtureV2)
            else dict(fixture)
        )
        value = finalize_qa_fixture(raw)
        if (
            raw.get("contract_version") != "domo-to-omni.qa-fixture.v2"
            or raw.get("fixture_hash") != value.fixture_hash
            or value.fixture_hash != qa_fixture_hash(value)
        ):
            raise AppendOnlyConflict("QA fixture v2 payload is not canonical")
        envelope = (
            artifact
            if isinstance(artifact, ArtifactEnvelope)
            else ArtifactEnvelope.from_mapping(artifact)
        )
        envelope.validate(
            expected_tenant_ref=value.tenant_ref,
            expected_run_id=value.run_id,
        )
        if (
            envelope.artifact_type != "qa_fixture"
            or envelope.ref != value.fixture_ref
            or envelope.content_sha256 != qa_fixture_content_sha256(value)
            or envelope.producer_ref != value.producer_ref
            or envelope.migration_unit_id != value.migration_unit_id
            or envelope.validation_cycle_id != value.validation_cycle_id
        ):
            raise AppendOnlyConflict(
                "QA fixture v2 does not match its exact artifact envelope"
            )
        payload = {
            "event_type": "qa_fixture_v2_registered",
            "artifact": envelope.to_mapping(),
            "fixture": value.model_dump(mode="json"),
        }

        def guard(records: list[dict[str, Any]]) -> None:
            current = _current_artifact_payload(
                records, artifact_id=envelope.artifact_id
            )
            try:
                current_envelope = (
                    ArtifactEnvelope.from_mapping(current)
                    if current is not None
                    else None
                )
            except (TypeError, ValueError) as exc:
                raise AppendOnlyConflict(
                    "QA fixture v2 requires a valid current artifact"
                ) from exc
            if (
                current_envelope is None
                or current_envelope.to_mapping() != envelope.to_mapping()
            ):
                raise AppendOnlyConflict(
                    "QA fixture v2 requires its exact current artifact"
                )
            if any(
                record.get("record_type") == "event"
                and record.get("payload", {}).get("event_type")
                == "qa_fixture_v2_registered"
                and (
                    record.get("payload", {}).get("artifact", {}).get("ref")
                    == envelope.ref
                    or record.get("payload", {}).get("fixture", {}).get(
                        "fixture_ref"
                    )
                    == value.fixture_ref
                )
                for record in records
            ):
                raise AppendOnlyConflict(
                    "QA fixture v2 payload is already registered"
                )

        self._append(
            tenant_ref=value.tenant_ref,
            run_id=value.run_id,
            record_type="event",
            record_id=f"qa-fixture-v2:{envelope.artifact_id}@{envelope.revision}",
            payload=payload,
            idempotency_key=idempotency_key,
            occurred_at=parse_time(value.created_at),
            guard=guard,
        )
        resolved = _current_registered_qa_v2_payload(
            self.records(value.tenant_ref, value.run_id),
            artifact_ref=envelope.ref,
            artifact_type="qa_fixture",
        )
        if resolved != value:
            raise AppendOnlyConflict("QA fixture v2 registration readback failed")
        return value

    def append_qa_result_v2(
        self,
        result: Any,
        artifact: ArtifactEnvelope | Mapping[str, Any],
        *,
        idempotency_key: str,
    ) -> Any:
        """Register one canonical v2 result against its current artifact."""

        from omni_migrator.qa.acceptance import (
            QAResultV2,
            finalize_qa_result,
            qa_result_content_sha256,
            qa_result_hash,
        )

        raw = (
            result.model_dump(mode="json")
            if isinstance(result, QAResultV2)
            else dict(result)
        )
        value = finalize_qa_result(raw)
        if (
            raw.get("contract_version") != "domo-to-omni.qa-result.v2"
            or raw.get("result_hash") != value.result_hash
            or value.result_hash != qa_result_hash(value)
        ):
            raise AppendOnlyConflict("QA result v2 payload is not canonical")
        envelope = (
            artifact
            if isinstance(artifact, ArtifactEnvelope)
            else ArtifactEnvelope.from_mapping(artifact)
        )
        envelope.validate(
            expected_tenant_ref=value.tenant_ref,
            expected_run_id=value.run_id,
        )
        if (
            envelope.artifact_type != "qa_result"
            or envelope.ref != value.result_ref
            or envelope.content_sha256 != qa_result_content_sha256(value)
            or envelope.producer_ref != value.verifier_ref
            or envelope.migration_unit_id != value.migration_unit_id
            or envelope.validation_cycle_id != value.validation_cycle_id
        ):
            raise AppendOnlyConflict(
                "QA result v2 does not match its exact artifact envelope"
            )
        payload = {
            "event_type": "qa_result_v2_registered",
            "artifact": envelope.to_mapping(),
            "result": value.model_dump(mode="json"),
        }

        def guard(records: list[dict[str, Any]]) -> None:
            current = _current_artifact_payload(
                records, artifact_id=envelope.artifact_id
            )
            try:
                current_envelope = (
                    ArtifactEnvelope.from_mapping(current)
                    if current is not None
                    else None
                )
            except (TypeError, ValueError) as exc:
                raise AppendOnlyConflict(
                    "QA result v2 requires a valid current artifact"
                ) from exc
            if (
                current_envelope is None
                or current_envelope.to_mapping() != envelope.to_mapping()
            ):
                raise AppendOnlyConflict(
                    "QA result v2 requires its exact current artifact"
                )
            if any(
                record.get("record_type") == "event"
                and record.get("payload", {}).get("event_type")
                == "qa_result_v2_registered"
                and (
                    record.get("payload", {}).get("artifact", {}).get("ref")
                    == envelope.ref
                    or record.get("payload", {}).get("result", {}).get(
                        "result_ref"
                    )
                    == value.result_ref
                )
                for record in records
            ):
                raise AppendOnlyConflict(
                    "QA result v2 payload is already registered"
                )

        self._append(
            tenant_ref=value.tenant_ref,
            run_id=value.run_id,
            record_type="event",
            record_id=f"qa-result-v2:{envelope.artifact_id}@{envelope.revision}",
            payload=payload,
            idempotency_key=idempotency_key,
            occurred_at=parse_time(value.executed_at),
            guard=guard,
        )
        resolved = _current_registered_qa_v2_payload(
            self.records(value.tenant_ref, value.run_id),
            artifact_ref=envelope.ref,
            artifact_type="qa_result",
        )
        if resolved != value:
            raise AppendOnlyConflict("QA result v2 registration readback failed")
        return value

    def append_target_environment_registration(
        self,
        *,
        tenant_ref: str,
        run_id: str,
        environment_ref: str,
        environment_tier: str,
        target_refs: Iterable[str],
        registered_by_ref: str,
        registered_at: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        """Register the configured target environment used by QA observations.

        This local control-plane record is a trust anchor for reference identity;
        it is not proof that a live vendor tenant was contacted.
        """

        validate_reference(tenant_ref)
        validate_run_id(run_id)
        validate_reference(environment_ref)
        validate_reference(registered_by_ref)
        targets = tuple(target_refs)
        if environment_tier not in {"development", "staging", "production"}:
            raise ValueError("target environment tier is unsupported")
        if not targets or len(targets) != len(set(targets)):
            raise ValueError("target environment references must be non-empty and unique")
        for reference in targets:
            validate_reference(reference)
        if registered_by_ref.split(":", 1)[0] not in {"human-ref", "person-ref"}:
            raise ValueError("target environments require a human configuration owner")
        when = parse_time(registered_at)
        payload = {
            "event_type": "target_environment_registered",
            "environment_ref": environment_ref,
            "environment_tier": environment_tier,
            "target_refs": list(targets),
            "registered_by_ref": registered_by_ref,
            "registered_at": registered_at,
        }

        def guard(records: list[dict[str, Any]]) -> None:
            if any(
                item.get("record_type") == "event"
                and item.get("payload", {}).get("event_type")
                == "target_environment_registered"
                and item.get("payload", {}).get("environment_ref")
                == environment_ref
                for item in records
            ):
                raise AppendOnlyConflict("target environment is already registered")

        return self._append(
            tenant_ref=tenant_ref,
            run_id=run_id,
            record_type="event",
            record_id=f"target-environment:{sha256_json(environment_ref)[:24]}",
            payload=payload,
            idempotency_key=idempotency_key,
            occurred_at=when,
            guard=guard,
        )

    def append_qa_target_operation_outcome(
        self,
        outcome: Any,
        artifact: ArtifactEnvelope | Mapping[str, Any],
        *,
        idempotency_key: str,
    ) -> Any:
        """Register one exact successful target operation for trusted QA use."""

        from omni_migrator.qa.target_outcomes import (
            QATargetOperationOutcome,
            finalize_qa_target_operation_outcome,
            qa_target_operation_outcome_content_sha256,
            qa_target_operation_outcome_hash,
        )

        raw = (
            outcome.model_dump(mode="json")
            if isinstance(outcome, QATargetOperationOutcome)
            else dict(outcome)
        )
        value = finalize_qa_target_operation_outcome(raw)
        if (
            raw.get("contract_version")
            != "domo-to-omni.qa-target-operation-outcome.v1"
            or raw.get("outcome_hash") != value.outcome_hash
            or value.outcome_hash != qa_target_operation_outcome_hash(value)
        ):
            raise AppendOnlyConflict("QA target operation outcome is not canonical")
        envelope = (
            artifact
            if isinstance(artifact, ArtifactEnvelope)
            else ArtifactEnvelope.from_mapping(artifact)
        )
        envelope.validate(
            expected_tenant_ref=value.tenant_ref,
            expected_run_id=value.run_id,
        )
        expected_lineage = {
            (
                binding.artifact_id,
                binding.revision,
                binding.content_sha256,
            )
            for binding in (
                value.promoted_target_artifact,
                value.receipt_binding.artifact,
                value.readback_binding.artifact,
            )
        }
        actual_lineage = {
            (
                str(item.get("artifact_id", "")),
                int(item.get("revision", 0)),
                str(item.get("content_sha256", "")),
            )
            for item in envelope.input_artifacts
        }
        if (
            envelope.artifact_type != "qa_target_operation_outcome"
            or envelope.ref != value.outcome_ref
            or envelope.content_sha256
            != qa_target_operation_outcome_content_sha256(value)
            or envelope.producer_ref != "agent-ref://migration-qa"
            or envelope.migration_unit_id != value.migration_unit_id
            or envelope.validation_cycle_id != value.validation_cycle_id
            or actual_lineage != expected_lineage
        ):
            raise AppendOnlyConflict(
                "QA target operation outcome does not match its exact artifact envelope"
            )
        payload = {
            "event_type": "qa_target_operation_outcome_registered",
            "artifact": envelope.to_mapping(),
            "outcome": value.model_dump(mode="json"),
        }

        def guard(records: list[dict[str, Any]]) -> None:
            current = _current_artifact_payload(
                records, artifact_id=envelope.artifact_id
            )
            try:
                current_envelope = (
                    ArtifactEnvelope.from_mapping(current)
                    if current is not None
                    else None
                )
            except (TypeError, ValueError) as exc:
                raise AppendOnlyConflict(
                    "QA target operation outcome requires a valid current artifact"
                ) from exc
            if (
                current_envelope is None
                or current_envelope.to_mapping() != envelope.to_mapping()
            ):
                raise AppendOnlyConflict(
                    "QA target operation outcome requires its exact current artifact"
                )
            if any(
                not _qa_binding_matches_current_artifact(records, binding)
                for binding in (
                    value.promoted_target_artifact,
                    value.receipt_binding.artifact,
                    value.readback_binding.artifact,
                )
            ):
                raise AppendOnlyConflict(
                    "QA target operation outcome contains stale target evidence"
                )
            environments = [
                item.get("payload", {})
                for item in records
                if item.get("record_type") == "event"
                and item.get("payload", {}).get("event_type")
                == "target_environment_registered"
                and item.get("payload", {}).get("environment_ref")
                == value.target_environment_ref
            ]
            if len(environments) != 1 or (
                environments[0].get("environment_tier")
                != value.target_environment_tier
                or value.receipt_binding.target_ref
                not in set(environments[0].get("target_refs", []))
            ):
                raise AppendOnlyConflict(
                    "QA target operation outcome lacks its trusted target environment"
                )
            if any(
                item.get("record_type") == "event"
                and item.get("payload", {}).get("event_type")
                == "qa_target_operation_outcome_registered"
                and (
                    item.get("payload", {}).get("outcome", {}).get("operation_id")
                    == value.operation_id
                    or item.get("payload", {}).get("outcome", {}).get("outcome_ref")
                    == value.outcome_ref
                )
                for item in records
            ):
                raise AppendOnlyConflict(
                    "QA target operation outcome is already registered"
                )

        self._append(
            tenant_ref=value.tenant_ref,
            run_id=value.run_id,
            record_type="event",
            record_id=f"qa-target-operation-outcome:{value.operation_id}",
            payload=payload,
            idempotency_key=idempotency_key,
            occurred_at=parse_time(value.recorded_at),
            guard=guard,
        )
        resolved = _current_registered_qa_target_operation_outcome(
            self.records(value.tenant_ref, value.run_id),
            operation_id=value.operation_id,
        )
        if resolved != value:
            raise AppendOnlyConflict(
                "QA target operation outcome registration readback failed"
            )
        return value

    def append_production_validation_report(
        self,
        report: Any,
        artifact: ArtifactEnvelope | Mapping[str, Any],
        *,
        idempotency_key: str,
    ) -> Any:
        """Register a report only after its exact production suite is validated."""

        from omni_migrator.qa.production import (
            ProductionValidationReport,
            finalize_production_validation_report,
            production_validation_report_content_sha256,
            production_validation_report_hash,
        )

        raw = (
            report.model_dump(mode="json")
            if isinstance(report, ProductionValidationReport)
            else dict(report)
        )
        value = finalize_production_validation_report(raw)
        if (
            raw.get("contract_version")
            != "domo-to-omni.production-validation-report.v1"
            or raw.get("report_hash") != value.report_hash
            or value.report_hash != production_validation_report_hash(value)
        ):
            raise AppendOnlyConflict("production validation report is not canonical")
        envelope = (
            artifact
            if isinstance(artifact, ArtifactEnvelope)
            else ArtifactEnvelope.from_mapping(artifact)
        )
        envelope.validate(
            expected_tenant_ref=value.tenant_ref,
            expected_run_id=value.run_id,
        )
        bound_evidence = (
            value.suite.artifact,
            value.suite_validation_artifact,
            *value.accepted_evidence_bindings.all_artifacts(),
        )
        expected_lineage = {
            (binding.artifact_id, binding.revision, binding.content_sha256)
            for binding in bound_evidence
        }
        actual_lineage = {
            (
                str(item.get("artifact_id", "")),
                int(item.get("revision", 0)),
                str(item.get("content_sha256", "")),
            )
            for item in envelope.input_artifacts
        }
        if (
            envelope.artifact_type != "production_validation_report"
            or envelope.ref != value.report_ref
            or envelope.content_sha256
            != production_validation_report_content_sha256(value)
            or envelope.producer_ref != "agent-ref://migration-qa"
            or envelope.migration_unit_id != value.migration_unit_id
            or envelope.validation_cycle_id != value.validation_cycle_id
            or actual_lineage != expected_lineage
        ):
            raise AppendOnlyConflict(
                "production validation report does not match its exact artifact envelope"
            )
        payload = {
            "event_type": "production_validation_report_registered",
            "artifact": envelope.to_mapping(),
            "report": value.model_dump(mode="json"),
        }

        def guard(records: list[dict[str, Any]]) -> None:
            current = _current_artifact_payload(
                records, artifact_id=envelope.artifact_id
            )
            try:
                current_envelope = (
                    ArtifactEnvelope.from_mapping(current)
                    if current is not None
                    else None
                )
            except (TypeError, ValueError) as exc:
                raise AppendOnlyConflict(
                    "production validation report requires a valid current artifact"
                ) from exc
            if (
                current_envelope is None
                or current_envelope.to_mapping() != envelope.to_mapping()
            ):
                raise AppendOnlyConflict(
                    "production validation report requires its exact current artifact"
                )
            if any(
                not _qa_binding_matches_current_artifact(records, binding)
                for binding in bound_evidence
            ):
                raise AppendOnlyConflict(
                    "production validation report contains stale accepted evidence"
                )
            validation_events = [
                item.get("payload", {})
                for item in records
                if item.get("record_type") == "event"
                and item.get("payload", {}).get("event_type")
                == "qa_suite_validated"
                and item.get("payload", {}).get("registration_ref")
                == value.suite_validation.registration_ref
            ]
            if len(validation_events) != 1 or {
                key: item
                for key, item in validation_events[0].items()
                if key != "event_type"
            } != value.suite_validation.model_dump(mode="json"):
                raise AppendOnlyConflict(
                    "production report requires its exact store-validated QA suite"
                )
            readbacks = {
                item.operation_id: item
                for item in value.accepted_evidence_bindings.target_readbacks
            }
            promoted_refs: set[str] = set()
            for receipt in value.accepted_evidence_bindings.target_receipts:
                outcome = _current_registered_qa_target_operation_outcome(
                    records, operation_id=receipt.operation_id
                )
                if (
                    outcome is None
                    or outcome.receipt_binding != receipt
                    or outcome.readback_binding
                    != readbacks.get(receipt.operation_id)
                    or outcome.target_environment_tier != "production"
                ):
                    raise AppendOnlyConflict(
                        "production report lacks an exact trusted target outcome"
                    )
                promoted_refs.add(outcome.promoted_target_artifact.artifact_ref)
            if promoted_refs != {
                item.artifact_ref
                for item in value.accepted_evidence_bindings.target_artifacts
            }:
                raise AppendOnlyConflict(
                    "production report target outcomes do not cover every promoted target"
                )
            if any(
                item.get("record_type") == "event"
                and item.get("payload", {}).get("event_type")
                == "production_validation_report_registered"
                and item.get("payload", {}).get("report", {}).get("report_ref")
                == value.report_ref
                for item in records
            ):
                raise AppendOnlyConflict(
                    "production validation report is already registered"
                )

        self._append(
            tenant_ref=value.tenant_ref,
            run_id=value.run_id,
            record_type="event",
            record_id=f"production-validation-report:{value.report_id}",
            payload=payload,
            idempotency_key=idempotency_key,
            occurred_at=parse_time(value.created_at),
            guard=guard,
        )
        resolved = _current_registered_production_validation_report(
            self.records(value.tenant_ref, value.run_id),
            report_ref=value.report_ref,
        )
        if resolved != value:
            raise AppendOnlyConflict(
                "production validation report registration readback failed"
            )
        return value

    def append_documentation_package(
        self,
        package: Any,
        artifact: ArtifactEnvelope | Mapping[str, Any],
        *,
        idempotency_key: str,
    ) -> Any:
        """Register one canonical, accepted-artifact-only documentation package."""

        from omni_migrator.control_plane.documentation import (
            DocumentationPackage,
            documentation_package_hash,
            finalize_documentation_package,
        )

        raw = (
            package.model_dump(mode="json")
            if isinstance(package, DocumentationPackage)
            else dict(package)
        )
        value = finalize_documentation_package(raw)
        if (
            raw != value.model_dump(mode="json")
            or value.package_hash != documentation_package_hash(value)
        ):
            raise AppendOnlyConflict(
                "documentation package is not canonical and pre-finalized"
            )
        envelope = (
            artifact
            if isinstance(artifact, ArtifactEnvelope)
            else ArtifactEnvelope.from_mapping(artifact)
        )
        try:
            envelope.validate(
                expected_tenant_ref=value.tenant_ref,
                expected_run_id=value.run_id,
            )
        except (TypeError, ValueError) as exc:
            raise AppendOnlyConflict(
                "documentation package artifact envelope is invalid"
            ) from exc
        payload = {
            "event_type": "documentation_package_registered",
            "artifact": envelope.to_mapping(),
            "package": value.model_dump(mode="json"),
        }

        def guard(records: list[dict[str, Any]]) -> None:
            errors = _documentation_registration_errors(
                records,
                package=value,
                package_artifact=envelope,
            )
            if errors:
                raise AppendOnlyConflict(
                    "documentation package is not current and accepted: "
                    + "; ".join(errors)
                )
            prior = [
                item.get("payload", {})
                for item in records
                if item.get("record_type") == "event"
                and item.get("payload", {}).get("event_type")
                == "documentation_package_registered"
                and (
                    item.get("payload", {}).get("package", {}).get("package_id")
                    == value.package_id
                    or all(
                        item.get("payload", {}).get("package", {}).get(key)
                        == expected
                        for key, expected in (
                            ("scope_id", value.scope_id),
                            ("wave_id", value.wave_id),
                            ("migration_unit_id", value.migration_unit_id),
                            ("validation_cycle_id", value.validation_cycle_id),
                        )
                    )
                )
            ]
            if prior:
                raise AppendOnlyConflict(
                    "documentation package is already registered for this unit and cycle"
                )

        self._append(
            tenant_ref=value.tenant_ref,
            run_id=value.run_id,
            record_type="event",
            record_id=f"documentation-package:{value.package_id}",
            payload=payload,
            idempotency_key=idempotency_key,
            occurred_at=parse_time(value.created_at),
            guard=guard,
        )
        resolved = self.resolve_current_documentation_package(
            value.tenant_ref,
            value.run_id,
            scope_id=value.scope_id,
            wave_id=value.wave_id,
            migration_unit_id=value.migration_unit_id,
            validation_cycle_id=value.validation_cycle_id,
            package_id=value.package_id,
        )
        if resolved != value:
            raise AppendOnlyConflict(
                "documentation package registration readback failed"
            )
        return value

    def resolve_current_documentation_package(
        self,
        tenant_ref: str,
        run_id: str,
        *,
        scope_id: str,
        wave_id: str,
        migration_unit_id: str,
        validation_cycle_id: str,
        package_id: str | None = None,
    ) -> Any | None:
        """Return one exact current documentation package or fail closed."""

        return _current_registered_documentation_package(
            self.records(tenant_ref, run_id),
            tenant_ref=tenant_ref,
            run_id=run_id,
            scope_id=scope_id,
            wave_id=wave_id,
            migration_unit_id=migration_unit_id,
            validation_cycle_id=validation_cycle_id,
            package_id=package_id,
        )

    def registered_documentation_packages(
        self,
        tenant_ref: str,
        run_id: str,
        *,
        scope_id: str,
        wave_id: str,
        migration_unit_id: str,
        validation_cycle_id: str,
    ) -> tuple[Any, ...]:
        """Query the exact current package set for one unit/cycle partition."""

        value = self.resolve_current_documentation_package(
            tenant_ref,
            run_id,
            scope_id=scope_id,
            wave_id=wave_id,
            migration_unit_id=migration_unit_id,
            validation_cycle_id=validation_cycle_id,
        )
        return (value,) if value is not None else ()

    def append_qa_evidence_snapshot(
        self,
        snapshot: Any,
        *,
        idempotency_key: str,
    ) -> dict[str, Any]:
        """Register one metadata-only QA evidence snapshot.

        Every binding must identify the exact latest artifact revision in this
        ledger partition.  The snapshot carries hashes and safe references only;
        raw query rows, screenshots, and source payloads remain outside the
        control-plane ledger.
        """

        from omni_migrator.qa.acceptance import (
            QAEvidenceSnapshot,
            finalize_qa_evidence_snapshot,
            qa_evidence_snapshot_hash,
        )

        raw = (
            snapshot.model_dump(mode="json")
            if isinstance(snapshot, QAEvidenceSnapshot)
            else dict(snapshot)
        )
        finalized = finalize_qa_evidence_snapshot(raw)
        if raw.get("snapshot_hash") != finalized.snapshot_hash:
            raise AppendOnlyConflict("QA evidence snapshot hash is not canonical")
        if finalized.snapshot_hash != qa_evidence_snapshot_hash(finalized):
            raise AppendOnlyConflict("QA evidence snapshot failed hash validation")
        payload = {
            "event_type": "qa_evidence_snapshot_registered",
            **finalized.model_dump(mode="json"),
        }

        def guard(records: list[dict[str, Any]]) -> None:
            stale_refs = sorted(
                binding.artifact_ref
                for binding in finalized.bindings.all_artifacts()
                if not _qa_binding_matches_current_artifact(records, binding)
            )
            if stale_refs:
                raise AppendOnlyConflict(
                    "QA evidence snapshot contains unregistered or stale artifact "
                    f"bindings: {stale_refs}"
                )

            unregistered_v2_refs = sorted(
                binding.artifact_ref
                for binding in (
                    *finalized.bindings.fixture_artifacts,
                    *finalized.bindings.result_artifacts,
                )
                if not _qa_v2_payload_matches_current_artifact(records, binding)
            )
            if unregistered_v2_refs:
                raise AppendOnlyConflict(
                    "QA evidence snapshot requires exact registered canonical v2 "
                    f"fixture/result payloads: {unregistered_v2_refs}"
                )

            prior = [
                record.get("payload", {})
                for record in records
                if record.get("record_type") == "event"
                and record.get("payload", {}).get("event_type")
                == "qa_evidence_snapshot_registered"
                and record.get("payload", {}).get("scope_id") == finalized.scope_id
                and record.get("payload", {}).get("wave_id") == finalized.wave_id
                and record.get("payload", {}).get("migration_unit_id")
                == finalized.migration_unit_id
                and record.get("payload", {}).get("validation_cycle_id")
                == finalized.validation_cycle_id
            ]
            identities = {str(item.get("snapshot_id")) for item in prior}
            if identities and identities != {finalized.snapshot_id}:
                raise AppendOnlyConflict(
                    "QA evidence partition cannot change snapshot identity"
                )
            revisions = [int(item.get("revision", 0)) for item in prior]
            if revisions and finalized.revision != max(revisions) + 1:
                raise AppendOnlyConflict(
                    "QA evidence snapshot revisions must advance by one"
                )
            if not revisions and finalized.revision != 1:
                raise AppendOnlyConflict(
                    "first QA evidence snapshot revision must be one"
                )
            if revisions:
                latest = max(prior, key=lambda item: int(item.get("revision", 0)))
                if finalized.supersedes_snapshot_hash != latest.get("snapshot_hash"):
                    raise AppendOnlyConflict(
                        "QA evidence snapshot must supersede the exact current hash"
                    )

        return self._append(
            tenant_ref=finalized.tenant_ref,
            run_id=finalized.run_id,
            record_type="event",
            record_id=(
                f"qa-evidence-snapshot:{finalized.scope_id}:{finalized.wave_id}:"
                f"{finalized.migration_unit_id}:{finalized.validation_cycle_id}:"
                f"{finalized.revision}"
            ),
            payload=payload,
            idempotency_key=idempotency_key,
            occurred_at=parse_time(finalized.registered_at),
            guard=guard,
        )

    def append_qa_suite_validation(
        self,
        registration: Any,
        *,
        idempotency_key: str,
    ) -> Any:
        """Append the exact current trusted QA-suite validation attestation."""

        from omni_migrator.qa.acceptance import (
            QASuiteValidationRegistration,
            qa_suite_validation_registration_hash,
        )

        value = (
            registration
            if isinstance(registration, QASuiteValidationRegistration)
            else QASuiteValidationRegistration.model_validate(registration)
        )
        if value.registration_hash != qa_suite_validation_registration_hash(value):
            raise AppendOnlyConflict("QA suite validation hash is not canonical")
        payload = {
            "event_type": "qa_suite_validated",
            **value.model_dump(mode="json"),
        }

        def guard(records: list[dict[str, Any]]) -> None:
            snapshots = [
                record.get("payload", {})
                for record in records
                if record.get("record_type") == "event"
                and record.get("payload", {}).get("event_type")
                == "qa_evidence_snapshot_registered"
                and record.get("payload", {}).get("scope_id") == value.scope_id
                and record.get("payload", {}).get("wave_id") == value.wave_id
                and record.get("payload", {}).get("migration_unit_id")
                == value.migration_unit_id
                and record.get("payload", {}).get("validation_cycle_id")
                == value.validation_cycle_id
            ]
            if not snapshots:
                raise AppendOnlyConflict(
                    "QA suite validation requires a current evidence snapshot"
                )
            latest = max(snapshots, key=lambda item: int(item.get("revision", 0)))
            if (
                latest.get("snapshot_ref") != value.evidence_snapshot_ref
                or latest.get("snapshot_hash") != value.evidence_snapshot_hash
                or int(latest.get("revision", 0)) != value.evidence_snapshot_revision
            ):
                raise AppendOnlyConflict(
                    "QA suite validation references a stale evidence snapshot"
                )

            try:
                from omni_migrator.qa.acceptance import (
                    finalize_qa_evidence_snapshot,
                )

                stored_snapshot = {
                    key: item for key, item in latest.items() if key != "event_type"
                }
                snapshot = finalize_qa_evidence_snapshot(stored_snapshot)
                if stored_snapshot.get("snapshot_hash") != snapshot.snapshot_hash:
                    raise ValueError("stored QA evidence snapshot hash is stale")
            except (TypeError, ValueError) as exc:
                raise AppendOnlyConflict(
                    "stored QA evidence snapshot is invalid"
                ) from exc
            if any(
                not _qa_binding_matches_current_artifact(records, binding)
                for binding in snapshot.bindings.all_artifacts()
            ):
                raise AppendOnlyConflict(
                    "QA suite validation references superseded bound evidence"
                )
            if any(
                not _qa_v2_payload_matches_current_artifact(records, binding)
                for binding in (
                    *snapshot.bindings.fixture_artifacts,
                    *snapshot.bindings.result_artifacts,
                )
            ):
                raise AppendOnlyConflict(
                    "QA suite validation requires current registered canonical v2 "
                    "fixture/result payloads"
                )

            suite_artifacts = [
                record.get("payload", {})
                for record in records
                if record.get("record_type") == "artifact"
                and record.get("payload", {}).get("artifact_type")
                == "qa_acceptance_suite"
                and record.get("payload", {}).get("migration_unit_id")
                == value.migration_unit_id
                and record.get("payload", {}).get("validation_cycle_id")
                == value.validation_cycle_id
            ]
            current_by_id = {
                str(item.get("artifact_id")): _current_artifact_payload(
                    records, artifact_id=str(item.get("artifact_id"))
                )
                for item in suite_artifacts
            }
            current = [
                item
                for item in current_by_id.values()
                if item is not None
                and item.get("artifact_type") == "qa_acceptance_suite"
                and item.get("migration_unit_id") == value.migration_unit_id
                and item.get("validation_cycle_id") == value.validation_cycle_id
            ]
            if len(current) != 1:
                raise AppendOnlyConflict(
                    "QA suite validation requires exactly one current suite artifact"
                )
            artifact = current[0]
            if (
                artifact.get("ref") != value.suite_artifact_ref
                or artifact.get("content_sha256")
                != value.suite_artifact_content_sha256
                or artifact.get("producer_ref") != value.verifier_ref
            ):
                raise AppendOnlyConflict(
                    "QA suite validation does not match the current suite artifact"
                )

        self._append(
            tenant_ref=value.tenant_ref,
            run_id=value.run_id,
            record_type="event",
            record_id=(
                f"qa-suite-validation:{value.scope_id}:{value.wave_id}:"
                f"{value.migration_unit_id}:{value.validation_cycle_id}:"
                f"{value.suite_hash.removeprefix('sha256:')}"
            ),
            payload=payload,
            idempotency_key=idempotency_key,
            occurred_at=parse_time(value.checked_at),
            guard=guard,
        )
        return value

    def append_domo_inventory_observation(
        self,
        observation: Mapping[str, Any],
        artifact: ArtifactEnvelope | Mapping[str, Any],
        *,
        idempotency_key: str,
    ) -> dict[str, Any]:
        """Bind one canonical Domo observation payload to its current artifact."""

        from omni_migrator.control_plane.domo_inventory import (
            inventory_observation_content_sha256,
            validate_inventory_observation,
        )

        raw = dict(observation)
        errors = validate_inventory_observation(raw)
        if (
            raw.get("contract_version")
            != "domo-to-omni.inventory-observation.v1"
            or raw.get("immutable") is not True
            or errors
        ):
            raise AppendOnlyConflict(
                "Domo inventory observation payload is not canonical: "
                + "; ".join(errors)
            )
        envelope = (
            artifact
            if isinstance(artifact, ArtifactEnvelope)
            else ArtifactEnvelope.from_mapping(artifact)
        )
        tenant_ref = str(raw.get("source_tenant_ref", ""))
        run_id = str(raw.get("run_id", ""))
        scope_id = str(raw.get("scope_id", ""))
        envelope.validate(
            expected_tenant_ref=tenant_ref,
            expected_run_id=run_id,
        )
        if (
            envelope.artifact_type != "domo_inventory_observation"
            or envelope.content_sha256
            != inventory_observation_content_sha256(raw)
            or envelope.producer_ref
            != "agent-ref://data-acquisition-ingestion"
        ):
            raise AppendOnlyConflict(
                "Domo inventory observation does not match its artifact envelope"
            )
        payload = {
            "event_type": "domo_inventory_observation_registered",
            "artifact": envelope.to_mapping(),
            "observation": raw,
        }

        def guard(records: list[dict[str, Any]]) -> None:
            if not _artifact_envelope_is_exactly_current(records, envelope):
                raise AppendOnlyConflict(
                    "Domo inventory observation requires its exact current artifact"
                )
            if any(
                record.get("record_type") == "event"
                and record.get("payload", {}).get("event_type")
                == "domo_inventory_observation_registered"
                and (
                    record.get("payload", {}).get("observation", {}).get(
                        "observation_id"
                    )
                    == raw.get("observation_id")
                    or record.get("payload", {}).get("artifact", {}).get("ref")
                    == envelope.ref
                )
                for record in records
            ):
                raise AppendOnlyConflict(
                    "Domo inventory observation is already registered"
                )

        self._append(
            tenant_ref=tenant_ref,
            run_id=run_id,
            record_type="event",
            record_id=(
                f"domo-inventory-observation:{raw['observation_id']}:"
                f"{envelope.artifact_id}@{envelope.revision}"
            ),
            payload=payload,
            idempotency_key=idempotency_key,
            occurred_at=parse_time(str(raw["observed_at"])),
            guard=guard,
        )
        resolved = _registered_domo_observations(
            self.records(tenant_ref, run_id),
            tenant_ref=tenant_ref,
            run_id=run_id,
            scope_id=scope_id,
        )
        if not any(item == raw for item in resolved):
            raise AppendOnlyConflict(
                "Domo inventory observation registration readback failed"
            )
        return raw

    def append_domo_portfolio_inventory(
        self,
        portfolio: Mapping[str, Any],
        artifact: ArtifactEnvelope | Mapping[str, Any],
        *,
        idempotency_key: str,
    ) -> dict[str, Any]:
        """Bind one canonical portfolio to its exact registered observations."""

        from omni_migrator.control_plane.domo_inventory import (
            portfolio_inventory_content_sha256,
            validate_portfolio_inventory,
        )

        raw = dict(portfolio)
        if (
            raw.get("contract_version")
            != "domo-to-omni.portfolio-inventory.v1"
            or raw.get("immutable") is not True
        ):
            raise AppendOnlyConflict(
                "Domo portfolio inventory payload is not canonical"
            )
        envelope = (
            artifact
            if isinstance(artifact, ArtifactEnvelope)
            else ArtifactEnvelope.from_mapping(artifact)
        )
        tenant_ref = str(raw.get("source_tenant_ref", ""))
        run_id = str(raw.get("run_id", ""))
        scope_id = str(raw.get("scope_id", ""))
        envelope.validate(
            expected_tenant_ref=tenant_ref,
            expected_run_id=run_id,
        )
        if (
            envelope.artifact_type != "domo_portfolio_inventory"
            or envelope.content_sha256
            != portfolio_inventory_content_sha256(raw)
            or envelope.producer_ref
            not in {
                "agent-ref://inventory-intake",
                "agent-ref://domo-to-omni-architect",
            }
        ):
            raise AppendOnlyConflict(
                "Domo portfolio inventory does not match its artifact envelope"
            )
        payload = {
            "event_type": "domo_portfolio_inventory_registered",
            "artifact": envelope.to_mapping(),
            "portfolio": raw,
        }

        def guard(records: list[dict[str, Any]]) -> None:
            if not _artifact_envelope_is_exactly_current(records, envelope):
                raise AppendOnlyConflict(
                    "Domo portfolio inventory requires its exact current artifact"
                )
            root_binding_fields = {
                "source_object_graph_ref": "source_object_graph",
                "evidence_bundle_ref": "evidence_bundle",
                "coverage_ledger_ref": "coverage_ledger",
                "inventory_snapshot_ref": "inventory_snapshot",
            }
            for field_name, artifact_type in root_binding_fields.items():
                current_candidates = [
                    item
                    for item in (
                        record.get("payload", {})
                        for record in records
                        if record.get("record_type") == "artifact"
                    )
                    if item.get("artifact_type") == artifact_type
                    and _current_artifact_payload(
                        records,
                        artifact_id=str(item.get("artifact_id", "")),
                    )
                    == item
                ]
                if (
                    len(current_candidates) != 1
                    or current_candidates[0].get("ref") != raw.get(field_name)
                ):
                    raise AppendOnlyConflict(
                        "Domo portfolio inventory does not bind the exact current "
                        f"{artifact_type} artifact"
                    )
            observations = _registered_domo_observations(
                records,
                tenant_ref=tenant_ref,
                run_id=run_id,
                scope_id=scope_id,
            )
            errors = validate_portfolio_inventory(raw, observations=observations)
            if errors:
                raise AppendOnlyConflict(
                    "Domo portfolio inventory is inconsistent with registered "
                    "observations: "
                    + "; ".join(errors)
                )
            if any(
                record.get("record_type") == "event"
                and record.get("payload", {}).get("event_type")
                == "domo_portfolio_inventory_registered"
                and (
                    record.get("payload", {}).get("portfolio", {}).get(
                        "portfolio_id"
                    )
                    == raw.get("portfolio_id")
                    or record.get("payload", {}).get("portfolio", {}).get(
                        "scope_id"
                    )
                    == scope_id
                )
                for record in records
            ):
                raise AppendOnlyConflict(
                    "Domo portfolio inventory is already registered for this scope"
                )

        self._append(
            tenant_ref=tenant_ref,
            run_id=run_id,
            record_type="event",
            record_id=(
                f"domo-portfolio-inventory:{raw['portfolio_id']}:"
                f"{envelope.artifact_id}@{envelope.revision}"
            ),
            payload=payload,
            idempotency_key=idempotency_key,
            occurred_at=parse_time(str(raw["as_of"])),
            guard=guard,
        )
        resolved = _registered_domo_portfolio(
            self.records(tenant_ref, run_id),
            tenant_ref=tenant_ref,
            run_id=run_id,
            scope_id=scope_id,
        )
        if resolved != raw:
            raise AppendOnlyConflict(
                "Domo portfolio inventory registration readback failed"
            )
        return raw

    def append_external_redesign_handoff(
        self,
        handoff: Mapping[str, Any] | Any,
        artifact: ArtifactEnvelope | Mapping[str, Any],
        *,
        idempotency_key: str,
    ) -> Any:
        """Bind one accepted human-owned external assignment to its portfolio."""

        from omni_migrator.control_plane.external_handoffs import (
            ExternalRedesignHandoff,
            external_redesign_handoff_content_sha256,
            finalize_external_redesign_handoff,
            validate_external_redesign_handoff,
        )

        raw = (
            handoff.model_dump(mode="json")
            if isinstance(handoff, ExternalRedesignHandoff)
            else dict(handoff)
        )
        errors = validate_external_redesign_handoff(raw)
        value = finalize_external_redesign_handoff(raw)
        if errors or raw != value.model_dump(mode="json"):
            raise AppendOnlyConflict(
                "external redesign handoff payload is not canonical: "
                + "; ".join(errors)
            )
        envelope = (
            artifact
            if isinstance(artifact, ArtifactEnvelope)
            else ArtifactEnvelope.from_mapping(artifact)
        )
        envelope.validate(
            expected_tenant_ref=value.tenant_ref,
            expected_run_id=value.run_id,
        )
        if (
            envelope.artifact_type != "external_redesign_assignment"
            or envelope.ref != value.handoff_ref
            or envelope.content_sha256
            != external_redesign_handoff_content_sha256(value)
            or envelope.producer_ref
            != "agent-ref://domo-to-omni-architect"
            or envelope.producer_work_package_id
            != value.assignment_work_package_id
            or envelope.migration_unit_id != value.migration_unit_id
            or envelope.validation_cycle_id != value.validation_cycle_id
        ):
            raise AppendOnlyConflict(
                "external redesign handoff does not match its artifact envelope"
            )
        payload = {
            "event_type": "external_redesign_handoff_registered",
            "artifact": envelope.to_mapping(),
            "handoff": value.model_dump(mode="json"),
        }

        def guard(records: list[dict[str, Any]]) -> None:
            if not _artifact_envelope_is_exactly_current(records, envelope):
                raise AppendOnlyConflict(
                    "external redesign handoff requires its exact current artifact"
                )
            before = _registered_external_redesign_handoffs(
                records,
                tenant_ref=value.tenant_ref,
                run_id=value.run_id,
                scope_id=value.scope_id,
            )
            if any(
                item.handoff_ref == value.handoff_ref
                or item.handoff_id == value.handoff_id
                for item in before
            ):
                raise AppendOnlyConflict(
                    "external redesign handoff is already registered"
                )
            portfolio = _registered_domo_portfolio(
                records,
                tenant_ref=value.tenant_ref,
                run_id=value.run_id,
                scope_id=value.scope_id,
            )
            if portfolio is None:
                raise AppendOnlyConflict(
                    "external redesign handoff requires the current registered portfolio"
                )
            portfolio_objects = {
                item["identity"]["object_id"]: item
                for item in portfolio["objects"]
            }
            portfolio_events = [
                record.get("payload", {})
                for record in records
                if record.get("record_type") == "event"
                and record.get("payload", {}).get("event_type")
                == "domo_portfolio_inventory_registered"
                and record.get("payload", {}).get("portfolio", {}).get("scope_id")
                == value.scope_id
            ]
            if len(portfolio_events) != 1:
                raise AppendOnlyConflict(
                    "external redesign handoff requires one exact registered portfolio artifact"
                )
            portfolio_artifact = ArtifactEnvelope.from_mapping(
                portfolio_events[0]["artifact"]
            )
            portfolio_input = {
                "artifact_id": portfolio_artifact.artifact_id,
                "revision": portfolio_artifact.revision,
                "content_sha256": portfolio_artifact.content_sha256,
            }
            if portfolio_input not in [dict(item) for item in envelope.input_artifacts]:
                raise AppendOnlyConflict(
                    "external redesign handoff lacks exact current portfolio artifact lineage"
                )
            expected_source_ids = {
                object_id
                for object_id, item in portfolio_objects.items()
                if value.handoff_ref in item.get("redesign_handoff_refs", [])
            }
            if {item.object_id for item in value.source_objects} != expected_source_ids:
                raise AppendOnlyConflict(
                    "external redesign handoff does not cover its exact portfolio object set"
                )
            for source in value.source_objects:
                item = portfolio_objects.get(source.object_id)
                if (
                    item is None
                    or item["identity"]["object_type"] != source.object_type
                    or item["identity"]["native_id"] != source.native_id
                    or item["object_hash"] != source.object_hash
                    or item["external_handoff_required"] is not True
                    or value.handoff_ref not in item["redesign_handoff_refs"]
                ):
                    raise AppendOnlyConflict(
                        "external redesign handoff source does not match the portfolio"
                    )
            for output in value.analytic_outputs:
                item = portfolio_objects.get(output.object_id)
                if (
                    item is None
                    or item["identity"]["object_type"] != "dataset"
                    or item["identity"]["native_id"] != output.native_id
                    or item["object_hash"] != output.object_hash
                ):
                    raise AppendOnlyConflict(
                        "external redesign handoff analytic output does not match the portfolio"
                    )
            declared_output_ids: set[str] = set()
            declared_side_effects: set[str] = set()
            for source in value.source_objects:
                profile = portfolio_objects[source.object_id].get(
                    "commonality", {}
                ).get("profile", {})
                if profile.get("profile_type") == "workflow":
                    declared_output_ids.update(profile.get("output_object_ids", []))
                    declared_side_effects.update(
                        item
                        for item in profile.get("side_effects", [])
                        if item != "none"
                    )
            if declared_output_ids != {
                item.object_id for item in value.analytic_outputs
            }:
                raise AppendOnlyConflict(
                    "external redesign handoff does not preserve declared workflow outputs"
                )
            if declared_side_effects and declared_side_effects != set(
                value.side_effect_kinds
            ):
                raise AppendOnlyConflict(
                    "external redesign handoff does not preserve declared workflow side effects"
                )

        self._append(
            tenant_ref=value.tenant_ref,
            run_id=value.run_id,
            record_type="event",
            record_id=(
                f"external-redesign-handoff:{value.handoff_id}:"
                f"{envelope.artifact_id}@{envelope.revision}"
            ),
            payload=payload,
            idempotency_key=idempotency_key,
            occurred_at=parse_time(value.accepted_decision.accepted_at),
            guard=guard,
        )
        resolved = _registered_external_redesign_handoffs(
            self.records(value.tenant_ref, value.run_id),
            tenant_ref=value.tenant_ref,
            run_id=value.run_id,
            scope_id=value.scope_id,
        )
        if not any(item == value for item in resolved):
            raise AppendOnlyConflict(
                "external redesign handoff registration readback failed"
            )
        return value

    def append_migration_scope_payload(
        self,
        scope: Mapping[str, Any],
        artifact: ArtifactEnvelope | Mapping[str, Any],
        *,
        migration_unit_id: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        """Register an exact current migration-scope payload for one unit."""

        from omni_migrator.control_plane.contract_integrity import validate_migration_scope

        raw = dict(scope)
        errors = validate_migration_scope(raw)
        envelope = (
            artifact
            if isinstance(artifact, ArtifactEnvelope)
            else ArtifactEnvelope.from_mapping(artifact)
        )
        tenant_ref = envelope.tenant_ref
        run_id = str(raw.get("run_id", ""))
        scope_id = str(raw.get("scope_id", ""))
        envelope.validate(expected_tenant_ref=tenant_ref, expected_run_id=run_id)
        unit_ids = {
            str(unit.get("migration_unit_id"))
            for wave in raw.get("waves", [])
            if isinstance(wave, Mapping)
            for unit in wave.get("units", [])
            if isinstance(unit, Mapping)
        }
        if (
            set(raw) != _MIGRATION_SCOPE_FIELDS
            or raw.get("contract_version") != "domo-to-omni.migration-scope.v1"
            or raw.get("status")
            not in {
                "proposed",
                "accepted",
                "in_progress",
                "completed",
                "blocked",
                "superseded",
            }
            or errors
            or migration_unit_id not in unit_ids
            or envelope.artifact_type != "migration_scope"
            or envelope.content_sha256 != sha256_json(raw)
            or envelope.producer_ref
            not in {
                "agent-ref://inventory-intake",
                "agent-ref://domo-to-omni-architect",
            }
            or envelope.migration_unit_id not in {None, migration_unit_id}
        ):
            raise AppendOnlyConflict(
                "migration scope payload is not canonically artifact-bound: "
                + "; ".join(errors)
            )
        payload = {
            "event_type": "migration_scope_registered",
            "artifact": envelope.to_mapping(),
            "scope": raw,
        }

        def guard(records: list[dict[str, Any]]) -> None:
            if not _artifact_envelope_is_exactly_current(records, envelope):
                raise AppendOnlyConflict(
                    "migration scope requires its exact current artifact"
                )
            if _registered_migration_scopes(
                records,
                tenant_ref=tenant_ref,
                run_id=run_id,
                scope_id=scope_id,
                migration_unit_id=migration_unit_id,
                validation_cycle_id=envelope.validation_cycle_id,
            ):
                raise AppendOnlyConflict(
                    "migration scope is already registered for this unit and cycle"
                )

        self._append(
            tenant_ref=tenant_ref,
            run_id=run_id,
            record_type="event",
            record_id=(
                f"migration-scope:{scope_id}:{migration_unit_id}:"
                f"{envelope.artifact_id}@{envelope.revision}"
            ),
            payload=payload,
            idempotency_key=idempotency_key,
            occurred_at=parse_time(envelope.created_at),
            guard=guard,
        )
        resolved = _registered_migration_scopes(
            self.records(tenant_ref, run_id),
            tenant_ref=tenant_ref,
            run_id=run_id,
            scope_id=scope_id,
            migration_unit_id=migration_unit_id,
            validation_cycle_id=envelope.validation_cycle_id,
        )
        if not any(item == raw for _artifact, item in resolved):
            raise AppendOnlyConflict("migration scope registration readback failed")
        return raw

    def append_repository_inventory_payload(
        self,
        inventory: Mapping[str, Any] | Any,
        artifact: ArtifactEnvelope | Mapping[str, Any],
        *,
        migration_unit_id: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        """Register one immutable pinned-repository inventory payload."""

        from omni_migrator.repositories.dbt.models import RepositoryInventory

        value = (
            inventory
            if isinstance(inventory, RepositoryInventory)
            else RepositoryInventory.model_validate(inventory)
        )
        raw = value.model_dump(mode="json")
        envelope = (
            artifact
            if isinstance(artifact, ArtifactEnvelope)
            else ArtifactEnvelope.from_mapping(artifact)
        )
        envelope.validate(
            expected_tenant_ref=envelope.tenant_ref,
            expected_run_id=value.run_id,
        )
        if (
            envelope.artifact_type != "repository_inventory"
            or envelope.content_sha256 != sha256_json(raw)
            or envelope.producer_ref != "agent-ref://dbt-analytics-engineer"
            or envelope.migration_unit_id not in {None, migration_unit_id}
        ):
            raise AppendOnlyConflict(
                "repository inventory payload is not canonically artifact-bound"
            )
        payload = {
            "event_type": "repository_inventory_registered",
            "artifact": envelope.to_mapping(),
            "inventory": raw,
        }

        def guard(records: list[dict[str, Any]]) -> None:
            if not _artifact_envelope_is_exactly_current(records, envelope):
                raise AppendOnlyConflict(
                    "repository inventory requires its exact current artifact"
                )
            if _registered_repository_inventories(
                records,
                tenant_ref=envelope.tenant_ref,
                run_id=value.run_id,
                migration_unit_id=migration_unit_id,
                validation_cycle_id=envelope.validation_cycle_id,
            ):
                raise AppendOnlyConflict(
                    "repository inventory is already registered for this unit and cycle"
                )

        self._append(
            tenant_ref=envelope.tenant_ref,
            run_id=value.run_id,
            record_type="event",
            record_id=(
                f"repository-inventory:{migration_unit_id}:"
                f"{envelope.artifact_id}@{envelope.revision}"
            ),
            payload=payload,
            idempotency_key=idempotency_key,
            occurred_at=parse_time(envelope.created_at),
            guard=guard,
        )
        resolved = _registered_repository_inventories(
            self.records(envelope.tenant_ref, value.run_id),
            tenant_ref=envelope.tenant_ref,
            run_id=value.run_id,
            migration_unit_id=migration_unit_id,
            validation_cycle_id=envelope.validation_cycle_id,
        )
        if not any(item == raw for _artifact, item in resolved):
            raise AppendOnlyConflict(
                "repository inventory registration readback failed"
            )
        return raw

    def append_repository_definition_evidence_payload(
        self,
        evidence: Mapping[str, Any] | Any,
        expected_profile_hash: str,
        artifact: ArtifactEnvelope | Mapping[str, Any],
        *,
        scope_id: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        """Register exact dbt source-definition evidence and its builder output."""

        from omni_migrator.repositories.dbt.models import RepositoryInventory
        from omni_migrator.semantic.models import RepositoryDefinitionEvidence
        from omni_migrator.semantic.profiles import build_dbt_semantic_profile

        value = (
            evidence
            if isinstance(evidence, RepositoryDefinitionEvidence)
            else RepositoryDefinitionEvidence.model_validate(evidence)
        )
        raw = value.model_dump(mode="json")
        envelope = (
            artifact
            if isinstance(artifact, ArtifactEnvelope)
            else ArtifactEnvelope.from_mapping(artifact)
        )
        envelope.validate(
            expected_tenant_ref=envelope.tenant_ref,
            expected_run_id=envelope.run_id,
        )
        if (
            envelope.artifact_type != "repository_definition_evidence"
            or envelope.content_sha256
            != _repository_definition_attestation_sha256(
                scope_id=scope_id,
                evidence=raw,
                expected_profile_hash=expected_profile_hash,
            )
            or envelope.producer_ref != "agent-ref://dbt-analytics-engineer"
            or envelope.migration_unit_id is None
        ):
            raise AppendOnlyConflict(
                "repository definition evidence is not canonically artifact-bound"
            )
        payload = {
            "event_type": "repository_definition_evidence_registered",
            "scope_id": scope_id,
            "artifact": envelope.to_mapping(),
            "evidence": raw,
            "expected_profile_hash": expected_profile_hash,
        }

        def guard(records: list[dict[str, Any]]) -> None:
            if not _artifact_envelope_is_exactly_current(records, envelope):
                raise AppendOnlyConflict(
                    "repository definition evidence requires its exact current artifact"
                )
            inventories = _registered_repository_inventories(
                records,
                tenant_ref=envelope.tenant_ref,
                run_id=envelope.run_id,
                migration_unit_id=str(envelope.migration_unit_id),
                validation_cycle_id=envelope.validation_cycle_id,
            )
            if len(inventories) != 1:
                raise AppendOnlyConflict(
                    "repository definition evidence requires one exact current repository inventory"
                )
            inventory_envelope, inventory_raw = inventories[0]
            inventory = RepositoryInventory.model_validate(inventory_raw)
            subject = _repository_subject_for_evidence(inventory, value.subject_id)
            try:
                expected_profile = build_dbt_semantic_profile(
                    inventory,
                    subject,
                    value,
                    run_id=envelope.run_id,
                    scope_id=scope_id,
                )
            except (TypeError, ValueError) as exc:
                raise AppendOnlyConflict(
                    "repository definition evidence is foreign to its current inventory"
                ) from exc
            if expected_profile.profile_hash != expected_profile_hash:
                raise AppendOnlyConflict(
                    "repository definition evidence expected profile hash is not builder-produced"
                )
            _require_semantic_dependency_lineage(
                envelope,
                (inventory_envelope,),
                dependency_kind="repository definition evidence",
            )
            existing = _registered_repository_definition_evidence(
                records,
                tenant_ref=envelope.tenant_ref,
                run_id=envelope.run_id,
                scope_id=scope_id,
                migration_unit_id=str(envelope.migration_unit_id),
                validation_cycle_id=envelope.validation_cycle_id,
            )
            if any(item.subject_id == value.subject_id for _a, item, _h, _p in existing):
                raise AppendOnlyConflict(
                    "repository definition evidence subject is already registered"
                )

        self._append(
            tenant_ref=envelope.tenant_ref,
            run_id=envelope.run_id,
            record_type="event",
            record_id=(
                f"repository-definition-evidence:{scope_id}:{value.subject_id}:"
                f"{envelope.artifact_id}@{envelope.revision}"
            ),
            payload=payload,
            idempotency_key=idempotency_key,
            occurred_at=parse_time(envelope.created_at),
            guard=guard,
        )
        resolved = _registered_repository_definition_evidence(
            self.records(envelope.tenant_ref, envelope.run_id),
            tenant_ref=envelope.tenant_ref,
            run_id=envelope.run_id,
            scope_id=scope_id,
            migration_unit_id=str(envelope.migration_unit_id),
            validation_cycle_id=envelope.validation_cycle_id,
        )
        if not any(
            item == value and profile_hash == expected_profile_hash
            for _artifact, item, profile_hash, _profile in resolved
        ):
            raise AppendOnlyConflict(
                "repository definition evidence registration readback failed"
            )
        return payload

    def append_semantic_profile_payload(
        self,
        profile: Mapping[str, Any] | Any,
        artifact: ArtifactEnvelope | Mapping[str, Any],
        *,
        idempotency_key: str,
    ) -> dict[str, Any]:
        """Register one current canonical source or target semantic profile."""

        from omni_migrator.semantic.models import SemanticProfile
        from omni_migrator.semantic.profiles import validate_semantic_profile

        value = (
            profile
            if isinstance(profile, SemanticProfile)
            else SemanticProfile.model_validate(profile)
        )
        raw = value.model_dump(mode="json")
        errors = validate_semantic_profile(value)
        envelope = (
            artifact
            if isinstance(artifact, ArtifactEnvelope)
            else ArtifactEnvelope.from_mapping(artifact)
        )
        envelope.validate(
            expected_tenant_ref=envelope.tenant_ref,
            expected_run_id=value.run_id,
        )
        allowed = (
            {"agent-ref://domo-to-omni-architect"}
            if envelope.artifact_type == "target_semantic_profile"
            else {
                "agent-ref://domo-bi-developer",
                "agent-ref://domo-analytics-engineer",
                "agent-ref://dbt-analytics-engineer",
                "agent-ref://omni-modeler",
            }
        )
        if (
            errors
            or envelope.artifact_type
            not in {"semantic_profile", "target_semantic_profile"}
            or envelope.content_sha256 != sha256_json(raw)
            or envelope.producer_ref not in allowed
            or envelope.migration_unit_id is None
        ):
            raise AppendOnlyConflict(
                "semantic profile payload is not canonically artifact-bound: "
                + "; ".join(errors)
            )
        payload = {
            "event_type": "semantic_profile_registered",
            "artifact": envelope.to_mapping(),
            "profile": raw,
        }

        def guard(records: list[dict[str, Any]]) -> None:
            if not _artifact_envelope_is_exactly_current(records, envelope):
                raise AppendOnlyConflict(
                    "semantic profile requires its exact current artifact"
                )
            _assert_current_domo_profile_builder_attestation(
                records,
                tenant_ref=envelope.tenant_ref,
                run_id=value.run_id,
                profile=value,
                envelope=envelope,
            )
            _assert_current_dbt_profile_builder_attestation(
                records,
                tenant_ref=envelope.tenant_ref,
                run_id=value.run_id,
                profile=value,
                envelope=envelope,
            )
            current = _registered_semantic_profiles(
                records,
                tenant_ref=envelope.tenant_ref,
                run_id=value.run_id,
                scope_id=value.scope_id,
                migration_unit_id=str(envelope.migration_unit_id),
                validation_cycle_id=envelope.validation_cycle_id,
            )
            if any(
                existing.profile_id == value.profile_id
                or existing.identity == value.identity
                for _artifact, existing in current
            ):
                raise AppendOnlyConflict(
                    "semantic profile identity is already registered for this unit and cycle"
                )

        self._append(
            tenant_ref=envelope.tenant_ref,
            run_id=value.run_id,
            record_type="event",
            record_id=(
                f"semantic-profile:{value.profile_id}:"
                f"{envelope.artifact_id}@{envelope.revision}"
            ),
            payload=payload,
            idempotency_key=idempotency_key,
            occurred_at=parse_time(envelope.created_at),
            guard=guard,
        )
        resolved = _registered_semantic_profiles(
            self.records(envelope.tenant_ref, value.run_id),
            tenant_ref=envelope.tenant_ref,
            run_id=value.run_id,
            scope_id=value.scope_id,
            migration_unit_id=str(envelope.migration_unit_id),
            validation_cycle_id=envelope.validation_cycle_id,
        )
        if not any(existing == value for _artifact, existing in resolved):
            raise AppendOnlyConflict("semantic profile registration readback failed")
        return raw

    def _append_semantic_analysis_payload(
        self,
        value: Mapping[str, Any] | Any,
        artifact: ArtifactEnvelope | Mapping[str, Any],
        *,
        event_type: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        """Register one exact current equivalence/consolidation payload."""

        (
            payload_field,
            identity_field,
            artifact_type,
            model_type,
            finalizer,
            validator,
        ) = _semantic_analysis_registration_contract(event_type)
        candidate = (
            value if isinstance(value, model_type) else model_type.model_validate(value)
        )
        raw = candidate.model_dump(mode="json")
        finalized = finalizer(raw)
        errors = validator(candidate)
        envelope = (
            artifact
            if isinstance(artifact, ArtifactEnvelope)
            else ArtifactEnvelope.from_mapping(artifact)
        )
        try:
            envelope.validate(
                expected_tenant_ref=envelope.tenant_ref,
                expected_run_id=candidate.run_id,
            )
        except (TypeError, ValueError) as exc:
            raise AppendOnlyConflict(
                f"{artifact_type} artifact envelope is invalid"
            ) from exc
        if (
            finalized.model_dump(mode="json") != raw
            or errors
            or envelope.artifact_type != artifact_type
            or envelope.content_sha256 != sha256_json(raw)
            or envelope.producer_ref
            not in {
                "agent-ref://semantic-consolidation",
                "agent-ref://semantic_consolidation",
            }
            or envelope.migration_unit_id is None
            or (
                event_type == "consolidation_decision_registered"
                and candidate.validation_cycle_id != envelope.validation_cycle_id
            )
        ):
            raise AppendOnlyConflict(
                f"{artifact_type} payload is not canonically artifact-bound: "
                + "; ".join(errors)
            )
        payload = {
            "event_type": event_type,
            "artifact": envelope.to_mapping(),
            payload_field: raw,
        }

        def guard(records: list[dict[str, Any]]) -> None:
            if not _artifact_envelope_is_exactly_current(records, envelope):
                raise AppendOnlyConflict(
                    f"{artifact_type} requires its exact current artifact"
                )
            _assert_semantic_analysis_dependencies_current(
                records,
                event_type=event_type,
                tenant_ref=envelope.tenant_ref,
                run_id=candidate.run_id,
                scope_id=candidate.scope_id,
                migration_unit_id=str(envelope.migration_unit_id),
                validation_cycle_id=envelope.validation_cycle_id,
                value=candidate,
                envelope=envelope,
            )
            current = _registered_semantic_analysis_payloads(
                records,
                event_type=event_type,
                tenant_ref=envelope.tenant_ref,
                run_id=candidate.run_id,
                scope_id=candidate.scope_id,
                migration_unit_id=str(envelope.migration_unit_id),
                validation_cycle_id=envelope.validation_cycle_id,
            )
            identity = getattr(candidate, identity_field)
            if any(
                getattr(existing, identity_field) == identity
                for _artifact, existing in current
            ):
                raise AppendOnlyConflict(
                    f"{artifact_type} identity is already registered for this unit and cycle"
                )

        identity = getattr(candidate, identity_field)
        self._append(
            tenant_ref=envelope.tenant_ref,
            run_id=candidate.run_id,
            record_type="event",
            record_id=(
                f"{event_type.removesuffix('_registered').replace('_', '-')}:"
                f"{identity}:{envelope.artifact_id}@{envelope.revision}"
            ),
            payload=payload,
            idempotency_key=idempotency_key,
            occurred_at=parse_time(envelope.created_at),
            guard=guard,
        )
        resolved = _registered_semantic_analysis_payloads(
            self.records(envelope.tenant_ref, candidate.run_id),
            event_type=event_type,
            tenant_ref=envelope.tenant_ref,
            run_id=candidate.run_id,
            scope_id=candidate.scope_id,
            migration_unit_id=str(envelope.migration_unit_id),
            validation_cycle_id=envelope.validation_cycle_id,
        )
        if not any(existing == candidate for _artifact, existing in resolved):
            raise AppendOnlyConflict(f"{artifact_type} registration readback failed")
        return raw

    def append_equivalence_assessment_payload(
        self,
        assessment: Mapping[str, Any] | Any,
        artifact: ArtifactEnvelope | Mapping[str, Any],
        *,
        idempotency_key: str,
    ) -> dict[str, Any]:
        return self._append_semantic_analysis_payload(
            assessment,
            artifact,
            event_type="equivalence_assessment_registered",
            idempotency_key=idempotency_key,
        )

    def append_consolidation_candidate_payload(
        self,
        candidate: Mapping[str, Any] | Any,
        artifact: ArtifactEnvelope | Mapping[str, Any],
        *,
        idempotency_key: str,
    ) -> dict[str, Any]:
        return self._append_semantic_analysis_payload(
            candidate,
            artifact,
            event_type="consolidation_candidate_registered",
            idempotency_key=idempotency_key,
        )

    def append_consolidation_decision_payload(
        self,
        decision: Mapping[str, Any] | Any,
        artifact: ArtifactEnvelope | Mapping[str, Any],
        *,
        idempotency_key: str,
    ) -> dict[str, Any]:
        return self._append_semantic_analysis_payload(
            decision,
            artifact,
            event_type="consolidation_decision_registered",
            idempotency_key=idempotency_key,
        )

    def append_semantic_profile_coverage(
        self,
        coverage: Mapping[str, Any] | Any,
        artifact: ArtifactEnvelope | Mapping[str, Any],
        *,
        idempotency_key: str,
    ) -> Any:
        """Register coverage only after store-derived denominator validation."""

        from omni_migrator.semantic.coverage import (
            SemanticProfileCoverage,
            finalize_semantic_profile_coverage,
            semantic_profile_coverage_content_sha256,
            validate_semantic_profile_coverage,
        )

        raw = (
            coverage.model_dump(mode="json")
            if isinstance(coverage, SemanticProfileCoverage)
            else dict(coverage)
        )
        value = finalize_semantic_profile_coverage(raw)
        if value.model_dump(mode="json") != raw:
            raise AppendOnlyConflict(
                "semantic-profile coverage payload is not pre-canonicalized"
            )
        envelope = (
            artifact
            if isinstance(artifact, ArtifactEnvelope)
            else ArtifactEnvelope.from_mapping(artifact)
        )
        envelope.validate(
            expected_tenant_ref=value.tenant_ref,
            expected_run_id=value.run_id,
        )
        if (
            envelope.artifact_type != "semantic_profile_coverage"
            or envelope.artifact_id != value.coverage_id
            or envelope.revision != value.coverage_revision
            or envelope.content_sha256
            != semantic_profile_coverage_content_sha256(value)
            or envelope.producer_ref != value.producer_ref
            or envelope.migration_unit_id != value.migration_unit_id
            or envelope.validation_cycle_id != value.validation_cycle_id
        ):
            raise AppendOnlyConflict(
                "semantic-profile coverage payload is not exactly artifact-bound"
            )
        payload = {
            "event_type": "semantic_profile_coverage_registered",
            "artifact": envelope.to_mapping(),
            "coverage": raw,
        }

        def guard(records: list[dict[str, Any]]) -> None:
            if not _artifact_envelope_is_exactly_current(records, envelope):
                raise AppendOnlyConflict(
                    "semantic-profile coverage requires its exact current artifact"
                )
            context, upstream = _semantic_profile_coverage_context(records, value)
            errors = validate_semantic_profile_coverage(
                value,
                validation_context=context,
            )
            if errors:
                raise AppendOnlyConflict(
                    "semantic-profile coverage validation failed: "
                    + "; ".join(errors)
                )
            expected_lineage = {
                (item.artifact_id, item.revision, item.content_sha256)
                for item in upstream
            }
            actual_lineage = {
                (
                    str(item.get("artifact_id", "")),
                    int(item.get("revision", 0)),
                    str(item.get("content_sha256", "")),
                )
                for item in envelope.input_artifacts
            }
            if actual_lineage != expected_lineage:
                raise AppendOnlyConflict(
                    "semantic-profile coverage artifact lineage is not the exact upstream set"
                )
            prior = [
                record.get("payload", {}).get("coverage")
                for record in records
                if record.get("record_type") == "event"
                and record.get("payload", {}).get("event_type")
                == "semantic_profile_coverage_registered"
                and record.get("payload", {}).get("artifact", {}).get("artifact_id")
                == envelope.artifact_id
                and int(
                    record.get("payload", {}).get("artifact", {}).get("revision", 0)
                )
                == envelope.revision - 1
            ]
            expected_supersedes = (
                str(prior[0].get("coverage_hash")) if len(prior) == 1 else None
            )
            if value.supersedes_coverage_hash != expected_supersedes:
                raise AppendOnlyConflict(
                    "semantic-profile coverage does not bind its exact predecessor"
                )

        self._append(
            tenant_ref=value.tenant_ref,
            run_id=value.run_id,
            record_type="event",
            record_id=(
                f"semantic-profile-coverage:{value.coverage_id}:"
                f"{envelope.revision}"
            ),
            payload=payload,
            idempotency_key=idempotency_key,
            occurred_at=parse_time(value.assembled_at),
            guard=guard,
        )
        resolved = _registered_semantic_profile_coverages(
            self.records(value.tenant_ref, value.run_id),
            tenant_ref=value.tenant_ref,
            run_id=value.run_id,
            scope_id=value.scope_id,
            migration_unit_id=value.migration_unit_id,
            validation_cycle_id=value.validation_cycle_id,
        )
        if (
            len(resolved) != 1
            or resolved[0][1].model_dump(mode="json")
            != value.model_dump(mode="json")
        ):
            raise AppendOnlyConflict(
                "semantic-profile coverage registration readback failed"
            )
        return value

    def registered_domo_inventory_observations(
        self, tenant_ref: str, run_id: str, scope_id: str
    ) -> tuple[dict[str, Any], ...]:
        return _registered_domo_observations(
            self.records(tenant_ref, run_id),
            tenant_ref=tenant_ref,
            run_id=run_id,
            scope_id=scope_id,
        )

    def registered_domo_portfolio_inventory(
        self, tenant_ref: str, run_id: str, scope_id: str
    ) -> dict[str, Any] | None:
        return _registered_domo_portfolio(
            self.records(tenant_ref, run_id),
            tenant_ref=tenant_ref,
            run_id=run_id,
            scope_id=scope_id,
        )

    def registered_migration_scope_payloads(
        self,
        tenant_ref: str,
        run_id: str,
        scope_id: str,
        migration_unit_id: str,
        validation_cycle_id: str,
    ) -> tuple[dict[str, Any], ...]:
        return tuple(
            payload
            for _artifact, payload in _registered_migration_scopes(
                self.records(tenant_ref, run_id),
                tenant_ref=tenant_ref,
                run_id=run_id,
                scope_id=scope_id,
                migration_unit_id=migration_unit_id,
                validation_cycle_id=validation_cycle_id,
            )
        )

    def registered_repository_inventory_payloads(
        self,
        tenant_ref: str,
        run_id: str,
        migration_unit_id: str,
        validation_cycle_id: str,
    ) -> tuple[dict[str, Any], ...]:
        return tuple(
            payload
            for _artifact, payload in _registered_repository_inventories(
                self.records(tenant_ref, run_id),
                tenant_ref=tenant_ref,
                run_id=run_id,
                migration_unit_id=migration_unit_id,
                validation_cycle_id=validation_cycle_id,
            )
        )

    def registered_repository_definition_evidence_payloads(
        self,
        tenant_ref: str,
        run_id: str,
        *,
        scope_id: str,
        migration_unit_id: str,
        validation_cycle_id: str,
    ) -> tuple[dict[str, Any], ...]:
        return tuple(
            {
                "scope_id": scope_id,
                "artifact": artifact.to_mapping(),
                "evidence": evidence.model_dump(mode="json"),
                "expected_profile_hash": expected_profile_hash,
            }
            for artifact, evidence, expected_profile_hash, _profile in (
                _registered_repository_definition_evidence(
                    self.records(tenant_ref, run_id),
                    tenant_ref=tenant_ref,
                    run_id=run_id,
                    scope_id=scope_id,
                    migration_unit_id=migration_unit_id,
                    validation_cycle_id=validation_cycle_id,
                )
            )
        )

    def registered_semantic_profile_payloads(
        self,
        tenant_ref: str,
        run_id: str,
        scope_id: str,
        migration_unit_id: str,
        validation_cycle_id: str,
    ) -> tuple[dict[str, Any], ...]:
        return tuple(
            profile.model_dump(mode="json")
            for _artifact, profile in _registered_semantic_profiles(
                self.records(tenant_ref, run_id),
                tenant_ref=tenant_ref,
                run_id=run_id,
                scope_id=scope_id,
                migration_unit_id=migration_unit_id,
                validation_cycle_id=validation_cycle_id,
            )
        )

    def _registered_semantic_analysis_payloads_for_partition(
        self,
        tenant_ref: str,
        run_id: str,
        scope_id: str,
        migration_unit_id: str,
        validation_cycle_id: str,
        *,
        event_type: str,
    ) -> tuple[dict[str, Any], ...]:
        return tuple(
            value.model_dump(mode="json")
            for _artifact, value in _registered_semantic_analysis_payloads(
                self.records(tenant_ref, run_id),
                event_type=event_type,
                tenant_ref=tenant_ref,
                run_id=run_id,
                scope_id=scope_id,
                migration_unit_id=migration_unit_id,
                validation_cycle_id=validation_cycle_id,
            )
        )

    def registered_equivalence_assessment_payloads(
        self,
        tenant_ref: str,
        run_id: str,
        scope_id: str,
        migration_unit_id: str,
        validation_cycle_id: str,
    ) -> tuple[dict[str, Any], ...]:
        return self._registered_semantic_analysis_payloads_for_partition(
            tenant_ref,
            run_id,
            scope_id,
            migration_unit_id,
            validation_cycle_id,
            event_type="equivalence_assessment_registered",
        )

    def registered_consolidation_candidate_payloads(
        self,
        tenant_ref: str,
        run_id: str,
        scope_id: str,
        migration_unit_id: str,
        validation_cycle_id: str,
    ) -> tuple[dict[str, Any], ...]:
        return self._registered_semantic_analysis_payloads_for_partition(
            tenant_ref,
            run_id,
            scope_id,
            migration_unit_id,
            validation_cycle_id,
            event_type="consolidation_candidate_registered",
        )

    def registered_consolidation_decision_payloads(
        self,
        tenant_ref: str,
        run_id: str,
        scope_id: str,
        migration_unit_id: str,
        validation_cycle_id: str,
    ) -> tuple[dict[str, Any], ...]:
        return self._registered_semantic_analysis_payloads_for_partition(
            tenant_ref,
            run_id,
            scope_id,
            migration_unit_id,
            validation_cycle_id,
            event_type="consolidation_decision_registered",
        )

    def registered_semantic_profile_coverages(
        self,
        tenant_ref: str,
        run_id: str,
        scope_id: str,
        migration_unit_id: str,
        validation_cycle_id: str,
    ) -> tuple[Any, ...]:
        return tuple(
            coverage
            for _artifact, coverage in _registered_semantic_profile_coverages(
                self.records(tenant_ref, run_id),
                tenant_ref=tenant_ref,
                run_id=run_id,
                scope_id=scope_id,
                migration_unit_id=migration_unit_id,
                validation_cycle_id=validation_cycle_id,
            )
        )

    def registered_external_redesign_handoffs(
        self, tenant_ref: str, run_id: str, scope_id: str
    ) -> tuple[Any, ...]:
        return _registered_external_redesign_handoffs(
            self.records(tenant_ref, run_id),
            tenant_ref=tenant_ref,
            run_id=run_id,
            scope_id=scope_id,
        )

    def append_work_package(
        self,
        work_package: Mapping[str, Any] | Any,
        *,
        idempotency_key: str,
    ) -> dict[str, Any]:
        """Append one canonical planner work package to the trusted partition."""

        from omni_migrator.orchestration.planner import PlannedWorkPackage

        raw = (
            work_package.model_dump(mode="json")
            if isinstance(work_package, PlannedWorkPackage)
            else dict(work_package)
        )
        value = PlannedWorkPackage.model_validate(raw).model_dump(mode="json")
        if value != raw:
            raise AppendOnlyConflict("work package payload is not pre-canonicalized")
        tenant_ref = str(value["tenant_ref"])
        run_id = str(value["run_id"])
        work_package_id = str(value["work_package_id"])

        def guard(records: list[dict[str, Any]]) -> None:
            if any(
                record.get("record_type") == "work_package"
                and record.get("record_id") == work_package_id
                for record in records
            ):
                raise AppendOnlyConflict(
                    f"work package is already registered: {work_package_id}"
                )

        self._append(
            tenant_ref=tenant_ref,
            run_id=run_id,
            record_type="work_package",
            record_id=work_package_id,
            payload=value,
            idempotency_key=idempotency_key,
            occurred_at=parse_time(str(value["timestamps"]["created_at"])),
            guard=guard,
        )
        matching = [
            record["payload"]
            for record in self.records(tenant_ref, run_id)
            if record.get("record_type") == "work_package"
            and record.get("record_id") == work_package_id
        ]
        if matching != [value]:
            raise AppendOnlyConflict("work package registration readback failed")
        return value

    def registered_work_packages(
        self,
        tenant_ref: str,
        run_id: str,
    ) -> tuple[dict[str, Any], ...]:
        return tuple(
            dict(record["payload"])
            for record in self.records(tenant_ref, run_id)
            if record.get("record_type") == "work_package"
        )

    def append_artifact(
        self,
        artifact: ArtifactEnvelope | Mapping[str, Any],
        *,
        idempotency_key: str,
    ) -> dict[str, Any]:
        envelope = (
            artifact
            if isinstance(artifact, ArtifactEnvelope)
            else ArtifactEnvelope.from_mapping(artifact, require_published_contract=True)
        )
        envelope.validate(expected_tenant_ref=envelope.tenant_ref, expected_run_id=envelope.run_id)
        payload = {
            "tenant_ref": envelope.tenant_ref,
            "run_id": envelope.run_id,
            "artifact_id": envelope.artifact_id,
            "artifact_type": envelope.artifact_type,
            "revision": envelope.revision,
            "ref": envelope.ref,
            "content_sha256": envelope.content_sha256,
            "producer_ref": envelope.producer_ref,
            "producer_work_package_id": envelope.producer_work_package_id,
            "input_artifacts": list(envelope.input_artifacts),
            "validation_cycle_id": envelope.validation_cycle_id,
            "created_at": envelope.created_at,
            "lineage_sha256": envelope.lineage_sha256,
            "migration_unit_id": envelope.migration_unit_id,
            "sensitivity": envelope.sensitivity,
            "retention_policy_ref": envelope.retention_policy_ref,
        }

        def guard(records: list[dict[str, Any]]) -> None:
            if any(
                record.get("record_type") == "artifact"
                and record.get("payload", {}).get("ref") == envelope.ref
                for record in records
            ):
                raise AppendOnlyConflict(
                    "artifact reference must be unique within the run"
                )
            prior_artifacts = [
                record["payload"]
                for record in records
                if record.get("record_type") == "artifact"
                and record.get("payload", {}).get("artifact_id") == envelope.artifact_id
            ]
            if any(
                str(payload.get("artifact_type")) != envelope.artifact_type
                or payload.get("migration_unit_id") != envelope.migration_unit_id
                for payload in prior_artifacts
            ):
                raise AppendOnlyConflict(
                    "artifact identity cannot change type or migration unit"
                )
            revisions = [int(payload["revision"]) for payload in prior_artifacts]
            if revisions and envelope.revision != max(revisions) + 1:
                raise AppendOnlyConflict("artifact revisions must advance by exactly one")
            if not revisions and envelope.revision != 1:
                raise AppendOnlyConflict("first artifact revision must be one")

        return self._append(
            tenant_ref=envelope.tenant_ref,
            run_id=envelope.run_id,
            record_type="artifact",
            record_id=f"{envelope.artifact_id}@{envelope.revision}",
            payload=payload,
            idempotency_key=idempotency_key,
            guard=guard,
        )

    def append_gate(
        self,
        tenant_ref: str,
        run_id: str,
        *,
        gate_id: str,
        validation_cycle_id: str,
        state: str,
        evidence_refs: Iterable[str],
        checked_by_ref: str,
        idempotency_key: str,
        revision: int = 1,
    ) -> dict[str, Any]:
        payload = {
            "gate_id": gate_id,
            "validation_cycle_id": validation_cycle_id,
            "state": state,
            "evidence_refs": list(evidence_refs),
            "checked_by_ref": checked_by_ref,
            "revision": revision,
        }
        return self._append(
            tenant_ref=tenant_ref,
            run_id=run_id,
            record_type="gate",
            record_id=f"{gate_id}@{validation_cycle_id}@{revision}",
            payload=payload,
            idempotency_key=idempotency_key,
        )

    def acquire_lease(
        self,
        tenant_ref: str,
        run_id: str,
        *,
        resource_ref: str,
        owner_ref: str,
        lease_id: str,
        idempotency_key: str,
        ttl_seconds: int,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        if ttl_seconds < 1 or ttl_seconds > 3600:
            raise ValueError("lease TTL must be between 1 and 3600 seconds")
        validate_reference(resource_ref)
        validate_reference(owner_ref)
        current = (now or utc_now()).astimezone(timezone.utc)
        expires = current + timedelta(seconds=ttl_seconds)

        def guard(records: list[dict[str, Any]]) -> None:
            active: dict[str, dict[str, Any]] = {}
            for record in records:
                payload = record.get("payload", {})
                event_type = payload.get("event_type")
                if event_type == "lease_acquired":
                    active[str(payload["resource_ref"])] = payload
                elif event_type == "lease_released":
                    active.pop(str(payload["resource_ref"]), None)
            existing = active.get(resource_ref)
            if existing and parse_time(str(existing["expires_at"])) > current:
                if existing.get("owner_ref") != owner_ref or existing.get("lease_id") != lease_id:
                    raise LeaseConflict("resource is leased by another worker")

        payload = {
            "event_type": "lease_acquired",
            "resource_ref": resource_ref,
            "owner_ref": owner_ref,
            "lease_id": lease_id,
            "expires_at": expires.isoformat().replace("+00:00", "Z"),
        }
        return self._append(
            tenant_ref=tenant_ref,
            run_id=run_id,
            record_type="event",
            record_id=f"lease-acquired-{lease_id}",
            payload=payload,
            idempotency_key=idempotency_key,
            occurred_at=current,
            guard=guard,
        )

    def release_lease(
        self,
        tenant_ref: str,
        run_id: str,
        *,
        resource_ref: str,
        owner_ref: str,
        lease_id: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        validate_reference(resource_ref)
        validate_reference(owner_ref)
        payload = {
            "event_type": "lease_released",
            "resource_ref": resource_ref,
            "owner_ref": owner_ref,
            "lease_id": lease_id,
        }

        def guard(records: list[dict[str, Any]]) -> None:
            active: Mapping[str, Any] | None = None
            for record in records:
                item = record.get("payload", {})
                if item.get("event_type") == "lease_acquired" and item.get(
                    "resource_ref"
                ) == resource_ref:
                    active = item
                elif item.get("event_type") == "lease_released" and item.get(
                    "resource_ref"
                ) == resource_ref:
                    active = None
            if active is None:
                raise LeaseConflict("resource has no active lease to release")
            if active.get("owner_ref") != owner_ref or active.get("lease_id") != lease_id:
                raise LeaseConflict("only the active lease owner can release the resource")

        return self._append(
            tenant_ref=tenant_ref,
            run_id=run_id,
            record_type="event",
            record_id=f"lease-released-{lease_id}",
            payload=payload,
            idempotency_key=idempotency_key,
            guard=guard,
        )

    def record_write_reconciliation(
        self,
        tenant_ref: str,
        run_id: str,
        *,
        operation_id: str,
        target_ref: str,
        readback_ref: str,
        outcome: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        """Record the readback disposition for one ambiguous write.

        Only ``not_applied`` makes a retry safe. ``applied`` prevents duplication and
        ``indeterminate`` keeps the target quarantined for human resolution.
        """

        if outcome not in {"applied", "not_applied", "indeterminate"}:
            raise ValueError("invalid ambiguous-write reconciliation outcome")
        validate_reference(target_ref)
        validate_reference(readback_ref)
        payload = {
            "event_type": "write_reconciliation",
            "operation_id": operation_id,
            "target_ref": target_ref,
            "readback_ref": readback_ref,
            "outcome": outcome,
        }

        def guard(records: list[dict[str, Any]]) -> None:
            prior: Mapping[str, Any] | None = None
            for record in records:
                item = record.get("payload", {})
                if item.get("event_type") == "write_result" and item.get(
                    "operation_id"
                ) == operation_id:
                    prior = item
            if prior is None or prior.get("result") != "ambiguous":
                raise AppendOnlyConflict(
                    "write reconciliation must reference an ambiguous prior operation"
                )
            if prior.get("target_ref") != target_ref:
                raise AppendOnlyConflict("write reconciliation target differs from prior write")

        return self._append(
            tenant_ref=tenant_ref,
            run_id=run_id,
            record_type="event",
            record_id=f"write-reconciliation-{operation_id}",
            payload=payload,
            idempotency_key=idempotency_key,
            guard=guard,
        )

    def record_write_receipt(
        self,
        tenant_ref: str,
        run_id: str,
        *,
        operation_id: str,
        action: str,
        target_ref: str,
        intended_fingerprint: str,
        authorization_id: str,
        work_package_id: str,
        lease_id: str,
        result: str,
        write_receipt_ref: str | None,
        readback_ref: str | None,
        idempotency_key: str,
        attempt: int = 1,
        retry_of_operation_id: str | None = None,
    ) -> dict[str, Any]:
        if result not in {"succeeded", "failed", "ambiguous"}:
            raise ValueError("invalid write result")
        if result == "succeeded" and (not write_receipt_ref or not readback_ref):
            raise ValueError("successful writes require a receipt and readback")
        if result == "ambiguous" and not readback_ref:
            raise ValueError("ambiguous writes require reconciliation readback before retry")
        if attempt < 1:
            raise ValueError("write attempt must be positive")
        if attempt > 1 and not retry_of_operation_id:
            raise ValueError("retry attempts require the prior operation ID")
        for reference in (target_ref, write_receipt_ref, readback_ref):
            if reference:
                validate_reference(reference)
        payload = {
                "operation_id": operation_id,
                "action": action,
                "target_ref": target_ref,
                "intended_fingerprint": intended_fingerprint,
                "authorization_id": authorization_id,
                "work_package_id": work_package_id,
                "lease_id": lease_id,
                "attempt": attempt,
                "retry_of_operation_id": retry_of_operation_id,
                "result": result,
                "write_receipt_ref": write_receipt_ref,
                "readback_ref": readback_ref,
            }

        def guard(records: list[dict[str, Any]]) -> None:
            lease: Mapping[str, Any] | None = None
            prior_writes: dict[str, Mapping[str, Any]] = {}
            reconciliations: dict[str, Mapping[str, Any]] = {}
            for record in records:
                item = record.get("payload", {})
                if item.get("event_type") == "lease_acquired" and item.get("resource_ref") == target_ref:
                    lease = item
                elif item.get("event_type") == "lease_released" and item.get("resource_ref") == target_ref:
                    lease = None
                elif item.get("event_type") == "write_result":
                    prior_writes[str(item.get("operation_id"))] = item
                elif item.get("event_type") == "write_reconciliation":
                    reconciliations[str(item.get("operation_id"))] = item
            if lease is None or lease.get("lease_id") != lease_id:
                raise LeaseConflict("write requires the active lease for its target")
            if parse_time(str(lease["expires_at"])) <= utc_now():
                raise LeaseConflict("write lease has expired")
            if attempt > 1:
                prior = prior_writes.get(str(retry_of_operation_id))
                if prior is None or prior.get("result") not in {"failed", "ambiguous"}:
                    raise AppendOnlyConflict("retry does not reference a failed or reconciled ambiguous write")
                if prior.get("result") == "ambiguous" and reconciliations.get(
                    str(retry_of_operation_id), {}
                ).get("outcome") != "not_applied":
                    raise AppendOnlyConflict(
                        "ambiguous write must be reconciled as not applied before retry"
                    )

        return self._append(
            tenant_ref=tenant_ref,
            run_id=run_id,
            record_type="event",
            record_id=f"write-{operation_id}",
            payload={"event_type": "write_result", **payload},
            idempotency_key=idempotency_key,
            guard=guard,
        )

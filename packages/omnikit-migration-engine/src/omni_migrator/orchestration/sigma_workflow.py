"""Register operator-reviewed Sigma planning evidence in the shared control plane.

This connects a capability capture and human route decision to supervised proposal
execution. It does not accept source completeness, certify QA, or grant target writes.
Human identity/approval records must come from the host's authenticated review surface,
never from a model response. The local CLI is an operator reference implementation.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime
from typing import Any, Literal, Mapping, Sequence

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field

from omni_migrator.control_plane.canonical import sha256_json
from omni_migrator.control_plane.records import ArtifactEnvelope
from omni_migrator.control_plane.store import AppendOnlyConflict, AppendOnlyControlPlaneStore
from omni_migrator.extractors.sigma.capability_contracts import (
    SigmaCapabilitySpikeBundle,
    SigmaSemanticRoutingArtifact,
)
from omni_migrator.extractors.sigma.semantic_routing import route_sigma_semantic_specialists


class SigmaPlanningApproval(BaseModel):
    """Exact host-supplied human record, not a self-attested model approval."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    record_ref: str = Field(pattern=r"^human-(?:approval|decision)-ref://.+")
    revision: str = Field(min_length=1)
    reviewer: str = Field(pattern=r"^human-ref://.+")
    approved_at: AwareDatetime
    purpose: Literal["source_context", "semantic_route"]
    subject: dict[str, Any]

    @property
    def content_hash(self) -> str:
        return sha256_json(self.model_dump(mode="json"))


def source_approval_subject(artifact: Any) -> dict[str, Any]:
    return {
        "artifact_id": artifact.artifact_id,
        "artifact_schema_version": artifact.schema_version,
        "artifact_run_id": artifact.run_id,
        "artifact_scope_id": artifact.scope_id,
        "artifact_created_at": artifact.created_at.isoformat().replace("+00:00", "Z"),
        "content_hash": artifact.content_hash,
    }


def route_approval_subject(value: Any) -> dict[str, Any]:
    """No circular hash: reviewer metadata is bound by the surrounding record."""

    value = getattr(value, "payload", value)
    raw = value.model_dump(mode="json") if isinstance(value, BaseModel) else dict(value)
    keys = (
        "decision_id", "run_id", "scope_id", "migration_unit_id", "comparison_scope_refs",
        "build_scope_refs", "target_environment_refs", "mode", "rationale",
        "source_context_bindings", "supersedes_decision", "question_version",
    )
    return {key: raw.get(key) for key in keys}


def _bundle_artifacts(bundle: SigmaCapabilitySpikeBundle) -> list[Any]:
    return [bundle.run_manifest, *bundle.observations, bundle.capability_matrix,
            bundle.workbook_graph, bundle.data_model_snapshot, bundle.behavior_manifest]


def _artifact_material(artifact: Any) -> dict[str, Any]:
    raw = artifact.model_dump(mode="json")
    raw.pop("content_hash")
    if sha256_json(raw) != artifact.content_hash:
        raise ValueError("Sigma artifact hash is not canonical")
    return raw


def _current_route(records: Sequence[Mapping[str, Any]], unit: str) -> Mapping[str, Any] | None:
    events = [item["payload"] for item in records
              if item.get("record_type") == "event"
              and item.get("payload", {}).get("event_type") in
              {"sigma_route_selected", "sigma_route_revoked"}
              and item["payload"].get("migration_unit_id") == unit]
    return events[-1] if events else None


def _envelope(artifact: Any, *, tenant_ref: str, run_id: str, unit: str,
              cycle: str, sensitivity: str, retention: str) -> ArtifactEnvelope:
    material = _artifact_material(artifact)
    envelope = ArtifactEnvelope(
        tenant_ref=tenant_ref, run_id=run_id, artifact_id=artifact.artifact_id,
        artifact_type=artifact.schema_version.removesuffix(".v1").replace("-", "_"),
        revision=1, ref=f"artifact-ref://{artifact.artifact_id}",
        content_sha256=sha256_json(material), producer_ref=artifact.producer,
        producer_work_package_id=None,
        input_artifacts=tuple({"artifact_id": item.artifact_id, "revision": 1,
                               "content_sha256": item.content_hash}
                              for item in artifact.upstream_hashes),
        validation_cycle_id=cycle, created_at=artifact.created_at.isoformat(),
        lineage_sha256="0" * 64, migration_unit_id=unit,
        sensitivity=sensitivity, retention_policy_ref=retention,
    )
    return replace(envelope, lineage_sha256=envelope.expected_lineage_sha256())


def _require_approval(record: SigmaPlanningApproval, *, purpose: str, subject: dict[str, Any],
                      ref: str, revision: str, digest: str, reviewer: str,
                      approved_at: datetime, human_reviewers: frozenset[str]) -> None:
    if (record.reviewer not in human_reviewers or record.reviewer != reviewer
            or record.record_ref != ref or record.revision != revision
            or record.purpose != purpose or record.subject != subject
            or record.content_hash != digest or record.approved_at != approved_at):
        raise ValueError("Sigma planning approval differs from the exact human/source binding")


def register_sigma_planning_context(
    *, store: AppendOnlyControlPlaneStore, context: Any, bundle: SigmaCapabilitySpikeBundle,
    route_approval: SigmaPlanningApproval, source_approvals: Sequence[SigmaPlanningApproval],
    human_reviewers: Sequence[str], expected_sigma_organization_ref: str,
) -> list[Any]:
    """Import source lineage and select a current route; return scoped runner inputs.

    These records authorize review-only proposals. Partial/manual source capabilities
    remain explicit; neither this function nor the returned inputs satisfies build gates.
    """

    from omni_migrator.orchestration.runner import EvidenceInput
    from omni_migrator.orchestration.sigma_planner import SigmaPlanningContext

    if type(store) is not AppendOnlyControlPlaneStore:
        raise TypeError("Sigma planning requires the canonical control-plane store")
    context = SigmaPlanningContext.model_validate(context)
    bundle = SigmaCapabilitySpikeBundle.model_validate(bundle.model_dump(mode="json"))
    decision = context.decision
    route_sigma_semantic_specialists(decision)
    if bundle.status != "ready_for_human_review":
        raise ValueError("blocked source evidence cannot start Sigma planning")
    manifest = bundle.run_manifest.payload
    # Canonical tenant-ref and Sigma organization-ref are distinct namespaces.
    # The authenticated host must explicitly supply this mapping; never infer it.
    if expected_sigma_organization_ref != manifest.organization_ref:
        raise ValueError("Sigma source organization differs from the host tenant mapping")
    if bundle.scope_id != decision.scope_id:
        raise ValueError("Sigma source and route scopes differ")
    if (set(manifest.comparison_scope_refs) != set(decision.payload.comparison_scope_refs)
            or set(manifest.build_scope_refs) != set(decision.payload.build_scope_refs)):
        raise ValueError("Sigma route differs from the acquired comparison/build scope")
    reviewers = frozenset(human_reviewers)
    if not reviewers or any(not person.startswith("human-ref://") for person in reviewers):
        raise ValueError("host must configure explicit human reviewers")
    by_ref = {record.record_ref: record for record in source_approvals}
    if len(by_ref) != len(source_approvals):
        raise ValueError("source approval references must be unique")
    artifacts = _bundle_artifacts(bundle)
    by_id = {artifact.artifact_id: artifact for artifact in artifacts}
    bindings = decision.payload.source_context_bindings
    if set(by_ref) != {binding.acceptance_ref for binding in bindings}:
        raise ValueError("source approval set differs from route source bindings")
    for binding in bindings:
        source = by_id.get(binding.artifact_id)
        if source is None or any((
            binding.content_hash != source.content_hash,
            binding.artifact_schema_version != source.schema_version,
            binding.artifact_run_id != source.run_id,
            binding.artifact_scope_id != source.scope_id,
            binding.artifact_created_at != source.created_at,
        )):
            raise ValueError("route source binding is absent or differs from captured source")
        _require_approval(
            by_ref[binding.acceptance_ref], purpose="source_context",
            subject=source_approval_subject(source), ref=binding.acceptance_ref,
            revision=binding.acceptance_record_revision, digest=binding.acceptance_record_sha256,
            reviewer=binding.accepted_by_ref, approved_at=binding.accepted_at,
            human_reviewers=reviewers,
        )
    payload = decision.payload
    _require_approval(
        route_approval, purpose="semantic_route", subject=route_approval_subject(decision),
        ref=payload.decision_ref, revision=payload.decision_record_revision,
        digest=payload.decision_record_sha256, reviewer=payload.decided_by_ref,
        approved_at=payload.decided_at, human_reviewers=reviewers,
    )
    # Preserve original artifact run/scope/lineage in content, while the envelope
    # locates this explicitly reviewed import in the new migration run partition.
    all_artifacts = [*artifacts, decision]
    existing = {item["payload"]["ref"]: item["payload"]
                for item in store.records(context.tenant_ref, context.run_id)
                if item["record_type"] == "artifact"}
    for artifact in all_artifacts:
        envelope = _envelope(
            artifact, tenant_ref=context.tenant_ref, run_id=context.run_id,
            unit=context.migration_unit_id, cycle=context.validation_cycle_id,
            sensitivity=manifest.data_classification, retention=manifest.retention_policy_ref,
        )
        prior = existing.get(envelope.ref)
        if prior is not None:
            if (prior["content_sha256"] != envelope.content_sha256
                    or prior["artifact_type"] != envelope.artifact_type
                    or prior["migration_unit_id"] != envelope.migration_unit_id):
                raise AppendOnlyConflict("existing Sigma import has a different identity or content")
        else:
            store.append_artifact(envelope, idempotency_key=f"sigma-import:{artifact.artifact_id}")

    selection = {
        "event_type": "sigma_route_selected", "migration_unit_id": context.migration_unit_id,
        "validation_cycle_id": context.validation_cycle_id,
        "decision_ref": f"artifact-ref://{decision.artifact_id}",
        "decision_hash": decision.content_hash, "mode": payload.mode,
        "decision": decision.model_dump(mode="json"),
        "route_approval": route_approval.model_dump(mode="json"),
        "source_approvals": [record.model_dump(mode="json") for record in source_approvals],
        "source_evidence_mode": manifest.evidence_mode,
        "source_organization_ref": manifest.organization_ref,
        "planning_only": True, "target_write_authority": False,
    }

    def guard(records: list[dict[str, Any]]) -> None:
        prior = _current_route(records, context.migration_unit_id)
        predecessor = payload.supersedes_decision
        if prior is None and predecessor is not None:
            raise AppendOnlyConflict("routing predecessor is not registered")
        if prior is not None and (predecessor is None
                                  or prior["decision_hash"] != predecessor.content_hash
                                  or prior["decision_ref"] != f"artifact-ref://{predecessor.artifact_id}"):
            raise AppendOnlyConflict("replacement must bind the current registered route")

    # Dedicated typed boundary; reserved event names cannot be appended generically.
    store._append(
        tenant_ref=context.tenant_ref, run_id=context.run_id, record_type="event",
        record_id=f"sigma-route:{decision.artifact_id}", payload=selection,
        idempotency_key=f"sigma-route:{decision.content_hash}",
        occurred_at=decision.created_at, guard=guard,
    )
    assert_sigma_route_current(store, context)
    return [EvidenceInput(ref=f"artifact-ref://{artifact.artifact_id}",
                          content_sha256=artifact.content_hash, redaction_status="redacted",
                          payload=_artifact_material(artifact)) for artifact in all_artifacts]


def assert_sigma_route_current(store: AppendOnlyControlPlaneStore, context: Any) -> None:
    """Read current canonical state on every status/dispatch/completion operation."""

    decision = SigmaSemanticRoutingArtifact.model_validate(context.decision.model_dump(mode="json"))
    route_sigma_semantic_specialists(decision)
    ledger = store.verified_ledger(context.tenant_ref, context.run_id)
    current = _current_route(ledger.records, context.migration_unit_id)
    if (current is None or current["event_type"] != "sigma_route_selected"
            or current["decision_hash"] != decision.content_hash
            or current["decision_ref"] != f"artifact-ref://{decision.artifact_id}"
            or current["validation_cycle_id"] != context.validation_cycle_id):
        raise ValueError("Sigma route is unregistered, revoked, superseded, or belongs to another cycle")
    hashes = {item.artifact_id: item.content_hash for item in decision.payload.source_context_bindings}
    hashes[decision.artifact_id] = decision.content_hash
    latest: dict[str, Mapping[str, Any]] = {}
    for record in ledger.records:
        if record["record_type"] == "artifact":
            artifact = record["payload"]
            prior = latest.get(artifact["artifact_id"])
            if prior is None or artifact["revision"] > prior["revision"]:
                latest[artifact["artifact_id"]] = artifact
    if any(artifact_id not in latest or latest[artifact_id]["content_sha256"] != digest
           for artifact_id, digest in hashes.items()):
        raise ValueError("Sigma source or route artifact changed after planning approval")
    require_current_sigma_artifact_refs(
        store, context, [f"artifact-ref://{artifact_id}" for artifact_id in hashes]
    )


def require_current_sigma_artifact_refs(
    store: AppendOnlyControlPlaneStore, context: Any, refs: Sequence[str]
) -> None:
    """Reject stale outputs and transitively changed inputs, not just missing refs."""

    latest: dict[str, Mapping[str, Any]] = {}
    for record in store.verified_ledger(context.tenant_ref, context.run_id).records:
        if record["record_type"] == "artifact":
            artifact = record["payload"]
            prior = latest.get(artifact["artifact_id"])
            if prior is None or artifact["revision"] > prior["revision"]:
                latest[artifact["artifact_id"]] = artifact
    by_ref = {artifact["ref"]: artifact for artifact in latest.values()}

    def visit(artifact: Mapping[str, Any], path: frozenset[str]) -> None:
        if artifact["artifact_id"] in path:
            raise ValueError("Sigma artifact lineage contains a cycle")
        if artifact["migration_unit_id"] != context.migration_unit_id:
            raise ValueError("Sigma artifact crosses its migration unit")
        for binding in artifact["input_artifacts"]:
            parent = latest.get(binding["artifact_id"])
            if (parent is None or parent["revision"] != binding["revision"]
                    or parent["content_sha256"] != binding["content_sha256"]):
                raise ValueError("Sigma artifact has a stale or unresolved upstream input")
            visit(parent, path | {artifact["artifact_id"]})

    for ref in refs:
        if ref not in by_ref:
            raise ValueError("Sigma artifact reference is missing or superseded")
        visit(by_ref[ref], frozenset())


def revoke_sigma_route(*, store: AppendOnlyControlPlaneStore, context: Any, reviewer: str,
                       human_reviewers: Sequence[str],
                       reason: Literal["source_changed", "route_changed", "approval_withdrawn"]) -> None:
    if reviewer not in human_reviewers or not reviewer.startswith("human-ref://"):
        raise ValueError("route revocation requires a host-authorized human")
    if reason not in {"source_changed", "route_changed", "approval_withdrawn"}:
        raise ValueError("unsupported revocation reason")
    decision = context.decision

    def guard(records: list[dict[str, Any]]) -> None:
        current = _current_route(records, context.migration_unit_id)
        if (current is None or current["event_type"] != "sigma_route_selected"
                or current["decision_hash"] != decision.content_hash):
            raise AppendOnlyConflict("only the current Sigma route can be revoked")

    store._append(
        tenant_ref=context.tenant_ref, run_id=context.run_id, record_type="event",
        record_id=f"sigma-route-revoked:{decision.artifact_id}",
        payload={"event_type": "sigma_route_revoked", "migration_unit_id": context.migration_unit_id,
                 "decision_ref": f"artifact-ref://{decision.artifact_id}",
                 "decision_hash": decision.content_hash, "reviewer": reviewer, "reason": reason},
        idempotency_key=f"sigma-revoke:{decision.content_hash}", guard=guard,
    )

"""Canonical, store-backed admission and atomic claims for target operations.

Registration binds an already authorized request to current planner evidence; it
does not create human authorization. The host configures the store and actor map.
"""

from __future__ import annotations

from datetime import datetime
from types import MappingProxyType
from typing import Any, Mapping
from urllib.parse import urlsplit
from uuid import uuid4

from omni_migrator.control_plane.canonical import sha256_json
from omni_migrator.control_plane.gates import GateRecordResolver
from omni_migrator.control_plane.records import ArtifactEnvelope
from omni_migrator.control_plane.store import AppendOnlyConflict, AppendOnlyControlPlaneStore
from omni_migrator.orchestration.planner import (
    INPUT_BOUND_GATE_REFS,
    PlannedWorkPackage,
)
from omni_migrator.targets.contracts import TargetOperationRequest

_WRITE_PHASES = {
    "write_dbt_development_branch": ("data_build", "branch_write"),
    "write_omni_authored_model_yaml": ("semantic_build", "branch_write"),
    "create_omni_document_in_quarantine": ("document_create", "document_create_write"),
    "create_omni_content_draft": ("content_build", "document_draft_write"),
}


class StoreBackedTargetExecutionResolver:
    """No caller-supplied readiness, resolver callbacks, or permissive fallback."""

    def __init__(
        self, *, store: AppendOnlyControlPlaneStore, actor_kinds: Mapping[str, str]
    ) -> None:
        if type(store) is not AppendOnlyControlPlaneStore:
            raise TypeError("target execution requires the canonical control-plane store")
        self._store = store
        self._actor_kinds = MappingProxyType(dict(actor_kinds))

    @staticmethod
    def _state(package: PlannedWorkPackage, records: tuple[Mapping[str, Any], ...]) -> str:
        state = package.status
        for record in records:
            payload = record.get("payload", {})
            if (
                payload.get("event_type") == "target_work_package_state"
                and payload.get("work_package_id") == package.work_package_id
                and payload.get("validation_cycle_id") == package.validation_cycle_id
            ):
                state = str(payload["status"])
        return state

    @staticmethod
    def _current_artifacts(records: tuple[Mapping[str, Any], ...]) -> dict[str, ArtifactEnvelope]:
        by_id: dict[str, ArtifactEnvelope] = {}
        for record in records:
            if record.get("record_type") == "artifact":
                artifact = ArtifactEnvelope.from_mapping(record["payload"])
                prior = by_id.get(artifact.artifact_id)
                if prior is None or artifact.revision > prior.revision:
                    by_id[artifact.artifact_id] = artifact
        by_ref = {artifact.ref: artifact for artifact in by_id.values()}
        if len(by_ref) != len(by_id):
            raise ValueError("target inputs have ambiguous current artifact references")
        return by_ref

    def _outputs_current(self, package, records, references) -> bool:
        artifacts = self._current_artifacts(records)
        outputs = [artifacts.get(reference) for reference in references]
        return (
            bool(outputs)
            and all(
                item is not None
                and item.producer_work_package_id == package.work_package_id
                and item.validation_cycle_id == package.validation_cycle_id
                and item.migration_unit_id == package.migration_unit_id
                for item in outputs
            )
            and set(package.expected_artifacts).issubset(
                {item.artifact_type for item in outputs if item is not None}
            )
        )

    def _dependency_current(self, package, records) -> bool:
        if self._state(package, records) != "completed":
            return False
        references = package.result.artifact_refs
        for item in records:
            payload = item.get("payload", {})
            if (
                payload.get("event_type") == "target_work_package_state"
                and payload.get("work_package_id") == package.work_package_id
                and payload.get("validation_cycle_id") == package.validation_cycle_id
                and payload.get("status") == "completed"
            ):
                references = payload.get("produced_artifact_refs", ())
        return self._outputs_current(package, records, references)

    def _context(self, request: TargetOperationRequest, *, now: datetime):
        type(request).model_validate(request.model_dump(mode="python"))
        ledger = self._store.verified_ledger(request.tenant_ref, request.run_id)
        records = ledger.records
        packages = {
            item["payload"]["work_package_id"]: PlannedWorkPackage.model_validate(item["payload"])
            for item in records
            if item.get("record_type") == "work_package"
        }
        package = packages.get(request.work_package_id)
        if package is None:
            raise ValueError("target work package is not registered in this partition")
        if any(
            getattr(package, name) != getattr(request, name)
            for name in (
                "tenant_ref",
                "run_id",
                "migration_unit_id",
                "validation_cycle_id",
                "work_package_id",
            )
        ):
            raise ValueError("target request differs from its registered work package partition")
        state = self._state(package, records)
        active_qa_read = (
            state == "in_progress"
            and request.action == "execute_snowflake_bounded_query"
            and package.phase in {"development_qa", "production_qa"}
            and package.authority.mode == "read_only"
        )
        if state not in {"pending", "ready"} and not active_qa_read:
            raise ValueError("target work package is not dispatchable")
        if any(
            item.get("payload", {}).get("event_type") == "target_work_package_state"
            and item["payload"].get("status") == "in_progress"
            and item["payload"].get("operation_id") == request.operation_id
            for item in records
        ):
            raise ValueError("target operation has already been claimed")
        if any(
            dependency not in packages
            or not self._dependency_current(packages[dependency], records)
            for dependency in package.depends_on
        ):
            raise ValueError("target work package has incomplete registered dependencies")
        authority = package.authority
        expected = _WRITE_PHASES.get(request.action)
        if expected is not None:
            if (
                (package.phase, authority.mode) != expected
                or authority.authorization_ref != request.authorization.authorization_ref
                or authority.intended_change_set_fingerprint != request.change_set_fingerprint
                or set(authority.target_scope_refs) != set(request.authorization.scope_refs)
            ):
                raise ValueError("target request does not match its registered package authority")
        elif request.action == "execute_snowflake_bounded_query":
            if "snowflake_bounded_query" not in authority.allowed_tools:
                raise ValueError("work package does not permit Snowflake validation queries")
        else:
            raise ValueError("target action has no supported registered work-package mapping")
        if self._actor_kinds.get(request.authorization.actor_ref) != "human":
            raise ValueError("target authorization actor is not a configured trusted human")
        if not package.gate_refs:
            raise ValueError("target execution requires current acceptance gates")

        artifacts = self._current_artifacts(records)
        input_bindings = []
        for reference in package.input_refs:
            # An action authorization is resolved/consumed independently by the
            # configured authorization store. Every other input is artifact-bound.
            if urlsplit(reference).scheme == "authorization-ref":
                continue
            artifact = artifacts.get(reference)
            if artifact is None:
                raise ValueError("target package input has no current typed artifact")
            artifact.validate(
                expected_tenant_ref=request.tenant_ref, expected_run_id=request.run_id
            )
            if (
                artifact.validation_cycle_id != request.validation_cycle_id
                or artifact.migration_unit_id not in {None, request.migration_unit_id}
            ):
                raise ValueError("target package input belongs to a stale cycle or another unit")
            input_bindings.append(
                {
                    "ref": reference,
                    "artifact_id": artifact.artifact_id,
                    "revision": artifact.revision,
                    "content_sha256": artifact.content_sha256,
                }
            )
        if not input_bindings:
            raise ValueError("target execution requires typed immutable package inputs")
        plan_ref = getattr(request, "dashboard_rebuild_plan_ref", None)
        if plan_ref is not None:
            plan = artifacts.get(plan_ref)
            if (
                plan_ref not in package.input_refs
                or plan is None
                or plan.artifact_type != "dashboard_rebuild_plan"
                or plan.content_sha256 != request.dashboard_rebuild_plan_fingerprint
            ):
                raise ValueError("target document plan is not the exact current package input")

        gates: dict[str, Mapping[str, Any]] = {}
        for record in records:
            if record.get("record_type") != "gate":
                continue
            gate = dict(record["payload"])
            if gate.get("validation_cycle_id") != request.validation_cycle_id:
                continue
            gate.setdefault("required_evidence_refs", gate.get("evidence_refs", []))
            gate.setdefault("checked_at", record["occurred_at"])
            prior = gates.get(str(gate["gate_id"]))
            if prior is None or int(gate.get("revision", 1)) > int(prior.get("revision", 1)):
                gates[str(gate["gate_id"])] = gate

        def events(kind: str):
            return [
                dict(item["payload"])
                for item in records
                if item.get("payload", {}).get("event_type") == kind
            ]

        resolver = GateRecordResolver.from_control_plane_records(
            tenant_ref=request.tenant_ref,
            run_id=request.run_id,
            validation_cycle_id=request.validation_cycle_id,
            gates=list(gates.values()),
            artifacts=[
                item["payload"] for item in records if item.get("record_type") == "artifact"
            ],
            actor_kinds=self._actor_kinds,
            strict_actor_resolution=True,
            now=now,
            dashboard_evidence_snapshots=events("dashboard_evidence_snapshot_registered"),
            dashboard_plan_validations=events("dashboard_plan_validated"),
            qa_evidence_snapshots=events("qa_evidence_snapshot_registered"),
            qa_suite_validations=events("qa_suite_validated"),
            semantic_profile_coverages=events("semantic_profile_coverage_registered"),
            verified_event_ledger=ledger,
        )
        for reference in package.gate_refs:
            if not resolver.is_gate_satisfied(
                gate_ref_value=reference,
                tenant_ref=request.tenant_ref,
                run_id=request.run_id,
                validation_cycle_id=request.validation_cycle_id,
                migration_unit_id=request.migration_unit_id,
            ):
                raise ValueError("target work package has an unsatisfied current lifecycle gate")
            if reference in INPUT_BOUND_GATE_REFS and not resolver.typed_evidence_refs_for_ref(
                reference, migration_unit_id=request.migration_unit_id
            ).issubset(set(package.input_refs)):
                raise ValueError("target gate evidence is absent from the package inputs")
            if resolver.bound_artifact_coverage_violations_for_ref(
                reference,
                bound_input_refs=package.input_refs,
                migration_unit_id=request.migration_unit_id,
            ):
                raise ValueError("target gate does not cover the exact accepted package inputs")
        binding = {
            "request_fingerprint": request.request_fingerprint(),
            "work_package_id": package.work_package_id,
            "validation_cycle_id": package.validation_cycle_id,
            "package_fingerprint": sha256_json(package.model_dump(mode="json")),
            "input_bindings": sorted(input_bindings, key=lambda item: item["ref"]),
        }
        return ledger, package, binding

    def _append_at_head(self, ledger, *, event_id: str, event_type: str, payload, now):
        def guard(records):
            if (
                len(records) != ledger.record_count
                or records[-1]["record_hash"] != ledger.ledger_head
            ):
                raise AppendOnlyConflict(
                    "execution state changed concurrently; reload before retry"
                )

        return self._store._append(
            tenant_ref=ledger.tenant_ref,
            run_id=ledger.run_id,
            record_type="event",
            record_id=event_id,
            payload={"event_type": event_type, **payload},
            idempotency_key=event_id,
            occurred_at=now,
            guard=guard,
        )

    def register_request(self, request: TargetOperationRequest, *, now: datetime) -> None:
        """Bind a request after resolving real package/gate/input state, never assertions."""
        ledger, _, binding = self._context(request, now=now)
        self._append_at_head(
            ledger,
            event_id=f"target-request-{request.operation_id}",
            event_type="target_execution_request_registered",
            payload=binding,
            now=now,
        )

    def validate(self, request: TargetOperationRequest, *, now: datetime):
        ledger, package, binding = self._context(request, now=now)
        registered = [
            item["payload"]
            for item in ledger.records
            if item.get("record_id") == f"target-request-{request.operation_id}"
        ]
        expected = {"event_type": "target_execution_request_registered", **binding}
        if registered != [expected]:
            raise ValueError(
                "target request or accepted input hashes differ from its trusted registration"
            )
        return ledger, package, binding

    def resolve_and_claim(self, request: TargetOperationRequest, *, now: datetime) -> None:
        ledger, package, binding = self.validate(request, now=now)
        self._append_at_head(
            ledger,
            event_id=f"target-claim-{request.operation_id}-{uuid4().hex}",
            event_type="target_work_package_state",
            payload={
                **binding,
                "status": "in_progress",
                "operation_id": request.operation_id,
                "previous_status": self._state(package, ledger.records),
            },
            now=now,
        )

    def transition_work_package_state(
        self,
        *,
        tenant_ref: str,
        run_id: str,
        work_package_id: str,
        status: str,
        actor_ref: str,
        reason: str,
        now: datetime,
        produced_artifact_refs: tuple[str, ...] = (),
    ) -> None:
        """Host-controlled completion/recovery; receipt success alone is not completion."""
        actor_kind = self._actor_kinds.get(actor_ref)
        if not reason.strip() or actor_kind not in {"human", "independent_qa", "runtime"}:
            raise ValueError(
                "package transitions require a configured trusted actor and explicit reason"
            )
        if status in {"ready", "superseded"} and actor_kind != "human":
            raise ValueError("package recovery or supersession requires a trusted human")
        if now.tzinfo is None:
            raise ValueError("package transition time must be timezone-aware")
        ledger = self._store.verified_ledger(tenant_ref, run_id)
        matching = [
            item["payload"]
            for item in ledger.records
            if item.get("record_type") == "work_package"
            and item.get("record_id") == work_package_id
        ]
        if len(matching) != 1:
            raise ValueError("package transition requires one registered work package")
        package = PlannedWorkPackage.model_validate(matching[0])
        previous = self._state(package, ledger.records)
        allowed = {
            "pending": {"blocked", "superseded"},
            "ready": {"blocked", "superseded"},
            "in_progress": {"completed", "blocked"},
            "blocked": {"ready", "superseded"},
        }
        if package.authority.mode not in {
            "branch_write",
            "document_create_write",
            "document_draft_write",
        }:
            allowed["pending"].add("completed")
            allowed["ready"].add("completed")
        if status not in allowed.get(previous, set()):
            raise ValueError("illegal target work-package state transition")
        if status == "completed":
            if not self._outputs_current(package, ledger.records, produced_artifact_refs):
                raise ValueError("completed package requires every current typed output")
        payload = {
            "work_package_id": work_package_id,
            "validation_cycle_id": package.validation_cycle_id,
            "status": status,
            "previous_status": previous,
            "actor_ref": actor_ref,
            "reason": reason,
            "produced_artifact_refs": list(produced_artifact_refs),
        }
        self._append_at_head(
            ledger,
            event_id=f"target-state-{sha256_json(payload)}-{ledger.record_count}",
            event_type="target_work_package_state",
            payload=payload,
            now=now,
        )

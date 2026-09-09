"""Route-dependent Sigma planning and shared work-package regressions."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from dataclasses import replace
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from omni_migrator.control_plane.canonical import sha256_json
from omni_migrator.control_plane.gates import required_gate_ids_for_work_phase
from omni_migrator.control_plane.policy import (
    PolicyContext,
    _required_package_gate_ids_for_work_package,
)
from omni_migrator.control_plane.records import ArtifactEnvelope
from omni_migrator.control_plane.store import AppendOnlyControlPlaneStore
from omni_migrator.extractors.sigma.capability_contracts import SigmaSemanticRoutingArtifact
from omni_migrator.extractors.sigma.semantic_routing import create_sigma_semantic_routing_decision
from omni_migrator.orchestration.planner import PlannedWorkPackage, validate_work_graph
from omni_migrator.orchestration.sigma_planner import SigmaPlanningContext, build_sigma_work_graph


EXAMPLES = Path(__file__).resolve().parents[3] / "contracts" / "sigma" / "examples"
WORK_PACKAGE_SCHEMA = (
    Path(__file__).resolve().parents[3] / "contracts" / "agent-work-package.schema.json"
)
DECIDED = datetime(2026, 9, 3, 15, tzinfo=UTC)
PLANNED = DECIDED + timedelta(minutes=1)


def _decision(route="omni-reconstruction"):
    value = json.loads(
        (
            EXAMPLES / (f"sigma-semantic-routing-decision-request.v1.{route}.example.json")
        ).read_text()
    )
    return create_sigma_semantic_routing_decision(value, created_at=DECIDED)


def _graph(route="omni-reconstruction"):
    return build_sigma_work_graph(
        _decision(route),
        tenant_ref="tenant-ref://example",
        validation_cycle_id="cycle-sigma-1",
        created_at=PLANNED,
    )


@pytest.mark.parametrize(
    "route,dbt_required,count",
    [
        ("warehouse-first", True, 6),
        ("omni-reconstruction", False, 5),
    ],
)
def test_sigma_route_builds_deterministic_bound_proposals(route, dbt_required, count):
    graph = _graph(route)
    decision = _decision(route)
    assert [item.model_dump(mode="json") for item in graph] == [
        item.model_dump(mode="json") for item in _graph(route)
    ]
    assert len(graph) == count
    validator = Draft202012Validator(json.loads(WORK_PACKAGE_SCHEMA.read_text()))
    roles = [item.assignee.agent_id for item in graph]
    assert ("sigma_dbt_analytics_engineer" in roles) is dbt_required
    assert roles[:2] == ["sigma_analytics_formula", "sigma_semantic_consolidation"]
    assert roles[-3:] == [
        "sigma_omni_modeler",
        "sigma_independent_qa",
        "sigma_documentation_training",
    ]
    for index, package in enumerate(graph):
        validator.validate(package.model_dump(mode="json"))
        assert package.depends_on == ([graph[index - 1].work_package_id] if index else [])
        assert package.sigma_routing.mode == decision.payload.mode
        assert package.sigma_routing.decision_hash == decision.content_hash
        assert package.sigma_routing.include_dependency_results is True
        assert package.sigma_routing.comparison_scope_refs == list(
            decision.payload.comparison_scope_refs
        )
        assert package.sigma_routing.build_scope_refs == list(decision.payload.build_scope_refs)
        assert package.sigma_routing.target_environment_refs == list(
            decision.payload.target_environment_refs
        )
        assert {item.object_id: item.fingerprint for item in package.source_scope} == {
            item.artifact_id: item.content_hash for item in decision.payload.source_context_bindings
        }
        assert all(ref.startswith("artifact-ref://") for ref in package.input_refs)
        assert f"artifact-ref://{decision.artifact_id}" in package.input_refs
        assert package.authority.mode in {"read_only", "proposal_only"}
        assert package.authority.authorization_ref is None
        assert package.authority.target_scope_refs == []
        assert package.authority.intended_change_set_fingerprint is None
        assert package.authority.allowed_tools == ["artifact_registry_read", "local_draft_write"]
        assert package.gate_refs == []
        assert package.status == "pending"
        assert package.result.state == "not_started"
    qa = graph[-2]
    assert ("dbt_readback" in qa.validation_requirements[0].method) is dbt_required
    assert "omni_readback" in qa.validation_requirements[0].method


def test_route_change_rekeys_every_package_without_changing_source_hashes():
    direct, warehouse = _graph(), _graph("warehouse-first")
    assert not {item.work_package_id for item in direct}.intersection(
        item.work_package_id for item in warehouse
    )
    assert (
        direct[0].sigma_routing.source_artifact_hashes
        == warehouse[0].sigma_routing.source_artifact_hashes
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("run_id", "run-other"),
        ("migration_unit_id", "unit-other"),
        ("created_at", "2026-09-03T14:00:00Z"),
        ("created_at", "2026-09-03T16:00:00"),
    ],
)
def test_context_rejects_wrong_identity_or_time(field, value):
    decision = _decision()
    context = {
        "tenant_ref": "tenant-ref://example",
        "run_id": decision.run_id,
        "migration_unit_id": decision.payload.migration_unit_id,
        "validation_cycle_id": "cycle-1",
        "created_at": PLANNED.isoformat(),
        "decision": decision,
    }
    context[field] = value
    with pytest.raises(ValidationError):
        SigmaPlanningContext.model_validate(context)


def test_planner_rejects_superseded_choice():
    value = _decision().model_dump(mode="json")
    value.update(supersession_state="superseded", superseded_by_artifact_id="decision-successor")
    value.pop("content_hash")
    value["content_hash"] = sha256_json(value)
    with pytest.raises(ValueError, match="superseded"):
        build_sigma_work_graph(
            SigmaSemanticRoutingArtifact.model_validate(value),
            tenant_ref="tenant-ref://example",
            validation_cycle_id="cycle-1",
            created_at=PLANNED,
        )


@pytest.mark.parametrize(
    "mutation", ["missing_binding", "missing_mode", "bad_hash", "missing_input", "wrong_source"]
)
def test_shared_package_rejects_missing_or_inconsistent_sigma_binding(mutation):
    value = _graph()[0].model_dump(mode="json")
    if mutation == "missing_binding":
        value.pop("sigma_routing")
    elif mutation == "missing_mode":
        value["sigma_routing"].pop("mode")
    elif mutation == "bad_hash":
        value["sigma_routing"]["decision_hash"] = "not-a-hash"
    elif mutation == "missing_input":
        value["input_refs"].pop()
    else:
        value["source_scope"][0]["fingerprint"] = "0" * 64
    with pytest.raises(ValidationError):
        PlannedWorkPackage.model_validate(value)


@pytest.mark.parametrize("mutation", ["phase", "assignee", "tool"])
def test_shared_direct_package_cannot_schedule_dbt(mutation):
    value = _graph()[0].model_dump(mode="json")
    if mutation == "phase":
        value["phase"] = "sigma_dbt_planning"
    elif mutation == "assignee":
        value["assignee"]["agent_id"] = "sigma_dbt_analytics_engineer"
    else:
        value["phase"] = "production_qa"
        value["gate_refs"] = ["gate-ref://omni_readback"]
        value["authority"]["allowed_tools"] = ["dbt_build"]
    with pytest.raises(ValidationError, match="cannot schedule dbt"):
        PlannedWorkPackage.model_validate(value)


def test_planning_package_cannot_gain_target_write_authority():
    value = _graph("warehouse-first")[2].model_dump(mode="json")
    value["authority"].update(
        mode="branch_write",
        authorization_ref="approval-ref://target",
        intended_change_set_fingerprint="a" * 64,
        target_scope_refs=["environment-ref://dbt/development"],
    )
    with pytest.raises(ValidationError, match="cannot grant execution"):
        PlannedWorkPackage.model_validate(value)


def test_shared_production_qa_prerequisites_are_route_dependent_and_domo_unchanged():
    direct = _graph()[3].model_dump(mode="json")
    direct.update(phase="production_qa", gate_refs=["gate-ref://omni_readback"])
    PlannedWorkPackage.model_validate(direct)

    warehouse = _graph("warehouse-first")[4].model_dump(mode="json")
    warehouse.update(phase="production_qa", gate_refs=["gate-ref://omni_readback"])
    with pytest.raises(ValidationError, match="dbt_readback"):
        PlannedWorkPackage.model_validate(warehouse)
    warehouse["gate_refs"].append("gate-ref://dbt_readback")
    PlannedWorkPackage.model_validate(warehouse)

    domo = dict(direct)
    domo["sigma_routing"] = None
    domo["source_scope"] = [
        {"system": "domo", "object_type": "card", "object_id": "card-1", "fingerprint": "a" * 64}
    ]
    domo["assignee"] = {"kind": "agent", "agent_id": "migration_qa"}
    with pytest.raises(ValidationError, match="dbt_readback"):
        PlannedWorkPackage.model_validate(domo)
    domo["gate_refs"] = ["gate-ref://omni_readback", "gate-ref://dbt_readback"]
    PlannedWorkPackage.model_validate(domo)
    assert "sigma_routing" not in PlannedWorkPackage.model_validate(domo).model_dump(mode="json")
    assert required_gate_ids_for_work_phase("production_qa") == ("dbt_readback", "omni_readback")


def test_graph_rejects_mixed_decision_hashes_for_one_unit_and_cycle():
    graph = _graph()
    value = graph[-1].model_dump(mode="json")
    value["sigma_routing"]["decision_hash"] = "f" * 64
    graph[-1] = PlannedWorkPackage.model_validate(value)
    with pytest.raises(ValueError, match="conflicting routing"):
        validate_work_graph(graph)


def _policy_records(tmp_path, decision):
    """Fixture-only registration to exercise canonical-ledger resolution without live calls."""
    store = AppendOnlyControlPlaneStore(tmp_path)
    envelopes = []
    for artifact_id, digest in [
        *(
            (item.artifact_id, item.content_hash)
            for item in decision.payload.source_context_bindings
        ),
        (decision.artifact_id, decision.content_hash),
    ]:
        envelope = ArtifactEnvelope(
            tenant_ref="tenant-ref://example",
            run_id=decision.run_id,
            migration_unit_id=decision.payload.migration_unit_id,
            artifact_id=artifact_id,
            artifact_type="sigma_planning_evidence",
            revision=1,
            ref=f"artifact-ref://{artifact_id}",
            content_sha256=digest,
            producer_ref="agent-ref://sigma-to-omni-architect",
            producer_work_package_id=None,
            input_artifacts=(),
            validation_cycle_id="cycle-sigma-1",
            created_at=DECIDED.isoformat(),
            lineage_sha256="0" * 64,
        )
        envelope = replace(envelope, lineage_sha256=envelope.expected_lineage_sha256())
        store.append_artifact(envelope, idempotency_key=artifact_id)
        envelopes.append(envelope)
    selection = {
        "event_type": "sigma_route_selected",
        "migration_unit_id": decision.payload.migration_unit_id,
        "validation_cycle_id": "cycle-sigma-1",
        "decision_ref": f"artifact-ref://{decision.artifact_id}",
        "decision_hash": decision.content_hash,
        "mode": decision.payload.mode,
        "decision": decision.model_dump(mode="json"),
        "planning_only": True,
        "target_write_authority": False,
    }
    store._append(
        tenant_ref="tenant-ref://example",
        run_id=decision.run_id,
        record_type="event",
        record_id="sigma-test-selection",
        payload=selection,
        idempotency_key="sigma-test-selection",
        occurred_at=DECIDED,
    )
    return store, envelopes, selection


@pytest.mark.parametrize("route", ["warehouse-first", "omni-reconstruction"])
def test_policy_and_schema_agree_with_shared_route_specific_production_prerequisites(
    tmp_path, route
):
    decision = _decision(route)
    package = _graph(route)[-2].model_dump(mode="json")
    prerequisites = required_gate_ids_for_work_phase(
        "production_qa", sigma_semantic_mode=decision.payload.mode
    )
    package.update(
        phase="production_qa",
        gate_refs=[f"gate-ref://{item}" for item in prerequisites],
        expected_artifacts=[
            "qa_result",
            "qa_acceptance_suite",
            "qa_suite_validation",
            "qa_target_operation_outcome",
            "production_validation_report",
            "independent_verdict",
        ],
    )
    package = PlannedWorkPackage.model_validate(package).model_dump(mode="json")
    Draft202012Validator(json.loads(WORK_PACKAGE_SCHEMA.read_text())).validate(package)
    store, _, _ = _policy_records(tmp_path, decision)
    context = PolicyContext(
        verified_event_ledger=store.verified_ledger("tenant-ref://example", decision.run_id)
    )
    assert _required_package_gate_ids_for_work_package(package, context) == frozenset(prerequisites)
    with pytest.raises(ValueError, match="verified route ledger"):
        _required_package_gate_ids_for_work_package(package, PolicyContext())


@pytest.mark.parametrize("mutation", ["revoked", "source_changed", "mode_hint"])
def test_policy_never_relaxes_prerequisites_from_stale_or_mismatched_route_metadata(
    tmp_path, mutation
):
    route = "warehouse-first" if mutation == "mode_hint" else "omni-reconstruction"
    decision = _decision(route)
    package = _graph(route)[-2].model_dump(mode="json")
    store, envelopes, selection = _policy_records(tmp_path, decision)
    if mutation == "mode_hint":
        package["sigma_routing"]["mode"] = "omni_semantic_reconstruction"
        package["sigma_routing"]["target_environment_refs"] = ["environment-ref://omni/quarantine"]
    elif mutation == "revoked":
        store._append(
            tenant_ref="tenant-ref://example",
            run_id=decision.run_id,
            record_type="event",
            record_id="sigma-test-revocation",
            idempotency_key="sigma-test-revocation",
            payload={**selection, "event_type": "sigma_route_revoked"},
            occurred_at=PLANNED,
        )
    else:
        changed = replace(
            envelopes[0], revision=2, ref=envelopes[0].ref + "/2", content_sha256="f" * 64
        )
        changed = replace(changed, lineage_sha256=changed.expected_lineage_sha256())
        store.append_artifact(changed, idempotency_key="source-changed")
    package.update(phase="production_qa", gate_refs=["gate-ref://omni_readback"])
    context = PolicyContext(
        verified_event_ledger=store.verified_ledger("tenant-ref://example", decision.run_id)
    )
    with pytest.raises(ValueError, match="registered semantic route|stale or unregistered"):
        _required_package_gate_ids_for_work_package(package, context)

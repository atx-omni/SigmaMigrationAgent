"""Credential-free integration: captured evidence -> human route -> durable proposals."""

from dataclasses import replace
from datetime import UTC, datetime
import json

import pytest

from omni_migrator.control_plane.canonical import sha256_json
from omni_migrator.control_plane.records import ArtifactEnvelope
from omni_migrator.control_plane.store import AppendOnlyConflict, AppendOnlyControlPlaneStore
from omni_migrator.extractors.sigma.semantic_routing import create_sigma_semantic_routing_decision
from omni_migrator.orchestration.provider import FixtureProposalProvider as Provider
from omni_migrator.orchestration.runner import EvidenceInput, MigrationRunConfig, MigrationRunner
from omni_migrator.orchestration.sigma_planner import SigmaPlanningContext
from omni_migrator.orchestration.sigma_workflow import (
    SigmaPlanningApproval,
    assert_sigma_route_current,
    register_sigma_planning_context,
    revoke_sigma_route,
    route_approval_subject,
    source_approval_subject,
)
from tests.test_sigma_capability_spike import _request as source_request, _run
from tests.test_sigma_semantic_routing import _request as route_request


REVIEWER = "human-ref://migration-owner"


def prepared(mode="omni_semantic_reconstruction"):
    # MockTransport simulates the live-request branch; this is not tenant evidence.
    bundle, _ = _run(request=source_request(scope_id="scope.sigma.migration.0001"))
    approvals = []
    bindings = []
    for artifact in (bundle.workbook_graph, bundle.data_model_snapshot):
        record = SigmaPlanningApproval(
            record_ref=f"human-approval-ref://sigma/source/{artifact.artifact_id}",
            revision="revision-1", reviewer=REVIEWER,
            approved_at=datetime(2026, 9, 3, 13, 30, tzinfo=UTC),
            purpose="source_context", subject=source_approval_subject(artifact),
        )
        approvals.append(record)
        bindings.append({**source_approval_subject(artifact), "accepted_by_ref": REVIEWER,
                         "acceptance_ref": record.record_ref,
                         "acceptance_record_revision": record.revision,
                         "acceptance_record_sha256": record.content_hash,
                         "accepted_at": record.approved_at,
                         "acceptance_verification_state": "reference_only"})
    request = route_request(mode=mode, source_context_bindings=bindings)
    approval = SigmaPlanningApproval(
        record_ref=request.decision_ref, revision=request.decision_record_revision,
        reviewer=REVIEWER, approved_at=request.decided_at,
        purpose="semantic_route", subject=route_approval_subject(request),
    )
    request = request.model_copy(update={"decision_record_sha256": approval.content_hash})
    decision = create_sigma_semantic_routing_decision(
        request, created_at=datetime(2026, 9, 3, 15, tzinfo=UTC)
    )
    context = SigmaPlanningContext(
        tenant_ref="tenant-ref://sigma-pilot", run_id=decision.run_id,
        migration_unit_id=decision.payload.migration_unit_id,
        validation_cycle_id="sigma-cycle-1", created_at="2026-09-03T15:01:00Z", decision=decision,
    )
    return bundle, context, approval, approvals


def register(store, material):
    bundle, context, approval, source_approvals = material
    return register_sigma_planning_context(
        store=store, context=context, bundle=bundle, route_approval=approval,
        source_approvals=source_approvals, human_reviewers=[REVIEWER],
        expected_sigma_organization_ref="sigma-org-ref://approved-org",
    )


def initialize(tmp_path, mode="omni_semantic_reconstruction"):
    material = prepared(mode)
    store = AppendOnlyControlPlaneStore(tmp_path / "control")
    inputs = register(store, material)
    config = MigrationRunConfig(
        context=material[1], model="operator-configured-test-model", human_reviewers=[REVIEWER],
        model_egress_approval_ref="human-approval-ref://test-only-egress",
        inputs=inputs, budget={"max_calls": 10, "max_reserved_tokens": 500_000,
                              "max_reserved_tokens_per_agent": 100_000, "max_input_bytes": 80_000,
                              "input_usd_per_million": 0, "output_usd_per_million": 0,
                              "max_estimated_cost_usd": 0},
    )
    return MigrationRunner.initialize(tmp_path / "run", config, control_store=store), material


def reviewed_output(runner, package_id, *, include_predecessors=True, complete=True):
    config, packages, resolver, completed = runner._graph()
    package = next(item for item in packages if item.work_package_id == package_id)
    input_refs = (runner._resolved_input_refs(config, packages, resolver, completed, package)
                  if include_predecessors else package.input_refs)
    payload = {"draft": "Human-reviewed planning output, not accepted target semantics."}
    envelope = ArtifactEnvelope(
        tenant_ref=config.context.tenant_ref, run_id=config.context.run_id,
        artifact_id=f"output-{package_id}", artifact_type=package.expected_artifacts[0], revision=1,
        ref=f"artifact-ref://output-{package_id}/v1", content_sha256=sha256_json(payload),
        producer_ref=f"agent-ref://{package.assignee.agent_id}", producer_work_package_id=package_id,
        input_artifacts=tuple({"artifact_id": item.artifact_id, "revision": item.revision,
                               "content_sha256": item.content_sha256}
                              for item in resolver.artifacts if item.ref in input_refs),
        validation_cycle_id=package.validation_cycle_id, migration_unit_id=package.migration_unit_id,
        created_at="2026-09-03T16:00:00Z", lineage_sha256="0" * 64,
    )
    envelope = replace(envelope, lineage_sha256=envelope.expected_lineage_sha256())
    runner.control.append_artifact(envelope, idempotency_key=f"output:{package_id}")
    runner.attach(EvidenceInput(ref=envelope.ref, payload=payload,
                                content_sha256=envelope.content_sha256, redaction_status="not_required"))
    if complete:
        runner.complete(package_id, reviewer=REVIEWER, artifact_refs=[envelope.ref])
    return envelope


@pytest.mark.parametrize("mode,expected", [("omni_semantic_reconstruction", 5),
                                            ("warehouse_first_refactor", 6)])
def test_captured_source_human_route_and_durable_proposal_handoff(tmp_path, mode, expected):
    runner, material = initialize(tmp_path, mode)
    status = runner.status()
    assert len(status["packages"]) == expected
    assert status["target_write_authority"] is False
    provider = Provider()
    result = runner.propose_next(provider, allow_model_calls=True)
    assert result["state"] == "proposed"
    assert result["accepted"] is False
    assert "Sigma-to-Omni" in provider.calls[0]["instructions"]
    assert "Domo-to-Omni" not in provider.calls[0]["instructions"]
    assert "no dbt" in provider.calls[0]["instructions"] if mode == "omni_semantic_reconstruction" else True
    reopened = MigrationRunner(runner.run_dir, control_store=runner.control)
    assert not reopened.status()["ready_package_ids"]  # no automatic repeated model call
    envelope = reviewed_output(reopened, result["package"])
    next_provider = Provider()
    next_result = reopened.propose_next(next_provider, allow_model_calls=True)
    assert next_result["state"] == "proposed"
    assert envelope.ref in next_provider.calls[0]["context"]["untrusted_evidence"]
    downstream = reviewed_output(reopened, next_result["package"])
    assert envelope.artifact_id in {item["artifact_id"] for item in downstream.input_artifacts}
    assert_sigma_route_current(runner.control, material[1])


def test_interrupted_graph_registration_cannot_report_partial_completion(tmp_path, monkeypatch):
    original = AppendOnlyControlPlaneStore.append_work_package
    registered = []

    def interrupt_after_first(store, package, **kwargs):
        if registered:
            raise RuntimeError("simulated initialization interruption")
        result = original(store, package, **kwargs)
        registered.append(package.work_package_id)
        return result

    with monkeypatch.context() as patch:
        patch.setattr(AppendOnlyControlPlaneStore, "append_work_package", interrupt_after_first)
        with pytest.raises(RuntimeError, match="initialization interruption"):
            initialize(tmp_path)
    assert len(registered) == 1
    reopened = MigrationRunner(tmp_path / "run", control_store=AppendOnlyControlPlaneStore(tmp_path / "control"))
    with pytest.raises(ValueError, match="registration is incomplete"):
        reopened.status()


def test_completion_rejects_missing_reviewed_predecessor_lineage(tmp_path):
    runner, _ = initialize(tmp_path)
    first = runner.propose_next(Provider(), allow_model_calls=True)
    reviewed_output(runner, first["package"])
    second = runner.propose_next(Provider(), allow_model_calls=True)
    output = reviewed_output(runner, second["package"], include_predecessors=False, complete=False)
    with pytest.raises(ValueError, match="predecessor lineage"):
        runner.complete(second["package"], reviewer=REVIEWER, artifact_refs=[output.ref])


@pytest.mark.parametrize("change", ["wrong_record_hash", "wrong_human", "wrong_subject"])
def test_self_attested_or_changed_approval_cannot_register(tmp_path, change):
    material = list(prepared())
    record = material[2]
    updates = {"wrong_record_hash": {"revision": "revision-2"},
               "wrong_human": {"reviewer": "human-ref://unknown"},
               "wrong_subject": {"subject": {"mode": "warehouse_first_refactor"}}}[change]
    material[2] = record.model_copy(update=updates)
    store = AppendOnlyControlPlaneStore(tmp_path / "control")
    with pytest.raises(ValueError, match="approval differs"):
        register(store, material)
    assert store.records(material[1].tenant_ref, material[1].run_id) == []


def test_revocation_blocks_resume_and_model_calls(tmp_path):
    runner, material = initialize(tmp_path)
    revoke_sigma_route(store=runner.control, context=material[1], reviewer=REVIEWER,
                       human_reviewers=[REVIEWER], reason="source_changed")
    provider = Provider()
    with pytest.raises(ValueError, match="revoked"):
        runner.propose_next(provider, allow_model_calls=True)
    assert provider.calls == []


def test_currentness_rejects_changed_source_and_generic_event_forgery(tmp_path):
    runner, material = initialize(tmp_path)
    store = runner.control
    with pytest.raises(AppendOnlyConflict):
        store.append_event(material[1].tenant_ref, material[1].run_id, event_id="forged",
                           event_type="sigma_route_selected", payload={}, idempotency_key="forged")
    source_id = material[1].decision.payload.source_context_bindings[0].artifact_id
    raw = next(item["payload"] for item in store.records(material[1].tenant_ref, material[1].run_id)
               if item["record_type"] == "artifact" and item["payload"]["artifact_id"] == source_id)
    revised = replace(ArtifactEnvelope.from_mapping(raw), revision=2,
                      ref=f"artifact-ref://{source_id}/new", content_sha256="f" * 64)
    revised = replace(revised, lineage_sha256=revised.expected_lineage_sha256())
    store.append_artifact(revised, idempotency_key="changed-source")
    with pytest.raises(ValueError, match="changed"):
        runner.status()


def test_provider_forgery_retains_budget_and_does_not_complete(tmp_path):
    runner, _ = initialize(tmp_path)
    provider = Provider(forged=True)
    result = runner.propose_next(provider, allow_model_calls=True)
    assert result["state"] == "failed"
    status = runner.status()
    assert not status["completed_package_ids"]
    assert status["attempts"][0]["reserved_tokens"] > 0
    assert not status["ready_package_ids"]


def test_explicit_egress_approval_required_before_provider_call(tmp_path):
    runner, _ = initialize(tmp_path)
    provider = Provider()
    assert runner.propose_next(provider)["state"] == "blocked"
    assert provider.calls == []


def test_sigma_cli_status_and_opt_in_boundary(tmp_path, capsys):
    from omni_migrator.runtime import main

    runner, _ = initialize(tmp_path)
    paths = ["--run-dir", str(runner.run_dir), "--control-dir", str(tmp_path / "control")]
    assert main(["sigma-run-status", *paths]) == 0
    status = json.loads(capsys.readouterr().out)
    assert status["planning_only"] is True and status["migration_accepted"] is False
    assert status["semantic_mode"] == "omni_semantic_reconstruction"
    assert main(["sigma-run-step", *paths]) == 2
    assert json.loads(capsys.readouterr().out)["state"] == "blocked"


def test_generic_event_payload_cannot_forge_route_selection(tmp_path):
    store = AppendOnlyControlPlaneStore(tmp_path / "control")
    with pytest.raises(AppendOnlyConflict):
        store.append_event("tenant-ref://sigma-pilot", "run.sigma.migration.0001",
                           event_id="forged-selection", event_type="ordinary_event",
                           payload={"event_type": "sigma_route_selected"},
                           idempotency_key="forged-selection")

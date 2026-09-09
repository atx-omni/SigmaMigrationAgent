"""Small regression suite against the Sigma implementation; all sockets denied."""
from dataclasses import replace
import json
from pathlib import Path
import socket
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import preflight as lab
import pytest
from omni_migrator.control_plane.store import AppendOnlyConflict
from omni_migrator.extractors.sigma.capability_spike import validate_artifact_content_hash
from omni_migrator.orchestration.sigma_workflow import revoke_sigma_route


@pytest.fixture(autouse=True)
def no_network():
    with lab.NetworkDeny() as guard:
        yield guard


@pytest.fixture(scope="module")
def suite():
    return lab.load_suite()


@pytest.fixture
def captured(suite):
    return lab.capture(suite, simulated_live_branch=True)[0]


def test_network_guard_is_real(no_network):
    with pytest.raises(AssertionError, match="network is forbidden"):
        socket.create_connection(("never-connect.example.invalid", 443))
    assert len(no_network.attempts) == 1


def test_strict_synthetic_input_cannot_open_live_capability_gate_or_register(suite, tmp_path):
    bundle, trace = lab.capture(suite)
    assert not trace["unmatched_routes"]
    assert bundle.status == "blocked"
    assert "live tenant evidence has not been collected" in bundle.blockers
    with pytest.raises(ValueError, match="blocked source evidence"):
        lab.initialize(bundle, "omni_semantic_reconstruction", tmp_path)


def test_capture_preserves_ids_formulas_nested_types_and_private_boundaries(suite, captured):
    assert captured.status == "ready_for_human_review", captured.blockers
    graph = captured.workbook_graph.payload
    assert graph.workbook_id == suite["request"]["workbook_id"]
    nodes = {node.native_id: node for node in graph.nodes}
    model = captured.data_model_snapshot.payload
    model_ids = {model.data_model_id}
    for page in model.sanitized_specification["pages"]:
        for element in page["elements"]:
            model_ids.add(element.get("id", element.get("elementId")))
    # Independent expected source facts live outside the production parser.
    expected = suite["expected"]
    for key in expected.get("required_native_ids", []):
        assert key in nodes or key in model_ids
    for item in expected.get("formula_bindings", []):
        node = nodes[item["column_id"]]
        assert node.properties["formula"] == item["formula"]
    assert nodes["wc-detail-size-options"].properties["type"] == (
        suite["independent_source_assertions"]["nested_column_type"])
    assert graph.untrusted_source_content is True
    for artifact in (captured.workbook_graph, captured.data_model_snapshot,
                     captured.capability_matrix, captured.behavior_manifest):
        assert validate_artifact_content_hash(artifact)
    serialized = captured.model_dump_json()
    for marker in expected.get("redacted_markers", []):
        assert marker not in serialized
    blocked_gates = {gate.gate_id: gate.state for gate in captured.gate_recommendations}
    assert blocked_gates["target_write_authorized"] == "blocked"
    assert blocked_gates["release_authorized"] == "blocked"
    assert captured.behavior_manifest.payload.unresolved_behavior_ids


def test_explicit_choice_has_no_default():
    prompt = lab.advance_sigma_semantic_routing()
    assert prompt.default_mode is None
    assert prompt.state == "awaiting_human_choice"
    assert {option.mode for option in prompt.options} == {
        "omni_semantic_reconstruction", "warehouse_first_refactor"}


@pytest.mark.parametrize("mode,count", [("omni_semantic_reconstruction", 5),
                                         ("warehouse_first_refactor", 6)])
def test_all_specialists_resume_and_finish_only_planning(captured, tmp_path, mode, count, no_network):
    result = lab.exercise_route(captured, mode, tmp_path)
    assert result["state"] == "work_graph_completed_not_released", result
    assert result["stub_provider_calls"] == count
    phases = [item["phase"] for item in result["steps"]]
    assert ("sigma_dbt_planning" in phases) == (mode == "warehouse_first_refactor")
    assert result["up_to_omni_push_ready"] is False
    assert result["final_status"]["target_write_authority"] is False
    assert result["final_status"]["release_authority"] is False
    assert no_network.attempts == []


def test_missing_opt_in_cannot_call_provider(captured, tmp_path):
    runner, _ = lab.initialize(captured, "omni_semantic_reconstruction", tmp_path)
    provider = lab.StubProvider()
    assert runner.propose_next(provider)["state"] == "blocked"
    assert provider.calls == []


def test_fake_approval_rejected_before_registration(captured, tmp_path):
    context, approval, sources = lab.prepare_route(captured, "omni_semantic_reconstruction")
    forged = approval.model_copy(update={"reviewer": "human-ref://unconfigured-attacker"})
    store = lab.AppendOnlyControlPlaneStore(tmp_path / "control")
    with pytest.raises(ValueError, match="approval differs"):
        lab.register_sigma_planning_context(
            store=store, context=context, bundle=captured, route_approval=forged,
            source_approvals=sources, human_reviewers=[lab.REVIEWER],
            expected_sigma_organization_ref=captured.run_manifest.payload.organization_ref)
    assert store.records(context.tenant_ref, context.run_id) == []


def test_forged_model_citation_fails_and_retains_reserved_budget(captured, tmp_path):
    runner, _ = lab.initialize(captured, "omni_semantic_reconstruction", tmp_path)
    result = runner.propose_next(lab.StubProvider(forged=True), allow_model_calls=True)
    assert result["state"] == "failed"
    status = runner.status()
    assert not status["completed_package_ids"] and not status["ready_package_ids"]
    assert status["attempts"][0]["reserved_tokens"] > 0


def test_provider_failure_requires_explicit_retry_without_budget_refund(captured, tmp_path):
    runner, _ = lab.initialize(captured, "omni_semantic_reconstruction", tmp_path)
    assert runner.propose_next(lab.StubProvider(fail=True), allow_model_calls=True)["state"] == "failed"
    prior = runner.status()["attempts"][0]
    assert prior["reserved_tokens"] > 0
    with pytest.raises(ValueError, match="reviewer"):
        runner.retry(prior["attempt"], reviewer="human-ref://attacker")
    runner.retry(prior["attempt"], reviewer=lab.REVIEWER)
    assert runner.status()["attempts"][0]["reserved_tokens"] == prior["reserved_tokens"]
    assert runner.propose_next(lab.StubProvider(), allow_model_calls=True)["state"] == "proposed"
    assert len(runner.status()["attempts"]) == 2


def test_unregistered_output_and_missing_predecessor_lineage_rejected(captured, tmp_path):
    runner, _ = lab.initialize(captured, "omni_semantic_reconstruction", tmp_path)
    first = runner.propose_next(lab.StubProvider(), allow_model_calls=True)
    with pytest.raises(ValueError, match="registered"):
        runner.complete(first["package"], reviewer=lab.REVIEWER, artifact_refs=["artifact-ref://fake"])
    lab.simulate_review(runner, first["package"])
    second = runner.propose_next(lab.StubProvider(), allow_model_calls=True)
    envelope = lab.simulate_review(runner, second["package"], include_predecessors=False, complete=False)
    with pytest.raises(ValueError, match="predecessor lineage"):
        runner.complete(second["package"], reviewer=lab.REVIEWER, artifact_refs=[envelope.ref])


def test_revocation_stops_resume_and_provider(captured, tmp_path):
    runner, material = lab.initialize(captured, "omni_semantic_reconstruction", tmp_path)
    revoke_sigma_route(store=runner.control, context=material[0], reviewer=lab.REVIEWER,
                       human_reviewers=[lab.REVIEWER], reason="source_changed")
    provider = lab.StubProvider()
    with pytest.raises(ValueError, match="revoked"):
        runner.propose_next(provider, allow_model_calls=True)
    assert provider.calls == []


def test_source_hash_change_and_generic_event_spoofing_rejected(captured, tmp_path):
    runner, material = lab.initialize(captured, "omni_semantic_reconstruction", tmp_path)
    context = material[0]
    with pytest.raises(AppendOnlyConflict):
        runner.control.append_event(context.tenant_ref, context.run_id, event_id="synthetic-forgery",
            event_type="sigma_route_selected", payload={}, idempotency_key="synthetic-forgery")
    source_id = context.decision.payload.source_context_bindings[0].artifact_id
    raw = next(record["payload"] for record in runner.control.records(context.tenant_ref, context.run_id)
               if record["record_type"] == "artifact" and record["payload"]["artifact_id"] == source_id)
    changed = replace(lab.ArtifactEnvelope.from_mapping(raw), revision=2,
                      ref=f"artifact-ref://{source_id}/changed", content_sha256="f" * 64)
    changed = replace(changed, lineage_sha256=changed.expected_lineage_sha256())
    runner.control.append_artifact(changed, idempotency_key="synthetic-source-change")
    with pytest.raises(ValueError, match="changed"):
        runner.status()


def test_partial_initialization_cannot_report_success(captured, tmp_path, monkeypatch):
    original = lab.AppendOnlyControlPlaneStore.append_work_package
    recorded = []
    def interrupt(store, package, **kwargs):
        if recorded:
            raise RuntimeError("synthetic interruption")
        result = original(store, package, **kwargs)
        recorded.append(package.work_package_id)
        return result
    with monkeypatch.context() as scope:
        scope.setattr(lab.AppendOnlyControlPlaneStore, "append_work_package", interrupt)
        with pytest.raises(RuntimeError, match="synthetic interruption"):
            lab.initialize(captured, "omni_semantic_reconstruction", tmp_path)
    reopened = lab.MigrationRunner(tmp_path / "run", control_store=lab.AppendOnlyControlPlaneStore(tmp_path / "control"))
    with pytest.raises(ValueError, match="registration is incomplete"):
        reopened.status()


@pytest.mark.parametrize("mode", ["omni_semantic_reconstruction", "warehouse_first_refactor"])
def test_user_goal_has_a_pre_push_target_build_handoff(captured, tmp_path, mode, monkeypatch):
    """Verify actual persisted outputs, not phase labels; no scope-parity claim.

The original complex capture remains unresolved. The independent, explicitly
reduced fictional example proves the supported operator-to-build path only.
"""
    from omni_migrator.prepush.cli import main
    from omni_migrator.prepush.session import Session
    repo = Path(__file__).resolve().parents[3]
    source, target = tmp_path / "source.json", tmp_path / "target.json"
    source.write_bytes((repo / "examples/retail-supported.json").read_bytes())
    target.write_bytes((repo / "examples/target.json").read_bytes())
    run = tmp_path / "public-run"
    assert captured.behavior_manifest.payload.unresolved_behavior_ids
    assert main(["init", "--run-dir", str(run), "--source", str(source), "--target", str(target), "--synthetic"]) == 0
    assert main(["route", "--run-dir", str(run), "--mode", mode]) == 0
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda _: "accept")
    assert main(["review", "--run-dir", str(run)]) == 0
    assert main(["build", "--run-dir", str(run)]) == 0
    path, result = Session(run).validate_package()
    assert result["status"] == "offline_preflight_passed", result
    manifest = json.loads((path / "manifest.json").read_text())
    assert manifest["synthetic"] is True
    assert manifest["migration_accepted"] is False
    assert manifest["build"]["dispositions"] and manifest["build"]["source_mappings"]
    names = set(manifest["files"])
    assert any(name.endswith(".view") for name in names)
    assert "omni/document.create.json" in names
    document = json.loads((path / "omni/document.create.json").read_text())
    assert document["queryPresentations"]["data"] and document["controls"]["data"]
    assert any(name.startswith("dbt/") for name in names) == (mode == "warehouse_first_refactor")

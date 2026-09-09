"""Offline Sigma exercise. Test doubles never establish production acceptance.

Run with Python dependencies installed, from the dedicated Sigma repository.
The local Sigma engine is imported explicitly; no sibling checkout is used.
"""
from __future__ import annotations

import copy
from dataclasses import replace
from datetime import UTC, datetime
import json
from pathlib import Path
import socket
import sys
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent
ENGINE = ROOT.parents[1] / "packages/omnikit-migration-engine/src"
sys.path.insert(0, str(ENGINE))

import httpx
import omni_migrator
from omni_migrator.control_plane.canonical import sha256_json
from omni_migrator.control_plane.records import ArtifactEnvelope
from omni_migrator.control_plane.store import AppendOnlyControlPlaneStore
from omni_migrator.extractors.sigma.api import SigmaApi
from omni_migrator.extractors.sigma.capability_contracts import (
    SigmaCapabilitySpikeRequest, SigmaSemanticRoutingDecisionRequest,
)
from omni_migrator.extractors.sigma.capability_spike import run_sigma_capability_spike
from omni_migrator.extractors.sigma.semantic_routing import (
    advance_sigma_semantic_routing, create_sigma_semantic_routing_decision,
)
from omni_migrator.orchestration.provider import DraftArtifact, ProviderResult, SpecialistProposal
from omni_migrator.orchestration.runner import EvidenceInput, MigrationRunConfig, MigrationRunner
from omni_migrator.orchestration.sigma_planner import SigmaPlanningContext
from omni_migrator.orchestration.sigma_workflow import (
    SigmaPlanningApproval, register_sigma_planning_context, route_approval_subject,
    source_approval_subject,
)

assert Path(omni_migrator.__file__).resolve().is_relative_to(ENGINE)
REVIEWER = "human-ref://synthetic-test-reviewer-not-a-real-person"
STAMP = datetime(2026, 9, 8, 16, 0, tzinfo=UTC)
PROVENANCE = {
    "synthetic": True, "live_tenant_evidence": False,
    "human_approvals": "test doubles only; not real approval",
    "provider": "deterministic test double; no live AI evaluation",
    "migration_accepted": False, "publish_authorized": False,
}


class NetworkDeny:
    """Block actual sockets even if a mocked adapter is accidentally omitted."""
    def __init__(self):
        self.attempts = []
        self.patches = []

    def deny(self, *args, **kwargs):
        self.attempts.append("network attempt blocked")
        raise AssertionError("All network is forbidden in the synthetic preflight")

    def __enter__(self):
        for target in ("socket.create_connection", "socket.getaddrinfo",
                       "socket.socket.connect", "socket.socket.connect_ex"):
            item = patch(target, self.deny)
            item.start()
            self.patches.append(item)
        return self

    def __exit__(self, *args):
        for item in reversed(self.patches):
            item.stop()


def write_result(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True, default=str) + "\n")


def load_suite():
    return json.loads((ROOT / "artifacts/fixture-suite.json").read_text())


def mutate(suite, mutations):
    value = copy.deepcopy(suite)
    for item in mutations:
        tokens = [token.replace("~1", "/").replace("~0", "~")
                  for token in item["path"].split("/")[1:]]
        parent = value
        for token in tokens[:-1]:
            parent = parent[int(token)] if isinstance(parent, list) else parent[token]
        key = int(tokens[-1]) if isinstance(parent, list) else tokens[-1]
        if item["op"] == "remove":
            del parent[key]
        elif item["op"] in {"add", "replace"}:
            parent[key] = copy.deepcopy(item["value"])
        else:
            raise ValueError("unsupported fixture mutation")
    return value


def capture(suite, *, simulated_live_branch=False):
    raw = copy.deepcopy(suite["request"])
    # Deliberate test-only branch coverage. Never call this real tenant evidence.
    raw["evidence_mode"] = "live_tenant" if simulated_live_branch else "synthetic_fixture"
    request = SigmaCapabilitySpikeRequest.model_validate(raw)
    calls, unmatched = [], []

    def handler(req):
        key = f"{req.method} {req.url.path}"
        query = dict(req.url.params)
        calls.append({"method": req.method, "path": req.url.path, "query": query})
        variants = sorted(suite["routes"].get(key, []),
                          key=lambda item: len(item.get("match_query", {})), reverse=True)
        for variant in variants:
            if all(query.get(k) == str(v) for k, v in variant.get("match_query", {}).items()):
                return httpx.Response(variant.get("status", 200), json=variant.get("json", {}))
        unmatched.append(key)
        return httpx.Response(404, json={"code": "unconfigured_synthetic_route"})

    api = SigmaApi(
        base_url=request.api_base_url, client_id="synthetic-client-not-a-credential",
        client_secret="synthetic-secret-not-a-credential", transport=httpx.MockTransport(handler),
        request_budget=request.request_budget,
    )
    try:
        bundle = run_sigma_capability_spike(request, api=api, started_at=STAMP)
    finally:
        api.close()
    return bundle, {"requests": calls, "unmatched_routes": unmatched}


def prepare_route(bundle, mode):
    """Simulate a review service using the real typed registration contracts."""
    approvals, bindings = [], []
    for artifact in (bundle.workbook_graph, bundle.data_model_snapshot):
        approval = SigmaPlanningApproval(
            record_ref=f"human-approval-ref://synthetic-only/source/{artifact.artifact_id}",
            revision="synthetic-r1", reviewer=REVIEWER,
            approved_at="2026-09-08T17:00:00Z", purpose="source_context",
            subject=source_approval_subject(artifact),
        )
        approvals.append(approval)
        bindings.append({**source_approval_subject(artifact), "accepted_by_ref": REVIEWER,
                         "acceptance_ref": approval.record_ref,
                         "acceptance_record_revision": approval.revision,
                         "acceptance_record_sha256": approval.content_hash,
                         "accepted_at": approval.approved_at,
                         "acceptance_verification_state": "reference_only"})
    manifest = bundle.run_manifest.payload
    target_refs = ["environment-ref://omni/synthetic-never-connect"]
    if mode == "warehouse_first_refactor":
        target_refs.append("environment-ref://dbt/synthetic-never-connect")
    request = SigmaSemanticRoutingDecisionRequest(
        schema_version="sigma-semantic-routing-decision-request.v1",
        decision_id=f"synthetic-{mode}", run_id=f"run.synthetic.{mode}", scope_id=bundle.scope_id,
        migration_unit_id="unit.synthetic.retail", comparison_scope_refs=list(manifest.comparison_scope_refs),
        build_scope_refs=list(manifest.build_scope_refs), target_environment_refs=target_refs,
        mode=mode, decided_by_ref=REVIEWER,
        decision_ref=f"human-decision-ref://synthetic-only/{mode}",
        decision_record_revision="synthetic-r1", decision_record_sha256="a" * 64,
        decided_at="2026-09-08T17:01:00Z", rationale="Synthetic route test; no customer authority.",
        source_context_bindings=bindings,
        question_version="sigma-semantic-migration-question.v1",
    )
    route_approval = SigmaPlanningApproval(
        record_ref=request.decision_ref, revision=request.decision_record_revision,
        reviewer=REVIEWER, approved_at=request.decided_at, purpose="semantic_route",
        subject=route_approval_subject(request),
    )
    request = request.model_copy(update={"decision_record_sha256": route_approval.content_hash})
    decision = create_sigma_semantic_routing_decision(
        request, created_at=datetime(2026, 9, 8, 17, 2, tzinfo=UTC))
    context = SigmaPlanningContext(
        tenant_ref="tenant-ref://synthetic-retail-only", run_id=decision.run_id,
        migration_unit_id=decision.payload.migration_unit_id,
        validation_cycle_id="synthetic-cycle-1", created_at="2026-09-08T17:03:00Z", decision=decision,
    )
    return context, route_approval, approvals


def initialize(bundle, mode, directory):
    directory = Path(directory)
    context, approval, source_approvals = prepare_route(bundle, mode)
    store = AppendOnlyControlPlaneStore(directory / "control")
    inputs = register_sigma_planning_context(
        store=store, context=context, bundle=bundle, route_approval=approval,
        source_approvals=source_approvals, human_reviewers=[REVIEWER],
        expected_sigma_organization_ref=bundle.run_manifest.payload.organization_ref,
    )
    config = MigrationRunConfig(
        context=context, model="synthetic-stub-no-live-model", human_reviewers=[REVIEWER],
        model_egress_approval_ref="human-approval-ref://synthetic-only/no-network",
        inputs=inputs, budget={"max_calls": 12, "max_calls_per_agent": 2,
            "max_reserved_tokens": 1_000_000, "max_reserved_tokens_per_agent": 200_000,
            "max_input_bytes": 100_000, "max_output_tokens": 1000,
            "input_usd_per_million": 0, "output_usd_per_million": 0,
            "max_estimated_cost_usd": 0},
    )
    runner = MigrationRunner.initialize(directory / "run", config, control_store=store)
    return runner, (context, approval, source_approvals)


class StubProvider:
    """Tests orchestration/lineage, never model quality or semantic correctness."""
    def __init__(self, *, forged=False, fail=False):
        self.calls = []
        self.forged = forged
        self.fail = fail

    def propose(self, *, instructions, context, max_output_tokens):
        raw = json.loads(context)
        self.calls.append({"instructions": instructions, "context": raw})
        assert "UNTRUSTED DATA" in instructions and "Sigma-to-Omni" in instructions
        if self.fail:
            raise RuntimeError("synthetic provider failure")
        package = raw["work_package"]
        content = {
            **PROVENANCE, "phase": package["phase"],
            "review_note": "Synthetic planning response only. Do not execute or approve semantics.",
            "required_follow_up": ["live source comparison", "real human review",
                                   "Sigma target-build integration", "Omni readback"],
        }
        refs = ["artifact-ref://invented-out-of-scope"] if self.forged else sorted(raw["untrusted_evidence"])
        return ProviderResult(
            response_id=f"synthetic-response-{len(self.calls)}", input_tokens=100, output_tokens=80,
            proposal=SpecialistProposal(
                status="proposed", summary="Synthetic orchestration test, not a migration.",
                artifacts=[DraftArtifact(artifact_type=package["expected_artifacts"][0],
                    title="Synthetic planning stub", content=json.dumps(content), source_refs=refs)],
                blockers=[], decision_requests=[],
            ),
        )


def simulate_review(runner, package_id, *, include_predecessors=True, complete=True):
    config, packages, resolver, completed = runner._graph()
    package = next(item for item in packages if item.work_package_id == package_id)
    refs = (runner._resolved_input_refs(config, packages, resolver, completed, package)
            if include_predecessors else package.input_refs)
    payload = {**PROVENANCE, "test_review": "simulated host registration; not human acceptance",
               "phase": package.phase}
    envelope = ArtifactEnvelope(
        tenant_ref=config.context.tenant_ref, run_id=config.context.run_id,
        artifact_id=f"synthetic-output-{package_id}", artifact_type=package.expected_artifacts[0],
        revision=1, ref=f"artifact-ref://synthetic-output-{package_id}/v1",
        content_sha256=sha256_json(payload), producer_ref=f"agent-ref://{package.assignee.agent_id}",
        producer_work_package_id=package_id,
        input_artifacts=tuple({"artifact_id": item.artifact_id, "revision": item.revision,
            "content_sha256": item.content_sha256} for item in resolver.artifacts if item.ref in refs),
        validation_cycle_id=package.validation_cycle_id, migration_unit_id=package.migration_unit_id,
        created_at="2026-09-08T18:00:00Z", lineage_sha256="0" * 64,
    )
    envelope = replace(envelope, lineage_sha256=envelope.expected_lineage_sha256())
    runner.control.append_artifact(envelope, idempotency_key=f"synthetic-output:{package_id}")
    runner.attach(EvidenceInput(ref=envelope.ref, payload=payload,
                  content_sha256=envelope.content_sha256, redaction_status="not_required"))
    if complete:
        runner.complete(package_id, reviewer=REVIEWER, artifact_refs=[envelope.ref])
    return envelope


def exercise_route(bundle, mode, directory):
    runner, _ = initialize(bundle, mode, directory)
    provider = StubProvider()
    log = []
    while runner.status()["ready_package_ids"]:
        # Bounded by the actual graph (five/six), plus explicit safety ceiling.
        if len(log) >= 6:
            raise AssertionError("unexpected extra planning steps")
        before = runner.status()
        result = runner.propose_next(provider, allow_model_calls=True)
        if result["state"] != "proposed":
            return {"state": "blocked_before_planning_completion", "result": result, "steps": log}
        assert result["accepted"] is False
        reopened = MigrationRunner(runner.run_dir, control_store=runner.control)
        assert not reopened.status()["ready_package_ids"], "proposal replayed without review"
        reviewed = simulate_review(reopened, result["package"])
        log.append({"phase": next(p["phase"] for p in before["packages"] if p["id"] == result["package"]),
                    "proposal": result, "test_reviewed_artifact": reviewed.to_mapping()
                    if hasattr(reviewed, "to_mapping") else {"ref": reviewed.ref, "lineage_sha256": reviewed.lineage_sha256}})
        runner = reopened
    final = runner.status()
    _, graph, _, _ = runner._graph()
    target_packages = [package.work_package_id for package in graph
                       if package.phase in {"semantic_build", "document_create", "content_build"}]
    assert not final["target_write_authority"] and not final["release_authority"]
    return {"state": final["state"], "steps": log, "final_status": final,
            "stub_provider_calls": len(provider.calls),
            "up_to_omni_push_ready": False,
            "target_build_package_ids": target_packages,
            "missing_deliverables": ["deployable Sigma-derived Omni model and dashboard",
                "independent semantic/behavior/security validation", "real review integration"],
            "provider_trace": provider.calls}


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise SystemExit("Choose a new output directory; prior evidence is never overwritten.")
    args.output.mkdir(parents=True)
    report = {"provenance": PROVENANCE, "engine_source": "isolated unchanged recovery snapshot",
              "original_baseline": "912e56d80431b50738397605d346ff5bf6c1b1be plus preserved local changes"}
    with NetworkDeny() as network:
        suite = load_suite()
        strict, trace = capture(suite)
        write_result(args.output / "strict-synthetic-capture.json", {
            "provenance": PROVENANCE, "engine_result": strict.model_dump(mode="json"), "transport": trace})
        report["strict_synthetic"] = {"status": strict.status, "blockers": strict.blockers}
        live_branch, trace = capture(suite, simulated_live_branch=True)
        write_result(args.output / "SIMULATED-live-branch-capture.json", {
            "provenance": {**PROVENANCE, "warning": "Inner live_tenant flags are branch simulation, NOT live evidence."},
            "engine_result": live_branch.model_dump(mode="json"), "transport": trace})
        report["mock_transport_capture"] = {"status": live_branch.status, "blockers": live_branch.blockers,
                                             "requests": len(trace["requests"]), "unmatched": trace["unmatched_routes"]}
        report["routes"] = {}
        if live_branch.status == "ready_for_human_review":
            for mode in ("omni_semantic_reconstruction", "warehouse_first_refactor"):
                result = exercise_route(live_branch, mode, args.output / mode)
                write_result(args.output / f"{mode}-trace.json", {"provenance": PROVENANCE, **result})
                report["routes"][mode] = {k: v for k, v in result.items() if k not in {"steps", "provider_trace"}}
        report["network_attempts"] = network.attempts
        report["omni_write_calls"] = 0
    write_result(args.output / "preflight-results.json", report)
    print(json.dumps({"report": str(args.output / "preflight-results.json"),
                      "capture": report["mock_transport_capture"],
                      "routes": {k: v["state"] for k, v in report["routes"].items()},
                      "network_attempts": len(report["network_attempts"]), "omni_writes": 0}, indent=2))


if __name__ == "__main__":
    main()

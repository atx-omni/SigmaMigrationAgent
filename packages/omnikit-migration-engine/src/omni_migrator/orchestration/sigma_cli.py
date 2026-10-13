"""Operator-only Sigma planning CLI. No target writes or automatic approvals."""

from __future__ import annotations

from pathlib import Path

from omni_migrator.control_plane.store import AppendOnlyControlPlaneStore
from omni_migrator.extractors.sigma.capability_contracts import SigmaCapabilitySpikeBundle
from omni_migrator.extractors.sigma.semantic_routing import prompt_for_sigma_semantic_route
from omni_migrator.orchestration.provider import EGRESS_DISABLED_REASON
from omni_migrator.orchestration.runner import EvidenceInput, MigrationRunConfig, MigrationRunner
from omni_migrator.orchestration.sigma_planner import SigmaPlanningContext
from omni_migrator.orchestration.sigma_workflow import (
    SigmaPlanningApproval,
    assert_sigma_route_current,
    register_sigma_planning_context,
    revoke_sigma_route,
)


def _read(path: Path, *, allow_array: bool = False):
    from omni_migrator.prepush.session import read_json

    return read_json(path, allow_array=allow_array)


def add_sigma_workflow_commands(commands):
    for operation in ("init", "status", "step", "attach", "complete", "retry", "revoke"):
        parser = commands.add_parser(
            f"sigma-run-{operation}", help=f"{operation.title()} supervised Sigma planning; no target writes."
        )
        parser.add_argument("--run-dir", type=Path, required=True)
        parser.add_argument("--control-dir", type=Path, required=True)
        if operation == "init":
            parser.add_argument("--config", type=Path, required=True)
            parser.add_argument("--bundle", type=Path, required=True)
            parser.add_argument("--route-approval", type=Path, required=True)
            parser.add_argument("--source-approvals", type=Path, required=True)
            parser.add_argument("--expected-sigma-organization-ref", required=True)
        if operation in {"init", "complete", "retry", "revoke"}:
            parser.add_argument("--reviewer", required=True)
        if operation == "step":
            parser.add_argument("--allow-model-call", action="store_true")
            parser.add_argument("--api-key-env", default="OPENAI_API_KEY")
        if operation == "attach":
            parser.add_argument("--evidence", type=Path, required=True)
        if operation == "complete":
            parser.add_argument("--package", required=True)
            parser.add_argument("--artifact-ref", action="append", required=True)
        if operation == "retry":
            parser.add_argument("--attempt", type=int, required=True)
        if operation == "revoke":
            parser.add_argument("--reason", required=True,
                                choices=("source_changed", "route_changed", "approval_withdrawn"))


def run_sigma_workflow_command(args):
    # Containment occurs before reading run/configuration files or credential state.
    if args.operation == "sigma-run-step":
        return {"state": "blocked", "reason": EGRESS_DISABLED_REASON,
                "provider_calls": 0, "production_egress_enabled": False}
    if args.operation == "sigma-run-init":
        raw = _read(args.config)
        if not raw.get("context", {}).get("decision"):
            return prompt_for_sigma_semantic_route().model_dump(mode="json")
        config = MigrationRunConfig.model_validate(raw)
        if not isinstance(config.context, SigmaPlanningContext):
            raise ValueError("Sigma workflow requires a Sigma planning context")
        if args.run_dir.exists():
            raise ValueError("Sigma run directory already exists; resume it instead")
        approval = SigmaPlanningApproval.model_validate(_read(args.route_approval))
        if args.reviewer != approval.reviewer or args.reviewer not in config.human_reviewers:
            raise ValueError("the configured route reviewer must initialize the run")
        store = AppendOnlyControlPlaneStore(args.control_dir)
        inputs = register_sigma_planning_context(
            store=store, context=config.context,
            bundle=SigmaCapabilitySpikeBundle.model_validate(_read(args.bundle)),
            route_approval=approval,
            source_approvals=[SigmaPlanningApproval.model_validate(item)
                              for item in _read(args.source_approvals, allow_array=True)],
            human_reviewers=config.human_reviewers,
            expected_sigma_organization_ref=args.expected_sigma_organization_ref,
        )
        imported = {item.ref for item in inputs}
        if imported & {item.ref for item in config.inputs}:
            raise ValueError("config must not replace imported source/route evidence")
        config = config.model_copy(update={"inputs": [*inputs, *config.inputs]})
        runner = MigrationRunner.initialize(args.run_dir, config, control_store=store)
        return {**runner.status(), "planning_only": True, "migration_accepted": False}

    store = AppendOnlyControlPlaneStore(args.control_dir)
    runner = MigrationRunner(args.run_dir, control_store=store)
    config = runner.config()
    if not isinstance(config.context, SigmaPlanningContext):
        raise ValueError("selected runtime is not a Sigma run")
    assert_sigma_route_current(store, config.context)
    if args.operation == "sigma-run-status":
        return {**runner.status(), "planning_only": True, "migration_accepted": False,
                "semantic_mode": config.context.decision.payload.mode}
    if args.operation == "sigma-run-attach":
        runner.attach(EvidenceInput.model_validate(_read(args.evidence)))
        return {"state": "evidence_attached_not_accepted"}
    if args.operation == "sigma-run-complete":
        runner.complete(args.package, reviewer=args.reviewer, artifact_refs=args.artifact_ref)
        return {"state": "planning_package_completed_not_migration_accepted"}
    if args.operation == "sigma-run-retry":
        runner.retry(args.attempt, reviewer=args.reviewer)
        return {"state": "retry_reviewed_budget_reservation_retained"}
    if args.operation == "sigma-run-revoke":
        revoke_sigma_route(store=store, context=config.context, reviewer=args.reviewer,
                           human_reviewers=config.human_reviewers, reason=args.reason)
        return {"state": "route_revoked_dependent_work_blocked"}
    raise ValueError("unsupported Sigma workflow operation")

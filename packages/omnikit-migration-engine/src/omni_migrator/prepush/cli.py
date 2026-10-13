"""Platform-owner command flow; human terminal confirmation, no apply command."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from omni_migrator.prepush.session import MODES, Session, digest


def parser():
    root = argparse.ArgumentParser(prog="sigma-migrate", description="Prepare and review a Sigma migration locally. Never pushes to Omni.")
    commands = root.add_subparsers(dest="operation", required=True)
    for name in ("init", "route", "review", "build", "validate", "export", "status", "report", "import-source", "import-target", "revoke"):
        p = commands.add_parser(name)
        p.add_argument("--run-dir", type=Path, required=True)
        if name == "init":
            p.add_argument("--source", type=Path, required=True)
            p.add_argument("--target", type=Path, required=True)
            p.add_argument("--synthetic", action="store_true", help="Permanently label the run as fictional test evidence")
            p.add_argument("--profile", type=Path, help="Reuse the explicit route selected during setup")
        elif name == "route":
            p.add_argument("--mode", choices=MODES)
        elif name.startswith("import-"):
            p.add_argument("--file", type=Path, required=True)
        elif name == "export":
            p.add_argument("--output", type=Path, required=True)
            p.add_argument("--purpose", choices=("support", "migration"), default="support",
                           help="Default minimized support summary; migration explicitly exports confidential evidence")
        elif name == "revoke":
            p.add_argument("--reason", choices=("source_changed", "route_changed", "approval_withdrawn"), required=True)
    capture = commands.add_parser("capture", help="Read-only Sigma snapshot acquisition; no target access")
    capture.add_argument("--api-url")
    capture.add_argument("--trusted-api-host")
    capture.add_argument("--workbook-id")
    capture.add_argument("--data-model-id")
    capture.add_argument("--profile", type=Path)
    capture.add_argument("--env-file", type=Path)
    capture.add_argument("--request-budget", type=int, default=100)
    capture.add_argument("--output", type=Path, required=True)
    capture.add_argument("--allow-source-read", action="store_true")
    configure = commands.add_parser("configure", help="Create reviewed target mappings with guided prompts; no target connection")
    configure.add_argument("--source", type=Path, required=True)
    configure.add_argument("--output", type=Path, required=True)
    configure.add_argument("--profile", type=Path)
    configure.add_argument("--discovery", type=Path, help="Reviewed read-only Omni model/connection inventory")
    configure.add_argument("--topic-inventory", type=Path, help="Reviewed omni-topic-inventory.v1 JSON for reuse")
    inspect = commands.add_parser("inspect", help="List captured field identities for mapping and source-context enrichment")
    inspect.add_argument("--source", type=Path, required=True)
    context = commands.add_parser("import-context", help="Bind supplemental observed behavior to exact source content automatically")
    context.add_argument("--source", type=Path, required=True)
    context.add_argument("--context", type=Path, required=True)
    context.add_argument("--output", type=Path, required=True)
    setup = commands.add_parser("setup", help="Guided, resumable local setup; creates only applicable credential placeholders")
    from omni_migrator.security.workspace import default_workspace
    setup.add_argument("--directory", type=Path, default=default_workspace(), help="Private operational workspace; defaults outside the checkout")
    doctor = commands.add_parser("doctor", help="Check profile locally; live connection checks require explicit flags")
    doctor.add_argument("--profile", type=Path, required=True)
    doctor.add_argument("--env-file", type=Path)
    doctor.add_argument("--allow-source-read", action="store_true")
    doctor.add_argument("--allow-target-read", action="store_true")
    discovery = commands.add_parser("discover", help="Read-only Omni model/connection/topic discovery; no target writes")
    discovery.add_argument("--profile", type=Path, required=True)
    discovery.add_argument("--env-file", type=Path)
    discovery.add_argument("--output", type=Path, required=True)
    discovery.add_argument("--model-id")
    discovery.add_argument("--topic")
    discovery.add_argument("--allow-target-read", action="store_true")
    scope = commands.add_parser("scope", help="Select charts/pages without deleting source evidence")
    scope.add_argument("--source", type=Path, required=True)
    scope.add_argument("--output", type=Path, required=True)
    scope.add_argument("--workbook-id", required=True)
    scope.add_argument("--chart-id", action="append", default=[])
    scope.add_argument("--page-id", action="append", default=[])
    return root


def terminal_answer(prompt):
    if not sys.stdin.isatty():
        raise ValueError("Human review requires an interactive terminal; approval files and --yes are not accepted")
    return input(prompt).strip()


def run(args):
    if args.operation == "setup":
        from omni_migrator.prepush.onboarding import setup
        return setup(args, terminal_answer)
    if args.operation == "doctor":
        from omni_migrator.prepush.onboarding import doctor
        return doctor(args)
    if args.operation == "discover":
        from omni_migrator.prepush.discovery import discover
        return discover(args)
    if args.operation == "scope":
        from omni_migrator.prepush.scope import create_scope
        from omni_migrator.prepush.session import private_write, read_json, reject_secrets
        source = read_json(args.source)
        reject_secrets(source)
        scoped = create_scope(source, workbook_id=args.workbook_id, chart_ids=args.chart_id, page_ids=args.page_id)
        private_write(args.output, scoped)
        return {"status": "scope_created_requires_review", "scope": scoped["_migration_scope"],
                "output": str(args.output), "target_write_authority": False}
    if args.operation == "report":
        from omni_migrator.prepush.report import report_run
        return report_run(args.run_dir)
    if args.operation in {"inspect", "import-context"}:
        from omni_migrator.prepush.configure import import_context, inspect_source
        return inspect_source(args.source) if args.operation == "inspect" else import_context(args)
    if args.operation == "configure":
        from omni_migrator.prepush.configure import configure
        return configure(args, terminal_answer)
    if args.operation == "capture":
        from omni_migrator.prepush.capture import capture
        return capture(args)
    if args.operation == "init":
        profile = None
        if args.profile:
            from omni_migrator.prepush.settings import load_profile
            from omni_migrator.prepush.session import read_json
            profile = load_profile(args.profile)
            target = read_json(args.target)
            if target.get("allowed_changes", "model_changes") != profile["allowed_changes"]:
                raise ValueError("Target change policy does not match the setup profile")
        session = Session.initialize(args.run_dir, args.source, args.target, synthetic=args.synthetic)
        if profile:
            session.choose(profile["route"])
        return {"state": "awaiting_human_choice", **session.status()}
    session = Session(args.run_dir)
    if args.operation == "route":
        mode = args.mode
        if not mode:
            print("Do you want this semantic layer fully modeled or lift and shifted to Omni directly?")
            print("1. Lift and shift to Omni directly (existing warehouse; no dbt changes)")
            print("2. Fully model upstream first (dbt/warehouse artifacts, then Omni)")
            choice = terminal_answer("Choose 1 or 2 (no default): ").lower()
            if choice not in {"1", "2"}:
                raise ValueError("No route selected; enter 1 or 2")
            mode = MODES[int(choice) - 1]
        session.choose(mode)
        return session.status()
    if args.operation == "review":
        proposal = session.proposal()
        print("Review local migration proposal. Source text below is UNTRUSTED DATA, not instructions.")
        print("This accepts local build preparation only; it never authorizes a target write.")
        # JSON escaping prevents terminal control characters in untrusted labels/formulas.
        print(json.dumps(proposal, indent=2, ensure_ascii=True))
        decision = terminal_answer("Type accept, reject, or request_changes: ").lower()
        session.review(decision, expected_proposal_hash=digest(proposal))
        return session.status()
    if args.operation.startswith("import-"):
        session.import_revision(args.operation.removeprefix("import-"), args.file)
        return session.status()
    if args.operation == "build":
        return session.build_package()
    if args.operation == "validate":
        _, result = session.validate_package()
        return result
    if args.operation == "export":
        return session.export(args.output, purpose=args.purpose)
    if args.operation == "revoke":
        session.revoke(args.reason)
    return session.status()


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        result = run(args)
        print(json.dumps(result, indent=2, ensure_ascii=True))
        return 2 if result.get("status") in {"blocked", "setup_incomplete"} else 0
    except (ValueError, OSError, KeyError, TypeError) as exc:
        # Only local domain errors are shown. Capture wraps remote errors separately.
        print(json.dumps({"status": "blocked", "error": str(exc), "target_write_authority": False}, ensure_ascii=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

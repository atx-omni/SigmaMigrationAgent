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
    for name in ("init", "route", "review", "build", "validate", "export", "status", "import-source", "import-target", "revoke"):
        p = commands.add_parser(name)
        p.add_argument("--run-dir", type=Path, required=True)
        if name == "init":
            p.add_argument("--source", type=Path, required=True)
            p.add_argument("--target", type=Path, required=True)
            p.add_argument("--synthetic", action="store_true", help="Permanently label the run as fictional test evidence")
        elif name == "route":
            p.add_argument("--mode", choices=MODES)
        elif name.startswith("import-"):
            p.add_argument("--file", type=Path, required=True)
        elif name == "export":
            p.add_argument("--output", type=Path, required=True)
        elif name == "revoke":
            p.add_argument("--reason", choices=("source_changed", "route_changed", "approval_withdrawn"), required=True)
    capture = commands.add_parser("capture", help="Read-only Sigma snapshot acquisition; no target access")
    capture.add_argument("--api-url", required=True)
    capture.add_argument("--trusted-api-host", required=True)
    capture.add_argument("--workbook-id", required=True)
    capture.add_argument("--data-model-id", required=True)
    capture.add_argument("--output", type=Path, required=True)
    capture.add_argument("--allow-source-read", action="store_true")
    configure = commands.add_parser("configure", help="Create reviewed target mappings with guided prompts; no target connection")
    configure.add_argument("--source", type=Path, required=True)
    configure.add_argument("--output", type=Path, required=True)
    inspect = commands.add_parser("inspect", help="List captured field identities for mapping and source-context enrichment")
    inspect.add_argument("--source", type=Path, required=True)
    context = commands.add_parser("import-context", help="Bind supplemental observed behavior to exact source content automatically")
    context.add_argument("--source", type=Path, required=True)
    context.add_argument("--context", type=Path, required=True)
    context.add_argument("--output", type=Path, required=True)
    return root


def terminal_answer(prompt):
    if not sys.stdin.isatty():
        raise ValueError("Human review requires an interactive terminal; approval files and --yes are not accepted")
    return input(prompt).strip()


def run(args):
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
        session = Session.initialize(args.run_dir, args.source, args.target, synthetic=args.synthetic)
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
        return session.export(args.output)
    if args.operation == "revoke":
        session.revoke(args.reason)
    return session.status()


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        result = run(args)
        print(json.dumps(result, indent=2, ensure_ascii=True))
        return 2 if result.get("status") == "blocked" else 0
    except (ValueError, OSError, KeyError, TypeError) as exc:
        # Only local domain errors are shown. Capture wraps remote errors separately.
        print(json.dumps({"status": "blocked", "error": str(exc), "target_write_authority": False}, ensure_ascii=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

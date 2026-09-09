"""Migration-team fictional offline orientation; never a migration or approval workflow.

Install the engine and its dependencies using SETUP-AND-USAGE.md first. The adjacent
engine/src and repository fallbacks locate code only; they do not bypass installation.
"""

from __future__ import annotations

import argparse
from contextlib import redirect_stdout
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile

# Reading the example and checking installation must not create import-cache files.
sys.dont_write_bytecode = True

STARTER_ROOT = Path(__file__).resolve().parent
SNAPSHOT_NAME = "fictional-sigma-snapshot.json"
SNAPSHOT_SHA256 = "de3de0f91367ef363eadae306b725f7493964b618de9ccb0d5bdd83ce0df1ffb"
ROUTES = {
    "modeled": ("warehouse_first_refactor", "Fully modeled before Omni"),
    "direct": ("omni_semantic_reconstruction", "Direct reconstruction in Omni"),
}


class StarterError(Exception):
    """An intentionally safe, customer-facing message."""


class FriendlyParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        # argparse's original message can echo arbitrary (possibly sensitive) input.
        raise StarterError(
            "Those options aren't supported. Use --help for examples. "
            "Please don't enter credentials or customer information here."
        )


def _engine_prompt() -> dict:
    if os.name != "posix":
        raise StarterError(
            "Native Windows is not supported. Run this package in WSL2 with Python 3.12; "
            "follow SETUP-AND-USAGE.md."
        )
    if sys.version_info < (3, 11):
        raise StarterError(
            "This Python version is too old. Use Python 3.12 on macOS, Linux, or WSL2 "
            "and create the virtual environment described in SETUP-AND-USAGE.md."
        )
    packaged_source = STARTER_ROOT / "engine" / "src"
    if (packaged_source / "omni_migrator" / "__init__.py").is_file():
        # Prefer this exact distribution over a stale engine installed elsewhere.
        sys.path.insert(0, str(packaged_source))
    elif importlib.util.find_spec("omni_migrator") is None:
        candidates = [
            STARTER_ROOT / "engine" / "src",
            STARTER_ROOT.parent.parent / "packages" / "omnikit-migration-engine" / "src",
        ]
        for candidate in candidates:
            if (candidate / "omni_migrator" / "__init__.py").is_file():
                sys.path.insert(0, str(candidate))
                break
    try:
        # Invoke the real CLI prompt, including its actual shared/Sigma CLI imports.
        # No request is provided: the engine cannot create a routing decision here.
        from omni_migrator.runtime import main as engine_main

        output = io.StringIO()
        with redirect_stdout(output):
            status = engine_main(["sigma-semantic-route"])
        prompt = json.loads(output.getvalue())
        modes = {option["mode"] for option in prompt["options"]}
        if (
            status != 2
            or prompt["state"] != "awaiting_human_choice"
            or prompt["default_mode"] is not None
            or modes != {route[0] for route in ROUTES.values()}
        ):
            raise ValueError("unexpected prompt contract")
        return prompt
    except Exception as error:
        raise StarterError(
            "The Sigma engine could not complete its readiness check. Use the Python 3.12 "
            "virtual environment on macOS, Linux, or WSL2, install this package's engine "
            "dependencies, and rerun .venv/bin/python start.py --check. "
            "See SETUP-AND-USAGE.md for the setup and troubleshooting steps."
        ) from error


def _snapshot_path() -> Path:
    path = STARTER_ROOT / "examples" / SNAPSHOT_NAME
    # This starter only accepts the bundled fictional example, not arbitrary uploads.
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 32_768:
        raise StarterError(
            "The fictional example is missing or changed. Extract a fresh copy of the "
            "package, keeping the bundled example unchanged. See SETUP-AND-USAGE.md."
        )
    if hashlib.sha256(path.read_bytes()).hexdigest() != SNAPSHOT_SHA256:
        raise StarterError(
            "The fictional example is missing or changed. Extract a fresh copy of the "
            "package, keeping the bundled example unchanged. See SETUP-AND-USAGE.md."
        )
    return path


def _choose_route(prompt: dict) -> str:
    print("\nDo you want the semantic layer fully modeled, or moved directly into Omni?")
    for number, key in enumerate(("modeled", "direct"), start=1):
        mode, label = ROUTES[key]
        description = next(option["description"] for option in prompt["options"] if option["mode"] == mode)
        print(f"\n{number}. {label}\n   {description}")
    print(f"\n{prompt['shared_guardrail']}")
    print("\nThere is no default. This is only a demo preference, not an approval.")
    while True:
        answer = input("Choose 1 or 2 (or q to leave): ").strip().casefold()
        if answer in {"1", "2"}:
            return "modeled" if answer == "1" else "direct"
        if answer == "q":
            raise EOFError
        print("Please choose 1 or 2, or q to leave. Nothing has been selected.")


def _write_new(path: Path, content: str) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(content)
        handle.write("\n")


def _run_demo(route: str, prompt: dict, snapshot: Path) -> Path:
    from omni_migrator.core.contracts import ExtractCtx, FileInput
    from omni_migrator.extractors.sigma.extractor import SigmaExtractor

    # The built-in manual extractor reads one file. No API client, provider, plugin
    # dispatch, target emitter, approval registry, or governed workflow is invoked.
    bundle = SigmaExtractor().extract(FileInput(paths=[snapshot]), ExtractCtx())
    counts = {
        "source_tables": len(bundle.model.views),
        "source_fields": sum(len(view.fields) for view in bundle.model.views),
        "dashboard_definitions": len(bundle.dashboards),
    }
    summary = {
        "demo_only": True,
        "fictional_source_only": True,
        "scope": "Offline source-extraction and routing orientation; not a migration.",
        "route_preference": ROUTES[route][0],
        "route_label": ROUTES[route][1],
        "route_preference_is_approval": False,
        "routing_decision_created": False,
        "approval_created": False,
        "target_write_authority": False,
        "migration_completed": False,
        "ai_used": False,
        "live_evidence_collected": False,
        "source_file": f"examples/{SNAPSHOT_NAME}",
        "source_sha256": SNAPSHOT_SHA256,
        "extracted_counts": counts,
    }
    results = (
        "YOUR OFFLINE DEMO RESULTS\n\n"
        "This is a purely fictional source-extraction example, not a migration.\n"
        f"The engine read examples/{SNAPSHOT_NAME}: metadata only, no customer records.\n"
        f"It extracted {counts['source_tables']} source table(s), "
        f"{counts['source_fields']} source field(s), and "
        f"{counts['dashboard_definitions']} dashboard definition(s).\n"
        "These counts describe this tiny example, not live source completeness.\n\n"
        f"Your demo preference: {ROUTES[route][1]}.\n"
        "Fully modeled means reviewing approved data-layer changes before Omni.\n"
        "Direct means reconstructing in Omni over accepted existing warehouse relations.\n"
        "Your preference is not an approval or a governed routing decision.\n"
        "The source extraction is the same for both choices; neither target path ran.\n\n"
        "No AI, credentials, network, live source evidence, approvals, or target writes were used.\n"
        "No Omni content was created. No parity, acceptance, or migration was completed.\n\n"
        "Files in this folder:\n"
        "- routing-prompt.json: the engine's real two-choice prompt, still awaiting a choice.\n"
        "- source-extraction.json: the real manual extractor's source-only representation.\n"
        "- demo-summary.json: counts and a nonbinding demo preference, not an approval.\n\n"
        "NEXT STEP\n"
        "Open SETUP-AND-USAGE.md in the package root and complete the planning worksheet.\n"
        "Review your actual source scope, evidence, and route choice before configuring\n"
        "a separately approved, governed workflow. The guide describes the required\n"
        "inputs and commands. Do not use these fictional files as customer evidence.\n"
        "No credentials belong in this starter.\n"
    )
    # Always create a fresh private sibling folder; never overwrite an earlier run.
    output = Path(tempfile.mkdtemp(prefix="demo-output-", dir=STARTER_ROOT))
    _write_new(output / "routing-prompt.json", json.dumps(prompt, indent=2))
    _write_new(output / "source-extraction.json", bundle.model_dump_json(indent=2))
    _write_new(output / "demo-summary.json", json.dumps(summary, indent=2))
    _write_new(output / "READ-MY-RESULTS.txt", results)
    return output


def main(argv: list[str] | None = None) -> int:
    parser = FriendlyParser(
        description="Explore a fictional Sigma example offline. No accounts or credentials needed.",
        epilog=(
            "Follow SETUP-AND-USAGE.md to install with Python 3.12 on macOS, Linux, or WSL2. "
            "Then run .venv/bin/python start.py for the walkthrough. "
            "For an unattended example: .venv/bin/python start.py --demo --route direct"
        ),
    )
    actions = parser.add_mutually_exclusive_group()
    actions.add_argument("--check", action="store_true", help="Check readiness without creating files.")
    actions.add_argument("--demo", action="store_true", help="Run an unattended fictional example.")
    parser.add_argument("--route", choices=ROUTES, help="Use direct or modeled with --demo; no default.")
    try:
        args = parser.parse_args(argv)
        if args.demo != (args.route is not None):
            raise StarterError("For an unattended example, use --demo --route direct or --demo --route modeled.")
        prompt = _engine_prompt()
        snapshot = _snapshot_path()
        if args.check:
            print("Ready for the fictional offline walkthrough. No files or systems were changed.")
            print("This checks local readiness only, not live Sigma/Omni access or migration readiness.")
            return 0
        print("SIGMA TO OMNI — OFFLINE ORIENTATION")
        print("Only a bundled fictional example is read. No AI, accounts, approvals, or target changes.")
        route = args.route or _choose_route(prompt)
        output = _run_demo(route, prompt, snapshot)
        print(f"\nYour fictional source-only example is ready. Preference: {ROUTES[route][1]}.")
        print(f"Open your results note: {output / 'READ-MY-RESULTS.txt'}")
        print("Nothing was migrated or approved. Open SETUP-AND-USAGE.md for your next steps.")
        return 0
    except (KeyboardInterrupt, EOFError):
        print("\nStopped. No route was approved and no systems were changed.")
        return 2
    except StarterError as error:
        print(str(error), file=sys.stderr)
        return 1
    except Exception:
        print(
            "The offline example stopped safely. No connected systems were changed. "
            "Check that you're using the package's Python 3.12 virtual environment and "
            "can create files in the extracted package folder. See SETUP-AND-USAGE.md. "
            "If a demo-output folder was created, its files may be incomplete.",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

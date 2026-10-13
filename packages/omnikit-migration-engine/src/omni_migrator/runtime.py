"""Safe process boundary for source extraction and supervised development migration."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from urllib.parse import urlsplit

from omni_migrator.bridge import bridge_capabilities, parse_and_execute_bridge_extract
from omni_migrator.conformance import CONFORMANCE_SOURCES, run_conformance
from omni_migrator.core.process_limits import apply_bridge_process_limits
from omni_migrator.extractors.sigma.api import SigmaApi
from omni_migrator.extractors.sigma.capability_contracts import (
    SigmaCapabilitySpikeRequest,
    SigmaSemanticRoutingArtifact,
)
from omni_migrator.extractors.sigma.capability_spike import run_sigma_capability_spike
from omni_migrator.extractors.sigma.semantic_routing import advance_sigma_semantic_routing


def _compact_json(value: object) -> str:
    return json.dumps(value, separators=(",", ":"))


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="omnikit-migration-engine",
        description="Governed extraction, supervised proposals, and development migration.",
    )
    commands = parser.add_subparsers(dest="operation", required=True)
    commands.add_parser("capabilities", help="Print supported read-only operations.")

    conformance = commands.add_parser(
        "conformance",
        help="Run deterministic, credential-free source conformance contracts.",
    )
    conformance.add_argument("--source", choices=CONFORMANCE_SOURCES)

    extract = commands.add_parser("extract", help="Run one bounded source extraction.")
    extract.add_argument(
        "--request",
        type=Path,
        help="Read the JSON request from a file instead of stdin.",
    )

    sigma_spike = commands.add_parser(
        "sigma-capability-spike",
        help="Run one fail-closed, read-only Sigma Phase-0 capability spike.",
    )
    sigma_spike.add_argument("--request", type=Path, required=True)
    sigma_spike.add_argument("--client-id-env", default="SIGMA_CLIENT_ID")
    sigma_spike.add_argument("--client-secret-env", default="SIGMA_CLIENT_SECRET")
    sigma_spike.add_argument(
        "--trusted-api-host",
        action="append",
        default=[],
        help=(
            "Operator-controlled exact Sigma API host allowlist. Repeat for multiple approved "
            "regional hosts; at least one value is required."
        ),
    )
    sigma_spike.add_argument(
        "--output",
        type=Path,
        help="Create a new mode-0600 bundle file; existing files are never overwritten.",
    )

    sigma_route = commands.add_parser(
        "sigma-semantic-route",
        help="Ask for or record the required Sigma semantic target-architecture choice.",
    )
    sigma_route.add_argument(
        "--request",
        type=Path,
        help="Validated decision request; omit it to emit the required two-option prompt.",
    )
    sigma_route.add_argument(
        "--output",
        type=Path,
        help="Create a new mode-0600 decision artifact; existing files are never overwritten.",
    )
    from omni_migrator.orchestration.sigma_cli import add_sigma_workflow_commands

    add_sigma_workflow_commands(commands)
    return parser


def _run_extract(request_path: Path | None) -> int:
    try:
        apply_bridge_process_limits()
        payload = request_path.read_text() if request_path else sys.stdin.read()
        sys.stdout.write(parse_and_execute_bridge_extract(payload))
        sys.stdout.write("\n")
        return 0
    except Exception:  # noqa: BLE001 - validation errors can contain credential-bearing input
        sys.stdout.write(
            _compact_json(
                {
                    "schema_version": "omnikit.migration.bundle.v1",
                    "error": {
                        "code": "bridge_extract_failed",
                        "message": "Source extraction failed safely; check request structure and access. Sensitive details were not emitted.",
                        "retryable": False,
                    },
                }
            )
        )
        sys.stdout.write("\n")
        return 1


def _write_new_private_file(path: Path, value: str) -> None:
    from omni_migrator.security.scanner import assert_safe_bytes
    from omni_migrator.security.workspace import assert_private_output
    assert_safe_bytes((value + "\n").encode(), filename=path.name)
    assert_private_output(path)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(value)
        handle.write("\n")


def _run_sigma_semantic_route(request_path: Path | None, output_path: Path | None) -> int:
    if output_path is not None and output_path.exists():
        raise FileExistsError("Sigma semantic routing output already exists")
    payload = json.loads(request_path.read_text()) if request_path is not None else None
    result = advance_sigma_semantic_routing(payload)
    serialized = result.model_dump_json(indent=2)
    if not isinstance(result, SigmaSemanticRoutingArtifact):
        sys.stdout.write(serialized)
        sys.stdout.write("\n")
        return 2
    if output_path is None:
        sys.stdout.write(serialized)
        sys.stdout.write("\n")
    else:
        _write_new_private_file(output_path, serialized)
        sys.stdout.write(
            _compact_json(
                {
                    "schema_version": "sigma-semantic-routing-cli-result.v1",
                    "status": "decision_recorded_target_design_still_gated",
                    "output": str(output_path),
                }
            )
        )
        sys.stdout.write("\n")
    return 0


def _run_sigma_capability_spike(
    request_path: Path,
    *,
    client_id_env: str,
    client_secret_env: str,
    trusted_api_hosts: tuple[str, ...],
    output_path: Path | None,
) -> int:
    environment_name = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
    if not environment_name.fullmatch(client_id_env) or not environment_name.fullmatch(
        client_secret_env
    ):
        raise ValueError("credential environment names are invalid")
    if output_path is not None and output_path.exists():
        raise FileExistsError("Sigma capability output already exists")
    from omni_migrator.security.workspace import assert_private_output
    if output_path is not None:
        assert_private_output(output_path)
    request = SigmaCapabilitySpikeRequest.model_validate_json(request_path.read_text())
    if request.evidence_mode != "live_tenant":
        raise ValueError("the live CLI accepts evidence_mode=live_tenant only")
    normalized_trusted_hosts = {value.strip().lower() for value in trusted_api_hosts}
    if not normalized_trusted_hosts or any(
        not re.fullmatch(r"[a-z0-9.-]{1,253}", value)
        or value.startswith(".")
        or value.endswith(".")
        or ".." in value
        for value in normalized_trusted_hosts
    ):
        raise ValueError("trusted Sigma API hosts are missing or invalid")
    parsed_request_url = urlsplit(request.api_base_url)
    request_host = parsed_request_url.hostname
    if parsed_request_url.port not in (None, 443):
        raise ValueError("request Sigma API origin uses an untrusted port")
    if request_host is None or request_host.lower() not in normalized_trusted_hosts:
        raise ValueError("request Sigma API host is not in the operator-controlled allowlist")

    # Resolve credentials only after the request host has passed the independent trust boundary.
    client_id = os.environ.get(client_id_env)
    client_secret = os.environ.get(client_secret_env)
    if not client_id or not client_secret:
        raise ValueError("Sigma credential environment variables are not both configured")

    api = SigmaApi(
        base_url=request.api_base_url,
        client_id=client_id,
        client_secret=client_secret,
        request_budget=request.request_budget,
        per_endpoint_request_budget=request.per_endpoint_request_budget,
    )
    try:
        result = run_sigma_capability_spike(request, api=api)
    finally:
        api.close()
    serialized = result.model_dump_json(indent=2)
    from omni_migrator.security.scanner import assert_safe_bytes
    assert_safe_bytes(serialized.encode(), filename="capability-result.json")
    if output_path is None:
        sys.stdout.write(serialized)
        sys.stdout.write("\n")
    else:
        _write_new_private_file(output_path, serialized)
        sys.stdout.write(
            _compact_json(
                {
                    "schema_version": "sigma-capability-spike-cli-result.v1",
                    "status": result.status,
                    "output": str(output_path),
                }
            )
        )
        sys.stdout.write("\n")
    return 0 if result.status == "ready_for_human_review" else 2


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.operation.startswith("sigma-run-"):
        try:
            from omni_migrator.orchestration.sigma_cli import run_sigma_workflow_command

            result = run_sigma_workflow_command(args)
            sys.stdout.write(_compact_json(result) + "\n")
            return 2 if result.get("state") in {"blocked", "failed", "awaiting_human_choice"} else 0
        except Exception:  # noqa: BLE001 - approval/source/model details must not leak
            sys.stdout.write(_compact_json({
                "state": "failed", "error_code": "sigma_workflow_failed_safely",
                "message": "Sigma planning stopped safely; check current approvals, inputs and operator configuration.",
                "target_write_authority": False,
            }) + "\n")
            return 1
    if args.operation.startswith("domo-"):
        try:
            from omni_migrator.orchestration.cli import run_domo_command

            result = run_domo_command(args)
            sys.stdout.write(_compact_json(result) + "\n")
            return 2 if result.get("state") in {"blocked", "failed"} else 0
        except Exception:  # noqa: BLE001 - never echo source payloads or provider credentials
            sys.stdout.write(
                _compact_json(
                    {
                        "state": "failed",
                        "error_code": "domo_operation_failed_safely",
                        "message": "Domo operation failed safely; check scoped inputs and operator configuration. No sensitive details were emitted.",
                    }
                )
                + "\n"
            )
            return 1
    if args.operation == "capabilities":
        sys.stdout.write(_compact_json(bridge_capabilities()))
        sys.stdout.write("\n")
        return 0
    if args.operation == "conformance":
        result = run_conformance(args.source)
        sys.stdout.write(_compact_json(result))
        sys.stdout.write("\n")
        return 0 if result["passed"] else 1
    if args.operation == "extract":
        return _run_extract(args.request)
    if args.operation == "sigma-capability-spike":
        try:
            apply_bridge_process_limits()
            return _run_sigma_capability_spike(
                args.request,
                client_id_env=args.client_id_env,
                client_secret_env=args.client_secret_env,
                trusted_api_hosts=tuple(args.trusted_api_host),
                output_path=args.output,
            )
        except Exception:  # noqa: BLE001 - emit no exception details at the process boundary
            sys.stdout.write(
                _compact_json(
                    {
                        "schema_version": "sigma-capability-spike-cli-result.v1",
                        "status": "failed",
                        "error": {
                            "code": "sigma_capability_spike_failed",
                            "message": "Sigma capability spike failed safely; sensitive details were not emitted.",
                            "retryable": False,
                        },
                    }
                )
            )
            sys.stdout.write("\n")
            return 1
    if args.operation == "sigma-semantic-route":
        try:
            apply_bridge_process_limits()
            return _run_sigma_semantic_route(args.request, args.output)
        except Exception:  # noqa: BLE001 - emit no decision contents at process boundary
            sys.stdout.write(
                _compact_json(
                    {
                        "schema_version": "sigma-semantic-routing-cli-result.v1",
                        "status": "failed",
                        "error": {
                            "code": "sigma_semantic_routing_failed",
                            "message": "Sigma semantic routing failed safely; decision details were not emitted.",
                            "retryable": False,
                        },
                    }
                )
            )
            sys.stdout.write("\n")
            return 1
    raise AssertionError(f"unsupported operation: {args.operation}")


if __name__ == "__main__":
    raise SystemExit(main())

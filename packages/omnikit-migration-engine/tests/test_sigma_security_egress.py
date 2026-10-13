"""Production egress containment plus inert, scanned transfer preparation."""
from datetime import datetime, timedelta, timezone
import hashlib
import json
from types import SimpleNamespace

import pytest

from omni_migrator.orchestration.egress import prepare_egress
from omni_migrator.orchestration.provider import FixtureProposalProvider, OpenAIProposalProvider
from omni_migrator.orchestration.runner import MigrationRunner
from omni_migrator.orchestration.sigma_cli import run_sigma_workflow_command
from omni_migrator.security.scanner import SecurityScanError


def arguments():
    issued = datetime(2026, 10, 12, tzinfo=timezone.utc)
    return dict(tenant_ref="tenant-ref://synthetic", run_id="fixture-run", purpose="review-summary",
                account_ref="account-ref://approved-account", project_ref="project-ref://pilot",
                model="operator-configured-model", instructions="Review summarized schema only.",
                sanitized_evidence={"evidence-ref://summary": {"field_count": 2}},
                original_evidence_sha256={"evidence-ref://summary": "a" * 64},
                issued_at=issued, expires_at=issued + timedelta(hours=1))


def test_production_provider_refuses_before_credential_or_transport_use():
    class Unreadable:
        def strip(self):
            pytest.fail("disabled provider must not examine credentials")
    with pytest.raises(RuntimeError, match="externally authenticated"):
        OpenAIProposalProvider(model="model", api_key=Unreadable(), transport=Unreadable())
    # Even bypassing __init__ cannot recover a HTTP request method.
    with pytest.raises(RuntimeError, match="disabled"):
        object.__new__(OpenAIProposalProvider).propose(
            instructions="", context="", max_output_tokens=1000)


def test_cli_refuses_even_missing_run_and_allow_flag_before_any_inputs():
    args = SimpleNamespace(operation="sigma-run-step", allow_model_call=True)
    result = run_sigma_workflow_command(args)
    assert result["state"] == "blocked" and result["provider_calls"] == 0


@pytest.mark.parametrize("approval", ["forged", "expired", "revoked", "wrong-provider", "changed-payload"])
def test_runner_does_not_invoke_arbitrary_provider_for_any_local_approval(approval):
    class NetworkProvider:
        def propose(self, **kwargs):
            pytest.fail("production provider was invoked")
    runner = object.__new__(MigrationRunner)
    runner.model_egress_approval_ref = approval
    result = runner.propose_next(NetworkProvider(), allow_model_calls=True)
    assert result["provider_calls"] == 0 and result["production_egress_enabled"] is False


def test_offline_fixture_is_not_extensible_to_network_provider():
    with pytest.raises(TypeError, match="cannot be extended"):
        class NetworkProvider(FixtureProposalProvider):
            pass


def test_prepared_payload_is_exact_scanned_hash_bound_and_never_approval():
    result = prepare_egress(**arguments())
    assert result == prepare_egress(**arguments())
    manifest = json.loads(result.manifest)
    assert manifest["payload_sha256"] == hashlib.sha256(result.payload).hexdigest()
    assert manifest["authorization_granted"] is False
    assert manifest["production_egress_enabled"] is False
    assert manifest["retention_verified"] is False
    assert manifest["sanitized_evidence_sha256"] != manifest["original_evidence_sha256"]
    altered = arguments() | {"model": "different-model"}
    assert prepare_egress(**altered).manifest != result.manifest


@pytest.mark.parametrize("location", ["instructions", "evidence", "purpose"])
def test_scanner_checks_entire_payload_and_manifest(location):
    args = arguments()
    value = "ghp_" + "A1b2" * 9
    if location == "evidence":
        args["sanitized_evidence"] = {"evidence-ref://summary": {"note": value}}
    else:
        args[location] = value
    with pytest.raises(SecurityScanError):
        prepare_egress(**args)


def test_expiry_and_evidence_mismatch_block_preparation():
    args = arguments()
    with pytest.raises(ValueError, match="expiry"):
        prepare_egress(**(args | {"expires_at": args["issued_at"] + timedelta(days=3)}))
    with pytest.raises(ValueError, match="exact original"):
        prepare_egress(**(args | {"original_evidence_sha256": {"other": "a" * 64}}))

"""Process-boundary safety tests for Sigma capability and semantic-routing CLIs."""

from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest
from pydantic import ValidationError

from omni_migrator.extractors.sigma.capability_contracts import SigmaCapabilitySpikeRequest
from omni_migrator.runtime import _write_new_private_file, main


ROOT = Path(__file__).resolve().parents[3]
EXAMPLE_REQUEST = (
    ROOT / "contracts" / "sigma" / "examples" / "sigma-capability-spike-request.v1.example.json"
)
EXAMPLE_ROUTE_REQUEST = (
    ROOT
    / "contracts"
    / "sigma"
    / "examples"
    / "sigma-semantic-routing-decision-request.v1.omni-reconstruction.example.json"
)


def _request() -> dict:
    return json.loads(EXAMPLE_REQUEST.read_text())


@pytest.mark.parametrize(
    "unsafe",
    ("..", "../../members", "segment/child", "segment?admin=true", "segment#fragment", "%2e%2e"),
)
@pytest.mark.parametrize("field", ("workbook_id", "data_model_id"))
def test_request_rejects_unsafe_object_ids(field, unsafe):
    request = _request()
    request[field] = unsafe

    with pytest.raises(ValidationError, match="safe opaque Sigma object ID"):
        SigmaCapabilitySpikeRequest.model_validate(request)


@pytest.mark.parametrize(
    "unsafe",
    ("..", "../../members", "segment/child", "segment?admin=true", "segment#fragment", "%2e%2e"),
)
def test_request_rejects_unsafe_tag_path_segment(unsafe):
    request = _request()
    request["source_freeze"]["workbook_tag_name"] = unsafe

    with pytest.raises(ValidationError, match="encoded Sigma URL path segment"):
        SigmaCapabilitySpikeRequest.model_validate(request)


def test_cli_never_echoes_rejected_raw_credential(tmp_path, capsys):
    raw_secret = "raw-client-secret-must-never-appear"
    request = _request()
    request["credential_ref"] = raw_secret
    request_path = tmp_path / "unsafe-request.json"
    request_path.write_text(json.dumps(request))

    exit_code = main(["sigma-capability-spike", "--request", str(request_path)])
    captured = capsys.readouterr()
    response = json.loads(captured.out)

    assert exit_code == 1
    assert response == {
        "schema_version": "sigma-capability-spike-cli-result.v1",
        "status": "failed",
        "error": {
            "code": "sigma_capability_spike_failed",
            "message": "Sigma capability spike failed safely; sensitive details were not emitted.",
            "retryable": False,
        },
    }
    assert raw_secret not in captured.out
    assert raw_secret not in captured.err


def test_cli_rejects_self_declared_untrusted_host_before_transport(tmp_path, capsys, monkeypatch):
    request = _request()
    request["api_base_url"] = "https://attacker.example"
    request["approved_api_hosts"] = ["attacker.example"]
    request_path = tmp_path / "self-approved-host.json"
    request_path.write_text(json.dumps(request))
    monkeypatch.setenv("SIGMA_CLIENT_ID", "client-id-must-not-be-sent")
    monkeypatch.setenv("SIGMA_CLIENT_SECRET", "secret-must-not-be-sent")
    transport_constructed = False

    def fail_if_constructed(**kwargs):
        nonlocal transport_constructed
        transport_constructed = True
        raise AssertionError("transport must not be constructed for an untrusted host")

    monkeypatch.setattr("omni_migrator.runtime.SigmaApi", fail_if_constructed)

    exit_code = main(
        [
            "sigma-capability-spike",
            "--request",
            str(request_path),
            "--trusted-api-host",
            "api.example.invalid",
        ]
    )

    assert exit_code == 1
    assert transport_constructed is False
    assert json.loads(capsys.readouterr().out)["status"] == "failed"


def test_bundle_output_is_owner_only_and_never_overwritten(tmp_path):
    output = tmp_path / "bundle.json"

    _write_new_private_file(output, '{"status":"first"}')

    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    assert output.read_text() == '{"status":"first"}\n'
    with pytest.raises(FileExistsError):
        _write_new_private_file(output, '{"status":"replacement"}')
    assert output.read_text() == '{"status":"first"}\n'


def test_semantic_route_cli_prompts_without_default_and_blocks_only_target_design(capsys):
    exit_code = main(["sigma-semantic-route"])
    prompt = json.loads(capsys.readouterr().out)

    assert exit_code == 2
    assert prompt["state"] == "awaiting_human_choice"
    assert prompt["default_mode"] is None
    assert prompt["blocks_target_design"] is True
    assert prompt["blocks_source_evidence_acquisition"] is False
    assert [item["mode"] for item in prompt["options"]] == [
        "warehouse_first_refactor",
        "omni_semantic_reconstruction",
    ]


def test_semantic_route_cli_records_a_private_create_only_decision(tmp_path, capsys):
    output = tmp_path / "semantic-route.json"

    exit_code = main(
        [
            "sigma-semantic-route",
            "--request",
            str(EXAMPLE_ROUTE_REQUEST),
            "--output",
            str(output),
        ]
    )
    response = json.loads(capsys.readouterr().out)
    decision = json.loads(output.read_text())

    assert exit_code == 0
    assert response["status"] == "decision_recorded_target_design_still_gated"
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    assert decision["payload"]["mode"] == "omni_semantic_reconstruction"
    assert decision["payload"]["target_write_authority"] is False


def test_existing_output_is_rejected_before_credentials_or_transport(tmp_path, capsys, monkeypatch):
    request_path = tmp_path / "request.json"
    request_path.write_text(json.dumps(_request()))
    output = tmp_path / "existing-bundle.json"
    output.write_text("preserve me")
    transport_constructed = False

    def fail_if_constructed(**kwargs):
        nonlocal transport_constructed
        transport_constructed = True
        raise AssertionError("transport must not be constructed when output already exists")

    monkeypatch.setattr("omni_migrator.runtime.SigmaApi", fail_if_constructed)
    exit_code = main(
        [
            "sigma-capability-spike",
            "--request",
            str(request_path),
            "--trusted-api-host",
            "aws-api.sigmacomputing.com",
            "--output",
            str(output),
        ]
    )

    assert exit_code == 1
    assert transport_constructed is False
    assert output.read_text() == "preserve me"
    assert json.loads(capsys.readouterr().out)["status"] == "failed"

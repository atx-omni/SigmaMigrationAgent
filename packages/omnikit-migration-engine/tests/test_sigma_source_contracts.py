"""Boundary cases for Sigma provider values and granular source evidence contracts."""

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from omni_migrator.extractors.sigma.capability_contracts import (
    SigmaSemanticRoutingArtifact,
    SigmaSemanticRoutingDecisionRequest,
)
from omni_migrator.extractors.sigma.semantic_routing import create_sigma_semantic_routing_decision

from omni_migrator.extractors.sigma.source_contracts import (
    normalize_sigma_document_version,
    selected_sigma_document_version,
)


@pytest.mark.parametrize("value", [7, 7.0, "7"])
def test_integral_numeric_versions_have_one_canonical_representation(value):
    assert normalize_sigma_document_version(value) == "7"


@pytest.mark.parametrize(
    "value",
    [
        True,
        False,
        None,
        0,
        -1,
        7.25,
        float("nan"),
        float("inf"),
        float(2**53),
        " 7",
        "+7",
        "7.0",
        {"version": 7},
    ],
)
def test_invalid_or_lossy_versions_do_not_coerce_to_an_accepted_selector(value):
    assert normalize_sigma_document_version(value) is None


def test_invalid_preferred_version_cannot_fall_back_to_another_version():
    assert (
        selected_sigma_document_version(
            {"latestVersion": True, "version": 7}, "latestVersion", "version"
        )
        is None
    )
    assert selected_sigma_document_version({"version": 7.0}, "latestVersion", "version") == "7"


@pytest.mark.parametrize(
    "schema_version",
    [
        "sigma-workbook-graph.v1",
        "sigma-behavior-manifest.v1",
        "sigma-api-capability-matrix.v1",
    ],
)
def test_routing_binds_granular_captured_source_artifacts(schema_version):
    contracts = Path(__file__).resolve().parents[3] / "contracts/sigma"
    payload = json.loads(
        (
            contracts
            / "examples/sigma-semantic-routing-decision-request.v1.omni-reconstruction.example.json"
        ).read_text()
    )
    binding = payload["source_context_bindings"][0]
    binding["artifact_schema_version"] = schema_version
    binding["artifact_id"] = f"{schema_version.removesuffix('.v1')}.captured-source"
    request = SigmaSemanticRoutingDecisionRequest.model_validate(payload)
    decision = create_sigma_semantic_routing_decision(request)
    assert decision.payload.source_context_bindings == request.source_context_bindings
    assert decision.upstream_hashes[0].content_hash == binding["content_hash"]
    assert decision.upstream_hashes[0].artifact_id == binding["artifact_id"]
    assert SigmaSemanticRoutingArtifact.model_validate_json(decision.model_dump_json()) == decision
    for artifact in (request, decision):
        schema = json.loads((contracts / f"{artifact.schema_version}.schema.json").read_text())
        Draft202012Validator(schema).validate(artifact.model_dump(mode="json"))

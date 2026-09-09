"""Governance and routing tests for the Sigma semantic architecture choice."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker
from pydantic import ValidationError

from omni_migrator.control_plane.canonical import sha256_json
from omni_migrator.extractors.sigma.capability_contracts import (
    SigmaCapabilitySpikeBundle,
    SigmaCapabilitySpikeRequest,
    SigmaSemanticRoutingArtifact,
    SigmaSemanticRoutingDecisionRequest,
    SigmaSemanticRoutingPrompt,
)
from omni_migrator.extractors.sigma.semantic_routing import (
    SEMANTIC_MIGRATION_GUARDRAIL,
    SEMANTIC_MIGRATION_OPTIONS,
    SEMANTIC_MIGRATION_QUESTION,
    advance_sigma_semantic_routing,
    create_sigma_semantic_routing_decision,
    route_sigma_semantic_specialists,
)


ROOT = Path(__file__).resolve().parents[3]
CREATED_AT = datetime(2026, 9, 3, 15, 0, tzinfo=UTC)


def _request(**overrides: object) -> SigmaSemanticRoutingDecisionRequest:
    value: dict[str, object] = {
        "schema_version": "sigma-semantic-routing-decision-request.v1",
        "decision_id": "semantic-route-0001",
        "run_id": "run.sigma.migration.0001",
        "scope_id": "scope.sigma.migration.0001",
        "migration_unit_id": "migration-unit-orders-0001",
        "comparison_scope_refs": [
            "sigma://workbooks/wb-1",
            "sigma://dataModels/dm-1",
        ],
        "build_scope_refs": ["sigma://workbooks/wb-1"],
        "target_environment_refs": [
            "environment-ref://dbt/development",
            "environment-ref://omni/quarantine",
        ],
        "mode": "warehouse_first_refactor",
        "decided_by_ref": "human-ref://migration-owner",
        "decision_ref": "human-decision-ref://sigma/semantic-route/0001",
        "decision_record_revision": "revision-1",
        "decision_record_sha256": "a" * 64,
        "decided_at": "2026-09-03T09:00:00-05:00",
        "rationale": "Use the governed data layer for approved shared and persistent logic.",
        "source_context_bindings": [
            {
                "artifact_id": "sigma-data-model-snapshot.run-0001",
                "artifact_schema_version": "sigma-data-model-snapshot.v1",
                "artifact_run_id": "run.sigma.phase0.0001",
                "artifact_scope_id": "scope.sigma.migration.0001",
                "content_hash": "b" * 64,
                "artifact_created_at": "2026-09-03T08:00:00-05:00",
                "accepted_by_ref": "human-ref://migration-owner",
                "acceptance_ref": "human-approval-ref://sigma/source-context/0001",
                "acceptance_record_revision": "revision-1",
                "acceptance_record_sha256": "c" * 64,
                "accepted_at": "2026-09-03T08:30:00-05:00",
                "acceptance_verification_state": "reference_only",
            }
        ],
        "question_version": "sigma-semantic-migration-question.v1",
    }
    if (
        overrides.get("mode") == "omni_semantic_reconstruction"
        and "target_environment_refs" not in overrides
    ):
        value["target_environment_refs"] = ["environment-ref://omni/quarantine"]
    value.update(overrides)
    return SigmaSemanticRoutingDecisionRequest.model_validate(value)


def _rehash_artifact(value: dict) -> None:
    material = dict(value)
    material.pop("content_hash")
    value["content_hash"] = sha256_json(material)


def test_agent_question_is_neutral_required_and_has_no_default_mode():
    assert SEMANTIC_MIGRATION_QUESTION == (
        "Which implementation path should this Sigma semantic layer use: warehouse-first "
        "refactoring before Omni, or direct reconstruction in Omni?"
    )
    assert "Both paths target bounded semantic equivalence" in SEMANTIC_MIGRATION_GUARDRAIL
    assert set(SEMANTIC_MIGRATION_OPTIONS) == {
        "warehouse_first_refactor",
        "omni_semantic_reconstruction",
    }

    missing_mode = _request().model_dump(mode="json")
    missing_mode.pop("mode")
    with pytest.raises(ValidationError, match="mode"):
        SigmaSemanticRoutingDecisionRequest.model_validate(missing_mode)


@pytest.mark.parametrize("input_value", [None, {}, {"mode": ""}, {"mode": "unsupported"}])
def test_manager_state_prompts_and_blocks_only_target_design_without_a_valid_choice(input_value):
    prompt = advance_sigma_semantic_routing(input_value)

    assert prompt.schema_version == "sigma-semantic-routing-prompt.v1"
    assert prompt.state == "awaiting_human_choice"
    assert prompt.default_mode is None
    assert prompt.shared_guardrail == SEMANTIC_MIGRATION_GUARDRAIL
    assert tuple(option.mode for option in prompt.options) == (
        "warehouse_first_refactor",
        "omni_semantic_reconstruction",
    )
    assert prompt.blocks_target_design is True
    assert prompt.blocks_source_evidence_acquisition is False


def test_published_prompt_schema_accepts_the_executable_manager_prompt():
    schema = json.loads(
        (ROOT / "contracts" / "sigma" / "sigma-semantic-routing-prompt.v1.schema.json").read_text()
    )
    prompt = advance_sigma_semantic_routing()

    errors = list(
        Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(
            prompt.model_dump(mode="json")
        )
    )
    assert errors == []


def test_prompt_contract_and_published_schema_reject_inverted_mode_copy():
    prompt = advance_sigma_semantic_routing().model_dump(mode="json")
    prompt["options"][0]["label"] = "Omni semantic reconstruction"
    prompt["options"][0]["description"] = SEMANTIC_MIGRATION_OPTIONS["omni_semantic_reconstruction"]
    prompt["options"][1]["label"] = "Warehouse-first refactor"
    prompt["options"][1]["description"] = SEMANTIC_MIGRATION_OPTIONS["warehouse_first_refactor"]

    with pytest.raises(ValidationError):
        SigmaSemanticRoutingPrompt.model_validate(prompt)

    schema = json.loads(
        (ROOT / "contracts" / "sigma" / "sigma-semantic-routing-prompt.v1.schema.json").read_text()
    )
    assert list(Draft202012Validator(schema).iter_errors(prompt))


def test_prompt_contract_and_published_schema_reject_a_biased_question():
    prompt = advance_sigma_semantic_routing().model_dump(mode="json")
    prompt["question"] = "Choose warehouse-first because it is the recommended option."

    with pytest.raises(ValidationError):
        SigmaSemanticRoutingPrompt.model_validate(prompt)

    schema = json.loads(
        (ROOT / "contracts" / "sigma" / "sigma-semantic-routing-prompt.v1.schema.json").read_text()
    )
    assert list(Draft202012Validator(schema).iter_errors(prompt))


def test_prompt_contract_and_published_schema_require_exactly_one_option_per_mode():
    prompt = advance_sigma_semantic_routing().model_dump(mode="json")
    prompt["options"][1] = dict(prompt["options"][0])

    with pytest.raises(ValidationError, match="both supported modes"):
        SigmaSemanticRoutingPrompt.model_validate(prompt)

    schema = json.loads(
        (ROOT / "contracts" / "sigma" / "sigma-semantic-routing-prompt.v1.schema.json").read_text()
    )
    assert list(Draft202012Validator(schema).iter_errors(prompt))


@pytest.mark.parametrize(
    ("mode", "expected_dbt", "expected_omni", "dbt_is_required"),
    [
        (
            "warehouse_first_refactor",
            "required_when_approved_blueprint_places_logic_upstream",
            "model_on_accepted_source_and_data_layer_relations",
            True,
        ),
        (
            "omni_semantic_reconstruction",
            "not_applicable_direct_route",
            "reconstruct_semantics_in_omni_over_accepted_warehouse_relations",
            False,
        ),
    ],
)
def test_human_choice_produces_an_executable_scope_bound_route(
    mode: str,
    expected_dbt: str,
    expected_omni: str,
    dbt_is_required: bool,
):
    decision = advance_sigma_semantic_routing(
        _request(
            mode=mode,
            decision_id=f"semantic-route-{mode}",
            decision_ref=f"human-decision-ref://sigma/semantic-route/{mode}",
        ),
        created_at=CREATED_AT,
    )

    assert isinstance(decision, SigmaSemanticRoutingArtifact)
    assert decision.classification == "stated_evidence"
    assert decision.payload.decision_verification_state == "reference_only"
    assert decision.payload.dbt_route == expected_dbt
    assert decision.payload.omni_model_route == expected_omni
    assert decision.payload.behavior_route == "separate_behavior_manifest_and_redesign"
    assert decision.payload.independent_qa_required is True
    assert decision.payload.automatic_one_to_one_claim_allowed is False
    assert decision.payload.target_design_approval_required is True
    assert decision.payload.target_write_authority is False
    assert decision.source_references == (
        decision.payload.decision_ref,
        *(
            value
            for item in decision.payload.source_context_bindings
            for value in (f"artifact-ref://{item.artifact_id}", item.acceptance_ref)
        ),
    )
    assert tuple(item.artifact_id for item in decision.upstream_hashes) == (
        "sigma-data-model-snapshot.run-0001",
    )
    routed = route_sigma_semantic_specialists(decision)
    assert ("sigma_dbt_analytics_engineer" in routed) is dbt_is_required
    assert "sigma_semantic_consolidation" in routed
    assert "sigma_omni_modeler" in routed
    assert "sigma_independent_qa" in routed

    material = decision.model_dump(mode="json")
    declared_hash = material.pop("content_hash")
    assert declared_hash == sha256_json(material)


@pytest.mark.parametrize(
    ("override", "message"),
    [
        ({"mode": "agent_selected_default"}, "mode"),
        ({"build_scope_refs": ["sigma://workbooks/outside"]}, "subset"),
        ({"decided_at": "2026-09-03T09:00:00"}, "timezone-aware"),
        ({"decided_by_ref": "agent-ref://self"}, "human-ref"),
        ({"decision_ref": "approval-ref://untrusted"}, "human-decision-ref"),
        ({"rationale": "short"}, "at least 10"),
        ({"decision_record_sha256": "unhashed"}, "pattern"),
        ({"migration_unit_id": "../outside"}, "pattern"),
        (
            {"target_environment_refs": ["environment-ref://omni/quarantine"]},
            "data-layer target",
        ),
        (
            {
                "mode": "omni_semantic_reconstruction",
                "target_environment_refs": [
                    "environment-ref://dbt/development",
                    "environment-ref://omni/quarantine",
                ],
            },
            "cannot include a data-layer target",
        ),
        (
            {
                "source_context_bindings": [
                    {
                        "artifact_id": "sigma-data-model-snapshot.run-0001",
                        "artifact_schema_version": "sigma-data-model-snapshot.v1",
                        "artifact_run_id": "run.sigma.phase0.0001",
                        "artifact_scope_id": "scope.sigma.migration.other",
                        "content_hash": "b" * 64,
                        "artifact_created_at": "2026-09-03T08:00:00-05:00",
                        "accepted_by_ref": "human-ref://migration-owner",
                        "acceptance_ref": "human-approval-ref://sigma/source-context/0001",
                        "acceptance_record_revision": "revision-1",
                        "acceptance_record_sha256": "c" * 64,
                        "accepted_at": "2026-09-03T08:30:00-05:00",
                    }
                ]
            },
            "semantic routing scope",
        ),
    ],
)
def test_decision_contract_rejects_inferred_unscoped_or_weakly_attributed_choices(
    override: dict[str, object], message: str
):
    with pytest.raises(ValidationError, match=message):
        _request(**override)


def test_artifact_rejects_route_scope_and_source_reference_tampering():
    decision = create_sigma_semantic_routing_decision(_request(), created_at=CREATED_AT)

    wrong_route = decision.model_dump(mode="json")
    wrong_route["payload"]["dbt_route"] = "not_applicable_direct_route"
    _rehash_artifact(wrong_route)
    with pytest.raises(ValidationError, match="contradicts"):
        SigmaSemanticRoutingArtifact.model_validate(wrong_route)

    wrong_scope = decision.model_dump(mode="json")
    wrong_scope["scope_id"] = "scope.sigma.migration.other"
    _rehash_artifact(wrong_scope)
    with pytest.raises(ValidationError, match="declared run and scope"):
        SigmaSemanticRoutingArtifact.model_validate(wrong_scope)

    wrong_sources = decision.model_dump(mode="json")
    wrong_sources["source_references"] = [wrong_sources["payload"]["decision_ref"]]
    _rehash_artifact(wrong_sources)
    with pytest.raises(ValidationError, match="source references"):
        SigmaSemanticRoutingArtifact.model_validate(wrong_sources)

    wrong_upstream = decision.model_dump(mode="json")
    wrong_upstream["upstream_hashes"][0]["content_hash"] = "f" * 64
    _rehash_artifact(wrong_upstream)
    with pytest.raises(ValidationError, match="exact source context hashes"):
        SigmaSemanticRoutingArtifact.model_validate(wrong_upstream)


@pytest.mark.parametrize("mode", ["warehouse_first_refactor", "omni_semantic_reconstruction"])
def test_superseded_decision_cannot_dispatch_its_old_specialist_route(mode):
    decision = create_sigma_semantic_routing_decision(_request(mode=mode), created_at=CREATED_AT)
    assert route_sigma_semantic_specialists(decision) == decision.payload.required_specialist_ids

    superseded = decision.model_dump(mode="json")
    superseded["supersession_state"] = "superseded"
    superseded["superseded_by_artifact_id"] = "sigma-semantic-routing-decision.successor"
    _rehash_artifact(superseded)
    historical_decision = SigmaSemanticRoutingArtifact.model_validate(superseded)

    with pytest.raises(ValueError, match="superseded.*cannot route"):
        route_sigma_semantic_specialists(historical_decision)


def test_decision_and_artifact_must_follow_source_context_chronologically():
    future_acceptance = _request().model_dump(mode="json")
    future_acceptance["source_context_bindings"][0]["accepted_at"] = "2026-09-03T09:30:00-05:00"
    with pytest.raises(ValidationError, match="cannot predate source context acceptance"):
        SigmaSemanticRoutingDecisionRequest.model_validate(future_acceptance)

    with pytest.raises(ValidationError, match="cannot predate the stated decision"):
        create_sigma_semantic_routing_decision(
            _request(),
            created_at=datetime(2026, 9, 3, 13, 15, tzinfo=UTC),
        )


def test_semantic_choice_is_not_an_input_or_ancestor_of_source_evidence():
    request_schema = SigmaCapabilitySpikeRequest.model_json_schema(mode="serialization")
    bundle_schema = SigmaCapabilitySpikeBundle.model_json_schema(mode="serialization")

    assert "semantic_migration" not in request_schema["properties"]
    assert "target_environment_refs" not in request_schema["properties"]
    assert "semantic_routing_decision" not in bundle_schema["properties"]

    warehouse = create_sigma_semantic_routing_decision(_request(), created_at=CREATED_AT)
    direct = create_sigma_semantic_routing_decision(
        _request(
            mode="omni_semantic_reconstruction",
            decision_id="semantic-route-0002",
            decision_ref="human-decision-ref://sigma/semantic-route/0002",
        ),
        created_at=CREATED_AT,
    )
    assert warehouse.run_id == direct.run_id
    assert warehouse.scope_id == direct.scope_id
    assert warehouse.content_hash != direct.content_hash
    assert warehouse.upstream_hashes == direct.upstream_hashes


def test_semantically_identical_input_order_produces_the_same_route_hash():
    first_binding = _request().model_dump(mode="json")["source_context_bindings"][0]
    second_binding = {
        **first_binding,
        "artifact_id": "sigma-capability-spike-bundle.run-0001",
        "artifact_schema_version": "sigma-capability-spike-bundle.v1",
        "content_hash": "e" * 64,
        "acceptance_ref": "human-approval-ref://sigma/source-context/0002",
        "acceptance_record_sha256": "f" * 64,
    }
    baseline = create_sigma_semantic_routing_decision(
        _request(source_context_bindings=[first_binding, second_binding]),
        created_at=CREATED_AT,
    )
    reordered = create_sigma_semantic_routing_decision(
        _request(
            comparison_scope_refs=[
                "sigma://dataModels/dm-1",
                "sigma://workbooks/wb-1",
            ],
            target_environment_refs=[
                "environment-ref://omni/quarantine",
                "environment-ref://dbt/development",
            ],
            source_context_bindings=[second_binding, first_binding],
        ),
        created_at=CREATED_AT,
    )

    assert reordered.content_hash == baseline.content_hash


def test_reselecting_a_mode_creates_a_typed_append_only_supersession_path():
    prior = create_sigma_semantic_routing_decision(_request(), created_at=CREATED_AT)
    with pytest.raises(ValidationError, match="cannot supersede itself"):
        _request(
            mode="omni_semantic_reconstruction",
            decision_ref="human-decision-ref://sigma/semantic-route/reused-id",
            decision_record_revision="revision-2",
            decision_record_sha256="d" * 64,
            decided_at="2026-09-03T10:30:00-05:00",
            supersedes_decision={
                "artifact_id": prior.artifact_id,
                "content_hash": prior.content_hash,
                "created_at": prior.created_at,
                "scope_id": prior.scope_id,
                "migration_unit_id": prior.payload.migration_unit_id,
            },
        )
    replacement = create_sigma_semantic_routing_decision(
        _request(
            decision_id="semantic-route-0002",
            mode="omni_semantic_reconstruction",
            decision_ref="human-decision-ref://sigma/semantic-route/0002",
            decision_record_revision="revision-2",
            decision_record_sha256="d" * 64,
            decided_at="2026-09-03T10:30:00-05:00",
            supersedes_decision={
                "artifact_id": prior.artifact_id,
                "content_hash": prior.content_hash,
                "created_at": prior.created_at,
                "scope_id": prior.scope_id,
                "migration_unit_id": prior.payload.migration_unit_id,
            },
        ),
        created_at=datetime(2026, 9, 3, 16, 0, tzinfo=UTC),
    )

    assert replacement.supersedes_artifact_id == prior.artifact_id
    assert replacement.upstream_hashes[-1].artifact_id == prior.artifact_id
    assert replacement.source_references[-1] == f"artifact-ref://{prior.artifact_id}"
    assert replacement.payload.mode == "omni_semantic_reconstruction"


@pytest.mark.parametrize(
    "example_name",
    [
        "sigma-semantic-routing-decision-request.v1.warehouse-first.example.json",
        "sigma-semantic-routing-decision-request.v1.omni-reconstruction.example.json",
    ],
)
def test_published_routing_schemas_validate_both_examples_and_generated_artifacts(
    example_name: str,
):
    directory = ROOT / "contracts" / "sigma"
    request_schema = json.loads(
        (directory / "sigma-semantic-routing-decision-request.v1.schema.json").read_text()
    )
    artifact_schema = json.loads(
        (directory / "sigma-semantic-routing-decision.v1.schema.json").read_text()
    )
    payload = json.loads((directory / "examples" / example_name).read_text())

    request_errors = list(
        Draft202012Validator(request_schema, format_checker=FormatChecker()).iter_errors(payload)
    )
    assert request_errors == []
    decision = create_sigma_semantic_routing_decision(payload, created_at=CREATED_AT)
    artifact_errors = list(
        Draft202012Validator(artifact_schema, format_checker=FormatChecker()).iter_errors(
            decision.model_dump(mode="json")
        )
    )
    assert artifact_errors == []


@pytest.mark.parametrize(
    ("mode", "invalid_targets"),
    [
        ("warehouse_first_refactor", ["environment-ref://omni/quarantine"]),
        (
            "warehouse_first_refactor",
            ["environment-ref://omni/quarantine", "environment-ref://tableau/development"],
        ),
        (
            "omni_semantic_reconstruction",
            ["environment-ref://omni/quarantine", "environment-ref://dbt/development"],
        ),
        ("omni_semantic_reconstruction", ["environment-ref://sigma/source"]),
    ],
)
def test_published_routing_schemas_reject_route_incompatible_target_environments(
    mode: str,
    invalid_targets: list[str],
):
    directory = ROOT / "contracts" / "sigma"
    request_schema = json.loads(
        (directory / "sigma-semantic-routing-decision-request.v1.schema.json").read_text()
    )
    artifact_schema = json.loads(
        (directory / "sigma-semantic-routing-decision.v1.schema.json").read_text()
    )
    request = _request(mode=mode).model_dump(mode="json")
    artifact = create_sigma_semantic_routing_decision(
        _request(mode=mode), created_at=CREATED_AT
    ).model_dump(mode="json")
    request["target_environment_refs"] = invalid_targets
    artifact["payload"]["target_environment_refs"] = invalid_targets

    assert list(Draft202012Validator(request_schema).iter_errors(request))
    assert list(Draft202012Validator(artifact_schema).iter_errors(artifact))


@pytest.mark.parametrize(
    ("field_name", "contradictory_value"),
    [
        ("dbt_route", "not_applicable_direct_route"),
        ("consolidation_route", "preserve_source_boundaries_for_direct_route"),
        (
            "omni_model_route",
            "reconstruct_semantics_in_omni_over_accepted_warehouse_relations",
        ),
        (
            "semantic_acceptance_objective",
            "bounded_semantic_equivalence_after_direct_reconstruction",
        ),
        (
            "required_specialist_ids",
            [
                "sigma_analytics_formula",
                "sigma_semantic_consolidation",
                "sigma_omni_modeler",
                "sigma_independent_qa",
            ],
        ),
        ("skipped_specialist_ids", ["sigma_dbt_analytics_engineer"]),
    ],
)
def test_published_decision_schema_rejects_mode_contradicting_route_effects(
    field_name: str,
    contradictory_value: object,
):
    schema = json.loads(
        (
            ROOT / "contracts" / "sigma" / "sigma-semantic-routing-decision.v1.schema.json"
        ).read_text()
    )
    artifact = create_sigma_semantic_routing_decision(_request(), created_at=CREATED_AT).model_dump(
        mode="json"
    )
    artifact["payload"][field_name] = contradictory_value

    assert list(Draft202012Validator(schema).iter_errors(artifact))

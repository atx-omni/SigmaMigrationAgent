from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
REGISTRY_PATH = ROOT / "agents" / "sigma" / "registry.json"


def _registry() -> dict:
    return json.loads(REGISTRY_PATH.read_text())


def test_sigma_registry_declares_manager_and_every_required_specialist_contract():
    registry = _registry()
    agents = registry["agents"]
    by_id = {agent["id"]: agent for agent in agents}

    assert registry["implemented_milestone"] == "phase_0_capability_spike"
    assert registry["phase_0_authority"]["artifact_registry"] == (
        "required_external_control_plane_not_wired"
    )
    assert registry["manager"] == "sigma_to_omni_architect"
    assert len(agents) == 10
    assert len(by_id) == len(agents)
    assert set(by_id) == {
        "sigma_to_omni_architect",
        "sigma_inventory_admin",
        "sigma_bi_workbook",
        "sigma_analytics_formula",
        "sigma_semantic_consolidation",
        "sigma_dbt_analytics_engineer",
        "sigma_omni_modeler",
        "sigma_omni_bi_developer",
        "sigma_independent_qa",
        "sigma_documentation_training",
    }

    for agent in agents:
        assert (REGISTRY_PATH.parent / agent["spec"]).is_file()
        assert agent["input_contracts"]
        assert agent["output_contracts"]
        assert agent["tool_profile"] in registry["tool_profiles"]
        assert agent["stopping_conditions"]
        assert agent["retry_policy"]
        assert agent["escalation_behavior"]


def test_phase_zero_profiles_expose_no_source_mutation_or_target_write_tools():
    registry = _registry()
    active = [agent for agent in registry["agents"] if agent["active_from_phase"] == 0]
    assert {agent["id"] for agent in active} == {
        "sigma_to_omni_architect",
        "sigma_inventory_admin",
        "sigma_bi_workbook",
        "sigma_analytics_formula",
    }

    forbidden_markers = ("mutation", "dbt_write", "snowflake_write", "omni_write", "release")
    for agent in active:
        profile = registry["tool_profiles"][agent["tool_profile"]]
        assert "artifact_registry_write" not in profile["allowed_tools"]
        assert not any(
            marker in tool for tool in profile["allowed_tools"] for marker in forbidden_markers
        )


def test_human_only_actions_cover_every_irreversible_or_acceptance_boundary():
    actions = set(_registry()["human_only_actions"])
    assert {
        "approve_scope",
        "approve_consolidation",
        "approve_security_disposition",
        "approve_operational_redesign",
        "authorize_target_write",
        "accept_business_security_operational_and_technical_results",
        "authorize_release",
        "authorize_cutover",
        "authorize_decommission",
    }.issubset(actions)


def test_semantic_routing_registry_has_two_no_default_paths_and_shared_assurance():
    registry = _registry()
    routing = registry["semantic_migration_discovery"]
    modes = routing["modes"]
    manager = next(agent for agent in registry["agents"] if agent["id"] == registry["manager"])

    assert routing["default_mode"] is None
    assert routing["required_before_target_design"] is True
    assert routing["blocks_phase_0_source_acquisition"] is False
    assert routing["prompt_contract"] == "sigma-semantic-routing-prompt.v1"
    assert routing["decision_request_contract"] == ("sigma-semantic-routing-decision-request.v1")
    assert "sigma-semantic-routing-prompt.v1" in manager["output_contracts"]
    assert set(modes) == {
        "warehouse_first_refactor",
        "omni_semantic_reconstruction",
    }
    for route in modes.values():
        assert "sigma_semantic_consolidation" in route["required_specialists"]
        assert "sigma_omni_modeler" in route["required_specialists"]
        assert "sigma_independent_qa" in route["required_specialists"]
        assert route["semantic_acceptance_objective"].startswith("bounded_semantic_equivalence")
    assert (
        "sigma_dbt_analytics_engineer" in modes["warehouse_first_refactor"]["required_specialists"]
    )
    assert modes["omni_semantic_reconstruction"]["skipped_specialists"] == [
        "sigma_dbt_analytics_engineer"
    ]

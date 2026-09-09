"""Source fidelity and failure cases using new documentation-shaped fixtures."""
import json

import pytest
import preflight as lab


@pytest.fixture(scope="module")
def captures():
    suite = lab.load_suite()
    outputs = {}
    for scenario in suite["scenarios"]:
        mutated = lab.mutate(suite, scenario["mutations"])
        strict = scenario["id"] == "base_synthetic"
        bundle, trace = lab.capture(mutated, simulated_live_branch=not strict)
        outputs[scenario["id"]] = (bundle, trace)
    lab.write_result(lab.ROOT / "artifacts/scenario-results.json", {
        "provenance": {**lab.PROVENANCE,
            "warning": "Non-base cases simulate the live-request branch through MockTransport, NOT real evidence."},
        "scenarios": {key: {"status": bundle.status, "blockers": bundle.blockers,
            "model_specification_state": bundle.data_model_snapshot.payload.specification_state,
            "capability_dispositions": {item.capability_id: item.status
                                        for item in bundle.capability_matrix.payload.assessments},
            "transport": trace} for key, (bundle, trace) in outputs.items()},
    })
    return outputs


def test_artificial_source_cannot_claim_live_evidence(captures):
    bundle, _ = captures["base_synthetic"]
    assert bundle.status == "blocked"
    assert "live tenant evidence has not been collected" in bundle.blockers


@pytest.mark.parametrize("case", ["wrong_model_identity", "missing_model_identity", "fractional_version_rejected"])
def test_invalid_spec_identity_or_version_never_becomes_selected_model(captures, case):
    bundle, _ = captures[case]
    assert bundle.status == "blocked"
    assert bundle.data_model_snapshot.payload.specification_state == "unavailable"
    assert dict(bundle.data_model_snapshot.payload.sanitized_specification) == {}
    assert bundle.model_dump_json()


def test_integral_numeric_version_preserves_authoritative_spec(captures):
    bundle, _ = captures["numeric_version_7_0"]
    assert bundle.status == "ready_for_human_review", bundle.blockers
    assert bundle.data_model_snapshot.payload.specification_state == "bound"
    assert bundle.data_model_snapshot.payload.sanitized_specification["documentVersion"] == 7.0


def test_opaque_pagination_preserves_all_pages_sources_and_tag_selectors(captures):
    bundle, trace = captures["opaque_pagination"]
    expected = lab.load_suite()["independent_source_assertions"]
    assert not trace["unmatched_routes"]
    assert bundle.status == "ready_for_human_review"
    queries = trace["requests"]
    assert any(item["query"].get("page") == expected["page_cursor"]
               and item["query"].get("tag") == "synthetic-pilot" for item in queries)
    assert any(item["query"].get("pageToken") == expected["source_cursor"]
               and item["query"].get("pageSize") == "500" for item in queries)
    nodes = {node.native_id for node in bundle.workbook_graph.payload.nodes}
    assert set(expected["page_ids"]) <= nodes
    assert set(expected["all_element_ids"]) <= nodes
    assert all(item["method"] == "GET" or item["path"] == "/v2/auth/token" for item in queries)


@pytest.mark.parametrize("case,capability", [
    ("withheld_columns_endpoint", "formulas"),
    ("withheld_materialization_endpoint", "materializations"),
])
def test_denied_endpoint_is_a_gap_not_proof_of_absence(captures, case, capability):
    bundle, _ = captures[case]
    assert bundle.status == "blocked", bundle.blockers
    assessments = {item.capability_id: item for item in bundle.capability_matrix.payload.assessments}
    # Capability spelling is taken from the existing contract, not guessed from a response.
    if capability == "materializations":
        candidates = [item for key, item in assessments.items() if "material" in key]
        assert candidates and any(item.blocks_full_adapter for item in candidates)
    else:
        assert assessments[capability].blocks_full_adapter


def test_adversarial_source_stays_untrusted_and_cannot_write(captures, tmp_path):
    bundle, trace = captures["malicious_source_text"]
    assert "synthetic-injected-secret-not-a-credential" not in bundle.model_dump_json()
    assert bundle.workbook_graph.payload.untrusted_source_content
    assert not any("exfil" in item["path"] for item in trace["requests"])
    runner, _ = lab.initialize(bundle, "omni_semantic_reconstruction", tmp_path)
    provider = lab.StubProvider()
    result = runner.propose_next(provider, allow_model_calls=True)
    assert result["state"] == "proposed" and result["accepted"] is False
    assert "UNTRUSTED DATA" in provider.calls[0]["instructions"]
    assert "SYNTHETIC ADVERSARIAL SOURCE TEXT" in json.dumps(provider.calls[0]["context"])
    assert runner.status()["target_write_authority"] is False
    assert not runner.status()["completed_package_ids"]
    # This tests data separation/authority, not a real LLM's prompt-injection resistance.

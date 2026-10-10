"""Existing Topic reuse: real typed query payloads and reopened negative checks."""
from __future__ import annotations

import json
import hashlib
import os
from pathlib import Path

import pytest

from omni_migrator.prepush.build import build
from omni_migrator.prepush.reuse import canonical_hash, source_fields
from omni_migrator.prepush.validate import validate
from omni_migrator.prepush.scope import create_scope

ROOT = Path(__file__).resolve().parents[3]
DIRECT = "omni_semantic_reconstruction"


def read_json(path):
    return json.loads(path.read_text())


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2))


def codes(package):
    return {row["code"] for row in validate(package)["issues"]}


def seal(package, manifest):
    manifest["files"] = {path.relative_to(package).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
                         for path in package.rglob("*") if path.is_file() and path.name != "manifest.json"}
    for name in ("source", "target"):
        manifest[name + "_sha256"] = canonical_hash(read_json(package / (name + ".json")))
    proposal = {**manifest["build"], "files": {name: (package / name).read_text() for name in manifest["files"]
                                             if name not in {"source.json", "target.json"}}}
    manifest["review"].update({key: manifest[key] for key in ("route", "source_sha256", "target_sha256")})
    manifest["review"]["proposal_sha256"] = canonical_hash(proposal)
    write_json(package / "manifest.json", manifest)


def reuse_target(source):
    original = read_json(ROOT / "examples/target.json")
    inventory = {"schema_version": "omni-topic-inventory.v1", "model_id": original["model_id"],
                 "connection_id": original["connection_id"], "topic_name": "retail", "base_view": "sales",
                 "captured_at": "2026-10-09T12:00:00Z", "evidence_ref": "synthetic-fixture://existing-topic",
                 "grain": "One row per order", "filters": [], "fields": {}}
    bindings = {}
    for locator, (_, raw, plural) in source_fields(source).items():
        reference = "sales." + raw["name"]
        definition = {"kind": "measure" if plural == "metrics" else "dimension",
                      "hidden": raw.get("hidden", False), "definition": {"source_formula": raw.get("formula", raw["name"])}}
        inventory["fields"][reference] = definition
        bindings[locator] = {"target_field": reference, "source_field_sha256": canonical_hash(raw),
                             "target_field_sha256": canonical_hash(definition), "compatibility": {
                                 "status": "compatible", "grain": "Both use order grain.",
                                 "filters": "No persistent target/source filters; East is a dashboard control.",
                                 "metric": "Synthetic source definitions match the imported target definitions.",
                                 "joins": "No joins in this synthetic single-view example."}}
    return {"model_id": original["model_id"], "connection_id": original["connection_id"],
            "document_name": original["document_name"], "allowed_changes": "dashboard_only",
            "existing_topic": {"inventory": inventory, "inventory_sha256": canonical_hash(inventory), "field_mappings": bindings}}


@pytest.fixture
def inputs():
    source = read_json(ROOT / "examples/retail-supported.json")
    return source, reuse_target(source)


@pytest.fixture
def package(inputs, tmp_path):
    source, target = inputs
    return make_package(source, target, tmp_path)


def make_package(source, target, tmp_path):
    proposal = build(source, DIRECT, target)
    root = tmp_path / "reuse"
    root.mkdir()
    for name, content in proposal["files"].items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    write_json(root / "source.json", source)
    write_json(root / "target.json", target)
    manifest = {"schema_version": "sigma-prepush-package.v1", "route": DIRECT, "synthetic": True,
                "target_write_authority": False, "migration_accepted": False, "live_validation": "not_performed",
                "review": {"decision": "accept", "actor": {"uid": os.getuid(), "name": "fixture-operator"}},
                "build": {key: value for key, value in proposal.items() if key != "files"}}
    seal(root, manifest)
    return root


def test_reuse_emits_only_dashboard_and_typed_semantic_queries(inputs):
    result = build(inputs[0], DIRECT, inputs[1])
    assert all(row["status"] == "implemented" for row in result["dispositions"]), result["dispositions"]
    assert set(result["files"]) == {"omni/document.create.json", "omni/document.patch.json", "queries/1.json", "queries/2.json"}
    document = json.loads(result["files"]["omni/document.create.json"])
    first = document["queryPresentations"]["data"]["1"]
    assert first["topicName"] == "retail"
    assert first["query"]["table"] == "sales"
    assert first["query"]["fields"] == ["sales.display_region", "sales.total_revenue"]
    query = json.loads(result["files"]["queries/1.json"])
    assert query["control_defaults"] == [{"field": "sales.region", "kind": "EQUALS", "values": ["East"]}]
    assert result["dependencies"][0]["status"] == "unverified"


def test_reuse_independent_validator_never_builds_or_uses_network(package, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("Independent local validation cannot build or call a target.")
    monkeypatch.setattr("omni_migrator.prepush.build.build", forbidden)
    monkeypatch.setattr("socket.socket", forbidden)
    result = validate(package)
    assert result["status"] == "offline_preflight_passed", result["issues"]
    assert result["migration_accepted"] is False


@pytest.mark.parametrize("mutation", ["target_hash", "source_hash", "identity", "visibility", "ambiguous", "blank_evidence"])
def test_invalid_topic_evidence_blocks_before_compilation(inputs, mutation):
    source, target = inputs
    topic = target["existing_topic"]
    mapping = next(iter(topic["field_mappings"].values()))
    if mutation == "target_hash":
        topic["inventory_sha256"] = "0" * 64
    elif mutation == "source_hash":
        mapping["source_field_sha256"] = "0" * 64
    elif mutation == "identity":
        target["model_id"] = "00000000-0000-0000-0000-000000000001"
    elif mutation == "visibility":
        topic["inventory"]["fields"]["sales.region"]["hidden"] = True
        topic["inventory_sha256"] = canonical_hash(topic["inventory"])
        mapping["target_field_sha256"] = canonical_hash(topic["inventory"]["fields"]["sales.region"])
    elif mutation == "ambiguous":
        second = list(topic["field_mappings"].values())[1]
        second["target_field"] = mapping["target_field"]
        second["target_field_sha256"] = mapping["target_field_sha256"]
    else:
        mapping["compatibility"]["grain"] = " "
    with pytest.raises(ValueError):
        build(source, DIRECT, target)


def test_missing_mapping_stays_in_denominator_and_blocks(inputs):
    source, target = inputs
    del target["existing_topic"]["field_mappings"]["data-model:fictional-retail/element:orders/metric:revenue"]
    result = build(source, DIRECT, target)
    by_id = {row["source_id"]: row for row in result["dispositions"]}
    assert by_id["revenue"]["status"] == "blocked"
    assert by_id["revenue-chart"]["status"] == "blocked"
    assert len(result["dispositions"]) == 15


def test_resealed_forbidden_model_file_is_rejected(package):
    path = package / "omni/model/unexpected.view"
    path.parent.mkdir(parents=True)
    path.write_text("table_name: orders\n")
    seal(package, read_json(package / "manifest.json"))
    assert "forbidden_dashboard_only_artifact" in codes(package)


def test_resealed_query_defaults_and_target_identity_are_rejected(package):
    path = package / "queries/1.json"
    query = read_json(path)
    query["control_defaults"] = []
    query["connection_id"] = "00000000-0000-0000-0000-000000000001"
    write_json(path, query)
    seal(package, read_json(package / "manifest.json"))
    assert "existing_topic_query_mismatch" in codes(package)


def test_resealed_inventory_change_is_rejected(package):
    target = read_json(package / "target.json")
    target["existing_topic"]["inventory"]["grain"] = "Different grain"
    write_json(package / "target.json", target)
    seal(package, read_json(package / "manifest.json"))
    assert "invalid_topic_evidence" in codes(package)


def test_modeled_dashboard_only_and_restricted_policies_fail_closed(inputs):
    source, target = inputs
    with pytest.raises(ValueError, match="warehouse-first"):
        build(source, "warehouse_first_refactor", target)
    target = read_json(ROOT / "examples/target.json")
    for policy in ("validation_only", "topic_additions", "unknown"):
        target["allowed_changes"] = policy
        with pytest.raises(ValueError, match="requires model_changes"):
            build(source, DIRECT, target)


@pytest.mark.parametrize("reuse", [False, True])
def test_scoped_pilot_retains_full_source_and_shared_control(inputs, tmp_path, reuse):
    source, target = inputs
    source = create_scope(source, workbook_id="fictional-overview", chart_ids=["revenue-chart"])
    if not reuse:
        target = read_json(ROOT / "examples/target.json")
    result = build(source, DIRECT, target)
    assert len(result["dispositions"]) == 15
    by_id = {row["source_id"]: row for row in result["dispositions"]}
    assert by_id["revenue-table"]["status"] == "excluded"
    assert by_id["revenue-table"]["target_paths"] == []
    assert by_id["region-filter"]["status"] == "implemented"
    assert by_id["completed-revenue"]["status"] == "implemented"  # Full model denominator is retained.
    document = json.loads(result["files"]["omni/document.create.json"])
    assert document["queryPresentations"]["order"] == ["1"]
    assert document["controls"]["data"]["control_1"]["map"] == {"1": ("sales.region" if reuse else "orders.region")}
    root = make_package(source, target, tmp_path)
    assert read_json(root / "source.json")["prepush_context"]["controls"]["region-filter"]["target_element_ids"] == ["revenue-chart", "revenue-table"]
    assert validate(root)["status"] == "offline_preflight_passed", validate(root)["issues"]
    manifest = read_json(root / "manifest.json")
    manifest["build"]["dispositions"] = [row for row in manifest["build"]["dispositions"] if row["source_id"] != "revenue-table"]
    seal(root, manifest)
    assert "missing_disposition" in codes(root)


def test_resealed_scope_exclusion_cannot_hide_a_required_object(inputs, tmp_path):
    source, target = inputs
    source = create_scope(source, workbook_id="fictional-overview", chart_ids=["revenue-chart"])
    root = make_package(source, target, tmp_path)
    source["_migration_scope"]["excluded_source_paths"].append("/workbooks/0/controls/0")
    write_json(root / "source.json", source)
    seal(root, read_json(root / "manifest.json"))
    assert "invalid_scope" in codes(root)

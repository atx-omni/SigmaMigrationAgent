"""Tamper reopened packages, not the builder's in-memory verdict or oracle."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from omni_migrator.prepush.build import build
from omni_migrator.prepush.validate import validate

ROOT = Path(__file__).resolve().parents[3]


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2), encoding="utf-8")


def read_json(path):
    return json.loads(path.read_text())


def seal(package, manifest):
    """Deliberately reseal corruption: structural checks must still catch it."""
    manifest["files"] = {
        path.relative_to(package).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in package.rglob("*") if path.is_file() and path.name != "manifest.json"
    }
    for name in ("source", "target"):
        manifest[name + "_sha256"] = digest(read_json(package / (name + ".json")))
    proposal = {**manifest["build"], "files": {
        name: (package / name).read_text()
        for name in manifest["files"] if name not in {"source.json", "target.json"}
    }}
    manifest["review"].update({
        key: manifest[key] for key in ("route", "source_sha256", "target_sha256")
    })
    manifest["review"]["proposal_sha256"] = digest(proposal)
    write_json(package / "manifest.json", manifest)


@pytest.fixture
def package(tmp_path):
    source = read_json(ROOT / "examples/retail-supported.json")
    target = read_json(ROOT / "examples/target.json")
    route = "omni_semantic_reconstruction"
    proposal = build(source, route, target)
    package = tmp_path / "package"
    package.mkdir()
    for name, content in proposal["files"].items():
        path = package / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    write_json(package / "source.json", source)
    write_json(package / "target.json", target)
    manifest = {
        "schema_version": "sigma-prepush-package.v1", "route": route,
        "synthetic": True, "target_write_authority": False, "migration_accepted": False,
        "live_validation": "not_performed",
        "review": {"decision": "accept", "actor": {"uid": os.getuid(), "name": "fixture-operator"}},
        "build": {key: value for key, value in proposal.items() if key != "files"},
    }
    seal(package, manifest)
    return package


def codes(package):
    result = validate(package)
    assert result["migration_accepted"] is False
    assert result["target_write_authority"] is False
    return {item["code"] for item in result["issues"]}


def mutate_documents(package, mutate):
    create = read_json(package / "omni/document.create.json")
    mutate(create)
    write_json(package / "omni/document.create.json", create)
    write_json(package / "omni/document.patch.json", {key: value for key, value in create.items() if key != "modelId"})
    seal(package, read_json(package / "manifest.json"))


def test_reopened_validator_never_regenerates_or_calls_network(package, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("No builder or network is allowed during independent validation")
    monkeypatch.setattr("omni_migrator.prepush.build.build", forbidden)
    monkeypatch.setattr("socket.socket", forbidden)
    result = validate(package)
    assert result["status"] == "offline_preflight_passed", result["issues"]
    assert result["live_validation"] == "not_performed"
    assert result["migration_accepted"] is False


def test_deleted_source_disposition_cannot_shrink_denominator(package):
    manifest = read_json(package / "manifest.json")
    removed = manifest["build"]["dispositions"].pop()
    manifest["build"]["source_mappings"] = [row for row in manifest["build"]["source_mappings"] if row["source_path"] != removed["source_path"]]
    seal(package, manifest)
    assert "missing_disposition" in codes(package)


@pytest.mark.parametrize("sql, expected", [
    ('SELECT "never_captured" AS "orders.display_region" FROM "analytics"."orders" LIMIT 1000', "query_schema_error"),
    ('SELECT * FROM "analytics"."orders"; DROP TABLE "analytics"."orders"', "unsafe_sql"),
    ('SELECT @@missing FROM "analytics"."orders"', "invalid_sql"),
    ('SELECT TODO FROM "analytics"."orders"', "placeholder_sql"),
])
def test_resealed_unsafe_or_unbound_sql_is_rejected(package, sql, expected):
    (package / "queries/1.sql").write_text(sql)
    seal(package, read_json(package / "manifest.json"))
    assert expected in codes(package)


def test_resealed_document_missing_field_is_rejected(package):
    mutate_documents(package, lambda document: document["queryPresentations"]["data"]["1"]["query"]["fields"].append("orders.never_captured"))
    assert "missing_query_field" in codes(package)


def test_resealed_control_scope_cannot_change_global_exclusion(package):
    mutate_documents(package, lambda document: document["controls"]["data"]["control_1"]["map"].update({"2": False}))
    assert "source_control_scope_changed" in codes(package)


def test_resealed_control_cannot_target_missing_tile(package):
    mutate_documents(package, lambda document: document["controls"]["data"]["control_1"]["map"].update({"missing": "orders.region"}))
    assert "invalid_control_scope" in codes(package)


def test_resealed_visibility_loss_is_rejected(package):
    path = package / "omni/model/analytics/orders.view"
    path.write_text(path.read_text().replace("hidden: true", "hidden: false"))
    seal(package, read_json(package / "manifest.json"))
    assert "visibility_changed" in codes(package)


def test_duplicate_yaml_key_is_not_last_value_wins(package):
    path = package / "omni/model/analytics/orders.view"
    path.write_text(path.read_text() + "table_name: attacker\n")
    seal(package, read_json(package / "manifest.json"))
    assert "invalid_document" in codes(package)


def test_duplicate_json_key_is_not_last_value_wins(package):
    path = package / "omni/document.create.json"
    path.write_text('{"name":"first",' + path.read_text()[1:])
    seal(package, read_json(package / "manifest.json"))
    assert "invalid_document" in codes(package)


def test_unlisted_files_and_escaping_paths_are_rejected(package):
    (package / "unlisted.sql").write_text("SELECT 1")
    manifest = read_json(package / "manifest.json")
    manifest["files"]["../outside.json"] = "0" * 64
    write_json(package / "manifest.json", manifest)
    assert {"unlisted_file", "unsafe_manifest_path"} <= codes(package)


def test_symlink_is_never_followed(package, tmp_path):
    outside = tmp_path / "outside.json"
    outside.write_text('{"password":"not-read"}')
    (package / "linked.json").symlink_to(outside)
    assert "symlink" in codes(package)


def test_resealed_credentials_and_authority_claims_are_rejected(package):
    target = read_json(package / "target.json")
    target["access_token"] = "fictional-secret-do-not-export"
    write_json(package / "target.json", target)
    manifest = read_json(package / "manifest.json")
    manifest["migration_accepted"] = True
    seal(package, manifest)
    assert {"embedded_credential", "invalid_authority"} <= codes(package)


def test_stale_review_and_unsealed_bytes_are_rejected(package):
    path = package / "queries/1.sql"
    path.write_text(path.read_text() + "\n")
    assert {"file_hash_mismatch", "stale_proposal_review"} <= codes(package)

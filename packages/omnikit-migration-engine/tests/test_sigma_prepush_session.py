"""Public command workflow tests; all approvals and data here are synthetic."""
import json
import socket
import sys
from pathlib import Path
from zipfile import ZipFile

import pytest

from omni_migrator.prepush.cli import main
from omni_migrator.prepush.session import Session, digest, reject_secrets, synthetic_taint

ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def fail(*args, **kwargs):
        raise AssertionError("Pre-push must not attempt a network connection")
    monkeypatch.setattr(socket, "create_connection", fail)
    monkeypatch.setattr(socket, "getaddrinfo", fail)
    monkeypatch.setattr(socket.socket, "connect", fail)


def prepared(tmp_path, mode="omni_semantic_reconstruction"):
    source, target = tmp_path / "source.json", tmp_path / "target.json"
    source.write_bytes((ROOT / "examples/retail-supported.json").read_bytes())
    target.write_bytes((ROOT / "examples/target.json").read_bytes())
    run = tmp_path / "run"
    assert main(["init", "--run-dir", str(run), "--source", str(source), "--target", str(target), "--synthetic"]) == 0
    assert main(["route", "--run-dir", str(run), "--mode", mode]) == 0
    return run, source, target


def accept(run, monkeypatch):
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda _: "accept")
    assert main(["review", "--run-dir", str(run)]) == 0


@pytest.mark.parametrize("mode", ["omni_semantic_reconstruction", "warehouse_first_refactor"])
def test_public_review_build_resume_validate_export(tmp_path, monkeypatch, mode):
    run, _, _ = prepared(tmp_path, mode)
    assert main(["build", "--run-dir", str(run)]) == 2  # review is mandatory
    accept(run, monkeypatch)
    assert main(["build", "--run-dir", str(run)]) == 0
    assert main(["validate", "--run-dir", str(run)]) == 0
    session = Session(run)  # reopening must retain actual persisted output
    path, result = session.validate_package()
    assert result["status"] == "offline_preflight_passed", result
    manifest = json.loads((path / "manifest.json").read_text())
    assert manifest["synthetic"] is True
    assert manifest["migration_accepted"] is False
    assert manifest["target_write_authority"] is False
    names = set(manifest["files"])
    assert "omni/document.create.json" in names
    assert any(name.endswith(".view") for name in names)
    assert any(name.startswith("dbt/") for name in names) == (mode == "warehouse_first_refactor")
    output = tmp_path / "reviewed.zip"
    assert main(["export", "--run-dir", str(run), "--output", str(output), "--purpose", "migration"]) == 0
    with ZipFile(output) as archive:
        assert set(archive.namelist()) == names | {"manifest.json"}
    assert main(["export", "--run-dir", str(run), "--output", str(output)]) == 2


def test_noninteractive_approval_refused(tmp_path, monkeypatch):
    run, _, _ = prepared(tmp_path)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    assert main(["review", "--run-dir", str(run)]) == 2
    assert Session(run).status()["review"] == "required"


@pytest.mark.parametrize("action", ["reject", "request_changes"])
def test_rejected_or_changes_requested_cannot_build(tmp_path, monkeypatch, action):
    run, _, _ = prepared(tmp_path)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda _: action)
    assert main(["review", "--run-dir", str(run)]) == 0
    assert main(["build", "--run-dir", str(run)]) == 2


def test_source_change_route_change_and_revocation_invalidate(tmp_path, monkeypatch):
    run, source, _ = prepared(tmp_path)
    accept(run, monkeypatch)
    payload = json.loads(source.read_text())
    payload["review_note"] = "new source revision"
    source.write_text(json.dumps(payload))
    assert main(["status", "--run-dir", str(run)]) == 2
    assert main(["import-source", "--run-dir", str(run), "--file", str(source)]) == 0
    assert Session(run).status()["review"] == "required"
    assert main(["route", "--run-dir", str(run), "--mode", "warehouse_first_refactor"]) == 0
    assert main(["revoke", "--run-dir", str(run), "--reason", "approval_withdrawn"]) == 0
    assert Session(run).status()["revoked"] is True
    assert main(["build", "--run-dir", str(run)]) == 2


@pytest.mark.parametrize("value", [{"refresh_token": "fictional-secret"}, {"token": "fictional-secret"}, {"note": "Bearer fictional-secret"}])
def test_secret_rejection(value):
    with pytest.raises(ValueError):
        reject_secrets(value)


@pytest.mark.parametrize("value", [{"evidence_mode": "synthetic_fixture"}, {"metadata": {"evidence_classification": "synthetic_fixture"}}, {"nested": [{"synthetic": True}]}])
def test_nested_synthetic_taint(value):
    assert synthetic_taint(value)


def test_tampered_object_or_event_rejected(tmp_path):
    run, _, _ = prepared(tmp_path)
    session = Session(run)
    row = next((run / "events").glob("*.json"))
    original = row.read_bytes()
    row.write_text(original.decode().replace('"local-os-user"', '"attacker"'))
    with pytest.raises(ValueError, match="integrity"):
        session.status()


def test_interrupted_build_is_retryable_without_deleting_files(tmp_path, monkeypatch):
    run, _, _ = prepared(tmp_path)
    accept(run, monkeypatch)
    from omni_migrator.prepush import session as module
    original = module.private_write
    def fail(path, value):
        if Path(path).name == "source.json":
            raise OSError("synthetic interrupted write")
        return original(path, value)
    with monkeypatch.context() as patch:
        patch.setattr(module, "private_write", fail)
        assert main(["build", "--run-dir", str(run)]) == 2
    assert main(["build", "--run-dir", str(run)]) == 0
    assert len(list(run.glob("package-*"))) == 2


def test_export_refuses_changed_bytes(tmp_path, monkeypatch):
    run, _, _ = prepared(tmp_path)
    accept(run, monkeypatch)
    assert main(["build", "--run-dir", str(run)]) == 0
    path, _ = Session(run).validate_package()
    (path / "queries/1.sql").write_text("select 999")
    output = tmp_path / "unsafe.zip"
    assert main(["export", "--run-dir", str(run), "--output", str(output)]) == 2
    assert not output.exists()


def test_import_context_calculates_hash_and_remains_unapproved(tmp_path):
    source = json.loads((ROOT / "examples/retail-supported.json").read_text())
    context = source.pop("prepush_context")
    context.pop("source_sha256")
    a, b, out = tmp_path / "source.json", tmp_path / "context.json", tmp_path / "enriched.json"
    a.write_text(json.dumps(source))
    b.write_text(json.dumps(context))
    assert main(["import-context", "--source", str(a), "--context", str(b), "--output", str(out)]) == 0
    enriched = json.loads(out.read_text())
    assert enriched["prepush_context"]["source_sha256"] == digest(source)
    assert "approval" not in enriched


@pytest.mark.parametrize("qualified", [False, True])
def test_configure_preserves_case_and_does_not_map_alias_as_physical(tmp_path, monkeypatch, qualified):
    from argparse import Namespace

    from omni_migrator.prepush.configure import configure
    answers = iter(["11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222", "Retail Review", "Analytics", "Orders", "Region", "Amount", "Status", "SigmaOrders"])
    target = tmp_path / "target.json"
    source = ROOT / "examples/retail-supported.json"
    if qualified:
        from omni_migrator.prepush.build import source_context_hash
        payload = json.loads(source.read_text())
        element = payload["dataModels"][0]["spec"]["pages"][0]["elements"][0]
        element["source"].pop("type")
        element["source"]["kind"] = "warehouse-table"
        for column in element["columns"]:
            if column["columnId"] != "region-alias":
                column["formula"] = f"[orders/{column['name']}]"
        payload["prepush_context"]["source_sha256"] = source_context_hash(payload)
        source = tmp_path / "qualified-source.json"
        source.write_text(json.dumps(payload))
    configure(Namespace(source=source, output=target), lambda _: next(answers))
    result = json.loads(target.read_text())
    relation, = result["relations"].values()
    assert relation["columns"] == {"region": "Region", "amount": "Amount", "status": "Status"}
    assert relation["schema"] == "Analytics"

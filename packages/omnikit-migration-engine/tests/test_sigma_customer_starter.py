"""Small offline checks for the customer walkthrough, using its bundled example."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import shutil
import socket
import sys

from omni_migrator.extractors.sigma.api import SigmaApi


def _starter(tmp_path, monkeypatch):
    source = Path(__file__).resolve().parents[3] / "customer" / "sigma"
    shutil.copy(source / "start.py", tmp_path / "start.py")
    shutil.copytree(source / "examples", tmp_path / "examples")
    monkeypatch.setattr(sys, "dont_write_bytecode", True)
    spec = importlib.util.spec_from_file_location("sigma_customer_starter", tmp_path / "start.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    def forbidden(*args, **kwargs):
        raise AssertionError("The offline starter must not open sockets or create a Sigma API client")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(SigmaApi, "__init__", forbidden)
    return module


def test_customer_check_imports_actual_cli_and_creates_no_outputs(tmp_path, monkeypatch, capsys):
    starter = _starter(tmp_path, monkeypatch)
    assert starter.main(["--check"]) == 0
    assert "Ready for the fictional offline walkthrough" in capsys.readouterr().out
    assert list(tmp_path.glob("demo-output-*")) == []
    assert not (tmp_path / "__pycache__").exists()
    assert "omni_migrator.orchestration.sigma_cli" in sys.modules
    (tmp_path / "examples" / starter.SNAPSHOT_NAME).write_text('{"sensitive": "not-demo"}')
    assert starter.main(["--check"]) == 1
    assert "not-demo" not in capsys.readouterr().err
    assert list(tmp_path.glob("demo-output-*")) == []


def test_both_demo_preferences_extract_only_fictional_source_into_new_folders(tmp_path, monkeypatch):
    starter = _starter(tmp_path, monkeypatch)
    first_files = None
    for route, mode in (
        ("direct", "omni_semantic_reconstruction"),
        ("modeled", "warehouse_first_refactor"),
    ):
        previous = set(tmp_path.glob("demo-output-*"))
        assert starter.main(["--demo", "--route", route]) == 0
        folder, = set(tmp_path.glob("demo-output-*")) - previous
        assert folder.stat().st_mode & 0o777 == 0o700
        assert {file.name for file in folder.iterdir()} == {
            "routing-prompt.json", "source-extraction.json", "demo-summary.json", "READ-MY-RESULTS.txt"
        }
        for file in folder.iterdir():
            assert file.stat().st_mode & 0o777 == 0o600
        prompt = json.loads((folder / "routing-prompt.json").read_text())
        assert prompt["state"] == "awaiting_human_choice"
        assert prompt["default_mode"] is None
        summary = json.loads((folder / "demo-summary.json").read_text())
        assert summary["route_preference"] == mode
        assert summary["extracted_counts"] == {
            "source_tables": 1, "source_fields": 2, "dashboard_definitions": 0
        }
        assert all(summary[field] is False for field in (
            "route_preference_is_approval", "routing_decision_created", "approval_created",
            "target_write_authority", "migration_completed", "ai_used", "live_evidence_collected"
        ))
        extraction = json.loads((folder / "source-extraction.json").read_text())
        assert extraction["source"] == "sigma"
        assert extraction["acquisition"]["mode"] == "manual"
        assert extraction["model"]["views"][0]["source_id"] == "fictional-orders-table"
        assert extraction["model"]["views"][0]["connection"]["omni_connection_id"] is None
        results_note = (folder / "READ-MY-RESULTS.txt").read_text()
        assert "No Omni content was created" in results_note
        assert "SETUP-AND-USAGE.md" in results_note
        assert "your migration operator" not in results_note
        if first_files is None:
            first_files = {file: file.read_bytes() for file in folder.iterdir()}
        else:
            assert all(file.read_bytes() == content for file, content in first_files.items())
    assert len(list(tmp_path.glob("demo-output-*"))) == 2


def test_missing_choice_and_sensitive_arguments_never_select_or_echo(tmp_path, monkeypatch, capsys):
    starter = _starter(tmp_path, monkeypatch)
    assert starter.main(["--demo"]) == 1
    assert starter.main(["--demo", "--route", "sensitive-credential-value"]) == 1
    assert "sensitive-credential-value" not in capsys.readouterr().err
    answers = iter(["", "not-a-choice", "q"])
    monkeypatch.setattr("builtins.input", lambda _: next(answers))
    assert starter.main([]) == 2
    assert "Nothing has been selected" in capsys.readouterr().out
    assert list(tmp_path.glob("demo-output-*")) == []

"""Synthetic operator input through the real configure, CLI and Session boundaries.

These automated interactions are not evidence of a real platform-owner walkthrough.
No target API, credential loading or live approval is involved.
"""
from __future__ import annotations

import json
import socket
from pathlib import Path

import pytest

from omni_migrator.prepush import cli
from omni_migrator.prepush.configure import configure
from omni_migrator.prepush.reuse import canonical_hash, source_fields
from omni_migrator.prepush.session import Session, digest, private_write, read_json
from tests.test_sigma_topic_reuse import reuse_target

ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture(autouse=True)
def no_connections(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("Guided local configuration must not connect to a target")
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)


@pytest.fixture
def guided_inputs(tmp_path):
    source = read_json(ROOT / "examples/retail-supported.json")
    target = reuse_target(source)
    profile = {"schema_version": "sigma-migration-profile.v1", "source_mode": "snapshot",
               "route": "omni_semantic_reconstruction", "allowed_changes": "dashboard_only",
               "target_auth": "offline"}
    source_path, profile_path = tmp_path / "source.json", tmp_path / "profile.json"
    inventory_path = tmp_path / "topic-inventory.json"
    private_write(source_path, source)
    private_write(profile_path, profile)
    private_write(inventory_path, target["existing_topic"]["inventory"])
    return source, target, source_path, profile_path, inventory_path


def configure_arguments(source_path, profile_path, inventory_path, output):
    return cli.parser().parse_args([
        "configure", "--source", str(source_path), "--profile", str(profile_path),
        "--topic-inventory", str(inventory_path), "--output", str(output)])


def answers_for(source, target, *, skip=None):
    answers = [target[key] for key in ("model_id", "connection_id", "document_name")]
    for locator in source_fields(source):
        if locator == skip:
            answers.append("")
            continue
        binding = target["existing_topic"]["field_mappings"][locator]
        answers.append(binding["target_field"])
        answers.extend(binding["compatibility"][key] for key in ("grain", "filters", "metric", "joins"))
    iterator, prompts = iter(answers), []

    def ask(prompt):
        prompts.append(prompt)
        return next(iterator)

    return ask, prompts, iterator


def test_guided_configure_creates_exact_hash_bound_topic_mapping(guided_inputs, tmp_path):
    source, target, source_path, profile_path, inventory_path = guided_inputs
    output = tmp_path / "configured.json"
    ask, prompts, answers = answers_for(source, target)
    result = configure(configure_arguments(source_path, profile_path, inventory_path, output), ask)
    assert result["status"] == "topic_mapping_created_requires_review"
    assert result["target_write_authority"] is False
    assert read_json(output) == target
    assert output.stat().st_mode & 0o777 == 0o600
    assert len(prompts) == 3 + 5 * len(source_fields(source))
    assert "Exact target field ID" in prompts[3]
    assert "compatible grain" in prompts[4]
    assert next(answers, None) is None


def test_scope_configure_review_build_report_through_public_cli(guided_inputs, tmp_path, monkeypatch):
    source, target, source_path, profile_path, inventory_path = guided_inputs
    scoped_path, target_path, run_dir = tmp_path / "scoped.json", tmp_path / "target.json", tmp_path / "run"

    def run(*arguments):
        return cli.run(cli.parser().parse_args(list(map(str, arguments))))

    scoped = run("scope", "--source", source_path, "--output", scoped_path,
                 "--workbook-id", "fictional-overview", "--chart-id", "revenue-chart")
    assert scoped["status"] == "scope_created_requires_review"
    assert scoped["scope"]["selected_chart_ids"] == ["revenue-chart"]
    assert scoped["scope"]["excluded_chart_ids"] == ["revenue-table"]
    assert len(read_json(scoped_path)["workbooks"][0]["pages"][0]["elements"]) == 2
    ask, _, answers = answers_for(source, target)
    monkeypatch.setattr(cli, "terminal_answer", ask)
    configured = cli.run(configure_arguments(scoped_path, profile_path, inventory_path, target_path))
    assert configured["status"] == "topic_mapping_created_requires_review"
    assert next(answers, None) is None
    state = run("init", "--run-dir", run_dir, "--source", scoped_path,
                "--target", target_path, "--profile", profile_path, "--synthetic")
    assert state["review"] == "required"
    initial = run("report", "--run-dir", run_dir)
    assert initial["counts"]["selected_charts"] == 1
    assert initial["counts"]["excluded_charts"] == 1
    assert initial["resume"]["operation"] == "review"
    assert initial["package_validation"] is None
    monkeypatch.setattr(cli, "terminal_answer", lambda _: "accept")
    assert run("review", "--run-dir", run_dir)["review"] == "accept"
    built = run("build", "--run-dir", run_dir)
    assert built["status"] == "offline_preflight_passed", built
    manifest = read_json(Path(built["package"]) / "manifest.json")
    assert not any(name.startswith(("omni/model/", "dbt/")) or name.endswith(".sql") for name in manifest["files"])
    report = run("report", "--run-dir", run_dir)
    charts = {row["source_id"]: row for row in report["charts"]}
    assert charts["revenue-chart"]["offline_validation"] == "offline_preflight_passed"
    assert charts["revenue-table"]["offline_validation"] == "not_in_pilot"
    assert report["resume"]["operation"] == "export"
    assert report["target_write_authority"] is report["migration_accepted"] is False
    assert report["synthetic"] is True
    assert report["live_validation"] == "not_performed"


def test_topic_inventory_revision_invalidates_real_session_review_and_package(guided_inputs, tmp_path):
    source, target, source_path, profile_path, inventory_path = guided_inputs
    output = tmp_path / "configured.json"
    ask, _, _ = answers_for(source, target)
    configure(configure_arguments(source_path, profile_path, inventory_path, output), ask)
    session = Session.initialize(tmp_path / "run", source_path, output, synthetic=True)
    session.choose("omni_semantic_reconstruction")
    session.review("accept", expected_proposal_hash=digest(session.proposal()))
    built = session.build_package()
    assert built["status"] == "offline_preflight_passed"
    revision = read_json(output)
    revision["existing_topic"]["inventory"]["captured_at"] = "2026-10-09T13:00:00Z"
    revision["existing_topic"]["inventory_sha256"] = canonical_hash(revision["existing_topic"]["inventory"])
    output.write_text(json.dumps(revision))  # Simulate the operator changing the reviewed input.
    with pytest.raises(ValueError, match="Imported target changed"):
        session.state()
    session.import_revision("target", output)
    state = Session(session.root).status()
    assert state["review"] == "required" and state["package"] is None
    assert Path(built["package"]).is_dir()  # Prior evidence is retained, never overwritten.
    with pytest.raises(ValueError, match="Accept the current proposal"):
        session.build_package()
    session.review("accept", expected_proposal_hash=digest(session.proposal()))
    assert session.build_package()["status"] == "offline_preflight_passed"


def test_configure_allows_unresolved_mapping_without_claiming_readiness(guided_inputs, tmp_path):
    source, target, source_path, profile_path, inventory_path = guided_inputs
    output = tmp_path / "configured.json"
    missing = "data-model:fictional-retail/element:orders/metric:revenue"
    ask, _, _ = answers_for(source, target, skip=missing)
    result = configure(configure_arguments(source_path, profile_path, inventory_path, output), ask)
    assert result["status"] == "topic_mapping_created_requires_review"
    assert missing not in read_json(output)["existing_topic"]["field_mappings"]
    session = Session.initialize(tmp_path / "run", source_path, output, synthetic=True)
    session.choose("omni_semantic_reconstruction")
    dispositions = {row["source_id"]: row for row in session.proposal()["dispositions"]}
    assert dispositions["revenue"]["status"] == dispositions["revenue-chart"]["status"] == "blocked"


def test_configure_rejects_topic_from_another_model_before_saving(guided_inputs, tmp_path):
    source, target, source_path, profile_path, inventory_path = guided_inputs
    output = tmp_path / "configured.json"
    target["model_id"] = "00000000-0000-0000-0000-000000000001"
    ask, prompts, _ = answers_for(source, target)
    with pytest.raises(ValueError, match="does not match"):
        configure(configure_arguments(source_path, profile_path, inventory_path, output), ask)
    assert len(prompts) == 3
    assert not output.exists()

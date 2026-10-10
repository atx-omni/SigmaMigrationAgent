"""Progress comes from persisted local artifacts and independent validation."""
from copy import deepcopy
import json
from pathlib import Path

import pytest

from omni_migrator.prepush.report import migration_report, report_run
from omni_migrator.prepush.scope import create_scope
from omni_migrator.prepush.session import Session, digest

ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture
def source():
    return json.loads((ROOT / "examples/retail-supported.json").read_text())


def test_unbuilt_report_has_no_validation_or_execution_claims(source):
    report = migration_report(source)
    assert report["counts"]["selected_charts"] == 2
    assert all(row["preparation"] == "not_built" and row["offline_validation"] == "not_performed" for row in report["charts"])
    assert report["resume"]["operation"] == "route"
    assert report["discrepancies"] == []
    assert report["duration"] == report["cost"] == "not_measured"
    assert report["target_write_authority"] is report["migration_accepted"] is False


def test_report_separates_compilation_from_validation_and_live_parity(source):
    scoped = create_scope(source, workbook_id="fictional-overview", chart_ids=["revenue-chart"])
    proposal = {"dispositions": [{"source_path": "/workbooks/0/pages/0/elements/0", "status": "implemented",
                                "reason": "Compiled", "target_paths": ["queries/1.sql"]}],
                "source_mappings": [{"source_path": "/workbooks/0/pages/0/elements/0",
                                     "target_object_ref": "queryPresentations.data.1"}]}
    state = {"route": "omni_semantic_reconstruction", "review": "accept"}
    report = migration_report(scoped, proposal, state=state)
    assert report["charts"][0]["preparation"] == "compiled"
    assert report["charts"][0]["offline_validation"] == "not_performed"
    assert report["charts"][1]["selection"] == "excluded"
    assert report["counts"]["compiled_selected_charts"] == 1
    assert report["resume"]["operation"] == "build"
    result = {"status": "blocked", "issues": [{"code": "query_schema_error", "path": "queries/1.sql", "message": "Unknown column"}]}
    report = migration_report(scoped, proposal, result, state)
    assert report["charts"][0]["offline_validation"] == "blocked"
    assert report["discrepancies"] == result["issues"]
    assert report["charts"][0]["live_validation"] == "not_performed"


def test_report_run_reopens_artifacts_and_rejects_source_drift(tmp_path, source):
    source_path, target_path = tmp_path / "source.json", tmp_path / "target.json"
    source_path.write_text(json.dumps(source))
    target_path.write_bytes((ROOT / "examples/target.json").read_bytes())
    session = Session.initialize(tmp_path / "run", source_path, target_path, synthetic=True)
    session.choose("omni_semantic_reconstruction")
    # Synthetic local test decision only; public operator review remains interactive.
    session.review("accept", expected_proposal_hash=digest(session.proposal()))
    session.build_package()
    before = report_run(tmp_path / "run")
    assert before["package_validation"]["status"] == "offline_preflight_passed"
    assert before["resume"]["operation"] == "export"
    assert all(row["offline_validation"] == "offline_preflight_passed" for row in before["charts"])
    assert before["synthetic"] is True
    assert report_run(tmp_path / "run") == before
    changed = deepcopy(source)
    changed["name"] = "different capture"
    source_path.write_text(json.dumps(changed))
    with pytest.raises(ValueError, match="changed"):
        report_run(tmp_path / "run")


def test_report_does_not_reuse_revoked_or_revised_work(tmp_path, source):
    source_path, target_path = tmp_path / "source.json", tmp_path / "target.json"
    source_path.write_text(json.dumps(source))
    target_path.write_bytes((ROOT / "examples/target.json").read_bytes())
    session = Session.initialize(tmp_path / "run", source_path, target_path, synthetic=True)
    session.choose("omni_semantic_reconstruction")
    session.revoke("approval_withdrawn")
    report = report_run(tmp_path / "run")
    assert report["resume"]["operation"] == "route"
    assert report["package_validation"] is None
    assert all(row["preparation"] == "not_built" for row in report["charts"])

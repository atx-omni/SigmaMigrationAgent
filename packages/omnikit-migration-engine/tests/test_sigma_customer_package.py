"""Bounded packaging checks: exact ZIP inventory, integrity, and safe inclusion."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from zipfile import ZipFile

import pytest


ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location("sigma_packager", ROOT / "scripts/build_sigma_customer_package.py")
PACKAGER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PACKAGER)


def test_distribution_inventory_and_reproducibility(tmp_path):
    first = tmp_path / "first.zip"
    second = tmp_path / "second.zip"
    a = PACKAGER.build(ROOT, first, "test-pilot")
    b = PACKAGER.build(ROOT, second, "test-pilot")
    assert a["sha256"] == b["sha256"]
    assert PACKAGER.verify(first)["verified"]
    with ZipFile(first) as archive:
        prefix = "Sigma-to-Omni-Pilot/"
        manifest = json.loads(archive.read(prefix + "PACKAGE-MANIFEST.json"))
        names = {item["path"] for item in manifest["files"]}
        assert {"START-HERE.html", "start.py", "SETUP-AND-USAGE.md", "engine/LICENSE",
                "engine/PROVENANCE.json", "engine/src/omni_migrator/orchestration/sigma_workflow.py",
                "contracts/common-definitions.v1.schema.json"} <= names
        assert any(name.startswith("engine/src/omni_migrator/rulebook/") for name in names)
        assert not any("/tests/" in name or "/.git/" in name or "/docs/" in name for name in names)
        skill_paths = {
            ".agents/skills/sigma-to-omni-migration/SKILL.md",
            ".agents/skills/sigma-to-omni-migration/agents/openai.yaml",
            ".agents/skills/sigma-to-omni-migration/references/runtime-workflow.md",
        }
        assert {name for name in names if name.startswith(".agents/skills/")} == skill_paths
        records = {item["path"]: item for item in manifest["files"]}
        for name in skill_paths:
            source = (ROOT / name).read_bytes()
            assert archive.read(prefix + name) == source
            assert records[name]["source_path"] == name
            assert records[name]["source_sha256"] == PACKAGER.digest(source)
            assert records[name]["sha256"] == PACKAGER.digest(source)
            assert records[name]["distribution_notice_added"] is False
        assert manifest["human_distribution_review_required"] is True
    with pytest.raises(ValueError, match="already exists"):
        PACKAGER.build(ROOT, first, "test-pilot")


@pytest.mark.parametrize("missing_name", PACKAGER.SKILL_FILES)
def test_missing_required_canonical_skill_file_blocks_distribution(tmp_path, monkeypatch, missing_name):
    missing = ROOT / missing_name
    assert missing.is_file(), "Run packaging checks after the canonical skill files exist"
    original_is_file = Path.is_file

    def is_file(path):
        return False if path == missing else original_is_file(path)

    # Simulate absence without moving or deleting an authored repository file.
    monkeypatch.setattr(Path, "is_file", is_file)
    destination = tmp_path / "missing-skill.zip"
    with pytest.raises(ValueError, match="missing or oversized package input") as error:
        PACKAGER.build(ROOT, destination, "test-missing-skill")
    assert missing_name in str(error.value)
    assert not destination.exists()


def test_skill_selection_does_not_glob_extra_files(tmp_path):
    unexpected = tmp_path / ".agents/skills/sigma-to-omni-migration/unreviewed.md"
    unexpected.parent.mkdir(parents=True)
    unexpected.write_text("Must not enter the allowlisted distribution.\n")
    selected = PACKAGER.selection(tmp_path)
    assert {name for name in selected if name.startswith(".agents/skills/")} == set(PACKAGER.SKILL_FILES)
    assert unexpected not in selected.values()


def test_scanner_rejects_private_values_and_symbolic_links_without_echoing(tmp_path):
    secret = tmp_path / "source.py"
    # Generated fixture is deliberately not a usable credential or a customer value.
    fake_value = "sk-" + "A" * 36
    secret.write_text(f"key = '{fake_value}'\n")
    with pytest.raises(ValueError, match="provider_key") as error:
        PACKAGER.read_safe(tmp_path, secret, "source.py")
    assert fake_value not in str(error.value)
    secret.write_text("safe source\n")
    link = tmp_path / "linked.py"
    link.symlink_to(secret)
    with pytest.raises(ValueError, match="symbolic link"):
        PACKAGER.read_safe(tmp_path, link, "linked.py")


def test_html_guide_links_are_bundled_and_contains_no_remote_assets():
    import re
    from urllib.parse import urlsplit

    selected = PACKAGER.selection(ROOT)
    html = selected["START-HERE.html"].read_text()
    for link in re.findall(r'href="([^"]+)"', html):
        if link.startswith("#"):
            assert f'id="{link[1:]}"' in html
        elif link.startswith("https://"):
            assert urlsplit(link).hostname in {"www.python.org", "help.sigmacomputing.com",
                                               "developers.openai.com", "docs.omni.co"}
        else:
            assert link in selected
    assert "<script" not in html and "<iframe" not in html
    assert not re.search(r'src="https?://', html)
    assert "DRAFT — requires explicit SE/AE review" in html
    assert "Ask your administrator" not in html
    assert "product/integration gaps" in html


def test_operator_html_matches_the_complete_authored_guide():
    spec = importlib.util.spec_from_file_location("sigma_guide", ROOT / "scripts/render_sigma_operator_guide.py")
    renderer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(renderer)
    markdown = renderer.SOURCE.read_text()
    assert renderer.TARGET.read_text() == renderer.render(markdown)
    assert markdown.count("\n## ") >= 12

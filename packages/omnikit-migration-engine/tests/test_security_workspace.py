"""Private operational data must not become source-control input."""
from pathlib import Path
import os
import stat
import subprocess

import pytest

from omni_migrator.security.workspace import assert_private_output, prepare_workspace


def git(root: Path, *args: str):
    return subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True)


def test_new_workspace_is_private_and_covers_renamed_files(tmp_path):
    work = prepare_workspace(tmp_path / "private" / "migration")
    assert stat.S_IMODE(work.stat().st_mode) == 0o700
    assert stat.S_IMODE(work.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE((work / ".gitignore").stat().st_mode) == 0o600
    git(work, "init", "-q")
    for name in ("renamed.json", "target.json", "exports/full.zip", ".env", "run/state.json"):
        assert_private_output(work / name)
        assert git(work, "check-ignore", "--", name).stdout.strip()
    assert prepare_workspace(work) == work


def test_unignored_and_tracked_destinations_rejected_before_writes(tmp_path):
    git(tmp_path, "init", "-q")
    with pytest.raises(ValueError, match="Git-trackable"):
        prepare_workspace(tmp_path / "unsafe")
    assert not (tmp_path / "unsafe").exists()
    (tmp_path / ".gitignore").write_text("private/\n")
    work = prepare_workspace(tmp_path / "private")
    tracked = work / "original.json"
    tracked.write_text("original evidence")
    git(tmp_path, "add", "-f", "private/original.json")
    with pytest.raises(ValueError, match="tracked"):
        assert_private_output(tracked)
    with pytest.raises(ValueError, match="tracked"):
        prepare_workspace(work)
    assert tracked.read_text() == "original evidence"


def test_shared_or_existing_conflicting_folders_are_not_silently_changed(tmp_path):
    shared = tmp_path / "shared"
    shared.mkdir(mode=0o755)
    with pytest.raises(ValueError, match="permissions 700"):
        prepare_workspace(shared)
    assert stat.S_IMODE(shared.stat().st_mode) == 0o755
    assert not (shared / ".gitignore").exists()
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    (private / ".gitignore").write_text(".env\n")
    with pytest.raises(ValueError, match="all evidence"):
        prepare_workspace(private)
    assert (private / ".gitignore").read_text() == ".env\n"


def test_symlink_and_parent_symlink_rejected(tmp_path):
    original = tmp_path / "original"
    original.mkdir(mode=0o700)
    link = tmp_path / "link"
    link.symlink_to(original, target_is_directory=True)
    with pytest.raises(ValueError, match="symbolic"):
        prepare_workspace(link)
    with pytest.raises(ValueError, match="symbolic"):
        assert_private_output(link / "renamed.json")
    assert not (original / "renamed.json").exists()


def test_output_under_private_parent_does_not_overwrite_existing_evidence(tmp_path):
    evidence = tmp_path / "evidence.json"
    evidence.write_text("unchanged")
    assert_private_output(evidence)
    assert evidence.read_text() == "unchanged"
    assert_private_output(tmp_path / "new" / "nested" / "output.json")
    assert stat.S_IMODE((tmp_path / "new").stat().st_mode) == 0o700
    assert stat.S_IMODE((tmp_path / "new/nested").stat().st_mode) == 0o700


def test_workspace_ignore_fifo_rejected_without_opening(tmp_path):
    os.mkfifo(tmp_path / ".gitignore", mode=0o600)
    with pytest.raises(ValueError, match="regular file"):
        prepare_workspace(tmp_path)

"""Private operational storage; source checkouts are not migration workspaces.

This prevents accidental publication, not a hostile process under the same OS user.
No evidence is relocated, chmodded, removed, or untracked automatically.
"""
from __future__ import annotations

import os
from pathlib import Path
import stat
import subprocess

from omni_migrator.security.transport import ResourceLimitError, bounded_process


def default_workspace() -> Path:
    return Path.home() / ".sigma-migrate" / "workspaces" / "migration"


def _safe_path(path: Path) -> Path:
    path = Path(os.path.abspath(path))
    if any(part.is_symlink() for part in (path, *path.parents)):
        raise ValueError("Operational storage cannot use symbolic links")
    return path


def _repository(path: Path) -> Path | None:
    for parent in (path, *path.parents):
        if (parent / ".git").exists():
            return parent
    return None


def _git(root: Path, *arguments: str) -> subprocess.CompletedProcess:
    # Read-only commands, no hooks/fsmonitor; ignore caller-supplied Git overrides.
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    try:
        return bounded_process(["git", "--no-optional-locks", "-c", "core.fsmonitor=false", "-C", str(root),
                                *arguments], env=env, timeout=10, stdout_limit=1024 * 1024, stderr_limit=8192)
    except (OSError, subprocess.TimeoutExpired, ResourceLimitError):
        raise ValueError("Cannot verify Git protection for operational storage; choose a private directory outside Git") from None


def _assert_git_protected(path: Path, *, directory: bool = False) -> None:
    root = _repository(path if path.is_dir() else path.parent)
    if root is None:
        return
    relative = path.relative_to(root).as_posix()
    tracked = _git(root, "ls-files", "-z", "--", relative)
    if tracked.returncode or tracked.stdout:
        raise ValueError("Operational destination is tracked or Git status cannot be verified; use a private workspace outside the checkout")
    ignored = _git(root, "check-ignore", "--quiet", "--no-index", "--", relative + ("/" if directory else ""))
    if ignored.returncode != 0:
        raise ValueError("Operational destination is Git-trackable; use setup's private workspace, not the source checkout")


def _mkdir_private(path: Path) -> None:
    missing = []
    current = path
    while not current.exists():
        missing.append(current)
        current = current.parent
    for directory in reversed(missing):
        directory.mkdir(mode=0o700)


def _assert_owner_private(directory: Path) -> None:
    info = directory.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError("Operational directory must be owned by you with permissions 700; use a new private setup directory")


def assert_private_output(path: Path, *, directory: bool = False) -> None:
    """Require ignored/untracked storage before creation; never alter an existing file."""
    path = _safe_path(path)
    _assert_git_protected(path, directory=directory)
    _mkdir_private(path.parent)
    _assert_owner_private(path.parent)
    if directory and path.exists():
        _assert_owner_private(path)


def prepare_workspace(directory: Path) -> Path:
    """Create a private workspace and protect every descendant if Git is later used."""
    directory = _safe_path(directory)
    # For in-checkout workspaces require the parent repository to ignore the
    # whole directory before we write even its protective .gitignore.
    _assert_git_protected(directory, directory=True)
    _mkdir_private(directory)
    _assert_owner_private(directory)
    ignore = directory / ".gitignore"
    if ignore.is_symlink():
        raise ValueError("Workspace ignore file cannot be a symbolic link")
    if not ignore.exists():
        fd = os.open(ignore, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write("# Private migration workspace: never commit operational evidence.\n*\n!.gitignore\n")
    else:
        # Do not overwrite user rules or claim an arbitrary ignore file is safe.
        if not ignore.is_file() or ignore.stat().st_size > 4096:
            raise ValueError("Existing workspace ignore file must be a small regular file")
        with ignore.open("rb") as stream:
            data = stream.read(4097)
        if len(data) > 4096:
            raise ValueError("Existing workspace ignore file exceeds size limit")
        rules = [line.strip() for line in data.decode("utf-8").splitlines()
                 if line.strip() and not line.lstrip().startswith("#")]
        if rules not in (["*"], ["*", "!.gitignore"]):
            raise ValueError("Existing workspace ignore rules do not protect all evidence; preserve it and select a new setup directory")
    return directory

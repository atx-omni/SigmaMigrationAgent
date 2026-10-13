#!/usr/bin/env python3
"""Reject partial lock updates, unlocked entries and pyproject/lock drift."""
from __future__ import annotations

import json
from pathlib import Path
import re
import tomllib

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

ROOT = Path(__file__).resolve().parents[1]
ENGINE = ROOT / "packages/omnikit-migration-engine"


def parse_lock(path: Path) -> dict[str, tuple[str, frozenset[str]]]:
    entries = {}
    for line in path.read_text().replace("\\\n", " ").splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        match = re.fullmatch(r"([A-Za-z0-9_.-]+)==([^\s;]+)((?:\s+--hash=sha256:[a-f0-9]{64})+)\s*", line)
        if not match:
            raise ValueError("Every dependency must use one exact version and SHA256 hashes")
        name = canonicalize_name(match[1])
        if name in entries:
            raise ValueError("Duplicate locked dependency")
        entries[name] = (match[2], frozenset(re.findall(r"--hash=sha256:([a-f0-9]{64})", match[3])))
    if not entries:
        raise ValueError("Empty dependency lock")
    return entries


def check(engine: Path = ENGINE) -> dict:
    locks = {kind: parse_lock(engine / f"requirements-{kind}.lock")
             for kind in ("runtime", "build", "dev")}
    for kind in ("runtime", "build"):
        for name, version_and_hashes in locks[kind].items():
            if locks["dev"].get(name) != version_and_hashes:
                raise ValueError("Runtime/build and development lock bytes or versions diverge")
    project = tomllib.loads((engine / "pyproject.toml").read_text())
    requirements = {"runtime": project["project"]["dependencies"],
                    "build": project["build-system"]["requires"],
                    "dev": project["project"]["optional-dependencies"]["dev"]}
    for kind, items in requirements.items():
        for value in items:
            requirement = Requirement(value)
            actual = locks[kind].get(canonicalize_name(requirement.name))
            if requirement.url or actual is None or actual[0] not in requirement.specifier:
                raise ValueError("Project dependencies differ from reviewed locks")
    for kind in ("runtime", "build", "dev"):
        for line in (engine / f"requirements-{kind}.in").read_text().splitlines():
            if not line.strip() or line.lstrip().startswith(("#", "-r ")):
                continue
            requirement = Requirement(line)
            actual = locks[kind].get(canonicalize_name(requirement.name))
            if requirement.url or actual is None or actual[0] not in requirement.specifier:
                raise ValueError("Reviewed dependency inputs differ from generated locks")
    return {"status": "passed", "locks": {kind: len(entries) for kind, entries in locks.items()}}


if __name__ == "__main__":
    try:
        print(json.dumps(check()))
    except (ValueError, OSError):
        print(json.dumps({"status": "blocked", "reason": "Dependency lock consistency failed"}))
        raise SystemExit(1) from None

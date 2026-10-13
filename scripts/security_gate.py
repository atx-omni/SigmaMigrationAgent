#!/usr/bin/env python3
"""Fail-closed secret/confidential-artifact gate over exact staged or release bytes.

Exceptions are reviewed exact-file hashes with a narrow rule and an expiry; paths
alone never exempt fixtures. Findings do not print filenames or matched content.
"""
from __future__ import annotations

import argparse
from datetime import date
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packages/omnikit-migration-engine/src"))

from omni_migrator.security.scanner import SecurityScanError, scan_bytes  # noqa: E402
from omni_migrator.security.transport import bounded_process  # noqa: E402

MAX_FILE = 25 * 1024 * 1024
MAX_REPOSITORY = 150 * 1024 * 1024
EXCEPTIONS = ".github/security-exceptions.json"
OPERATIONAL_SCHEMAS = (
    "sigma-migration-profile", "sigma-prepush-context", "sigma-migration-scope",
    "sigma-prepush-manifest", "sigma-capability-spike-bundle", "sigma-data-model-snapshot",
    "sigma-workbook-graph", "omni-topic-inventory", "sigma-egress-proposal",
)


def git(root: Path, *args: str) -> bytes:
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    result = bounded_process(["git", "--no-optional-locks", "-c", "core.fsmonitor=false",
                              "-C", str(root), *args], env=env,
                             stdout_limit=MAX_FILE, timeout=15)
    if result.returncode:
        raise ValueError("Git inspection failed; security gate is blocked")
    return result.stdout


def confidential_artifact(data: bytes, filename: str) -> bool:
    """Recognize operational content independently of its filename or extension."""
    parts = Path(filename).parts
    if any(part.startswith(".env") for part in parts) or filename.endswith(
        (".sqlite", ".sqlite3", ".db", ".pem", ".key")
    ):
        return True
    if data.startswith(b"SQLite format 3\x00"):
        return True
    try:
        value = json.loads(data)
    except (ValueError, UnicodeError, RecursionError):
        # Event stores and formatted YAML must not bypass checks by renaming.
        for line in data.splitlines():
            if line.lstrip().startswith(b"{"):
                try:
                    if _confidential_value(json.loads(line)):
                        return True
                except (ValueError, UnicodeError, RecursionError):
                    pass
        return bool(re.search(
            rb'''(?m)^\s*(?:"?(?:tenant_ref|model_egress_approval_ref)"?)\s*:\s*["']''', data))
    return _confidential_value(value)


def _confidential_value(value) -> bool:
    pending = [value]
    visited = 0
    while pending:
        visited += 1
        if visited > 200000:
            raise ValueError("Operational artifact scan exceeds its node budget")
        item = pending.pop()
        if isinstance(item, dict):
            keys = set(item)
            if ({"workbooks", "dataModels"} <= keys and isinstance(item["workbooks"], list)
                    or {"model_id", "connection_id", "document_name"} <= keys
                    and isinstance(item["model_id"], str)
                    or {"tenant_ref", "run_id"} <= keys and isinstance(item["tenant_ref"], str)
                    or {"previous_hash", "event_hash"} <= keys
                    or "_prepush_capture" in keys or "_migration_scope" in keys
                    or any(str(item.get("schema_version", item.get("schema", ""))).startswith(prefix)
                           for prefix in OPERATIONAL_SCHEMAS)):
                return True
            pending.extend(item.values())
        elif isinstance(item, list):
            pending.extend(item)
    return False


def exception_rules(raw: bytes, *, today: date) -> dict[tuple[str, str], set[str]]:
    value = json.loads(raw)
    if value.get("schema_version") != "sigma-security-exceptions.v1":
        raise ValueError("Invalid security exceptions policy")
    result: dict[tuple[str, str], set[str]] = {}
    for item in value["entries"]:
        if (set(item) != {"path", "sha256", "rules", "reason", "expires"}
                or not re.fullmatch(r"[a-f0-9]{64}", item["sha256"])
                or not item["reason"].strip()
                or date.fromisoformat(item["expires"]) < today
                or not item["rules"]
                or not set(item["rules"]) <= {"confidential_artifact", "credential_assignment",
                                             "credential_property", "credential_format",
                                             "credential_url"}):
            raise ValueError("Invalid or expired exact-byte security exception")
        key = (item["path"], item["sha256"])
        if key in result:
            raise ValueError("Duplicate security exception")
        result[key] = set(item["rules"])
    return result


def inspect(root: Path, *, staged: bool = False, today: date | None = None) -> dict:
    today = today or date.today()
    paths = git(root, "ls-files", "-z", "--cached").split(b"\x00")
    if not staged:
        paths += git(root, "ls-files", "-z", "--others", "--exclude-standard").split(b"\x00")
    names = sorted({name.decode("utf-8") for name in paths if name})
    if staged:
        index = git(root, "ls-files", "--stage", "-z").split(b"\x00")
        if any(record and record[:6] not in {b"100644", b"100755"} for record in index):
            raise ValueError("Security gate refuses symbolic links and submodules in staged source")
    def read(name: str) -> bytes:
        if staged:
            return git(root, "show", f":{name}")
        path = root / name
        if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_FILE:
            raise ValueError("Security gate requires bounded regular source files")
        return path.read_bytes()
    rules = exception_rules(read(EXCEPTIONS), today=today) if EXCEPTIONS in names else {}
    findings = []
    total = 0
    for name in names:
        data = read(name)
        total += len(data)
        if total > MAX_REPOSITORY:
            raise ValueError("Repository security scan exceeds the bounded source budget")
        digest = hashlib.sha256(data).hexdigest()
        exempt = rules.get((name, digest), set())
        file_id = hashlib.sha256(name.encode()).hexdigest()[:16]
        for finding in scan_bytes(data, filename=name):
            if finding.code not in exempt:
                findings.append({"file_id": file_id, "code": finding.code, "line": finding.line})
        if confidential_artifact(data, name) and "confidential_artifact" not in exempt:
            findings.append({"file_id": file_id, "code": "confidential_artifact", "line": 0})
        if len(findings) > 100:
            break
    return {"status": "blocked" if findings else "passed", "files_scanned": len(names),
            "findings": findings[:100], "staged_bytes": staged}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--staged", action="store_true")
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args(argv)
    try:
        result = inspect(args.root.resolve(), staged=args.staged)
    except (ValueError, OSError, SecurityScanError, subprocess.SubprocessError):
        result = {"status": "blocked", "reason": "Security inspection could not complete safely"}
    print(json.dumps(result, indent=2))
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())

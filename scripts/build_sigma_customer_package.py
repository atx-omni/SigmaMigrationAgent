#!/usr/bin/env python3
"""Build an allowlisted, reproducible customer pilot ZIP; never publish it."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import stat
import subprocess
import tempfile
from pathlib import Path, PurePosixPath
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo


ROOT = Path(__file__).resolve().parents[1]
PACKAGE_NAME = "Sigma-to-Omni-Pilot"
ENGINE = "packages/omnikit-migration-engine"
CUSTOMER = "customer/sigma"
CUSTOMER_FILES = (
    "README.md", "START-HERE.html", "SETUP-AND-USAGE.md", "PILOT-WORKSHEET.md",
    "SOFTWARE-NOTICES.md", "start.py", "examples/fictional-sigma-snapshot.json",
)
ENGINE_FILES = ("pyproject.toml", "LICENSE", "PROVENANCE.json", "requirements-tested.txt")
SKILL_FILES = (
    ".agents/skills/sigma-to-omni-migration/SKILL.md",
    ".agents/skills/sigma-to-omni-migration/agents/openai.yaml",
    ".agents/skills/sigma-to-omni-migration/references/runtime-workflow.md",
)
BLOCKED_PARTS = {".git", ".codex", ".venv", "__pycache__", "tests", "evals", "evidence",
                 ".runs", ".artifacts", ".secrets", "customer-evidence", "node_modules"}
SCAN_RULES = {
    "personal_local_path": re.compile(r"/Users/[^/\s]+/|[A-Z]:\\Users\\[^\\\s]+\\"),
    "internal_chat_link": re.compile(r"https://exploreomni\.slack\.com/"),
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "provider_key": re.compile(r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{32,}"),
    "github_token": re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{50,})"),
    "slack_token": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}"),
    "aws_access_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
}
MODIFICATION_NOTICE = (
    "# Distribution adaptation notice: supplied in the modified Sigma-to-Omni pilot engine.\n"
    "# See the distribution SOFTWARE-NOTICES.md and engine/PROVENANCE.json for attribution.\n"
)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def selection(root: Path) -> dict[str, Path]:
    """Explicit customer/skill files plus source code/rulebook and reference schemas."""
    selected = {name: root / CUSTOMER / name for name in CUSTOMER_FILES}
    selected["SOFTWARE-NOTICES.md"] = root / "SOFTWARE-NOTICES.md"
    selected.update({f"engine/{name}": root / ENGINE / name for name in ENGINE_FILES})
    # Required canonical skill files retain their discovery path. Do not glob
    # arbitrary skills or bypass the same scanning/checksum path as other files.
    selected.update({name: root / name for name in SKILL_FILES})
    for path in sorted((root / "examples").glob("*.json")):
        selected[f"examples/{path.name}"] = path
    selected["engine/README.md"] = root / CUSTOMER / "ENGINE-README.md"
    for path in sorted((root / ENGINE / "src/omni_migrator").rglob("*")):
        relative = path.relative_to(root / ENGINE)
        if not BLOCKED_PARTS.intersection(relative.parts) and path.suffix in {".py", ".md"}:
            selected[f"engine/{relative.as_posix()}"] = path
    for path in sorted((root / "contracts").glob("*.schema.json")):
        selected[path.relative_to(root).as_posix()] = path
    for path in sorted((root / "contracts/sigma").glob("*.schema.json")):
        selected[path.relative_to(root).as_posix()] = path
    for name in (
        "sigma-capability-spike-request.v1.example.json",
        "sigma-semantic-routing-decision-request.v1.omni-reconstruction.example.json",
        "sigma-semantic-routing-decision-request.v1.warehouse-first.example.json",
    ):
        selected[f"contracts/sigma/examples/{name}"] = root / "contracts/sigma/examples" / name
    return selected


def read_safe(root: Path, path: Path, archive_name: str) -> bytes:
    relative = path.relative_to(root)
    if BLOCKED_PARTS.intersection(relative.parts):
        raise ValueError(f"excluded path: {archive_name}")
    if any(part.startswith(".env") for part in relative.parts):
        raise ValueError(f"environment file excluded: {archive_name}")
    if any((root.joinpath(*relative.parts[:n])).is_symlink()
           for n in range(1, len(relative.parts) + 1)):
        raise ValueError(f"symbolic link excluded: {archive_name}")
    if not path.is_file() or path.stat().st_size > 8_000_000:
        raise ValueError(f"missing or oversized package input: {archive_name}")
    data = path.read_bytes()
    content = data.decode("utf-8")
    for rule, pattern in SCAN_RULES.items():
        if pattern.search(content):
            # Never echo the possible secret or private value.
            raise ValueError(f"distribution scan requires review: {archive_name} ({rule})")
    return data


def with_notice(name: str, data: bytes) -> bytes:
    if not name.startswith("engine/src/") or not name.endswith(".py"):
        return data
    lines = data.decode("utf-8").splitlines(keepends=True)
    prefix = 0
    for index, line in enumerate(lines[:2]):
        if line.startswith("#!") or re.search(r"coding[:=]\s*[-\w.]+", line):
            prefix = index + 1
    if prefix and not lines[prefix - 1].endswith("\n"):
        lines[prefix - 1] += "\n"
    lines.insert(prefix, MODIFICATION_NOTICE)
    return "".join(lines).encode("utf-8")


def git_value(root: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True,
                          text=True, timeout=10).stdout.strip()


def build(root: Path, destination: Path, release_id: str) -> dict:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,70}", release_id):
        raise ValueError("release ID must be a short filename-safe identifier")
    root = root.resolve(strict=True)
    # Keep the single authored operating guide and shipped HTML in sync.
    spec = importlib.util.spec_from_file_location("sigma_operator_renderer", root / "scripts/render_sigma_operator_guide.py")
    renderer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(renderer)
    guide = root / CUSTOMER / "SETUP-AND-USAGE.md"
    if (root / CUSTOMER / "START-HERE.html").read_text() != renderer.render(guide.read_text()):
        raise ValueError("operator HTML is stale; render the guide before packaging")
    if destination.exists() or destination.is_symlink():
        raise ValueError("output already exists; choose a new ZIP filename")
    if destination.suffix.lower() != ".zip":
        raise ValueError("output must be a ZIP filename")
    snapshot_head = git_value(root, "rev-parse", "HEAD")
    dirty = bool(git_value(root, "status", "--porcelain", "--untracked-files=normal"))
    content = {}
    records = []
    for name, path in sorted(selection(root).items()):
        raw = read_safe(root, path, name)
        shipped = with_notice(name, raw)
        content[name] = shipped
        records.append({"path": name, "size_bytes": len(shipped), "sha256": digest(shipped),
                        "source_path": path.relative_to(root).as_posix(),
                        "source_sha256": digest(raw),
                        "distribution_notice_added": shipped != raw})
    manifest = {
        "schema": "sigma-customer-package.v1", "package_id": release_id,
        "status": "draft-supervised-pilot-not-production", "human_distribution_review_required": True,
        "source_base_commit": snapshot_head,
        "source_snapshot": "working-tree-with-local-changes" if dirty else "committed-tree",
        "scope": "Sigma source acquisition and reviewed local pre-push generation; no accepted target migration",
        "runtime_dependencies_included": False,
        "manifest_is_signature": False,
        "files": records,
    }
    content["PACKAGE-MANIFEST.json"] = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
    content["CHECKSUMS.sha256"] = "".join(
        f"{digest(data)}  {name}\n" for name, data in sorted(content.items())
    ).encode()
    # Detect edits during collection before publishing even a local release artifact.
    for record in records:
        if digest(read_safe(root, root / record["source_path"], record["path"])) != record["source_sha256"]:
            raise ValueError("source changed during packaging; rebuild from a stable snapshot")
    if git_value(root, "rev-parse", "HEAD") != snapshot_head:
        raise ValueError("source commit changed during packaging; rebuild")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="sigma-package-", dir=destination.parent) as scratch:
        temporary = Path(scratch) / "package.zip"
        with ZipFile(temporary, "x", compression=ZIP_DEFLATED, compresslevel=9) as archive:
            for name, data in sorted(content.items()):
                entry = ZipInfo(f"{PACKAGE_NAME}/{name}", date_time=(2026, 9, 8, 0, 0, 0))
                entry.create_system = 3
                entry.external_attr = (stat.S_IFREG | 0o644) << 16
                entry.compress_type = ZIP_DEFLATED
                archive.writestr(entry, data)
        # Exclusive creation: never overwrite a package already at the destination.
        destination.hardlink_to(temporary)
    verify(destination)
    return {"output": str(destination.resolve()), "package_id": release_id,
            "files": len(content), "bytes": destination.stat().st_size,
            "sha256": digest(destination.read_bytes()), "source_snapshot": manifest["source_snapshot"]}


def verify(path: Path) -> dict:
    with ZipFile(path) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)) or archive.testzip() is not None:
            raise ValueError("archive integrity failure")
        prefix = f"{PACKAGE_NAME}/"
        for name in names:
            normalized = PurePosixPath(name)
            if not name.startswith(prefix) or normalized.is_absolute() or ".." in normalized.parts:
                raise ValueError("unsafe archive member")
            if BLOCKED_PARTS.intersection(normalized.parts) or stat.S_ISLNK(archive.getinfo(name).external_attr >> 16):
                raise ValueError("excluded archive member")
        manifest = json.loads(archive.read(prefix + "PACKAGE-MANIFEST.json"))
        expected = {prefix + item["path"] for item in manifest["files"]}
        expected.update({prefix + "PACKAGE-MANIFEST.json", prefix + "CHECKSUMS.sha256"})
        if set(names) != expected:
            raise ValueError("archive and manifest inventories differ")
        for item in manifest["files"]:
            data = archive.read(prefix + item["path"])
            if len(data) != item["size_bytes"] or digest(data) != item["sha256"]:
                raise ValueError("archive fingerprint mismatch")
        for row in archive.read(prefix + "CHECKSUMS.sha256").decode().splitlines():
            expected_hash, name = row.split("  ", 1)
            if digest(archive.read(prefix + name)) != expected_hash:
                raise ValueError("checksum inventory mismatch")
        return {"verified": True, "package_id": manifest["package_id"], "files": len(names)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--release-id", default="2026-09-08-pilot.2")
    parser.add_argument("--verify", type=Path)
    args = parser.parse_args()
    if bool(args.output) == bool(args.verify):
        parser.error("choose --output or --verify")
    result = verify(args.verify) if args.verify else build(ROOT, args.output, args.release_id)
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

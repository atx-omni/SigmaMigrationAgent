#!/usr/bin/env python3
"""Prepare private release provenance/SBOM and verify an externally signed release.

No signing key is created, loaded or accepted. A release custodian signs the exact
manifest outside this tool (for example with an organization-held RSA/EC key).
Recipients MUST obtain the public-key fingerprint and expected commit through an
independently trusted channel, not from the artifact being verified.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import struct
import sys
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packages/omnikit-migration-engine/src"))

from omni_migrator.security.scanner import assert_safe_bytes  # noqa: E402
from omni_migrator.security.transport import bounded_process  # noqa: E402
from security_gate import git, inspect  # noqa: E402
from check_dependency_locks import check as check_locks  # noqa: E402

MAX_ARCHIVE = 100 * 1024 * 1024
LOCK_DIR = "packages/omnikit-migration-engine"


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def read_regular(path: Path, maximum: int) -> bytes:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > maximum:
        raise ValueError("Expected a bounded regular release file")
    with path.open("rb") as stream:
        value = stream.read(maximum + 1)
    if len(value) > maximum:
        raise ValueError("Release input exceeds the size limit")
    return value


def scan_archive(artifact: bytes) -> None:
    """Reject ambiguous archives and scan the exact decompressed member bytes."""
    if len(artifact) > MAX_ARCHIVE:
        raise ValueError("Release exceeds the archive byte budget")
    # Validate the ordinary ZIP directory before ZipFile allocates entry objects.
    # ZIP64, multidisk, appended data, oversized comments/directories fail closed.
    tail = artifact[-65557:]
    position = tail.rfind(b"PK\x05\x06")
    if position < 0 or len(tail) - position < 22:
        raise ValueError("Release ZIP directory is missing or unsupported")
    _, disk, start_disk, disk_count, count, size, offset, comment_size = struct.unpack(
        "<4s4H2IH", tail[position:position + 22])
    absolute_position = len(artifact) - len(tail) + position
    if (disk or start_disk or disk_count != count or count > 1000 or size > 2 * 1024 * 1024
            or size == 0xFFFFFFFF or offset == 0xFFFFFFFF
            or len(tail) - position != 22 + comment_size or offset + size != absolute_position):
        raise ValueError("Release ZIP directory exceeds its bounds")
    with zipfile.ZipFile(io.BytesIO(artifact)) as archive:
        entries = archive.infolist()
        if len(entries) > 1000 or len(entries) != count:
            raise ValueError("Release contains too many members")
        names = set()
        total = 0
        for entry in entries:
            normalized = PurePosixPath(entry.filename)
            if (entry.filename in names or entry.filename.startswith(("/", "\\"))
                    or "\\" in entry.filename or ".." in Path(entry.filename).parts
                    or normalized.as_posix() != entry.filename
                    or not stat.S_ISREG(entry.external_attr >> 16)
                    or any(part.startswith(".env") for part in normalized.parts)
                    or entry.flag_bits & 1 or entry.file_size > 25 * 1024 * 1024):
                raise ValueError("Release contains an unsupported or ambiguous member")
            names.add(entry.filename)
            with archive.open(entry) as stream:
                value = stream.read(25 * 1024 * 1024 + 1)
            total += len(value)
            if total > MAX_ARCHIVE:
                raise ValueError("Release expands beyond the allowed byte budget")
            assert_safe_bytes(value, filename=entry.filename)


def prepare(root: Path, artifact_path: Path, *, expected_repository: str) -> bytes:
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", expected_repository):
        raise ValueError("Expected repository must be an explicit owner/name")
    if git(root, "status", "--porcelain", "--untracked-files=normal"):
        raise ValueError("Release preparation requires a clean reviewed source commit")
    remote = git(root, "config", "--get", "remote.origin.url").decode().strip()
    if remote.removesuffix(".git") not in {
        f"https://github.com/{expected_repository}", f"git@github.com:{expected_repository}"
    }:
        raise ValueError("Source repository identity differs from the pinned release identity")
    if inspect(root)["status"] != "passed":
        raise ValueError("Source security gate is blocked")
    check_locks(root / LOCK_DIR)
    artifact = read_regular(artifact_path, MAX_ARCHIVE)
    scan_archive(artifact)
    # An arbitrary scanned ZIP must never acquire this checkout's provenance.
    # Rebuild the allowlisted package with the same identifier and require exact
    # byte equality, not merely claims in its self-authored manifest.
    import build_sigma_customer_package as packager

    verified = packager.verify(artifact_path)
    with tempfile.TemporaryDirectory(prefix="sigma-release-rebuild-") as scratch:
        rebuilt = Path(scratch) / "rebuilt.zip"
        packager.build(root, rebuilt, verified["package_id"])
        if read_regular(rebuilt, MAX_ARCHIVE) != artifact:
            raise ValueError("Release does not match a deterministic rebuild of current source")
    locks = {}
    components = {}
    for name in ("requirements-runtime.lock", "requirements-build.lock", "requirements-dev.lock"):
        data = read_regular(root / LOCK_DIR / name, 2 * 1024 * 1024)
        locks[name] = digest(data)
        for package, version in re.findall(rb"(?m)^([A-Za-z0-9_.-]+)==([^\s;\\]+)", data):
            package, version = package.decode(), version.decode()
            components[(package, version)] = {"type": "library", "name": package,
                                              "version": version,
                                              "purl": f"pkg:pypi/{package}@{version}"}
    manifest = json.dumps({
        "schema_version": "sigma-release-attestation.v1",
        "repository": expected_repository,
        "commit": git(root, "rev-parse", "HEAD").decode().strip(),
        "source_tree": git(root, "rev-parse", "HEAD^{tree}").decode().strip(),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "subject": {"sha256": digest(artifact), "size": len(artifact)},
        "dependency_locks": locks,
        "sbom": {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
                 "components": [components[key] for key in sorted(components)]},
        "signed": False, "release_status": "awaiting_external_signature",
        "review_evidence": "Clean source commit; independent PR approval must be enforced externally",
        "live_migration_accepted": False,
    }, sort_keys=True, indent=2, allow_nan=False).encode() + b"\n"
    assert_safe_bytes(manifest, filename="release-attestation.json")
    return manifest


def verify(artifact_path: Path, manifest_path: Path, signature_path: Path, public_key_path: Path,
           *, public_key_sha256: str, expected_repository: str, expected_commit: str) -> dict:
    if not re.fullmatch(r"[a-f0-9]{64}", public_key_sha256) or not re.fullmatch(
        r"[a-f0-9]{40}", expected_commit
    ):
        raise ValueError("An independently pinned public-key fingerprint and commit are required")
    public_key = read_regular(public_key_path, 65536)
    if digest(public_key) != public_key_sha256:
        raise ValueError("Release publisher public-key identity does not match trusted fingerprint")
    if not public_key.startswith((b"-----BEGIN PUBLIC KEY-----", b"-----BEGIN RSA PUBLIC KEY-----")):
        raise ValueError("Only a public verification key is accepted")
    # Bound files before invoking the verifier. Never accept a key bundled in a
    # manifest as its own trust root or a trust-on-first-use fingerprint.
    signature = read_regular(signature_path, 65536)
    manifest_bytes = read_regular(manifest_path, 2 * 1024 * 1024)
    assert_safe_bytes(manifest_bytes, filename="release-attestation.json")
    # Verify fixed copies of the inspected bytes, not caller-controlled paths.
    with tempfile.TemporaryDirectory(prefix="sigma-signature-check-") as scratch:
        paths = []
        for name, data in (("publisher.pem", public_key), ("signature.bin", signature),
                           ("manifest.json", manifest_bytes)):
            path = Path(scratch) / name
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
            paths.append(path)
        result = bounded_process(
            ["openssl", "dgst", "-sha256", "-verify", str(paths[0]),
             "-signature", str(paths[1]), str(paths[2])],
            env={"PATH": os.defpath}, timeout=15, stdout_limit=4096, stderr_limit=4096,
        )
    if result.returncode:
        raise ValueError("Detached release signature is invalid")
    # Re-read to reject replacement while the external verifier was running.
    if (read_regular(public_key_path, 65536) != public_key
            or read_regular(manifest_path, 2 * 1024 * 1024) != manifest_bytes):
        raise ValueError("Release verification inputs changed during inspection")
    manifest = json.loads(manifest_bytes)
    if (manifest.get("schema_version") != "sigma-release-attestation.v1"
            or manifest.get("repository") != expected_repository
            or manifest.get("commit") != expected_commit):
        raise ValueError("Signed release does not match the pinned repository and commit")
    artifact = read_regular(artifact_path, MAX_ARCHIVE)
    if manifest.get("subject") != {"sha256": digest(artifact), "size": len(artifact)}:
        raise ValueError("Release artifact differs from signed bytes")
    scan_archive(artifact)
    return {"status": "verified", "publisher_key_sha256": public_key_sha256,
            "repository": expected_repository, "commit": expected_commit,
            "artifact_sha256": digest(artifact), "live_migration_accepted": False}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="operation", required=True)
    staging = commands.add_parser("prepare")
    staging.add_argument("--root", type=Path, default=ROOT)
    staging.add_argument("--artifact", type=Path, required=True)
    staging.add_argument("--expected-repository", required=True)
    staging.add_argument("--output", type=Path, required=True)
    verification = commands.add_parser("verify")
    for name in ("artifact", "manifest", "signature", "public-key"):
        verification.add_argument("--" + name, type=Path, required=True)
    for name in ("public-key-sha256", "expected-repository", "expected-commit"):
        verification.add_argument("--" + name, required=True)
    args = parser.parse_args(argv)
    try:
        if args.operation == "prepare":
            value = prepare(args.root.resolve(), args.artifact,
                            expected_repository=args.expected_repository)
            fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(value)
            result = {"status": "awaiting_external_signature", "publishable": False}
        else:
            result = verify(args.artifact, args.manifest, args.signature, args.public_key,
                            public_key_sha256=args.public_key_sha256,
                            expected_repository=args.expected_repository,
                            expected_commit=args.expected_commit)
    except Exception:
        result = {"status": "blocked", "reason": "Release signature or security requirements were not satisfied"}
    print(json.dumps(result, indent=2))
    return 0 if result["status"] in {"verified", "awaiting_external_signature"} else 1


if __name__ == "__main__":
    raise SystemExit(main())

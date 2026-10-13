"""Exact-byte Git and detached-signature release gates in disposable repositories."""
from datetime import date
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import stat
import struct
import sys
import zipfile

import pytest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts"))


def script(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


gate = script("security_gate")
release = script("release_security")
locks = script("check_dependency_locks")


def local_git(root, *args):
    return subprocess.run(["git", "-C", str(root), *args], check=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout


def test_forced_staged_renamed_evidence_is_detected_by_content(tmp_path):
    local_git(tmp_path, "init", "-q")
    (tmp_path / ".gitignore").write_text("*.private\n")
    data = json.dumps({"workbooks": [{"name": "private"}], "dataModels": []})
    (tmp_path / "ordinary.private").write_text(data)
    local_git(tmp_path, "add", "-f", "ordinary.private")
    result = gate.inspect(tmp_path, staged=True)
    assert result["status"] == "blocked"
    assert result["findings"][0]["code"] == "confidential_artifact"
    assert "private" not in json.dumps(result)


def test_gate_reads_staged_bytes_not_cleaned_worktree(tmp_path):
    local_git(tmp_path, "init", "-q")
    (tmp_path / "notes.txt").write_text("ghp_" + "A1b2" * 9)
    local_git(tmp_path, "add", "notes.txt")
    (tmp_path / "notes.txt").write_text("clean replacement\n")
    assert gate.inspect(tmp_path, staged=True)["status"] == "blocked"
    assert gate.inspect(tmp_path)["status"] == "passed"


def test_exact_fixture_exception_does_not_allow_modified_or_renamed_data(tmp_path):
    local_git(tmp_path, "init", "-q")
    value = b'{"workbooks": [], "dataModels": [], "synthetic": true}'
    (tmp_path / "fixture.json").write_bytes(value)
    (tmp_path / ".github").mkdir()
    policy = {"schema_version": "sigma-security-exceptions.v1", "entries": [{
        "path": "fixture.json", "sha256": hashlib.sha256(value).hexdigest(),
        "rules": ["confidential_artifact"], "reason": "Reviewed empty fictional test fixture",
        "expires": "2027-01-01",
    }]}
    (tmp_path / gate.EXCEPTIONS).write_text(json.dumps(policy))
    assert gate.inspect(tmp_path, today=date(2026, 10, 12))["status"] == "passed"
    (tmp_path / "fixture.json").write_bytes(value + b"\n")
    assert gate.inspect(tmp_path, today=date(2026, 10, 12))["status"] == "blocked"
    (tmp_path / "fixture.json").rename(tmp_path / "renamed.json")
    assert gate.inspect(tmp_path, today=date(2026, 10, 12))["status"] == "blocked"
    with pytest.raises(ValueError, match="expired"):
        gate.inspect(tmp_path, today=date(2027, 2, 1))


def test_dependency_locks_pin_every_distribution_with_hashes():
    assert locks.check()["status"] == "passed"
    for filename in ("requirements-runtime.lock", "requirements-build.lock", "requirements-dev.lock"):
        value = (ROOT / "packages/omnikit-migration-engine" / filename).read_text()
        entries = value.replace("\\\n", " ").splitlines()
        packages = [line for line in entries if line and not line.lstrip().startswith("#")]
        assert packages
        for line in packages:
            assert "==" in line and "--hash=sha256:" in line
            assert "://" not in line and "--index-url" not in line


def test_partial_lock_update_is_rejected(tmp_path):
    import shutil

    engine = ROOT / "packages/omnikit-migration-engine"
    for path in [engine / "pyproject.toml", *engine.glob("requirements-*.in"),
                 *engine.glob("requirements-*.lock")]:
        shutil.copyfile(path, tmp_path / path.name)
    build_lock = tmp_path / "requirements-build.lock"
    build_lock.write_text(build_lock.read_text().replace("hatchling==1.27.0", "hatchling==1.27.1"))
    with pytest.raises(ValueError, match="diverge"):
        locks.check(tmp_path)


def archive_bytes():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as output:
        entry = zipfile.ZipInfo("README.md")
        entry.external_attr = (stat.S_IFREG | 0o644) << 16
        output.writestr(entry, "Fictional release verification fixture.\n")
    return buffer.getvalue()


def test_release_verifies_real_detached_signature_and_rejects_changed_inputs(tmp_path):
    # Ephemeral test-only key; production code neither creates nor loads private keys.
    private = tmp_path / "ephemeral-test-key.pem"
    public = tmp_path / "test-public.pem"
    subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048",
                    "-out", str(private)], check=True, capture_output=True)
    subprocess.run(["openssl", "pkey", "-in", str(private), "-pubout", "-out", str(public)],
                   check=True, capture_output=True)
    os.chmod(private, 0o600)
    artifact = tmp_path / "fixture.zip"
    artifact.write_bytes(archive_bytes())
    manifest = tmp_path / "attestation.json"
    manifest.write_text(json.dumps({
        "schema_version": "sigma-release-attestation.v1", "repository": "test/fixture",
        "commit": "a" * 40, "subject": {"sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
                                         "size": artifact.stat().st_size},
    }))
    signature = tmp_path / "signature.bin"
    subprocess.run(["openssl", "dgst", "-sha256", "-sign", str(private), "-out", str(signature),
                    str(manifest)], check=True, capture_output=True)
    kwargs = dict(public_key_sha256=hashlib.sha256(public.read_bytes()).hexdigest(),
                  expected_repository="test/fixture", expected_commit="a" * 40)
    assert release.verify(artifact, manifest, signature, public, **kwargs)["status"] == "verified"
    with pytest.raises(ValueError, match="identity"):
        release.verify(artifact, manifest, signature, public,
                       **(kwargs | {"public_key_sha256": "b" * 64}))
    with pytest.raises(ValueError, match="repository and commit"):
        release.verify(artifact, manifest, signature, public,
                       **(kwargs | {"expected_commit": "b" * 40}))
    artifact.write_bytes(artifact.read_bytes() + b"changed")
    with pytest.raises(ValueError, match="signed bytes"):
        release.verify(artifact, manifest, signature, public, **kwargs)
    manifest.write_text(manifest.read_text() + " ")
    with pytest.raises(ValueError, match="signature"):
        release.verify(artifact, manifest, signature, public, **kwargs)


def test_unsigned_release_and_unsafe_archive_members_fail(tmp_path):
    with pytest.raises(ValueError, match="pinned"):
        release.verify(tmp_path / "a", tmp_path / "b", tmp_path / "c", tmp_path / "d",
                       public_key_sha256="", expected_repository="test/fixture", expected_commit="")
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as output:
        output.writestr("../unexpected.txt", "value")
    with pytest.raises(ValueError, match="unsupported"):
        release.scan_archive(buffer.getvalue())


@pytest.mark.parametrize("mutation", ["too_many_entries", "directory_too_large", "trailing_bytes"])
def test_archive_directory_is_bounded_before_zipfile_parsing(monkeypatch, mutation):
    value = bytearray(archive_bytes())
    position = value.rfind(b"PK\x05\x06")
    if mutation == "too_many_entries":
        struct.pack_into("<H", value, position + 8, 1001)
        struct.pack_into("<H", value, position + 10, 1001)
    elif mutation == "directory_too_large":
        struct.pack_into("<I", value, position + 12, 3 * 1024 * 1024)
    else:
        value += b"trailing"
    monkeypatch.setattr(release.zipfile, "ZipFile", lambda *_: pytest.fail("must preflight first"))
    with pytest.raises(ValueError, match="directory"):
        release.scan_archive(bytes(value))

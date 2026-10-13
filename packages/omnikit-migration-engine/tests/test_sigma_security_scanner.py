"""Synthetic credential reproductions at import and exact persisted-output boundaries."""
from __future__ import annotations

import hashlib
import json
import socket
from pathlib import Path
from zipfile import ZipFile

import pytest

from omni_migrator.prepush.session import Session, digest, encoded, reject_secrets
from omni_migrator.prepush.validate import validate
from omni_migrator.security import scanner

ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture(autouse=True)
def deny_network(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("Secret checking must never verify a credential online")
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)


def samples():
    # Construct synthetic tokens so the fixture source is not itself a token dump.
    return [
        "ghp_" + "A" * 36,
        "github_pat_" + "a" * 22 + "_" + "B" * 59,
        "xoxb-" + "123456789012-" * 2 + "a" * 24,
        "-----BEGIN " + "PRIVATE KEY-----\n" + "synthetic" + "\n-----END PRIVATE KEY-----",
        "postgres://" + "fixture:" + "not-a-real-password" + "@warehouse.invalid/db",
        "https://warehouse.invalid/query?" + "api_key=" + "not-a-real-key",
        "The operator supplied " + "password=" + "not-a-real-password",
        "Authorization: " + "Bearer " + "not-a-real-access-value",
    ]


@pytest.mark.parametrize("text", samples())
def test_shared_policy_detects_free_text_without_exposing_it(text):
    data = json.dumps({"description": text}).encode()
    findings = scanner.scan_bytes(data)
    assert findings
    assert text not in repr(findings)
    with pytest.raises(scanner.SecurityScanError) as captured:
        scanner.assert_safe_bytes(data)
    assert text not in str(captured.value)
    with pytest.raises(scanner.SecurityScanError):
        reject_secrets({"nested": [{"description": text}]})


def test_escaped_json_names_and_values_cannot_hide_credentials():
    # Escaping the first character bypasses a regex-only serialized-JSON scan.
    value = samples()[0]
    escaped = '{"description":"\\u0067' + value[1:] + '"}'
    assert scanner.scan_bytes(escaped.encode())
    assert scanner.scan_bytes(b'{"client\\u005fsecret":"fixture"}')
    assert scanner.scan_bytes(b'\xef\xbb\xbf{"client\\u005fsecret":"fixture"}')
    assert scanner.scan_bytes(b'"client\\u005fsecret": "fixture"', filename="artifact.yml")
    assert scanner.scan_bytes(b'{}', filename=value + ".json")
    assert scanner.scan_bytes(("postgres://user%3Afictional%40warehouse.invalid/db").encode())


def test_pragmas_and_process_environment_cannot_bypass(monkeypatch):
    monkeypatch.setenv("DETECT_SECRETS_DISABLE", "1")
    text = samples()[0] + "  # pragma: allowlist secret"
    assert scanner.scan_bytes(text.encode())


def test_code_references_are_not_credentials_but_literals_and_renamed_data_are():
    source = b'api_key = os.environ["OPENAI_API_KEY"]\nbuild_authorization = "build_authorization"\n'
    assert not scanner.scan_bytes(source, filename="reference.py")
    assert scanner.scan_bytes(b'api_key = "literal-value"\n', filename="unsafe.py")
    assert scanner.scan_bytes(b'{"api_key": "literal-value"}', filename="renamed.py")
    assert scanner.scan_bytes(('note = "' + samples()[0] + '"\n').encode(), filename="unsafe.py")
    with pytest.raises(scanner.SecurityScanError):
        scanner.scan_bytes(b'not valid Python : literal-value', filename="broken.py")


def test_boolean_authorization_metadata_is_not_a_credential():
    assert not scanner.scan_bytes(b'{"authorization_granted":false}')
    assert scanner.scan_bytes(b'{"authorization":"literal-value"}')


def test_structured_redaction_is_allowed_but_other_containers_are_not():
    scanner.assert_safe_value({"clientSecret": {"redacted": "secret"}})
    with pytest.raises(scanner.SecurityScanError):
        scanner.assert_safe_value({"clientSecret": {"value": "literal-value"}})
    with pytest.raises(scanner.SecurityScanError):
        scanner.assert_safe_value({"clientSecret": ["literal-value"]})


def test_scanner_failure_and_unsupported_input_fail_closed(monkeypatch):
    def unavailable():
        raise ImportError("must-not-be-disclosed")
    monkeypatch.setattr(scanner, "_plugins", unavailable)
    with pytest.raises(scanner.SecurityScanError, match="could not complete") as captured:
        scanner.assert_safe_bytes(b"innocent data")
    assert "must-not-be-disclosed" not in str(captured.value)


@pytest.mark.parametrize("data", [b"\xff", b"\x00", b"a" * (1024 * 1024 + 1)])
def test_nontext_and_oversized_lines_fail_closed(data):
    with pytest.raises(scanner.SecurityScanError):
        scanner.assert_safe_bytes(data)


def prepared(tmp_path):
    source, target = tmp_path / "source.json", tmp_path / "target.json"
    source.write_bytes((ROOT / "examples/retail-supported.json").read_bytes())
    target.write_bytes((ROOT / "examples/target.json").read_bytes())
    session = Session.initialize(tmp_path / "run", source, target, synthetic=True)
    session.choose("omni_semantic_reconstruction")
    session.review("accept", expected_proposal_hash=digest(session.proposal()))
    session.build_package()
    return session


def reseal_for_test(session, package):
    """Model a malicious same-OS-user package, not an accidental checksum mismatch."""
    manifest = json.loads((package / "manifest.json").read_text())
    manifest["files"] = {
        path.relative_to(package).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in package.rglob("*") if path.is_file() and path.name != "manifest.json"
    }
    (package / "manifest.json").write_bytes(encoded(manifest))
    session.append("build", {"path": package.name, "manifest_sha256": digest(manifest),
                             "validation": {"status": "offline_preflight_passed"}})


@pytest.mark.parametrize("name", ["queries/1.sql", "omni/model/extra.view", "source.json", "manifest.json"])
@pytest.mark.parametrize("purpose", ["support", "migration"])
def test_resealed_credential_is_never_exportable(tmp_path, name, purpose):
    session = prepared(tmp_path)
    package, _ = session.validate_package()
    path = package / name
    secret = samples()[2]
    if name.endswith(".json"):
        content = json.loads(path.read_text())
        content["description"] = secret
        path.write_text(json.dumps(content))
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("description: " + secret)
    reseal_for_test(session, package)
    result = validate(package)
    assert result["security_status"] == "blocked"
    assert secret not in json.dumps(result)
    output = tmp_path / "blocked.zip"
    with pytest.raises(scanner.SecurityScanError):
        session.export(output, purpose=purpose)
    assert not output.exists()


def test_support_is_default_allowlisted_and_full_export_is_explicit(tmp_path):
    session = prepared(tmp_path)
    assert (session.root / ".gitignore").read_text().splitlines()[-2:] == ["*", "!.gitignore"]
    package, _ = session.validate_package()
    before = {p.relative_to(package).as_posix(): p.read_bytes()
              for p in package.rglob("*") if p.is_file()}
    result = session.export(tmp_path / "support.zip")
    assert result["export_purpose"] == "support"
    with ZipFile(tmp_path / "support.zip") as archive:
        assert archive.namelist() == ["support-summary.json"]
        summary = json.loads(archive.read("support-summary.json"))
        assert summary["artifact_count"] == len(before) - 1
        raw = json.dumps(summary)
        for forbidden in ("Retail", "orders", "11111111-", "source_sha256", "actor", "SELECT", "/Users/"):
            assert forbidden not in raw
    session.export(tmp_path / "migration.zip", purpose="migration")
    with ZipFile(tmp_path / "migration.zip") as archive:
        assert set(archive.namelist()) == set(before)
        for name, expected in before.items():
            assert archive.read(name) == expected
        extracted = tmp_path / "extracted"
        archive.extractall(extracted)
    assert validate(extracted)["status"] == "offline_preflight_passed"
    assert before == {p.relative_to(package).as_posix(): p.read_bytes()
                      for p in package.rglob("*") if p.is_file()}


def test_manifest_and_source_names_are_scanned_before_diagnostic_output(tmp_path):
    session = prepared(tmp_path)
    package, _ = session.validate_package()
    name = samples()[0] + ".json"
    (package / name).write_text("{}")
    reseal_for_test(session, package)
    result = validate(package)
    assert result["security_status"] == "blocked"
    assert name not in json.dumps(result)


def test_export_rechecks_exact_bytes_after_validator(tmp_path, monkeypatch):
    session = prepared(tmp_path)
    package, result = session.validate_package()
    path = package / "source.json"
    value = json.loads(path.read_text())
    value["description"] = samples()[0]
    path.write_text(json.dumps(value))
    reseal_for_test(session, package)
    # Even a stale or replaced validation verdict cannot authorize unsafe output.
    monkeypatch.setattr(session, "validate_package", lambda: (package, result))
    with pytest.raises(scanner.SecurityScanError):
        session.export(tmp_path / "stale-validator.zip", purpose="migration")
    assert not (tmp_path / "stale-validator.zip").exists()

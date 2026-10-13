"""Synthetic credential reproductions at import and exact persisted-output boundaries."""
from __future__ import annotations

import hashlib
import json
import socket
from pathlib import Path
from urllib.parse import quote
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


@pytest.mark.parametrize("alias", [
    "api_token", "API_TOKEN", "apiToken", "api-token", "api.token", "api token",
    "Api__Token", "OMNI_API_TOKEN", "credentials", "client_secret_backup", "access_token_value",
])
def test_v2_aliases_share_structured_text_and_url_policy(alias):
    secret = "fictional-credential-value"
    surfaces = [
        json.dumps({alias: secret}).encode(),
        (f'Operator note: "{alias}" = "{secret}"').encode(),
        ("https://warehouse.invalid/?" + quote(alias, safe="") + "=" + quote(secret)).encode(),
    ]
    for data in surfaces:
        findings = scanner.scan_bytes(data)
        assert findings, alias
        assert secret not in repr(findings)
        with pytest.raises(scanner.SecurityScanError) as captured:
            scanner.assert_safe_bytes(data)
        assert secret not in str(captured.value)


def test_encoded_aliases_and_credential_containers_are_not_extension_bypasses():
    secret = "fictional-credential-value"
    encoded = "api" + r"\u005f" + "token"
    surfaces = [
        (json.dumps({"api_token": secret}).replace("api_token", encoded).encode(), "input.json"),
        (f'"{encoded}": "{secret}"'.encode(), "input.yaml"),
        (f'{encoded}={secret}'.encode(), "note.txt"),
        (("https://warehouse.invalid/?" + quote(quote("api_token", safe=""), safe="")
          .replace("_", "%255f") + "=" + secret).encode(), "note.txt"),
        (json.dumps({"credentials": {"value": secret}}).encode(), "renamed.py"),
        (f'credentials:\n  value: "{secret}"\n'.encode(), "input.yaml"),
    ]
    for data, name in surfaces:
        assert scanner.scan_bytes(data, filename=name), name
    assert scanner.POLICY_VERSION == "sigma-secret-policy.v2"


def test_environment_references_redactions_and_normal_text_stay_benign():
    source = b'api_token = os.environ["OMNI_API_TOKEN"]\ncredentials = {"api_token": os.getenv("OMNI_API_TOKEN")}\n'
    assert not scanner.scan_bytes(source, filename="reference.py")
    for value in ("${OMNI_API_TOKEN}", "$OMNI_API_TOKEN", "[REDACTED]", {"redacted": "secret"}):
        scanner.assert_safe_value({"api_token": value, "credentials": value})
    for text in ("api_token=${OMNI_API_TOKEN}", "API_TOKEN=$OMNI_API_TOKEN",
                 "https://warehouse.invalid/?api_token=%24%7BOMNI_API_TOKEN%7D",
                 "SELECT label LIKE '%E9%'", r"A regex character is \xZZ", "tokenizer=word"):
        assert not scanner.scan_bytes(text.encode())
    # A reference with a literal fallback is not a reference-only credential.
    assert scanner.scan_bytes(('api_token=${OMNI_API_TOKEN:-' + 'literal-value}').encode())
    for name in ("input.json", "renamed.py"):
        assert scanner.scan_bytes(b'{"credentials":{"fictional_credential_as_key":null}}', filename=name)


def test_opaque_containers_cannot_hide_in_notes_or_mixed_python_expressions():
    secret = "synthetic-opaque-material"
    samples = [
        (f'credentials: {{"value":"{secret}"}}'.encode(), "notes.txt"),
        (f'api_token = ["{secret}"]'.encode(), "notes.txt"),
        (f'credentials = {{"value":"{secret}", "reference": os.getenv("OTHER")}}'.encode(), "dump.py"),
    ]
    for data, filename in samples:
        assert scanner.scan_bytes(data, filename=filename)
    for data, filename in [
        (b'credentials = {"reference": os.getenv("OTHER")}', "reference.py"),
        (b'credentials:\n  redacted: secret\n', "redacted.yaml"),
        (b'credentials: {redacted: secret}', "redacted.yaml"),
        (b'credentials: {"redacted": "secret"}', "notes.txt"),
        (b'credentials: {\n"redacted": "secret"\n}', "notes.txt"),
    ]:
        assert not scanner.scan_bytes(data, filename=filename)


def test_url_detector_does_not_misclassify_regex_source_as_query_parameters():
    source = br'''_SECRET_VALUE_RE = r'(?:api[_-]?key|token|secret|password|authorization)\s*[:=]\s*\S+)' '''
    assert not scanner.scan_bytes(source, filename="policy.py")
    value = "synthetic-opaque-material"
    assert scanner.scan_bytes(("https://warehouse.invalid/?API%5fTOKEN=" + value).encode())


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
    for name in ("source", "target"):
        manifest[name + "_sha256"] = digest(json.loads((package / (name + ".json")).read_text()))
    manifest["review"].update({key: manifest[key] for key in ("route", "source_sha256", "target_sha256")})
    proposal = {**manifest["build"], "files": {
        name: (package / name).read_text() for name in manifest["files"]
        if name not in {"source.json", "target.json"}
    }}
    manifest["review"]["proposal_sha256"] = digest(proposal)
    (package / "manifest.json").write_bytes(encoded(manifest))
    session.append("build", {"path": package.name, "manifest_sha256": digest(manifest),
                             "validation": {"status": "offline_preflight_passed",
                                            "security_status": "passed",
                                            "security_policy": "sigma-secret-policy.v1"}})


@pytest.mark.parametrize("alias", ["api_token", "credentials"])
def test_new_aliases_block_actual_initialization_before_creating_run(tmp_path, alias, capsys):
    source = json.loads((ROOT / "examples/retail-supported.json").read_text())
    secret = "fictional-credential-value"
    source["metadata"] = {alias: secret if alias == "api_token" else {"value": secret}}
    path = tmp_path / "source.json"
    path.write_text(json.dumps(source))
    with pytest.raises(scanner.SecurityScanError) as captured:
        Session.initialize(tmp_path / "run", path, ROOT / "examples/target.json", synthetic=True)
    assert not (tmp_path / "run").exists()
    assert secret not in str(captured.value) + capsys.readouterr().out


def test_generated_api_token_is_blocked_at_actual_build_boundary(tmp_path, monkeypatch):
    session = prepared(tmp_path)
    from omni_migrator.prepush import build as module
    original = module.build
    secret = "fictional-credential-value"

    def contaminated(*args, **kwargs):
        proposal = original(*args, **kwargs)
        proposal["files"]["queries/1.sql"] += "\n-- API_TOKEN=" + secret
        return proposal

    monkeypatch.setattr(module, "build", contaminated)
    session.review("accept", expected_proposal_hash=digest(session.proposal()))
    with pytest.raises(scanner.SecurityScanError):
        session.build_package()
    assert all(secret.encode() not in path.read_bytes() for path in session.root.rglob("*") if path.is_file())


@pytest.mark.parametrize("purpose", ["support", "migration"])
@pytest.mark.parametrize("alias", ["api_token", "credentials"])
def test_v1_resealed_contamination_blocks_validation_and_both_exports(tmp_path, purpose, alias, capsys):
    session = prepared(tmp_path)
    package, prior = session.validate_package()
    source_path = package / "source.json"
    value = json.loads(source_path.read_text())
    secret = "fictional-credential-value"
    value["metadata"] = {alias: secret if alias == "api_token" else {"value": secret}}
    source_path.write_text(json.dumps(value))
    reseal_for_test(session, package)
    before = {p.relative_to(package).as_posix(): p.read_bytes() for p in package.rglob("*") if p.is_file()}
    assert prior["security_status"] == "passed"
    result = validate(package)
    assert result["security_policy"] == "sigma-secret-policy.v2"
    assert result["security_status"] == "blocked"
    output = tmp_path / "blocked.zip"
    with pytest.raises(scanner.SecurityScanError) as captured:
        session.export(output, purpose=purpose)
    assert not output.exists()
    assert secret not in json.dumps(result) + str(captured.value) + capsys.readouterr().out
    assert before == {p.relative_to(package).as_posix(): p.read_bytes() for p in package.rglob("*") if p.is_file()}


def test_clean_old_policy_package_reopens_and_exports_without_rewriting(tmp_path):
    session = prepared(tmp_path)
    package, _ = session.validate_package()
    manifest_path = package / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    # The original package schema predates classification/policy fields. The
    # history fixture deliberately records the older policy's accepted verdict.
    manifest.pop("classification", None)
    manifest_path.write_text(json.dumps(manifest))
    reseal_for_test(session, package)
    evidence = {p.relative_to(package).as_posix(): p.read_bytes() for p in package.rglob("*") if p.is_file()}
    history = {p.name: p.read_bytes() for p in (session.root / "events").iterdir()}
    path, result = Session(session.root).validate_package()
    assert path == package
    assert result["status"] == "offline_preflight_passed"
    assert result["security_policy"] == "sigma-secret-policy.v2"
    session.export(tmp_path / "old-support.zip")
    session.export(tmp_path / "old-migration.zip", purpose="migration")
    with ZipFile(tmp_path / "old-migration.zip") as archive:
        assert {name: archive.read(name) for name in archive.namelist()} == evidence
    with ZipFile(tmp_path / "old-support.zip") as archive:
        assert archive.namelist() == ["support-summary.json"]
        assert json.loads(archive.read("support-summary.json"))["security_policy"] == "sigma-secret-policy.v2"
    assert evidence == {p.relative_to(package).as_posix(): p.read_bytes() for p in package.rglob("*") if p.is_file()}
    assert all((session.root / "events" / name).read_bytes() == data for name, data in history.items())


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


@pytest.mark.parametrize("purpose", ["support", "migration"])
@pytest.mark.parametrize("field", ["description", "api_token"])
def test_export_rechecks_exact_bytes_after_validator(tmp_path, monkeypatch, purpose, field):
    session = prepared(tmp_path)
    package, result = session.validate_package()
    path = package / "source.json"
    value = json.loads(path.read_text())
    value[field] = samples()[0] if field == "description" else "fictional-credential-value"
    path.write_text(json.dumps(value))
    reseal_for_test(session, package)
    # Even a stale or replaced validation verdict cannot authorize unsafe output.
    monkeypatch.setattr(session, "validate_package", lambda: (package, result))
    with pytest.raises(scanner.SecurityScanError):
        session.export(tmp_path / "stale-validator.zip", purpose=purpose)
    assert not (tmp_path / "stale-validator.zip").exists()

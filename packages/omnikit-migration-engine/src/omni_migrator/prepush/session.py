"""OS-owned local review sessions; append-only decisions, no target execution.

This is a single-operator process boundary, NOT remote identity authentication.
Other processes running as the same OS user share its authority. No approval in
this module confers live-evidence validity, target-write or release authority.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import pwd
import re
import uuid
import zipfile
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath

from omni_migrator.security.scanner import (
    POLICY_VERSION,
    SecurityScanError,
    assert_safe_bytes,
    assert_safe_value,
)
from omni_migrator.security.workspace import assert_private_output, prepare_workspace

MODES = ("omni_semantic_reconstruction", "warehouse_first_refactor")
LIMIT = 25 * 1024 * 1024


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True, allow_nan=False) + "\n").encode()


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                                    allow_nan=False).encode()).hexdigest()


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON keys are not allowed")
        result[key] = value
    return result


def read_json(path, *, allow_array=False):
    path = Path(path).absolute()
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise ValueError("Symbolic links are not accepted for migration inputs")
    if not path.is_file() or path.stat().st_size > LIMIT:
        raise ValueError("Input must be a regular JSON file no larger than 25 MB")
    with path.open("rb") as stream:
        data = stream.read(LIMIT + 1)
    assert_safe_bytes(data, filename=path.name)
    value = json.loads(data, object_pairs_hook=_pairs,
                       parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Nonfinite JSON")))
    if not isinstance(value, dict) and not (allow_array and isinstance(value, list)):
        raise TypeError("Input must contain one JSON object" if not allow_array
                        else "Input must contain one JSON object or array")
    return value


def private_write(path, value):
    data = value if isinstance(value, bytes) else encoded(value)
    assert_private_output(Path(path))
    assert_safe_bytes(data, filename=Path(path).name)
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())


def actor():
    uid = os.getuid()
    return {"uid": uid, "name": pwd.getpwuid(uid).pw_name, "trust": "local-os-user"}


def reject_secrets(value):
    """Backward-compatible entry point for the shared credential policy."""
    assert_safe_value(value)


def synthetic_taint(value):
    """Synthetic origin is sticky; changing a file name or wrapper cannot upgrade it."""
    if isinstance(value, dict):
        for key, child in value.items():
            if "synthetic" in key.lower() and child not in (False, None, ""):
                return True
            if key in {"evidence_mode", "evidence_classification", "classification"} and isinstance(child, str) and "synthetic" in child.lower():
                return True
            if synthetic_taint(child):
                return True
    elif isinstance(value, list):
        return any(synthetic_taint(child) for child in value)
    return False


class Session:
    def __init__(self, root):
        self.root = Path(root).absolute()
        if any(p.is_symlink() for p in (self.root, *self.root.parents)):
            raise ValueError("Run directory cannot use symbolic links")
        stat = self.root.stat()
        if stat.st_uid != os.getuid() or stat.st_mode & 0o077:
            raise ValueError("Run directory must be private (mode 700) and owned by this OS user")

    @classmethod
    def initialize(cls, root, source_path, target_path, *, synthetic=False):
        source, target = read_json(source_path), read_json(target_path)
        reject_secrets(source)
        reject_secrets(target)
        if not source.get("dataModels") or not source.get("workbooks"):
            raise ValueError("Source must contain captured dataModels and workbooks")
        root = Path(root).absolute()
        assert_private_output(root, directory=True)
        if any(p.is_symlink() for p in (root, *root.parents)):
            raise ValueError("Run directory cannot use symbolic links")
        root.mkdir(mode=0o700, parents=False)
        prepare_workspace(root)
        session = cls(root)
        (root / "objects").mkdir(mode=0o700)
        (root / "events").mkdir(mode=0o700)
        with session.lock():
            session.append("initialize", {
                "actor": actor(), "synthetic": bool(synthetic or synthetic_taint(source) or synthetic_taint(target)),
                "source_sha256": session.save(source), "target_sha256": session.save(target),
                "source_path": str(Path(source_path).absolute()), "target_path": str(Path(target_path).absolute()),
            })
        return session

    @contextmanager
    def lock(self):
        fd = os.open(self.root / ".lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "r+") as handle:
            fcntl.flock(handle, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(handle, fcntl.LOCK_UN)

    def events(self):
        result, previous = [], None
        for index, path in enumerate(sorted((self.root / "events").iterdir()), 1):
            if path.name != f"{index:06d}.json":
                raise ValueError("Run event sequence is incomplete")
            row = read_json(path)
            claimed = row.pop("sha256")
            if digest(row) != claimed or row["previous"] != previous:
                raise ValueError("Run event integrity mismatch")
            result.append(row)
            previous = claimed
        if not result:
            return []
        if result[0]["operation"] != "initialize" or result[0]["payload"]["actor"]["uid"] != os.getuid():
            raise ValueError("Run belongs to a different operator")
        return result

    def append(self, operation, payload):
        rows = self.events()
        previous = digest(rows[-1]) if rows else None
        row = {"operation": operation, "payload": payload, "previous": previous,
               "sequence": len(rows) + 1, "at": datetime.now(UTC).isoformat()}
        private_write(self.root / "events" / f"{len(rows)+1:06d}.json", {**row, "sha256": digest(row)})

    def save(self, value):
        key = digest(value)
        path = self.root / "objects" / f"{key}.json"
        if path.exists():
            if digest(read_json(path)) != key:
                raise ValueError("Stored object was modified")
        else:
            private_write(path, value)
        return key

    def load(self, key):
        if not re.fullmatch(r"[0-9a-f]{64}", key):
            raise ValueError("Invalid stored-object identifier")
        value = read_json(self.root / "objects" / f"{key}.json")
        if digest(value) != key:
            raise ValueError("Stored object was modified")
        return value

    def state(self, *, current=True):
        state = {"route": None, "review": None, "package": None, "revoked": False}
        for row in self.events():
            op, payload = row["operation"], row["payload"]
            if op == "initialize":
                state.update(payload)
            elif op in {"source", "target"}:
                state.update(payload)
                state.update(review=None, package=None)
            elif op == "route":
                state.update(route=payload["route"], review=None, package=None, revoked=False)
            elif op == "review":
                state.update(review=payload, package=None)
            elif op == "revoke":
                state.update(review=None, package=None, revoked=True)
            elif op == "build":
                state["package"] = payload
        if "source_sha256" not in state:
            raise ValueError("Run initialization was interrupted; create a new run")
        for kind in ("source", "target"):
            self.load(state[kind + "_sha256"])
            if current and digest(read_json(state[kind + "_path"])) != state[kind + "_sha256"]:
                raise ValueError(f"Imported {kind} changed; import the new revision and review again")
        return state

    def import_revision(self, kind, path):
        if kind not in {"source", "target"}:
            raise ValueError("Invalid input kind")
        value = read_json(path)
        reject_secrets(value)
        if kind == "source" and (not value.get("dataModels") or not value.get("workbooks")):
            raise ValueError("Source needs dataModels and workbooks")
        with self.lock():
            prior = self.state(current=False)
            payload = {kind + "_sha256": self.save(value), kind + "_path": str(Path(path).absolute()), "actor": actor()}
            payload["synthetic"] = bool(prior["synthetic"] or synthetic_taint(value))
            self.append(kind, payload)

    def choose(self, mode):
        if mode not in MODES:
            raise ValueError("Choose one of the two supported routes")
        with self.lock():
            self.state()
            self.append("route", {"route": mode, "actor": actor()})

    def proposal(self):
        state = self.state()
        if state["revoked"] or state["route"] not in MODES:
            raise ValueError("Choose a current route before review/build")
        from omni_migrator.prepush.build import build
        return build(self.load(state["source_sha256"]), state["route"], self.load(state["target_sha256"]))

    def review(self, decision, *, expected_proposal_hash):
        if decision not in {"accept", "reject", "request_changes"}:
            raise ValueError("Invalid review action")
        with self.lock():
            state = self.state()
            proposal_hash = digest(self.proposal())
            if proposal_hash != expected_proposal_hash:
                raise ValueError("Proposal changed while it was being reviewed")
            self.append("review", {"decision": decision, "actor": actor(), "route": state["route"],
                                  "source_sha256": state["source_sha256"], "target_sha256": state["target_sha256"],
                                  "proposal_sha256": proposal_hash,
                                  "synthetic": state["synthetic"], "target_write_authority": False})

    def revoke(self, reason):
        if reason not in {"source_changed", "route_changed", "approval_withdrawn"}:
            raise ValueError("Select a documented revocation reason")
        with self.lock():
            self.state(current=False)
            self.append("revoke", {"reason": reason, "actor": actor()})

    def build_package(self):
        with self.lock():
            state = self.state()
            proposal = self.proposal()
            review = state["review"]
            if (not review or review["decision"] != "accept" or review["proposal_sha256"] != digest(proposal)
                    or any(review[key] != state[key] for key in ("route", "source_sha256", "target_sha256"))):
                raise ValueError("Accept the current proposal through review before building")
            sequence = len(self.events()) + 1
            destination = self.root / f"package-{sequence:06d}-{uuid.uuid4().hex[:12]}"
            destination.mkdir(mode=0o700)
            files = {"source.json": encoded(self.load(state["source_sha256"])),
                     "target.json": encoded(self.load(state["target_sha256"]))}
            for name, content in proposal["files"].items():
                path = PurePosixPath(name)
                if (path.is_absolute() or ".." in path.parts or "\\" in name or name in files
                        or name == "manifest.json" or str(path) != name):
                    raise ValueError("Unsafe output path")
                files[name] = content.encode()
            for name, content in files.items():
                assert_safe_bytes(content, filename=name)
                path = destination / name
                private_write(path, content)
            manifest = {"schema_version": "sigma-prepush-package.v1", "route": state["route"],
                        "classification": "confidential_customer_migration_evidence",
                        "source_sha256": state["source_sha256"], "target_sha256": state["target_sha256"],
                        "synthetic": state["synthetic"], "review": review,
                        "files": {name: hashlib.sha256(data).hexdigest() for name, data in files.items()},
                        "build": {key: value for key, value in proposal.items() if key != "files"},
                        "target_write_authority": False, "migration_accepted": False,
                        "live_validation": "not_performed"}
            assert_safe_bytes(encoded(manifest), filename="manifest.json")
            private_write(destination / "manifest.json", manifest)
            from omni_migrator.prepush.validate import validate
            result = validate(destination)
            self.append("build", {"path": destination.name, "manifest_sha256": digest(manifest), "validation": result})
            return {"package": str(destination), **result}

    def validate_package(self):
        state = self.state()
        if state["revoked"] or not state["package"]:
            raise ValueError("No current reviewed package; review and build first")
        path = self.root / state["package"]["path"]
        if digest(read_json(path / "manifest.json")) != state["package"]["manifest_sha256"]:
            raise ValueError("Package manifest was modified after build")
        from omni_migrator.prepush.validate import validate
        return path, validate(path)

    def export(self, output, *, purpose="support"):
        """Share a minimized support summary, or explicitly request confidential evidence.

        Both routes revalidate package integrity and all sealed evidence. Semantic
        blockers may accompany a review package; security blockers never may.
        """
        if purpose not in {"support", "migration"}:
            raise ValueError("Choose support or migration export purpose")
        with self.lock():
            path, result = self.validate_package()
            if result.get("security_status") != "passed":
                raise SecurityScanError("Package security or integrity validation failed; no export was created.")
            output = Path(output).absolute()
            assert_private_output(output)
            if any(p.is_symlink() for p in (output, *output.parents)):
                raise ValueError("Export path cannot use symbolic links")
            if output.suffix.lower() != ".zip":
                raise ValueError("Export filename must end in .zip")
            manifest = read_json(path / "manifest.json")
            with (path / "manifest.json").open("rb") as stream:
                manifest_bytes = stream.read(25 * 1024 * 1024 + 1)
            if len(manifest_bytes) > 25 * 1024 * 1024:
                raise ValueError("Package manifest exceeds the bounded export size")
            verified_bytes = {"manifest.json": manifest_bytes}
            if digest(json.loads(verified_bytes["manifest.json"])) != self.state()["package"]["manifest_sha256"]:
                raise ValueError("Package manifest changed during export")
            if len(manifest["files"]) > 1000:
                raise ValueError("Package exceeds the bounded export inventory")
            total = len(verified_bytes["manifest.json"])
            # Read once, hash once, scan once, then publish those SAME bytes.
            for name, expected in manifest["files"].items():
                entry = PurePosixPath(name)
                if entry.is_absolute() or ".." in entry.parts or "\\" in name:
                    raise ValueError("Unsafe package inventory")
                item = path / name
                if (any(p.is_symlink() for p in (item, *item.parents)) or not item.is_file()
                        or item.stat().st_size > 10 * 1024 * 1024):
                    raise ValueError("Package content changed; rebuild before export")
                with item.open("rb") as stream:
                    data = stream.read(10 * 1024 * 1024 + 1)
                total += len(data)
                if len(data) > 10 * 1024 * 1024 or total > 50 * 1024 * 1024:
                    raise ValueError("Package exceeds the bounded export size")
                if hashlib.sha256(data).hexdigest() != expected:
                    raise ValueError("Package content changed; rebuild before export")
                verified_bytes[name] = data
            for name, data in verified_bytes.items():
                assert_safe_bytes(data, filename=name)
            if purpose == "support":
                # Do not copy identifiers, issue paths/messages, SQL, formulas,
                # source names, caller strings, OS identities, or manifest hashes.
                # Even diagnostic messages may contain customer-controlled text.
                build = manifest.get("build", {})
                coverage = build.get("dispositions", [])
                summary = {
                    "schema_version": "sigma-support-summary.v1",
                    "export_purpose": "support",
                    "classification": "minimized_support_diagnostics",
                    "security_policy": POLICY_VERSION,
                    "status": "blocked" if result["status"] == "blocked" else "offline_preflight_passed",
                    "issue_count": len(result.get("issues", [])),
                    "artifact_count": len(manifest["files"]),
                    "source_object_count": len(coverage) if isinstance(coverage, list) else 0,
                    "synthetic": bool(manifest.get("synthetic")),
                    "target_write_authority": False,
                    "migration_accepted": False,
                    "live_validation": "not_performed",
                }
                verified_bytes = {"support-summary.json": encoded(summary)}
            for name, data in verified_bytes.items():
                assert_safe_bytes(data, filename=name)
            with output.open("xb") as handle:
                os.fchmod(handle.fileno(), 0o600)
                with zipfile.ZipFile(handle, "w", zipfile.ZIP_DEFLATED) as archive:
                    for name, data in sorted(verified_bytes.items()):
                        archive.writestr(name, data)
            self.append("export", {"package": path.name, "actor": actor(), "status": result["status"],
                                   "purpose": purpose, "security_policy": POLICY_VERSION})
            # Support command output is minimized too, not only the ZIP payload.
            response = summary if purpose == "support" else {
                **result, "classification": "confidential_customer_migration_evidence"
            }
            return {"output": str(output), "export_purpose": purpose, **response}

    def status(self):
        state = self.state()
        return {"route": state["route"], "synthetic": state["synthetic"],
                "review": state["review"]["decision"] if state["review"] else "required",
                "revoked": state["revoked"], "package": state["package"],
                "target_write_authority": False, "migration_accepted": False,
                "live_validation": "not_performed"}

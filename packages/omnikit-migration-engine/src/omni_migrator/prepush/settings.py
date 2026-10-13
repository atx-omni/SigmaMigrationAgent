"""Explicit configuration loading. Never imported by the offline compiler/validator."""
from __future__ import annotations

import os
import re
import stat
from pathlib import Path
from urllib.parse import urlsplit

from omni_migrator.prepush.session import read_json, reject_secrets

KEYS = {"SIGMA_API_URL", "SIGMA_CLIENT_ID", "SIGMA_CLIENT_SECRET", "OMNI_BASE_URL", "OMNI_API_TOKEN"}
ROUTES = ("omni_semantic_reconstruction", "warehouse_first_refactor")
POLICIES = ("validation_only", "dashboard_only", "model_changes")


def origin(value: str) -> str:
    """Accept only an operator-selected HTTPS origin, not source-supplied URLs."""
    try:
        parsed = urlsplit(value)
        valid = (parsed.scheme == "https" and parsed.hostname and parsed.port in (None, 443)
                 and not parsed.username and not parsed.password and not parsed.query
                 and not parsed.fragment and parsed.path in ("", "/")
                 and re.fullmatch(r"[a-zA-Z0-9.-]+", parsed.hostname))
    except ValueError:
        valid = False
    if not valid:
        raise ValueError("Use an exact HTTPS platform origin without a path, port, or credentials")
    return f"https://{parsed.hostname.lower()}"


def required_keys(profile: dict) -> list[str]:
    keys = []
    if profile["source_mode"] == "api":
        keys += ["SIGMA_API_URL", "SIGMA_CLIENT_ID", "SIGMA_CLIENT_SECRET"]
    if profile["target_auth"] == "token":
        keys += ["OMNI_BASE_URL", "OMNI_API_TOKEN"]
    return keys


def load_profile(path: Path) -> dict:
    value = read_json(path)
    return validate_profile(value)


def validate_profile(value: dict) -> dict:
    reject_secrets(value)
    allowed = {"schema_version", "source_mode", "route", "allowed_changes", "target_auth",
               "sigma_origin", "omni_origin", "omni_profile", "workbook_id", "data_model_id"}
    if set(value) - allowed or value.get("schema_version") != "sigma-migration-profile.v1":
        raise ValueError("Unsupported migration profile; use setup to create a compatible profile")
    if (value.get("source_mode") not in {"api", "snapshot"} or value.get("route") not in ROUTES
            or value.get("allowed_changes") not in POLICIES
            or value.get("target_auth") not in {"offline", "oauth", "token"}):
        raise ValueError("Migration profile has missing or invalid workflow choices")
    if value["route"] == ROUTES[1] and value["allowed_changes"] == "dashboard_only":
        raise ValueError("Dashboard-only reuse requires the direct route")
    if value["source_mode"] == "api":
        origin(value.get("sigma_origin", ""))
        for name in ("workbook_id", "data_model_id"):
            if not isinstance(value.get(name), str) or not re.fullmatch(r"[A-Za-z0-9_.~-]+", value[name]):
                raise ValueError(f"Profile requires a valid {name}")
    if value["target_auth"] != "offline":
        origin(value.get("omni_origin", ""))
    if value["target_auth"] == "oauth" and not re.fullmatch(r"[A-Za-z0-9_-]+", value.get("omni_profile", "")):
        raise ValueError("OAuth requires a named Omni CLI profile")
    return value


def write_private_text(path: Path, text: str) -> None:
    from omni_migrator.security.workspace import assert_private_output
    assert_private_output(path)
    if any(parent.is_symlink() for parent in (path, *path.parents)):
        raise ValueError("Symbolic links are not accepted for setup files")
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(text)


def parse_dotenv(path: Path) -> dict[str, str]:
    """A small data format, NOT a shell script; reject expansions and ambiguous syntax."""
    if any(parent.is_symlink() for parent in path.parents):
        raise ValueError("Symbolic links are not accepted for credential directories")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "r", encoding="utf-8") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError("The selected .env must be an owner-only regular file (permissions 600)")
        if info.st_size > 16384:
            raise ValueError("The selected .env is too large")
        result = {}
        for number, raw in enumerate(stream, 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            key, separator, value = line.partition("=")
            if not separator or key not in KEYS or key in result:
                raise ValueError(f"Invalid or duplicate .env variable on line {number}; values withheld")
            if any(char in value for char in ("$", "`", "\\", "\x00")) or any(ord(c) < 32 for c in value):
                raise ValueError(f"Unsupported .env syntax on line {number}; shell expressions are not allowed")
            if value.startswith(('"', "'")):
                if len(value) < 2 or value[-1] != value[0]:
                    raise ValueError(f"Unclosed .env quote on line {number}")
                value = value[1:-1]
            elif any(c.isspace() for c in value) or '"' in value or "'" in value:
                raise ValueError(f"Quote the entire .env value on line {number}")
            result[key] = value
    return result


def resolve(profile: dict, env_file: Path | None, *, source=False, target=False, environ=None) -> dict:
    """Process environment wins over an explicitly selected file; no implicit cwd search."""
    environment = os.environ if environ is None else environ
    file_values = parse_dotenv(env_file) if env_file is not None else {}
    keys = required_keys(profile)
    keys = [key for key in keys if (source and key.startswith("SIGMA_")) or (target and key.startswith("OMNI_"))]
    values = {key: environment.get(key, file_values.get(key, "")) for key in keys}
    missing = [key for key, value in values.items() if not value or value.startswith("REPLACE_")]
    if missing:
        raise ValueError("Provide these variables in the selected .env or environment: " + ", ".join(missing))
    for key, profile_key in (("SIGMA_API_URL", "sigma_origin"), ("OMNI_BASE_URL", "omni_origin")):
        if key in values and origin(values[key]) != origin(profile[profile_key]):
            raise ValueError(f"{key} conflicts with the confirmed profile host; no credentials were sent")
    return values

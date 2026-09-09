"""Canonical hashing, time, and reference validation helpers."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any, Iterable
from urllib.parse import urlsplit


DEFAULT_REFERENCE_SCHEMES = frozenset(
    {
        "account-ref",
        "actor-ref",
        "agent-ref",
        "approval-ref",
        "artifact",
        "artifact-ref",
        "audit-policy",
        "branch-ref",
        "capability-ref",
        "candidate-ref",
        "consumer-ref",
        "decision-ref",
        "domo-card-ref",
        "domo-dataflow-ref",
        "domo-dataset-ref",
        "domo-object-ref",
        "domo-page-ref",
        "egress-policy",
        "environment-ref",
        "evidence-ref",
        "gate-ref",
        "handoff-ref",
        "human-ref",
        "inventory-ref",
        "migration-unit-ref",
        "omni-branch-ref",
        "omni-document-ref",
        "omni-folder-ref",
        "omni-model-ref",
        "omni-org-ref",
        "partition-policy",
        "person-ref",
        "persona-ref",
        "persona-policy-ref",
        "principal-ref",
        "qa-evidence-snapshot-ref",
        "qa-fixture-ref",
        "qa-result-ref",
        "qa-suite-validation-ref",
        "qa-target-outcome-ref",
        "query-fixture-ref",
        "repo-ref",
        "retention-policy",
        "retention-policy-ref",
        "run-ref",
        "source-object-ref",
        "tenant-ref",
        "tolerance-policy-ref",
        "validation-ref",
        "work-package-ref",
    }
)

SECRET_SCHEME = "secret-ref"
_SAFE_RUN_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{7,127}$")


def canonical_json(value: Any) -> str:
    """Return one stable JSON representation suitable for content addressing."""

    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def sha256_json(value: Any) -> str:
    return sha256_text(canonical_json(value))


def parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include a timezone")
    return parsed.astimezone(timezone.utc)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def validate_run_id(run_id: str) -> None:
    if not _SAFE_RUN_ID.fullmatch(run_id):
        raise ValueError(f"invalid run ID: {run_id!r}")


def _host_allowed(hostname: str, allowed_hosts: Iterable[str]) -> bool:
    normalized = hostname.rstrip(".").lower()
    for candidate in allowed_hosts:
        allowed = candidate.rstrip(".").lower()
        if allowed.startswith("*."):
            suffix = allowed[1:]
            if normalized.endswith(suffix) and normalized != suffix[1:]:
                return True
        elif normalized == allowed:
            return True
    return False


def validate_reference(
    reference: str,
    *,
    allowed_schemes: Iterable[str] = DEFAULT_REFERENCE_SCHEMES,
    allowed_hosts: Iterable[str] = (),
    allow_secret: bool = False,
    require_known_scheme: bool = True,
) -> None:
    """Validate a registry-style URI without ever resolving it.

    HTTP(S) references require an explicit host allowlist.  Userinfo, query strings,
    fragments, whitespace, and unapproved schemes are always rejected.  Secret
    references are accepted only in fields that explicitly opt in.
    """

    if not isinstance(reference, str) or not reference or any(ch.isspace() for ch in reference):
        raise ValueError("reference must be a non-empty URI without whitespace")
    parsed = urlsplit(reference)
    if not parsed.scheme:
        raise ValueError("reference must include a scheme")
    scheme = parsed.scheme.lower()
    if parsed.query or parsed.fragment:
        raise ValueError("reference query strings and fragments are forbidden")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("credential-bearing URI userinfo is forbidden")
    if scheme == SECRET_SCHEME:
        if not allow_secret:
            raise ValueError("secret references are forbidden in this field")
        if not parsed.netloc or not parsed.path:
            raise ValueError("secret reference must name a store and key")
        return
    allowed = set(allowed_schemes)
    if require_known_scheme and scheme not in allowed and scheme not in {"https", "http"}:
        raise ValueError(f"unapproved reference scheme: {scheme}")
    if scheme == "http":
        raise ValueError("unencrypted HTTP references are forbidden")
    if scheme == "https":
        if not parsed.hostname:
            raise ValueError("HTTPS reference must include a hostname")
        if not allowed_hosts or not _host_allowed(parsed.hostname, allowed_hosts):
            raise ValueError(f"reference host is not allowlisted: {parsed.hostname}")
    elif not parsed.netloc and not parsed.path:
        raise ValueError("reference must identify an object")


def partition_key(tenant_ref: str, run_id: str) -> str:
    """Return an opaque filesystem-safe key for one tenant/run partition."""

    validate_reference(tenant_ref)
    validate_run_id(run_id)
    return sha256_json({"tenant_ref": tenant_ref, "run_id": run_id})

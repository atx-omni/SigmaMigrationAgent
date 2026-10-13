"""Prepare a scanned, hash-bound transfer proposal without granting or using egress.

This is NOT an approval verifier. Production dispatch is disabled until a separate
authenticated gateway holds credentials and enforces authorization, revocation and
replay rules. A local user can edit local files; a checksum is not authentication.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
import hashlib
import json
import re
from typing import Any

from omni_migrator.orchestration.provider import SpecialistProposal
from omni_migrator.security.scanner import assert_safe_bytes, assert_safe_value


@dataclass(frozen=True)
class PreparedEgress:
    """The exact inspected bytes; downstream code must never regenerate them."""

    payload: bytes
    manifest: bytes


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def prepare_egress(
    *, tenant_ref: str, run_id: str, purpose: str, account_ref: str, project_ref: str,
    model: str, instructions: str, sanitized_evidence: dict[str, Any],
    original_evidence_sha256: dict[str, str], issued_at: datetime, expires_at: datetime,
    max_output_tokens: int = 4000,
) -> PreparedEgress:
    """Build inert proposal bytes from explicitly minimized evidence, never raw inputs.

    Original hashes identify private source records, not permission to transfer
    them. Sanitized hashes are computed here from actual proposed evidence. All
    fields, instructions, JSON-schema text, and manifest bytes use the same scanner.
    """
    if any(not isinstance(item, str) or not item.strip() or len(item) > 256 for item in
           (tenant_ref, run_id, purpose, account_ref, project_ref, model)):
        raise ValueError("explicit bounded transfer identity and purpose are required")
    if issued_at.utcoffset() is None or expires_at.utcoffset() is None:
        raise ValueError("transfer timestamps must include a timezone")
    if not issued_at < expires_at <= issued_at + timedelta(hours=24):
        raise ValueError("transfer proposal expiry must be within 24 hours of issue")
    if not 256 <= max_output_tokens <= 16000:
        raise ValueError("invalid transfer output budget")
    if not sanitized_evidence or set(sanitized_evidence) != set(original_evidence_sha256):
        raise ValueError("sanitized evidence must cover the exact original hash references")
    if any(not re.fullmatch(r"[0-9a-f]{64}", value)
           for value in original_evidence_sha256.values()):
        raise ValueError("invalid original evidence digest")
    assert_safe_value(sanitized_evidence)
    payload = _canonical({
        "model": model, "store": False, "instructions": instructions,
        "input": [{"role": "user", "content": _canonical(sanitized_evidence).decode("utf-8")}],
        "max_output_tokens": max_output_tokens,
        "text": {"format": {"type": "json_schema", "name": "migration_proposal",
                            "strict": True, "schema": SpecialistProposal.model_json_schema()}},
    })
    if len(payload) > 100000:
        raise ValueError("minimized transfer proposal exceeds its byte budget")
    assert_safe_bytes(payload, filename="ai-egress-payload.json")
    from omni_migrator.security import scanner

    manifest = _canonical({
        "schema_version": "sigma-egress-proposal.v1", "tenant_ref": tenant_ref,
        "run_id": run_id, "purpose": purpose, "provider": "openai",
        "endpoint": "https://api.openai.com/v1/responses", "model": model,
        "account_ref": account_ref, "project_ref": project_ref,
        "original_evidence_sha256": original_evidence_sha256,
        "sanitized_evidence_sha256": {
            ref: _digest(_canonical(value)) for ref, value in sanitized_evidence.items()
        },
        "payload_sha256": _digest(payload), "payload_bytes": len(payload),
        "scanner_policy": scanner.POLICY_VERSION,
        "issued_at": issued_at.isoformat(), "expires_at": expires_at.isoformat(),
        "authorization_granted": False, "production_egress_enabled": False,
        "required_external_controls": ["authenticated_approver", "exact_payload_binding",
                                       "provider_account_binding", "revocation", "expiry", "replay"],
        "retention_verified": False,
    })
    assert_safe_bytes(manifest, filename="ai-egress-manifest.json")
    return PreparedEgress(payload=payload, manifest=manifest)

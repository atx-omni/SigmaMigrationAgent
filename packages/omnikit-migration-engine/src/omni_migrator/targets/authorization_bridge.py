"""Explicit operator-reviewed conversion between planner and driver vocabulary.

This helper grants no authority and never registers or consumes an authorization.
It accepts a complete reviewed target binding, not a request to infer one.
"""

from __future__ import annotations

from types import MappingProxyType
from typing import Any, Mapping

from omni_migrator.targets.contracts import TargetAuthorizationBinding


REVIEWED_TARGET_ACTIONS = MappingProxyType(
    {
        "create_dbt_branch_changes": "write_dbt_development_branch",
        "create_omni_model_branch_changes": "write_omni_authored_model_yaml",
        "create_omni_document_in_quarantine": "create_omni_document_in_quarantine",
        "create_omni_content_draft": "create_omni_content_draft",
    }
)

_PLANNER_FIELDS = frozenset(
    {
        "authorization_id",
        "actor_ref",
        "action",
        "scope_refs",
        "approved_at",
        "expires_at",
        "artifact_fingerprint",
        "validation_cycle_id",
        "evidence_ref",
    }
)


def bridge_reviewed_authorization(
    planner_authorization: Mapping[str, Any],
    *,
    planner_authorization_ref: str,
    reviewed_target_action: str,
    reviewed_target_binding: TargetAuthorizationBinding,
) -> TargetAuthorizationBinding:
    """Require review of the concrete action and every unchanged approval binding.

    The host supplies the trusted planner record and the complete operator-reviewed
    target binding. Only the four listed development actions are convertible.
    Promotion, publication, security changes, and implicit aliases are rejected.
    """
    source = dict(planner_authorization)
    if set(source) != _PLANNER_FIELDS:
        raise ValueError("planner authorization must contain its exact published fields")
    action = REVIEWED_TARGET_ACTIONS.get(source["action"])
    if action is None or reviewed_target_action != action:
        raise ValueError("operator review does not name the exact supported target action")
    if planner_authorization_ref != f"authorization-ref://{source['authorization_id']}":
        raise ValueError("planner authorization reference does not bind its exact identity")
    if not isinstance(source["scope_refs"], (list, tuple)):
        raise ValueError("planner authorization scopes must be an explicit sequence")
    expected = TargetAuthorizationBinding(
        authorization_ref=planner_authorization_ref,
        authorization_id=source["authorization_id"],
        actor_ref=source["actor_ref"],
        action=action,
        scope_refs=tuple(source["scope_refs"]),
        approved_at=source["approved_at"],
        expires_at=source["expires_at"],
        artifact_fingerprint=source["artifact_fingerprint"],
        validation_cycle_id=source["validation_cycle_id"],
        approval_evidence_ref=source["evidence_ref"],
    )
    reviewed = TargetAuthorizationBinding.model_validate(
        reviewed_target_binding.model_dump(mode="python")
    )
    if reviewed != expected:
        raise ValueError(
            "operator-reviewed target binding changes the approved identity, scope, or evidence"
        )
    return expected


__all__ = ["REVIEWED_TARGET_ACTIONS", "bridge_reviewed_authorization"]

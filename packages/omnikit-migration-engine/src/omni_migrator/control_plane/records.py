"""Immutable control-plane record and artifact envelope helpers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from omni_migrator.control_plane.canonical import (
    parse_time,
    sha256_json,
    validate_reference,
    validate_run_id,
)


class RecordValidationError(ValueError):
    """Raised when a control-plane record violates identity or lineage rules."""


@dataclass(frozen=True)
class ArtifactEnvelope:
    tenant_ref: str
    run_id: str
    artifact_id: str
    artifact_type: str
    revision: int
    ref: str
    content_sha256: str
    producer_ref: str
    producer_work_package_id: str | None
    input_artifacts: tuple[Mapping[str, Any], ...]
    validation_cycle_id: str
    created_at: str
    lineage_sha256: str
    migration_unit_id: str | None = None
    sensitivity: str = "internal"
    retention_policy_ref: str | None = None

    @classmethod
    def from_mapping(
        cls,
        value: Mapping[str, Any],
        *,
        require_published_contract: bool = False,
    ) -> "ArtifactEnvelope":
        published_fields = {
            "contract_version",
            "tenant_ref",
            "run_id",
            "artifact_id",
            "artifact_type",
            "revision",
            "ref",
            "content_sha256",
            "producer_ref",
            "producer_work_package_id",
            "input_artifacts",
            "validation_cycle_id",
            "created_at",
            "lineage_sha256",
            "migration_unit_id",
            "sensitivity",
            "retention_policy_ref",
            "immutable",
        }
        if extras := set(value) - published_fields:
            raise RecordValidationError(
                f"artifact envelope contains unknown fields: {sorted(extras)}"
            )
        contract_version = value.get("contract_version")
        if contract_version is not None and contract_version != "domo-to-omni.artifact-envelope.v1":
            raise RecordValidationError("artifact envelope contract version is unsupported")
        immutable = value.get("immutable")
        if immutable is not None and immutable is not True:
            raise RecordValidationError("artifact envelope must be immutable")
        if require_published_contract:
            missing = published_fields - set(value)
            if missing:
                raise RecordValidationError(
                    f"published artifact envelope is missing fields: {sorted(missing)}"
                )
            if value.get("contract_version") != "domo-to-omni.artifact-envelope.v1":
                raise RecordValidationError("published artifact envelope lacks its contract version")
            if value.get("immutable") is not True:
                raise RecordValidationError("published artifact envelope must declare immutable=true")
        return cls(
            tenant_ref=str(value["tenant_ref"]),
            run_id=str(value["run_id"]),
            artifact_id=str(value["artifact_id"]),
            artifact_type=str(value["artifact_type"]),
            revision=int(value["revision"]),
            ref=str(value["ref"]),
            content_sha256=str(value["content_sha256"]),
            producer_ref=str(value["producer_ref"]),
            producer_work_package_id=(
                str(value["producer_work_package_id"])
                if value.get("producer_work_package_id") is not None
                else None
            ),
            input_artifacts=tuple(value.get("input_artifacts", ())),
            validation_cycle_id=str(value["validation_cycle_id"]),
            created_at=str(value["created_at"]),
            lineage_sha256=str(value["lineage_sha256"]),
            migration_unit_id=(
                str(value["migration_unit_id"])
                if value.get("migration_unit_id") is not None
                else None
            ),
            sensitivity=str(value.get("sensitivity", "internal")),
            retention_policy_ref=(
                str(value["retention_policy_ref"])
                if value.get("retention_policy_ref") is not None
                else None
            ),
        )

    def to_mapping(self) -> dict[str, Any]:
        """Return the canonical published artifact-envelope contract shape."""

        return {
            "contract_version": "domo-to-omni.artifact-envelope.v1",
            "tenant_ref": self.tenant_ref,
            "run_id": self.run_id,
            "artifact_id": self.artifact_id,
            "artifact_type": self.artifact_type,
            "revision": self.revision,
            "ref": self.ref,
            "content_sha256": self.content_sha256,
            "producer_ref": self.producer_ref,
            "producer_work_package_id": self.producer_work_package_id,
            "input_artifacts": [dict(item) for item in self.input_artifacts],
            "validation_cycle_id": self.validation_cycle_id,
            "created_at": self.created_at,
            "lineage_sha256": self.lineage_sha256,
            "migration_unit_id": self.migration_unit_id,
            "sensitivity": self.sensitivity,
            "retention_policy_ref": self.retention_policy_ref,
            "immutable": True,
        }

    def lineage_material(self) -> dict[str, Any]:
        normalized_inputs = sorted(
            (
                {
                    "artifact_id": str(item["artifact_id"]),
                    "revision": int(item["revision"]),
                    "content_sha256": str(item["content_sha256"]),
                }
                for item in self.input_artifacts
            ),
            key=lambda item: (item["artifact_id"], item["revision"], item["content_sha256"]),
        )
        return {
            "tenant_ref": self.tenant_ref,
            "run_id": self.run_id,
            "artifact_id": self.artifact_id,
            "artifact_type": self.artifact_type,
            "revision": self.revision,
            "content_sha256": self.content_sha256,
            "producer_ref": self.producer_ref,
            "producer_work_package_id": self.producer_work_package_id,
            "input_artifacts": normalized_inputs,
            "validation_cycle_id": self.validation_cycle_id,
            "migration_unit_id": self.migration_unit_id,
        }

    def expected_lineage_sha256(self) -> str:
        return sha256_json(self.lineage_material())

    def validate(self, *, expected_tenant_ref: str | None = None, expected_run_id: str | None = None) -> None:
        validate_reference(self.tenant_ref)
        validate_run_id(self.run_id)
        validate_run_id(self.artifact_id)
        validate_run_id(self.artifact_type)
        validate_run_id(self.validation_cycle_id)
        if self.producer_work_package_id is not None:
            validate_run_id(self.producer_work_package_id)
        if self.migration_unit_id is not None:
            validate_run_id(self.migration_unit_id)
        validate_reference(self.ref)
        validate_reference(self.producer_ref)
        if self.retention_policy_ref:
            validate_reference(self.retention_policy_ref)
        if self.sensitivity in {"confidential", "restricted", "highly_restricted"} and not self.retention_policy_ref:
            raise RecordValidationError("sensitive artifacts require an explicit retention policy")
        if expected_tenant_ref is not None and self.tenant_ref != expected_tenant_ref:
            raise RecordValidationError("artifact crosses tenant partition")
        if expected_run_id is not None and self.run_id != expected_run_id:
            raise RecordValidationError("artifact crosses run partition")
        if self.revision < 1:
            raise RecordValidationError("artifact revision must be positive")
        try:
            parse_time(self.created_at)
        except (TypeError, ValueError) as exc:
            raise RecordValidationError("artifact creation time must be timezone-aware") from exc
        if self.sensitivity not in {
            "public",
            "internal",
            "confidential",
            "restricted",
            "highly_restricted",
        }:
            raise RecordValidationError("artifact sensitivity is unsupported")
        if len(self.content_sha256) != 64 or any(ch not in "0123456789abcdef" for ch in self.content_sha256):
            raise RecordValidationError("artifact content hash is not lowercase SHA-256")
        input_identities: set[tuple[str, int]] = set()
        for item in self.input_artifacts:
            try:
                artifact_id = str(item["artifact_id"])
                revision = int(item["revision"])
                content_sha256 = str(item["content_sha256"])
            except (KeyError, TypeError, ValueError) as exc:
                raise RecordValidationError("artifact input identity is malformed") from exc
            validate_run_id(artifact_id)
            if revision < 1:
                raise RecordValidationError("artifact input revision must be positive")
            if len(content_sha256) != 64 or any(
                ch not in "0123456789abcdef" for ch in content_sha256
            ):
                raise RecordValidationError("artifact input hash is not lowercase SHA-256")
            identity = (artifact_id, revision)
            if identity in input_identities:
                raise RecordValidationError("artifact input revisions must be unique")
            input_identities.add(identity)
        if self.lineage_sha256 != self.expected_lineage_sha256():
            raise RecordValidationError("artifact lineage hash does not match its envelope")


def validate_artifact_identity_series(
    artifacts: list[ArtifactEnvelope] | tuple[ArtifactEnvelope, ...],
) -> None:
    """Require one immutable type/unit identity for each run-scoped artifact ID.

    Revisions may change content and validation cycle, but an artifact ID may never
    be reused for another artifact type or migration unit. This keeps append-only
    revision, invalidation, QA, and gate freshness semantics globally consistent.
    """

    identities: dict[str, tuple[str, str | None]] = {}
    revision_identities: set[tuple[str, int]] = set()
    refs: set[str] = set()
    for artifact in artifacts:
        identity = (artifact.artifact_type, artifact.migration_unit_id)
        previous = identities.setdefault(artifact.artifact_id, identity)
        if previous != identity:
            raise RecordValidationError(
                "artifact identity is immutable across revisions: "
                f"{artifact.artifact_id} changed type or migration unit"
            )
        revision_identity = (artifact.artifact_id, artifact.revision)
        if revision_identity in revision_identities:
            raise RecordValidationError(
                "artifact revision identity is duplicated within the run: "
                f"{artifact.artifact_id}@{artifact.revision}"
            )
        revision_identities.add(revision_identity)
        if artifact.ref in refs:
            raise RecordValidationError(
                "artifact reference is not unique within the run: "
                f"{artifact.ref} identifies multiple artifact revisions"
            )
        refs.add(artifact.ref)


def artifact_lineage_hash(value: Mapping[str, Any]) -> str:
    """Compute a lineage hash for an envelope before it is registered."""

    provisional = dict(value)
    provisional.setdefault("lineage_sha256", "0" * 64)
    return ArtifactEnvelope.from_mapping(provisional).expected_lineage_sha256()


def downstream_artifact_ids(
    artifacts: list[ArtifactEnvelope], changed_artifact_ids: set[str]
) -> set[str]:
    """Return the transitive downstream closure for superseded artifacts."""

    invalidated = set(changed_artifact_ids)
    changed = True
    while changed:
        changed = False
        for artifact in artifacts:
            if artifact.artifact_id in invalidated:
                continue
            input_ids = {str(item["artifact_id"]) for item in artifact.input_artifacts}
            if input_ids & invalidated:
                invalidated.add(artifact.artifact_id)
                changed = True
    return invalidated

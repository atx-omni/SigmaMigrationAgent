"""Immutable semantic-profile denominator and current-profile coverage contracts.

The manifest in this module is evidence, not authority.  A manifest is complete
only when it is validated against a trusted context derived from the canonical
control-plane partition.  That context supplies the exact denominator and the
actual current semantic-profile payloads; caller-asserted profile bindings alone
are deliberately insufficient.
"""

from __future__ import annotations

from collections import Counter
from copy import deepcopy
from typing import Any, Literal, Mapping, Sequence
from urllib.parse import quote, urlsplit

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from omni_migrator.control_plane.canonical import parse_time, sha256_json
from omni_migrator.control_plane.domo_inventory import (
    semantic_profile_requirement_hash,
)
from omni_migrator.semantic.models import AssetIdentity, SemanticProfile
from omni_migrator.semantic.profiles import validate_semantic_profile

_SHA256_PATTERN = r"^sha256:[a-f0-9]{64}$"
_RAW_SHA256_PATTERN = r"^[a-f0-9]{64}$"
_STABLE_ID_PATTERN = r"^[a-z0-9][a-z0-9._-]{7,127}$"
_NON_SECRET_REF_PATTERN = r"^[A-Za-z][A-Za-z0-9+.-]*:.+$"
_OWNER_REF_PATTERN = r"^(?:human-ref|person-ref|person|team-ref|external-team-ref):.+$"

SubjectKind = Literal[
    "source_object",
    "repository_resource",
    "dashboard_query",
    "pdp_security",
    "target_semantic",
]
InclusionBasis = Literal[
    "migration_selected",
    "dependency_reachable",
    "commonality_eligible",
    "repository_required",
    "dashboard_query_required",
    "pdp_security_required",
    "target_proposal_required",
]
RevisionBindingName = Literal[
    "source_snapshot", "portfolio", "migration_scope", "repository", "target_proposals"
]

_EXPECTED_ARTIFACT_TYPES = {
    "source_snapshot": "inventory_snapshot",
    "portfolio": "domo_portfolio_inventory",
    "migration_scope": "migration_scope",
    "repository": "repository_inventory",
    "target_proposals": "target_semantic_profile",
}
_SUBJECT_BINDINGS: dict[str, str] = {
    "source_object": "portfolio",
    "repository_resource": "repository",
    "dashboard_query": "portfolio",
    "pdp_security": "portfolio",
    "target_semantic": "target_proposals",
}
_SUBJECT_BASES: dict[str, frozenset[str]] = {
    "source_object": frozenset(
        {"migration_selected", "dependency_reachable", "commonality_eligible"}
    ),
    "repository_resource": frozenset({"repository_required"}),
    "dashboard_query": frozenset(
        {
            "dashboard_query_required",
            "migration_selected",
            "dependency_reachable",
            "commonality_eligible",
        }
    ),
    "pdp_security": frozenset(
        {
            "pdp_security_required",
            "migration_selected",
            "dependency_reachable",
            "commonality_eligible",
        }
    ),
    "target_semantic": frozenset({"target_proposal_required"}),
}
_SUBJECT_PRODUCERS: dict[str, frozenset[str]] = {
    "source_object": frozenset(
        {
            "agent-ref://domo-analytics-engineer",
            "agent-ref://domo-bi-developer",
        }
    ),
    "repository_resource": frozenset({"agent-ref://dbt-analytics-engineer"}),
    "dashboard_query": frozenset({"agent-ref://domo-bi-developer"}),
    "pdp_security": frozenset(
        {
            "agent-ref://domo-analytics-engineer",
            "agent-ref://domo-bi-developer",
        }
    ),
    "target_semantic": frozenset({"agent-ref://domo-to-omni-architect"}),
}

_DOMO_PROFILE_KINDS: dict[str, str] = {
    "dataset": "dataset_output",
    "dataflow": "transformation",
    "magic_etl": "transformation",
    "sql_dataflow": "transformation",
    "beast_mode": "calculation",
    "variable": "calculation",
    "card": "dashboard_query",
    "page": "dashboard_query",
    "subpage": "dashboard_query",
    "pdp_policy": "security_policy",
    "workflow": "workflow_output",
}


def _sha256(value: Any) -> str:
    return f"sha256:{sha256_json(value)}"


def _raw(value: Mapping[str, Any] | BaseModel) -> dict[str, Any]:
    return (
        value.model_dump(mode="json")
        if isinstance(value, BaseModel)
        else deepcopy(dict(value))
    )


def _tupleize(value: Any) -> Any:
    if isinstance(value, list):
        return tuple(_tupleize(item) for item in value)
    if isinstance(value, tuple):
        return tuple(_tupleize(item) for item in value)
    if isinstance(value, Mapping):
        return {key: _tupleize(item) for key, item in value.items()}
    return value


def _canonical_hash(value: Mapping[str, Any] | BaseModel, self_field: str) -> str:
    material = _raw(value)
    material.pop(self_field, None)
    return _sha256(material)


def _safe_reference(value: str) -> str:
    parsed = urlsplit(value)
    if (
        not parsed.scheme
        or parsed.scheme.lower()
        in {
            "secret",
            "secret-ref",
            "vault",
            "vault-ref",
            "credential",
            "credential-ref",
        }
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or any(character.isspace() for character in value)
        or (not parsed.netloc and not parsed.path)
    ):
        raise ValueError("coverage references must be safe non-secret URI references")
    return value


def _validation_messages(exc: ValidationError) -> tuple[str, ...]:
    messages: list[str] = []
    for item in exc.errors(include_url=False):
        location = ".".join(str(part) for part in item["loc"])
        message = item["msg"]
        messages.append(f"{location}: {message}" if location else message)
    return tuple(sorted(set(messages)))


class _StrictFrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    @model_validator(mode="after")
    def references_are_safe(self) -> "_StrictFrozenModel":
        for name in type(self).model_fields:
            if not (name.endswith("_ref") or name.endswith("_refs")):
                continue
            value = getattr(self, name)
            values = value if isinstance(value, tuple) else (value,)
            for reference in values:
                if isinstance(reference, str):
                    _safe_reference(reference)
        return self


class ArtifactRevisionBinding(_StrictFrozenModel):
    tenant_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    run_id: str = Field(pattern=_STABLE_ID_PATTERN)
    scope_id: str = Field(pattern=_STABLE_ID_PATTERN)
    migration_unit_id: str = Field(pattern=_STABLE_ID_PATTERN)
    validation_cycle_id: str = Field(pattern=_STABLE_ID_PATTERN)
    artifact_id: str = Field(pattern=_STABLE_ID_PATTERN)
    artifact_type: Literal[
        "inventory_snapshot",
        "domo_portfolio_inventory",
        "migration_scope",
        "repository_inventory",
        "target_semantic_profile",
        "semantic_profile",
    ]
    artifact_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    revision: int = Field(ge=1)
    content_sha256: str = Field(pattern=_RAW_SHA256_PATTERN)
    semantic_hash: str = Field(pattern=_SHA256_PATTERN)
    producer_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    binding_hash: str = Field(pattern=_SHA256_PATTERN)


class CoverageRevisionBindings(_StrictFrozenModel):
    source_snapshot: ArtifactRevisionBinding
    portfolio: ArtifactRevisionBinding
    migration_scope: ArtifactRevisionBinding
    repository: ArtifactRevisionBinding
    target_proposals: tuple[ArtifactRevisionBinding, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def bindings_are_exact_and_partitioned(self) -> "CoverageRevisionBindings":
        partition: tuple[str, ...] | None = None
        exact_targets: set[tuple[str, int, str, str]] = set()
        for name, value in self:
            bindings = value if isinstance(value, tuple) else (value,)
            expected_type = _EXPECTED_ARTIFACT_TYPES[name]
            for binding in bindings:
                if binding.artifact_type != expected_type:
                    raise ValueError(f"{name} must bind artifact type {expected_type}")
                current = (
                    binding.tenant_ref,
                    binding.run_id,
                    binding.scope_id,
                    binding.migration_unit_id,
                    binding.validation_cycle_id,
                )
                if partition is None:
                    partition = current
                elif current != partition:
                    raise ValueError(
                        "coverage revision bindings cross control-plane partitions"
                    )
                if name == "target_proposals":
                    exact_target = (
                        binding.artifact_id,
                        binding.revision,
                        binding.content_sha256,
                        binding.semantic_hash,
                    )
                    if exact_target in exact_targets:
                        raise ValueError("coverage repeats an exact target proposal binding")
                    exact_targets.add(exact_target)
        return self


class SemanticCoverageSubject(_StrictFrozenModel):
    subject_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    subject_kind: SubjectKind
    profile_identity: AssetIdentity
    inclusion_basis: tuple[InclusionBasis, ...] = Field(min_length=1)
    derived_from_binding: RevisionBindingName
    source_artifact_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    source_artifact_revision: int = Field(ge=1)
    source_revision_hash: str = Field(pattern=_SHA256_PATTERN)
    subject_hash: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def inclusion_is_exact(self) -> "SemanticCoverageSubject":
        if len(self.inclusion_basis) != len(set(self.inclusion_basis)):
            raise ValueError("subject repeats an inclusion basis")
        allowed = _SUBJECT_BASES[self.subject_kind]
        if not set(self.inclusion_basis).issubset(allowed):
            raise ValueError("subject inclusion basis does not match subject kind")
        if self.subject_kind == "source_object" and not set(self.inclusion_basis).intersection(
            allowed
        ):
            raise ValueError("source objects must be selected or commonality eligible")
        required_basis = {
            "repository_resource": "repository_required",
            "dashboard_query": "dashboard_query_required",
            "pdp_security": "pdp_security_required",
            "target_semantic": "target_proposal_required",
        }.get(self.subject_kind)
        if required_basis is not None and required_basis not in self.inclusion_basis:
            raise ValueError(f"{self.subject_kind} requires inclusion basis {required_basis}")
        if self.derived_from_binding != _SUBJECT_BINDINGS[self.subject_kind]:
            raise ValueError("subject is derived from the wrong revision binding")
        return self


class SemanticProfileBinding(_StrictFrozenModel):
    artifact: ArtifactRevisionBinding
    profile_id: str = Field(pattern=_STABLE_ID_PATTERN)
    profile_hash: str = Field(pattern=_SHA256_PATTERN)
    identity: AssetIdentity

    @model_validator(mode="after")
    def artifact_is_a_profile(self) -> "SemanticProfileBinding":
        if self.artifact.artifact_type not in {
            "semantic_profile",
            "target_semantic_profile",
        }:
            raise ValueError("profile resolutions must bind semantic profile artifacts")
        return self


class OwnedCoverageBlocker(_StrictFrozenModel):
    blocker_id: str = Field(pattern=_STABLE_ID_PATTERN)
    owner_ref: str = Field(pattern=_OWNER_REF_PATTERN)
    reason_code: str = Field(pattern=_STABLE_ID_PATTERN)
    summary: str = Field(min_length=1, max_length=4096)
    evidence_refs: tuple[str, ...] = Field(min_length=1)
    opened_at: str
    blocker_hash: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def blocker_is_well_formed(self) -> "OwnedCoverageBlocker":
        parse_time(self.opened_at)
        if len(self.evidence_refs) != len(set(self.evidence_refs)):
            raise ValueError("blocker repeats evidence references")
        return self


class SemanticCoverageResolution(_StrictFrozenModel):
    subject_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    subject_hash: str = Field(pattern=_SHA256_PATTERN)
    disposition: Literal["profile", "blocker"]
    profile: SemanticProfileBinding | None
    blocker: OwnedCoverageBlocker | None
    resolution_hash: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def exactly_one_resolution(self) -> "SemanticCoverageResolution":
        if self.disposition == "profile" and (self.profile is None or self.blocker is not None):
            raise ValueError("profile dispositions require only a profile binding")
        if self.disposition == "blocker" and (self.blocker is None or self.profile is not None):
            raise ValueError("blocker dispositions require only an owned blocker")
        return self


class CoverageAuthority(_StrictFrozenModel):
    authorizes_tenant_acceptance: Literal[False]
    authorizes_target_writes: Literal[False]
    authorizes_promotion: Literal[False]
    authorizes_cutover: Literal[False]
    authorizes_decommissioning: Literal[False]


class SemanticProfileCoverage(_StrictFrozenModel):
    contract_version: Literal["domo-to-omni.semantic-profile-coverage.v1"]
    coverage_id: str = Field(pattern=_STABLE_ID_PATTERN)
    coverage_revision: int = Field(ge=1)
    supersedes_coverage_hash: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
    )
    tenant_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    run_id: str = Field(pattern=_STABLE_ID_PATTERN)
    scope_id: str = Field(pattern=_STABLE_ID_PATTERN)
    migration_unit_id: str = Field(pattern=_STABLE_ID_PATTERN)
    validation_cycle_id: str = Field(pattern=_STABLE_ID_PATTERN)
    revision_bindings: CoverageRevisionBindings
    status: Literal["complete", "blocked"]
    subjects: tuple[SemanticCoverageSubject, ...] = Field(min_length=1)
    subject_count: int = Field(ge=1)
    denominator_hash: str = Field(pattern=_SHA256_PATTERN)
    resolutions: tuple[SemanticCoverageResolution, ...] = Field(min_length=1)
    resolution_count: int = Field(ge=1)
    profile_producer_refs: tuple[str, ...]
    evidence_refs: tuple[str, ...] = Field(min_length=1)
    producer_ref: Literal["agent-ref://domo-to-omni-architect"]
    assembled_at: str
    coverage_hash: str = Field(pattern=_SHA256_PATTERN)
    authority: CoverageAuthority
    immutable: Literal[True]
    provenance: dict[str, Any]
    security_metadata: dict[str, Any]

    @model_validator(mode="after")
    def denominator_is_closed(self) -> "SemanticProfileCoverage":
        parse_time(self.assembled_at)
        if (self.coverage_revision == 1) != (self.supersedes_coverage_hash is None):
            raise ValueError(
                "only coverage revision one may omit supersedes_coverage_hash"
            )
        partition = (
            self.tenant_ref,
            self.run_id,
            self.scope_id,
            self.migration_unit_id,
            self.validation_cycle_id,
        )
        binding_partition = self.revision_bindings.source_snapshot
        if partition != (
            binding_partition.tenant_ref,
            binding_partition.run_id,
            binding_partition.scope_id,
            binding_partition.migration_unit_id,
            binding_partition.validation_cycle_id,
        ):
            raise ValueError("coverage manifest and revision bindings cross partitions")

        subject_refs = [subject.subject_ref for subject in self.subjects]
        subject_identities = [
            (
                subject.profile_identity.system,
                subject.profile_identity.kind,
                subject.profile_identity.object_id,
                subject.profile_identity.revision_hash,
            )
            for subject in self.subjects
        ]
        resolution_refs = [resolution.subject_ref for resolution in self.resolutions]
        if len(subject_refs) != len(set(subject_refs)):
            raise ValueError("coverage denominator repeats subject references")
        if len(subject_identities) != len(set(subject_identities)):
            raise ValueError("coverage denominator repeats subject identities")
        if len(resolution_refs) != len(set(resolution_refs)):
            raise ValueError("coverage manifest repeats subject resolutions")
        if self.subject_count != len(self.subjects):
            raise ValueError("subject_count does not match the denominator")
        if self.resolution_count != len(self.resolutions):
            raise ValueError("resolution_count does not match resolutions")
        if Counter(subject_refs) != Counter(resolution_refs):
            raise ValueError("every denominator subject requires exactly one resolution")

        subjects = {subject.subject_ref: subject for subject in self.subjects}
        expected_producers: set[str] = set()
        profile_artifact_refs: set[str] = set()
        profile_ids: set[str] = set()
        blocker_count = 0
        for resolution in self.resolutions:
            subject = subjects[resolution.subject_ref]
            if resolution.subject_hash != subject.subject_hash:
                raise ValueError("resolution subject hash does not match its denominator subject")
            if resolution.profile is not None:
                if resolution.profile.identity != subject.profile_identity:
                    raise ValueError("profile resolution substitutes a different subject identity")
                artifact = resolution.profile.artifact
                expected_profile_type = (
                    "target_semantic_profile"
                    if subject.subject_kind == "target_semantic"
                    else "semantic_profile"
                )
                if artifact.artifact_type != expected_profile_type:
                    raise ValueError(
                        "profile resolution uses the wrong artifact type for its subject"
                    )
                if (
                    artifact.tenant_ref,
                    artifact.run_id,
                    artifact.scope_id,
                    artifact.migration_unit_id,
                    artifact.validation_cycle_id,
                ) != partition:
                    raise ValueError("profile resolution crosses the coverage partition")
                if artifact.producer_ref not in _SUBJECT_PRODUCERS[subject.subject_kind]:
                    raise ValueError("profile resolution uses an unauthorized subject producer")
                if artifact.artifact_ref in profile_artifact_refs:
                    raise ValueError("one semantic-profile artifact resolves multiple subjects")
                if resolution.profile.profile_id in profile_ids:
                    raise ValueError("one semantic profile resolves multiple subjects")
                profile_artifact_refs.add(artifact.artifact_ref)
                profile_ids.add(resolution.profile.profile_id)
                expected_producers.add(artifact.producer_ref)
            else:
                blocker_count += 1

        if tuple(sorted(expected_producers)) != self.profile_producer_refs:
            raise ValueError("profile_producer_refs do not match all profile resolutions")
        if len(self.profile_producer_refs) != len(set(self.profile_producer_refs)):
            raise ValueError("profile_producer_refs contains duplicates")
        if len(self.evidence_refs) != len(set(self.evidence_refs)):
            raise ValueError("coverage evidence references contain duplicates")
        if self.status == "complete" and blocker_count:
            raise ValueError("complete coverage cannot contain blockers")
        if self.status == "blocked" and not blocker_count:
            raise ValueError("blocked coverage requires at least one owned blocker")

        for subject in self.subjects:
            binding_value = getattr(
                self.revision_bindings, subject.derived_from_binding
            )
            source_bindings = (
                binding_value if isinstance(binding_value, tuple) else (binding_value,)
            )
            matches = [
                binding
                for binding in source_bindings
                if subject.source_artifact_ref == binding.artifact_ref
                and subject.source_artifact_revision == binding.revision
                and subject.source_revision_hash == binding.semantic_hash
            ]
            if len(matches) != 1:
                raise ValueError("subject is stale against its declared revision binding")
        return self


class CurrentSemanticProfileEvidence(_StrictFrozenModel):
    subject_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    artifact: ArtifactRevisionBinding
    profile: SemanticProfile


class SemanticProfileCoverageValidationContext(_StrictFrozenModel):
    tenant_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    run_id: str = Field(pattern=_STABLE_ID_PATTERN)
    scope_id: str = Field(pattern=_STABLE_ID_PATTERN)
    migration_unit_id: str = Field(pattern=_STABLE_ID_PATTERN)
    validation_cycle_id: str = Field(pattern=_STABLE_ID_PATTERN)
    revision_bindings: CoverageRevisionBindings
    expected_subjects: tuple[SemanticCoverageSubject, ...] = Field(min_length=1)
    current_profiles: tuple[CurrentSemanticProfileEvidence, ...]

    @model_validator(mode="after")
    def context_is_partitioned(self) -> "SemanticProfileCoverageValidationContext":
        refs = [subject.subject_ref for subject in self.expected_subjects]
        identities = [
            (
                subject.profile_identity.system,
                subject.profile_identity.kind,
                subject.profile_identity.object_id,
                subject.profile_identity.revision_hash,
            )
            for subject in self.expected_subjects
        ]
        if len(refs) != len(set(refs)):
            raise ValueError("trusted denominator repeats subject references")
        if len(identities) != len(set(identities)):
            raise ValueError("trusted denominator repeats subject identities")
        partition = (
            self.tenant_ref,
            self.run_id,
            self.scope_id,
            self.migration_unit_id,
            self.validation_cycle_id,
        )
        source = self.revision_bindings.source_snapshot
        if partition != (
            source.tenant_ref,
            source.run_id,
            source.scope_id,
            source.migration_unit_id,
            source.validation_cycle_id,
        ):
            raise ValueError("trusted context and revision bindings cross partitions")
        return self


def artifact_revision_binding_hash(value: Mapping[str, Any] | ArtifactRevisionBinding) -> str:
    return _canonical_hash(value, "binding_hash")


def semantic_coverage_subject_hash(value: Mapping[str, Any] | SemanticCoverageSubject) -> str:
    return _canonical_hash(value, "subject_hash")


def owned_coverage_blocker_hash(value: Mapping[str, Any] | OwnedCoverageBlocker) -> str:
    return _canonical_hash(value, "blocker_hash")


def semantic_coverage_resolution_hash(
    value: Mapping[str, Any] | SemanticCoverageResolution,
) -> str:
    return _canonical_hash(value, "resolution_hash")


def semantic_profile_coverage_denominator_hash(
    subjects: Sequence[Mapping[str, Any] | SemanticCoverageSubject],
) -> str:
    ordered = sorted((_raw(subject) for subject in subjects), key=lambda item: item["subject_ref"])
    return _sha256({"subjects": ordered})


def semantic_profile_coverage_hash(
    value: Mapping[str, Any] | SemanticProfileCoverage,
) -> str:
    return _canonical_hash(value, "coverage_hash")


def semantic_profile_coverage_content_sha256(
    value: Mapping[str, Any] | SemanticProfileCoverage,
) -> str:
    """Return the raw content digest expected by an ArtifactEnvelope."""

    return sha256_json(_raw(value))


def coverage_artifact_revision_binding(
    envelope: Mapping[str, Any] | Any,
    *,
    scope_id: str,
    semantic_hash: str,
    migration_unit_id: str | None = None,
) -> ArtifactRevisionBinding:
    """Create a canonical exact revision binding for store-derived coverage context."""

    from omni_migrator.control_plane.records import ArtifactEnvelope

    value = (
        envelope
        if isinstance(envelope, ArtifactEnvelope)
        else ArtifactEnvelope.from_mapping(envelope)
    )
    resolved_unit_id = value.migration_unit_id or migration_unit_id
    if resolved_unit_id is None:
        raise ValueError("semantic-profile coverage bindings require a migration unit")
    if (
        value.migration_unit_id is not None
        and migration_unit_id is not None
        and value.migration_unit_id != migration_unit_id
    ):
        raise ValueError("semantic-profile coverage binding crosses a migration unit")
    raw = {
        "tenant_ref": value.tenant_ref,
        "run_id": value.run_id,
        "scope_id": scope_id,
        "migration_unit_id": resolved_unit_id,
        "validation_cycle_id": value.validation_cycle_id,
        "artifact_id": value.artifact_id,
        "artifact_type": value.artifact_type,
        "artifact_ref": value.ref,
        "revision": value.revision,
        "content_sha256": value.content_sha256,
        "semantic_hash": semantic_hash,
        "producer_ref": value.producer_ref,
        "binding_hash": "sha256:" + "0" * 64,
    }
    raw["binding_hash"] = artifact_revision_binding_hash(raw)
    return ArtifactRevisionBinding.model_validate(raw, strict=True)


def derive_semantic_profile_subject_denominator(
    *,
    portfolio: Mapping[str, Any],
    migration_scope: Mapping[str, Any],
    repository_inventory: Mapping[str, Any],
    target_profiles: Sequence[Mapping[str, Any] | SemanticProfile],
    revision_bindings: CoverageRevisionBindings | Mapping[str, Any],
    migration_unit_id: str,
) -> tuple[SemanticCoverageSubject, ...]:
    """Derive the exact unit denominator from canonical registered payloads.

    Repository inventory is already scoped by its registered artifact envelope, so
    every applicable resource and semantic asset in that immutable snapshot is
    included.  Domo subjects are the selected unit's dependency closure plus every
    commonality-eligible object in the canonical comparison scope.  Every accepted
    source context and every proposed target semantic artifact is an independent
    subject; unrelated portfolio/profile registrations cannot expand the denominator
    and no aggregate profile can hide omissions.
    """

    bindings = (
        revision_bindings
        if isinstance(revision_bindings, CoverageRevisionBindings)
        else CoverageRevisionBindings.model_validate(_tupleize(revision_bindings), strict=True)
    )
    units = [
        unit
        for wave in migration_scope.get("waves", [])
        if isinstance(wave, Mapping)
        for unit in wave.get("units", [])
        if isinstance(unit, Mapping) and unit.get("migration_unit_id") == migration_unit_id
    ]
    if len(units) != 1:
        raise ValueError("coverage denominator requires exactly one canonical migration unit")
    selected_ids = {
        str(item.get("object_id"))
        for item in units[0].get("source_objects", [])
        if isinstance(item, Mapping)
    }
    objects = {
        str(item.get("identity", {}).get("object_id")): item
        for item in portfolio.get("objects", [])
        if isinstance(item, Mapping) and isinstance(item.get("identity"), Mapping)
    }
    if missing := sorted(selected_ids - set(objects)):
        raise ValueError(f"migration unit source objects are absent from the portfolio: {missing}")

    comparison_ids = {
        str(item.get("object_id"))
        for item in migration_scope.get("comparison_scope", [])
        if isinstance(item, Mapping)
    }
    if missing := sorted(comparison_ids - set(objects)):
        raise ValueError(
            "comparison-scope objects are absent from the portfolio: "
            f"{missing}"
        )

    reachable = set(selected_ids)
    pending = list(selected_ids)
    while pending:
        current = pending.pop()
        lineage = objects[current].get("lineage", {})
        dependency_ids = (
            lineage.get("consumer_object_ids", []) if isinstance(lineage, Mapping) else []
        )
        for dependency_id in dependency_ids:
            dependency = str(dependency_id)
            if dependency in objects and dependency not in reachable:
                reachable.add(dependency)
                pending.append(dependency)
    eligible_ids = {
        str(value)
        for value in portfolio.get("commonality_admission", {}).get(
            "eligible_object_ids", []
        )
    }
    if missing := sorted(eligible_ids - set(objects)):
        raise ValueError(
            "commonality-eligible objects are absent from the portfolio: "
            f"{missing}"
        )
    applicable_ids = reachable | (eligible_ids & comparison_ids)

    raw_subjects: list[dict[str, Any]] = []
    for object_id in sorted(applicable_ids):
        item = objects[object_id]
        identity = item["identity"]
        object_type = str(identity.get("object_type"))
        if object_type in {"card", "page", "subpage"}:
            subject_kind = "dashboard_query"
            required_basis = "dashboard_query_required"
        elif object_type == "pdp_policy":
            subject_kind = "pdp_security"
            required_basis = "pdp_security_required"
        else:
            subject_kind = "source_object"
            required_basis = None
        bases = []
        if object_id in selected_ids:
            bases.append("migration_selected")
        elif object_id in reachable:
            bases.append("dependency_reachable")
        if object_id in eligible_ids:
            bases.append("commonality_eligible")
        if required_basis is not None:
            bases.append(required_basis)
        expected_profile_kind = _DOMO_PROFILE_KINDS.get(object_type)
        requirements = item.get("semantic_profile_requirements", [])
        if expected_profile_kind is None:
            continue
        if not isinstance(requirements, list) or not requirements:
            raise ValueError(
                f"portfolio object {object_id} lacks explicit semantic profile requirements"
            )
        for requirement in requirements:
            if not isinstance(requirement, Mapping):
                raise ValueError(
                    f"portfolio object {object_id} has a malformed profile requirement"
                )
            requirement_id = str(requirement.get("requirement_id", ""))
            requirement_hash = str(requirement.get("requirement_hash", ""))
            context_id = str(requirement.get("context_id", ""))
            context_hash = str(requirement.get("context_hash", ""))
            if (
                requirement.get("base_object_id") != object_id
                or requirement.get("profile_kind") != expected_profile_kind
                or requirement_hash != semantic_profile_requirement_hash(requirement)
            ):
                raise ValueError(
                    f"portfolio object {object_id} has a stale or misbound profile requirement"
                )
            definition = item.get("definition", {})
            if isinstance(definition, Mapping) and definition.get("content_hash") is not None:
                if requirement.get("source_revision_hash") != definition.get("content_hash"):
                    raise ValueError(
                        f"portfolio object {object_id} profile requirement uses a foreign revision"
                    )
            profile_object_id = (
                object_id
                if context_id == "base"
                else f"{object_id}.context.{context_hash[7:23]}"
            )
            raw_subjects.append(
                {
                    "subject_ref": (
                        f"subject-ref://domo/{quote(object_id, safe='._-')}/"
                        f"{quote(requirement_id, safe='._-')}"
                    ),
                    "subject_kind": subject_kind,
                    "profile_identity": {
                        "system": "domo",
                        "kind": expected_profile_kind,
                        "object_id": profile_object_id,
                        "revision_hash": requirement_hash,
                    },
                    "inclusion_basis": sorted(set(bases)),
                    "derived_from_binding": "portfolio",
                    "source_artifact_ref": bindings.portfolio.artifact_ref,
                    "source_artifact_revision": bindings.portfolio.revision,
                    "source_revision_hash": bindings.portfolio.semantic_hash,
                    "subject_hash": "sha256:" + "0" * 64,
                }
            )

    for item in repository_inventory.get("resources", []):
        if str(item.get("resource_type", "")).lower() not in {
            "model",
            "source",
            "seed",
            "snapshot",
        }:
            continue
        raw_subjects.append(
            {
                "subject_ref": f"subject-ref://repository/{quote(str(item['unique_id']), safe='._-')}",
                "subject_kind": "repository_resource",
                "profile_identity": {
                    "system": "dbt",
                    "kind": "dbt_resource",
                    "object_id": str(item["unique_id"]),
                    "revision_hash": str(item["resource_hash"]),
                },
                "inclusion_basis": ["repository_required"],
                "derived_from_binding": "repository",
                "source_artifact_ref": bindings.repository.artifact_ref,
                "source_artifact_revision": bindings.repository.revision,
                "source_revision_hash": bindings.repository.semantic_hash,
                "subject_hash": "sha256:" + "0" * 64,
            }
        )
    for item in repository_inventory.get("semantic_assets", []):
        raw_subjects.append(
            {
                "subject_ref": f"subject-ref://repository/{quote(str(item['asset_id']), safe='._-')}",
                "subject_kind": "repository_resource",
                "profile_identity": {
                    "system": "dbt",
                    "kind": "dbt_resource",
                    "object_id": str(item["asset_id"]),
                    "revision_hash": str(item["definition_hash"]),
                },
                "inclusion_basis": ["repository_required"],
                "derived_from_binding": "repository",
                "source_artifact_ref": bindings.repository.artifact_ref,
                "source_artifact_revision": bindings.repository.revision,
                "source_revision_hash": bindings.repository.semantic_hash,
                "subject_hash": "sha256:" + "0" * 64,
            }
        )

    normalized_targets = [
        profile
        if isinstance(profile, SemanticProfile)
        else SemanticProfile.model_validate(profile)
        for profile in target_profiles
    ]
    if not normalized_targets:
        raise ValueError("coverage requires one or more target proposal profiles per unit")
    target_bindings_by_hash = {
        binding.semantic_hash: binding for binding in bindings.target_proposals
    }
    if len(target_bindings_by_hash) != len(bindings.target_proposals):
        raise ValueError("target proposal bindings must have unique semantic hashes")
    target_hashes = {target.profile_hash for target in normalized_targets}
    if len(target_hashes) != len(normalized_targets):
        raise ValueError("target proposal profiles must be unique")
    if target_hashes != set(target_bindings_by_hash):
        raise ValueError(
            "target proposal profiles do not exactly match their artifact revision bindings"
        )
    for target in normalized_targets:
        target_binding = target_bindings_by_hash[target.profile_hash]
        raw_subjects.append(
            {
                "subject_ref": (
                    f"subject-ref://target/{quote(target.identity.object_id, safe='._-')}"
                ),
                "subject_kind": "target_semantic",
                "profile_identity": target.identity.model_dump(mode="json"),
                "inclusion_basis": ["target_proposal_required"],
                "derived_from_binding": "target_proposals",
                "source_artifact_ref": target_binding.artifact_ref,
                "source_artifact_revision": target_binding.revision,
                "source_revision_hash": target_binding.semantic_hash,
                "subject_hash": "sha256:" + "0" * 64,
            }
        )

    subjects: list[SemanticCoverageSubject] = []
    for raw in raw_subjects:
        raw["subject_hash"] = semantic_coverage_subject_hash(raw)
        subjects.append(SemanticCoverageSubject.model_validate(_tupleize(raw), strict=True))
    ordered = tuple(sorted(subjects, key=lambda item: item.subject_ref))
    refs = [item.subject_ref for item in ordered]
    identities = [item.profile_identity for item in ordered]
    if len(refs) != len(set(refs)) or len(identities) != len(set(identities)):
        raise ValueError("derived semantic-profile denominator contains duplicate subjects")
    return ordered


def finalize_semantic_profile_coverage(value: Mapping[str, Any]) -> SemanticProfileCoverage:
    """Canonicalize and hash a draft without asserting store-backed completeness."""

    result = deepcopy(dict(value))
    bindings = result["revision_bindings"]
    for binding_value in bindings.values():
        binding_items = (
            binding_value if isinstance(binding_value, list) else [binding_value]
        )
        for binding in binding_items:
            binding["binding_hash"] = artifact_revision_binding_hash(binding)

    subjects = list(result.get("subjects", []))
    for subject in subjects:
        subject["inclusion_basis"] = sorted(subject.get("inclusion_basis", []))
        subject["subject_hash"] = semantic_coverage_subject_hash(subject)
    subjects.sort(key=lambda subject: subject["subject_ref"])
    result["subjects"] = subjects
    result["subject_count"] = len(subjects)
    result["denominator_hash"] = semantic_profile_coverage_denominator_hash(subjects)

    resolutions = list(result.get("resolutions", []))
    subject_hashes = {subject["subject_ref"]: subject["subject_hash"] for subject in subjects}
    producers: set[str] = set()
    blocker_count = 0
    for resolution in resolutions:
        resolution["subject_hash"] = subject_hashes.get(
            resolution["subject_ref"], resolution.get("subject_hash")
        )
        profile = resolution.get("profile")
        blocker = resolution.get("blocker")
        if profile is not None:
            profile["artifact"]["binding_hash"] = artifact_revision_binding_hash(
                profile["artifact"]
            )
            producers.add(profile["artifact"]["producer_ref"])
        if blocker is not None:
            blocker_count += 1
            blocker["evidence_refs"] = sorted(blocker.get("evidence_refs", []))
            blocker["blocker_hash"] = owned_coverage_blocker_hash(blocker)
        resolution["resolution_hash"] = semantic_coverage_resolution_hash(resolution)
    resolutions.sort(key=lambda resolution: resolution["subject_ref"])
    result["resolutions"] = resolutions
    result["resolution_count"] = len(resolutions)
    result["profile_producer_refs"] = sorted(producers)
    result["status"] = "blocked" if blocker_count else "complete"
    result["evidence_refs"] = sorted(result.get("evidence_refs", []))
    result["coverage_hash"] = semantic_profile_coverage_hash(result)
    return SemanticProfileCoverage.model_validate(_tupleize(result), strict=True)


def validate_semantic_profile_coverage(
    value: Mapping[str, Any] | SemanticProfileCoverage,
    *,
    validation_context: SemanticProfileCoverageValidationContext | Mapping[str, Any] | None,
) -> tuple[str, ...]:
    """Validate integrity and exact current coverage against trusted store evidence.

    The context is intentionally mandatory for a successful result.  Application
    code should build it only from the exact canonical store partition.
    """

    raw = _raw(value)
    try:
        coverage = SemanticProfileCoverage.model_validate(_tupleize(raw), strict=True)
    except ValidationError as exc:
        return _validation_messages(exc)

    errors: list[str] = []
    for name, binding_value in coverage.revision_bindings:
        binding_items = (
            binding_value if isinstance(binding_value, tuple) else (binding_value,)
        )
        for index, binding in enumerate(binding_items):
            if binding.binding_hash != artifact_revision_binding_hash(binding):
                suffix = f"[{index}]" if isinstance(binding_value, tuple) else ""
                errors.append(
                    f"revision_bindings.{name}{suffix}.binding_hash is stale"
                )
    for subject in coverage.subjects:
        if subject.subject_hash != semantic_coverage_subject_hash(subject):
            errors.append(f"subject {subject.subject_ref} has a stale subject_hash")
    for resolution in coverage.resolutions:
        if resolution.profile is not None:
            artifact = resolution.profile.artifact
            if artifact.binding_hash != artifact_revision_binding_hash(artifact):
                errors.append(f"profile for {resolution.subject_ref} has a stale artifact binding")
        if resolution.blocker is not None and resolution.blocker.blocker_hash != owned_coverage_blocker_hash(
            resolution.blocker
        ):
            errors.append(f"blocker for {resolution.subject_ref} has a stale blocker_hash")
        if resolution.resolution_hash != semantic_coverage_resolution_hash(resolution):
            errors.append(f"resolution for {resolution.subject_ref} has a stale resolution_hash")
    if coverage.denominator_hash != semantic_profile_coverage_denominator_hash(coverage.subjects):
        errors.append("denominator_hash does not match the exact subject denominator")
    if coverage.coverage_hash != semantic_profile_coverage_hash(coverage):
        errors.append("coverage_hash does not match semantic-profile coverage content")

    if validation_context is None:
        errors.append("trusted store-backed semantic-profile coverage context is required")
        return tuple(sorted(set(errors)))
    try:
        context = (
            validation_context
            if isinstance(validation_context, SemanticProfileCoverageValidationContext)
            else SemanticProfileCoverageValidationContext.model_validate(
                _tupleize(validation_context), strict=True
            )
        )
    except ValidationError as exc:
        errors.extend(f"validation_context.{message}" for message in _validation_messages(exc))
        return tuple(sorted(set(errors)))

    actual_partition = (
        coverage.tenant_ref,
        coverage.run_id,
        coverage.scope_id,
        coverage.migration_unit_id,
        coverage.validation_cycle_id,
    )
    expected_partition = (
        context.tenant_ref,
        context.run_id,
        context.scope_id,
        context.migration_unit_id,
        context.validation_cycle_id,
    )
    if actual_partition != expected_partition:
        errors.append("coverage manifest does not match the trusted tenant/run/scope/unit/cycle")
    if coverage.revision_bindings != context.revision_bindings:
        errors.append("coverage revision bindings are stale or foreign")

    actual_subjects = {subject.subject_ref: subject for subject in coverage.subjects}
    expected_subjects = {subject.subject_ref: subject for subject in context.expected_subjects}
    omitted = sorted(set(expected_subjects) - set(actual_subjects))
    foreign = sorted(set(actual_subjects) - set(expected_subjects))
    if omitted:
        errors.append(f"coverage denominator omits trusted subjects: {', '.join(omitted)}")
    if foreign:
        errors.append(f"coverage denominator contains foreign subjects: {', '.join(foreign)}")
    for subject_ref in sorted(set(actual_subjects).intersection(expected_subjects)):
        if actual_subjects[subject_ref] != expected_subjects[subject_ref]:
            errors.append(f"coverage subject {subject_ref} is stale or substituted")

    current_by_subject: dict[str, list[CurrentSemanticProfileEvidence]] = {}
    for current in context.current_profiles:
        current_by_subject.setdefault(current.subject_ref, []).append(current)
    resolutions = {resolution.subject_ref: resolution for resolution in coverage.resolutions}
    profile_resolution_refs = {
        ref for ref, resolution in resolutions.items() if resolution.disposition == "profile"
    }
    foreign_current = sorted(set(current_by_subject) - profile_resolution_refs)
    if foreign_current:
        errors.append(
            "trusted context contains profiles not used by profile resolutions: "
            + ", ".join(foreign_current)
        )

    for subject_ref in sorted(profile_resolution_refs):
        current = current_by_subject.get(subject_ref, [])
        if len(current) != 1:
            errors.append(
                f"profile resolution {subject_ref} requires exactly one current trusted profile; "
                f"found {len(current)}"
            )
            continue
        evidence = current[0]
        resolution = resolutions[subject_ref]
        assert resolution.profile is not None
        if evidence.artifact != resolution.profile.artifact:
            errors.append(f"profile resolution {subject_ref} binds a stale or foreign artifact")
        profile_payload = evidence.profile.model_dump(mode="json")
        if evidence.artifact.content_sha256 != sha256_json(profile_payload):
            errors.append(f"profile resolution {subject_ref} content hash does not match its payload")
        if evidence.artifact.semantic_hash != evidence.profile.profile_hash:
            errors.append(f"profile resolution {subject_ref} semantic hash does not match its payload")
        if evidence.profile.status != "ready" or validate_semantic_profile(evidence.profile):
            errors.append(f"profile resolution {subject_ref} does not bind a current valid ready profile")
        if evidence.profile.run_id != coverage.run_id or evidence.profile.scope_id != coverage.scope_id:
            errors.append(f"profile resolution {subject_ref} crosses the run or scope")
        if evidence.profile.profile_id != resolution.profile.profile_id:
            errors.append(f"profile resolution {subject_ref} substitutes a different profile_id")
        if evidence.profile.profile_hash != resolution.profile.profile_hash:
            errors.append(f"profile resolution {subject_ref} binds a stale profile_hash")
        if evidence.profile.identity != resolution.profile.identity:
            errors.append(f"profile resolution {subject_ref} substitutes a different profile identity")
        expected = expected_subjects.get(subject_ref)
        if expected is not None and evidence.profile.identity != expected.profile_identity:
            errors.append(f"profile resolution {subject_ref} substitutes a different subject")

    return tuple(sorted(set(errors)))


__all__ = [
    "ArtifactRevisionBinding",
    "CoverageAuthority",
    "CoverageRevisionBindings",
    "CurrentSemanticProfileEvidence",
    "OwnedCoverageBlocker",
    "SemanticCoverageResolution",
    "SemanticCoverageSubject",
    "SemanticProfileBinding",
    "SemanticProfileCoverage",
    "SemanticProfileCoverageValidationContext",
    "artifact_revision_binding_hash",
    "coverage_artifact_revision_binding",
    "derive_semantic_profile_subject_denominator",
    "finalize_semantic_profile_coverage",
    "owned_coverage_blocker_hash",
    "semantic_coverage_resolution_hash",
    "semantic_coverage_subject_hash",
    "semantic_profile_coverage_denominator_hash",
    "semantic_profile_coverage_hash",
    "semantic_profile_coverage_content_sha256",
    "validate_semantic_profile_coverage",
]

"""Deterministic, bounded discovery of pairwise semantic candidates.

Candidate discovery is intentionally weaker than equivalence assessment.  It
uses only exact, indexed signals to nominate profile pairs for specialist
review, never a name/schema/sample similarity heuristic, and never grants
consolidation authority.  Full profile hashes bind references and repository
mappings. Repeated full hashes are ambiguous duplicate inputs and therefore fail
closed; canonical-definition and evidence-neutral dimension hashes discover
otherwise distinct profiles.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Collection, Mapping, Sequence
from copy import deepcopy
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from omni_migrator.control_plane.canonical import sha256_json
from omni_migrator.semantic.equivalence import RepositoryAssetMapping
from omni_migrator.semantic.models import SemanticProfile
from omni_migrator.semantic.profiles import DIMENSIONS, validate_semantic_profile

CandidateSignalCategory = Literal[
    "canonical_definition_hash",
    "semantic_dimension_signature",
    "direct_lineage_overlap",
    "direct_consumer_overlap",
    "repository_asset_mapping",
]

_SIGNAL_ORDER: tuple[CandidateSignalCategory, ...] = (
    "canonical_definition_hash",
    "semantic_dimension_signature",
    "direct_lineage_overlap",
    "direct_consumer_overlap",
    "repository_asset_mapping",
)
_SIGNAL_RANK = {signal: index for index, signal in enumerate(_SIGNAL_ORDER)}
_SYSTEM_RANK = {"domo": 0, "dbt": 1, "snowflake": 2, "omni": 3}
_SHA256_PATTERN = r"^sha256:[a-f0-9]{64}$"
_EVIDENCE_LOCATION_KEYS = {
    "evidence_refs",
    "original_ref",
    "sla_ref",
    "translation_refs",
    "uniqueness_evidence_refs",
}


class CandidateGenerationError(ValueError):
    """Candidate generation failed closed because its inputs were ambiguous."""


class CandidateBudgetExceeded(CandidateGenerationError):
    """The configured maximum number of distinct candidates was exceeded."""


class _FrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class CandidateProfileReference(_FrozenModel):
    profile_id: str = Field(min_length=1)
    system: Literal["domo", "dbt", "snowflake", "omni"]
    asset_kind: str = Field(min_length=1)
    asset_id: str = Field(min_length=1)
    asset_revision_hash: str = Field(pattern=_SHA256_PATTERN)
    profile_hash: str = Field(pattern=_SHA256_PATTERN)
    immutable: Literal[True] = True


class CandidateSignal(_FrozenModel):
    category: CandidateSignalCategory
    match_fingerprints: tuple[str, ...] = Field(min_length=1)
    evidence_refs: tuple[str, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def values_are_canonical(self) -> "CandidateSignal":
        if tuple(sorted(set(self.match_fingerprints))) != self.match_fingerprints:
            raise ValueError("signal match fingerprints must be sorted and unique")
        if any(
            not value.startswith("sha256:") or len(value) != 71
            for value in self.match_fingerprints
        ):
            raise ValueError("signal matches must be opaque sha256 fingerprints")
        if tuple(sorted(set(self.evidence_refs))) != self.evidence_refs:
            raise ValueError("signal evidence references must be sorted and unique")
        return self


class SemanticCandidate(_FrozenModel):
    """A non-authorizing pointer to one exact directional profile pair."""

    contract_version: Literal["domo-to-omni.semantic-candidate.v1"] = (
        "domo-to-omni.semantic-candidate.v1"
    )
    candidate_id: str = Field(min_length=1)
    run_id: str = Field(min_length=1)
    scope_id: str = Field(min_length=1)
    source_profile: CandidateProfileReference
    target_profile: CandidateProfileReference
    signals: tuple[CandidateSignal, ...] = Field(min_length=1)
    evidence_refs: tuple[str, ...] = Field(min_length=1)
    proposal_only: Literal[True] = True
    authorizes_consolidation: Literal[False] = False
    candidate_hash: str = Field(pattern=_SHA256_PATTERN)
    immutable: Literal[True] = True

    @model_validator(mode="after")
    def pair_and_signals_are_canonical(self) -> "SemanticCandidate":
        if self.source_profile.profile_hash == self.target_profile.profile_hash:
            raise ValueError("candidate profiles must be distinct immutable revisions")
        categories = tuple(signal.category for signal in self.signals)
        expected = tuple(sorted(set(categories), key=_SIGNAL_RANK.__getitem__))
        if categories != expected:
            raise ValueError("candidate signals must be unique and canonically ordered")
        signal_evidence = {
            reference for signal in self.signals for reference in signal.evidence_refs
        }
        if tuple(sorted(set(self.evidence_refs))) != self.evidence_refs:
            raise ValueError("candidate evidence references must be sorted and unique")
        if not signal_evidence.issubset(self.evidence_refs):
            raise ValueError("candidate evidence must contain every signal evidence reference")
        return self


def _sha256(value: Any) -> str:
    return f"sha256:{sha256_json(value)}"


def _profile_sort_key(profile: SemanticProfile) -> tuple[Any, ...]:
    return (
        _SYSTEM_RANK[profile.identity.system],
        profile.profile_id,
        profile.identity.kind,
        profile.identity.object_id,
        profile.identity.revision_hash,
        profile.profile_hash,
    )


def _ordered_pair(
    left: SemanticProfile, right: SemanticProfile
) -> tuple[SemanticProfile, SemanticProfile]:
    if _profile_sort_key(left) <= _profile_sort_key(right):
        return left, right
    return right, left


def _profile_reference(profile: SemanticProfile) -> CandidateProfileReference:
    return CandidateProfileReference(
        profile_id=profile.profile_id,
        system=profile.identity.system,
        asset_kind=profile.identity.kind,
        asset_id=profile.identity.object_id,
        asset_revision_hash=profile.identity.revision_hash,
        profile_hash=profile.profile_hash,
        immutable=True,
    )


def _without_evidence_location_noise(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {
            str(key): _without_evidence_location_noise(item)
            for key, item in value.items()
            if key not in _EVIDENCE_LOCATION_KEYS
        }
    if isinstance(value, (list, tuple)):
        return [_without_evidence_location_noise(item) for item in value]
    return value


def semantic_dimension_signature(profile: SemanticProfile) -> str:
    """Hash semantic dimensions while ignoring only evidence-location metadata."""

    raw = profile.model_dump(mode="json")
    material = {
        dimension: _without_evidence_location_noise(raw[dimension]) for dimension in DIMENSIONS
    }
    return _sha256(material)


def repository_asset_mapping_hash(mapping: RepositoryAssetMapping) -> str:
    return _sha256(mapping.model_dump(mode="json"))


def _candidate_material(value: Mapping[str, Any]) -> dict[str, Any]:
    material = deepcopy(dict(value))
    material.pop("candidate_hash", None)
    return material


def semantic_candidate_hash(value: Mapping[str, Any] | SemanticCandidate) -> str:
    raw = value.model_dump(mode="json") if isinstance(value, SemanticCandidate) else value
    return _sha256(_candidate_material(raw))


def validate_semantic_candidate(value: Mapping[str, Any] | SemanticCandidate) -> list[str]:
    raw = value.model_dump(mode="json") if isinstance(value, SemanticCandidate) else dict(value)
    errors: list[str] = []
    try:
        candidate = SemanticCandidate.model_validate(raw)
    except ValueError as exc:
        return [f"semantic candidate is invalid: {exc}"]
    if candidate.candidate_hash != semantic_candidate_hash(candidate):
        errors.append("candidate_hash does not match candidate content")
    return errors


def _signal_evidence(
    category: CandidateSignalCategory,
    source: SemanticProfile,
    target: SemanticProfile,
) -> set[str]:
    if category == "canonical_definition_hash":
        return {source.definition.original_ref, target.definition.original_ref}
    if category == "direct_lineage_overlap":
        return set(source.lineage.evidence_refs) | set(target.lineage.evidence_refs)
    return set(source.evidence_refs) | set(target.evidence_refs)


def _profile_indexes(
    profiles: Sequence[SemanticProfile],
) -> dict[tuple[str, str, CandidateSignalCategory, str], list[SemanticProfile]]:
    indexes: dict[
        tuple[str, str, CandidateSignalCategory, str], list[SemanticProfile]
    ] = defaultdict(list)
    for profile in profiles:
        partition = (profile.run_id, profile.scope_id)
        if (
            profile.definition.canonical_state == "supported"
            and profile.definition.canonical_hash is not None
        ):
            indexes[
                (*partition, "canonical_definition_hash", profile.definition.canonical_hash)
            ].append(profile)
        indexes[
            (*partition, "semantic_dimension_signature", semantic_dimension_signature(profile))
        ].append(profile)
        if profile.lineage.state == "known":
            direct_lineage = set(profile.lineage.authoritative_source_ids) | set(
                profile.lineage.upstream_asset_ids
            )
            for asset_id in sorted(direct_lineage):
                indexes[(*partition, "direct_lineage_overlap", asset_id)].append(profile)
        for consumer_id in sorted(set(profile.consumers)):
            indexes[(*partition, "direct_consumer_overlap", consumer_id)].append(profile)
    return indexes


def _validate_profiles(profiles: Sequence[SemanticProfile]) -> None:
    profile_ids: dict[str, SemanticProfile] = {}
    asset_identities: dict[tuple[str, str, str], SemanticProfile] = {}
    profile_hashes: dict[str, SemanticProfile] = {}
    for profile in profiles:
        errors = validate_semantic_profile(profile)
        if errors:
            raise CandidateGenerationError(
                f"semantic profile {profile.profile_id!r} is stale or invalid: {'; '.join(errors)}"
            )
        identity = (profile.identity.system, profile.identity.kind, profile.identity.object_id)
        if profile.profile_id in profile_ids:
            raise CandidateGenerationError(
                f"duplicate or conflicting profile identity: {profile.profile_id}"
            )
        if identity in asset_identities:
            raise CandidateGenerationError(
                "duplicate or conflicting asset identity: " + "/".join(identity)
            )
        if profile.profile_hash in profile_hashes:
            raise CandidateGenerationError(
                f"duplicate or conflicting profile hash: {profile.profile_hash}"
            )
        profile_ids[profile.profile_id] = profile
        asset_identities[identity] = profile
        profile_hashes[profile.profile_hash] = profile


def _mapping_model(value: RepositoryAssetMapping | Mapping[str, Any]) -> RepositoryAssetMapping:
    if isinstance(value, RepositoryAssetMapping):
        return value
    try:
        return RepositoryAssetMapping.model_validate(value)
    except ValueError as exc:
        raise CandidateGenerationError(f"repository asset mapping is invalid: {exc}") from exc


def generate_semantic_candidates(
    profiles: Collection[SemanticProfile],
    *,
    asset_mappings: Collection[RepositoryAssetMapping | Mapping[str, Any]] = (),
    max_candidates: int = 10_000,
) -> tuple[SemanticCandidate, ...]:
    """Generate exact-signal candidate pairs within immutable run/scope partitions.

    The inverted indexes restrict comparison to profiles sharing at least one
    exact signal.  Generation stops as soon as the distinct-pair budget would be
    exceeded; it never falls back to a global Cartesian comparison.
    """

    if max_candidates < 1:
        raise ValueError("max_candidates must be at least one")
    ordered_profiles = sorted(
        profiles,
        key=lambda item: (item.run_id, item.scope_id, *_profile_sort_key(item)),
    )
    _validate_profiles(ordered_profiles)
    by_hash = {profile.profile_hash: profile for profile in ordered_profiles}

    accumulators: dict[
        tuple[str, str],
        dict[CandidateSignalCategory, dict[str, set[str]]],
    ] = {}

    def add_signal(
        left: SemanticProfile,
        right: SemanticProfile,
        *,
        category: CandidateSignalCategory,
        match_fingerprint: str,
        evidence_refs: Collection[str],
    ) -> None:
        if left.run_id != right.run_id or left.scope_id != right.scope_id:
            raise CandidateGenerationError("candidate signals cannot cross run/scope partitions")
        source, target = _ordered_pair(left, right)
        key = (source.profile_hash, target.profile_hash)
        if key not in accumulators:
            if len(accumulators) >= max_candidates:
                raise CandidateBudgetExceeded(
                    f"candidate budget exceeded: more than {max_candidates} distinct pairs"
                )
            accumulators[key] = {}
        signal = accumulators[key].setdefault(category, {})
        signal.setdefault(match_fingerprint, set()).update(evidence_refs)

    indexes = _profile_indexes(ordered_profiles)
    for (run_id, scope_id, category, raw_key), bucket in sorted(indexes.items()):
        del run_id, scope_id
        unique_bucket = sorted(
            {profile.profile_hash: profile for profile in bucket}.values(),
            key=_profile_sort_key,
        )
        if len(unique_bucket) < 2:
            continue
        match_fingerprint = (
            raw_key
            if category
            in {
                "canonical_definition_hash",
                "semantic_dimension_signature",
            }
            else _sha256({"signal": category, "value": raw_key})
        )
        for index, left in enumerate(unique_bucket[:-1]):
            for right in unique_bucket[index + 1 :]:
                source, target = _ordered_pair(left, right)
                add_signal(
                    source,
                    target,
                    category=category,
                    match_fingerprint=match_fingerprint,
                    evidence_refs=_signal_evidence(category, source, target),
                )

    normalized_mappings = sorted(
        (_mapping_model(item) for item in asset_mappings),
        key=repository_asset_mapping_hash,
    )
    for mapping in normalized_mappings:
        source = by_hash.get(mapping.source_profile_fingerprint)
        target = by_hash.get(mapping.target_profile_fingerprint)
        if source is None or target is None:
            raise CandidateGenerationError(
                "repository asset mapping references a missing or stale profile revision"
            )
        if source is target:
            raise CandidateGenerationError("repository asset mapping cannot bind a profile to itself")
        if source.run_id != target.run_id or source.scope_id != target.scope_id:
            raise CandidateGenerationError("repository asset mapping crosses run/scope partitions")
        add_signal(
            source,
            target,
            category="repository_asset_mapping",
            match_fingerprint=repository_asset_mapping_hash(mapping),
            evidence_refs=mapping.evidence_refs,
        )

    candidates: list[SemanticCandidate] = []
    for source_hash, target_hash in sorted(
        accumulators,
        key=lambda pair: (
            by_hash[pair[0]].run_id,
            by_hash[pair[0]].scope_id,
            _profile_sort_key(by_hash[pair[0]]),
            _profile_sort_key(by_hash[pair[1]]),
        ),
    ):
        source = by_hash[source_hash]
        target = by_hash[target_hash]
        signal_models: list[CandidateSignal] = []
        for category in sorted(
            accumulators[(source_hash, target_hash)], key=_SIGNAL_RANK.__getitem__
        ):
            matches = accumulators[(source_hash, target_hash)][category]
            signal_models.append(
                CandidateSignal(
                    category=category,
                    match_fingerprints=tuple(sorted(matches)),
                    evidence_refs=tuple(
                        sorted(
                            {
                                reference
                                for references in matches.values()
                                for reference in references
                            }
                        )
                    ),
                )
            )
        source_ref = _profile_reference(source)
        target_ref = _profile_reference(target)
        evidence_refs = tuple(
            sorted({reference for signal in signal_models for reference in signal.evidence_refs})
        )
        seed = {
            "run_id": source.run_id,
            "scope_id": source.scope_id,
            "source_profile": source_ref.model_dump(mode="json"),
            "target_profile": target_ref.model_dump(mode="json"),
            "signals": [signal.model_dump(mode="json") for signal in signal_models],
        }
        draft: dict[str, Any] = {
            "contract_version": "domo-to-omni.semantic-candidate.v1",
            "candidate_id": f"semantic-candidate-{sha256_json(seed)[:24]}",
            "run_id": source.run_id,
            "scope_id": source.scope_id,
            "source_profile": source_ref.model_dump(mode="json"),
            "target_profile": target_ref.model_dump(mode="json"),
            "signals": [signal.model_dump(mode="json") for signal in signal_models],
            "evidence_refs": evidence_refs,
            "proposal_only": True,
            "authorizes_consolidation": False,
            "candidate_hash": "sha256:" + "0" * 64,
            "immutable": True,
        }
        draft["candidate_hash"] = semantic_candidate_hash(draft)
        candidate = SemanticCandidate.model_validate(draft)
        errors = validate_semantic_candidate(candidate)
        if errors:
            raise CandidateGenerationError("; ".join(errors))
        candidates.append(candidate)
    return tuple(candidates)


__all__ = [
    "CandidateBudgetExceeded",
    "CandidateGenerationError",
    "CandidateProfileReference",
    "CandidateSignal",
    "CandidateSignalCategory",
    "SemanticCandidate",
    "generate_semantic_candidates",
    "repository_asset_mapping_hash",
    "semantic_candidate_hash",
    "semantic_dimension_signature",
    "validate_semantic_candidate",
]

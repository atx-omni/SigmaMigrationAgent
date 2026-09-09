"""Trusted append-only QA evidence resolution.

The resolver deliberately derives the acceptance denominator from the current
validated dashboard evidence snapshot plus its canonical full plan payload.  A
QA suite and its own snapshot cannot therefore agree with each other while
silently dropping a semantic asset, behavior instance, propagation edge,
consumer, secured persona, or negative consolidation candidate.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, replace
from typing import Any, Literal, Mapping
from urllib.parse import quote

from omni_migrator.control_plane.canonical import sha256_json
from omni_migrator.control_plane.records import ArtifactEnvelope
from omni_migrator.control_plane.store import (
    AppendOnlyControlPlaneStore,
    _current_artifact_payload,
    _current_registered_production_validation_report,
    _current_registered_qa_target_operation_outcome,
    _current_registered_qa_v2_payload,
    _qa_binding_matches_current_artifact,
    _qa_v2_payload_matches_current_artifact,
    _registered_semantic_profile_coverages,
    _registered_semantic_profiles,
)
from omni_migrator.dashboards.rebuild_plan import (
    DashboardEvidenceSnapshot,
    DashboardRebuildPlan,
    DashboardPlanValidationRegistration,
    dashboard_plan_content_sha256,
    dashboard_evidence_snapshot_hash,
    dashboard_rebuild_plan_hash,
    dashboard_plan_validation_registration_hash,
    finalize_dashboard_evidence_snapshot,
    finalize_dashboard_rebuild_plan,
)
from omni_migrator.qa.acceptance import (
    ComparisonContextPair,
    ComparisonContextProvenanceBinding,
    CoverageDimension,
    QACoverageDenominator,
    QAEvidenceSnapshot,
    QAFixtureV2,
    QAResultV2,
    QASuiteValidationRegistration,
    finalize_qa_evidence_snapshot,
    finalize_comparison_context_provenance_binding,
    comparison_context_pair_hash,
    qa_coverage_denominator_hash,
    qa_evidence_snapshot_hash,
    qa_suite_validation_registration_hash,
)
from omni_migrator.semantic.coverage import (
    SemanticProfileCoverage,
    semantic_profile_coverage_hash,
)
from omni_migrator.semantic.models import SemanticProfile


_SEMANTIC_COVERAGE_LINEAGE_KEY = "semantic_coverage_lineage"


@dataclass(frozen=True)
class QASubjectRequirement:
    """One exact QA case required by accepted migration evidence."""

    dimension: CoverageDimension
    subject_ref: str
    subject_hash: str
    comparison_context_id: str | None = None
    comparison_context_hash: str | None = None
    source_consumer_ref: str | None = None
    persona_ref: str | None = None
    expected_access: Literal["allow", "deny"] | None = None
    negative_candidate_ref: str | None = None
    expected_consolidation_outcome: Literal["different", "unknown"] | None = None

    def __post_init__(self) -> None:
        if (self.comparison_context_id is None) != (
            self.comparison_context_hash is None
        ):
            raise ValueError(
                "QA subject comparison-context ID and hash must be supplied together"
            )


def semantic_coverage_subject_for_qa_profile(
    profile: SemanticProfile,
    coverage: SemanticProfileCoverage,
) -> str | None:
    """Resolve one accepted profile to exactly one covered base subject.

    Coverage v1 closes the base semantic denominator.  A dashboard may require
    multiple context-specific profiles descended from one covered Card or Beast
    Mode subject.  Those descendants must carry an explicit, hash-paired lineage
    assertion and retain the base object in their typed lineage; a matching name,
    producer, or profile shape is never sufficient.
    """

    subjects = {item.subject_ref: item for item in coverage.subjects}
    resolutions = {
        item.subject_ref: item
        for item in coverage.resolutions
        if item.disposition == "profile" and item.profile is not None
    }
    exact = [
        subject_ref
        for subject_ref, resolution in resolutions.items()
        if resolution.profile is not None
        and resolution.profile.profile_id == profile.profile_id
        and resolution.profile.profile_hash == profile.profile_hash
        and resolution.profile.identity == profile.identity
    ]
    if len(exact) == 1:
        return exact[0]
    if exact:
        return None

    raw_lineage = profile.provenance.get(_SEMANTIC_COVERAGE_LINEAGE_KEY)
    if not isinstance(raw_lineage, Mapping) or set(raw_lineage) != {
        "subject_ref",
        "subject_hash",
        "base_profile_id",
        "base_profile_hash",
    }:
        return None
    subject_ref = raw_lineage.get("subject_ref")
    subject = subjects.get(subject_ref)
    resolution = resolutions.get(subject_ref)
    if subject is None or resolution is None or resolution.profile is None:
        return None
    base = resolution.profile
    lineage_ids = {
        *profile.lineage.authoritative_source_ids,
        *profile.lineage.upstream_asset_ids,
    }
    if (
        raw_lineage.get("subject_hash") != subject.subject_hash
        or raw_lineage.get("base_profile_id") != base.profile_id
        or raw_lineage.get("base_profile_hash") != base.profile_hash
        or base.identity.object_id not in lineage_ids
        or profile.run_id != coverage.run_id
        or profile.scope_id != coverage.scope_id
    ):
        return None
    return str(subject_ref)


def _profiles_match_semantic_coverage(
    profiles: tuple[SemanticProfile, ...] | list[SemanticProfile],
    coverage: SemanticProfileCoverage,
) -> bool:
    """Return whether every accepted profile has one exact covered lineage."""

    if (
        coverage.status != "complete"
        or coverage.coverage_hash != semantic_profile_coverage_hash(coverage)
        or any(item.disposition != "profile" for item in coverage.resolutions)
    ):
        return False
    profile_ids = [item.profile_id for item in profiles]
    profile_hashes = [item.profile_hash for item in profiles]
    if len(profile_ids) != len(set(profile_ids)) or len(profile_hashes) != len(
        set(profile_hashes)
    ):
        return False
    return all(
        semantic_coverage_subject_for_qa_profile(profile, coverage) is not None
        for profile in profiles
    )


def semantic_profile_context_provenance_binding(
    profile: SemanticProfile,
) -> ComparisonContextProvenanceBinding | None:
    """Derive the immutable QA-context assertion for one Domo context profile.

    Base profiles and non-Domo profiles are not context-specific.  A Domo
    descendant is accepted only when it carries the complete evidence-derived
    semantic-profile requirement provenance emitted by the canonical builder.
    """

    provenance = profile.provenance
    context_id = provenance.get("context_id")
    requirement_provenance_present = any(
        key in provenance
        for key in (
            "semantic_profile_requirement_id",
            "semantic_profile_requirement_hash",
            "context_ref",
            "context_hash",
        )
    )
    if context_id is None:
        if requirement_provenance_present:
            raise ValueError(
                f"profile {profile.profile_id} has incomplete semantic-context provenance"
            )
        return None
    if context_id == "base":
        return None
    required = {
        "semantic_profile_requirement_id": provenance.get(
            "semantic_profile_requirement_id"
        ),
        "semantic_profile_requirement_hash": provenance.get(
            "semantic_profile_requirement_hash"
        ),
        "context_id": context_id,
        "context_ref": provenance.get("context_ref"),
        "context_hash": provenance.get("context_hash"),
    }
    if provenance.get("source_system") != "domo" or any(
        not isinstance(value, str) or not value for value in required.values()
    ):
        raise ValueError(
            f"context-sensitive profile {profile.profile_id} lacks trusted Domo "
            "semantic-profile requirement provenance"
        )
    requirement_hash = str(required["semantic_profile_requirement_hash"])
    if profile.identity.revision_hash != requirement_hash:
        raise ValueError(
            f"context-sensitive profile {profile.profile_id} is not bound to its "
            "semantic-profile requirement revision"
        )
    provenance_hash = "sha256:" + sha256_json(
        {
            "profile_id": profile.profile_id,
            "profile_hash": profile.profile_hash,
            "identity": profile.identity.model_dump(mode="json"),
            **required,
            "consumer_object_id": provenance.get("consumer_object_id"),
        }
    )
    return finalize_comparison_context_provenance_binding(
        {
            "provenance_kind": "semantic_profile_context",
            "provenance_id": required["semantic_profile_requirement_id"],
            "provenance_ref": required["context_ref"],
            "provenance_hash": provenance_hash,
            "binding_hash": "sha256:" + "0" * 64,
        }
    )


def dashboard_filter_context_provenance_binding(
    *,
    plan: DashboardRebuildPlan,
    query_mapping: Any,
    filter_context: Any,
) -> ComparisonContextProvenanceBinding:
    """Seal one accepted dashboard filter-context behavior for QA pairing."""

    mapping_matches = [
        item
        for item in plan.query_mappings
        if item.query_id == query_mapping.query_id
        and item.mapping_hash == query_mapping.mapping_hash
    ]
    if len(mapping_matches) != 1 or filter_context not in query_mapping.filter_contexts:
        raise ValueError(
            "dashboard filter-context provenance is not an exact accepted plan member"
        )
    consumer_id = (
        query_mapping.consumer_contract.source_consumer_id
        if query_mapping.consumer_contract is not None
        else None
    )
    provenance_hash = "sha256:" + sha256_json(
        {
            "plan_id": plan.plan_id,
            "plan_hash": plan.plan_hash,
            "query_id": query_mapping.query_id,
            "query_mapping_hash": query_mapping.mapping_hash,
            "source_consumer_id": consumer_id,
            "filter_context": filter_context.model_dump(mode="json"),
        }
    )
    return finalize_comparison_context_provenance_binding(
        {
            "provenance_kind": "dashboard_filter_context",
            "provenance_id": filter_context.source_behavior_id,
            "provenance_ref": filter_context.context_ref,
            "provenance_hash": provenance_hash,
            "binding_hash": "sha256:" + "0" * 64,
        }
    )


def _comparison_context_for_provenance(
    binding: ComparisonContextProvenanceBinding,
    comparison_contexts: tuple[ComparisonContextPair, ...],
) -> ComparisonContextPair:
    matches = [
        context
        for context in comparison_contexts
        if binding in context.provenance_bindings
    ]
    if len(matches) != 1:
        raise ValueError(
            "trusted QA comparison contexts must bind each context-sensitive "
            f"provenance identity exactly once: {binding.provenance_kind}/"
            f"{binding.provenance_id}"
        )
    return matches[0]


def qa_subject_reference(subject_kind: str, *identity_parts: str) -> str:
    """Build the canonical non-secret identity for one QA subject."""

    if not subject_kind or not identity_parts or any(not str(item) for item in identity_parts):
        raise ValueError("QA subject references require a kind and exact identity parts")
    kind = quote(subject_kind.lower(), safe="._-")
    parts = "/".join(quote(str(item), safe="._-") for item in identity_parts)
    return f"qa-subject-ref://{kind}/{parts}"


def _qa_subject_hash(
    *,
    dimension: CoverageDimension,
    subject_ref: str,
    evidence_hashes: tuple[str, ...],
    material: Any,
) -> str:
    return "sha256:" + sha256_json(
        {
            "dimension": dimension,
            "subject_ref": subject_ref,
            "evidence_hashes": sorted(evidence_hashes),
            "material": material,
        }
    )


def _requirement(
    dimension: CoverageDimension,
    subject_kind: str,
    identity_parts: tuple[str, ...],
    *,
    evidence_hashes: tuple[str, ...],
    material: Any,
    source_consumer_ref: str | None = None,
    persona_ref: str | None = None,
    expected_access: Literal["allow", "deny"] | None = None,
    negative_candidate_ref: str | None = None,
    expected_consolidation_outcome: Literal["different", "unknown"] | None = None,
    comparison_context: ComparisonContextPair | None = None,
    context_provenance: ComparisonContextProvenanceBinding | None = None,
) -> QASubjectRequirement:
    if (comparison_context is None) != (context_provenance is None):
        raise ValueError(
            "context-sensitive QA requirements need an exact context and provenance pair"
        )
    context_binding_material = None
    context_evidence_hashes: tuple[str, ...] = ()
    if comparison_context is not None and context_provenance is not None:
        if context_provenance not in comparison_context.provenance_bindings:
            raise ValueError(
                "QA comparison context does not carry the required provenance binding"
            )
        context_binding_material = {
            "comparison_context_id": comparison_context.context_id,
            "comparison_context_hash": comparison_context.pair_hash,
            "context_provenance": context_provenance.model_dump(mode="json"),
        }
        context_evidence_hashes = (
            comparison_context.pair_hash,
            context_provenance.provenance_hash,
            context_provenance.binding_hash,
        )
    subject_ref = qa_subject_reference(subject_kind, *identity_parts)
    return QASubjectRequirement(
        dimension=dimension,
        subject_ref=subject_ref,
        subject_hash=_qa_subject_hash(
            dimension=dimension,
            subject_ref=subject_ref,
            evidence_hashes=(*evidence_hashes, *context_evidence_hashes),
            material=(
                {
                    "subject": material,
                    "comparison_context_binding": context_binding_material,
                }
                if context_binding_material is not None
                else material
            ),
        ),
        comparison_context_id=(
            comparison_context.context_id
            if comparison_context is not None
            else None
        ),
        comparison_context_hash=(
            comparison_context.pair_hash
            if comparison_context is not None
            else None
        ),
        source_consumer_ref=source_consumer_ref,
        persona_ref=persona_ref,
        expected_access=expected_access,
        negative_candidate_ref=negative_candidate_ref,
        expected_consolidation_outcome=expected_consolidation_outcome,
    )


def _requirement_sort_key(item: QASubjectRequirement) -> tuple[str, ...]:
    return (
        item.dimension,
        item.subject_ref,
        item.subject_hash,
        item.comparison_context_id or "",
        item.comparison_context_hash or "",
        item.source_consumer_ref or "",
        item.persona_ref or "",
        item.expected_access or "",
        item.negative_candidate_ref or "",
        item.expected_consolidation_outcome or "",
    )


def derive_exact_qa_subject_requirements(
    *,
    plan: DashboardRebuildPlan,
    dashboard_snapshot: DashboardEvidenceSnapshot,
    semantic_profile_coverage: SemanticProfileCoverage | None = None,
    comparison_contexts: (
        tuple[ComparisonContextPair, ...] | list[ComparisonContextPair] | None
    ) = None,
) -> tuple[QASubjectRequirement, ...]:
    """Derive the complete subject-level QA denominator from trusted evidence.

    Subject hashes are deterministic projections of canonical plan, Topic, profile,
    decision, and (when supplied by the trusted resolver) semantic-coverage evidence.
    The optional manifest keeps standalone structural derivation available, but the
    authoritative store path always supplies it and rejects an unlinked accepted
    profile before deriving any QA subjects.  This function does not accept a
    caller-supplied count or generic dimension marker, so repeated behavior instances
    cannot collapse into one case.
    """

    if plan.plan_hash != dashboard_rebuild_plan_hash(plan):
        raise ValueError("dashboard plan hash is stale")
    trusted_comparison_contexts: tuple[ComparisonContextPair, ...] | None = None
    if comparison_contexts is not None:
        trusted_comparison_contexts = tuple(comparison_contexts)
        if not trusted_comparison_contexts:
            raise ValueError("trusted QA comparison contexts cannot be empty")
        context_ids = [item.context_id for item in trusted_comparison_contexts]
        if len(context_ids) != len(set(context_ids)) or any(
            item.pair_hash != comparison_context_pair_hash(item)
            for item in trusted_comparison_contexts
        ):
            raise ValueError("trusted QA comparison contexts are duplicate or stale")
        provenance_identities = [
            (binding.provenance_kind, binding.provenance_id)
            for context in trusted_comparison_contexts
            for binding in context.provenance_bindings
        ]
        if len(provenance_identities) != len(set(provenance_identities)):
            raise ValueError(
                "trusted QA comparison contexts map one provenance identity more than once"
            )
    topics_by_id = {
        item.blueprint_id: item for item in dashboard_snapshot.topic_blueprints
    }
    selected_topic_ids = {
        item.topic_blueprint_id
        for item in plan.query_mappings
        if item.outcome == "mapped" and item.topic_blueprint_id is not None
    }
    if not selected_topic_ids:
        raise ValueError("QA denominator requires at least one mapped Topic")
    if not selected_topic_ids.issubset(topics_by_id):
        raise ValueError("dashboard plan references a Topic absent from its snapshot")
    selected_topics = [topics_by_id[item] for item in sorted(selected_topic_ids)]
    selected_consumer_ids = {
        item.consumer_contract.source_consumer_id
        for item in plan.query_mappings
        if item.outcome == "mapped" and item.consumer_contract is not None
    }
    if not selected_consumer_ids:
        raise ValueError("mapped dashboard queries require exact source consumers")

    profiles_by_id = {item.profile_id: item for item in dashboard_snapshot.profiles}
    required_profile_ids = {item.profile_id for item in plan.profile_bindings}
    if not required_profile_ids or not required_profile_ids.issubset(profiles_by_id):
        raise ValueError("dashboard plan profile bindings are not closed by its snapshot")
    required_profiles = [profiles_by_id[item] for item in sorted(required_profile_ids)]
    if semantic_profile_coverage is not None and not _profiles_match_semantic_coverage(
        required_profiles,
        semantic_profile_coverage,
    ):
        raise ValueError(
            "dashboard semantic profiles do not match the accepted semantic coverage"
        )
    profile_context_bindings: dict[
        str,
        tuple[ComparisonContextPair, ComparisonContextProvenanceBinding],
    ] = {}
    for profile in required_profiles:
        provenance_binding = semantic_profile_context_provenance_binding(profile)
        if provenance_binding is None:
            continue
        if trusted_comparison_contexts is None:
            continue
        profile_context_bindings[profile.profile_id] = (
            _comparison_context_for_provenance(
                provenance_binding,
                trusted_comparison_contexts,
            ),
            provenance_binding,
        )

    requirements: list[QASubjectRequirement] = []

    # Every applicable source/target semantic asset is tested independently.
    profile_dimensions = {
        "key": "grain",
        "grain": "grain",
        "schema": "definition",
        "freshness": "operations",
        "time_semantics": "time",
    }
    for profile in required_profiles:
        profile_context = profile_context_bindings.get(profile.profile_id)
        comparison_context = profile_context[0] if profile_context is not None else None
        context_provenance = profile_context[1] if profile_context is not None else None
        for dimension, dimension_name in profile_dimensions.items():
            dimension_hash = profile.dimension_hashes.get(dimension_name)
            if dimension_hash is None:
                raise ValueError(
                    f"profile {profile.profile_id} lacks {dimension_name} dimension evidence"
                )
            requirements.append(
                _requirement(
                    dimension,  # type: ignore[arg-type]
                    "semantic-profile",
                    (profile.profile_id, dimension),
                    evidence_hashes=(profile.profile_hash, dimension_hash),
                    material={
                        "asset": profile.identity.model_dump(mode="json"),
                        "dimension_name": dimension_name,
                    },
                    comparison_context=comparison_context,
                    context_provenance=context_provenance,
                )
            )

        if profile.filters.state != "not_applicable":
            filter_hash = profile.dimension_hashes.get("filters")
            if filter_hash is None:
                raise ValueError(
                    f"profile {profile.profile_id} lacks filter dimension evidence"
                )
            requirements.append(
                _requirement(
                    "filter_context",
                    "semantic-profile-filter-context",
                    (profile.profile_id,),
                    evidence_hashes=(profile.profile_hash, filter_hash),
                    material=profile.filters.model_dump(mode="json"),
                    comparison_context=comparison_context,
                    context_provenance=context_provenance,
                )
            )

        is_calculation = (
            profile.identity.kind
            in {"calculation", "transformation", "dbt_resource", "omni_candidate"}
            or profile.definition.language == "beast_mode"
        )
        if is_calculation:
            aggregation_hash = profile.dimension_hashes.get("aggregation")
            definition_hash = profile.dimension_hashes.get("definition")
            if aggregation_hash is None or definition_hash is None:
                raise ValueError(
                    f"calculation profile {profile.profile_id} lacks exact calculation evidence"
                )
            if profile.aggregation.stage in {"row", "pre_aggregate"}:
                calculation_dimension: CoverageDimension = "row_calculation"
            elif profile.aggregation.stage in {
                "aggregate",
                "post_aggregate",
                "window",
                "fixed_lod",
            }:
                calculation_dimension = "aggregate_calculation"
            else:
                raise ValueError(
                    f"calculation profile {profile.profile_id} has no testable aggregation stage"
                )
            requirements.append(
                _requirement(
                    calculation_dimension,
                    "semantic-calculation",
                    (profile.profile_id,),
                    evidence_hashes=(
                        profile.profile_hash,
                        definition_hash,
                        aggregation_hash,
                    ),
                    material={
                        "definition": profile.definition.model_dump(mode="json"),
                        "aggregation": profile.aggregation.model_dump(mode="json"),
                    },
                    comparison_context=comparison_context,
                    context_provenance=context_provenance,
                )
            )

    def append_security_subject(
        *,
        evidence_hashes: tuple[str, ...],
        subject_kind: str,
        identity_parts: tuple[str, ...],
        material: Mapping[str, Any],
        persona_ref: str,
        access: str,
        source_consumer_ref: str | None = None,
    ) -> None:
        dimensions: tuple[tuple[CoverageDimension, Literal["allow", "deny"]], ...]
        if access == "allowed":
            dimensions = (("security_allow", "allow"),)
        else:
            dimensions = (
                ("security_deny", "deny"),
                ("derived_field_leakage", "deny"),
            )
        for dimension, expected_access in dimensions:
            requirements.append(
                _requirement(
                    dimension,
                    subject_kind,
                    identity_parts,
                    evidence_hashes=evidence_hashes,
                    material=material,
                    source_consumer_ref=source_consumer_ref,
                    persona_ref=persona_ref,
                    expected_access=expected_access,
                )
            )

    # Fanout is closed once per Topic and once per join, while target measures are
    # closed individually rather than by one aggregate-calculation marker.
    for topic in selected_topics:
        views_by_id = {item.view_id: item for item in topic.views}
        fields_by_view = {
            view_id: tuple(
                sorted(
                    (item for item in topic.fields if item.view_id == view_id),
                    key=lambda item: item.field_id,
                )
            )
            for view_id in views_by_id
        }
        time_fields_by_view = {
            view_id: tuple(
                item
                for item in fields
                if item.field_kind == "time_dimension"
            )
            for view_id, fields in fields_by_view.items()
        }
        time_profiles_by_view = {
            view_id: profiles_by_id[view.profile_id]
            for view_id, view in views_by_id.items()
            if view.profile_id in profiles_by_id
            and profiles_by_id[view.profile_id].time.state != "not_applicable"
        }
        component_view_ids = {
            **{item.view_id: item.view_id for item in topic.views},
            **{item.field_id: item.view_id for item in topic.fields},
            **{item.measure_id: item.view_id for item in topic.measures},
        }
        topic_time_fields = tuple(
            item
            for fields in time_fields_by_view.values()
            for item in fields
        )
        topic_semantic_evidence = (topic.blueprint_hash,)
        requirements.extend(
            (
                _requirement(
                    "key",
                    "topic-key",
                    (topic.blueprint_id,),
                    evidence_hashes=topic_semantic_evidence,
                    material={
                        "primary_key_fields": topic.base_fact.primary_key_fields,
                        "uniqueness_evidence_refs": (
                            topic.base_fact.uniqueness_evidence_refs
                        ),
                    },
                ),
                _requirement(
                    "grain",
                    "topic-grain",
                    (topic.blueprint_id,),
                    evidence_hashes=topic_semantic_evidence,
                    material=topic.base_fact.model_dump(mode="json"),
                ),
                _requirement(
                    "schema",
                    "topic-schema",
                    (topic.blueprint_id,),
                    evidence_hashes=topic_semantic_evidence,
                    material={
                        "views": [item.model_dump(mode="json") for item in topic.views],
                        "fields": [item.model_dump(mode="json") for item in topic.fields],
                        "measures": [
                            item.model_dump(mode="json") for item in topic.measures
                        ],
                    },
                ),
                _requirement(
                    "freshness",
                    "topic-freshness",
                    (topic.blueprint_id,),
                    evidence_hashes=topic_semantic_evidence,
                    material=topic.freshness.model_dump(mode="json"),
                ),
            )
        )
        if topic_time_fields or time_profiles_by_view:
            requirements.append(
                _requirement(
                    "time_semantics",
                    "topic-time",
                    (topic.blueprint_id,),
                    evidence_hashes=topic_semantic_evidence,
                    material={
                        "time_fields": [
                            item.model_dump(mode="json") for item in topic_time_fields
                        ],
                        "view_profiles": [
                            {
                                "view_id": view_id,
                                "profile_id": profile.profile_id,
                                "profile_hash": profile.profile_hash,
                                "time": profile.time.model_dump(mode="json"),
                            }
                            for view_id, profile in sorted(
                                time_profiles_by_view.items()
                            )
                        ],
                        "freshness": topic.freshness.model_dump(mode="json"),
                    },
                )
            )

        for view in topic.views:
            view_fields = fields_by_view[view.view_id]
            view_time_fields = time_fields_by_view[view.view_id]
            requirements.extend(
                (
                    _requirement(
                        "key",
                        "topic-view-key",
                        (topic.blueprint_id, view.view_id),
                        evidence_hashes=topic_semantic_evidence,
                        material={
                            "primary_key_fields": view.primary_key_fields,
                            "key_evidence_refs": view.key_evidence_refs,
                            "grain_key_exception": (
                                view.grain_key_exception.model_dump(mode="json")
                                if view.grain_key_exception is not None
                                else None
                            ),
                        },
                    ),
                    _requirement(
                        "grain",
                        "topic-view-grain",
                        (topic.blueprint_id, view.view_id),
                        evidence_hashes=topic_semantic_evidence,
                        material={"grain": view.grain, "profile_id": view.profile_id},
                    ),
                    _requirement(
                        "schema",
                        "topic-view-schema",
                        (topic.blueprint_id, view.view_id),
                        evidence_hashes=topic_semantic_evidence,
                        material={
                            "view": view.model_dump(mode="json"),
                            "fields": [
                                item.model_dump(mode="json") for item in view_fields
                            ],
                        },
                    ),
                    _requirement(
                        "freshness",
                        "topic-view-freshness",
                        (topic.blueprint_id, view.view_id),
                        evidence_hashes=topic_semantic_evidence,
                        material=topic.freshness.model_dump(mode="json"),
                    ),
                )
            )
            view_time_profile = time_profiles_by_view.get(view.view_id)
            if view_time_fields or view_time_profile is not None:
                requirements.append(
                    _requirement(
                        "time_semantics",
                        "topic-view-time",
                        (topic.blueprint_id, view.view_id),
                        evidence_hashes=topic_semantic_evidence,
                        material={
                            "time_fields": [
                                item.model_dump(mode="json")
                                for item in view_time_fields
                            ],
                            "profile_time": (
                                {
                                    "profile_id": view_time_profile.profile_id,
                                    "profile_hash": view_time_profile.profile_hash,
                                    "time": view_time_profile.time.model_dump(mode="json"),
                                }
                                if view_time_profile is not None
                                else None
                            ),
                            "freshness": topic.freshness.model_dump(mode="json"),
                        },
                    )
                )

        for field in topic.fields:
            view = views_by_id[field.view_id]
            requirements.extend(
                (
                    _requirement(
                        "grain",
                        "topic-field-grain",
                        (topic.blueprint_id, field.field_id),
                        evidence_hashes=topic_semantic_evidence,
                        material={"field": field.field_id, "view_grain": view.grain},
                    ),
                    _requirement(
                        "schema",
                        "topic-field-schema",
                        (topic.blueprint_id, field.field_id),
                        evidence_hashes=topic_semantic_evidence,
                        material=field.model_dump(mode="json"),
                    ),
                    _requirement(
                        "freshness",
                        "topic-field-freshness",
                        (topic.blueprint_id, field.field_id),
                        evidence_hashes=topic_semantic_evidence,
                        material=topic.freshness.model_dump(mode="json"),
                    ),
                )
            )
            if field.field_kind == "identifier":
                requirements.append(
                    _requirement(
                        "key",
                        "topic-field-key",
                        (topic.blueprint_id, field.field_id),
                        evidence_hashes=topic_semantic_evidence,
                        material={
                            "field": field.model_dump(mode="json"),
                            "view_primary_key_fields": view.primary_key_fields,
                            "view_key_evidence_refs": view.key_evidence_refs,
                        },
                    )
                )
            if field.field_kind == "time_dimension":
                requirements.append(
                    _requirement(
                        "time_semantics",
                        "topic-field-time",
                        (topic.blueprint_id, field.field_id),
                        evidence_hashes=topic_semantic_evidence,
                        material={
                            "field": field.model_dump(mode="json"),
                            "freshness": topic.freshness.model_dump(mode="json"),
                        },
                    )
                )

        requirements.append(
            _requirement(
                "fanout",
                "topic-fanout",
                (topic.blueprint_id,),
                evidence_hashes=(topic.blueprint_hash,),
                material={
                    "base_fact": topic.base_fact.model_dump(mode="json"),
                    "join_ids": sorted(item.join_id for item in topic.joins),
                },
            )
        )
        for join in topic.joins:
            requirements.append(
                _requirement(
                    "fanout",
                    "topic-join",
                    (topic.blueprint_id, join.join_id),
                    evidence_hashes=(
                        topic.blueprint_hash,
                        join.fanout_test.result_hash,
                    ),
                    material=join.model_dump(mode="json"),
                )
            )
        for measure in topic.measures:
            requirements.extend(
                (
                    _requirement(
                        "aggregate_calculation",
                        "topic-measure",
                        (topic.blueprint_id, measure.measure_id),
                        evidence_hashes=topic_semantic_evidence,
                        material=measure.model_dump(mode="json"),
                    ),
                    _requirement(
                        "grain",
                        "topic-measure-grain",
                        (topic.blueprint_id, measure.measure_id),
                        evidence_hashes=topic_semantic_evidence,
                        material={
                            "measure_grain": measure.grain,
                            "view_grain": views_by_id[measure.view_id].grain,
                        },
                    ),
                    _requirement(
                        "schema",
                        "topic-measure-schema",
                        (topic.blueprint_id, measure.measure_id),
                        evidence_hashes=topic_semantic_evidence,
                        material=measure.model_dump(mode="json"),
                    ),
                    _requirement(
                        "freshness",
                        "topic-measure-freshness",
                        (topic.blueprint_id, measure.measure_id),
                        evidence_hashes=topic_semantic_evidence,
                        material=topic.freshness.model_dump(mode="json"),
                    ),
                )
            )
            measure_time_profile = time_profiles_by_view.get(measure.view_id)
            if (
                time_fields_by_view[measure.view_id]
                or measure_time_profile is not None
            ):
                requirements.append(
                    _requirement(
                        "time_semantics",
                        "topic-measure-time",
                        (topic.blueprint_id, measure.measure_id),
                        evidence_hashes=topic_semantic_evidence,
                        material={
                            "measure": measure.model_dump(mode="json"),
                            "time_fields": [
                                item.model_dump(mode="json")
                                for item in time_fields_by_view[measure.view_id]
                            ],
                            "profile_time": (
                                {
                                    "profile_id": measure_time_profile.profile_id,
                                    "profile_hash": measure_time_profile.profile_hash,
                                    "time": measure_time_profile.time.model_dump(mode="json"),
                                }
                                if measure_time_profile is not None
                                else None
                            ),
                        },
                    )
                )

        source_mappings_by_id = {
            item.mapping_id: item for item in topic.source_mappings
        }
        for placement in topic.logic_placements:
            requirements.extend(
                (
                    _requirement(
                        "schema",
                        "topic-logic-schema",
                        (topic.blueprint_id, placement.placement_id),
                        evidence_hashes=topic_semantic_evidence,
                        material=placement.model_dump(mode="json"),
                    ),
                    _requirement(
                        "freshness",
                        "topic-logic-freshness",
                        (topic.blueprint_id, placement.placement_id),
                        evidence_hashes=topic_semantic_evidence,
                        material=topic.freshness.model_dump(mode="json"),
                    ),
                )
            )
            placement_profiles = {
                source_mappings_by_id[mapping_ref].source_profile_id
                for mapping_ref in placement.source_mapping_refs
            }
            placement_time_profiles = [
                profiles_by_id[profile_id]
                for profile_id in sorted(placement_profiles)
                if profile_id in profiles_by_id
                and profiles_by_id[profile_id].time.state != "not_applicable"
            ]
            if placement_time_profiles:
                requirements.append(
                    _requirement(
                        "time_semantics",
                        "topic-logic-time",
                        (topic.blueprint_id, placement.placement_id),
                        evidence_hashes=topic_semantic_evidence,
                        material={
                            "placement": placement.model_dump(mode="json"),
                            "source_profile_time": [
                                {
                                    "profile_id": item.profile_id,
                                    "profile_hash": item.profile_hash,
                                    "time": item.time.model_dump(mode="json"),
                                }
                                for item in placement_time_profiles
                            ],
                        },
                    )
                )

        governed_security = topic.security.target_security_domain != "unrestricted"
        if governed_security:
            security_base = topic.security.model_dump(mode="json")
            domains = {
                *topic.security.source_security_domains,
                topic.security.target_security_domain,
            }
            policies = {
                *topic.security.source_policy_refs,
                *topic.security.target_policy_refs,
            }
            for expectation in topic.security.persona_expectations:
                expectation_material = expectation.model_dump(mode="json")
                append_security_subject(
                    evidence_hashes=(topic.blueprint_hash,),
                    subject_kind="secured-topic-persona",
                    identity_parts=(topic.blueprint_id, expectation.persona_ref),
                    material={
                        "security": security_base,
                        "expectation": expectation_material,
                    },
                    persona_ref=expectation.persona_ref,
                    access=expectation.access,
                )
                for domain in sorted(domains):
                    append_security_subject(
                        evidence_hashes=(topic.blueprint_hash,),
                        subject_kind="secured-domain-persona",
                        identity_parts=(
                            topic.blueprint_id,
                            domain,
                            expectation.persona_ref,
                        ),
                        material={
                            "security_domain": domain,
                            "security": security_base,
                            "expectation": expectation_material,
                        },
                        persona_ref=expectation.persona_ref,
                        access=expectation.access,
                    )
                for policy_ref in sorted(policies):
                    append_security_subject(
                        evidence_hashes=(topic.blueprint_hash,),
                        subject_kind="secured-policy-persona",
                        identity_parts=(
                            topic.blueprint_id,
                            policy_ref,
                            expectation.persona_ref,
                        ),
                        material={
                            "policy_ref": policy_ref,
                            "security": security_base,
                            "expectation": expectation_material,
                        },
                        persona_ref=expectation.persona_ref,
                        access=expectation.access,
                    )

        for consumer in topic.consumer_mappings:
            if consumer.source_consumer_id not in selected_consumer_ids:
                continue
            consumer_ref = source_consumer_reference(consumer.source_consumer_id)
            consumer_material = consumer.model_dump(mode="json")
            consumer_view_ids = {
                component_view_ids[component_ref]
                for component_ref in consumer.topic_component_refs
                if component_ref in component_view_ids
            }
            consumer_key_material = {
                view_id: {
                    "primary_key_fields": views_by_id[view_id].primary_key_fields,
                    "key_evidence_refs": views_by_id[view_id].key_evidence_refs,
                }
                for view_id in sorted(consumer_view_ids)
            }
            if consumer_key_material:
                requirements.extend(
                    (
                        _requirement(
                            "key",
                            "topic-consumer-key",
                            (topic.blueprint_id, consumer.source_consumer_id),
                            evidence_hashes=topic_semantic_evidence,
                            material=consumer_key_material,
                            source_consumer_ref=consumer_ref,
                        ),
                        _requirement(
                            "grain",
                            "topic-consumer-grain",
                            (topic.blueprint_id, consumer.source_consumer_id),
                            evidence_hashes=topic_semantic_evidence,
                            material={
                                view_id: views_by_id[view_id].grain
                                for view_id in sorted(consumer_view_ids)
                            },
                            source_consumer_ref=consumer_ref,
                        ),
                    )
                )
            requirements.extend(
                (
                    _requirement(
                        "schema",
                        "topic-consumer-schema",
                        (topic.blueprint_id, consumer.source_consumer_id),
                        evidence_hashes=topic_semantic_evidence,
                        material=consumer_material,
                        source_consumer_ref=consumer_ref,
                    ),
                    _requirement(
                        "freshness",
                        "topic-consumer-freshness",
                        (topic.blueprint_id, consumer.source_consumer_id),
                        evidence_hashes=topic_semantic_evidence,
                        material=topic.freshness.model_dump(mode="json"),
                        source_consumer_ref=consumer_ref,
                    ),
                )
            )
            consumer_time_fields = tuple(
                item
                for view_id in sorted(consumer_view_ids)
                for item in time_fields_by_view[view_id]
            )
            consumer_time_profiles = tuple(
                (view_id, time_profiles_by_view[view_id])
                for view_id in sorted(consumer_view_ids)
                if view_id in time_profiles_by_view
            )
            if consumer_time_fields or consumer_time_profiles:
                requirements.append(
                    _requirement(
                        "time_semantics",
                        "topic-consumer-time",
                        (topic.blueprint_id, consumer.source_consumer_id),
                        evidence_hashes=topic_semantic_evidence,
                        material={
                            "consumer": consumer_material,
                            "time_fields": [
                                item.model_dump(mode="json")
                                for item in consumer_time_fields
                            ],
                            "view_profiles": [
                                {
                                    "view_id": view_id,
                                    "profile_id": profile.profile_id,
                                    "profile_hash": profile.profile_hash,
                                    "time": profile.time.model_dump(mode="json"),
                                }
                                for view_id, profile in consumer_time_profiles
                            ],
                        },
                        source_consumer_ref=consumer_ref,
                    )
                )
            for dimension in ("consumer_contract",):
                requirements.append(
                    _requirement(
                        dimension,
                        "topic-consumer",
                        (topic.blueprint_id, consumer.source_consumer_id),
                        evidence_hashes=(topic.blueprint_hash,),
                        material=consumer_material,
                        source_consumer_ref=consumer_ref,
                    )
                )

            for expectation in topic.security.persona_expectations:
                if not governed_security:
                    continue
                security_material = {
                    "security": topic.security.model_dump(mode="json"),
                    "consumer": consumer_material,
                    "expectation": expectation.model_dump(mode="json"),
                }
                append_security_subject(
                    evidence_hashes=(topic.blueprint_hash,),
                    subject_kind="secured-consumer-persona",
                    identity_parts=(
                        topic.blueprint_id,
                        consumer.source_consumer_id,
                        expectation.persona_ref,
                    ),
                    material=security_material,
                    source_consumer_ref=consumer_ref,
                    persona_ref=expectation.persona_ref,
                    access=expectation.access,
                )

    represented_behavior_ids = {
        behavior.source_behavior_id
        for mapping in plan.query_mappings
        for behaviors in (
            mapping.filter_contexts,
            mapping.controls,
            mapping.interactions,
            mapping.drills,
            mapping.visualizations,
            mapping.formatting,
            mapping.layouts,
            mapping.responsive,
            mapping.security,
            mapping.personas,
            mapping.operations,
        )
        for behavior in behaviors
    }
    for card in plan.card_mappings:
        completeness = card.content_completeness
        if completeness is None:
            continue
        represented_behavior_ids.update(
            item.source_behavior_id for item in completeness.formatting
        )
        represented_behavior_ids.update(
            item.source_behavior_id for item in completeness.security
        )
        represented_behavior_ids.update(
            item.source_behavior_id for item in completeness.personas
        )
        represented_behavior_ids.update(
            item.source_behavior_id for item in completeness.operations
        )
        for placement in completeness.placements:
            if placement.layout is not None:
                represented_behavior_ids.add(placement.layout.source_behavior_id)
            if placement.responsive is not None:
                represented_behavior_ids.add(placement.responsive.source_behavior_id)

    source_queries = {
        item.query.object_id: item for item in plan.source.queries
    }
    for query_mapping in plan.query_mappings:
        if query_mapping.outcome != "mapped":
            continue
        source_query = source_queries.get(query_mapping.query_id)
        if source_query is None or query_mapping.consumer_contract is None:
            raise ValueError("mapped query lacks exact source denominator evidence")
        consumer_ref = source_consumer_reference(
            query_mapping.consumer_contract.source_consumer_id
        )
        requirements.append(
            _requirement(
                "query_result",
                "dashboard-query",
                (plan.plan_id, query_mapping.query_id),
                evidence_hashes=(
                    plan.plan_hash,
                    source_query.query.revision_hash,
                    query_mapping.mapping_hash,
                ),
                material={
                    "query": source_query.model_dump(mode="json"),
                    "mapping": query_mapping.model_dump(mode="json"),
                },
                source_consumer_ref=consumer_ref,
            )
        )

        for context in query_mapping.filter_contexts:
            behavior_provenance = (
                dashboard_filter_context_provenance_binding(
                    plan=plan,
                    query_mapping=query_mapping,
                    filter_context=context,
                )
                if trusted_comparison_contexts is not None
                else None
            )
            behavior_comparison_context = (
                _comparison_context_for_provenance(
                    behavior_provenance,
                    trusted_comparison_contexts,
                )
                if behavior_provenance is not None
                and trusted_comparison_contexts is not None
                else None
            )
            requirements.append(
                _requirement(
                    "filter_context",
                    "dashboard-filter-context",
                    (plan.plan_id, query_mapping.query_id, context.source_behavior_id),
                    evidence_hashes=(plan.plan_hash, query_mapping.mapping_hash),
                    material=context.model_dump(mode="json"),
                    source_consumer_ref=consumer_ref,
                    comparison_context=behavior_comparison_context,
                    context_provenance=behavior_provenance,
                )
            )
        for control in query_mapping.controls:
            requirements.append(
                _requirement(
                    "control",
                    "dashboard-control",
                    (plan.plan_id, query_mapping.query_id, control.source_behavior_id),
                    evidence_hashes=(plan.plan_hash, query_mapping.mapping_hash),
                    material=control.model_dump(mode="json"),
                    source_consumer_ref=consumer_ref,
                )
            )
            for endpoint_kind, endpoint_ids in (
                ("card", control.target_card_ids),
                ("query", control.target_query_ids),
            ):
                for endpoint_id in endpoint_ids:
                    requirements.append(
                        _requirement(
                            "filter_propagation",
                            "dashboard-filter-edge",
                            (
                                plan.plan_id,
                                query_mapping.query_id,
                                control.source_behavior_id,
                                endpoint_kind,
                                endpoint_id,
                            ),
                            evidence_hashes=(plan.plan_hash, query_mapping.mapping_hash),
                            material={
                                "control": control.model_dump(mode="json"),
                                "endpoint_kind": endpoint_kind,
                                "endpoint_id": endpoint_id,
                            },
                            source_consumer_ref=consumer_ref,
                        )
                    )
        for interaction in query_mapping.interactions:
            requirements.append(
                _requirement(
                    "interaction",
                    "dashboard-interaction",
                    (plan.plan_id, query_mapping.query_id, interaction.source_behavior_id),
                    evidence_hashes=(plan.plan_hash, query_mapping.mapping_hash),
                    material=interaction.model_dump(mode="json"),
                    source_consumer_ref=consumer_ref,
                )
            )
        for drill in query_mapping.drills:
            requirements.append(
                _requirement(
                    "drill",
                    "dashboard-drill",
                    (plan.plan_id, query_mapping.query_id, drill.source_behavior_id),
                    evidence_hashes=(plan.plan_hash, query_mapping.mapping_hash),
                    material=drill.model_dump(mode="json"),
                    source_consumer_ref=consumer_ref,
                )
            )
        for visual in query_mapping.visualizations:
            requirements.append(
                _requirement(
                    "visual_fixture",
                    "dashboard-visual",
                    (plan.plan_id, query_mapping.query_id, visual.source_behavior_id),
                    evidence_hashes=(plan.plan_hash, query_mapping.mapping_hash),
                    material=visual.model_dump(mode="json"),
                    source_consumer_ref=consumer_ref,
                )
            )
        for formatting in query_mapping.formatting:
            requirements.append(
                _requirement(
                    "visual_fixture",
                    "dashboard-query-formatting",
                    (
                        plan.plan_id,
                        query_mapping.query_id,
                        formatting.source_behavior_id,
                    ),
                    evidence_hashes=(plan.plan_hash, query_mapping.mapping_hash),
                    material=formatting.model_dump(mode="json"),
                    source_consumer_ref=consumer_ref,
                )
            )
        for layout in query_mapping.layouts:
            requirements.append(
                _requirement(
                    "layout_intent",
                    "dashboard-query-layout",
                    (
                        plan.plan_id,
                        query_mapping.query_id,
                        layout.source_behavior_id,
                    ),
                    evidence_hashes=(plan.plan_hash, query_mapping.mapping_hash),
                    material=layout.model_dump(mode="json"),
                    source_consumer_ref=consumer_ref,
                )
            )
        for responsive in query_mapping.responsive:
            requirements.append(
                _requirement(
                    "visual_fixture",
                    "dashboard-query-responsive",
                    (
                        plan.plan_id,
                        query_mapping.query_id,
                        responsive.source_behavior_id,
                    ),
                    evidence_hashes=(plan.plan_hash, query_mapping.mapping_hash),
                    material=responsive.model_dump(mode="json"),
                    source_consumer_ref=consumer_ref,
                )
            )
        for security in query_mapping.security:
            for persona in query_mapping.personas:
                append_security_subject(
                    evidence_hashes=(plan.plan_hash, query_mapping.mapping_hash),
                    subject_kind="secured-query-security-persona",
                    identity_parts=(
                        plan.plan_id,
                        query_mapping.query_id,
                        security.source_behavior_id,
                        persona.persona_ref,
                    ),
                    material={
                        "security": security.model_dump(mode="json"),
                        "persona": persona.model_dump(mode="json"),
                    },
                    source_consumer_ref=consumer_ref,
                    persona_ref=persona.persona_ref,
                    access=persona.access,
                )
        for persona in query_mapping.personas:
            append_security_subject(
                evidence_hashes=(plan.plan_hash, query_mapping.mapping_hash),
                subject_kind="secured-query-persona",
                identity_parts=(
                    plan.plan_id,
                    query_mapping.query_id,
                    persona.source_behavior_id,
                    persona.persona_ref,
                ),
                material=persona.model_dump(mode="json"),
                source_consumer_ref=consumer_ref,
                persona_ref=persona.persona_ref,
                access=persona.access,
            )
        for operation in query_mapping.operations:
            requirements.append(
                _requirement(
                    "operations",
                    "dashboard-query-operation",
                    (plan.plan_id, query_mapping.query_id, operation.source_behavior_id),
                    evidence_hashes=(plan.plan_hash, query_mapping.mapping_hash),
                    material=operation.model_dump(mode="json"),
                    source_consumer_ref=consumer_ref,
                )
            )

    content_placements = {
        item.source_placement_id: item
        for card in plan.card_mappings
        if card.content_completeness is not None
        for item in card.content_completeness.placements
    }
    for placement in plan.source.placements:
        content_placement = content_placements.get(placement.placement_id)
        requirements.append(
            _requirement(
                "layout_intent",
                "dashboard-placement",
                (plan.plan_id, placement.placement_id),
                evidence_hashes=(plan.plan_hash, placement.placement_hash),
                material={
                    "source": placement.model_dump(mode="json"),
                    "content_target": (
                        content_placement.model_dump(mode="json")
                        if content_placement is not None
                        else None
                    ),
                },
            )
        )
    for card in plan.card_mappings:
        completeness = card.content_completeness
        if completeness is None:
            continue
        completeness_evidence = (
            plan.plan_hash,
            card.mapping_hash,
            completeness.completeness_hash,
        )
        requirements.append(
            _requirement(
                "visual_fixture",
                "dashboard-content-card",
                (plan.plan_id, card.source_card_id),
                evidence_hashes=completeness_evidence,
                material={
                    "content_ref": card.content_ref,
                    "source_card_evidence_ref": (
                        completeness.source_card_evidence_ref
                    ),
                    "source_card_evidence_hash": (
                        completeness.source_card_evidence_hash
                    ),
                    "target_card_ref": completeness.target_card_ref,
                },
            )
        )
        for formatting in completeness.formatting:
            requirements.append(
                _requirement(
                    "visual_fixture",
                    "dashboard-content-formatting",
                    (
                        plan.plan_id,
                        card.source_card_id,
                        formatting.source_behavior_id,
                    ),
                    evidence_hashes=completeness_evidence,
                    material=formatting.model_dump(mode="json"),
                )
            )
        for placement in completeness.placements:
            if placement.responsive is None:
                continue
            requirements.append(
                _requirement(
                    "visual_fixture",
                    "dashboard-content-responsive",
                    (
                        plan.plan_id,
                        card.source_card_id,
                        placement.source_placement_id,
                        placement.responsive.source_behavior_id,
                    ),
                    evidence_hashes=completeness_evidence,
                    material={
                        "placement": placement.source_placement_id,
                        "responsive": placement.responsive.model_dump(mode="json"),
                    },
                )
            )

        content_expectations: dict[tuple[str, str], Mapping[str, Any]] = {
            (item.persona_ref, item.access): item.model_dump(mode="json")
            for item in completeness.personas
        }
        if not content_expectations:
            content_expectations = {
                (item.persona_ref, item.access): item.model_dump(mode="json")
                for topic in selected_topics
                for item in topic.security.persona_expectations
            }
        governed_content_security = (
            completeness.security_resolution_id is not None
            or any(
                item.target_security_domain != "unrestricted"
                for item in completeness.security
            )
        )
        if governed_content_security:
            for (persona_ref, access), expectation in sorted(
                content_expectations.items()
            ):
                card_material = {
                    "card": card.source_card_id,
                    "security": [
                        item.model_dump(mode="json")
                        for item in completeness.security
                    ],
                    "security_resolution_id": completeness.security_resolution_id,
                    "persona_resolution_id": completeness.persona_resolution_id,
                    "expectation": expectation,
                }
                append_security_subject(
                    evidence_hashes=completeness_evidence,
                    subject_kind="secured-content-card-persona",
                    identity_parts=(
                        plan.plan_id,
                        card.source_card_id,
                        persona_ref,
                    ),
                    material=card_material,
                    persona_ref=persona_ref,
                    access=access,
                )
                for security in completeness.security:
                    append_security_subject(
                        evidence_hashes=completeness_evidence,
                        subject_kind="secured-content-domain-persona",
                        identity_parts=(
                            plan.plan_id,
                            card.source_card_id,
                            security.target_security_domain,
                            persona_ref,
                        ),
                        material={
                            **card_material,
                            "security_domain": security.target_security_domain,
                        },
                        persona_ref=persona_ref,
                        access=access,
                    )
                    for policy_ref in security.target_policy_refs:
                        append_security_subject(
                            evidence_hashes=completeness_evidence,
                            subject_kind="secured-content-policy-persona",
                            identity_parts=(
                                plan.plan_id,
                                card.source_card_id,
                                policy_ref,
                                persona_ref,
                            ),
                            material={
                                **card_material,
                                "policy_ref": policy_ref,
                            },
                            persona_ref=persona_ref,
                            access=access,
                        )
        for operation in completeness.operations:
            requirements.append(
                _requirement(
                    "operations",
                    "dashboard-content-operation",
                    (plan.plan_id, card.source_card_id, operation.source_behavior_id),
                    evidence_hashes=(plan.plan_hash, card.mapping_hash),
                    material=operation.model_dump(mode="json"),
                )
            )

    special_behaviors = {
        item.behavior_id: item for item in plan.source.special_behaviors
    }
    operational_behavior_kinds = {
        "refresh",
        "freshness",
        "cache",
        "schedule",
        "alert",
        "export",
        "writeback",
        "workflow_side_effect",
        "embed",
        "app",
    }
    visual_behavior_kinds = {"unsupported_visual", "formatting", "responsive"}
    for resolution in plan.behavior_resolutions:
        if resolution.source_behavior_id in represented_behavior_ids:
            continue
        source_behavior = special_behaviors[resolution.source_behavior_id]
        resolution_evidence = (
            plan.plan_hash,
            source_behavior.behavior_hash,
            resolution.resolution_hash,
        )
        resolution_material = {
            "source_behavior": source_behavior.model_dump(mode="json"),
            "resolution": resolution.model_dump(mode="json"),
        }
        if resolution.behavior_kind in operational_behavior_kinds:
            requirements.append(
                _requirement(
                    "operations",
                    "dashboard-special-operation",
                    (
                        plan.plan_id,
                        resolution.source_behavior_id,
                        resolution.resolution_id,
                    ),
                    evidence_hashes=resolution_evidence,
                    material=resolution_material,
                )
            )
        elif resolution.behavior_kind in visual_behavior_kinds:
            requirements.append(
                _requirement(
                    "visual_fixture",
                    "dashboard-special-visual",
                    (
                        plan.plan_id,
                        resolution.source_behavior_id,
                        resolution.resolution_id,
                    ),
                    evidence_hashes=resolution_evidence,
                    material=resolution_material,
                )
            )
        elif resolution.behavior_kind == "layout":
            requirements.append(
                _requirement(
                    "layout_intent",
                    "dashboard-special-layout",
                    (
                        plan.plan_id,
                        resolution.source_behavior_id,
                        resolution.resolution_id,
                    ),
                    evidence_hashes=resolution_evidence,
                    material=resolution_material,
                )
            )
        elif resolution.behavior_kind in {"security", "persona"}:
            for topic in selected_topics:
                for expectation in topic.security.persona_expectations:
                    append_security_subject(
                        evidence_hashes=(
                            *resolution_evidence,
                            topic.blueprint_hash,
                        ),
                        subject_kind="secured-behavior-resolution-persona",
                        identity_parts=(
                            plan.plan_id,
                            topic.blueprint_id,
                            resolution.resolution_id,
                            expectation.persona_ref,
                        ),
                        material={
                            **resolution_material,
                            "topic": topic.blueprint_id,
                            "expectation": expectation.model_dump(mode="json"),
                        },
                        persona_ref=expectation.persona_ref,
                        access=expectation.access,
                    )

    decisions_by_id = {
        item.decision_id: item for item in dashboard_snapshot.decisions
    }
    for decision in sorted(decisions_by_id.values(), key=lambda item: item.decision_id):
        if decision.classification not in {"different", "unknown"}:
            continue
        if not set(decision.affected_consumer_ids) & selected_consumer_ids:
            member_ids = {item.profile_id for item in decision.member_profiles}
            if not member_ids & required_profile_ids:
                continue
        for candidate in decision.candidate_refs:
            candidate_ref = negative_candidate_reference(candidate.candidate_id)
            requirements.append(
                _requirement(
                    "negative_consolidation_control",
                    "negative-consolidation-candidate",
                    (decision.decision_id, candidate.candidate_id),
                    evidence_hashes=(decision.decision_hash,),
                    material=candidate.model_dump(mode="json"),
                    negative_candidate_ref=candidate_ref,
                    expected_consolidation_outcome=decision.classification,
                )
            )

    if semantic_profile_coverage is not None:
        requirements = [
            replace(
                item,
                subject_hash=_qa_subject_hash(
                    dimension=item.dimension,
                    subject_ref=item.subject_ref,
                    evidence_hashes=(
                        item.subject_hash,
                        semantic_profile_coverage.coverage_hash,
                    ),
                    material={
                        "semantic_coverage_denominator_hash": (
                            semantic_profile_coverage.denominator_hash
                        )
                    },
                ),
            )
            for item in requirements
        ]

    keys = [_requirement_sort_key(item) for item in requirements]
    if len(keys) != len(set(keys)):
        raise ValueError("derived QA subject denominator contains duplicate requirements")
    return tuple(sorted(requirements, key=_requirement_sort_key))


def qa_subject_denominator_is_exact(
    cases: Any,
    expected: tuple[QASubjectRequirement, ...],
) -> bool:
    """Return whether cases close the exact subject multiset and cardinality."""

    def core(item: Any) -> tuple[Any, ...]:
        return (
            item.dimension,
            item.subject_ref,
            item.subject_hash,
            item.source_consumer_ref,
            item.persona_ref,
            item.expected_access,
            item.negative_candidate_ref,
            item.expected_consolidation_outcome,
        )

    try:
        actual = tuple(cases)
        expected_by_core = {core(item): item for item in expected}
        actual_by_core = {core(item): item for item in actual}
    except (AttributeError, TypeError, ValueError):
        return False
    if (
        len(actual) != len(expected)
        or len(actual_by_core) != len(actual)
        or len(expected_by_core) != len(expected)
        or set(actual_by_core) != set(expected_by_core)
    ):
        return False
    for identity, requirement in expected_by_core.items():
        if requirement.comparison_context_id is None:
            continue
        case = actual_by_core[identity]
        if (
            getattr(case, "comparison_context_id", None)
            != requirement.comparison_context_id
            or getattr(case, "comparison_context_hash", None)
            != requirement.comparison_context_hash
        ):
            return False
    return True


def source_consumer_reference(source_consumer_id: str) -> str:
    """Return the canonical safe reference for one Domo consumer identity."""

    if "://" in source_consumer_id:
        return source_consumer_id
    parts = source_consumer_id.split(".")
    if len(parts) >= 3 and parts[0].lower() == "domo":
        kind = quote(parts[1].lower(), safe="")
        identifier = quote(".".join(parts[2:]), safe="._-")
        return f"consumer-ref://domo/{kind}/{identifier}"
    return f"consumer-ref://domo/source/{quote(source_consumer_id, safe='._-')}"


def negative_candidate_reference(candidate_id: str) -> str:
    """Return the canonical reference for one rejected or unresolved candidate."""

    return f"candidate-ref://consolidation/{quote(candidate_id, safe='._-')}"


def _event_payload(record: Mapping[str, Any], event_type: str) -> Mapping[str, Any] | None:
    payload = record.get("payload", {})
    if record.get("record_type") != "event" or payload.get("event_type") != event_type:
        return None
    return payload


def _without_event_type(payload: Mapping[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in payload.items() if key != "event_type"}


def _artifact_envelope(payload: Mapping[str, Any]) -> ArtifactEnvelope:
    envelope = ArtifactEnvelope.from_mapping(payload)
    envelope.validate(
        expected_tenant_ref=envelope.tenant_ref,
        expected_run_id=envelope.run_id,
    )
    return envelope


class StoreBackedQAEvidenceResolver:
    """Resolve only current QA evidence from the canonical hash-chained ledger."""

    qa_subject_applicability_is_authoritative = True

    def __init__(self, *, store: AppendOnlyControlPlaneStore) -> None:
        if type(store) is not AppendOnlyControlPlaneStore:
            raise TypeError("QA resolver requires the canonical append-only store")
        self.store = store

    def _records(self, tenant_ref: str, run_id: str) -> list[dict[str, Any]]:
        return self.store.records(tenant_ref, run_id)

    @staticmethod
    def _identity_matches(
        value: Any,
        *,
        tenant_ref: str,
        run_id: str,
        scope_id: str,
        wave_id: str,
        migration_unit_id: str,
        validation_cycle_id: str,
    ) -> bool:
        return all(
            getattr(value, key) == expected
            for key, expected in (
                ("tenant_ref", tenant_ref),
                ("run_id", run_id),
                ("scope_id", scope_id),
                ("wave_id", wave_id),
                ("migration_unit_id", migration_unit_id),
                ("validation_cycle_id", validation_cycle_id),
            )
        )

    def resolve_current_qa_evidence_snapshot(
        self,
        *,
        tenant_ref: str,
        run_id: str,
        scope_id: str,
        wave_id: str,
        migration_unit_id: str,
        validation_cycle_id: str,
    ) -> QAEvidenceSnapshot | None:
        records = self._records(tenant_ref, run_id)
        snapshots: list[QAEvidenceSnapshot] = []
        for record in records:
            payload = _event_payload(record, "qa_evidence_snapshot_registered")
            if payload is None:
                continue
            raw = _without_event_type(payload)
            try:
                snapshot = finalize_qa_evidence_snapshot(raw)
            except (TypeError, ValueError):
                return None
            if raw.get("snapshot_hash") != snapshot.snapshot_hash:
                return None
            if self._identity_matches(
                snapshot,
                tenant_ref=tenant_ref,
                run_id=run_id,
                scope_id=scope_id,
                wave_id=wave_id,
                migration_unit_id=migration_unit_id,
                validation_cycle_id=validation_cycle_id,
            ):
                snapshots.append(snapshot)
        if not snapshots or len({item.snapshot_id for item in snapshots}) != 1:
            return None
        snapshots.sort(key=lambda item: item.revision)
        if [item.revision for item in snapshots] != list(range(1, len(snapshots) + 1)):
            return None
        for index, snapshot in enumerate(snapshots):
            if snapshot.snapshot_hash != qa_evidence_snapshot_hash(snapshot):
                return None
            predecessor = snapshots[index - 1] if index else None
            if predecessor is not None and (
                snapshot.supersedes_snapshot_hash != predecessor.snapshot_hash
            ):
                return None
        current = snapshots[-1]
        if any(
            not _qa_binding_matches_current_artifact(records, binding)
            for binding in current.bindings.all_artifacts()
        ):
            return None
        if any(
            not _qa_v2_payload_matches_current_artifact(records, binding)
            for binding in (
                *current.bindings.fixture_artifacts,
                *current.bindings.result_artifacts,
            )
        ):
            return None
        return current

    def _resolve_current_qa_v2_payload(
        self,
        *,
        tenant_ref: str,
        run_id: str,
        scope_id: str,
        wave_id: str,
        migration_unit_id: str,
        validation_cycle_id: str,
        artifact_ref: str,
        artifact_type: str,
    ) -> QAFixtureV2 | QAResultV2 | None:
        value = _current_registered_qa_v2_payload(
            self._records(tenant_ref, run_id),
            artifact_ref=artifact_ref,
            artifact_type=artifact_type,
        )
        if value is None or not self._identity_matches(
            value,
            tenant_ref=tenant_ref,
            run_id=run_id,
            scope_id=scope_id,
            wave_id=wave_id,
            migration_unit_id=migration_unit_id,
            validation_cycle_id=validation_cycle_id,
        ):
            return None
        return value

    def resolve_current_qa_fixture_v2(
        self,
        *,
        tenant_ref: str,
        run_id: str,
        scope_id: str,
        wave_id: str,
        migration_unit_id: str,
        validation_cycle_id: str,
        artifact_ref: str,
    ) -> QAFixtureV2 | None:
        """Resolve one current canonical fixture only through its exact artifact."""

        value = self._resolve_current_qa_v2_payload(
            tenant_ref=tenant_ref,
            run_id=run_id,
            scope_id=scope_id,
            wave_id=wave_id,
            migration_unit_id=migration_unit_id,
            validation_cycle_id=validation_cycle_id,
            artifact_ref=artifact_ref,
            artifact_type="qa_fixture",
        )
        return value if isinstance(value, QAFixtureV2) else None

    def resolve_current_qa_result_v2(
        self,
        *,
        tenant_ref: str,
        run_id: str,
        scope_id: str,
        wave_id: str,
        migration_unit_id: str,
        validation_cycle_id: str,
        artifact_ref: str,
    ) -> QAResultV2 | None:
        """Resolve one current canonical result only through its exact artifact."""

        value = self._resolve_current_qa_v2_payload(
            tenant_ref=tenant_ref,
            run_id=run_id,
            scope_id=scope_id,
            wave_id=wave_id,
            migration_unit_id=migration_unit_id,
            validation_cycle_id=validation_cycle_id,
            artifact_ref=artifact_ref,
            artifact_type="qa_result",
        )
        return value if isinstance(value, QAResultV2) else None

    def resolve_current_qa_target_operation_outcome(
        self,
        *,
        tenant_ref: str,
        run_id: str,
        scope_id: str,
        wave_id: str,
        migration_unit_id: str,
        validation_cycle_id: str,
        operation_id: str,
    ) -> Any | None:
        """Resolve one current operation only from its canonical store event."""

        value = _current_registered_qa_target_operation_outcome(
            self._records(tenant_ref, run_id),
            operation_id=operation_id,
        )
        if value is None or not self._identity_matches(
            value,
            tenant_ref=tenant_ref,
            run_id=run_id,
            scope_id=scope_id,
            wave_id=wave_id,
            migration_unit_id=migration_unit_id,
            validation_cycle_id=validation_cycle_id,
        ):
            return None
        return value

    def resolve_current_production_validation_report(
        self,
        *,
        tenant_ref: str,
        run_id: str,
        scope_id: str,
        wave_id: str,
        migration_unit_id: str,
        validation_cycle_id: str,
        report_ref: str,
    ) -> Any | None:
        """Resolve one exact current downstream production report."""

        value = _current_registered_production_validation_report(
            self._records(tenant_ref, run_id),
            report_ref=report_ref,
        )
        if value is None or not self._identity_matches(
            value,
            tenant_ref=tenant_ref,
            run_id=run_id,
            scope_id=scope_id,
            wave_id=wave_id,
            migration_unit_id=migration_unit_id,
            validation_cycle_id=validation_cycle_id,
        ):
            return None
        return value

    def _current_dashboard_snapshot(
        self,
        *,
        tenant_ref: str,
        run_id: str,
        scope_id: str,
        wave_id: str,
        migration_unit_id: str,
        validation_cycle_id: str,
    ) -> DashboardEvidenceSnapshot | None:
        snapshots: list[DashboardEvidenceSnapshot] = []
        for record in self._records(tenant_ref, run_id):
            payload = _event_payload(record, "dashboard_evidence_snapshot_registered")
            if payload is None:
                continue
            raw = _without_event_type(payload)
            try:
                snapshot = finalize_dashboard_evidence_snapshot(raw)
            except (TypeError, ValueError):
                return None
            if raw.get("snapshot_hash") != snapshot.snapshot_hash:
                return None
            if (
                snapshot.tenant_ref == tenant_ref
                and snapshot.run_id == run_id
                and snapshot.scope_id == scope_id
                and snapshot.wave_id == wave_id
                and snapshot.migration_unit_id == migration_unit_id
                and snapshot.validation_cycle_id == validation_cycle_id
            ):
                snapshots.append(snapshot)
        if not snapshots or len({item.snapshot_id for item in snapshots}) != 1:
            return None
        snapshots.sort(key=lambda item: item.revision)
        if [item.revision for item in snapshots] != list(range(1, len(snapshots) + 1)):
            return None
        for index, snapshot in enumerate(snapshots):
            if snapshot.snapshot_hash != dashboard_evidence_snapshot_hash(snapshot):
                return None
            predecessor = snapshots[index - 1] if index else None
            if predecessor is not None and (
                snapshot.supersedes_snapshot_hash != predecessor.snapshot_hash
            ):
                return None
        current = snapshots[-1]
        try:
            self.store.assert_dashboard_evidence_snapshot_current(current)
        except (RuntimeError, TypeError, ValueError):
            return None
        return current

    def _current_dashboard_validation(
        self,
        *,
        tenant_ref: str,
        run_id: str,
        scope_id: str,
        migration_unit_id: str,
        validation_cycle_id: str,
        dashboard_snapshot: DashboardEvidenceSnapshot,
    ) -> DashboardPlanValidationRegistration | None:
        registrations = [
            item
            for item in dashboard_snapshot.plan_registrations
            if item.migration_unit_id == migration_unit_id
            and item.validation_cycle_id == validation_cycle_id
        ]
        if len(registrations) != 1:
            return None
        plan = registrations[0]
        candidates: list[DashboardPlanValidationRegistration] = []
        for record in self._records(tenant_ref, run_id):
            payload = _event_payload(record, "dashboard_plan_validated")
            if payload is None:
                continue
            try:
                value = DashboardPlanValidationRegistration.model_validate(
                    _without_event_type(payload)
                )
            except (TypeError, ValueError):
                return None
            if (
                value.scope_id == scope_id
                and value.wave_id == dashboard_snapshot.wave_id
                and value.migration_unit_id == migration_unit_id
                and value.validation_cycle_id == validation_cycle_id
                and value.plan_id == plan.plan_id
            ):
                candidates.append(value)
        current = [
            value
            for value in candidates
            if value.registration_hash
            == dashboard_plan_validation_registration_hash(value)
            and value.plan_hash == plan.plan_hash
            and value.evidence_snapshot_ref == dashboard_snapshot.snapshot_ref
            and value.evidence_snapshot_hash == dashboard_snapshot.snapshot_hash
            and value.evidence_snapshot_revision == dashboard_snapshot.revision
        ]
        return current[0] if len(current) == 1 else None

    def _current_dashboard_plan_payload(
        self,
        *,
        tenant_ref: str,
        run_id: str,
        scope_id: str,
        migration_unit_id: str,
        validation_cycle_id: str,
        plan_validation: DashboardPlanValidationRegistration,
    ) -> DashboardRebuildPlan | None:
        """Resolve the one canonical full plan behind a dashboard validation.

        Dashboard evidence snapshots intentionally summarize query mappings.  Exact
        behavior-instance QA therefore requires the store's typed full-plan event;
        the snapshot hash alone cannot reconstruct controls or propagation edges.
        """

        matches: list[DashboardRebuildPlan] = []
        for record in self._records(tenant_ref, run_id):
            payload = _event_payload(record, "dashboard_plan_payload_registered")
            if payload is None or not isinstance(payload.get("plan"), Mapping):
                continue
            raw_plan = dict(payload["plan"])
            try:
                plan = finalize_dashboard_rebuild_plan(raw_plan)
            except (TypeError, ValueError):
                return None
            if raw_plan != plan.model_dump(mode="json"):
                return None
            if (
                plan.run_id == run_id
                and plan.scope_id == scope_id
                and plan.migration_unit_id == migration_unit_id
                and plan.validation_cycle_id == validation_cycle_id
                and plan.plan_id == plan_validation.plan_id
                and plan.plan_hash == plan_validation.plan_hash
                and dashboard_plan_content_sha256(plan)
                == plan_validation.plan_artifact_content_sha256
            ):
                matches.append(plan)
        return matches[0] if len(matches) == 1 else None

    def _current_semantic_profile_coverage(
        self,
        *,
        tenant_ref: str,
        run_id: str,
        scope_id: str,
        migration_unit_id: str,
        validation_cycle_id: str,
        binding: Any,
    ) -> tuple[ArtifactEnvelope, SemanticProfileCoverage] | None:
        """Resolve one exact current typed semantic-coverage registration."""

        records = self._records(tenant_ref, run_id)
        try:
            coverages = _registered_semantic_profile_coverages(
                records,
                tenant_ref=tenant_ref,
                run_id=run_id,
                scope_id=scope_id,
                migration_unit_id=migration_unit_id,
                validation_cycle_id=validation_cycle_id,
            )
        except (RuntimeError, TypeError, ValueError):
            return None
        if len(coverages) != 1:
            return None
        envelope, coverage = coverages[0]
        if (
            coverage.status != "complete"
            or coverage.coverage_hash != semantic_profile_coverage_hash(coverage)
            or binding.artifact_type != "semantic_profile_coverage"
            or binding.artifact_id != envelope.artifact_id
            or binding.artifact_ref != envelope.ref
            or binding.revision != envelope.revision
            or binding.content_sha256 != envelope.content_sha256
            or binding.semantic_hash != coverage.coverage_hash
            or binding.producer_ref != envelope.producer_ref
            or envelope.migration_unit_id != migration_unit_id
            or envelope.validation_cycle_id != validation_cycle_id
        ):
            return None
        return envelope, coverage

    def _current_semantic_profiles(
        self,
        *,
        tenant_ref: str,
        run_id: str,
        scope_id: str,
        migration_unit_id: str,
        validation_cycle_id: str,
    ) -> tuple[tuple[ArtifactEnvelope, SemanticProfile], ...] | None:
        try:
            return _registered_semantic_profiles(
                self._records(tenant_ref, run_id),
                tenant_ref=tenant_ref,
                run_id=run_id,
                scope_id=scope_id,
                migration_unit_id=migration_unit_id,
                validation_cycle_id=validation_cycle_id,
            )
        except (RuntimeError, TypeError, ValueError):
            return None

    def resolve_current_qa_denominator(
        self,
        *,
        tenant_ref: str,
        run_id: str,
        scope_id: str,
        wave_id: str,
        migration_unit_id: str,
        validation_cycle_id: str,
    ) -> QACoverageDenominator | None:
        qa_snapshot = self.resolve_current_qa_evidence_snapshot(
            tenant_ref=tenant_ref,
            run_id=run_id,
            scope_id=scope_id,
            wave_id=wave_id,
            migration_unit_id=migration_unit_id,
            validation_cycle_id=validation_cycle_id,
        )
        if qa_snapshot is None:
            return None
        dashboard_snapshot = self._current_dashboard_snapshot(
            tenant_ref=tenant_ref,
            run_id=run_id,
            scope_id=scope_id,
            wave_id=wave_id,
            migration_unit_id=migration_unit_id,
            validation_cycle_id=validation_cycle_id,
        )
        if dashboard_snapshot is None:
            return None
        plan_validation = self._current_dashboard_validation(
            tenant_ref=tenant_ref,
            run_id=run_id,
            scope_id=scope_id,
            migration_unit_id=migration_unit_id,
            validation_cycle_id=validation_cycle_id,
            dashboard_snapshot=dashboard_snapshot,
        )
        if plan_validation is None:
            return None
        dashboard_plan = self._current_dashboard_plan_payload(
            tenant_ref=tenant_ref,
            run_id=run_id,
            scope_id=scope_id,
            migration_unit_id=migration_unit_id,
            validation_cycle_id=validation_cycle_id,
            plan_validation=plan_validation,
        )
        if dashboard_plan is None:
            return None
        plan_binding = qa_snapshot.bindings.dashboard_plan
        if (
            plan_binding.semantic_hash != plan_validation.plan_hash
            or plan_binding.artifact_ref != plan_validation.plan_artifact_ref
            or plan_binding.content_sha256
            != plan_validation.plan_artifact_content_sha256
        ):
            return None
        coverage_registration = self._current_semantic_profile_coverage(
            tenant_ref=tenant_ref,
            run_id=run_id,
            scope_id=scope_id,
            migration_unit_id=migration_unit_id,
            validation_cycle_id=validation_cycle_id,
            binding=qa_snapshot.bindings.semantic_profile_coverage,
        )
        if coverage_registration is None:
            return None
        _coverage_artifact, semantic_coverage = coverage_registration

        plan_id = plan_validation.plan_id
        selected_topic_ids = {
            item.topic_blueprint_id
            for item in dashboard_snapshot.query_mappings
            if item.plan_id == plan_id
        }
        if not selected_topic_ids:
            return None
        topics_by_id = {
            item.blueprint_id: item for item in dashboard_snapshot.topic_blueprints
        }
        registered_by_id = {
            item.blueprint_id: item for item in dashboard_snapshot.registered_topics
        }
        accepted_by_id = {
            item.blueprint_id: item for item in dashboard_snapshot.accepted_topics
        }
        if not selected_topic_ids.issubset(
            set(topics_by_id) & set(registered_by_id) & set(accepted_by_id)
        ):
            return None
        topic_binding_ids: set[str] = set()
        for binding in qa_snapshot.bindings.topic_blueprints:
            matches = [
                topic_id
                for topic_id in selected_topic_ids
                if registered_by_id[topic_id].blueprint_hash == binding.semantic_hash
                and topics_by_id[topic_id].blueprint_hash == binding.semantic_hash
                and accepted_by_id[topic_id].blueprint_hash == binding.semantic_hash
            ]
            if len(matches) != 1:
                return None
            topic_binding_ids.add(matches[0])
        if topic_binding_ids != selected_topic_ids:
            return None

        selected_topics = [topics_by_id[item] for item in sorted(selected_topic_ids)]
        source_consumer_ids = {
            mapping.consumer_contract.source_consumer_id
            for mapping in dashboard_plan.query_mappings
            if mapping.outcome == "mapped" and mapping.consumer_contract is not None
        }
        source_consumer_refs = {
            source_consumer_reference(item) for item in source_consumer_ids
        }
        allowed_personas = {
            item.persona_ref
            for topic in selected_topics
            for item in topic.security.persona_expectations
            if item.access == "allowed"
        } | {
            item.persona_ref
            for card in dashboard_plan.card_mappings
            if card.content_completeness is not None
            for item in card.content_completeness.personas
            if item.access == "allowed"
        }
        denied_personas = {
            item.persona_ref
            for topic in selected_topics
            for item in topic.security.persona_expectations
            if item.access == "denied"
        } | {
            item.persona_ref
            for card in dashboard_plan.card_mappings
            if card.content_completeness is not None
            for item in card.content_completeness.personas
            if item.access == "denied"
        }
        if not source_consumer_refs or not allowed_personas or not denied_personas:
            return None

        accepted_topic_profile_ids = {
            profile_id
            for topic_id in selected_topic_ids
            for profile_id in accepted_by_id[topic_id].profile_ids
        }
        plan_profile_ids = {
            item.profile_id for item in dashboard_plan.profile_bindings
        }
        # Dashboard-only query profiles (for example, a source Page or Card
        # behavior profile) need not be Topic members.  QA must bind the exact
        # union of the accepted Topic profiles and the dashboard plan profiles.
        required_profile_ids = accepted_topic_profile_ids | plan_profile_ids
        profiles_by_id = {
            item.profile_id: item for item in dashboard_snapshot.profiles
        }
        if not required_profile_ids.issubset(profiles_by_id):
            return None
        current_profiles = self._current_semantic_profiles(
            tenant_ref=tenant_ref,
            run_id=run_id,
            scope_id=scope_id,
            migration_unit_id=migration_unit_id,
            validation_cycle_id=validation_cycle_id,
        )
        if current_profiles is None:
            return None
        profile_binding_ids: set[str] = set()
        accepted_profiles: list[SemanticProfile] = []
        for binding in qa_snapshot.bindings.semantic_profiles:
            matches = [
                profile_id
                for profile_id in required_profile_ids
                if profiles_by_id[profile_id].profile_hash == binding.semantic_hash
            ]
            if len(matches) != 1:
                return None
            profile_id = matches[0]
            current_matches = [
                (envelope, profile)
                for envelope, profile in current_profiles
                if profile.profile_id == profile_id
                and profile.profile_hash == binding.semantic_hash
                and envelope.artifact_id == binding.artifact_id
                and envelope.artifact_type == binding.artifact_type
                and envelope.ref == binding.artifact_ref
                and envelope.revision == binding.revision
                and envelope.content_sha256 == binding.content_sha256
                and envelope.producer_ref == binding.producer_ref
            ]
            if len(current_matches) != 1:
                return None
            _profile_artifact, current_profile = current_matches[0]
            if current_profile != profiles_by_id[profile_id]:
                return None
            subject_ref = semantic_coverage_subject_for_qa_profile(
                current_profile,
                semantic_coverage,
            )
            if subject_ref is None:
                return None
            resolution = next(
                (
                    item
                    for item in semantic_coverage.resolutions
                    if item.subject_ref == subject_ref
                ),
                None,
            )
            if resolution is None or resolution.profile is None:
                return None
            if (
                resolution.profile.profile_id == current_profile.profile_id
                and resolution.profile.profile_hash == current_profile.profile_hash
                and (
                    resolution.profile.artifact.artifact_id
                    != _profile_artifact.artifact_id
                    or resolution.profile.artifact.artifact_type
                    != _profile_artifact.artifact_type
                    or resolution.profile.artifact.artifact_ref
                    != _profile_artifact.ref
                    or resolution.profile.artifact.revision
                    != _profile_artifact.revision
                    or resolution.profile.artifact.content_sha256
                    != _profile_artifact.content_sha256
                    or resolution.profile.artifact.producer_ref
                    != _profile_artifact.producer_ref
                )
            ):
                return None
            profile_binding_ids.add(profile_id)
            accepted_profiles.append(current_profile)
        if profile_binding_ids != required_profile_ids:
            return None
        if not _profiles_match_semantic_coverage(
            accepted_profiles,
            semantic_coverage,
        ):
            return None

        decisions_by_id = {
            item.decision_id: item for item in dashboard_snapshot.decisions
        }
        positive_decision_ids = {
            decision_id
            for topic_id in selected_topic_ids
            for decision_id in accepted_by_id[topic_id].decision_ids
        }
        if not positive_decision_ids.issubset(decisions_by_id):
            return None
        negative_decisions = {
            decision_id: decision
            for decision_id, decision in decisions_by_id.items()
            if decision.classification in {"different", "unknown"}
            and (
                set(decision.affected_consumer_ids) & source_consumer_ids
                or {item.profile_id for item in decision.member_profiles}
                & required_profile_ids
            )
        }
        if not negative_decisions:
            return None
        required_decision_ids = positive_decision_ids | set(negative_decisions)
        decision_binding_ids: set[str] = set()
        for binding in qa_snapshot.bindings.consolidation_decisions:
            matches = [
                decision_id
                for decision_id in required_decision_ids
                if decisions_by_id[decision_id].decision_hash == binding.semantic_hash
            ]
            if len(matches) != 1:
                return None
            decision_binding_ids.add(matches[0])
        if decision_binding_ids != required_decision_ids:
            return None

        expected_negative_outcomes = {
            negative_candidate_reference(candidate.candidate_id): decision.classification
            for decision in negative_decisions.values()
            for candidate in decision.candidate_refs
        }
        if not expected_negative_outcomes:
            return None
        denominator = qa_snapshot.denominator
        if (
            denominator.denominator_hash != qa_coverage_denominator_hash(denominator)
            or set(denominator.source_consumer_refs) != source_consumer_refs
            or set(denominator.allowed_persona_refs) != allowed_personas
            or set(denominator.denied_persona_refs) != denied_personas
            or {item.artifact_ref for item in qa_snapshot.bindings.persona_policies}
            != allowed_personas | denied_personas
        ):
            return None

        expected_derived = {
            plan_binding.binding_hash,
            qa_snapshot.bindings.semantic_profile_coverage.binding_hash,
            *(item.binding_hash for item in qa_snapshot.bindings.topic_blueprints),
            *(item.binding_hash for item in qa_snapshot.bindings.semantic_profiles),
            *(item.binding_hash for item in qa_snapshot.bindings.consolidation_decisions),
        }
        if set(denominator.derived_from_binding_hashes) != expected_derived:
            return None

        try:
            expected_subjects = derive_exact_qa_subject_requirements(
                plan=dashboard_plan,
                dashboard_snapshot=dashboard_snapshot,
                semantic_profile_coverage=semantic_coverage,
                comparison_contexts=qa_snapshot.comparison_contexts,
            )
        except (TypeError, ValueError):
            return None
        if not qa_subject_denominator_is_exact(
            denominator.cases, expected_subjects
        ):
            return None

        consumer_cases = {
            (item.source_consumer_ref, item.dimension)
            for item in denominator.cases
            if item.dimension in {"consumer_contract", "query_result"}
        }
        if consumer_cases != {
            (consumer, dimension)
            for consumer in source_consumer_refs
            for dimension in ("consumer_contract", "query_result")
        }:
            return None
        persona_cases = {
            (item.persona_ref, item.dimension, item.expected_access)
            for item in denominator.cases
            if item.dimension in {
                "security_allow",
                "security_deny",
                "derived_field_leakage",
            }
        }
        expected_persona_cases = {
            *((persona, "security_allow", "allow") for persona in allowed_personas),
            *((persona, "security_deny", "deny") for persona in denied_personas),
            *((persona, "derived_field_leakage", "deny") for persona in denied_personas),
        }
        if persona_cases != expected_persona_cases:
            return None
        negative_cases = {
            (item.negative_candidate_ref, item.expected_consolidation_outcome)
            for item in denominator.cases
            if item.dimension == "negative_consolidation_control"
        }
        if negative_cases != set(expected_negative_outcomes.items()):
            return None
        if any(count != 1 for count in Counter(item.case_id for item in denominator.cases).values()):
            return None
        return denominator

    def resolve_current_qa_suite_artifact(
        self,
        *,
        tenant_ref: str,
        run_id: str,
        scope_id: str,
        wave_id: str,
        migration_unit_id: str,
        validation_cycle_id: str,
        suite_id: str,
    ) -> ArtifactEnvelope | None:
        del scope_id, wave_id, suite_id
        records = self._records(tenant_ref, run_id)
        artifact_ids = {
            str(record.get("payload", {}).get("artifact_id"))
            for record in records
            if record.get("record_type") == "artifact"
            and record.get("payload", {}).get("artifact_type")
            == "qa_acceptance_suite"
            and record.get("payload", {}).get("migration_unit_id")
            == migration_unit_id
            and record.get("payload", {}).get("validation_cycle_id")
            == validation_cycle_id
        }
        current = [
            _current_artifact_payload(records, artifact_id=artifact_id)
            for artifact_id in artifact_ids
        ]
        current = [
            item
            for item in current
            if item is not None
            and item.get("artifact_type") == "qa_acceptance_suite"
            and item.get("migration_unit_id") == migration_unit_id
            and item.get("validation_cycle_id") == validation_cycle_id
        ]
        if len(current) != 1:
            return None
        try:
            return _artifact_envelope(current[0])
        except (TypeError, ValueError):
            return None

    def resolve_current_qa_suite_validation(
        self,
        *,
        tenant_ref: str,
        run_id: str,
        scope_id: str,
        wave_id: str,
        migration_unit_id: str,
        validation_cycle_id: str,
    ) -> QASuiteValidationRegistration | None:
        snapshot = self.resolve_current_qa_evidence_snapshot(
            tenant_ref=tenant_ref,
            run_id=run_id,
            scope_id=scope_id,
            wave_id=wave_id,
            migration_unit_id=migration_unit_id,
            validation_cycle_id=validation_cycle_id,
        )
        suite_artifact = self.resolve_current_qa_suite_artifact(
            tenant_ref=tenant_ref,
            run_id=run_id,
            scope_id=scope_id,
            wave_id=wave_id,
            migration_unit_id=migration_unit_id,
            validation_cycle_id=validation_cycle_id,
            suite_id="current",
        )
        if snapshot is None or suite_artifact is None:
            return None
        matches: list[QASuiteValidationRegistration] = []
        for record in self._records(tenant_ref, run_id):
            payload = _event_payload(record, "qa_suite_validated")
            if payload is None:
                continue
            try:
                value = QASuiteValidationRegistration.model_validate(
                    _without_event_type(payload)
                )
            except (TypeError, ValueError):
                return None
            if not self._identity_matches(
                value,
                tenant_ref=tenant_ref,
                run_id=run_id,
                scope_id=scope_id,
                wave_id=wave_id,
                migration_unit_id=migration_unit_id,
                validation_cycle_id=validation_cycle_id,
            ):
                continue
            if (
                value.registration_hash == qa_suite_validation_registration_hash(value)
                and value.evidence_snapshot_ref == snapshot.snapshot_ref
                and value.evidence_snapshot_hash == snapshot.snapshot_hash
                and value.evidence_snapshot_revision == snapshot.revision
                and value.suite_artifact_ref == suite_artifact.ref
                and value.suite_artifact_content_sha256 == suite_artifact.content_sha256
            ):
                matches.append(value)
        return matches[0] if len(matches) == 1 else None


class RecordBackedQAEvidenceResolver(StoreBackedQAEvidenceResolver):
    """Resolve QA evidence from already verified ledger records in policy/evals."""

    def __init__(self, *, records: tuple[Mapping[str, Any], ...] | list[Mapping[str, Any]]):
        self.store = None
        self._trusted_records = tuple(dict(item) for item in records)

    def _records(self, tenant_ref: str, run_id: str) -> list[dict[str, Any]]:
        return [
            dict(item)
            for item in self._trusted_records
            if item.get("tenant_ref") == tenant_ref and item.get("run_id") == run_id
        ]


__all__ = [
    "QASubjectRequirement",
    "RecordBackedQAEvidenceResolver",
    "StoreBackedQAEvidenceResolver",
    "dashboard_filter_context_provenance_binding",
    "derive_exact_qa_subject_requirements",
    "negative_candidate_reference",
    "qa_subject_denominator_is_exact",
    "qa_subject_reference",
    "semantic_profile_context_provenance_binding",
    "source_consumer_reference",
]

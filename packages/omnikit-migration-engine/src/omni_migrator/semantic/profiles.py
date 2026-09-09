"""Build and verify immutable semantic profiles."""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Mapping, Sequence

from omni_migrator.control_plane.canonical import canonical_json, sha256_json
from omni_migrator.extractors.domo.models import DomoObject
from omni_migrator.repositories.dbt.models import (
    RepositoryInventory,
    ResourceRecord,
    SemanticAssetRecord,
)
from omni_migrator.semantic.models import (
    RepositoryDefinitionEvidence,
    SemanticProfile,
    SemanticProfileRequirement,
    repository_definition_evidence_hash,
    semantic_profile_requirement_hash,
)
from omni_migrator.semantic.normalize import canonicalize_definition

DIMENSIONS = (
    "definition",
    "grain",
    "lineage",
    "aggregation",
    "filters",
    "joins",
    "time",
    "security",
    "operations",
    "consumers",
    "side_effects",
)
DOMO_PROFILE_BUILDER_VERSION = "domo-semantic-profile-builder-v1"
DBT_PROFILE_BUILDER_VERSION = "dbt-semantic-profile-builder-v1"

_DOMO_TYPE_ALIASES = {
    "dashboard": "page",
    "magicetl": "magic_etl",
    "sql_data_flow": "sql_dataflow",
    "beastmode": "beast_mode",
    "pdp": "pdp_policy",
}

_PROFILE_KIND_BY_DOMO_TYPE = {
    "page": "dashboard_query",
    "subpage": "dashboard_query",
    "card": "dashboard_query",
    "dataset": "dataset_output",
    "dataset_schema": "dataset_output",
    "dataflow": "transformation",
    "magic_etl": "transformation",
    "sql_dataflow": "transformation",
    "beast_mode": "calculation",
    "variable": "calculation",
    "pdp_policy": "security_policy",
    "workflow": "workflow_output",
}

_MISSING = object()


def _sha256(value: Any) -> str:
    return f"sha256:{sha256_json(value)}"


def _normalized_domo_type(value: str) -> str:
    normalized = value.lower().replace("-", "_").replace(" ", "_")
    return _DOMO_TYPE_ALIASES.get(normalized, normalized)


def _requirement_id(requirement: SemanticProfileRequirement) -> str:
    material = {
        "base_object_id": requirement.base_object_id,
        "context_id": requirement.context_id,
        "context_hash": requirement.context_hash,
    }
    return f"semantic-profile-requirement.{sha256_json(material)[:24]}"


def _profile_object_id(requirement: SemanticProfileRequirement) -> str:
    if requirement.context_id == "base":
        return requirement.base_object_id
    return (
        f"{requirement.base_object_id}.context."
        f"{requirement.context_hash.removeprefix('sha256:')[:16]}"
    )


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        return []
    return sorted({str(item) for item in value if isinstance(item, str) and item})


def _context_descriptor(
    source_object: DomoObject,
    requirement: SemanticProfileRequirement,
) -> tuple[dict[str, Any] | None, list[str]]:
    if requirement.context_id == "base":
        descriptor: dict[str, Any] = {"context_id": "base"}
        if requirement.context_hash != _sha256(descriptor):
            raise ValueError("base context_hash does not match the canonical base descriptor")
        return descriptor, []

    semantic = _mapping(source_object.attributes.get("semantic_profile"))
    raw_contexts = semantic.get("contexts")
    if not isinstance(raw_contexts, list):
        return None, [f"context:{requirement.context_id}:evidence_missing"]
    matches = [
        item
        for item in raw_contexts
        if isinstance(item, Mapping) and item.get("context_id") == requirement.context_id
    ]
    if not matches:
        return None, [f"context:{requirement.context_id}:evidence_missing"]
    if len(matches) != 1:
        raise ValueError(f"context_id is not unique in Domo evidence: {requirement.context_id}")
    descriptor = deepcopy(dict(matches[0]))
    hash_material = deepcopy(descriptor)
    hash_material.pop("context_ref", None)
    if requirement.context_hash != _sha256(hash_material):
        raise ValueError("context_hash does not match the captured Domo context")
    descriptor_ref = descriptor.get("context_ref")
    if descriptor_ref is not None and descriptor_ref != requirement.context_ref:
        raise ValueError("context_ref does not match the captured Domo context")
    blockers: list[str] = []
    if descriptor_ref is None:
        blockers.append(f"context:{requirement.context_id}:reference_missing")
    descriptor_consumer = descriptor.get("consumer_object_id")
    if descriptor_consumer is not None and descriptor_consumer != requirement.consumer_object_id:
        raise ValueError("consumer_object_id does not match the captured Domo context")
    if (
        requirement.consumer_object_id is not None
        and descriptor_consumer is None
        and descriptor.get("consumer_object_key") is None
    ):
        blockers.append(f"context:{requirement.context_id}:consumer_evidence_missing")
    return descriptor, blockers


def _original_definition(source_type: str, source_object: DomoObject) -> Any:
    definition = source_object.attributes.get("definition", _MISSING)
    if source_type == "sql_dataflow":
        if isinstance(definition, Mapping):
            return definition.get("sql", _MISSING)
        return _MISSING
    if source_type in {"beast_mode", "variable"}:
        if isinstance(definition, Mapping):
            return definition.get("formula", _MISSING)
        return _MISSING
    return definition


def _definition_language(source_type: str) -> tuple[str, str | None, str]:
    if source_type == "sql_dataflow":
        return "sql", None, "domo-sql-dataflow"
    if source_type in {"beast_mode", "variable"}:
        return "beast_mode", None, "domo-beast-mode"
    if source_type == "magic_etl":
        return "magic_etl", None, "domo-magic-etl"
    if source_type in {"dataflow", "workflow"}:
        return "workflow", None, f"domo-{source_type.replace('_', '-')}"
    return "workflow", None, f"domo-{source_type.replace('_', '-')}"


def _semantic_value(
    source_object: DomoObject,
    context: Mapping[str, Any] | None,
    name: str,
) -> Any:
    if context is not None and name in context:
        return context[name]
    return _mapping(source_object.attributes.get("semantic_profile")).get(name, _MISSING)


def _definition_mapping(source_object: DomoObject) -> Mapping[str, Any]:
    return _mapping(source_object.attributes.get("definition"))


def _profile_grain(
    source_type: str,
    source_object: DomoObject,
    context: Mapping[str, Any] | None,
) -> dict[str, Any]:
    explicit = _semantic_value(source_object, context, "grain")
    if isinstance(explicit, Mapping):
        return {
            "state": explicit.get("state", "known"),
            "description": explicit.get("description"),
            "key_fields": _string_list(explicit.get("key_fields", [])),
            "row_universe": explicit.get("row_universe"),
            "uniqueness_evidence_refs": _string_list(
                explicit.get("uniqueness_evidence_refs", [])
            ),
        }
    definition = _definition_mapping(source_object)
    description = definition.get("grain")
    if isinstance(description, str) and description:
        return {
            "state": "known",
            "description": description,
            "key_fields": _string_list(definition.get("key_fields", [])),
            "row_universe": definition.get("row_universe"),
            "uniqueness_evidence_refs": _string_list(
                definition.get("uniqueness_evidence_refs", [])
            ),
        }
    if source_type == "pdp_policy":
        return {
            "state": "not_applicable",
            "description": None,
            "key_fields": [],
            "row_universe": None,
            "uniqueness_evidence_refs": [],
        }
    return {
        "state": "unknown",
        "description": None,
        "key_fields": [],
        "row_universe": None,
        "uniqueness_evidence_refs": [],
    }


def _profile_lineage(
    portfolio_object: Mapping[str, Any],
    source_object: DomoObject,
    context: Mapping[str, Any] | None,
    requirement: SemanticProfileRequirement,
) -> dict[str, Any]:
    explicit = _semantic_value(source_object, context, "lineage")
    portfolio_lineage = _mapping(portfolio_object.get("lineage"))
    if isinstance(explicit, Mapping):
        return {
            "state": explicit.get("state", "known"),
            "authoritative_source_ids": _string_list(
                explicit.get("authoritative_source_ids", [requirement.base_object_id])
            ),
            "upstream_asset_ids": _string_list(explicit.get("upstream_asset_ids", [])),
            "relational_operations": _string_list(
                explicit.get("relational_operations", [])
            ),
            "evidence_refs": _string_list(
                explicit.get("evidence_refs", requirement.evidence_refs)
            ),
        }
    if portfolio_lineage:
        return {
            "state": "known",
            "authoritative_source_ids": [requirement.base_object_id],
            "upstream_asset_ids": _string_list(
                portfolio_lineage.get("consumer_object_ids", [])
            ),
            "relational_operations": [],
            "evidence_refs": sorted(requirement.evidence_refs),
        }
    return {
        "state": "unknown",
        "authoritative_source_ids": [requirement.base_object_id],
        "upstream_asset_ids": [],
        "relational_operations": [],
        "evidence_refs": sorted(requirement.evidence_refs),
    }


def _aggregation_stage(value: Any) -> str | None:
    aliases = {"preaggregate": "pre_aggregate", "postaggregate": "post_aggregate"}
    if not isinstance(value, str):
        return None
    normalized = value.lower().replace("-", "_").replace(" ", "_")
    normalized = aliases.get(normalized, normalized)
    return normalized if normalized in {
        "row",
        "pre_aggregate",
        "aggregate",
        "post_aggregate",
        "window",
        "fixed_lod",
        "unknown",
        "not_applicable",
    } else None


def _profile_aggregation(
    source_type: str,
    source_object: DomoObject,
    context: Mapping[str, Any] | None,
) -> dict[str, Any]:
    explicit = _semantic_value(source_object, context, "aggregation")
    if isinstance(explicit, Mapping):
        return {
            "state": explicit.get("state", "known"),
            "stage": explicit.get("stage", "unknown"),
            "grouping_fields": _string_list(explicit.get("grouping_fields", [])),
            "distinct_mode": explicit.get("distinct_mode", "unknown"),
            "partition_fields": _string_list(explicit.get("partition_fields", [])),
            "order_fields": _string_list(explicit.get("order_fields", [])),
            "window_frame": explicit.get("window_frame"),
            "null_semantics": explicit.get("null_semantics"),
        }
    definition = _definition_mapping(source_object)
    stage = _aggregation_stage(definition.get("calculation_stage"))
    if stage is None and isinstance(definition.get("beast_mode"), Mapping):
        stage = _aggregation_stage(definition["beast_mode"].get("calculation_stage"))
    if stage is not None and stage not in {"unknown", "not_applicable"}:
        return {
            "state": "known",
            "stage": stage,
            "grouping_fields": _string_list(definition.get("grouping_fields", [])),
            "distinct_mode": definition.get("distinct_mode", "none"),
            "partition_fields": _string_list(definition.get("partition_fields", [])),
            "order_fields": _string_list(definition.get("order_fields", [])),
            "window_frame": definition.get("window_frame"),
            "null_semantics": definition.get("null_semantics"),
        }
    if source_type == "pdp_policy":
        return {
            "state": "not_applicable",
            "stage": "not_applicable",
            "grouping_fields": [],
            "distinct_mode": "none",
            "partition_fields": [],
            "order_fields": [],
            "window_frame": None,
            "null_semantics": None,
        }
    return {
        "state": "unknown",
        "stage": "unknown",
        "grouping_fields": [],
        "distinct_mode": "unknown",
        "partition_fields": [],
        "order_fields": [],
        "window_frame": None,
        "null_semantics": None,
    }


def _predicates(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return sorted(
        {
            item if isinstance(item, str) else canonical_json(item)
            for item in value
            if isinstance(item, (str, Mapping))
        }
    )


def _profile_filters(
    source_type: str,
    source_object: DomoObject,
    context: Mapping[str, Any] | None,
    requirement: SemanticProfileRequirement,
) -> dict[str, Any]:
    explicit = _semantic_value(source_object, context, "filters")
    if isinstance(explicit, Mapping):
        return {
            "state": explicit.get("state", "known"),
            "stage": explicit.get("stage", "unknown"),
            "scope": explicit.get("scope", "unknown"),
            "precedence": _string_list(explicit.get("precedence", [])),
            "predicates": _predicates(explicit.get("predicates", [])),
            "evidence_refs": _string_list(
                explicit.get("evidence_refs", requirement.evidence_refs)
            ),
        }
    definition = _definition_mapping(source_object)
    definition_filters = definition.get("filters")
    if isinstance(definition_filters, list):
        stage = "dashboard" if source_type in {"page", "subpage", "card"} else "row"
        scope = "card" if source_type == "card" else "global" if source_type in {"page", "subpage"} else "dataset"
        return {
            "state": "known",
            "stage": stage,
            "scope": scope,
            "precedence": [],
            "predicates": _predicates(definition_filters),
            "evidence_refs": sorted(requirement.evidence_refs),
        }
    if source_type in {"beast_mode", "variable", "pdp_policy"} and requirement.context_id == "base":
        return {
            "state": "not_applicable",
            "stage": "not_applicable",
            "scope": "not_applicable",
            "precedence": [],
            "predicates": [],
            "evidence_refs": sorted(requirement.evidence_refs),
        }
    return {
        "state": "unknown",
        "stage": "unknown",
        "scope": "unknown",
        "precedence": [],
        "predicates": [],
        "evidence_refs": sorted(requirement.evidence_refs),
    }


def _profile_joins(
    source_object: DomoObject,
    context: Mapping[str, Any] | None,
) -> list[dict[str, Any]]:
    explicit = _semantic_value(source_object, context, "joins")
    if not isinstance(explicit, list):
        return []
    return [deepcopy(dict(item)) for item in explicit if isinstance(item, Mapping)]


def _profile_time(
    source_type: str,
    source_object: DomoObject,
    context: Mapping[str, Any] | None,
) -> dict[str, Any]:
    explicit = _semantic_value(source_object, context, "time")
    if isinstance(explicit, Mapping):
        return {
            "state": explicit.get("state", "known"),
            "timezone": explicit.get("timezone"),
            "fiscal_calendar_ref": explicit.get("fiscal_calendar_ref"),
            "date_boundary_semantics": explicit.get("date_boundary_semantics"),
            "late_arriving_behavior": explicit.get("late_arriving_behavior"),
        }
    if source_type in {"beast_mode", "variable", "pdp_policy"}:
        return {
            "state": "not_applicable",
            "timezone": None,
            "fiscal_calendar_ref": None,
            "date_boundary_semantics": None,
            "late_arriving_behavior": None,
        }
    return {
        "state": "unknown",
        "timezone": None,
        "fiscal_calendar_ref": None,
        "date_boundary_semantics": None,
        "late_arriving_behavior": None,
    }


def _profile_security(
    source_type: str,
    source_object: DomoObject,
    context: Mapping[str, Any] | None,
    requirement: SemanticProfileRequirement,
) -> dict[str, Any]:
    explicit = _semantic_value(source_object, context, "security")
    if isinstance(explicit, Mapping):
        return {
            "state": explicit.get("state", "known"),
            "security_domain": explicit.get("security_domain"),
            "pdp_policy_refs": _string_list(explicit.get("pdp_policy_refs", [])),
            "masking_policy_refs": _string_list(
                explicit.get("masking_policy_refs", [])
            ),
            "principal_precedence": _string_list(
                explicit.get("principal_precedence", [])
            ),
            "derived_field_exposure": explicit.get("derived_field_exposure", "unknown"),
            "evidence_refs": _string_list(
                explicit.get("evidence_refs", requirement.evidence_refs)
            ),
        }
    definition = _definition_mapping(source_object)
    if source_type == "pdp_policy":
        derived = _mapping(definition.get("derived_sensitive_field"))
        return {
            "state": "known",
            "security_domain": definition.get("policy_id"),
            "pdp_policy_refs": sorted(requirement.evidence_refs),
            "masking_policy_refs": [],
            "principal_precedence": _string_list(
                definition.get("principal_precedence", [])
            ),
            "derived_field_exposure": (
                "leakage_risk" if derived.get("must_not_leak") is True else "unknown"
            ),
            "evidence_refs": sorted(requirement.evidence_refs),
        }
    return {
        "state": "unknown",
        "security_domain": None,
        "pdp_policy_refs": [],
        "masking_policy_refs": [],
        "principal_precedence": [],
        "derived_field_exposure": "unknown",
        "evidence_refs": sorted(requirement.evidence_refs),
    }


def _profile_operations(
    source_type: str,
    portfolio_object: Mapping[str, Any],
    source_object: DomoObject,
    context: Mapping[str, Any] | None,
) -> dict[str, Any]:
    explicit = _semantic_value(source_object, context, "operations")
    owners = _string_list(portfolio_object.get("owner_refs", []))
    if isinstance(explicit, Mapping):
        return {
            "state": explicit.get("state", "known"),
            "update_mode": explicit.get("update_mode", "unknown"),
            "watermark_field": explicit.get("watermark_field"),
            "freshness_sla": explicit.get("freshness_sla"),
            "history_behavior": explicit.get("history_behavior"),
            "backfill_behavior": explicit.get("backfill_behavior"),
            "owner_refs": _string_list(explicit.get("owner_refs", owners)),
            "sla_ref": explicit.get("sla_ref"),
        }
    definition = _definition_mapping(source_object)
    if source_type in {"page", "subpage", "card", "beast_mode", "variable", "pdp_policy"} and owners:
        return {
            "state": "known",
            "update_mode": "view",
            "watermark_field": None,
            "freshness_sla": definition.get("freshness_sla"),
            "history_behavior": None,
            "backfill_behavior": None,
            "owner_refs": owners,
            "sla_ref": definition.get("sla_ref"),
        }
    return {
        "state": "unknown",
        "update_mode": definition.get("update_mode", "unknown"),
        "watermark_field": definition.get("watermark_field"),
        "freshness_sla": definition.get("freshness_sla"),
        "history_behavior": definition.get("history_behavior"),
        "backfill_behavior": definition.get("backfill_behavior"),
        "owner_refs": owners,
        "sla_ref": definition.get("sla_ref"),
    }


def _profile_consumers(
    portfolio_object: Mapping[str, Any],
    source_object: DomoObject,
    context: Mapping[str, Any] | None,
    requirement: SemanticProfileRequirement,
) -> list[str]:
    explicit = _semantic_value(source_object, context, "consumers")
    lineage = _mapping(portfolio_object.get("lineage"))
    definition = _definition_mapping(source_object)
    values = {
        *_string_list(explicit),
        *_string_list(lineage.get("producer_object_ids", [])),
    }
    consumer_ref = definition.get("consumer_ref")
    if isinstance(consumer_ref, str) and consumer_ref:
        values.add(consumer_ref)
    if requirement.consumer_object_id is not None:
        values.add(requirement.consumer_object_id)
    return sorted(values)


def _profile_side_effects(
    source_object: DomoObject,
    context: Mapping[str, Any] | None,
) -> list[dict[str, Any]]:
    explicit = _semantic_value(source_object, context, "side_effects")
    if not isinstance(explicit, list):
        return []
    return [deepcopy(dict(item)) for item in explicit if isinstance(item, Mapping)]


def _dimension_blockers(profile: Mapping[str, Any]) -> list[str]:
    blockers: list[str] = []
    for dimension in ("grain", "lineage", "aggregation", "filters", "time", "security", "operations"):
        state = _mapping(profile.get(dimension)).get("state")
        if state in {"unknown", "conflict"}:
            blockers.append(f"{dimension}:{state}")
    if not _mapping(profile.get("operations")).get("owner_refs"):
        blockers.append("operations:accountable_owner_missing")
    for effect in profile.get("side_effects", []):
        if isinstance(effect, Mapping) and not effect.get("handoff_ref"):
            blockers.append("side_effects:external_handoff_missing")
    return blockers


def build_domo_semantic_profile(
    portfolio_object: Mapping[str, Any],
    source_object: DomoObject,
    requirement: Mapping[str, Any] | SemanticProfileRequirement,
    *,
    run_id: str,
    scope_id: str,
) -> SemanticProfile:
    """Build one immutable Domo profile from an exact inventory requirement.

    Integrity mismatches are rejected. Missing semantic evidence is represented
    by a blocked profile so the accelerator never invents readiness.
    """

    requirement_model = (
        requirement
        if isinstance(requirement, SemanticProfileRequirement)
        else SemanticProfileRequirement.model_validate(requirement)
    )
    if requirement_model.requirement_hash != semantic_profile_requirement_hash(
        requirement_model
    ):
        raise ValueError("requirement_hash does not match semantic profile requirement")
    if requirement_model.requirement_id != _requirement_id(requirement_model):
        raise ValueError("requirement_id is not deterministic for its context")

    raw_members = portfolio_object.get("semantic_profile_requirements")
    if not isinstance(raw_members, list):
        raise ValueError("portfolio object has no semantic_profile_requirements denominator")
    member_matches = [
        item
        for item in raw_members
        if isinstance(item, Mapping)
        and item.get("requirement_id") == requirement_model.requirement_id
    ]
    if len(member_matches) != 1:
        raise ValueError("semantic profile requirement is not a unique portfolio member")
    member = SemanticProfileRequirement.model_validate(member_matches[0])
    if member != requirement_model:
        raise ValueError("semantic profile requirement differs from the portfolio member")

    identity = _mapping(portfolio_object.get("identity"))
    source_type = _normalized_domo_type(source_object.object_type)
    if identity.get("object_type") != source_type:
        raise ValueError("Domo object type does not match portfolio identity")
    if identity.get("native_id") != source_object.object_id:
        raise ValueError("Domo native ID does not match portfolio identity")
    if identity.get("object_id") != requirement_model.base_object_id:
        raise ValueError("base_object_id does not match portfolio identity")
    expected_kind = _PROFILE_KIND_BY_DOMO_TYPE.get(source_type)
    if expected_kind is None or requirement_model.profile_kind != expected_kind:
        raise ValueError("profile_kind does not match the Domo object type")

    portfolio_definition = _mapping(portfolio_object.get("definition"))
    if portfolio_definition.get("content_ref") != requirement_model.definition_ref:
        raise ValueError("definition_ref does not match portfolio evidence")
    if (
        portfolio_definition.get("content_hash") is not None
        and portfolio_definition.get("content_hash")
        != requirement_model.source_revision_hash
    ):
        raise ValueError("source_revision_hash does not match portfolio evidence")
    if (
        source_object.content_hash is not None
        and source_object.content_hash != requirement_model.source_revision_hash
    ):
        raise ValueError("source_revision_hash does not match the Domo object")

    original = _original_definition(source_type, source_object)
    evidence_blockers: list[str] = []
    if original is _MISSING:
        original = None
        evidence_blockers.append("definition:source_definition_missing")
    elif requirement_model.definition_hash != _sha256(original):
        raise ValueError("definition_hash does not match the captured Domo definition")
    if source_object.content_hash is None:
        evidence_blockers.append("source_revision:content_hash_missing")
    if source_object.definition_state != "definition_complete":
        evidence_blockers.append(
            f"definition:evidence_state:{source_object.definition_state}"
        )
    if portfolio_definition.get("state") != "extracted_complete":
        evidence_blockers.append(
            f"definition:portfolio_state:{portfolio_definition.get('state', 'missing')}"
        )

    context, context_blockers = _context_descriptor(source_object, requirement_model)
    evidence_blockers.extend(context_blockers)
    if (
        context is not None
        and context.get("consumer_object_key") is not None
        and requirement_model.consumer_object_id is not None
        and requirement_model.consumer_object_id
        not in _string_list(
            _mapping(portfolio_object.get("lineage")).get("producer_object_ids", [])
        )
    ):
        raise ValueError(
            "context consumer does not match the portfolio consumer lineage"
        )
    if requirement_model.context_ref not in requirement_model.evidence_refs:
        evidence_blockers.append("context:reference_not_bound_to_requirement_evidence")

    language, default_dialect, runtime = _definition_language(source_type)
    definition_source = _definition_mapping(source_object)
    dialect_value = definition_source.get("dialect", default_dialect)
    dialect = str(dialect_value) if dialect_value is not None else None
    evidence_refs = sorted(
        {
            *requirement_model.evidence_refs,
            *source_object.source_refs,
            requirement_model.definition_ref,
            requirement_model.context_ref,
        }
    )
    draft: dict[str, Any] = {
        "contract_version": "domo-to-omni.semantic-profile.v1",
        "profile_id": (
            "profile.domo."
            + sha256_json(
                {
                    "run_id": run_id,
                    "scope_id": scope_id,
                    "requirement_id": requirement_model.requirement_id,
                    "requirement_hash": requirement_model.requirement_hash,
                }
            )[:24]
        ),
        "run_id": run_id,
        "scope_id": scope_id,
        "identity": {
            "system": "domo",
            "kind": requirement_model.profile_kind,
            "object_id": _profile_object_id(requirement_model),
            "revision_hash": requirement_model.requirement_hash,
        },
        "status": "blocked",
        "definition": {
            "state": (
                "complete"
                if original is not None
                and source_object.definition_state == "definition_complete"
                and portfolio_definition.get("state") == "extracted_complete"
                else "unknown" if original is None else "partial"
            ),
            "language": language,
            "dialect": dialect,
            "runtime": runtime,
            "original_definition": original,
            "original_ref": requirement_model.definition_ref,
            "original_hash": requirement_model.definition_hash,
            "canonicalizer_version": "",
            "canonical_state": "unknown",
            "canonical_form": None,
            "canonical_hash": None,
            "translation_refs": [],
            "unsupported_reason": "pending",
        },
        "grain": _profile_grain(source_type, source_object, context),
        "lineage": _profile_lineage(
            portfolio_object, source_object, context, requirement_model
        ),
        "aggregation": _profile_aggregation(source_type, source_object, context),
        "filters": _profile_filters(
            source_type, source_object, context, requirement_model
        ),
        "joins": _profile_joins(source_object, context),
        "time": _profile_time(source_type, source_object, context),
        "security": _profile_security(
            source_type, source_object, context, requirement_model
        ),
        "operations": _profile_operations(
            source_type, portfolio_object, source_object, context
        ),
        "consumers": _profile_consumers(
            portfolio_object, source_object, context, requirement_model
        ),
        "side_effects": _profile_side_effects(source_object, context),
        "unknowns": [],
        "blockers": [],
        "evidence_refs": evidence_refs,
        "dimension_hashes": {},
        "profile_hash": "sha256:" + "0" * 64,
        "immutable": True,
        "provenance": {
            "producer_ref": (
                "agent-ref://domo-bi-developer"
                if requirement_model.profile_kind == "dashboard_query"
                else "agent-ref://domo-analytics-engineer"
            ),
            "builder_version": DOMO_PROFILE_BUILDER_VERSION,
            "source_system": "domo",
            "source_object_type": source_type,
            "source_native_id": source_object.object_id,
            "source_revision_hash": requirement_model.source_revision_hash,
            "semantic_profile_requirement_id": requirement_model.requirement_id,
            "semantic_profile_requirement_hash": requirement_model.requirement_hash,
            "base_object_id": requirement_model.base_object_id,
            "context_id": requirement_model.context_id,
            "context_ref": requirement_model.context_ref,
            "context_hash": requirement_model.context_hash,
            "consumer_object_id": requirement_model.consumer_object_id,
        },
        "security_metadata": deepcopy(
            dict(_mapping(portfolio_object.get("security")))
        ),
    }
    blockers = sorted(set(evidence_blockers + _dimension_blockers(draft)))
    draft["blockers"] = blockers
    draft["unknowns"] = list(blockers)
    draft["status"] = "blocked" if blockers else "ready"
    return finalize_semantic_profile(draft)


def _repository_subject(
    inventory: RepositoryInventory,
    value: Mapping[str, Any] | ResourceRecord | SemanticAssetRecord,
) -> tuple[ResourceRecord | SemanticAssetRecord, str]:
    if isinstance(value, ResourceRecord):
        supplied: ResourceRecord | SemanticAssetRecord = value
        subject_kind = "resource"
    elif isinstance(value, SemanticAssetRecord):
        supplied = value
        subject_kind = "semantic_asset"
    elif "unique_id" in value:
        supplied = ResourceRecord.model_validate(value)
        subject_kind = "resource"
    elif "asset_id" in value:
        supplied = SemanticAssetRecord.model_validate(value)
        subject_kind = "semantic_asset"
    else:
        raise ValueError("repository semantic subject must be a resource or semantic asset")

    members: Sequence[ResourceRecord | SemanticAssetRecord]
    subject_id: str
    if subject_kind == "resource":
        members = inventory.resources
        subject_id = supplied.unique_id  # type: ignore[union-attr]
    else:
        members = inventory.semantic_assets
        subject_id = supplied.asset_id  # type: ignore[union-attr]
    matches = [
        item
        for item in members
        if (
            item.unique_id if isinstance(item, ResourceRecord) else item.asset_id
        )
        == subject_id
    ]
    if len(matches) != 1:
        raise ValueError("repository semantic subject is not a unique inventory member")
    if matches[0] != supplied:
        raise ValueError("repository semantic subject differs from the inventory member")
    return supplied, subject_kind


def _repository_owner_ref(owner: str | None) -> list[str]:
    if owner is None or not owner.strip():
        return []
    return [f"owner-ref://dbt/{sha256_json(owner)[:20]}"]


def _explicit_grain(
    dimensions: Mapping[str, Any],
    inventory: RepositoryInventory,
    subject: ResourceRecord | SemanticAssetRecord,
) -> dict[str, Any]:
    explicit = dimensions.get("grain")
    if isinstance(explicit, Mapping):
        return {
            "state": explicit.get("state", "known"),
            "description": explicit.get("description"),
            "key_fields": _string_list(explicit.get("key_fields", [])),
            "row_universe": explicit.get("row_universe"),
            "uniqueness_evidence_refs": _string_list(
                explicit.get("uniqueness_evidence_refs", [])
            ),
        }
    if isinstance(subject, ResourceRecord):
        primary_keys = sorted(
            {
                column
                for constraint in inventory.constraints
                if constraint.resource_unique_id == subject.unique_id
                and constraint.constraint_type in {"primary_key", "unique"}
                for column in (
                    constraint.columns
                    or ([constraint.column_name] if constraint.column_name else [])
                )
            }
        )
        if primary_keys:
            return {
                "state": "known",
                "description": f"declared key columns: {', '.join(primary_keys)}",
                "key_fields": primary_keys,
                "row_universe": subject.compiled_relation_name or subject.relation_name,
                "uniqueness_evidence_refs": [
                    f"repository-constraint-ref://{constraint.constraint_id}"
                    for constraint in inventory.constraints
                    if constraint.resource_unique_id == subject.unique_id
                    and constraint.constraint_type in {"primary_key", "unique"}
                ],
            }
        if subject.resource_type == "macro":
            return {
                "state": "not_applicable",
                "description": None,
                "key_fields": [],
                "row_universe": None,
                "uniqueness_evidence_refs": [],
            }
    return {
        "state": "unknown",
        "description": None,
        "key_fields": [],
        "row_universe": None,
        "uniqueness_evidence_refs": [],
    }


def _explicit_aggregation(
    dimensions: Mapping[str, Any],
    subject: ResourceRecord | SemanticAssetRecord,
) -> dict[str, Any]:
    explicit = dimensions.get("aggregation")
    if isinstance(explicit, Mapping):
        return {
            "state": explicit.get("state", "known"),
            "stage": explicit.get("stage", "unknown"),
            "grouping_fields": _string_list(explicit.get("grouping_fields", [])),
            "distinct_mode": explicit.get("distinct_mode", "unknown"),
            "partition_fields": _string_list(explicit.get("partition_fields", [])),
            "order_fields": _string_list(explicit.get("order_fields", [])),
            "window_frame": explicit.get("window_frame"),
            "null_semantics": explicit.get("null_semantics"),
        }
    if isinstance(subject, ResourceRecord) and subject.resource_type in {"source", "seed"}:
        return {
            "state": "not_applicable",
            "stage": "not_applicable",
            "grouping_fields": [],
            "distinct_mode": "none",
            "partition_fields": [],
            "order_fields": [],
            "window_frame": None,
            "null_semantics": None,
        }
    return {
        "state": "unknown",
        "stage": "unknown",
        "grouping_fields": [],
        "distinct_mode": "unknown",
        "partition_fields": [],
        "order_fields": [],
        "window_frame": None,
        "null_semantics": None,
    }


def _explicit_filters(
    dimensions: Mapping[str, Any],
    subject: ResourceRecord | SemanticAssetRecord,
    evidence_refs: Sequence[str],
) -> dict[str, Any]:
    explicit = dimensions.get("filters")
    if isinstance(explicit, Mapping):
        return {
            "state": explicit.get("state", "known"),
            "stage": explicit.get("stage", "unknown"),
            "scope": explicit.get("scope", "unknown"),
            "precedence": _string_list(explicit.get("precedence", [])),
            "predicates": _predicates(explicit.get("predicates", [])),
            "evidence_refs": _string_list(
                explicit.get("evidence_refs", evidence_refs)
            ),
        }
    if isinstance(subject, ResourceRecord) and subject.resource_type in {"source", "seed"}:
        return {
            "state": "not_applicable",
            "stage": "not_applicable",
            "scope": "not_applicable",
            "precedence": [],
            "predicates": [],
            "evidence_refs": sorted(evidence_refs),
        }
    return {
        "state": "unknown",
        "stage": "unknown",
        "scope": "unknown",
        "precedence": [],
        "predicates": [],
        "evidence_refs": sorted(evidence_refs),
    }


def _explicit_time(dimensions: Mapping[str, Any]) -> dict[str, Any]:
    explicit = dimensions.get("time")
    if isinstance(explicit, Mapping):
        return {
            "state": explicit.get("state", "known"),
            "timezone": explicit.get("timezone"),
            "fiscal_calendar_ref": explicit.get("fiscal_calendar_ref"),
            "date_boundary_semantics": explicit.get("date_boundary_semantics"),
            "late_arriving_behavior": explicit.get("late_arriving_behavior"),
        }
    return {
        "state": "unknown",
        "timezone": None,
        "fiscal_calendar_ref": None,
        "date_boundary_semantics": None,
        "late_arriving_behavior": None,
    }


def _explicit_security(
    dimensions: Mapping[str, Any], evidence_refs: Sequence[str]
) -> dict[str, Any]:
    explicit = dimensions.get("security")
    if isinstance(explicit, Mapping):
        return {
            "state": explicit.get("state", "known"),
            "security_domain": explicit.get("security_domain"),
            "pdp_policy_refs": _string_list(explicit.get("pdp_policy_refs", [])),
            "masking_policy_refs": _string_list(
                explicit.get("masking_policy_refs", [])
            ),
            "principal_precedence": _string_list(
                explicit.get("principal_precedence", [])
            ),
            "derived_field_exposure": explicit.get("derived_field_exposure", "unknown"),
            "evidence_refs": _string_list(
                explicit.get("evidence_refs", evidence_refs)
            ),
        }
    return {
        "state": "unknown",
        "security_domain": None,
        "pdp_policy_refs": [],
        "masking_policy_refs": [],
        "principal_precedence": [],
        "derived_field_exposure": "unknown",
        "evidence_refs": sorted(evidence_refs),
    }


def _explicit_operations(
    dimensions: Mapping[str, Any],
    subject: ResourceRecord | SemanticAssetRecord,
) -> dict[str, Any]:
    explicit = dimensions.get("operations")
    owner = subject.owner
    owners = _repository_owner_ref(owner)
    if isinstance(explicit, Mapping):
        return {
            "state": explicit.get("state", "known"),
            "update_mode": explicit.get("update_mode", "unknown"),
            "watermark_field": explicit.get("watermark_field"),
            "freshness_sla": explicit.get("freshness_sla"),
            "history_behavior": explicit.get("history_behavior"),
            "backfill_behavior": explicit.get("backfill_behavior"),
            "owner_refs": _string_list(explicit.get("owner_refs", owners)),
            "sla_ref": explicit.get("sla_ref"),
        }
    update_mode = "unknown"
    if isinstance(subject, SemanticAssetRecord):
        update_mode = "view"
    elif subject.materialization in {"view", "materialized_view", "ephemeral"}:
        update_mode = "view"
    elif subject.materialization == "table":
        update_mode = "replace"
    return {
        "state": "known" if update_mode != "unknown" and owners else "unknown",
        "update_mode": update_mode,
        "watermark_field": None,
        "freshness_sla": None,
        "history_behavior": None,
        "backfill_behavior": None,
        "owner_refs": owners,
        "sla_ref": None,
    }


def _repository_lineage(
    inventory: RepositoryInventory,
    subject: ResourceRecord | SemanticAssetRecord,
    evidence_refs: Sequence[str],
) -> dict[str, Any]:
    if isinstance(subject, ResourceRecord):
        upstream = subject.depends_on_unique_ids
        operations = [subject.materialization] if subject.materialization else []
        subject_id = subject.unique_id
    else:
        upstream = sorted(
            {*subject.related_resource_unique_ids, *subject.depends_on_asset_ids}
        )
        operations = [subject.asset_type]
        subject_id = subject.asset_id
    return {
        "state": "known",
        "authoritative_source_ids": [subject_id],
        "upstream_asset_ids": sorted(upstream),
        "relational_operations": sorted(operations),
        "evidence_refs": sorted(evidence_refs),
    }


def _repository_consumers(
    inventory: RepositoryInventory,
    subject: ResourceRecord | SemanticAssetRecord,
    dimensions: Mapping[str, Any],
) -> list[str]:
    explicit = _string_list(dimensions.get("consumers", []))
    if isinstance(subject, ResourceRecord):
        subject_id = subject.unique_id
        derived = {
            *subject.exposure_unique_ids,
            *(
                edge.to_unique_id
                for edge in inventory.lineage_edges
                if edge.from_unique_id == subject_id
            ),
            *(
                asset.asset_id
                for asset in inventory.semantic_assets
                if subject_id in asset.related_resource_unique_ids
            ),
        }
    else:
        subject_id = subject.asset_id
        derived = {
            asset.asset_id
            for asset in inventory.semantic_assets
            if subject_id in asset.depends_on_asset_ids
        }
    return sorted({*explicit, *derived})


def _repository_file_binding(
    inventory: RepositoryInventory,
    subject: ResourceRecord | SemanticAssetRecord,
    evidence: RepositoryDefinitionEvidence,
) -> tuple[bool, list[str]]:
    blockers: list[str] = []
    if isinstance(subject, ResourceRecord):
        expected_path = subject.original_file_path
        expected_hash = subject.source_file_hash
        files = [
            item
            for item in inventory.source_files
            if expected_path is not None and item.relative_path == expected_path
        ]
    else:
        semantic_artifacts = [
            item
            for item in inventory.artifact_files
            if item.artifact_type == "semantic_manifest"
        ]
        if len(semantic_artifacts) > 1:
            raise ValueError("repository inventory has duplicate semantic manifests")
        expected_path = (
            semantic_artifacts[0].relative_path if semantic_artifacts else None
        )
        expected_hash = semantic_artifacts[0].content_hash if semantic_artifacts else None
        files = semantic_artifacts

    if evidence.relative_path is not None and evidence.relative_path != expected_path:
        raise ValueError("definition evidence path does not match repository inventory")
    if evidence.source_file_hash is not None and evidence.source_file_hash != expected_hash:
        raise ValueError("source_file_hash does not match repository inventory")
    if expected_path is None or evidence.relative_path is None:
        blockers.append("repository_definition:path_missing")
    if expected_hash is None or evidence.source_file_hash is None:
        blockers.append("repository_definition:source_file_hash_missing")
    if expected_path is not None and expected_hash is not None:
        if len(files) != 1:
            blockers.append("repository_definition:source_file_record_missing")
        elif files[0].content_hash != expected_hash:
            raise ValueError("repository member source hash differs from its file record")
    return not blockers, blockers


def build_dbt_semantic_profile(
    repository_inventory: Mapping[str, Any] | RepositoryInventory,
    resource_or_semantic_asset: (
        Mapping[str, Any] | ResourceRecord | SemanticAssetRecord
    ),
    source_definition_evidence: (
        Mapping[str, Any] | RepositoryDefinitionEvidence
    ),
    *,
    run_id: str,
    scope_id: str,
) -> SemanticProfile:
    """Build an immutable dbt profile bound to a pinned repository inventory."""

    inventory = (
        repository_inventory
        if isinstance(repository_inventory, RepositoryInventory)
        else RepositoryInventory.model_validate(repository_inventory)
    )
    if run_id != inventory.run_id:
        raise ValueError("profile run_id does not match repository inventory")
    subject, subject_kind = _repository_subject(
        inventory, resource_or_semantic_asset
    )
    evidence = (
        source_definition_evidence
        if isinstance(source_definition_evidence, RepositoryDefinitionEvidence)
        else RepositoryDefinitionEvidence.model_validate(source_definition_evidence)
    )
    if evidence.evidence_hash != repository_definition_evidence_hash(evidence):
        raise ValueError("repository definition evidence_hash is stale")

    subject_id = (
        subject.unique_id if isinstance(subject, ResourceRecord) else subject.asset_id
    )
    revision_hash = (
        subject.resource_hash
        if isinstance(subject, ResourceRecord)
        else subject.definition_hash
    )
    if evidence.subject_id != subject_id:
        raise ValueError("definition evidence subject does not match repository member")
    if evidence.repository_ref != inventory.repository.repository_ref:
        raise ValueError("definition evidence repository_ref does not match inventory")
    if evidence.commit_sha != inventory.repository.commit_sha:
        raise ValueError("definition evidence commit_sha does not match inventory")
    if evidence.inventory_hash != inventory.inventory_hash:
        raise ValueError("definition evidence inventory_hash does not match inventory")

    file_binding_complete, blockers = _repository_file_binding(
        inventory, subject, evidence
    )
    if isinstance(subject, ResourceRecord):
        if evidence.definition_kind == "semantic_asset":
            raise ValueError("resource definition evidence cannot use semantic_asset kind")
        expected_definition_hash = (
            subject.compiled_code_hash
            if evidence.definition_kind == "compiled"
            else subject.definition_hash
        )
        if evidence.definition_kind == "compiled" and evidence.language not in {
            "sql",
            "query",
        }:
            raise ValueError("compiled dbt definitions must use SQL/query language")
        if (
            subject.original_file_path is not None
            and subject.original_file_path.endswith(".sql")
            and evidence.definition is not None
            and evidence.language not in {"sql", "query"}
        ):
            raise ValueError("dbt SQL resources require SQL/query definition evidence")
    else:
        if evidence.definition_kind != "semantic_asset":
            raise ValueError("semantic assets require semantic_asset definition evidence")
        if evidence.language != "workflow":
            raise ValueError("semantic asset definitions require structured workflow language")
        expected_definition_hash = subject.definition_hash

    verified_definition: Any = None
    if evidence.definition is None or evidence.definition_hash is None:
        blockers.append("repository_definition:definition_missing")
    elif expected_definition_hash is None:
        blockers.append("repository_definition:inventory_definition_hash_missing")
    elif evidence.definition_hash != expected_definition_hash:
        raise ValueError("definition_hash does not match repository inventory")
    else:
        verified_definition = evidence.definition
    if evidence.definition_ref not in evidence.evidence_refs:
        blockers.append("repository_definition:reference_not_bound_to_evidence")

    dimensions = _mapping(evidence.semantic_dimensions)
    evidence_refs = sorted(
        {
            *evidence.evidence_refs,
            evidence.definition_ref,
            inventory.repository.identity_evidence_ref,
            *inventory.provenance.source_artifact_refs,
        }
    )
    grain = _explicit_grain(dimensions, inventory, subject)
    aggregation = _explicit_aggregation(dimensions, subject)
    filters = _explicit_filters(dimensions, subject, evidence_refs)
    joins_value = dimensions.get("joins")
    joins = (
        [deepcopy(dict(item)) for item in joins_value if isinstance(item, Mapping)]
        if isinstance(joins_value, list)
        else []
    )
    time = _explicit_time(dimensions)
    security = _explicit_security(dimensions, evidence_refs)
    operations = _explicit_operations(dimensions, subject)
    side_effects_value = dimensions.get("side_effects")
    side_effects = (
        [
            deepcopy(dict(item))
            for item in side_effects_value
            if isinstance(item, Mapping)
        ]
        if isinstance(side_effects_value, list)
        else []
    )
    draft: dict[str, Any] = {
        "contract_version": "domo-to-omni.semantic-profile.v1",
        "profile_id": (
            "profile.dbt."
            + sha256_json(
                {
                    "run_id": run_id,
                    "scope_id": scope_id,
                    "inventory_hash": inventory.inventory_hash,
                    "subject_id": subject_id,
                    "revision_hash": revision_hash,
                    "evidence_hash": evidence.evidence_hash,
                }
            )[:24]
        ),
        "run_id": run_id,
        "scope_id": scope_id,
        "identity": {
            "system": "dbt",
            "kind": "dbt_resource",
            "object_id": subject_id,
            "revision_hash": revision_hash,
        },
        "status": "blocked",
        "definition": {
            "state": (
                "complete"
                if verified_definition is not None and file_binding_complete
                else "partial" if verified_definition is not None else "unknown"
            ),
            "language": evidence.language,
            "dialect": evidence.dialect,
            "runtime": f"dbt-{evidence.definition_kind}",
            "original_definition": verified_definition,
            "original_ref": evidence.definition_ref,
            "original_hash": evidence.definition_hash or _sha256(None),
            "canonicalizer_version": "",
            "canonical_state": "unknown",
            "canonical_form": None,
            "canonical_hash": None,
            "translation_refs": [],
            "unsupported_reason": "pending",
        },
        "grain": grain,
        "lineage": _repository_lineage(
            inventory, subject, evidence_refs
        ),
        "aggregation": aggregation,
        "filters": filters,
        "joins": joins,
        "time": time,
        "security": security,
        "operations": operations,
        "consumers": _repository_consumers(inventory, subject, dimensions),
        "side_effects": side_effects,
        "unknowns": [],
        "blockers": [],
        "evidence_refs": evidence_refs,
        "dimension_hashes": {},
        "profile_hash": "sha256:" + "0" * 64,
        "immutable": True,
        "provenance": {
            "producer_ref": "agent-ref://dbt-analytics-engineer",
            "builder_version": DBT_PROFILE_BUILDER_VERSION,
            "source_system": "dbt_repository",
            "repository_ref": inventory.repository.repository_ref,
            "git_ref": inventory.repository.git_ref,
            "commit_sha": inventory.repository.commit_sha,
            "repository_inventory_id": inventory.inventory_id,
            "repository_inventory_hash": inventory.inventory_hash,
            "subject_kind": subject_kind,
            "subject_id": subject_id,
            "subject_revision_hash": revision_hash,
            "relative_path": evidence.relative_path,
            "source_file_hash": evidence.source_file_hash,
            "repository_definition_hash": evidence.definition_hash,
            "repository_definition_evidence_hash": evidence.evidence_hash,
        },
        "security_metadata": inventory.security.model_dump(mode="json"),
    }
    blockers.extend(_dimension_blockers(draft))
    if joins_value is None and (
        (isinstance(subject, ResourceRecord) and subject.resource_type in {"model", "snapshot"})
        or (
            isinstance(subject, SemanticAssetRecord)
            and subject.asset_type == "semantic_model"
        )
    ):
        blockers.append("joins:unknown")
    blockers = sorted(set(blockers))
    draft["blockers"] = blockers
    draft["unknowns"] = list(blockers)
    draft["status"] = "blocked" if blockers else "ready"
    return finalize_semantic_profile(draft)


def semantic_dimension_hashes(profile: Mapping[str, Any]) -> dict[str, str]:
    return {dimension: _sha256(profile.get(dimension)) for dimension in DIMENSIONS}


def semantic_profile_hash(profile: Mapping[str, Any]) -> str:
    material = deepcopy(dict(profile))
    material.pop("profile_hash", None)
    return _sha256(material)


def finalize_semantic_profile(value: Mapping[str, Any]) -> SemanticProfile:
    """Canonicalize a draft and bind every semantic dimension to a hash."""

    result = deepcopy(dict(value))
    definition = result.setdefault("definition", {})
    original = definition.get("original_definition")
    if original is not None:
        definition["original_hash"] = _sha256(original)
    canonical = canonicalize_definition(
        original,
        language=str(definition.get("language", "unknown")),
        dialect=(str(definition["dialect"]) if definition.get("dialect") is not None else None),
    )
    definition["canonicalizer_version"] = canonical.version
    definition["canonical_state"] = canonical.state
    definition["canonical_form"] = canonical.form
    definition["canonical_hash"] = canonical.content_hash
    definition["unsupported_reason"] = canonical.reason

    blockers = list(result.get("blockers", []))
    unknowns = list(result.get("unknowns", []))
    if canonical.state == "unknown":
        reason = f"definition:{canonical.reason}"
        if reason not in blockers:
            blockers.append(reason)
        if reason not in unknowns:
            unknowns.append(reason)
        result["status"] = "blocked"
    result["blockers"] = sorted(set(blockers))
    result["unknowns"] = sorted(set(unknowns))
    result["dimension_hashes"] = semantic_dimension_hashes(result)
    result["profile_hash"] = semantic_profile_hash(result)
    return SemanticProfile.model_validate(result)


def validate_semantic_profile(value: Mapping[str, Any] | SemanticProfile) -> list[str]:
    """Recompute hashes and return staleness or readiness violations."""

    raw = value.model_dump(mode="json") if isinstance(value, SemanticProfile) else dict(value)
    errors: list[str] = []
    expected_dimensions = semantic_dimension_hashes(raw)
    if raw.get("dimension_hashes") != expected_dimensions:
        errors.append("dimension_hashes do not match semantic dimensions")
    if raw.get("profile_hash") != semantic_profile_hash(raw):
        errors.append("profile_hash does not match semantic profile content")
    definition = raw.get("definition", {})
    if isinstance(definition, Mapping):
        original = definition.get("original_definition")
        if original is not None and definition.get("original_hash") != _sha256(original):
            errors.append("original_hash does not match the preserved definition")
        canonical = canonicalize_definition(
            original,
            language=str(definition.get("language", "unknown")),
            dialect=(
                str(definition["dialect"])
                if definition.get("dialect") is not None
                else None
            ),
        )
        if definition.get("canonicalizer_version") != canonical.version:
            errors.append("canonicalizer_version is stale or unsupported")
        if definition.get("canonical_state") != canonical.state:
            errors.append("canonical_state does not match deterministic canonicalization")
        if definition.get("canonical_form") != canonical.form:
            errors.append("canonical_form does not match deterministic canonicalization")
        if definition.get("canonical_hash") != canonical.content_hash:
            errors.append("canonical_hash does not match deterministic canonicalization")
    try:
        SemanticProfile.model_validate(raw)
    except ValueError as exc:
        errors.append(f"semantic profile readiness is invalid: {exc}")
    return errors

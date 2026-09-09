"""Project normalized Domo evidence into the versioned root inventory contracts.

The extractor owns acquisition.  This module owns only deterministic contract
projection: no credentials, network calls, target connections, or source writes.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Iterable, Mapping, Sequence

from omni_migrator.control_plane.canonical import (
    canonical_json,
    parse_time,
    sha256_json,
    validate_run_id,
)
from omni_migrator.control_plane.contract_integrity import (
    dependency_edge_hash,
    inventory_contract_hash,
    source_object_fingerprint,
    source_object_metadata_hash,
    validate_inventory_contract_set,
)
from omni_migrator.control_plane.domo_inventory import (
    complete_catalog_authority_errors,
    exact_id_set_hash,
    exact_object_set_hash,
    inventory_observation_hash,
    portfolio_inventory_hash,
    portfolio_object_hash,
    semantic_profile_requirement_hash,
    validate_inventory_observation,
    validate_portfolio_inventory,
)
from omni_migrator.extractors.domo.models import DomoEvidenceBundle, DomoObject
from omni_migrator.semantic.profiles import (
    DOMO_PROFILE_BUILDER_VERSION,
    build_domo_semantic_profile,
)


_SOURCE_OBJECT_TYPES = frozenset(
    {
        "page",
        "subpage",
        "card",
        "dataset",
        "dataset_schema",
        "dataflow",
        "magic_etl",
        "sql_dataflow",
        "beast_mode",
        "variable",
        "pdp_policy",
        "schedule",
        "alert",
        "workflow",
        "app_studio_app",
        "custom_app",
        "domo_everywhere_embed",
        "workbench_job",
        "connector_account",
        "file_asset",
        "code_engine_package",
        "publication",
        "user",
        "group",
        "role",
        "other",
    }
)

_RELATIONSHIPS = {
    "contains": "contains",
    "queries": "powered_by",
    "query": "powered_by",
    "powered_by": "powered_by",
    "input_to": "input_to",
    "feeds": "input_to",
    "produced_by": "output_of",
    "output_of": "output_of",
    "uses_field": "uses_field",
    "uses_beast_mode": "uses_beast_mode",
    "uses_variable": "uses_variable",
    "secured_by": "secured_by",
    "scheduled_by": "scheduled_by",
    "alerts_on": "alerts_on",
    "embeds": "embeds",
    "drills_to": "drills_to",
    "triggers": "triggers",
    "invokes": "invokes",
    "owned_by": "owned_by",
    "derived_from": "derived_from",
}

_SEMANTIC_PROFILE_KINDS: dict[str, str] = {
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

_STATE_COLUMNS = {
    "extracted_complete": "complete",
    "extracted_partial": "partial",
    "metadata_only": "metadata_only",
    "manual_capture_required": "manual_required",
    "blocked": "blocked",
}

_CLASSIFICATION_RANK = {"public": 0, "internal": 1, "confidential": 2, "restricted": 3}
_REDACTION_RANK = {
    "not_required": 0,
    "redacted": 1,
    "tokenized": 2,
    "restricted_reference_only": 3,
    "pending": 4,
}


@dataclass(frozen=True)
class InventoryProjection:
    """One transactionally consistent set of root inventory documents."""

    source_object_graph: dict[str, Any]
    evidence_bundle: dict[str, Any]
    coverage_ledger: dict[str, Any]
    inventory_snapshot: dict[str, Any]
    inventory_observations: tuple[dict[str, Any], ...]
    portfolio_inventory: dict[str, Any]

    def as_documents(self) -> dict[str, dict[str, Any]]:
        """Return the legacy transactional root set for its four-way validator."""

        return {
            "source_object_graph": self.source_object_graph,
            "evidence_bundle": self.evidence_bundle,
            "coverage_ledger": self.coverage_ledger,
            "inventory_snapshot": self.inventory_snapshot,
        }

    def as_inventory_documents(self) -> dict[str, Any]:
        """Return every first-class acquisition and inventory contract."""

        return {
            **self.as_documents(),
            "domo_inventory_observations": [
                deepcopy(item) for item in self.inventory_observations
            ],
            "domo_portfolio_inventory": deepcopy(self.portfolio_inventory),
        }


def _utc_text(value: str | datetime) -> str:
    parsed = parse_time(value) if isinstance(value, str) else value
    return parsed.isoformat().replace("+00:00", "Z")


def _stable_slug(value: str, *, limit: int = 40) -> str:
    normalized = re.sub(r"[^a-z0-9._-]+", "-", value.lower()).strip("-._")
    return (normalized or "object")[:limit]


def _source_type(value: str) -> str:
    normalized = value.lower().replace("-", "_").replace(" ", "_")
    aliases = {
        "dashboard": "page",
        "magicetl": "magic_etl",
        "sql_data_flow": "sql_dataflow",
        "beastmode": "beast_mode",
        "pdp": "pdp_policy",
        "app": "custom_app",
        "everywhere": "domo_everywhere_embed",
        "connector": "connector_account",
    }
    normalized = aliases.get(normalized, normalized)
    return normalized if normalized in _SOURCE_OBJECT_TYPES else "other"


def _parse_object_key(key: str) -> tuple[str, str]:
    source_type, separator, native_id = key.partition(":")
    if not separator or not source_type or not native_id:
        return "other", key
    return source_type, native_id


def _stable_object_id(source_type: str, native_id: str) -> str:
    mapped_type = _source_type(source_type)
    digest = sha256_json({"object_type": source_type, "native_id": native_id})[:16]
    return f"domo.{mapped_type}.{_stable_slug(native_id)}.{digest}"


def _stable_id(prefix: str, material: Any) -> str:
    return f"{prefix}.{sha256_json(material)[:20]}"


def _artifact_ref(run_id: str, scope_id: str, name: str) -> str:
    return f"artifact-ref://{run_id}/{scope_id}/{name}"


def _evidence_ref(object_id: str) -> str:
    return f"evidence-ref://domo/{object_id}"


def _security(
    *,
    tenant_partition_id: str,
    classification: str,
    redaction_state: str,
    access_policy_ref: str,
    retention_policy_ref: str,
    egress_policy_ref: str,
    source_pdp_context_ref: str | None = None,
) -> dict[str, Any]:
    contains_sensitive_data = classification in {"confidential", "restricted"}
    value: dict[str, Any] = {
        "classification": classification,
        "contains_sensitive_data": contains_sensitive_data,
        "data_categories": ["customer_confidential"] if contains_sensitive_data else ["none"],
        "redaction_state": redaction_state,
        "tenant_partition_id": tenant_partition_id,
        "access_policy_ref": access_policy_ref,
        "retention_policy_ref": retention_policy_ref,
        "egress_policy_ref": egress_policy_ref,
    }
    if source_pdp_context_ref is not None:
        value["source_pdp_context_ref"] = source_pdp_context_ref
    return value


def _root_security(
    objects: Sequence[DomoObject],
    *,
    tenant_partition_id: str,
    access_policy_ref: str,
    retention_policy_ref: str,
    egress_policy_ref: str,
) -> dict[str, Any]:
    classification = max(
        (item.sensitivity for item in objects),
        key=lambda value: _CLASSIFICATION_RANK[value],
    )
    redaction_state = max(
        (item.redaction_state for item in objects),
        key=lambda value: _REDACTION_RANK[value],
    )
    return _security(
        tenant_partition_id=tenant_partition_id,
        classification=classification,
        redaction_state=redaction_state,
        access_policy_ref=access_policy_ref,
        retention_policy_ref=retention_policy_ref,
        egress_policy_ref=egress_policy_ref,
    )


def _provenance(
    *,
    tenant_ref: str,
    channel: str,
    captured_at: str,
    actor_ref: str,
    request_id: str,
    content_hash: str,
    permission_context_ref: str | None = None,
) -> dict[str, Any]:
    value: dict[str, Any] = {
        "source_system": "domo",
        "tenant_ref": tenant_ref,
        "acquisition_channel": channel,
        "captured_at": captured_at,
        "actor_ref": actor_ref,
        "request_id": request_id,
        "extractor_version": "omnikit-domo-inventory-projection/1.0.0",
        "content_hash": content_hash,
    }
    if permission_context_ref is not None:
        value["permission_context_ref"] = permission_context_ref
    return value


def _object_content_hash(item: DomoObject) -> str:
    if item.content_hash is not None:
        return item.content_hash
    return f"sha256:{sha256_json(item.model_dump(mode='json', exclude={'content_hash'}))}"


def _object_document(
    item: DomoObject,
    *,
    object_id: str,
    tenant_partition_id: str,
    actor_ref: str,
    request_id: str,
    access_policy_ref: str,
    retention_policy_ref: str,
    egress_policy_ref: str,
) -> dict[str, Any]:
    evidence_refs = sorted(set(item.source_refs)) or [_evidence_ref(object_id)]
    definition_hash = _object_content_hash(item)
    semantic_metadata = (
        item.attributes.get("semantic_profile", {})
        if isinstance(item.attributes.get("semantic_profile"), Mapping)
        else {}
    )
    operations_metadata = (
        semantic_metadata.get("operations", {})
        if isinstance(semantic_metadata, Mapping)
        else {}
    )
    owner_refs = sorted(
        {
            str(value)
            for value in (
                operations_metadata.get("owner_refs", [])
                if isinstance(operations_metadata, Mapping)
                else []
            )
            if isinstance(value, str) and value
        }
    )
    document: dict[str, Any] = {
        "identity": {
            "object_id": object_id,
            "object_type": _source_type(item.object_type),
            "native_id": item.object_id,
        },
        "name": item.title or item.object_id,
        "lifecycle_state": "unknown",
        "evidence_state": item.evidence_state,
        "source_version": item.content_hash or None,
        "metadata_hash": "sha256:" + "0" * 64,
        "definition_hash": definition_hash,
        "last_modified_at": None,
        "owner_refs": owner_refs,
        "evidence_refs": evidence_refs,
        "security": _security(
            tenant_partition_id=tenant_partition_id,
            classification=item.sensitivity,
            redaction_state=item.redaction_state,
            access_policy_ref=access_policy_ref,
            retention_policy_ref=retention_policy_ref,
            egress_policy_ref=egress_policy_ref,
            source_pdp_context_ref=item.permission_context_ref,
        ),
        "provenance": _provenance(
            tenant_ref=item.tenant_ref,
            channel=item.extraction_method,
            captured_at=_utc_text(item.acquired_at),
            actor_ref=actor_ref,
            request_id=request_id,
            content_hash=definition_hash,
            permission_context_ref=item.permission_context_ref,
        ),
    }
    document["metadata_hash"] = source_object_metadata_hash(document)
    return document


def _placeholder_document(
    key: str,
    *,
    tenant_ref: str,
    tenant_partition_id: str,
    captured_at: str,
    actor_ref: str,
    request_id: str,
    access_policy_ref: str,
    retention_policy_ref: str,
    egress_policy_ref: str,
) -> tuple[str, dict[str, Any]]:
    raw_type, native_id = _parse_object_key(key)
    object_id = _stable_object_id(raw_type, native_id)
    definition_hash = f"sha256:{sha256_json({'missing_object_key': key})}"
    document: dict[str, Any] = {
        "identity": {
            "object_id": object_id,
            "object_type": _source_type(raw_type),
            "native_id": native_id,
        },
        "name": native_id,
        "lifecycle_state": "unknown",
        "evidence_state": "blocked",
        "source_version": None,
        "metadata_hash": "sha256:" + "0" * 64,
        "definition_hash": definition_hash,
        "last_modified_at": None,
        "owner_refs": [],
        "evidence_refs": [_evidence_ref(object_id)],
        "security": _security(
            tenant_partition_id=tenant_partition_id,
            classification="confidential",
            redaction_state="restricted_reference_only",
            access_policy_ref=access_policy_ref,
            retention_policy_ref=retention_policy_ref,
            egress_policy_ref=egress_policy_ref,
        ),
        "provenance": _provenance(
            tenant_ref=tenant_ref,
            channel="control_plane",
            captured_at=captured_at,
            actor_ref=actor_ref,
            request_id=request_id,
            content_hash=definition_hash,
        ),
    }
    document["metadata_hash"] = source_object_metadata_hash(document)
    return object_id, document


def _closure_record(evidence: DomoEvidenceBundle) -> Any | None:
    return next(
        (
            item
            for item in evidence.coverage
            if item.capability == "selected_scope_dependency_closure"
        ),
        None,
    )


def _choose_entry_keys(
    evidence: DomoEvidenceBundle,
    *,
    known_keys: set[str],
    entry_object_keys: Sequence[str] | None,
    preferred_scope_keys: set[str] | None = None,
) -> list[str]:
    if entry_object_keys:
        unknown = sorted(set(entry_object_keys) - known_keys)
        if unknown:
            raise ValueError(f"entry objects are absent from projected dependency graph: {unknown}")
        return sorted(set(entry_object_keys))
    candidates = set(preferred_scope_keys or known_keys)
    targets = {
        edge.target_key
        for edge in evidence.edges
        if edge.source_key in candidates and edge.target_key in candidates
    }
    roots = sorted(candidates - targets)
    preferred_roots = [
        key
        for key in roots
        if _source_type(_parse_object_key(key)[0])
        in {"page", "app_studio_app", "custom_app", "workflow"}
    ]
    if preferred_scope_keys:
        entries = preferred_roots or roots
        reachable = _reachable_scope_keys(evidence, entries)
        for key in sorted(candidates - reachable):
            entries.append(key)
            reachable.update(_reachable_scope_keys(evidence, [key]))
        return entries
    return preferred_roots or roots or [sorted(candidates)[0]]


def _reachable_scope_keys(evidence: DomoEvidenceBundle, entry_keys: Sequence[str]) -> set[str]:
    adjacency: dict[str, set[str]] = {}
    for edge in evidence.edges:
        adjacency.setdefault(edge.source_key, set()).add(edge.target_key)
    reachable = set(entry_keys)
    pending = list(entry_keys)
    while pending:
        source_key = pending.pop()
        for target_key in adjacency.get(source_key, set()):
            if target_key not in reachable:
                reachable.add(target_key)
                pending.append(target_key)
    return reachable


def _manual_by_object(evidence: DomoEvidenceBundle) -> dict[str, list[Any]]:
    result: dict[str, list[Any]] = {}
    for request in evidence.manual_capture_queue:
        result.setdefault(request.object_key, []).append(request)
    return result


def _definition_facet_status(evidence_state: str) -> str:
    return {
        "extracted_complete": "complete",
        "extracted_partial": "partial",
        "metadata_only": "metadata_only",
        "manual_capture_required": "missing",
        "blocked": "missing",
    }[evidence_state]


def _channels(objects: Iterable[DomoObject]) -> list[str]:
    values = {
        channel
        for item in objects
        for channel in ([item.extraction_method] + list(item.channels))
    }
    return sorted(values)


_PLATFORM_CAPABILITY_BY_TYPE = {
    "page": "pages",
    "card": "cards",
    "dataset": "datasets",
}
_DENOMINATOR_CAPABILITY_BY_TYPE = {
    "page": "portfolio-pages",
    "subpage": "portfolio-pages",
    "card": "portfolio-cards",
    "beast_mode": "portfolio-cards",
    "variable": "portfolio-cards",
    "dataset": "portfolio-datasets",
    "dataset_schema": "portfolio-datasets",
    "pdp_policy": "portfolio-datasets",
    "dataflow": "portfolio-dataflows",
    "magic_etl": "portfolio-dataflows",
    "sql_dataflow": "portfolio-dataflows",
}
_GOVERNED_REPORT_CHANNELS = ("domostats_connector", "governance_connector")
_COMMONALITY_PROFILE_TYPES = frozenset(
    {"dataset", "dataflow", "magic_etl", "sql_dataflow", "beast_mode", "workflow"}
)
_EXTERNAL_HANDOFF_TYPES = frozenset(
    {"workflow", "app_studio_app", "custom_app", "domo_everywhere_embed"}
)


def _observation_kind(channel: str, source_items: Sequence[DomoObject]) -> str:
    declared_by_item = []
    for item in source_items:
        by_channel = item.provenance.get("observation_kind_by_channel")
        declared = (
            by_channel.get(channel)
            if isinstance(by_channel, Mapping)
            else item.provenance.get("observation_kind")
            if item.extraction_method == channel
            else None
        )
        declared_by_item.append(declared)
    declared_kinds = {item for item in declared_by_item if item is not None}
    if declared_kinds:
        if declared_kinds != {"detail_hydration"} or channel not in {
            "domo_platform_api_oauth",
            "domo_product_api_developer_token",
        }:
            raise ValueError(
                "explicit observation_kind is supported only for authenticated "
                "Platform/Product detail hydration"
            )
        if any(item != "detail_hydration" for item in declared_by_item):
            raise ValueError(
                "objects grouped into one channel observation must share the "
                "detail-hydration evidence kind"
            )
        return "detail_hydration"
    return {
        "domo_platform_api_oauth": "platform_list",
        "domo_product_api_developer_token": "product_search",
        "domostats_connector": "domostats_report",
        "governance_connector": "governance_report",
        "domo_cli": "customer_export",
        "workbench_export": "customer_export",
        "pro_code_zip_export": "customer_export",
        "customer_operated_export": "customer_export",
        "manual_capture": "manual_manifest",
    }.get(channel, "manual_manifest")


def _definition_kind(object_type: str) -> str:
    return {
        "page": "page",
        "subpage": "page",
        "card": "card",
        "dataset": "dataset",
        "dataset_schema": "dataset",
        "beast_mode": "beast_mode",
        "sql_dataflow": "sql_dataflow",
        "magic_etl": "magic_etl",
        "workflow": "workflow",
        "app_studio_app": "application",
        "custom_app": "application",
        "domo_everywhere_embed": "application",
    }.get(object_type, "other")


def _semantic_original_definition(source_object: DomoObject | None) -> Any:
    if source_object is None:
        return None
    definition = source_object.attributes.get("definition")
    if source_object.object_type == "sql_dataflow" and isinstance(definition, Mapping):
        return definition.get("sql")
    if source_object.object_type in {"beast_mode", "variable"} and isinstance(
        definition, Mapping
    ):
        return definition.get("formula")
    return definition


def _semantic_profile_requirements(
    *,
    source_object: DomoObject | None,
    object_id: str,
    object_type: str,
    definition_ref: str,
    source_revision_hash: str,
    evidence_refs: Sequence[str],
    object_ids_by_key: Mapping[str, str],
) -> list[dict[str, Any]]:
    """Project exact base/context profile obligations without copying raw definitions.

    Context descriptors remain in the immutable source evidence.  The portfolio
    carries only their hashes and safe references so later builders must prove
    that the exact source revision was used.
    """

    profile_kind = _SEMANTIC_PROFILE_KINDS.get(object_type)
    if profile_kind is None:
        return []
    original_definition = _semantic_original_definition(source_object)
    definition_hash = f"sha256:{sha256_json(original_definition)}"
    semantic_metadata = (
        source_object.attributes.get("semantic_profile", {})
        if source_object is not None
        else {}
    )
    raw_contexts = (
        semantic_metadata.get("contexts", [])
        if isinstance(semantic_metadata, Mapping)
        else []
    )
    declared_contexts = (
        [item for item in raw_contexts if isinstance(item, Mapping)]
        if isinstance(raw_contexts, list)
        else []
    )
    contexts = [
        {"context_id": "base"},
        *(
            item
            for item in declared_contexts
            if str(item.get("context_id", "")).strip() != "base"
        ),
    ]

    requirements: list[dict[str, Any]] = []
    seen_context_ids: set[str] = set()
    for raw_context in contexts:
        context = deepcopy(dict(raw_context))
        context_ref_override = context.pop("context_ref", None)
        context_id = str(context.get("context_id", "")).strip()
        if not context_id:
            raise ValueError(
                f"semantic profile context for {object_id} requires context_id"
            )
        context_hash = f"sha256:{sha256_json(context)}"
        if context_id in seen_context_ids:
            raise ValueError(
                f"semantic profile context for {object_id} is duplicated: {context_id}"
            )
        seen_context_ids.add(context_id)
        requirement_seed = {
            "base_object_id": object_id,
            "context_id": context_id,
            "context_hash": context_hash,
        }
        requirement_id = (
            "semantic-profile-requirement."
            f"{sha256_json(requirement_seed)[:24]}"
        )
        context_ref = (
            str(context_ref_override)
            if context_ref_override is not None
            else f"semantic-context-ref://domo/{object_id}/{context_hash[7:31]}"
        )
        consumer_object_id = None
        consumer_object_key = context.get("consumer_object_key")
        if consumer_object_key is not None:
            consumer_object_id = object_ids_by_key.get(str(consumer_object_key))
            if consumer_object_id is None:
                raise ValueError(
                    f"semantic context {context_id} references an unknown consumer object"
                )
        requirement: dict[str, Any] = {
            "requirement_id": requirement_id,
            "profile_kind": profile_kind,
            "base_object_id": object_id,
            "context_id": context_id,
            "context_ref": context_ref,
            "context_hash": context_hash,
            "definition_ref": definition_ref,
            "definition_hash": definition_hash,
            "source_revision_hash": source_revision_hash,
            "consumer_object_id": consumer_object_id,
            "evidence_refs": sorted(set((*evidence_refs, context_ref))),
            "requirement_hash": "",
        }
        requirement["requirement_hash"] = semantic_profile_requirement_hash(
            requirement
        )
        requirements.append(requirement)
    return sorted(requirements, key=lambda item: item["requirement_id"])


def _matching_checkpoint(
    evidence: DomoEvidenceBundle, capability: str
) -> Any | None:
    expected_endpoints = {capability.lower(), f"v1/{capability.lower()}"}
    matches = [
        item
        for item in evidence.checkpoints
        if item.endpoint.strip("/").lower() in expected_endpoints
    ]
    return matches[0] if len(matches) == 1 else None


def _nullable_request_context() -> dict[str, Any]:
    return {
        "source_ref": None,
        "filters_hash": None,
        "window": None,
        "report_generated_at": None,
    }


def _is_non_secret_ref(value: Any) -> bool:
    if not isinstance(value, str) or not re.fullmatch(
        r"[A-Za-z][A-Za-z0-9+.-]*:.+", value
    ):
        return False
    return value.split(":", 1)[0].lower() not in {
        "secret",
        "secret-ref",
        "vault",
        "credential",
        "credential-ref",
    }


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and bool(
        re.fullmatch(r"sha256:[a-f0-9]{64}", value)
    )


def _typed_window(value: Any) -> dict[str, str] | None:
    if not isinstance(value, Mapping):
        return None
    if set(value) != {"start", "end", "timezone"}:
        return None
    start = value.get("start")
    end = value.get("end")
    timezone_name = value.get("timezone")
    if not all(isinstance(item, str) and item for item in (start, end, timezone_name)):
        return None
    try:
        if parse_time(start) > parse_time(end):
            return None
    except ValueError:
        return None
    return {"start": start, "end": end, "timezone": timezone_name}


def _authoritative_request_context(
    record: Any | None,
    *,
    role: str,
    object_type: str,
    projected_at: str,
) -> tuple[dict[str, Any], int | None, list[str]]:
    """Read provider context without substituting projected values for missing evidence."""

    if record is None:
        return _nullable_request_context(), None, [
            f"{role} denominator coverage is missing"
        ]
    provenance = record.provenance if isinstance(record.provenance, Mapping) else {}
    nested_keys = (
        ("api_request_context", "platform_request_context", "request_context")
        if role == "platform"
        else ("report_request_context", "request_context")
    )
    nested: Mapping[str, Any] = {}
    for key in nested_keys:
        candidate = provenance.get(key)
        if isinstance(candidate, Mapping):
            nested = candidate
            break

    prefix = "api" if role == "platform" else "report"
    raw_source_ref = provenance.get(f"{prefix}_source_ref", nested.get("source_ref"))
    if raw_source_ref is None:
        raw_source_ref = provenance.get("source_ref")
    if raw_source_ref is None and len(record.source_refs) == 1:
        raw_source_ref = record.source_refs[0]

    raw_filters_hash = provenance.get(
        f"{prefix}_filters_hash", nested.get("filters_hash")
    )
    if raw_filters_hash is None:
        raw_filters_hash = provenance.get("filters_hash")
    raw_filters = provenance.get(f"{prefix}_filters", nested.get("filters"))
    if raw_filters is None:
        raw_filters = provenance.get("filters")
    if raw_filters_hash is None and raw_filters is not None:
        raw_filters_hash = f"sha256:{sha256_json(raw_filters)}"

    raw_window = provenance.get(f"{prefix}_window", nested.get("window"))
    if raw_window is None:
        raw_window = provenance.get("report_window" if role == "report" else "window")
    window = _typed_window(raw_window)

    raw_generated_at = provenance.get(
        "report_generated_at", nested.get("report_generated_at")
    )
    if raw_generated_at is None and role == "report":
        raw_generated_at = provenance.get("generated_at")
    report_generated_at: str | None = None
    if isinstance(raw_generated_at, str):
        try:
            parse_time(raw_generated_at)
            report_generated_at = raw_generated_at
        except ValueError:
            pass

    raw_provider_total = provenance.get(
        f"{prefix}_provider_total", nested.get("provider_total")
    )
    if raw_provider_total is None:
        raw_provider_total = provenance.get("provider_total")
    declared_counts = provenance.get("declared_counts")
    if (
        raw_provider_total is None
        and role == "report"
        and isinstance(declared_counts, Mapping)
    ):
        raw_provider_total = declared_counts.get(object_type)
    provider_total = (
        raw_provider_total
        if isinstance(raw_provider_total, int)
        and not isinstance(raw_provider_total, bool)
        and raw_provider_total >= 0
        else None
    )

    context = {
        "source_ref": raw_source_ref if _is_non_secret_ref(raw_source_ref) else None,
        "filters_hash": raw_filters_hash if _is_sha256(raw_filters_hash) else None,
        "window": window,
        "report_generated_at": report_generated_at if role == "report" else None,
    }
    diagnostics: list[str] = []
    if context["source_ref"] is None:
        diagnostics.append(f"{role} source reference is missing or invalid")
    if context["filters_hash"] is None:
        diagnostics.append(f"{role} filters are missing or invalid")
    if context["window"] is None:
        diagnostics.append(f"{role} acquisition window is missing or invalid")
    if role == "report":
        if report_generated_at is None:
            diagnostics.append("report generated-at is missing or invalid")
        else:
            generated = parse_time(report_generated_at)
            if generated > parse_time(projected_at):
                diagnostics.append("report generated-at is later than the observation")
            if window is not None and generated < parse_time(window["end"]):
                diagnostics.append("report generated-at precedes the report window end")
        if provider_total is None:
            diagnostics.append("report provider total is missing or invalid")
    return context, provider_total, diagnostics


def _checkpoint_pagination(checkpoint: Any | None) -> dict[str, Any]:
    if checkpoint is None:
        return {
            "strategy": "offset_limit",
            "page_count": 0,
            "request_count": 0,
            "exhausted": False,
            "truncated": False,
            "ceiling_reached": False,
            "next_offset": None,
            "checkpoint_ref": None,
            "checkpoint_hash": None,
            "endpoint": None,
            "seen_ids": [],
            "seen_id_set_hash": exact_id_set_hash([]),
            "expected_total": None,
            "warnings": [],
        }
    material = checkpoint.model_dump(mode="json")
    checkpoint_hash = f"sha256:{sha256_json(material)}"
    return {
        "strategy": "offset_limit",
        "page_count": checkpoint.page_count,
        "request_count": checkpoint.request_count,
        "exhausted": checkpoint.complete,
        "truncated": checkpoint.truncated,
        "ceiling_reached": checkpoint.truncated,
        "next_offset": checkpoint.next_offset,
        "checkpoint_ref": (
            f"evidence-ref://domo/checkpoint/{_stable_slug(checkpoint.endpoint)}/"
            f"{checkpoint_hash.removeprefix('sha256:')}"
        ),
        "checkpoint_hash": checkpoint_hash,
        "endpoint": checkpoint.endpoint,
        "seen_ids": list(checkpoint.seen_ids),
        "seen_id_set_hash": exact_id_set_hash(checkpoint.seen_ids),
        "expected_total": checkpoint.expected_total,
        "warnings": list(checkpoint.warnings),
    }


def _non_checkpoint_pagination(
    *,
    strategy: str,
    page_count: int,
    request_count: int,
    exhausted: bool,
) -> dict[str, Any]:
    return {
        "strategy": strategy,
        "page_count": page_count,
        "request_count": request_count,
        "exhausted": exhausted,
        "truncated": False,
        "ceiling_reached": False,
        "next_offset": None,
        "checkpoint_ref": None,
        "checkpoint_hash": None,
        "endpoint": None,
        "seen_ids": [],
        "seen_id_set_hash": exact_id_set_hash([]),
        "expected_total": None,
        "warnings": [],
    }


def _build_inventory_observations(
    evidence: DomoEvidenceBundle,
    *,
    graph_objects_by_key: dict[str, dict[str, Any]],
    source_objects_by_key: dict[str, DomoObject],
    run_id: str,
    scope_id: str,
    tenant_ref: str,
    visibility_principal_ref: str,
    projected_at: str,
    actor_ref: str,
    request_id: str,
    bundle_seed: str,
    access_policy_ref: str,
    root_security: dict[str, Any],
) -> tuple[dict[str, Any], ...]:
    groups: dict[tuple[str, str], list[str]] = defaultdict(list)
    for key in sorted(graph_objects_by_key):
        source_object = source_objects_by_key.get(key)
        channels = (
            sorted(
                set(
                    [source_object.extraction_method, *source_object.channels]
                )
            )
            if source_object is not None
            else ["manual_capture"]
        )
        object_type = graph_objects_by_key[key]["identity"]["object_type"]
        for channel in channels:
            groups[(object_type, channel)].append(key)

    coverage_by_capability = {item.capability: item for item in evidence.coverage}
    reconciliation_by_type = {
        item.capability.removeprefix("inventory_reconciliation:"): item
        for item in evidence.coverage
        if item.capability.startswith("inventory_reconciliation:")
    }
    selected_report_channel: dict[str, str] = {}
    pairable_types: set[str] = set()
    pair_diagnostics: dict[str, list[str]] = defaultdict(list)
    platform_context_by_type: dict[str, dict[str, Any]] = {}
    report_context_by_type: dict[str, dict[str, Any]] = {}
    report_total_by_type: dict[str, int | None] = {}
    report_evidence_diagnostics: dict[str, list[str]] = defaultdict(list)
    complete_report_evidence_types: set[str] = set()
    observed_object_types = {object_type for object_type, _channel in groups}
    for object_type in sorted(observed_object_types):
        reconciliation = reconciliation_by_type.get(object_type)
        report_channels = [
            channel
            for channel in _GOVERNED_REPORT_CHANNELS
            if groups.get((object_type, channel))
        ]
        if not report_channels:
            continue
        report_context, report_total, context_errors = _authoritative_request_context(
            reconciliation,
            role="report",
            object_type=object_type,
            projected_at=projected_at,
        )
        report_context_by_type[object_type] = report_context
        report_total_by_type[object_type] = report_total
        report_evidence_diagnostics[object_type].extend(context_errors)
        if len(report_channels) != 1:
            report_evidence_diagnostics[object_type].append(
                "exactly one governed report channel is required"
            )
            continue
        report_channel = report_channels[0]
        report_keys = set(groups[(object_type, report_channel)])
        if reconciliation is None:
            report_evidence_diagnostics[object_type].append(
                "governed report coverage is missing"
            )
            continue
        report_observed_count = reconciliation.provenance.get(
            "report_observed_count"
        )
        if report_observed_count != len(report_keys):
            report_evidence_diagnostics[object_type].append(
                "governed report observed count does not match emitted objects"
            )
        report_channels_from_evidence = reconciliation.provenance.get(
            "report_channels"
        )
        if report_channels_from_evidence != [report_channel]:
            report_evidence_diagnostics[object_type].append(
                "governed report channel does not match reconciliation evidence"
            )
        if report_total != len(report_keys):
            report_evidence_diagnostics[object_type].append(
                "report provider total does not match emitted objects"
            )
        if not report_evidence_diagnostics[object_type]:
            complete_report_evidence_types.add(object_type)

    for object_type, platform_capability in _PLATFORM_CAPABILITY_BY_TYPE.items():
        reconciliation = reconciliation_by_type.get(object_type)
        platform_coverage = coverage_by_capability.get(platform_capability)
        checkpoint = _matching_checkpoint(evidence, platform_capability)
        platform_keys = set(groups.get((object_type, "domo_platform_api_oauth"), []))
        report_channels = [
            channel
            for channel in _GOVERNED_REPORT_CHANNELS
            if groups.get((object_type, channel))
        ]
        platform_context, _, platform_context_errors = _authoritative_request_context(
            platform_coverage,
            role="platform",
            object_type=object_type,
            projected_at=projected_at,
        )
        report_context = report_context_by_type.get(
            object_type, _nullable_request_context()
        )
        report_total = report_total_by_type.get(object_type)
        report_context_errors = report_evidence_diagnostics.get(object_type, [])
        platform_context_by_type[object_type] = platform_context
        pair_diagnostics[object_type].extend(platform_context_errors)
        pair_diagnostics[object_type].extend(report_context_errors)
        if len(report_channels) != 1:
            pair_diagnostics[object_type].append(
                "exactly one governed report channel is required"
            )
            continue
        report_channel = report_channels[0]
        selected_report_channel[object_type] = report_channel
        report_keys = set(groups[(object_type, report_channel)])
        if reconciliation is None or reconciliation.status != "complete":
            pair_diagnostics[object_type].append(
                "API/report reconciliation coverage is not complete"
            )
        elif reconciliation.truncated or reconciliation.gaps:
            pair_diagnostics[object_type].append(
                "API/report reconciliation is truncated or has unresolved gaps"
            )
        if platform_coverage is None or platform_coverage.status != "complete":
            pair_diagnostics[object_type].append(
                "Platform list coverage is not complete"
            )
        elif platform_coverage.truncated or platform_coverage.gaps:
            pair_diagnostics[object_type].append(
                "Platform list coverage is truncated or has unresolved gaps"
            )
        expected_native_ids = {
            _parse_object_key(key)[1] for key in platform_keys
        }
        if checkpoint is None:
            pair_diagnostics[object_type].append(
                "an exact Platform pagination checkpoint is required"
            )
        else:
            checkpoint_ids = list(checkpoint.seen_ids)
            if len(checkpoint_ids) != len(set(checkpoint_ids)):
                pair_diagnostics[object_type].append(
                    "Platform checkpoint contains duplicate seen IDs"
                )
            if set(checkpoint_ids) != expected_native_ids:
                pair_diagnostics[object_type].append(
                    "Platform checkpoint seen IDs do not match emitted objects"
                )
            if checkpoint.expected_total is None:
                pair_diagnostics[object_type].append(
                    "Platform checkpoint provider total is missing"
                )
            elif checkpoint.expected_total != len(expected_native_ids):
                pair_diagnostics[object_type].append(
                    "Platform checkpoint provider total does not match emitted objects"
                )
            if checkpoint.complete and checkpoint.expected_total is not None and (
                checkpoint.next_offset != checkpoint.expected_total
            ):
                pair_diagnostics[object_type].append(
                    "Platform checkpoint offset does not reconcile to provider total"
                )
            if not checkpoint.complete or checkpoint.truncated:
                pair_diagnostics[object_type].append(
                    "Platform checkpoint is incomplete or truncated"
                )
            if checkpoint.warnings:
                pair_diagnostics[object_type].append(
                    "Platform checkpoint contains provider warnings"
                )
        if not platform_keys:
            pair_diagnostics[object_type].append(
                "Platform list emitted no typed objects"
            )
        if reconciliation is not None and (
            platform_keys != report_keys
            or platform_keys != set(reconciliation.object_keys)
        ):
            pair_diagnostics[object_type].append(
                "API/report exact object sets do not reconcile"
            )
        if platform_coverage is not None and (
            platform_keys != set(platform_coverage.object_keys)
        ):
            pair_diagnostics[object_type].append(
                "Platform coverage object set does not match emitted objects"
            )
        if report_total is not None and report_total != len(report_keys):
            pair_diagnostics[object_type].append(
                "report provider total does not match emitted objects"
            )
        if (
            platform_context["filters_hash"] != report_context["filters_hash"]
            or platform_context["window"] != report_context["window"]
        ):
            pair_diagnostics[object_type].append(
                "API/report filters or acquisition windows do not reconcile"
            )
        if not pair_diagnostics[object_type]:
            pairable_types.add(object_type)

    observations: list[dict[str, Any]] = []
    for (object_type, channel), keys in sorted(groups.items()):
        source_items = [
            source_objects_by_key[key]
            for key in keys
            if key in source_objects_by_key
        ]
        identities = [
            deepcopy(graph_objects_by_key[key]["identity"]) for key in sorted(keys)
        ]
        kind = _observation_kind(channel, source_items)
        is_pair_denominator = object_type in pairable_types and channel in {
            "domo_platform_api_oauth",
            selected_report_channel.get(object_type),
        }
        if kind == "product_search":
            completeness = "discovery_only"
        elif is_pair_denominator:
            completeness = "complete"
        elif source_items and all(
            item.evidence_state == "extracted_complete" for item in source_items
        ) and (
            kind in {"detail_hydration", "customer_export", "manual_manifest"}
            or (
                kind in {"domostats_report", "governance_report"}
                and object_type in complete_report_evidence_types
                and object_type not in _PLATFORM_CAPABILITY_BY_TYPE
            )
        ):
            completeness = "complete"
        else:
            completeness = "partial"

        authorization_refs = {
            item.permission_context_ref or access_policy_ref for item in source_items
        }
        authorization_ref = (
            next(iter(authorization_refs))
            if len(authorization_refs) == 1
            else access_policy_ref
        )
        if len(authorization_refs) > 1:
            is_pair_denominator = False
            completeness = "partial"

        if kind == "platform_list":
            platform_capability = _PLATFORM_CAPABILITY_BY_TYPE.get(object_type, "")
            checkpoint = _matching_checkpoint(evidence, platform_capability)
            pagination = _checkpoint_pagination(checkpoint)
            request_context = deepcopy(
                platform_context_by_type.get(
                    object_type, _nullable_request_context()
                )
            )
            provider_total = (
                checkpoint.expected_total if checkpoint is not None else None
            )
            duplicate_count = (
                len(checkpoint.seen_ids) - len(set(checkpoint.seen_ids))
                if checkpoint is not None
                else 0
            )
        elif kind == "product_search":
            pagination = _non_checkpoint_pagination(
                strategy="bounded_search",
                page_count=0,
                request_count=0,
                exhausted=False,
            )
            request_context = _nullable_request_context()
            provider_total = None
            duplicate_count = 0
        elif kind in {"domostats_report", "governance_report", "customer_export"}:
            pagination = _non_checkpoint_pagination(
                strategy="single_document",
                page_count=1,
                request_count=1,
                exhausted=completeness == "complete",
            )
            if kind in {"domostats_report", "governance_report"}:
                request_context = deepcopy(
                    report_context_by_type.get(
                        object_type, _nullable_request_context()
                    )
                )
                provider_total = report_total_by_type.get(object_type)
            else:
                request_context = _nullable_request_context()
                provider_total = None
            duplicate_count = 0
        else:
            pagination = _non_checkpoint_pagination(
                strategy="not_applicable",
                page_count=0,
                request_count=0,
                exhausted=completeness == "complete",
            )
            request_context = _nullable_request_context()
            provider_total = None
            duplicate_count = 0

        capability_id = _DENOMINATOR_CAPABILITY_BY_TYPE.get(
            object_type, f"portfolio-{object_type}"
        )
        diagnostics: list[str] = []
        if kind == "platform_list" or kind in {
            "domostats_report",
            "governance_report",
        }:
            diagnostics.extend(
                pair_diagnostics.get(object_type, [])
                if object_type in _PLATFORM_CAPABILITY_BY_TYPE
                else report_evidence_diagnostics.get(object_type, [])
            )
        diagnostics.extend(str(item) for item in pagination["warnings"])
        reconciliation = reconciliation_by_type.get(object_type)
        if reconciliation is not None and reconciliation.status != "complete":
            diagnostics.extend(reconciliation.gaps)
        if len(authorization_refs) > 1:
            diagnostics.append(
                "objects in the channel did not share one authorization context"
            )
        observation: dict[str, Any] = {
            "contract_version": "domo-to-omni.inventory-observation.v1",
            "observation_id": _stable_id(
                "observation.domo",
                {
                    "run_id": run_id,
                    "scope_id": scope_id,
                    "capability": capability_id,
                    "channel": channel,
                    "object_type": object_type,
                    "observation_kind": kind,
                    "authorization_ref": authorization_ref,
                },
            ),
            "run_id": run_id,
            "scope_id": scope_id,
            "source_tenant_ref": tenant_ref,
            "visibility_principal_ref": visibility_principal_ref,
            "capability_id": capability_id,
            "observation_kind": kind,
            "channel": channel,
            "observed_at": projected_at,
            "authority": {
                "visibility_principal_ref": visibility_principal_ref,
                "authorization_ref": authorization_ref,
                "read_only": True,
            },
            "request_context": request_context,
            "pagination": pagination,
            "totals": {
                "observed_count": len(identities),
                "provider_total": provider_total,
                "duplicate_count": duplicate_count,
                "denied_count": 0,
                "failed_count": 0,
                "excluded_count": 0,
            },
            "observed_objects": identities,
            "exact_id_set_hash": exact_object_set_hash(identities),
            "exclusions": [],
            "diagnostics": sorted(set(diagnostics)),
            "completeness": completeness,
            "denominator_eligible": is_pair_denominator,
            "observation_hash": "",
            "immutable": True,
            "provenance": _provenance(
                tenant_ref=tenant_ref,
                channel=channel,
                captured_at=projected_at,
                actor_ref=actor_ref,
                request_id=request_id,
                content_hash=bundle_seed,
                permission_context_ref=authorization_ref,
            ),
            "security": deepcopy(root_security),
        }
        observation["observation_hash"] = inventory_observation_hash(observation)
        observations.append(observation)

    observations.sort(key=lambda item: item["observation_id"])
    return tuple(observations)


def _build_portfolio_inventory(
    *,
    graph: dict[str, Any],
    inventory_snapshot: dict[str, Any],
    observations: tuple[dict[str, Any], ...],
    source_objects_by_key: dict[str, DomoObject],
    object_ids_by_key: dict[str, str],
    run_id: str,
    scope_id: str,
    tenant_ref: str,
    visibility_principal_ref: str,
    projected_at: str,
    actor_ref: str,
    request_id: str,
    bundle_seed: str,
    root_security: dict[str, Any],
) -> dict[str, Any]:
    graph_object_by_id = {
        item["identity"]["object_id"]: item for item in graph["objects"]
    }
    source_by_stable_id = {
        object_ids_by_key[key]: item for key, item in source_objects_by_key.items()
    }
    observations_by_identity: dict[tuple[str, str, str], list[str]] = defaultdict(list)
    for observation in observations:
        for identity in observation["observed_objects"]:
            observations_by_identity[
                (
                    identity["object_type"],
                    identity["object_id"],
                    identity["native_id"],
                )
            ].append(observation["observation_id"])

    incoming_ids: dict[str, set[str]] = defaultdict(set)
    outgoing_ids: dict[str, set[str]] = defaultdict(set)
    for edge in graph["edges"]:
        incoming_ids[edge["to_object_id"]].add(edge["from_object_id"])
        outgoing_ids[edge["from_object_id"]].add(edge["to_object_id"])

    portfolio_objects: list[dict[str, Any]] = []
    for object_id in sorted(graph_object_by_id):
        graph_object = graph_object_by_id[object_id]
        identity = deepcopy(graph_object["identity"])
        identity_key = (
            identity["object_type"],
            identity["object_id"],
            identity["native_id"],
        )
        source_object = source_by_stable_id.get(object_id)
        object_type = identity["object_type"]
        evidence_refs = sorted(set(graph_object["evidence_refs"]))
        definition_complete = graph_object["evidence_state"] == "extracted_complete"
        definition_content_ref = evidence_refs[0] if evidence_refs else None
        definition_content_hash = graph_object.get("definition_hash")
        if definition_content_ref is None:
            definition_content_hash = None

        schema_evidence: dict[str, Any]
        raw_schema = (
            source_object.attributes.get("schema")
            if source_object is not None
            else None
        )
        if object_type in {"dataset", "dataset_schema"} and raw_schema:
            schema_evidence = {
                "state": "complete" if definition_complete else "partial",
                "content_ref": f"evidence-ref://domo/{object_id}/schema",
                "content_hash": f"sha256:{sha256_json(raw_schema)}",
                "evidence_refs": evidence_refs,
            }
        elif object_type in {"dataset", "dataset_schema"}:
            schema_evidence = {
                "state": "missing",
                "content_ref": None,
                "content_hash": None,
                "evidence_refs": evidence_refs,
            }
        else:
            schema_evidence = {
                "state": "not_applicable",
                "content_ref": None,
                "content_hash": None,
                "evidence_refs": evidence_refs,
            }

        requires_handoff = object_type in _EXTERNAL_HANDOFF_TYPES
        redesign_handoff_refs = (
            [f"handoff-ref://{run_id}/{scope_id}/{object_id}"]
            if requires_handoff
            else []
        )
        if object_type in _COMMONALITY_PROFILE_TYPES:
            missing_requirements = ["type-specific semantic profile is not yet accepted"]
            if not definition_complete:
                missing_requirements.append("complete portable definition evidence")
            if not graph_object["owner_refs"]:
                missing_requirements.append("unambiguous owner")
            if object_type == "dataset" and schema_evidence["state"] != "complete":
                missing_requirements.append("complete dataset schema evidence")
            if requires_handoff:
                missing_requirements.append("accepted external redesign handoff")
            commonality = {
                "status": "blocked",
                "reasons": sorted(set(missing_requirements)),
                "profile": {
                    "profile_type": "incomplete",
                    "missing_requirements": sorted(set(missing_requirements)),
                },
            }
            owner_state = "known" if graph_object["owner_refs"] else "missing"
        else:
            commonality = {
                "status": "not_applicable",
                "reasons": ["object type is outside analytic commonality profiling"],
                "profile": {"profile_type": "not_applicable"},
            }
            owner_state = (
                "known" if graph_object["owner_refs"] else "not_applicable"
            )

        semantic_requirements = _semantic_profile_requirements(
            source_object=source_object,
            object_id=object_id,
            object_type=object_type,
            definition_ref=(
                definition_content_ref
                or f"evidence-ref://domo/{object_id}/definition-missing"
            ),
            source_revision_hash=(str(graph_object.get("definition_hash"))),
            evidence_refs=(
                evidence_refs
                or [f"evidence-ref://domo/{object_id}/definition-missing"]
            ),
            object_ids_by_key=object_ids_by_key,
        )
        portfolio_object: dict[str, Any] = {
            "identity": identity,
            "name": graph_object["name"],
            "lifecycle_state": graph_object["lifecycle_state"],
            "owner_state": owner_state,
            "owner_refs": deepcopy(graph_object["owner_refs"]),
            "evidence_state": graph_object["evidence_state"],
            "observation_ids": sorted(observations_by_identity[identity_key]),
            "definition": {
                "kind": _definition_kind(object_type),
                "state": graph_object["evidence_state"],
                "content_ref": definition_content_ref,
                "content_hash": definition_content_hash,
                "evidence_refs": evidence_refs,
            },
            "schema": schema_evidence,
            "lineage": {
                "producer_object_ids": sorted(incoming_ids[object_id]),
                "consumer_object_ids": sorted(outgoing_ids[object_id]),
            },
            "usage": [],
            "output_semantics": None,
            "external_handoff_required": requires_handoff,
            "redesign_handoff_refs": redesign_handoff_refs,
            "commonality": commonality,
            "semantic_profile_requirements": semantic_requirements,
            "semantic_profile_expectations": [],
            "object_hash": "",
            "security": deepcopy(graph_object["security"]),
        }
        if source_object is not None:
            portfolio_object["semantic_profile_expectations"] = [
                {
                    "requirement_id": requirement["requirement_id"],
                    "requirement_hash": requirement["requirement_hash"],
                    "expected_profile_hash": build_domo_semantic_profile(
                        portfolio_object,
                        source_object,
                        requirement,
                        run_id=run_id,
                        scope_id=scope_id,
                    ).profile_hash,
                    "builder_version": DOMO_PROFILE_BUILDER_VERSION,
                }
                for requirement in semantic_requirements
            ]
        portfolio_object["object_hash"] = portfolio_object_hash(portfolio_object)
        portfolio_objects.append(portfolio_object)

    authority_errors = complete_catalog_authority_errors(
        {"objects": portfolio_objects, "as_of": projected_at},
        {item["observation_id"]: item for item in observations},
    )
    legacy_completion = inventory_snapshot["completion"]["state"]
    if legacy_completion == "blocked":
        catalog_state = "blocked"
    elif legacy_completion == "complete" and not authority_errors:
        catalog_state = "complete"
    else:
        catalog_state = "partial"

    object_ids_by_type: dict[str, list[str]] = defaultdict(list)
    status_ids: dict[str, list[str]] = defaultdict(list)
    missing_owner_count = 0
    for item in portfolio_objects:
        object_id = item["identity"]["object_id"]
        object_ids_by_type[item["identity"]["object_type"]].append(object_id)
        status_ids[item["commonality"]["status"]].append(object_id)
        if item["owner_state"] in {"missing", "ambiguous"}:
            missing_owner_count += 1

    if status_ids["blocked"]:
        admission_status = "blocked"
        admission_reasons = [
            "one or more analytic objects lack accepted commonality evidence"
        ]
    elif catalog_state == "complete":
        admission_status = "ready"
        admission_reasons = []
    else:
        admission_status = "partial"
        admission_reasons = [
            "portfolio completeness denominators have not reconciled"
        ]

    portfolio: dict[str, Any] = {
        "contract_version": "domo-to-omni.portfolio-inventory.v1",
        "portfolio_id": _stable_id(
            "portfolio.domo",
            {"run_id": run_id, "scope_id": scope_id, "bundle": bundle_seed},
        ),
        "run_id": run_id,
        "scope_id": scope_id,
        "source_tenant_ref": tenant_ref,
        "visibility_principal_ref": visibility_principal_ref,
        "as_of": projected_at,
        "source_object_graph_ref": _artifact_ref(
            run_id, scope_id, "source-object-graph"
        ),
        "evidence_bundle_ref": _artifact_ref(run_id, scope_id, "evidence-bundle"),
        "coverage_ledger_ref": _artifact_ref(run_id, scope_id, "coverage-ledger"),
        "inventory_snapshot_ref": _artifact_ref(
            run_id, scope_id, "inventory-snapshot"
        ),
        "observation_ids": sorted(
            item["observation_id"] for item in observations
        ),
        "objects": portfolio_objects,
        "object_sets": [
            {
                "object_type": object_type,
                "count": len(object_ids),
                "object_ids": sorted(object_ids),
                "exact_id_set_hash": exact_id_set_hash(object_ids),
            }
            for object_type, object_ids in sorted(object_ids_by_type.items())
        ],
        "summary": {
            "catalog_state": catalog_state,
            "total_objects": len(portfolio_objects),
            "eligible_objects": len(status_ids["eligible"]),
            "blocked_objects": len(status_ids["blocked"]),
            "not_applicable_objects": len(status_ids["not_applicable"]),
            "missing_owner_objects": missing_owner_count,
        },
        "commonality_admission": {
            "status": admission_status,
            "eligible_object_ids": sorted(status_ids["eligible"]),
            "excluded_object_ids": sorted(status_ids["not_applicable"]),
            "blocking_object_ids": sorted(status_ids["blocked"]),
            "reasons": admission_reasons,
        },
        "portfolio_hash": "",
        "immutable": True,
        "provenance": _provenance(
            tenant_ref=tenant_ref,
            channel="control_plane",
            captured_at=projected_at,
            actor_ref=actor_ref,
            request_id=request_id,
            content_hash=bundle_seed,
        ),
        "security": deepcopy(root_security),
    }
    portfolio["portfolio_hash"] = portfolio_inventory_hash(portfolio)
    return portfolio


def project_domo_evidence_bundle(
    evidence: DomoEvidenceBundle,
    *,
    run_id: str,
    scope_id: str,
    tenant_ref: str | None = None,
    as_of: str | None = None,
    entry_object_keys: Sequence[str] | None = None,
    actor_ref: str = "agent-ref://data-acquisition-ingestion",
    access_policy_ref: str = "audit-policy://domo-migration/source-read",
    retention_policy_ref: str = "retention-policy://domo-migration/evidence",
    egress_policy_ref: str = "egress-policy://domo-migration/no-unapproved-egress",
) -> InventoryProjection:
    """Build the schema-shaped, integrity-checked inventory contract family.

    ``as_of`` is optional; when omitted, the latest source acquisition timestamp is
    used.  This keeps repeated projection of the same evidence byte-for-byte stable.
    """

    validate_run_id(run_id)
    validate_run_id(scope_id)
    normalized = evidence.finalized()
    if not normalized.objects:
        raise ValueError("Domo evidence bundle must contain at least one source object")

    tenant_refs = {item.tenant_ref for item in normalized.objects}
    if len(tenant_refs) != 1:
        raise ValueError(f"Domo evidence bundle crosses tenant boundaries: {sorted(tenant_refs)}")
    inferred_tenant_ref = next(iter(tenant_refs))
    if tenant_ref is not None and tenant_ref != inferred_tenant_ref:
        raise ValueError("requested tenant does not match Domo evidence provenance")
    tenant_ref = inferred_tenant_ref

    visibility_principals = {
        item.visibility_principal_ref for item in normalized.objects
    }
    if len(visibility_principals) != 1:
        raise ValueError(
            "Domo evidence bundle crosses visibility-principal boundaries: "
            f"{sorted(visibility_principals)}"
        )
    visibility_principal_ref = next(iter(visibility_principals))

    acquired_times = [parse_time(item.acquired_at) for item in normalized.objects]
    projected_at_dt = parse_time(as_of) if as_of is not None else max(acquired_times)
    if projected_at_dt < max(acquired_times):
        raise ValueError("inventory as_of cannot precede acquired source evidence")
    projected_at = _utc_text(projected_at_dt)

    bundle_seed = normalized.bundle_fingerprint or f"sha256:{sha256_json(normalized.model_dump(mode='json'))}"
    request_id = _stable_id("request.inventory", {"run_id": run_id, "scope_id": scope_id, "bundle": bundle_seed})
    tenant_partition_id = _stable_id("tenant.partition", tenant_ref)
    root_security = _root_security(
        normalized.objects,
        tenant_partition_id=tenant_partition_id,
        access_policy_ref=access_policy_ref,
        retention_policy_ref=retention_policy_ref,
        egress_policy_ref=egress_policy_ref,
    )

    object_ids_by_key: dict[str, str] = {}
    graph_objects_by_key: dict[str, dict[str, Any]] = {}
    source_objects_by_key = {item.key: item for item in normalized.objects}
    for item in normalized.objects:
        object_id = _stable_object_id(item.object_type, item.object_id)
        if object_id in object_ids_by_key.values():
            raise ValueError(f"stable Domo object ID collision for {item.key}")
        object_ids_by_key[item.key] = object_id
        graph_objects_by_key[item.key] = _object_document(
            item,
            object_id=object_id,
            tenant_partition_id=tenant_partition_id,
            actor_ref=actor_ref,
            request_id=request_id,
            access_policy_ref=access_policy_ref,
            retention_policy_ref=retention_policy_ref,
            egress_policy_ref=egress_policy_ref,
        )

    closure_record = _closure_record(normalized)
    declared_scope_keys = set(closure_record.object_keys) if closure_record is not None else set()
    missing_keys = sorted(
        {
            endpoint
            for edge in normalized.edges
            for endpoint in (edge.source_key, edge.target_key)
            if endpoint not in object_ids_by_key
        }
        | (declared_scope_keys - set(object_ids_by_key))
    )
    for key in missing_keys:
        object_id, document = _placeholder_document(
            key,
            tenant_ref=tenant_ref,
            tenant_partition_id=tenant_partition_id,
            captured_at=projected_at,
            actor_ref=actor_ref,
            request_id=request_id,
            access_policy_ref=access_policy_ref,
            retention_policy_ref=retention_policy_ref,
            egress_policy_ref=egress_policy_ref,
        )
        object_ids_by_key[key] = object_id
        graph_objects_by_key[key] = document

    graph_edges: list[dict[str, Any]] = []
    for edge in normalized.edges:
        edge_id = _stable_id(
            "edge.domo",
            {
                "source": object_ids_by_key[edge.source_key],
                "target": object_ids_by_key[edge.target_key],
                "relation": edge.relation,
            },
        )
        evidence_refs = sorted(set(edge.source_refs)) or [f"evidence-ref://domo/edge/{edge_id}"]
        projected_edge: dict[str, Any] = {
            "edge_id": edge_id,
            "from_object_id": object_ids_by_key[edge.source_key],
            "to_object_id": object_ids_by_key[edge.target_key],
            "relationship": _RELATIONSHIPS.get(edge.relation.lower(), "derived_from"),
            "confidence": "documented" if edge.source_refs else "observed",
            "evidence_refs": evidence_refs,
            "edge_hash": "sha256:" + "0" * 64,
        }
        projected_edge["edge_hash"] = dependency_edge_hash(projected_edge)
        graph_edges.append(projected_edge)
    graph_edges.sort(key=lambda item: item["edge_id"])

    entry_keys = _choose_entry_keys(
        normalized,
        known_keys=set(object_ids_by_key),
        entry_object_keys=entry_object_keys,
        preferred_scope_keys=declared_scope_keys or None,
    )
    reachable_scope_keys = _reachable_scope_keys(normalized, entry_keys)
    required_scope_keys = reachable_scope_keys | declared_scope_keys
    closure_denominator_gaps = sorted(reachable_scope_keys - declared_scope_keys)
    missing_required_keys = sorted(set(missing_keys) & required_scope_keys)
    if missing_required_keys or (closure_record is not None and closure_record.status == "blocked"):
        closure_status = "blocked"
    elif (
        closure_record is not None
        and closure_record.status == "complete"
        and not closure_denominator_gaps
    ):
        closure_status = "complete"
    else:
        closure_status = "partial"
    unresolved_reasons = []
    if missing_required_keys:
        unresolved_reasons.append(
            "dependency endpoints missing source evidence: "
            + ", ".join(missing_required_keys)
        )
    if closure_record is None:
        unresolved_reasons.append("selected-scope dependency closure was not evaluated")
    elif closure_denominator_gaps:
        unresolved_reasons.append(
            "selected-scope dependency closure denominator omits reachable objects: "
            + ", ".join(closure_denominator_gaps)
        )
    elif closure_record.status != "complete":
        unresolved_reasons.extend(closure_record.gaps or [f"dependency closure is {closure_record.status}"])
    graph: dict[str, Any] = {
        "contract_version": "domo-to-omni.source-object-graph.v1",
        "graph_id": _stable_id("graph.domo", {"run_id": run_id, "scope_id": scope_id, "bundle": bundle_seed}),
        "run_id": run_id,
        "scope_id": scope_id,
        "generated_at": projected_at,
        "objects": [graph_objects_by_key[key] for key in sorted(graph_objects_by_key)],
        "edges": graph_edges,
        "closure": {
            "entry_object_ids": [object_ids_by_key[key] for key in entry_keys],
            "status": closure_status,
            "captured_all_reachable": closure_status == "complete",
            "unresolved_object_ids": [object_ids_by_key[key] for key in missing_required_keys],
            "unresolved_reasons": sorted(set(unresolved_reasons)),
        },
        "graph_hash": "sha256:" + "0" * 64,
        "provenance": _provenance(
            tenant_ref=tenant_ref,
            channel="control_plane",
            captured_at=projected_at,
            actor_ref=actor_ref,
            request_id=request_id,
            content_hash="sha256:" + "0" * 64,
        ),
        "security": deepcopy(root_security),
    }
    graph["graph_hash"] = inventory_contract_hash("source_object_graph", graph)
    graph["provenance"]["content_hash"] = graph["graph_hash"]

    evidence_entries: list[dict[str, Any]] = []
    for key in sorted(source_objects_by_key):
        item = source_objects_by_key[key]
        object_id = object_ids_by_key[key]
        content_hash = _object_content_hash(item)
        normalized_bytes = canonical_json(item.model_dump(mode="json")).encode("utf-8")
        content_ref = sorted(set(item.source_refs))[0] if item.source_refs else _evidence_ref(object_id)
        evidence_kind = "inventory_metadata" if item.evidence_state == "metadata_only" else "definition"
        evidence_entries.append(
            {
                "evidence_id": _stable_id("evidence.domo", {"object_id": object_id, "hash": content_hash}),
                "object": graph_objects_by_key[key]["identity"],
                "evidence_kind": evidence_kind,
                "evidence_state": item.evidence_state,
                "channel": item.extraction_method,
                "media_type": "application/json",
                "content_ref": content_ref,
                "content_hash": content_hash,
                "byte_size": len(normalized_bytes),
                "captured_at": _utc_text(item.acquired_at),
                "provenance": _provenance(
                    tenant_ref=tenant_ref,
                    channel=item.extraction_method,
                    captured_at=_utc_text(item.acquired_at),
                    actor_ref=actor_ref,
                    request_id=request_id,
                    content_hash=content_hash,
                    permission_context_ref=item.permission_context_ref,
                ),
                "security": deepcopy(graph_objects_by_key[key]["security"]),
            }
        )

    coverage_ref = _artifact_ref(run_id, scope_id, "coverage-ledger")
    evidence_document: dict[str, Any] = {
        "contract_version": "domo-to-omni.evidence-bundle.v1",
        "bundle_id": _stable_id("bundle.evidence", {"run_id": run_id, "scope_id": scope_id, "bundle": bundle_seed}),
        "run_id": run_id,
        "scope_id": scope_id,
        "created_at": projected_at,
        "entries": evidence_entries,
        "coverage_ledger_ref": coverage_ref,
        "bundle_hash": "sha256:" + "0" * 64,
        "immutable": True,
        "security": deepcopy(root_security),
    }
    evidence_document["bundle_hash"] = inventory_contract_hash("evidence_bundle", evidence_document)

    manual_by_object = _manual_by_object(normalized)
    coverage_entries: list[dict[str, Any]] = []
    for key in sorted(graph_objects_by_key):
        graph_object = graph_objects_by_key[key]
        object_id = graph_object["identity"]["object_id"]
        required_for_scope = key in required_scope_keys
        requests = manual_by_object.get(key, []) if required_for_scope else []
        blockers = [request.reason for request in requests if request.blocking]
        if required_for_scope and key in missing_keys:
            blockers.append("Dependency object is missing source evidence.")
        if required_for_scope and graph_object["evidence_state"] != "extracted_complete":
            blockers.append(f"Definition evidence is {graph_object['evidence_state']}.")
        build_eligibility = (
            "not_applicable"
            if not required_for_scope
            else "ready" if not blockers else "not_ready"
        )
        evidence_refs = graph_object["evidence_refs"]
        coverage_entries.append(
            {
                "coverage_entry_id": _stable_id("coverage.object", object_id),
                "object": graph_object["identity"],
                "required_for_scope": required_for_scope,
                "evidence_state": graph_object["evidence_state"],
                "facets": [
                    {"facet": "metadata", "status": "complete", "evidence_refs": evidence_refs},
                    {
                        "facet": "definition",
                        "status": _definition_facet_status(graph_object["evidence_state"]),
                        "evidence_refs": evidence_refs,
                    },
                ],
                "evidence_refs": evidence_refs,
                "manual_capture_request_refs": [
                    _artifact_ref(run_id, scope_id, f"manual-capture/{_stable_slug(request.request_id)}")
                    for request in sorted(requests, key=lambda value: value.request_id)
                ],
                "blockers": sorted(set(blockers)),
                "build_eligibility": build_eligibility,
                "object_fingerprint": source_object_fingerprint(graph_object),
                "security": deepcopy(graph_object["security"]),
            }
        )

    ready_count = sum(item["build_eligibility"] == "ready" for item in coverage_entries)
    incomplete_count = sum(
        item["build_eligibility"] == "not_ready" for item in coverage_entries
    )
    excluded_count = sum(
        item["build_eligibility"] == "not_applicable" for item in coverage_entries
    )
    blocking_ids = sorted(
        item["object"]["object_id"]
        for item in coverage_entries
        if item["build_eligibility"] == "not_ready"
    )
    if closure_status == "blocked" or any(
        request.blocking and request.object_key in required_scope_keys
        for request in normalized.manual_capture_queue
    ):
        coverage_status = "blocked"
    elif closure_status == "complete" and incomplete_count == 0:
        coverage_status = "complete"
    else:
        coverage_status = "partial"
    if coverage_status == "blocked" and not blocking_ids:
        blocking_ids = sorted(graph["closure"]["entry_object_ids"])

    coverage_document: dict[str, Any] = {
        "contract_version": "domo-to-omni.coverage-ledger.v1",
        "ledger_id": _stable_id("coverage.ledger", {"run_id": run_id, "scope_id": scope_id, "bundle": bundle_seed}),
        "run_id": run_id,
        "scope_id": scope_id,
        "as_of": projected_at,
        "entries": coverage_entries,
        "summary": {
            "status": coverage_status,
            "total_objects": len(coverage_entries),
            "ready_objects": ready_count,
            "incomplete_objects": incomplete_count,
            "excluded_objects": excluded_count,
            "blocking_object_ids": blocking_ids,
        },
        "ledger_hash": "sha256:" + "0" * 64,
        "security": deepcopy(root_security),
    }
    coverage_document["ledger_hash"] = inventory_contract_hash("coverage_ledger", coverage_document)

    objects = graph["objects"]
    counts_by_type = Counter(item["identity"]["object_type"] for item in objects)
    states_by_type: dict[str, Counter[str]] = {}
    for item in objects:
        states_by_type.setdefault(item["identity"]["object_type"], Counter())[item["evidence_state"]] += 1
    object_counts = []
    for object_type in sorted(counts_by_type):
        row = {"object_type": object_type, "total": counts_by_type[object_type]}
        for state, column in _STATE_COLUMNS.items():
            row[column] = states_by_type[object_type][state]
        object_counts.append(row)

    channel_counts = Counter(
        channel
        for item in normalized.objects
        for channel in set([item.extraction_method, *item.channels])
    )
    reconciliation_channels = _channels(normalized.objects) or ["control_plane"]
    reconciliations = []
    for index, channel in enumerate(reconciliation_channels):
        difference_count = len(missing_required_keys) if index == 0 else 0
        reconciliations.append(
            {
                "channel": channel,
                "status": "difference_unresolved" if difference_count else "reconciled",
                "observed_count": channel_counts.get(channel, 0),
                "difference_count": difference_count,
                "evidence_refs": [f"evidence-ref://domo/reconciliation/{_stable_slug(channel)}"],
            }
        )

    if closure_status == "complete" and coverage_status == "complete":
        completion_state = "complete"
    elif closure_status == "blocked" or coverage_status == "blocked":
        completion_state = "blocked"
    else:
        completion_state = "partial"
    manual_refs = [
        _artifact_ref(run_id, scope_id, f"manual-capture/{_stable_slug(request.request_id)}")
        for request in sorted(normalized.manual_capture_queue, key=lambda value: value.request_id)
        if request.object_key in required_scope_keys
    ]

    snapshot: dict[str, Any] = {
        "contract_version": "domo-to-omni.inventory-snapshot.v1",
        "snapshot_id": _stable_id("inventory.snapshot", {"run_id": run_id, "scope_id": scope_id, "bundle": bundle_seed}),
        "run_id": run_id,
        "scope_id": scope_id,
        "as_of": projected_at,
        "preflight_ref": _artifact_ref(run_id, scope_id, "capability-preflight"),
        "source_object_graph_ref": _artifact_ref(run_id, scope_id, "source-object-graph"),
        "coverage_ledger_ref": coverage_ref,
        "evidence_bundle_ref": _artifact_ref(run_id, scope_id, "evidence-bundle"),
        "reconciliations": reconciliations,
        "object_counts": object_counts,
        "completion": {
            "state": completion_state,
            "dependency_closure": closure_status,
            "coverage_state": coverage_status,
            "unresolved_object_ids": graph["closure"]["unresolved_object_ids"],
            "manual_capture_request_refs": manual_refs,
        },
        "source_fingerprint": "sha256:" + "0" * 64,
        "immutable": True,
        "provenance": _provenance(
            tenant_ref=tenant_ref,
            channel="control_plane",
            captured_at=projected_at,
            actor_ref=actor_ref,
            request_id=request_id,
            content_hash="sha256:" + "0" * 64,
        ),
        "security": deepcopy(root_security),
    }
    snapshot["source_fingerprint"] = inventory_contract_hash("inventory_snapshot", snapshot)
    snapshot["provenance"]["content_hash"] = snapshot["source_fingerprint"]

    inventory_observations = _build_inventory_observations(
        normalized,
        graph_objects_by_key=graph_objects_by_key,
        source_objects_by_key=source_objects_by_key,
        run_id=run_id,
        scope_id=scope_id,
        tenant_ref=tenant_ref,
        visibility_principal_ref=visibility_principal_ref,
        projected_at=projected_at,
        actor_ref=actor_ref,
        request_id=request_id,
        bundle_seed=bundle_seed,
        access_policy_ref=access_policy_ref,
        root_security=root_security,
    )
    portfolio_inventory = _build_portfolio_inventory(
        graph=graph,
        inventory_snapshot=snapshot,
        observations=inventory_observations,
        source_objects_by_key=source_objects_by_key,
        object_ids_by_key=object_ids_by_key,
        run_id=run_id,
        scope_id=scope_id,
        tenant_ref=tenant_ref,
        visibility_principal_ref=visibility_principal_ref,
        projected_at=projected_at,
        actor_ref=actor_ref,
        request_id=request_id,
        bundle_seed=bundle_seed,
        root_security=root_security,
    )

    projection = InventoryProjection(
        source_object_graph=graph,
        evidence_bundle=evidence_document,
        coverage_ledger=coverage_document,
        inventory_snapshot=snapshot,
        inventory_observations=inventory_observations,
        portfolio_inventory=portfolio_inventory,
    )
    if errors := validate_inventory_contract_set(**projection.as_documents()):
        raise ValueError("projected inventory contract set is inconsistent: " + "; ".join(errors))
    observation_errors = [
        f"{item['observation_id']}: {error}"
        for item in projection.inventory_observations
        for error in validate_inventory_observation(item)
    ]
    if observation_errors:
        raise ValueError(
            "projected inventory observations are inconsistent: "
            + "; ".join(observation_errors)
        )
    if errors := validate_portfolio_inventory(
        projection.portfolio_inventory,
        observations=projection.inventory_observations,
    ):
        raise ValueError(
            "projected portfolio inventory is inconsistent: " + "; ".join(errors)
        )
    return projection


__all__ = ["InventoryProjection", "project_domo_evidence_bundle"]

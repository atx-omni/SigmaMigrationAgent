"""Semantic integrity checks for Domo portfolio inventory contracts.

JSON Schema validates shape.  These helpers recompute content-addressed sets and
cross-document relationships so counts or caller assertions cannot establish
inventory completeness on their own.
"""

from __future__ import annotations

from collections import defaultdict
from copy import deepcopy
from typing import Any, Mapping, Sequence

from omni_migrator.control_plane.canonical import sha256_json


# Capability families are explicit because a matching API/report hash is not
# meaningful when the underlying endpoint could never enumerate that object
# type.  The families cover listable roots plus their bounded typed detail
# closure; unknown families cannot establish a denominator.
DENOMINATOR_CAPABILITY_OBJECT_TYPES: dict[str, frozenset[str]] = {
    "portfolio-datasets": frozenset({"dataset", "dataset_schema", "pdp_policy"}),
    "portfolio-dataflows": frozenset(
        {"dataflow", "magic_etl", "sql_dataflow"}
    ),
    "portfolio-pages": frozenset({"page", "subpage"}),
    "portfolio-cards": frozenset({"card", "beast_mode", "variable"}),
    "portfolio-workflows": frozenset({"workflow"}),
    "portfolio-applications": frozenset(
        {"app_studio_app", "custom_app", "domo_everywhere_embed"}
    ),
    "portfolio-operations": frozenset(
        {"schedule", "alert", "publication", "workbench_job"}
    ),
    "portfolio-administration": frozenset(
        {"connector_account", "file_asset", "code_engine_package", "user", "group", "role"}
    ),
}

# Only these typed roots are actually enumerated by the allowlisted public
# Platform list client.  Other members of the capability families are bounded
# dependency/detail closure; they must never be relabelled as list results just
# to make a portfolio look complete.
PLATFORM_DENOMINATOR_ROOT_OBJECT_TYPES: dict[str, frozenset[str]] = {
    "portfolio-datasets": frozenset({"dataset"}),
    "portfolio-pages": frozenset({"page"}),
    "portfolio-cards": frozenset({"card"}),
}

_DEPENDENCY_REPORT_KINDS = frozenset({"domostats_report", "governance_report"})
_DEPENDENCY_DEFINITION_KINDS = frozenset(
    {"detail_hydration", "customer_export", "manual_manifest"}
)


def _sha256(value: Any) -> str:
    return f"sha256:{sha256_json(value)}"


def _identity_key(value: Mapping[str, Any]) -> tuple[str, str, str]:
    return (
        str(value.get("object_type", "")),
        str(value.get("object_id", "")),
        str(value.get("native_id", "")),
    )


def exact_object_set_hash(objects: Sequence[Mapping[str, Any]]) -> str:
    """Hash an exact, order-independent set of typed source identities."""

    identities = [
        {
            "object_type": object_type,
            "object_id": object_id,
            "native_id": native_id,
        }
        for object_type, object_id, native_id in sorted(_identity_key(item) for item in objects)
    ]
    return _sha256(identities)


def exact_id_set_hash(object_ids: Sequence[str]) -> str:
    """Hash an order-independent stable-ID set."""

    return _sha256(sorted(str(item) for item in object_ids))


def inventory_observation_hash(observation: Mapping[str, Any]) -> str:
    material = deepcopy(dict(observation))
    material.pop("observation_hash", None)
    return _sha256(material)


def portfolio_object_hash(item: Mapping[str, Any]) -> str:
    material = deepcopy(dict(item))
    material.pop("object_hash", None)
    return _sha256(material)


def semantic_profile_requirement_hash(item: Mapping[str, Any]) -> str:
    material = deepcopy(dict(item))
    material.pop("requirement_hash", None)
    return _sha256(material)


def portfolio_inventory_hash(portfolio: Mapping[str, Any]) -> str:
    material = deepcopy(dict(portfolio))
    material.pop("portfolio_hash", None)
    return _sha256(material)


def inventory_observation_content_sha256(observation: Mapping[str, Any]) -> str:
    """Return the canonical, unprefixed payload hash used by artifact envelopes."""

    return sha256_json(observation)


def portfolio_inventory_content_sha256(portfolio: Mapping[str, Any]) -> str:
    """Return the canonical, unprefixed payload hash used by artifact envelopes."""

    return sha256_json(portfolio)


def validate_inventory_observation(observation: Mapping[str, Any]) -> list[str]:
    """Return deterministic cross-field errors for one channel observation."""

    errors: list[str] = []
    objects = observation.get("observed_objects", [])
    if not isinstance(objects, list):
        return ["observed_objects must be an array"]
    identities = [
        _identity_key(item) for item in objects if isinstance(item, Mapping)
    ]
    if len(identities) != len(objects):
        errors.append("observed_objects contains a non-object identity")
    if len(identities) != len(set(identities)):
        errors.append("observed_objects contains duplicate typed identities")

    totals = observation.get("totals", {})
    if not isinstance(totals, Mapping):
        errors.append("totals must be an object")
        totals = {}
    if totals.get("observed_count") != len(set(identities)):
        errors.append("totals.observed_count does not match the exact observed ID set")
    if totals.get("duplicate_count", 0) and len(identities) == len(set(identities)):
        # Duplicates may have been removed by a deterministic parser, but they must
        # not survive in the exact set.  The count remains diagnostic evidence.
        pass
    expected_set_hash = exact_object_set_hash(
        [item for item in objects if isinstance(item, Mapping)]
    )
    if observation.get("exact_id_set_hash") != expected_set_hash:
        errors.append("exact_id_set_hash does not match observed_objects")
    if observation.get("observation_hash") != inventory_observation_hash(observation):
        errors.append("observation_hash does not match observation content")

    kind = observation.get("observation_kind")
    completeness = observation.get("completeness")
    denominator_eligible = observation.get("denominator_eligible")
    pagination = observation.get("pagination", {})
    if not isinstance(pagination, Mapping):
        errors.append("pagination must be an object")
        pagination = {}

    authority = observation.get("authority", {})
    if not isinstance(authority, Mapping):
        errors.append("authority must be an object")
        authority = {}
    if observation.get("visibility_principal_ref") != authority.get(
        "visibility_principal_ref"
    ):
        errors.append(
            "top-level and authority visibility principals do not match"
        )

    if kind == "product_search":
        if completeness != "discovery_only" or denominator_eligible is not False:
            errors.append("Product Search is discovery-only and cannot be a denominator")
    if denominator_eligible is True:
        if kind not in {"platform_list", "domostats_report", "governance_report"}:
            errors.append(
                "only Platform list or governed-report observations can be denominators"
            )
        if completeness != "complete":
            errors.append("only a complete observation can be denominator-eligible")
        if not pagination.get("exhausted"):
            errors.append("denominator-eligible observation must exhaust pagination")
        if pagination.get("truncated") or pagination.get("ceiling_reached"):
            errors.append("truncated or ceiling-limited observations cannot be denominators")
        if totals.get("failed_count", 0) or totals.get("denied_count", 0):
            errors.append("failed or denied objects prevent denominator eligibility")
        if totals.get("excluded_count", 0):
            errors.append("excluded objects prevent exact denominator eligibility")
        provider_total = totals.get("provider_total")
        if provider_total is not None and provider_total != totals.get("observed_count"):
            errors.append("provider total does not match the exact observed count")
        capability_id = str(observation.get("capability_id", ""))
        allowed_types = DENOMINATOR_CAPABILITY_OBJECT_TYPES.get(capability_id)
        root_types = PLATFORM_DENOMINATOR_ROOT_OBJECT_TYPES.get(capability_id)
        observed_types = {identity[0] for identity in identities}
        if allowed_types is None:
            errors.append(
                "denominator capability is not in the authoritative object-type matrix"
            )
        elif not observed_types.issubset(allowed_types):
            errors.append(
                "denominator observation contains object types unsupported by its "
                f"capability: {capability_id}"
            )
        if root_types is None or not observed_types.intersection(root_types):
            errors.append(
                "denominator observation lacks a Platform-listable root for its "
                f"capability: {capability_id}"
            )
    if (
        kind in _DEPENDENCY_REPORT_KINDS
        and completeness == "complete"
        and denominator_eligible is False
    ):
        provider_total = totals.get("provider_total")
        if provider_total != totals.get("observed_count"):
            errors.append(
                "complete governed-report observation provider total does not match "
                "the exact observed count"
            )
        request_context = observation.get("request_context", {})
        if not isinstance(request_context, Mapping) or any(
            request_context.get(field) is None
            for field in ("source_ref", "filters_hash", "window", "report_generated_at")
        ):
            errors.append(
                "complete governed-report observation requires authoritative request context"
            )
    return errors


def _observation_map(
    observations: Sequence[Mapping[str, Any]] | None,
) -> tuple[dict[str, Mapping[str, Any]], list[str]]:
    result: dict[str, Mapping[str, Any]] = {}
    errors: list[str] = []
    for observation in observations or ():
        observation_id = str(observation.get("observation_id", ""))
        if observation_id in result:
            errors.append(f"duplicate observation ID: {observation_id}")
        result[observation_id] = observation
        errors.extend(
            f"observation {observation_id}: {error}"
            for error in validate_inventory_observation(observation)
        )
    return result, errors


def complete_catalog_authority_errors(
    portfolio: Mapping[str, Any],
    observation_by_id: Mapping[str, Mapping[str, Any]],
) -> list[str]:
    """Validate the exact authority partition for a complete catalog.

    Public Platform pagination closes only the Page/Card/DataSet root sets.
    Typed dependencies such as Beast Modes, PDP policies, and SQL DataFlows
    remain in the same canonical portfolio only when a governed inventory
    observation and a complete detail/manual definition both bind the exact
    identity at the same as-of point.  This preserves fail-closed completeness
    without pretending an unsupported Platform list endpoint exists.
    """

    errors: list[str] = []
    objects = [
        item
        for item in portfolio.get("objects", [])
        if isinstance(item, Mapping) and isinstance(item.get("identity"), Mapping)
    ]
    object_by_identity = {
        _identity_key(item["identity"]): item
        for item in objects
    }
    object_identity_keys = set(object_by_identity)
    root_object_types = frozenset(
        object_type
        for types in PLATFORM_DENOMINATOR_ROOT_OBJECT_TYPES.values()
        for object_type in types
    )
    root_identity_keys = {
        identity for identity in object_identity_keys if identity[0] in root_object_types
    }
    dependency_identity_keys = object_identity_keys - root_identity_keys

    denominator_observations = [
        item
        for item in observation_by_id.values()
        if item.get("denominator_eligible") is True
    ]
    by_capability: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for item in denominator_observations:
        by_capability[str(item.get("capability_id", ""))].append(item)

    paired_observation_ids_by_identity: dict[
        tuple[str, str, str], set[str]
    ] = defaultdict(set)
    paired_identity_union: set[tuple[str, str, str]] = set()
    paired_identity_capabilities: dict[
        tuple[str, str, str], set[str]
    ] = defaultdict(set)
    for capability_id, capability_observations in sorted(by_capability.items()):
        api = [
            item
            for item in capability_observations
            if item.get("observation_kind") == "platform_list"
        ]
        reports = [
            item
            for item in capability_observations
            if item.get("observation_kind") in _DEPENDENCY_REPORT_KINDS
        ]
        unsupported = [
            item
            for item in capability_observations
            if item not in api and item not in reports
        ]
        if len(api) != 1 or len(reports) != 1 or unsupported:
            errors.append(
                "complete portfolio capability requires exactly one API and one "
                f"governed-report denominator: {capability_id}"
            )
            continue
        pair = [api[0], reports[0]]
        authority_contexts = {
            sha256_json(
                {
                    "authorization_ref": item.get("authority", {}).get(
                        "authorization_ref"
                    ),
                    "read_only": item.get("authority", {}).get("read_only"),
                }
            )
            for item in pair
        }
        request_contexts = {
            sha256_json(
                {
                    "filters_hash": item.get("request_context", {}).get(
                        "filters_hash"
                    ),
                    "window": item.get("request_context", {}).get("window"),
                }
            )
            for item in pair
        }
        observed_at_values = {str(item.get("observed_at", "")) for item in pair}
        security_contexts = {sha256_json(item.get("security", {})) for item in pair}
        if (
            len(authority_contexts) != 1
            or len(request_contexts) != 1
            or len(observed_at_values) != 1
            or observed_at_values != {str(portfolio.get("as_of", ""))}
            or len(security_contexts) != 1
        ):
            errors.append(
                "API/report denominator authority, filters, window, as-of, or "
                f"security context does not reconcile: {capability_id}"
            )
            continue
        identity_sets = {
            frozenset(
                _identity_key(observed)
                for observed in item.get("observed_objects", [])
                if isinstance(observed, Mapping)
            )
            for item in capability_observations
        }
        if len(identity_sets) != 1:
            errors.append(
                "API/report denominator exact ID sets do not reconcile: "
                f"{capability_id}"
            )
            continue
        paired_identities = set(next(iter(identity_sets)))
        root_types = PLATFORM_DENOMINATOR_ROOT_OBJECT_TYPES.get(capability_id)
        if root_types is None or any(
            identity[0] not in root_types for identity in paired_identities
        ):
            errors.append(
                "paired API/report denominator includes a non-listable dependency: "
                f"{capability_id}"
            )
            continue
        pair_observation_ids = {
            str(item.get("observation_id", "")) for item in pair
        }
        paired_identity_union.update(paired_identities)
        for paired_identity in paired_identities:
            paired_identity_capabilities[paired_identity].add(capability_id)
            paired_observation_ids_by_identity[paired_identity].update(
                pair_observation_ids
            )

    if not denominator_observations:
        errors.append(
            "complete portfolio requires reconciled API and governed-report denominators"
        )
    if paired_identity_union != root_identity_keys:
        errors.append(
            "paired API/report denominator roots do not exactly match the "
            "Platform-listable portfolio roots"
        )
    duplicate_capabilities = {
        identity: capabilities
        for identity, capabilities in paired_identity_capabilities.items()
        if len(capabilities) != 1
    }
    if duplicate_capabilities:
        errors.append(
            "paired API/report capabilities do not form an exact root partition"
        )

    report_observation_ids_by_identity: dict[
        tuple[str, str, str], set[str]
    ] = defaultdict(set)
    definition_observation_ids_by_identity: dict[
        tuple[str, str, str], set[str]
    ] = defaultdict(set)
    portfolio_as_of = str(portfolio.get("as_of", ""))
    for observation_id, observation in observation_by_id.items():
        if observation.get("denominator_eligible") is True:
            continue
        if observation.get("completeness") != "complete":
            continue
        if str(observation.get("observed_at", "")) != portfolio_as_of:
            continue
        kind = str(observation.get("observation_kind", ""))
        if kind not in _DEPENDENCY_REPORT_KINDS | _DEPENDENCY_DEFINITION_KINDS:
            continue
        capability_id = str(observation.get("capability_id", ""))
        allowed_types = DENOMINATOR_CAPABILITY_OBJECT_TYPES.get(capability_id)
        if allowed_types is None:
            continue
        for observed in observation.get("observed_objects", []):
            if not isinstance(observed, Mapping):
                continue
            identity = _identity_key(observed)
            if identity[0] not in allowed_types:
                continue
            if kind in _DEPENDENCY_REPORT_KINDS:
                report_observation_ids_by_identity[identity].add(observation_id)
            else:
                definition_observation_ids_by_identity[identity].add(observation_id)

    object_id_by_identity = {
        identity: str(item.get("identity", {}).get("object_id", ""))
        for identity, item in object_by_identity.items()
    }
    adjacency: dict[str, set[str]] = defaultdict(set)
    known_object_ids = set(object_id_by_identity.values())
    for item in objects:
        identity = _identity_key(item["identity"])
        object_id = object_id_by_identity[identity]
        lineage = item.get("lineage", {})
        if not isinstance(lineage, Mapping):
            continue
        for related_id in [
            *lineage.get("producer_object_ids", []),
            *lineage.get("consumer_object_ids", []),
        ]:
            related = str(related_id)
            if related in known_object_ids:
                adjacency[object_id].add(related)
                adjacency[related].add(object_id)
    reachable_object_ids = {
        object_id_by_identity[identity]
        for identity in paired_identity_union
        if identity in object_id_by_identity
    }
    pending = list(reachable_object_ids)
    while pending:
        current = pending.pop()
        for related in adjacency[current] - reachable_object_ids:
            reachable_object_ids.add(related)
            pending.append(related)

    for identity in sorted(root_identity_keys):
        item = object_by_identity[identity]
        cited_ids = set(item.get("observation_ids", []))
        required_ids = paired_observation_ids_by_identity.get(identity, set())
        if not required_ids or not required_ids.issubset(cited_ids):
            errors.append(
                "complete portfolio root must cite its exact paired API/report "
                f"denominator: {identity[1]}"
            )
    for identity in sorted(dependency_identity_keys):
        item = object_by_identity[identity]
        cited_ids = set(item.get("observation_ids", []))
        report_ids = report_observation_ids_by_identity.get(identity, set())
        definition_ids = definition_observation_ids_by_identity.get(identity, set())
        if not report_ids.intersection(cited_ids):
            errors.append(
                "complete portfolio dependency must cite exact governed-report "
                f"membership evidence: {identity[1]}"
            )
        if not definition_ids.intersection(cited_ids):
            errors.append(
                "complete portfolio dependency must cite exact detail/manual "
                f"definition evidence: {identity[1]}"
            )
        if object_id_by_identity[identity] not in reachable_object_ids:
            errors.append(
                "complete portfolio dependency is not connected to a paired "
                f"Platform-listable root: {identity[1]}"
            )
        definition = item.get("definition", {})
        if (
            item.get("evidence_state") != "extracted_complete"
            or not isinstance(definition, Mapping)
            or definition.get("state") != "extracted_complete"
        ):
            errors.append(
                "complete portfolio dependency lacks a complete portable definition: "
                f"{identity[1]}"
            )

    return errors


def validate_portfolio_inventory(
    portfolio: Mapping[str, Any],
    *,
    observations: Sequence[Mapping[str, Any]] | None = None,
) -> list[str]:
    """Validate portfolio counts, references, commonality admission, and evidence."""

    errors: list[str] = []
    observation_by_id, observation_errors = _observation_map(observations)
    errors.extend(observation_errors)
    if observations is not None:
        expected_partition = (
            str(portfolio.get("source_tenant_ref", "")),
            str(portfolio.get("run_id", "")),
            str(portfolio.get("scope_id", "")),
            str(portfolio.get("visibility_principal_ref", "")),
        )
        for observation_id, observation in observation_by_id.items():
            authority = observation.get("authority", {})
            actual_partition = (
                str(observation.get("source_tenant_ref", "")),
                str(observation.get("run_id", "")),
                str(observation.get("scope_id", "")),
                (
                    str(authority.get("visibility_principal_ref", ""))
                    if isinstance(authority, Mapping)
                    else ""
                ),
            )
            if actual_partition != expected_partition:
                errors.append(
                    "portfolio observation crosses tenant, run, scope, or visibility "
                    f"principal: {observation_id}"
                )

    objects = portfolio.get("objects", [])
    if not isinstance(objects, list):
        return [*errors, "objects must be an array"]
    object_by_id: dict[str, Mapping[str, Any]] = {}
    object_identity_keys: set[tuple[str, str, str]] = set()
    object_types: dict[str, list[str]] = defaultdict(list)
    statuses: dict[str, set[str]] = defaultdict(set)
    output_producers: list[tuple[str, str, str | None]] = []
    requirement_consumers: list[tuple[str, str, str]] = []
    missing_owners = 0
    for item in objects:
        if not isinstance(item, Mapping):
            errors.append("objects contains a non-object entry")
            continue
        identity = item.get("identity", {})
        if not isinstance(identity, Mapping):
            errors.append("portfolio object identity must be an object")
            continue
        object_id = str(identity.get("object_id", ""))
        if object_id in object_by_id:
            errors.append(f"duplicate portfolio object ID: {object_id}")
        object_by_id[object_id] = item
        object_identity_keys.add(_identity_key(identity))
        object_types[str(identity.get("object_type", ""))].append(object_id)
        commonality = item.get("commonality", {})
        status = (
            str(commonality.get("status", ""))
            if isinstance(commonality, Mapping)
            else ""
        )
        statuses[status].add(object_id)
        if item.get("owner_state") in {"missing", "ambiguous"}:
            missing_owners += 1
            if status == "eligible":
                errors.append(f"commonality-eligible object lacks an unambiguous owner: {object_id}")
        if item.get("object_hash") != portfolio_object_hash(item):
            errors.append(f"object_hash does not match portfolio object: {object_id}")
        object_type = str(identity.get("object_type", ""))
        expected_profile_kind = {
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
        }.get(object_type)
        requirements = item.get("semantic_profile_requirements", [])
        if not isinstance(requirements, list):
            errors.append(
                f"portfolio object {object_id} semantic_profile_requirements must be an array"
            )
            requirements = []
        if expected_profile_kind is not None and not requirements:
            errors.append(
                f"portfolio object {object_id} lacks an explicit semantic profile requirement"
            )
        requirement_ids: set[str] = set()
        context_ids: set[str] = set()
        for requirement in requirements:
            if not isinstance(requirement, Mapping):
                errors.append(
                    f"portfolio object {object_id} has a non-object semantic profile requirement"
                )
                continue
            requirement_id = str(requirement.get("requirement_id", ""))
            if requirement_id in requirement_ids:
                errors.append(
                    f"portfolio object {object_id} repeats semantic profile requirement: "
                    f"{requirement_id}"
                )
            requirement_ids.add(requirement_id)
            context_id = str(requirement.get("context_id", ""))
            if context_id in context_ids:
                errors.append(
                    f"portfolio object {object_id} repeats semantic profile context: "
                    f"{context_id}"
                )
            context_ids.add(context_id)
            if requirement.get("base_object_id") != object_id:
                errors.append(
                    f"semantic profile requirement {requirement_id} binds the wrong base object"
                )
            if requirement.get("profile_kind") != expected_profile_kind:
                errors.append(
                    f"semantic profile requirement {requirement_id} has the wrong profile kind"
                )
            definition = item.get("definition", {})
            if not isinstance(definition, Mapping) or (
                definition.get("content_hash") is not None
                and requirement.get("source_revision_hash")
                != definition.get("content_hash")
            ) or (
                definition.get("content_ref") is not None
                and requirement.get("definition_ref") != definition.get("content_ref")
            ):
                errors.append(
                    f"semantic profile requirement {requirement_id} is not bound to the "
                    "portfolio definition revision"
                )
            if requirement.get("requirement_hash") != semantic_profile_requirement_hash(
                requirement
            ):
                errors.append(
                    f"semantic profile requirement hash is stale: {requirement_id}"
                )
            consumer_object_id = requirement.get("consumer_object_id")
            if consumer_object_id is not None:
                requirement_consumers.append(
                    (object_id, requirement_id, str(consumer_object_id))
                )
        expectations = item.get("semantic_profile_expectations", [])
        if not isinstance(expectations, list):
            errors.append(
                f"portfolio object {object_id} semantic_profile_expectations must be an array"
            )
            expectations = []
        expectations_by_id: dict[str, Mapping[str, Any]] = {}
        for expectation in expectations:
            if not isinstance(expectation, Mapping):
                errors.append(
                    f"portfolio object {object_id} has a non-object semantic profile expectation"
                )
                continue
            requirement_id = str(expectation.get("requirement_id", ""))
            if requirement_id in expectations_by_id:
                errors.append(
                    f"portfolio object {object_id} repeats semantic profile expectation: "
                    f"{requirement_id}"
                )
            expectations_by_id[requirement_id] = expectation
        expected_expectation_ids = (
            requirement_ids
            if item.get("evidence_state") == "extracted_complete"
            else set(expectations_by_id)
        )
        if (
            set(expectations_by_id) != expected_expectation_ids
            or not set(expectations_by_id).issubset(requirement_ids)
        ):
            errors.append(
                f"portfolio object {object_id} semantic profile expectations do not "
                "exactly cover its requirements"
            )
        requirements_by_id = {
            str(requirement.get("requirement_id", "")): requirement
            for requirement in requirements
            if isinstance(requirement, Mapping)
        }
        for requirement_id in sorted(
            set(expectations_by_id).intersection(requirements_by_id)
        ):
            expectation = expectations_by_id[requirement_id]
            requirement = requirements_by_id[requirement_id]
            if expectation.get("requirement_hash") != requirement.get(
                "requirement_hash"
            ):
                errors.append(
                    f"semantic profile expectation {requirement_id} binds a stale requirement"
                )
            if not expectation.get("expected_profile_hash") or not expectation.get(
                "builder_version"
            ):
                errors.append(
                    f"semantic profile expectation {requirement_id} is incomplete"
                )
        for observation_id in item.get("observation_ids", []):
            if observations is not None and observation_id not in observation_by_id:
                errors.append(
                    f"portfolio object {object_id} references unknown observation: {observation_id}"
                )
            elif observations is not None:
                observed_identities = {
                    _identity_key(observed)
                    for observed in observation_by_id[observation_id].get(
                        "observed_objects", []
                    )
                    if isinstance(observed, Mapping)
                }
                if _identity_key(identity) not in observed_identities:
                    errors.append(
                        f"portfolio object {object_id} is absent from cited observation: "
                        f"{observation_id}"
                    )
        lineage = item.get("lineage", {})
        if isinstance(lineage, Mapping):
            for related_id in [
                *lineage.get("producer_object_ids", []),
                *lineage.get("consumer_object_ids", []),
            ]:
                if related_id not in object_by_id and related_id not in {
                    str(obj.get("identity", {}).get("object_id", ""))
                    for obj in objects
                    if isinstance(obj, Mapping)
                }:
                    errors.append(
                        f"portfolio object {object_id} has dangling lineage reference: {related_id}"
                    )

        if observations is not None:
            for usage in item.get("usage", []):
                if not isinstance(usage, Mapping):
                    continue
                usage_observation_id = str(usage.get("source_observation_id", ""))
                usage_observation = observation_by_id.get(usage_observation_id)
                if usage_observation is None:
                    errors.append(
                        f"portfolio object {object_id} has usage from unknown observation: "
                        f"{usage_observation_id}"
                    )
                    continue
                observed_identities = {
                    _identity_key(observed)
                    for observed in usage_observation.get("observed_objects", [])
                    if isinstance(observed, Mapping)
                }
                if _identity_key(identity) not in observed_identities:
                    errors.append(
                        f"portfolio object {object_id} usage observation does not contain "
                        f"the object: {usage_observation_id}"
                    )

        output_semantics = item.get("output_semantics")
        commonality_profile = (
            commonality.get("profile", {})
            if isinstance(commonality, Mapping)
            else {}
        )
        if isinstance(output_semantics, Mapping):
            producer_id = str(output_semantics.get("producer_object_id", ""))
            profile_producer = (
                str(commonality_profile.get("producer_object_id", ""))
                if isinstance(commonality_profile, Mapping)
                and commonality_profile.get("profile_type") == "dataset_output"
                else None
            )
            output_producers.append((object_id, producer_id, profile_producer))

        supported_commonality_types = {
            "beast_mode",
            "dataflow",
            "sql_dataflow",
            "magic_etl",
            "workflow",
            "dataset",
        }
        if object_type in supported_commonality_types and status == "not_applicable":
            errors.append(
                f"supported commonality object cannot be not_applicable: {object_id}"
            )

        if status == "eligible":
            if item.get("evidence_state") != "extracted_complete":
                errors.append(f"commonality-eligible object lacks complete evidence: {object_id}")
            definition = item.get("definition", {})
            if not isinstance(definition, Mapping) or definition.get("state") != "extracted_complete":
                errors.append(f"commonality-eligible object lacks a complete definition: {object_id}")
            if not isinstance(definition, Mapping) or not definition.get("content_ref") or not definition.get("content_hash"):
                errors.append(f"commonality-eligible object lacks definition provenance: {object_id}")
            security = item.get("security", {})
            if isinstance(security, Mapping) and security.get("redaction_state") in {
                "pending",
                "restricted_reference_only",
            }:
                errors.append(f"commonality-eligible object has unusable redaction state: {object_id}")
            if object_type == "workflow" and item.get("external_handoff_required") is not True:
                errors.append(f"workflow analytic profiling must preserve an external side-effect handoff: {object_id}")

    known_object_ids = set(object_by_id)
    for object_id, requirement_id, consumer_object_id in requirement_consumers:
        if consumer_object_id not in known_object_ids:
            errors.append(
                f"semantic profile requirement {requirement_id} for {object_id} "
                f"references unknown consumer: {consumer_object_id}"
            )
    for object_id, producer_id, profile_producer in output_producers:
        lineage = object_by_id[object_id].get("lineage", {})
        declared_producers = (
            set(lineage.get("producer_object_ids", []))
            if isinstance(lineage, Mapping)
            else set()
        )
        if producer_id == object_id:
            errors.append(
                f"portfolio DataSet output {object_id} cannot produce itself"
            )
        if producer_id not in known_object_ids:
            errors.append(
                f"portfolio DataSet output {object_id} has dangling producer: {producer_id}"
            )
        if producer_id not in declared_producers:
            errors.append(
                f"portfolio DataSet output {object_id} producer is absent from lineage"
            )
        if profile_producer is not None and profile_producer != producer_id:
            errors.append(
                f"portfolio DataSet output {object_id} has contradictory producer IDs"
            )

    for object_id, item in object_by_id.items():
        commonality = item.get("commonality", {})
        profile = (
            commonality.get("profile", {})
            if isinstance(commonality, Mapping)
            else {}
        )
        if not isinstance(profile, Mapping):
            continue
        profile_type = profile.get("profile_type")
        referenced_fields_by_profile = {
            "beast_mode": ("consumer_object_ids",),
            "sql_dataflow": ("ordered_input_object_ids", "output_object_ids"),
            "magic_etl": ("input_object_ids", "output_object_ids"),
            "workflow": ("output_object_ids",),
        }
        for field_name in referenced_fields_by_profile.get(str(profile_type), ()):
            for related_id in profile.get(field_name, []):
                if related_id not in known_object_ids:
                    errors.append(
                        f"portfolio object {object_id} has dangling {profile_type} "
                        f"{field_name} reference: {related_id}"
                    )
    declared_set_ids: set[str] = set()
    for declared in portfolio.get("object_sets", []):
        if not isinstance(declared, Mapping):
            errors.append("object_sets contains a non-object entry")
            continue
        object_type = str(declared.get("object_type", ""))
        ids = [str(item) for item in declared.get("object_ids", [])]
        if declared.get("count") != len(set(ids)):
            errors.append(f"object set count does not match exact IDs for type {object_type}")
        if declared.get("exact_id_set_hash") != exact_id_set_hash(ids):
            errors.append(f"object set hash does not match exact IDs for type {object_type}")
        if set(ids) != set(object_types.get(object_type, [])):
            errors.append(f"object set does not match portfolio objects for type {object_type}")
        overlap = declared_set_ids & set(ids)
        if overlap:
            errors.append(f"portfolio object appears in more than one type set: {sorted(overlap)}")
        declared_set_ids.update(ids)
    if declared_set_ids != known_object_ids:
        errors.append("object_sets do not form an exact partition of portfolio objects")

    summary = portfolio.get("summary", {})
    if isinstance(summary, Mapping):
        expected_summary = {
            "total_objects": len(known_object_ids),
            "eligible_objects": len(statuses["eligible"]),
            "blocked_objects": len(statuses["blocked"]),
            "not_applicable_objects": len(statuses["not_applicable"]),
            "missing_owner_objects": missing_owners,
        }
        for key, expected in expected_summary.items():
            if summary.get(key) != expected:
                errors.append(f"summary.{key} does not match portfolio objects")

    admission = portfolio.get("commonality_admission", {})
    if isinstance(admission, Mapping):
        declared_eligible = set(admission.get("eligible_object_ids", []))
        declared_excluded = set(admission.get("excluded_object_ids", []))
        declared_blocking = set(admission.get("blocking_object_ids", []))
        if declared_eligible != statuses["eligible"]:
            errors.append("commonality eligible set does not match object statuses")
        if declared_excluded != statuses["not_applicable"]:
            errors.append("commonality excluded set does not match object statuses")
        if declared_blocking != statuses["blocked"]:
            errors.append("commonality blocking set does not match object statuses")
        if (declared_eligible | declared_excluded | declared_blocking) != known_object_ids:
            errors.append("commonality admission does not partition portfolio objects")
        catalog_state = str(portfolio.get("summary", {}).get("catalog_state", ""))
        expected_admission_status = (
            "blocked"
            if statuses["blocked"]
            else "ready"
            if catalog_state == "complete"
            else "partial"
        )
        if admission.get("status") != expected_admission_status:
            errors.append(
                "commonality admission status is not derived from catalog and object states"
            )
        if expected_admission_status != "ready" and not admission.get("reasons"):
            errors.append("non-ready commonality admission requires a reason")

    top_observation_ids = set(portfolio.get("observation_ids", []))
    if observations is None:
        if portfolio.get("summary", {}).get("catalog_state") == "complete":
            errors.append(
                "complete portfolio validation requires the supplied observation ledger"
            )
    else:
        if top_observation_ids != set(observation_by_id):
            errors.append("portfolio observation IDs do not match supplied observations")
        if portfolio.get("summary", {}).get("catalog_state") == "complete":
            errors.extend(
                complete_catalog_authority_errors(portfolio, observation_by_id)
            )

    if portfolio.get("portfolio_hash") != portfolio_inventory_hash(portfolio):
        errors.append("portfolio_hash does not match portfolio content")
    return errors

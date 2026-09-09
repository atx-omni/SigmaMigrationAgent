"""Semantic and cross-document checks for the Domo inventory contract set.

JSON Schema validates shape. These checks validate relationships that span arrays or
documents: identity uniqueness, graph endpoints, count reconciliation, shared
partitions, and evidence chronology. Content bytes remain in the governed evidence
store; their recorded hashes are verified against bytes at registration time.
"""

from __future__ import annotations

from collections import Counter
from copy import deepcopy
from datetime import datetime, timezone
from typing import Any, Mapping, Sequence
from urllib.parse import urlsplit

from omni_migrator.control_plane.canonical import parse_time, sha256_json


_INVENTORY_HASH_PATHS: dict[str, tuple[tuple[str, ...], ...]] = {
    "source_object_graph": (("graph_hash",), ("provenance", "content_hash")),
    "evidence_bundle": (("bundle_hash",),),
    "coverage_ledger": (("ledger_hash",),),
    "inventory_snapshot": (("source_fingerprint",), ("provenance", "content_hash")),
}


def _without_paths(value: Mapping[str, Any], paths: Sequence[tuple[str, ...]]) -> dict[str, Any]:
    normalized = deepcopy(dict(value))
    for path in paths:
        parent: Any = normalized
        for part in path[:-1]:
            if not isinstance(parent, dict) or part not in parent:
                parent = None
                break
            parent = parent[part]
        if isinstance(parent, dict):
            parent.pop(path[-1], None)
    return normalized


def canonical_contract_hash(
    value: Mapping[str, Any],
    *,
    exclude_paths: Sequence[tuple[str, ...]] = (),
) -> str:
    """Return a prefixed canonical SHA-256 after removing self-referential fields."""

    return f"sha256:{sha256_json(_without_paths(value, exclude_paths))}"


def inventory_contract_hash(contract_name: str, value: Mapping[str, Any]) -> str:
    """Recompute a root inventory document hash under its frozen v1 rule."""

    try:
        paths = _INVENTORY_HASH_PATHS[contract_name]
    except KeyError as exc:
        raise ValueError(f"unknown inventory contract hash rule: {contract_name}") from exc
    return canonical_contract_hash(value, exclude_paths=paths)


def dependency_edge_hash(edge: Mapping[str, Any]) -> str:
    return canonical_contract_hash(edge, exclude_paths=(("edge_hash",),))


def cross_scope_exception_hash(exception: Mapping[str, Any]) -> str:
    """Bind one cross-scope exception to its source revision and approval evidence."""

    return canonical_contract_hash(exception, exclude_paths=(("exception_hash",),))


def source_object_metadata_hash(source_object: Mapping[str, Any]) -> str:
    """Hash source identity and observable metadata, excluding definition bytes."""

    material = {
        key: deepcopy(source_object.get(key))
        for key in (
            "identity",
            "name",
            "lifecycle_state",
            "evidence_state",
            "source_version",
            "last_modified_at",
            "owner_refs",
            "security",
        )
    }
    return canonical_contract_hash(material)


def source_object_fingerprint(source_object: Mapping[str, Any]) -> str:
    """Hash one fully projected source object for its coverage-ledger binding."""

    return canonical_contract_hash(source_object)


def _duplicates(values: Sequence[str]) -> set[str]:
    counts = Counter(values)
    return {value for value, count in counts.items() if count > 1}


def _root_identity(document: Mapping[str, Any]) -> tuple[str, str, str]:
    security = document.get("security", {})
    return (
        str(document.get("run_id", "")),
        str(document.get("scope_id", "")),
        str(security.get("tenant_partition_id", "")),
    )


def _reachable_object_ids(
    *,
    entry_ids: set[str],
    edges: Sequence[Mapping[str, Any]],
    known_object_ids: set[str],
) -> set[str]:
    """Return the directed dependency closure rooted at the declared scope entries."""

    adjacency: dict[str, set[str]] = {}
    for edge in edges:
        source = str(edge.get("from_object_id", ""))
        target = str(edge.get("to_object_id", ""))
        if source in known_object_ids and target in known_object_ids:
            adjacency.setdefault(source, set()).add(target)
    reachable = set(entry_ids) & known_object_ids
    pending = list(reachable)
    while pending:
        source = pending.pop()
        for target in adjacency.get(source, set()):
            if target not in reachable:
                reachable.add(target)
                pending.append(target)
    return reachable


def validate_inventory_contract_set(
    *,
    source_object_graph: Mapping[str, Any],
    evidence_bundle: Mapping[str, Any],
    coverage_ledger: Mapping[str, Any],
    inventory_snapshot: Mapping[str, Any],
) -> list[str]:
    """Return every semantic integrity error across one inventory snapshot."""

    errors: list[str] = []
    documents = {
        "source_object_graph": source_object_graph,
        "evidence_bundle": evidence_bundle,
        "coverage_ledger": coverage_ledger,
        "inventory_snapshot": inventory_snapshot,
    }
    identities = {name: _root_identity(document) for name, document in documents.items()}
    if len(set(identities.values())) != 1:
        errors.append(f"inventory contracts cross run, scope, or tenant partitions: {identities}")

    objects = list(source_object_graph.get("objects", []))
    object_ids = [str(item.get("identity", {}).get("object_id", "")) for item in objects]
    if duplicates := _duplicates(object_ids):
        errors.append(f"source object graph contains duplicate object IDs: {sorted(duplicates)}")
    object_by_id = {
        str(item.get("identity", {}).get("object_id")): item
        for item in objects
        if item.get("identity", {}).get("object_id")
    }
    known_object_ids = set(object_by_id)
    for object_id, item in object_by_id.items():
        expected_metadata_hash = source_object_metadata_hash(item)
        if item.get("metadata_hash") != expected_metadata_hash:
            errors.append(f"source object {object_id} metadata hash is not canonical")
        definition_hash = item.get("definition_hash")
        provenance_hash = item.get("provenance", {}).get("content_hash")
        if definition_hash is not None and provenance_hash != definition_hash:
            errors.append(f"source object {object_id} definition and provenance hashes differ")

    edges = list(source_object_graph.get("edges", []))
    edge_ids = [str(edge.get("edge_id", "")) for edge in edges]
    if duplicates := _duplicates(edge_ids):
        errors.append(f"source object graph contains duplicate edge IDs: {sorted(duplicates)}")
    for edge in edges:
        edge_id = str(edge.get("edge_id", "unknown"))
        for endpoint in ("from_object_id", "to_object_id"):
            if str(edge.get(endpoint, "")) not in known_object_ids:
                errors.append(f"edge {edge_id} has an unknown {endpoint}")
        if edge.get("edge_hash") != dependency_edge_hash(edge):
            errors.append(f"edge {edge_id} hash is not canonical")

    closure = source_object_graph.get("closure", {})
    entry_ids = {str(value) for value in closure.get("entry_object_ids", [])}
    unresolved_ids = {str(value) for value in closure.get("unresolved_object_ids", [])}
    if missing := (entry_ids | unresolved_ids) - known_object_ids:
        errors.append(f"closure references unknown object IDs: {sorted(missing)}")
    closure_complete = closure.get("status") == "complete"
    if closure_complete and (
        not closure.get("captured_all_reachable")
        or unresolved_ids
        or closure.get("unresolved_reasons")
    ):
        errors.append("complete dependency closure contains unresolved or uncaptured state")

    evidence_entries = list(evidence_bundle.get("entries", []))
    evidence_ids = [str(item.get("evidence_id", "")) for item in evidence_entries]
    evidence_object_ids = {
        str(item.get("object", {}).get("object_id", "")) for item in evidence_entries
    }
    if duplicates := _duplicates(evidence_ids):
        errors.append(f"evidence bundle contains duplicate evidence IDs: {sorted(duplicates)}")
    for item in evidence_entries:
        evidence_id = str(item.get("evidence_id", "unknown"))
        object_id = str(item.get("object", {}).get("object_id", ""))
        if object_id not in known_object_ids:
            errors.append(f"evidence {evidence_id} references an unknown source object")
        provenance_hash = item.get("provenance", {}).get("content_hash")
        if provenance_hash and provenance_hash != item.get("content_hash"):
            errors.append(f"evidence {evidence_id} content and provenance hashes differ")

    graph_hash = source_object_graph.get("graph_hash")
    if graph_hash != inventory_contract_hash("source_object_graph", source_object_graph):
        errors.append("source graph hash is not canonical")
    if graph_hash != source_object_graph.get("provenance", {}).get("content_hash"):
        errors.append("source graph hash differs from its provenance hash")
    if evidence_bundle.get("bundle_hash") != inventory_contract_hash(
        "evidence_bundle", evidence_bundle
    ):
        errors.append("evidence bundle hash is not canonical")
    if coverage_ledger.get("ledger_hash") != inventory_contract_hash(
        "coverage_ledger", coverage_ledger
    ):
        errors.append("coverage ledger hash is not canonical")
    source_fingerprint = inventory_snapshot.get("source_fingerprint")
    if source_fingerprint != inventory_contract_hash("inventory_snapshot", inventory_snapshot):
        errors.append("inventory fingerprint is not canonical")
    if source_fingerprint != inventory_snapshot.get("provenance", {}).get("content_hash"):
        errors.append("inventory fingerprint differs from its provenance hash")

    coverage_entries = list(coverage_ledger.get("entries", []))
    coverage_entry_ids = [str(item.get("coverage_entry_id", "")) for item in coverage_entries]
    coverage_object_ids = [
        str(item.get("object", {}).get("object_id", "")) for item in coverage_entries
    ]
    required_coverage_ids = {
        str(item.get("object", {}).get("object_id", ""))
        for item in coverage_entries
        if item.get("required_for_scope") is True
    }
    if duplicates := _duplicates(coverage_entry_ids):
        errors.append(f"coverage ledger contains duplicate entry IDs: {sorted(duplicates)}")
    if duplicates := _duplicates(coverage_object_ids):
        errors.append(f"coverage ledger contains duplicate source objects: {sorted(duplicates)}")
    unknown_coverage = set(coverage_object_ids) - known_object_ids
    if unknown_coverage:
        errors.append(
            f"coverage ledger references unknown source objects: {sorted(unknown_coverage)}"
        )
    for item in coverage_entries:
        object_id = str(item.get("object", {}).get("object_id", ""))
        source_object = object_by_id.get(object_id)
        if source_object is not None and item.get(
            "object_fingerprint"
        ) != source_object_fingerprint(source_object):
            errors.append(f"coverage entry for {object_id} has a stale source object fingerprint")

    summary = coverage_ledger.get("summary", {})
    ready = sum(item.get("build_eligibility") == "ready" for item in coverage_entries)
    incomplete = sum(item.get("build_eligibility") == "not_ready" for item in coverage_entries)
    excluded = sum(item.get("build_eligibility") == "not_applicable" for item in coverage_entries)
    expected_summary = {
        "total_objects": len(coverage_entries),
        "ready_objects": ready,
        "incomplete_objects": incomplete,
        "excluded_objects": excluded,
    }
    for key, expected in expected_summary.items():
        if summary.get(key) != expected:
            errors.append(f"coverage summary {key} is {summary.get(key)!r}; expected {expected}")
    if summary.get("status") == "complete":
        if incomplete or summary.get("blocking_object_ids"):
            errors.append("complete coverage summary contains incomplete or blocking objects")
        if set(coverage_object_ids) != known_object_ids:
            errors.append("complete coverage does not account for every graph object")

    object_counts = list(inventory_snapshot.get("object_counts", []))
    count_types = [str(item.get("object_type", "")) for item in object_counts]
    if duplicates := _duplicates(count_types):
        errors.append(f"inventory snapshot repeats object count types: {sorted(duplicates)}")
    actual_by_type = Counter(
        str(item.get("identity", {}).get("object_type", "")) for item in objects
    )
    states_by_type: dict[str, Counter[str]] = {}
    for item in objects:
        object_type = str(item.get("identity", {}).get("object_type", ""))
        states_by_type.setdefault(object_type, Counter())[str(item.get("evidence_state", ""))] += 1
    state_columns = {
        "extracted_complete": "complete",
        "extracted_partial": "partial",
        "metadata_only": "metadata_only",
        "manual_capture_required": "manual_required",
        "blocked": "blocked",
    }
    for item in object_counts:
        object_type = str(item.get("object_type", ""))
        if item.get("total") != actual_by_type.get(object_type, 0):
            errors.append(f"inventory total does not match graph objects for type {object_type}")
        for state, column in state_columns.items():
            if item.get(column) != states_by_type.get(object_type, Counter()).get(state, 0):
                errors.append(
                    f"inventory {column} count does not match graph for type {object_type}"
                )
        category_total = sum(int(item.get(column, 0)) for column in state_columns.values())
        if category_total != item.get("total"):
            errors.append(f"inventory state counts do not sum to total for type {object_type}")
    if set(count_types) != set(actual_by_type):
        errors.append("inventory object counts do not cover every graph object type")

    completion = inventory_snapshot.get("completion", {})
    if completion.get("state") == "complete":
        if not closure_complete or summary.get("status") != "complete":
            errors.append("complete inventory requires complete closure and coverage")
        if completion.get("unresolved_object_ids") or completion.get("manual_capture_request_refs"):
            errors.append(
                "complete inventory contains unresolved objects or manual capture requests"
            )
        unresolved_reconciliations = [
            item
            for item in inventory_snapshot.get("reconciliations", [])
            if item.get("status") == "difference_unresolved"
            or (
                int(item.get("difference_count", 0)) > 0
                and item.get("status") != "difference_explained"
            )
        ]
        if unresolved_reconciliations:
            errors.append("complete inventory contains unresolved count reconciliation")
        reachable_ids = _reachable_object_ids(
            entry_ids=entry_ids,
            edges=edges,
            known_object_ids=known_object_ids,
        )
        missing_required_coverage = reachable_ids - required_coverage_ids
        if missing_required_coverage:
            errors.append(
                "complete inventory has reachable objects without required coverage: "
                f"{sorted(missing_required_coverage)}"
            )
        unreachable_required_coverage = required_coverage_ids - reachable_ids
        if unreachable_required_coverage:
            errors.append(
                "complete inventory has required coverage outside entry dependency closure: "
                f"{sorted(unreachable_required_coverage)}"
            )
        non_blocked_object_ids = {
            object_id
            for object_id, item in object_by_id.items()
            if item.get("evidence_state") != "blocked"
        }
        missing_evidence = non_blocked_object_ids - evidence_object_ids
        if missing_evidence:
            errors.append(
                "complete inventory has non-blocked graph objects without evidence entries: "
                f"{sorted(missing_evidence)}"
            )

    try:
        graph_at = parse_time(str(source_object_graph["generated_at"]))
        evidence_at = parse_time(str(evidence_bundle["created_at"]))
        coverage_at = parse_time(str(coverage_ledger["as_of"]))
        snapshot_at = parse_time(str(inventory_snapshot["as_of"]))
        if not graph_at <= evidence_at <= coverage_at <= snapshot_at:
            errors.append("inventory contract timestamps are not monotonic")
        for item in evidence_entries:
            if parse_time(str(item["captured_at"])) > evidence_at:
                errors.append(
                    f"evidence {item.get('evidence_id')} was captured after bundle creation"
                )
    except (KeyError, ValueError) as exc:
        errors.append(f"inventory contract timestamp is invalid: {exc}")

    return errors


def validate_migration_scope(scope: Mapping[str, Any]) -> list[str]:
    """Validate comparison-versus-migration scope relationships beyond JSON Schema."""

    errors: list[str] = []
    comparison = scope.get("comparison_scope", [])
    migration = scope.get("migration_scope", [])
    exceptions = scope.get("cross_scope_exceptions", [])

    ScopeIdentity = tuple[str, str, str]

    def identities(
        items: Any,
        label: str,
    ) -> tuple[dict[ScopeIdentity, str], set[str]]:
        if not isinstance(items, list):
            errors.append(f"{label} must be an array")
            return {}, set()
        values: list[ScopeIdentity] = []
        object_ids: list[str] = []
        fingerprints: dict[ScopeIdentity, str] = {}
        for item in items:
            if not isinstance(item, Mapping):
                errors.append(f"{label} contains a non-object reference")
                continue
            identity = (
                str(item.get("object_id", "")),
                str(item.get("object_type", "")),
                str(item.get("native_id", "")),
            )
            values.append(identity)
            object_ids.append(identity[0])
            fingerprints[identity] = str(item.get("source_fingerprint", ""))
        if len(values) != len(set(values)) or _duplicates(object_ids):
            errors.append(f"{label} contains duplicate object identities")
        return fingerprints, set(object_ids)

    comparison_by_identity, _ = identities(comparison, "comparison scope")
    migration_by_identity, _ = identities(migration, "migration scope")
    comparison_ids = set(comparison_by_identity)
    migration_ids = set(migration_by_identity)
    mismatched_shared = {
        identity
        for identity in comparison_ids & migration_ids
        if comparison_by_identity[identity] != migration_by_identity[identity]
    }
    if mismatched_shared:
        errors.append(
            "comparison and migration scope fingerprints differ for shared objects: "
            f"{sorted(identity[0] for identity in mismatched_shared)}"
        )

    exception_ids: list[str] = []
    exception_identities: list[ScopeIdentity] = []
    exception_by_identity: dict[ScopeIdentity, Mapping[str, Any]] = {}
    if not isinstance(exceptions, list):
        errors.append("cross-scope exceptions must be an array")
        exceptions = []
    for exception in exceptions:
        if not isinstance(exception, Mapping):
            errors.append("cross-scope exceptions contain a non-object entry")
            continue
        exception_id = str(exception.get("exception_id", ""))
        exception_ids.append(exception_id)
        source_object = exception.get("source_object", {})
        if not isinstance(source_object, Mapping):
            errors.append(f"cross-scope exception {exception_id or 'unknown'} has no source object")
            continue
        identity = (
            str(source_object.get("object_id", "")),
            str(source_object.get("object_type", "")),
            str(source_object.get("native_id", "")),
        )
        exception_identities.append(identity)
        exception_by_identity[identity] = exception
        if exception.get("exception_hash") != cross_scope_exception_hash(exception):
            errors.append(
                f"cross-scope exception {exception_id or 'unknown'} hash is not canonical"
            )
        if not _is_human_decider(str(exception.get("approved_by_ref", ""))):
            errors.append(
                f"cross-scope exception {exception_id or 'unknown'} must be approved by a human"
            )
        try:
            parse_time(str(exception.get("approved_at", "")))
        except ValueError:
            errors.append(
                f"cross-scope exception {exception_id or 'unknown'} approval timestamp is invalid"
            )

    if _duplicates(exception_ids):
        errors.append("cross-scope exceptions contain duplicate exception IDs")
    if len(exception_identities) != len(set(exception_identities)):
        errors.append("cross-scope exceptions contain duplicate source object identities")

    migration_only = migration_ids - comparison_ids
    exception_identity_set = set(exception_by_identity)
    missing_exceptions = migration_only - exception_identity_set
    if missing_exceptions:
        errors.append(
            "migration scope contains objects outside comparison scope without matching "
            "approved exceptions"
        )
    unused_exceptions = exception_identity_set - migration_only
    if unused_exceptions:
        errors.append(
            "cross-scope exceptions are unused by migration-only objects: "
            f"{sorted(identity[0] for identity in unused_exceptions)}"
        )
    for identity in migration_only & exception_identity_set:
        exception_source = exception_by_identity[identity].get("source_object", {})
        exception_fingerprint = (
            str(exception_source.get("source_fingerprint", ""))
            if isinstance(exception_source, Mapping)
            else ""
        )
        if exception_fingerprint != migration_by_identity[identity]:
            errors.append(
                "cross-scope exception source fingerprint does not match migration scope "
                f"for object {identity[0]}"
            )

    unit_objects: set[ScopeIdentity] = set()
    for wave in scope.get("waves", []):
        if not isinstance(wave, Mapping):
            continue
        for unit in wave.get("units", []):
            if not isinstance(unit, Mapping):
                continue
            for item in unit.get("source_objects", []):
                if isinstance(item, Mapping):
                    unit_objects.add(
                        (
                            str(item.get("object_id", "")),
                            str(item.get("object_type", "")),
                            str(item.get("native_id", "")),
                        )
                    )
    if unit_objects - migration_ids:
        errors.append("migration units contain source objects outside migration scope")
    return errors


def _is_human_decider(reference: str) -> bool:
    return urlsplit(reference).scheme.lower() in {"human-ref", "person-ref", "person"}


def _reference_identity(reference: str) -> str:
    parsed = urlsplit(reference)
    return "/".join(part for part in (parsed.netloc, parsed.path.strip("/")) if part)


def _is_independent_qa_verifier(reference: str) -> bool:
    if _is_human_decider(reference):
        return True
    parsed = urlsplit(reference)
    identity = _reference_identity(reference).replace("-", "_")
    return parsed.scheme.lower() == "agent-ref" and identity == "migration_qa"


def _record_value(record: Any, key: str, default: Any = None) -> Any:
    if isinstance(record, Mapping):
        return record.get(key, default)
    return getattr(record, key, default)


def _content_hash(value: Any) -> str:
    result = str(value or "")
    return result.removeprefix("sha256:")


def _watermark_is_typed(value: Any) -> bool:
    if not isinstance(value, Mapping):
        return False
    kind = value.get("kind")
    raw_value = value.get("value")
    if kind == "timestamp":
        try:
            parse_time(str(raw_value))
        except ValueError:
            return False
        return True
    if kind == "batch_id":
        return isinstance(raw_value, str) and bool(raw_value.strip())
    if kind == "snapshot_ref":
        return isinstance(raw_value, str) and bool(urlsplit(raw_value).scheme)
    return False


def validate_qa_result(
    qa_result: Mapping[str, Any],
    *,
    now: datetime | None = None,
    expected_tenant_ref: str | None = None,
    expected_run_id: str | None = None,
    expected_validation_cycle_id: str | None = None,
    expected_source_environment_ref: str | None = None,
    expected_target_environment_ref: str | None = None,
    expected_promotion_bundle_fingerprint: str | None = None,
    artifacts: Sequence[Any] = (),
    require_registered_artifacts: bool = False,
    require_typed_watermarks: bool = True,
) -> list[str]:
    """Validate independent QA semantics and exact artifact observations.

    JSON Schema owns the field shapes. This function owns relationships that JSON
    Schema cannot express: verifier/producer separation, partition binding, artifact
    revision and hash identity, snapshot comparability, and current decision timing.
    """

    errors: list[str] = []
    result_id = str(qa_result.get("qa_result_id") or "unknown")
    if expected_tenant_ref is not None and qa_result.get("tenant_ref") != expected_tenant_ref:
        errors.append(f"QA result {result_id} is missing or crosses tenant partition")
    if expected_run_id is not None and qa_result.get("run_id") != expected_run_id:
        errors.append(f"QA result {result_id} is missing or crosses run partition")
    if (
        expected_validation_cycle_id is not None
        and qa_result.get("validation_cycle_id") != expected_validation_cycle_id
    ):
        errors.append(f"QA result {result_id} belongs to a stale validation cycle")

    verifier_ref = str(qa_result.get("verifier_ref", ""))
    producer_refs = {str(value) for value in qa_result.get("producer_refs", [])}
    if not _is_independent_qa_verifier(verifier_ref):
        errors.append(f"QA result {result_id} lacks an independent QA verifier")
    if not producer_refs:
        errors.append(f"QA result {result_id} does not identify artifact producers")
    if verifier_ref in producer_refs:
        errors.append(f"QA result {result_id} is self-certified by an artifact producer")

    artifacts_by_ref = {
        str(_record_value(artifact, "ref")): artifact
        for artifact in artifacts
        if _record_value(artifact, "ref")
    }
    latest_revisions: dict[str, int] = {}
    for artifact in artifacts:
        artifact_id = str(_record_value(artifact, "artifact_id", ""))
        revision = int(_record_value(artifact, "revision", 0) or 0)
        if artifact_id:
            latest_revisions[artifact_id] = max(revision, latest_revisions.get(artifact_id, 0))

    observations: dict[str, Mapping[str, Any]] = {}
    for side_name in ("source", "target"):
        side = qa_result.get(side_name)
        if not isinstance(side, Mapping):
            errors.append(f"QA result {result_id} lacks {side_name} artifact revision identity")
            continue
        observations[side_name] = side
        artifact_ref = str(side.get("artifact_ref", ""))
        try:
            revision = int(side.get("revision", 0))
        except (TypeError, ValueError):
            revision = 0
        if not artifact_ref or revision < 1:
            errors.append(f"QA result {result_id} lacks {side_name} artifact revision identity")
        watermark = side.get("watermark")
        if require_typed_watermarks and not _watermark_is_typed(watermark):
            errors.append(f"QA result {result_id} has an untyped {side_name} watermark")
        elif not require_typed_watermarks and not watermark:
            errors.append(f"QA result {result_id} lacks a {side_name} watermark")
        artifact = artifacts_by_ref.get(artifact_ref)
        if artifact is None:
            if require_registered_artifacts:
                errors.append(f"QA result {result_id} references an unknown {side_name} artifact")
            continue
        artifact_revision = int(_record_value(artifact, "revision", 0) or 0)
        artifact_id = str(_record_value(artifact, "artifact_id", ""))
        artifact_producer = str(_record_value(artifact, "producer_ref", ""))
        if revision != artifact_revision:
            errors.append(f"QA result {result_id} has the wrong {side_name} artifact revision")
        if latest_revisions.get(artifact_id) != artifact_revision:
            errors.append(f"QA result {result_id} relies on a superseded {side_name} revision")
        if _content_hash(side.get("content_sha256")) != _content_hash(
            _record_value(artifact, "content_sha256", "")
        ):
            errors.append(f"QA result {result_id} has the wrong {side_name} artifact hash")
        if artifact_producer not in producer_refs:
            errors.append(f"QA result {result_id} omits its {side_name} artifact producer identity")
        if verifier_ref == artifact_producer:
            errors.append(f"QA result {result_id} is verified by its {side_name} producer")
        artifact_cycle = str(_record_value(artifact, "validation_cycle_id", ""))
        if artifact_cycle and artifact_cycle != str(qa_result.get("validation_cycle_id", "")):
            errors.append(f"QA result {result_id} observes a stale {side_name} artifact cycle")

    source = observations.get("source", {})
    target = observations.get("target", {})
    source_snapshot = source.get("logical_snapshot_id")
    target_snapshot = target.get("logical_snapshot_id")
    if not source_snapshot or source_snapshot != target_snapshot:
        errors.append(f"QA result {result_id} compares different logical snapshots")
    if (
        expected_source_environment_ref is not None
        and source.get("environment_ref") != expected_source_environment_ref
    ):
        errors.append(f"QA result {result_id} observes the wrong source environment")
    if (
        expected_target_environment_ref is not None
        and target.get("environment_ref") != expected_target_environment_ref
    ):
        errors.append(f"QA result {result_id} observes the wrong target environment")

    gate_id = str(qa_result.get("gate_id", ""))
    if gate_id == "query_parity" and not qa_result.get("tolerances"):
        errors.append(f"QA result {result_id} lacks approved query tolerances")
    if gate_id == "production_validation":
        if (
            source.get("environment_tier") != "production"
            or target.get("environment_tier") != "production"
        ):
            errors.append(f"QA result {result_id} does not validate production environments")
        promotion_fingerprint = qa_result.get("promotion_bundle_fingerprint")
        if not promotion_fingerprint:
            errors.append(f"QA result {result_id} lacks a production promotion fingerprint")
        elif (
            expected_promotion_bundle_fingerprint is not None
            and promotion_fingerprint != expected_promotion_bundle_fingerprint
        ):
            errors.append(f"QA result {result_id} validates a different promotion bundle")

    result = qa_result.get("result")
    checks = list(qa_result.get("checks", []))
    if result in {"passed", "accepted"}:
        if not checks or any(check.get("outcome") != "passed" for check in checks):
            errors.append(f"QA result {result_id} claims acceptance with non-passing checks")
        if not qa_result.get("evidence_refs"):
            errors.append(f"QA result {result_id} claims acceptance without evidence")
        if qa_result.get("blockers"):
            errors.append(f"QA result {result_id} claims acceptance with blockers")
    elif result == "failed" and not any(check.get("outcome") == "failed" for check in checks):
        errors.append(f"QA result {result_id} claims failure without a failed check")
    elif result == "blocked" and not qa_result.get("blockers"):
        errors.append(f"QA result {result_id} claims blocked without blockers")
    elif result == "accepted_with_approved_exceptions":
        waiver = qa_result.get("waiver_decision")
        if not isinstance(waiver, Mapping):
            errors.append(f"QA result {result_id} lacks an approved exception decision")
        else:
            if waiver.get("action") != "accept_qa_exception":
                errors.append(f"QA result {result_id} has a waiver for the wrong action")
            if not _is_human_decider(str(waiver.get("decided_by_ref", ""))):
                errors.append(f"QA result {result_id} waiver is not human-resolved")
            if _content_hash(waiver.get("artifact_fingerprint")) != _content_hash(
                target.get("content_sha256")
            ):
                errors.append(f"QA result {result_id} waiver is bound to another artifact")
            if now is not None:
                try:
                    decided_at = parse_time(str(waiver["decided_at"]))
                    expires_at = parse_time(str(waiver["expires_at"]))
                    current = now.astimezone(timezone.utc)
                    if decided_at > current or expires_at <= current or decided_at >= expires_at:
                        errors.append(f"QA result {result_id} waiver is not currently valid")
                except (KeyError, ValueError) as exc:
                    errors.append(f"QA result {result_id} waiver timing is invalid: {exc}")

    try:
        executed_at = parse_time(str(qa_result["executed_at"]))
        if now is not None and executed_at > now.astimezone(timezone.utc):
            errors.append(f"QA result {result_id} is future-dated")
        for side_name, side in observations.items():
            if parse_time(str(side["observed_at"])) > executed_at:
                errors.append(
                    f"QA result {result_id} was executed before its {side_name} observation"
                )
    except (KeyError, ValueError) as exc:
        errors.append(f"QA result {result_id} has invalid observation timing: {exc}")

    return errors


def validate_migration_lifecycle(
    lifecycle: Mapping[str, Any],
    *,
    now: datetime,
    expected_run_id: str | None = None,
    expected_scope_ref: str | None = None,
    expected_source_fingerprint: str | None = None,
    expected_artifact_fingerprint: str | None = None,
) -> list[str]:
    """Validate phase prerequisites and time-bound, release-bound human decisions."""

    errors: list[str] = []
    current = now.astimezone(timezone.utc)
    parallel = lifecycle.get("parallel_run", {})
    cutover = lifecycle.get("cutover", {})
    hypercare = lifecycle.get("hypercare", {})
    decommission = lifecycle.get("source_decommission", {})
    scope_ref = str(lifecycle.get("scope_ref", ""))
    release_fingerprint = cutover.get("target_release_hash")

    if expected_run_id is not None and lifecycle.get("run_id") != expected_run_id:
        errors.append("migration lifecycle crosses the expected run partition")
    if expected_scope_ref is not None and scope_ref != expected_scope_ref:
        errors.append("migration lifecycle crosses the expected scope")
    if (
        expected_source_fingerprint is not None
        and cutover.get("source_snapshot_hash") != expected_source_fingerprint
    ):
        errors.append("migration lifecycle is bound to a different source snapshot")
    if (
        expected_artifact_fingerprint is not None
        and release_fingerprint != expected_artifact_fingerprint
    ):
        errors.append("migration lifecycle is bound to a different release fingerprint")

    def criteria_passed(path: str, criteria: Any) -> bool:
        items = (
            list(criteria)
            if isinstance(criteria, Sequence) and not isinstance(criteria, (str, bytes))
            else []
        )
        if not items:
            errors.append(f"{path} has no criteria")
            return False
        passed = True
        for criterion in items:
            if not isinstance(criterion, Mapping) or criterion.get("status") != "passed":
                passed = False
                errors.append(f"{path} contains an unaccepted criterion")
                continue
            if criterion.get("evidence_required") and not criterion.get("evidence_refs"):
                passed = False
                errors.append(f"{path} contains a passed criterion without evidence")
        return passed

    parallel_status = str(parallel.get("status", ""))
    if parallel_status in {"active", "completed"}:
        criteria_passed("parallel_run.entry_criteria", parallel.get("entry_criteria"))
    if parallel_status == "completed":
        try:
            minimum_cycles = int(parallel.get("minimum_observation_cycles", 0) or 0)
            observed_cycles = int(parallel.get("observed_cycles", 0) or 0)
        except (TypeError, ValueError):
            minimum_cycles = 0
            observed_cycles = 0
            errors.append("completed parallel run has invalid observation-cycle counts")
        if minimum_cycles < 1 or observed_cycles < minimum_cycles:
            errors.append("completed parallel run has not met its minimum observation cycles")
        criteria_passed("parallel_run.exit_criteria", parallel.get("exit_criteria"))
        if not parallel.get("qa_result_refs") or not parallel.get("metric_evidence_refs"):
            errors.append("completed parallel run lacks QA and metric evidence")
        if not parallel.get("acceptance_decision"):
            errors.append("completed parallel run lacks a human acceptance decision")
        if not release_fingerprint:
            errors.append("completed parallel run lacks a current target release fingerprint")

    cutover_status = str(cutover.get("status", ""))
    if cutover_status in {"ready", "authorized", "executing", "accepted"}:
        if parallel_status != "completed" or not parallel.get("acceptance_decision"):
            errors.append("cutover authorization requires an accepted completed parallel run")
    if cutover_status in {"authorized", "executing", "accepted"}:
        if not cutover.get("approval_decision"):
            errors.append("cutover authorization requires a human approval decision")
        if not cutover.get("evidence_refs") or not release_fingerprint:
            errors.append("cutover authorization lacks release evidence or fingerprint")
    if cutover_status == "accepted" and not cutover.get("acceptance_decision"):
        errors.append("accepted cutover lacks a human acceptance decision")

    hypercare_status = str(hypercare.get("status", ""))
    if hypercare_status in {"active", "completed", "extended"} and cutover_status != "accepted":
        errors.append("hypercare cannot advance before cutover acceptance")
    if hypercare_status == "completed":
        criteria_passed("hypercare.exit_criteria", hypercare.get("exit_criteria"))
        if not hypercare.get("metric_evidence_refs"):
            errors.append("completed hypercare lacks metric evidence")
        if not hypercare.get("acceptance_decision"):
            errors.append("completed hypercare lacks a human acceptance decision")

    decommission_status = str(decommission.get("status", ""))
    if decommission_status in {"authorized", "completed"}:
        if hypercare_status != "completed" or not hypercare.get("acceptance_decision"):
            errors.append("source decommission requires accepted completed hypercare")
        if not decommission.get("approval_decision"):
            errors.append("source decommission requires a human approval decision")
        if not decommission.get("source_object_ids") or not decommission.get("evidence_refs"):
            errors.append("source decommission lacks source scope or evidence")

    decisions = (
        (
            "parallel_run.acceptance_decision",
            "accept_parallel_run",
            parallel.get("acceptance_decision"),
        ),
        (
            "cutover.approval_decision",
            "authorize_cutover",
            cutover.get("approval_decision"),
        ),
        (
            "cutover.acceptance_decision",
            "accept_cutover",
            cutover.get("acceptance_decision"),
        ),
        (
            "hypercare.acceptance_decision",
            "accept_hypercare",
            hypercare.get("acceptance_decision"),
        ),
        (
            "source_decommission.approval_decision",
            "authorize_source_decommission",
            decommission.get("approval_decision"),
        ),
    )
    decision_ids: list[str] = []
    decision_refs: list[str] = []
    for path, expected_action, decision in decisions:
        if not isinstance(decision, Mapping):
            continue
        decision_ids.append(str(decision.get("decision_id", "")))
        decision_refs.append(str(decision.get("decision_ref", "")))
        decider = str(decision.get("decided_by_ref", ""))
        if not _is_human_decider(decider):
            errors.append(f"{path} is not resolved by a human actor")
        if decision.get("action") != expected_action:
            errors.append(f"{path} is bound to the wrong lifecycle action")
        if decision.get("scope_ref") != scope_ref:
            errors.append(f"{path} is bound to a different migration scope")
        if not release_fingerprint:
            errors.append(f"{path} lacks a current target release fingerprint")
        elif decision.get("artifact_fingerprint") != release_fingerprint:
            errors.append(f"{path} is bound to a different target release fingerprint")
        try:
            decided_at = parse_time(str(decision["decided_at"]))
            expires_at = parse_time(str(decision["expires_at"]))
            if decided_at > current:
                errors.append(f"{path} is future-dated")
            if expires_at <= current:
                errors.append(f"{path} is expired")
            if decided_at >= expires_at:
                errors.append(f"{path} expires before or when it is decided")
        except (KeyError, ValueError) as exc:
            errors.append(f"{path} has invalid decision timing: {exc}")
    if duplicates := _duplicates(decision_ids):
        errors.append(f"lifecycle reuses decision IDs across actions: {sorted(duplicates)}")
    if duplicates := _duplicates(decision_refs):
        errors.append(f"lifecycle reuses decision references across actions: {sorted(duplicates)}")

    for path, window in (
        ("parallel_run.planned_window", parallel.get("planned_window", {})),
        ("cutover.planned_window", cutover.get("planned_window", {})),
        ("hypercare.planned_window", hypercare.get("planned_window", {})),
    ):
        try:
            if parse_time(str(window["starts_at"])) >= parse_time(str(window["ends_at"])):
                errors.append(f"{path} must end after it starts")
        except (KeyError, ValueError) as exc:
            errors.append(f"{path} is invalid: {exc}")

    return errors

"""Stable source identity and evidence enrichment for migration bundles."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from typing import Any

from pydantic import BaseModel

from omni_migrator.ir.schema import MigrationBundle, SourceEvidence

_IDENTITY_KEYS = {"source_id", "native_source_id", "selection_aliases", "source_locator", "evidence"}


def _scrub_identity(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: _scrub_identity(item)
            for key, item in sorted(value.items())
            if key not in _IDENTITY_KEYS
        }
    if isinstance(value, list):
        return [_scrub_identity(item) for item in value]
    return value


def content_sha256(value: BaseModel | dict[str, Any]) -> str:
    payload = value.model_dump(mode="json") if isinstance(value, BaseModel) else value
    encoded = json.dumps(_scrub_identity(payload), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def stable_source_id(source: str, kind: str, locator: str) -> str:
    digest = hashlib.sha256(f"{source}|{kind}|{locator}".encode("utf-8")).hexdigest()[:24]
    return f"{source}:{kind}:{digest}"


def _evidence(
    locator: str,
    value: BaseModel,
    fingerprints: list[dict[str, Any]],
) -> list[SourceEvidence]:
    content_hash = content_sha256(value)
    if not fingerprints:
        return [SourceEvidence(locator=locator, content_sha256=content_hash, role="derived")]
    return [
        SourceEvidence(
            artifact_name=str(fingerprint.get("name") or "") or None,
            artifact_sha256=str(fingerprint.get("sha256") or "") or None,
            locator=locator,
            content_sha256=content_hash,
            role="bundle_input",
        )
        for fingerprint in fingerprints
    ]


def _assign(value: BaseModel, source: str, kind: str, locator: str, fingerprints: list[dict[str, Any]]) -> None:
    current_locator = getattr(value, "source_locator", None)
    resolved_locator = current_locator or locator
    if not getattr(value, "source_id", None):
        setattr(value, "source_id", stable_source_id(source, kind, resolved_locator))
    if not current_locator:
        setattr(value, "source_locator", resolved_locator)
    if not getattr(value, "evidence", None):
        setattr(value, "evidence", _evidence(resolved_locator, value, fingerprints))


def enrich_bundle_identity(
    bundle: MigrationBundle,
    fingerprints: list[dict[str, Any]] | None = None,
) -> MigrationBundle:
    """Fill missing IDs/evidence without replacing native extractor identity.

    Name-based locators are stable across ordering changes. When duplicate dashboard
    locators occur and no native identifier is available, the content hash is used as
    a deterministic disambiguator rather than an array index.
    """

    source = str(bundle.source)
    source_fingerprints = fingerprints or []

    for view in bundle.model.views:
        view_locator = view.source_locator or f"view:{view.name}"
        _assign(view, source, "view", view_locator, source_fingerprints)
        for field in view.fields:
            field_locator = field.source_locator or f"{view_locator}/field:{field.source_name or field.name}"
            _assign(field, source, "field", field_locator, source_fingerprints)

    for topic in bundle.model.topics:
        topic_locator = topic.source_locator or f"topic:{topic.name}"
        _assign(topic, source, "topic", topic_locator, source_fingerprints)
        for join in topic.joins:
            join_locator = join.source_locator or (
                f"{topic_locator}/join:{join.join_from_view}->{join.join_to_view}:{join.on_sql}"
            )
            _assign(join, source, "join", join_locator, source_fingerprints)

    for requirement in bundle.model.requirements:
        requirement_locator = requirement.source_locator or (
            f"semantic-requirement:{requirement.object_type}:{requirement.name}:"
            f"{content_sha256(requirement)[:12]}"
        )
        _assign(requirement, source, "semantic_requirement", requirement_locator, source_fingerprints)

    dashboard_locators = [dashboard.source_locator or f"dashboard:{dashboard.source_url or dashboard.name}" for dashboard in bundle.dashboards]
    duplicate_dashboard_locators = {locator for locator, count in Counter(dashboard_locators).items() if count > 1}
    for dashboard, base_locator in zip(bundle.dashboards, dashboard_locators, strict=True):
        dashboard_locator = base_locator
        if not dashboard.source_id and base_locator in duplicate_dashboard_locators:
            dashboard_locator = f"{base_locator}#{content_sha256(dashboard)[:16]}"
        _assign(dashboard, source, "dashboard", dashboard_locator, source_fingerprints)

        for filter_index, filter_item in enumerate(dashboard.filters):
            filter_locator = filter_item.source_locator or (
                f"{dashboard_locator}/filter:{filter_item.field}:{filter_item.operator}:"
                f"{content_sha256(filter_item)[:12]}"
            )
            _assign(filter_item, source, "filter", filter_locator, source_fingerprints)

        for tile in dashboard.tiles:
            tile_key = tile.source_locator or tile.title or content_sha256(tile)[:16]
            tile_locator = tile.source_locator or f"{dashboard_locator}/tile:{tile_key}"
            _assign(tile, source, "tile", tile_locator, source_fingerprints)
            if tile.query:
                query_locator = tile.query.source_locator or f"{tile_locator}/query"
                _assign(tile.query, source, "query", query_locator, source_fingerprints)
                for filter_item in tile.query.filters:
                    filter_locator = filter_item.source_locator or (
                        f"{query_locator}/filter:{filter_item.field}:{filter_item.operator}:"
                        f"{content_sha256(filter_item)[:12]}"
                    )
                    _assign(filter_item, source, "filter", filter_locator, source_fingerprints)
                for dynamic_field in tile.query.dynamic_fields:
                    dynamic_locator = dynamic_field.source_locator or (
                        f"{query_locator}/dynamic:{dynamic_field.name}:{content_sha256(dynamic_field)[:12]}"
                    )
                    _assign(dynamic_field, source, "dynamic_field", dynamic_locator, source_fingerprints)

        for binding in dashboard.filter_bindings:
            binding_locator = binding.source_locator or (
                f"{dashboard_locator}/binding:{binding.dashboard_filter_id}->{binding.tile_id}:"
                f"{binding.target_field or 'excluded'}"
            )
            _assign(binding, source, "filter_binding", binding_locator, source_fingerprints)

    return bundle


def assert_bundle_identity(bundle: MigrationBundle) -> None:
    """Reject a bridge result whose public source identity is incomplete."""

    nodes: list[BaseModel] = []
    for view in bundle.model.views:
        nodes.append(view)
        nodes.extend(view.fields)
    for topic in bundle.model.topics:
        nodes.append(topic)
        nodes.extend(topic.joins)
    nodes.extend(bundle.model.requirements)
    for dashboard in bundle.dashboards:
        nodes.append(dashboard)
        nodes.extend(dashboard.filters)
        for tile in dashboard.tiles:
            nodes.append(tile)
            if tile.query:
                nodes.append(tile.query)
                nodes.extend(tile.query.filters)
                nodes.extend(tile.query.dynamic_fields)
        nodes.extend(dashboard.filter_bindings)

    for node in nodes:
        source_id = getattr(node, "source_id", None)
        source_locator = getattr(node, "source_locator", None)
        evidence = getattr(node, "evidence", None)
        if not isinstance(source_id, str) or not source_id.strip():
            raise ValueError("bridge bundle contains an object without source_id")
        if not isinstance(source_locator, str) or not source_locator.strip():
            raise ValueError("bridge bundle contains an object without source_locator")
        if not isinstance(evidence, list) or not evidence:
            raise ValueError("bridge bundle contains an object without source evidence")
        for item in evidence:
            if not item.locator.strip() or len(item.content_sha256) != 64:
                raise ValueError("bridge bundle contains malformed source evidence")

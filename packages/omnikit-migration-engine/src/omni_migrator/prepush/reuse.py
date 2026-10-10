"""Local, typed evidence contract for reusing one existing Omni Topic.

An imported inventory is evidence, not a live API response or permission to write.
No client, token loader, builder, or network dependency belongs in this module.
Compatibility notes are reviewed operator assertions; hashes prove consistency,
not semantic equivalence or the freshness of the target tenant.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


def canonical_hash(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=False, allow_nan=False).encode()).hexdigest()


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, hide_input_in_errors=True)


class TopicField(_Strict):
    kind: Literal["dimension", "measure"]
    hidden: bool
    definition: dict[str, Any] = Field(min_length=1)


class TopicInventory(_Strict):
    schema_version: Literal["omni-topic-inventory.v1"]
    model_id: str
    connection_id: str
    topic_name: str = Field(pattern=r"^[A-Za-z_][A-Za-z0-9_]*$")
    base_view: str = Field(pattern=r"^[A-Za-z_][A-Za-z0-9_]*$")
    captured_at: str = Field(min_length=1, max_length=100)
    evidence_ref: str = Field(min_length=1, max_length=500)
    grain: str = Field(min_length=1, max_length=2000)
    filters: list[dict[str, Any]]
    fields: dict[str, TopicField] = Field(min_length=1, max_length=1000)


class Compatibility(_Strict):
    status: Literal["compatible"]
    grain: str = Field(min_length=1, max_length=2000)
    filters: str = Field(min_length=1, max_length=2000)
    metric: str = Field(min_length=1, max_length=2000)
    joins: str = Field(min_length=1, max_length=2000)


class FieldMapping(_Strict):
    target_field: str
    source_field_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    target_field_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    compatibility: Compatibility


class ExistingTopic(_Strict):
    inventory: TopicInventory
    inventory_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    field_mappings: dict[str, FieldMapping] = Field(min_length=1, max_length=1000)


class ReuseTarget(_Strict):
    model_id: str
    connection_id: str
    document_name: str = Field(min_length=1, max_length=144)
    allowed_changes: Literal["dashboard_only"]
    existing_topic: ExistingTopic


def source_fields(snapshot: dict) -> dict[str, tuple[str, dict, str]]:
    """Stable locators -> (source pointer, original field record, collection kind)."""
    result = {}
    for di, dm in enumerate(snapshot.get("dataModels", [])):
        dm_id = dm.get("dataModelId", dm.get("id", ""))
        for pi, page in enumerate(dm.get("spec", {}).get("pages", [])):
            for ei, element in enumerate(page.get("elements", [])):
                element_id = element.get("elementId", element.get("id", ""))
                for plural, singular, id_key in (("columns", "column", "columnId"), ("metrics", "metric", "metricId")):
                    for fi, field in enumerate(element.get(plural, [])):
                        identity = field.get(id_key, field.get("id", ""))
                        locator = f"data-model:{dm_id}/element:{element_id}/{singular}:{identity}"
                        if not dm_id or not element_id or not identity or locator in result:
                            raise ValueError("Source field identities must be present and unique for Topic reuse.")
                        result[locator] = (f"/dataModels/{di}/spec/pages/{pi}/elements/{ei}/{plural}/{fi}", field, plural)
    return result


def validate_target(target: dict, snapshot: dict) -> dict:
    """Check imported evidence and mappings; return a detached typed dictionary."""
    value = ReuseTarget.model_validate(target).model_dump()
    inventory = value["existing_topic"]["inventory"]
    for key in ("model_id", "connection_id"):
        UUID(value[key])
        if value[key] != inventory[key]:
            raise ValueError("Existing Topic inventory belongs to a different model or connection.")
    if canonical_hash(inventory) != value["existing_topic"]["inventory_sha256"]:
        raise ValueError("Existing Topic inventory hash is stale or invalid.")
    if any(not str(inventory[key]).strip() for key in ("captured_at", "evidence_ref", "grain")):
        raise ValueError("Existing Topic evidence must be substantive, not blank.")
    for reference in inventory["fields"]:
        owner, separator, field = reference.partition(".")
        if (owner != inventory["base_view"] or separator != "." or not field.isascii()
                or not field.replace("_", "a").isalnum() or field[0].isdigit()):
            raise ValueError("This reuse slice requires exact fields from the selected Topic base view.")
    sources = source_fields(snapshot)
    seen = set()
    for locator, binding in value["existing_topic"]["field_mappings"].items():
        if locator not in sources or binding["target_field"] not in inventory["fields"]:
            raise ValueError("Topic mapping references a missing source or target field.")
        raw = sources[locator][1]
        definition = inventory["fields"][binding["target_field"]]
        if binding["source_field_sha256"] != canonical_hash(raw):
            raise ValueError("Topic mapping binds a stale source field definition.")
        if binding["target_field_sha256"] != canonical_hash(definition):
            raise ValueError("Topic mapping binds a stale target field definition.")
        if "hidden" in raw and (type(raw["hidden"]) is not bool or raw["hidden"] != definition["hidden"]):
            raise ValueError("Existing Topic field visibility differs from captured source visibility.")
        if binding["target_field"] in seen:
            raise ValueError("Ambiguous many-to-one source field mappings require separate review.")
        seen.add(binding["target_field"])
        if any(not note.strip() for key, note in binding["compatibility"].items() if key != "status"):
            raise ValueError("Compatibility evidence must explain grain, filters, metric and joins.")
    return value

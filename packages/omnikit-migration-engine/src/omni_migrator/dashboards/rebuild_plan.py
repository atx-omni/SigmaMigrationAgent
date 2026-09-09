"""Immutable, proposal-only dashboard rebuild plans with fail-closed evidence checks."""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from typing import TYPE_CHECKING, Any, Literal, Protocol
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, model_validator

from omni_migrator.control_plane.canonical import parse_time, sha256_json
from omni_migrator.control_plane.records import ArtifactEnvelope
from omni_migrator.semantic.consolidation import (
    ConsolidationDecision,
    consolidation_decision_hash,
    consolidation_input_fingerprint,
)
from omni_migrator.semantic.equivalence import (
    AssessmentValidationContext,
    validate_validation_context,
)
from omni_migrator.semantic.models import SemanticProfile
from omni_migrator.semantic.profiles import validate_semantic_profile
from omni_migrator.semantic.topic_blueprints import (
    TopicBlueprint,
    TopicField,
    TopicMeasure,
    topic_blueprint_hash,
    topic_component_hash,
)

if TYPE_CHECKING:
    from omni_migrator.control_plane.store import AppendOnlyControlPlaneStore

_SHA256_PATTERN = r"^sha256:[a-f0-9]{64}$"
_STABLE_ID_PATTERN = r"^[a-z0-9][a-z0-9._-]{7,127}$"
_NON_SECRET_REF_PATTERN = r"^[A-Za-z][A-Za-z0-9+.-]*:.+$"
_ACTOR_REF_PATTERN = r"^(?:agent-ref|human-ref|person-ref|person):.+$"
_ZERO_HASH = "sha256:" + "0" * 64

ComponentKind = Literal["field", "measure"]
BehaviorKind = Literal[
    "field",
    "measure",
    "grouping",
    "sort",
    "filter",
    "filter_context",
    "control",
    "interaction",
    "drill",
    "visualization",
    "formatting",
    "layout",
    "responsive",
    "security",
    "persona",
    "operation",
]
SpecialBehaviorKind = Literal[
    "app",
    "embed",
    "refresh",
    "freshness",
    "cache",
    "schedule",
    "alert",
    "export",
    "writeback",
    "workflow_side_effect",
    "unsupported_visual",
    "formatting",
    "layout",
    "responsive",
    "security",
    "persona",
]
ResolutionDisposition = Literal[
    "mapped", "external_handoff", "blocked", "approved_exception"
]
BehaviorResolutionStatus = Literal["pending", "accepted", "completed", "blocked"]


def _sha256(value: Any) -> str:
    return f"sha256:{sha256_json(value)}"


class _StrictFrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    @model_validator(mode="after")
    def tuple_items_are_unique(self) -> "_StrictFrozenModel":
        for field_name in type(self).model_fields:
            value = getattr(self, field_name)
            if not isinstance(value, tuple):
                continue
            comparable = [
                item.model_dump(mode="json") if isinstance(item, BaseModel) else item
                for item in value
            ]
            if any(
                item == prior
                for index, item in enumerate(comparable)
                for prior in comparable[:index]
            ):
                raise ValueError(f"{field_name} must contain unique items")
        return self

    @model_validator(mode="after")
    def references_are_non_secret(self) -> "_StrictFrozenModel":
        prohibited = {
            "secret",
            "secret-ref",
            "vault",
            "vault-ref",
            "credential",
            "credential-ref",
        }
        for field_name in type(self).model_fields:
            if not (field_name.endswith("_ref") or field_name.endswith("_refs")):
                continue
            # Topic consumer contracts preserve semantic component identifiers from
            # the accepted Topic contract.  They are identifiers, despite the
            # historical ``*_refs`` field name, and therefore do not carry a URI
            # scheme.  Their exact values are independently bound below.
            if field_name == "topic_component_refs":
                continue
            value = getattr(self, field_name)
            references = value if isinstance(value, tuple) else (value,)
            for reference in references:
                if not isinstance(reference, str):
                    continue
                parsed = urlsplit(reference)
                if (
                    any(character.isspace() for character in reference)
                    or not parsed.scheme
                    or parsed.scheme.lower() in prohibited
                    or parsed.username is not None
                    or parsed.password is not None
                    or parsed.query
                    or parsed.fragment
                    or parsed.scheme.lower() == "http"
                    or (parsed.scheme.lower() == "https" and not parsed.hostname)
                    or (not parsed.netloc and not parsed.path)
                ):
                    raise ValueError(
                        "artifact references must use safe non-secret URI references"
                    )
        return self


class SourceArtifactRevision(_StrictFrozenModel):
    object_type: Literal["page", "card", "query"]
    object_id: str = Field(min_length=1)
    revision_hash: str = Field(pattern=_SHA256_PATTERN)
    evidence_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    evidence_hash: str = Field(pattern=_SHA256_PATTERN)


class SourceBehaviorBinding(_StrictFrozenModel):
    behavior_id: str = Field(pattern=_STABLE_ID_PATTERN)
    kind: BehaviorKind
    revision_hash: str = Field(pattern=_SHA256_PATTERN)
    evidence_refs: tuple[str, ...] = Field(min_length=1)
    behavior_hash: str = Field(pattern=_SHA256_PATTERN)


class QueryBehaviorDenominator(_StrictFrozenModel):
    field_ids: tuple[str, ...]
    measure_ids: tuple[str, ...]
    grouping_ids: tuple[str, ...]
    sort_ids: tuple[str, ...]
    filter_ids: tuple[str, ...]
    filter_context_ids: tuple[str, ...]
    control_ids: tuple[str, ...]
    interaction_ids: tuple[str, ...]
    drill_ids: tuple[str, ...]
    visualization_ids: tuple[str, ...]
    formatting_ids: tuple[str, ...]
    layout_ids: tuple[str, ...]
    responsive_ids: tuple[str, ...]
    security_ids: tuple[str, ...]
    persona_ids: tuple[str, ...]
    operation_ids: tuple[str, ...]
    denominator_hash: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def query_selects_at_least_one_component(self) -> "QueryBehaviorDenominator":
        if not self.field_ids and not self.measure_ids:
            raise ValueError("a query denominator requires a field or measure")
        ids = [
            *self.field_ids,
            *self.measure_ids,
            *self.grouping_ids,
            *self.sort_ids,
            *self.filter_ids,
            *self.filter_context_ids,
            *self.control_ids,
            *self.interaction_ids,
            *self.drill_ids,
            *self.visualization_ids,
            *self.formatting_ids,
            *self.layout_ids,
            *self.responsive_ids,
            *self.security_ids,
            *self.persona_ids,
            *self.operation_ids,
        ]
        if len(ids) != len(set(ids)):
            raise ValueError("query behavior IDs must be unique across categories")
        return self


_BEHAVIOR_FIELDS: tuple[tuple[str, BehaviorKind], ...] = (
    ("field_ids", "field"),
    ("measure_ids", "measure"),
    ("grouping_ids", "grouping"),
    ("sort_ids", "sort"),
    ("filter_ids", "filter"),
    ("filter_context_ids", "filter_context"),
    ("control_ids", "control"),
    ("interaction_ids", "interaction"),
    ("drill_ids", "drill"),
    ("visualization_ids", "visualization"),
    ("formatting_ids", "formatting"),
    ("layout_ids", "layout"),
    ("responsive_ids", "responsive"),
    ("security_ids", "security"),
    ("persona_ids", "persona"),
    ("operation_ids", "operation"),
)


class SourceQueryDenominator(_StrictFrozenModel):
    query: SourceArtifactRevision
    card_id: str = Field(min_length=1)
    placement_ids: tuple[str, ...] = Field(min_length=1)
    source_consumer_id: str = Field(min_length=1)
    source_profile_id: str = Field(pattern=_STABLE_ID_PATTERN)
    source_profile_hash: str = Field(pattern=_SHA256_PATTERN)
    source_profile_asset_id: str = Field(min_length=1)
    decision_ids: tuple[str, ...] = Field(min_length=1)
    behaviors: tuple[SourceBehaviorBinding, ...] = Field(min_length=1)
    behavior_denominator: QueryBehaviorDenominator

    @model_validator(mode="after")
    def behavior_partition_is_exact(self) -> "SourceQueryDenominator":
        if self.query.object_type != "query":
            raise ValueError("source query denominators require a query revision")
        by_id = {item.behavior_id: item for item in self.behaviors}
        if len(by_id) != len(self.behaviors):
            raise ValueError("source query behaviors require unique behavior_id values")
        expected: dict[str, BehaviorKind] = {
            behavior_id: kind
            for field_name, kind in _BEHAVIOR_FIELDS
            for behavior_id in getattr(self.behavior_denominator, field_name)
        }
        if set(by_id) != set(expected):
            raise ValueError("query behavior denominator must partition every source behavior")
        if any(by_id[behavior_id].kind != kind for behavior_id, kind in expected.items()):
            raise ValueError("query behavior category does not match source behavior kind")
        return self


class SourceCardDenominator(_StrictFrozenModel):
    card: SourceArtifactRevision
    query_ids: tuple[str, ...]
    exact_query_set_hash: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def card_revision_is_typed(self) -> "SourceCardDenominator":
        if self.card.object_type != "card":
            raise ValueError("source card denominators require a card revision")
        if self.exact_query_set_hash != _sha256(sorted(self.query_ids)):
            raise ValueError("card exact_query_set_hash does not match query_ids")
        return self


class GridPlacement(_StrictFrozenModel):
    x: int = Field(ge=0)
    y: int = Field(ge=0)
    width: int = Field(gt=0)
    height: int = Field(gt=0)


class SourceCardPlacement(_StrictFrozenModel):
    placement_id: str = Field(pattern=_STABLE_ID_PATTERN)
    page_id: str = Field(min_length=1)
    card_id: str = Field(min_length=1)
    revision_hash: str = Field(pattern=_SHA256_PATTERN)
    evidence_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    evidence_hash: str = Field(pattern=_SHA256_PATTERN)
    grid: GridPlacement
    responsive_behavior: Literal["fixed", "stack", "reflow", "hide"]
    breakpoint_refs: tuple[str, ...] = Field(min_length=1)
    placement_hash: str = Field(pattern=_SHA256_PATTERN)


class SourceSpecialBehavior(_StrictFrozenModel):
    behavior_id: str = Field(pattern=_STABLE_ID_PATTERN)
    kind: SpecialBehaviorKind
    parent_type: Literal["page", "card", "query"]
    parent_id: str = Field(min_length=1)
    revision_hash: str = Field(pattern=_SHA256_PATTERN)
    evidence_refs: tuple[str, ...] = Field(min_length=1)
    behavior_hash: str = Field(pattern=_SHA256_PATTERN)


class SourceDashboardContext(_StrictFrozenModel):
    run_id: str = Field(pattern=_STABLE_ID_PATTERN)
    scope_id: str = Field(pattern=_STABLE_ID_PATTERN)
    migration_unit_id: str = Field(pattern=_STABLE_ID_PATTERN)
    page_id: str = Field(min_length=1)
    validation_context_hash: str = Field(pattern=_SHA256_PATTERN)
    inventory_closure_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    inventory_closure_hash: str = Field(pattern=_SHA256_PATTERN)
    source_graph_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    source_graph_hash: str = Field(pattern=_SHA256_PATTERN)
    coverage_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    coverage_hash: str = Field(pattern=_SHA256_PATTERN)
    evidence_bundle_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    evidence_bundle_hash: str = Field(pattern=_SHA256_PATTERN)
    dashboard_ir_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    dashboard_ir_hash: str = Field(pattern=_SHA256_PATTERN)
    experience_fixture_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    experience_fixture_hash: str = Field(pattern=_SHA256_PATTERN)
    query_fixture_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    query_fixture_hash: str = Field(pattern=_SHA256_PATTERN)
    closure_status: Literal["complete"] = "complete"
    source_query_validation_status: Literal["complete"] = "complete"
    source_card_order: tuple[str, ...]
    source_placement_order: tuple[str, ...]
    context_hash: str = Field(pattern=_SHA256_PATTERN)


class SourceDashboardDenominator(_StrictFrozenModel):
    context: SourceDashboardContext
    page: SourceArtifactRevision
    page_profile_id: str | None = Field(default=None, pattern=_STABLE_ID_PATTERN)
    page_profile_hash: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    page_profile_asset_id: str | None = None
    cards: tuple[SourceCardDenominator, ...] = Field(min_length=1)
    placements: tuple[SourceCardPlacement, ...] = Field(min_length=1)
    queries: tuple[SourceQueryDenominator, ...]
    special_behaviors: tuple[SourceSpecialBehavior, ...]
    denominator_hash: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def page_card_query_partition_is_exact(self) -> "SourceDashboardDenominator":
        if self.page.object_type != "page":
            raise ValueError("dashboard denominator requires one Page revision")
        page_profile_values = (
            self.page_profile_id,
            self.page_profile_hash,
            self.page_profile_asset_id,
        )
        if any(value is not None for value in page_profile_values) and not all(
            value is not None for value in page_profile_values
        ):
            raise ValueError("Page semantic-profile binding must be complete or absent")
        card_ids = [item.card.object_id for item in self.cards]
        query_ids = [item.query.object_id for item in self.queries]
        if len(card_ids) != len(set(card_ids)):
            raise ValueError("dashboard denominator contains duplicate Card IDs")
        if len(query_ids) != len(set(query_ids)):
            raise ValueError("dashboard denominator contains duplicate query IDs")
        placement_ids = [item.placement_id for item in self.placements]
        if len(placement_ids) != len(set(placement_ids)):
            raise ValueError("dashboard denominator contains duplicate placement IDs")
        if (
            set(self.context.source_card_order) != set(card_ids)
            or set(self.context.source_placement_order) != set(placement_ids)
        ):
            raise ValueError("source context order must exactly cover Cards and placements")
        if any(
            placement.page_id != self.page.object_id
            or placement.card_id not in set(card_ids)
            for placement in self.placements
        ):
            raise ValueError("every Card placement must bind the denominator Page and Card")
        if {placement.card_id for placement in self.placements} != set(card_ids):
            raise ValueError("every denominator Card requires at least one Page placement")
        query_by_card: dict[str, set[str]] = {card_id: set() for card_id in card_ids}
        for query in self.queries:
            if query.card_id not in query_by_card:
                raise ValueError("every source query must belong to a denominator Card")
            query_by_card[query.card_id].add(query.query.object_id)
        for card in self.cards:
            if set(card.query_ids) != query_by_card[card.card.object_id]:
                raise ValueError("each Card query set must exactly match source queries")
        placement_ids_by_card = {
            card_id: {
                placement.placement_id
                for placement in self.placements
                if placement.card_id == card_id
            }
            for card_id in card_ids
        }
        if any(
            set(query.placement_ids) != placement_ids_by_card[query.card_id]
            for query in self.queries
        ):
            raise ValueError("each query must bind every exact placement of its source Card")
        special_ids = [item.behavior_id for item in self.special_behaviors]
        if len(special_ids) != len(set(special_ids)):
            raise ValueError("special behaviors require unique behavior_id values")
        query_behaviors = [
            (query.query.object_id, behavior)
            for query in self.queries
            for behavior in query.behaviors
        ]
        query_behavior_ids = [behavior.behavior_id for _, behavior in query_behaviors]
        if len(query_behavior_ids) != len(set(query_behavior_ids)):
            raise ValueError("query behavior IDs must be globally unique within a Page")
        known_parents = {
            "page": {self.page.object_id},
            "card": set(card_ids),
            "query": set(query_ids),
        }
        if any(
            behavior.parent_id not in known_parents[behavior.parent_type]
            for behavior in self.special_behaviors
        ):
            raise ValueError("special behaviors must bind a denominator Page, Card, or query")
        query_behavior_by_id = {
            behavior.behavior_id: (query_id, behavior)
            for query_id, behavior in query_behaviors
        }
        expected_query_kind: dict[SpecialBehaviorKind, BehaviorKind | None] = {
            "app": None,
            "embed": None,
            "refresh": "operation",
            "freshness": "operation",
            "cache": "operation",
            "schedule": "operation",
            "alert": "operation",
            "export": "operation",
            "writeback": "operation",
            "workflow_side_effect": "operation",
            "unsupported_visual": "visualization",
            "formatting": "formatting",
            "layout": "layout",
            "responsive": "responsive",
            "security": "security",
            "persona": "persona",
        }
        for special in self.special_behaviors:
            if special.behavior_id not in query_behavior_by_id:
                continue
            query_id, behavior = query_behavior_by_id[special.behavior_id]
            if (
                special.parent_type != "query"
                or special.parent_id != query_id
                or expected_query_kind[special.kind] != behavior.kind
                or special.revision_hash != behavior.revision_hash
            ):
                raise ValueError(
                    "special query behaviors must match their exact query behavior evidence"
                )
        return self


class DashboardTopicBinding(_StrictFrozenModel):
    blueprint_id: str = Field(pattern=_STABLE_ID_PATTERN)
    blueprint_hash: str = Field(pattern=_SHA256_PATTERN)
    accepted_topic_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    accepted_topic_hash: str = Field(pattern=_SHA256_PATTERN)
    readiness_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    readiness_hash: str = Field(pattern=_SHA256_PATTERN)
    topic_validation_fingerprint: str = Field(pattern=_SHA256_PATTERN)
    component_catalog_hash: str = Field(pattern=_SHA256_PATTERN)


class DashboardProfileBinding(_StrictFrozenModel):
    profile_id: str = Field(pattern=_STABLE_ID_PATTERN)
    profile_hash: str = Field(pattern=_SHA256_PATTERN)
    system: Literal["domo", "dbt", "snowflake", "omni"]
    asset_id: str = Field(min_length=1)


class DashboardDecisionBinding(_StrictFrozenModel):
    decision_id: str = Field(pattern=_STABLE_ID_PATTERN)
    decision_hash: str = Field(pattern=_SHA256_PATTERN)
    input_fingerprint: str = Field(pattern=_SHA256_PATTERN)
    validation_cycle_id: str = Field(pattern=_STABLE_ID_PATTERN)


class TargetDashboardIntent(_StrictFrozenModel):
    dashboard_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    title: str = Field(min_length=1)
    collection_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    content_action: Literal["create_new", "update_existing"]


class PageRebuildMapping(_StrictFrozenModel):
    source_page_id: str = Field(min_length=1)
    source_page_revision_hash: str = Field(pattern=_SHA256_PATTERN)
    target_dashboard_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    source_card_order: tuple[str, ...]
    target_card_order: tuple[str, ...]
    source_placement_ids: tuple[str, ...]
    evidence_refs: tuple[str, ...] = Field(min_length=1)
    mapping_hash: str = Field(pattern=_SHA256_PATTERN)


class TargetTopicComponentRef(_StrictFrozenModel):
    blueprint_id: str = Field(pattern=_STABLE_ID_PATTERN)
    component_id: str = Field(pattern=_STABLE_ID_PATTERN)
    component_kind: ComponentKind
    component_hash: str = Field(pattern=_SHA256_PATTERN)


class FieldSelectionMapping(_StrictFrozenModel):
    source_behavior_id: str = Field(pattern=_STABLE_ID_PATTERN)
    target: TargetTopicComponentRef


class MeasureSelectionMapping(_StrictFrozenModel):
    source_behavior_id: str = Field(pattern=_STABLE_ID_PATTERN)
    target: TargetTopicComponentRef


class GroupingMapping(_StrictFrozenModel):
    source_behavior_id: str = Field(pattern=_STABLE_ID_PATTERN)
    target: TargetTopicComponentRef
    position: int = Field(ge=0)


class SortMapping(_StrictFrozenModel):
    source_behavior_id: str = Field(pattern=_STABLE_ID_PATTERN)
    target: TargetTopicComponentRef
    direction: Literal["ascending", "descending"]
    nulls: Literal["first", "last", "source_default"]
    priority: int = Field(ge=0)


class FilterMapping(_StrictFrozenModel):
    source_behavior_id: str = Field(pattern=_STABLE_ID_PATTERN)
    target: TargetTopicComponentRef
    operator: str = Field(min_length=1)
    stage: Literal["row", "pre_aggregate", "post_aggregate", "dashboard"]
    value_mode: Literal["literal_set", "parameter", "runtime", "user_attribute"]
    value_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)


class FilterContextMapping(_StrictFrozenModel):
    source_behavior_id: str = Field(pattern=_STABLE_ID_PATTERN)
    scope: Literal["page", "card", "query"]
    precedence: int = Field(ge=0)
    applies_to_filter_ids: tuple[str, ...] = Field(min_length=1)
    context_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)


class ControlMapping(_StrictFrozenModel):
    source_behavior_id: str = Field(pattern=_STABLE_ID_PATTERN)
    target: TargetTopicComponentRef
    control_type: Literal["select", "multi_select", "date_range", "input", "toggle"]
    propagation: Literal["all_cards", "selected_cards", "source_card_only"]
    target_card_ids: tuple[str, ...] = Field(min_length=1)
    target_query_ids: tuple[str, ...] = Field(min_length=1)
    default_value_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)


class InteractionMapping(_StrictFrozenModel):
    source_behavior_id: str = Field(pattern=_STABLE_ID_PATTERN)
    interaction_type: Literal[
        "cross_filter", "navigate", "open_url", "select", "custom"
    ]
    source_card_id: str = Field(min_length=1)
    target_card_ids: tuple[str, ...]
    target_query_ids: tuple[str, ...]
    target_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)

    @model_validator(mode="after")
    def interaction_has_a_target(self) -> "InteractionMapping":
        if not self.target_card_ids and not self.target_query_ids:
            raise ValueError("interactions require a target Card or query")
        return self


class DrillMapping(_StrictFrozenModel):
    source_behavior_id: str = Field(pattern=_STABLE_ID_PATTERN)
    ordered_components: tuple[TargetTopicComponentRef, ...] = Field(min_length=1)
    terminal_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)


class VisualizationMapping(_StrictFrozenModel):
    source_behavior_id: str = Field(pattern=_STABLE_ID_PATTERN)
    source_visual_type: str = Field(min_length=1)
    target_visual_type: str | None
    behavior_resolution_id: str | None = Field(default=None, pattern=_STABLE_ID_PATTERN)

    @model_validator(mode="after")
    def visual_is_mapped_or_resolved(self) -> "VisualizationMapping":
        if (self.target_visual_type is None) == (self.behavior_resolution_id is None):
            raise ValueError("visuals require exactly one target or behavior resolution")
        return self


class FormattingMapping(_StrictFrozenModel):
    source_behavior_id: str = Field(pattern=_STABLE_ID_PATTERN)
    format_kind: Literal["number", "currency", "percent", "date", "text", "visual"]
    target_format_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    preserves_value_semantics: Literal[True] = True


class LayoutMapping(_StrictFrozenModel):
    source_behavior_id: str = Field(pattern=_STABLE_ID_PATTERN)
    source_placement_id: str = Field(pattern=_STABLE_ID_PATTERN)
    target_card_id: str = Field(pattern=_STABLE_ID_PATTERN)
    source: GridPlacement
    target: GridPlacement


class ResponsiveMapping(_StrictFrozenModel):
    source_behavior_id: str = Field(pattern=_STABLE_ID_PATTERN)
    behavior: Literal["fixed", "stack", "reflow", "hide"]
    breakpoint_refs: tuple[str, ...] = Field(min_length=1)


class SecurityMapping(_StrictFrozenModel):
    source_behavior_id: str = Field(pattern=_STABLE_ID_PATTERN)
    target_security_domain: str = Field(min_length=1)
    target_policy_refs: tuple[str, ...]
    behavior: Literal["preserved", "approved_change"]
    accepted_difference_ref: str | None

    @model_validator(mode="after")
    def change_requires_difference(self) -> "SecurityMapping":
        if self.behavior == "approved_change" and self.accepted_difference_ref is None:
            raise ValueError("approved security changes require an accepted difference")
        if self.behavior == "preserved" and self.accepted_difference_ref is not None:
            raise ValueError("preserved security cannot carry an accepted difference")
        return self


class PersonaMapping(_StrictFrozenModel):
    source_behavior_id: str = Field(pattern=_STABLE_ID_PATTERN)
    persona_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    access: Literal["allowed", "denied"]
    derived_field_access: Literal["visible", "masked", "hidden", "not_applicable"]


class OperationMapping(_StrictFrozenModel):
    source_behavior_id: str = Field(pattern=_STABLE_ID_PATTERN)
    operation_kind: Literal[
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
    ]
    owner_ref: str = Field(pattern=_ACTOR_REF_PATTERN)
    target_ref: str | None = Field(default=None, pattern=_NON_SECRET_REF_PATTERN)
    behavior_resolution_id: str | None = Field(default=None, pattern=_STABLE_ID_PATTERN)

    @model_validator(mode="after")
    def operation_is_mapped_or_resolved(self) -> "OperationMapping":
        if (self.target_ref is None) == (self.behavior_resolution_id is None):
            raise ValueError("operations require exactly one target or behavior resolution")
        return self


class ContentCardPlacementMapping(_StrictFrozenModel):
    """Exact source-placement reconstruction for one zero-query content Card."""

    source_card_id: str = Field(min_length=1)
    source_card_revision_hash: str = Field(pattern=_SHA256_PATTERN)
    source_placement_id: str = Field(pattern=_STABLE_ID_PATTERN)
    source_placement_revision_hash: str = Field(pattern=_SHA256_PATTERN)
    source_placement_evidence_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    source_placement_evidence_hash: str = Field(pattern=_SHA256_PATTERN)
    target_card_id: str = Field(pattern=_STABLE_ID_PATTERN)
    layout: LayoutMapping | None
    layout_resolution_id: str | None = Field(default=None, pattern=_STABLE_ID_PATTERN)
    responsive: ResponsiveMapping | None
    responsive_resolution_id: str | None = Field(
        default=None, pattern=_STABLE_ID_PATTERN
    )
    evidence_refs: tuple[str, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def placement_dimensions_are_closed(self) -> "ContentCardPlacementMapping":
        if (self.layout is None) == (self.layout_resolution_id is None):
            raise ValueError(
                "content Card placements require exactly one layout mapping or resolution"
            )
        if (self.responsive is None) == (self.responsive_resolution_id is None):
            raise ValueError(
                "content Card placements require exactly one responsive mapping or resolution"
            )
        if self.layout is not None and (
            self.layout.source_placement_id != self.source_placement_id
            or self.layout.target_card_id != self.target_card_id
        ):
            raise ValueError(
                "content Card placement layout must bind its exact placement and target Card"
            )
        return self


class ContentCardOperationMapping(_StrictFrozenModel):
    """Mapped, explicitly inapplicable, or resolved content-Card operation."""

    source_behavior_id: str = Field(pattern=_STABLE_ID_PATTERN)
    source_card_id: str = Field(min_length=1)
    source_card_revision_hash: str = Field(pattern=_SHA256_PATTERN)
    operation_kind: Literal[
        "none",
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
    ]
    owner_ref: str = Field(pattern=_ACTOR_REF_PATTERN)
    disposition: Literal["mapped", "not_applicable", "behavior_resolution"]
    target_ref: str | None = Field(default=None, pattern=_NON_SECRET_REF_PATTERN)
    behavior_resolution_id: str | None = Field(
        default=None, pattern=_STABLE_ID_PATTERN
    )
    evidence_refs: tuple[str, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def operation_disposition_is_exact(self) -> "ContentCardOperationMapping":
        if self.disposition == "not_applicable":
            valid = (
                self.operation_kind == "none"
                and self.target_ref is None
                and self.behavior_resolution_id is None
            )
        elif self.disposition == "mapped":
            valid = (
                self.operation_kind != "none"
                and self.target_ref is not None
                and self.behavior_resolution_id is None
            )
        else:
            valid = (
                self.operation_kind != "none"
                and self.target_ref is None
                and self.behavior_resolution_id is not None
            )
        if not valid:
            raise ValueError("content Card operation fields do not match disposition")
        return self


class ContentCardCompleteness(_StrictFrozenModel):
    """Closed DSH-01 boundary for a text, markdown, or image Card."""

    source_card_id: str = Field(min_length=1)
    source_card_revision_hash: str = Field(pattern=_SHA256_PATTERN)
    source_card_evidence_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    source_card_evidence_hash: str = Field(pattern=_SHA256_PATTERN)
    target_card_id: str = Field(pattern=_STABLE_ID_PATTERN)
    target_card_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    source_placement_ids: tuple[str, ...] = Field(min_length=1)
    placements: tuple[ContentCardPlacementMapping, ...] = Field(min_length=1)
    formatting: tuple[FormattingMapping, ...]
    formatting_resolution_id: str | None = Field(
        default=None, pattern=_STABLE_ID_PATTERN
    )
    security: tuple[SecurityMapping, ...]
    security_resolution_id: str | None = Field(
        default=None, pattern=_STABLE_ID_PATTERN
    )
    personas: tuple[PersonaMapping, ...]
    persona_resolution_id: str | None = Field(
        default=None, pattern=_STABLE_ID_PATTERN
    )
    operations: tuple[ContentCardOperationMapping, ...] = Field(min_length=1)
    evidence_refs: tuple[str, ...] = Field(min_length=1)
    completeness_hash: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def dimensions_are_closed(self) -> "ContentCardCompleteness":
        placement_ids = [item.source_placement_id for item in self.placements]
        if len(placement_ids) != len(set(placement_ids)) or set(
            placement_ids
        ) != set(self.source_placement_ids):
            raise ValueError(
                "content Card completeness must cover every source placement exactly once"
            )
        if (not self.formatting) == (self.formatting_resolution_id is None):
            raise ValueError(
                "content Cards require formatting mappings or one exact resolution"
            )
        if (not self.security) == (self.security_resolution_id is None):
            raise ValueError(
                "content Cards require security mappings or one exact resolution"
            )
        if self.security:
            if len(self.security) != 1 or not self.security[0].target_policy_refs:
                raise ValueError(
                    "mapped content Card security requires one domain with explicit policies"
                )
            if self.security[0].behavior != "preserved":
                raise ValueError(
                    "mapped content Card security must preserve behavior; changes require "
                    "one exact resolution"
                )
        if (not self.personas) == (self.persona_resolution_id is None):
            raise ValueError(
                "content Cards require persona mappings or one exact resolution"
            )
        if self.personas:
            persona_refs = [item.persona_ref for item in self.personas]
            access = {item.access for item in self.personas}
            if len(persona_refs) != len(set(persona_refs)) or access != {
                "allowed",
                "denied",
            }:
                raise ValueError(
                    "mapped content Card personas require unique allowed and denied expectations"
                )
        behavior_ids = [
            *(item.source_behavior_id for item in self.formatting),
            *(item.source_behavior_id for item in self.security),
            *(item.source_behavior_id for item in self.personas),
            *(item.source_behavior_id for item in self.operations),
            *(
                item.layout.source_behavior_id
                for item in self.placements
                if item.layout is not None
            ),
            *(
                item.responsive.source_behavior_id
                for item in self.placements
                if item.responsive is not None
            ),
        ]
        if len(behavior_ids) != len(set(behavior_ids)):
            raise ValueError(
                "content Card completeness requires unique behavior mapping IDs"
            )
        resolution_ids = [
            *(
                item.layout_resolution_id
                for item in self.placements
                if item.layout_resolution_id is not None
            ),
            *(
                item.responsive_resolution_id
                for item in self.placements
                if item.responsive_resolution_id is not None
            ),
            *(
                item.behavior_resolution_id
                for item in self.operations
                if item.behavior_resolution_id is not None
            ),
            *(
                value
                for value in (
                    self.formatting_resolution_id,
                    self.security_resolution_id,
                    self.persona_resolution_id,
                )
                if value is not None
            ),
        ]
        if len(resolution_ids) != len(set(resolution_ids)):
            raise ValueError(
                "one behavior resolution cannot silently cover multiple content dimensions"
            )
        return self


class CardRebuildMapping(_StrictFrozenModel):
    source_card_id: str = Field(min_length=1)
    source_card_revision_hash: str = Field(pattern=_SHA256_PATTERN)
    card_kind: Literal["query", "text", "markdown", "image", "other"]
    source_query_ids: tuple[str, ...]
    source_placement_ids: tuple[str, ...] = Field(min_length=1)
    target_card_id: str = Field(pattern=_STABLE_ID_PATTERN)
    target_card_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    content_ref: str | None = Field(default=None, pattern=_NON_SECRET_REF_PATTERN)
    content_completeness: ContentCardCompleteness | None
    behavior_resolution_id: str | None = Field(default=None, pattern=_STABLE_ID_PATTERN)
    evidence_refs: tuple[str, ...] = Field(min_length=1)
    mapping_hash: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def card_kind_is_explicit(self) -> "CardRebuildMapping":
        if self.card_kind == "query":
            if (
                not self.source_query_ids
                or self.content_ref is not None
                or self.content_completeness is not None
                or self.behavior_resolution_id is not None
            ):
                raise ValueError("query Cards require source queries and no content fallback")
        elif self.card_kind in {"text", "markdown", "image"}:
            if (
                self.source_query_ids
                or self.content_ref is None
                or self.content_completeness is None
                or self.behavior_resolution_id is not None
            ):
                raise ValueError(
                    "content Cards require one content reference and closed completeness"
                )
            completeness = self.content_completeness
            if (
                completeness.source_card_id != self.source_card_id
                or completeness.source_card_revision_hash
                != self.source_card_revision_hash
                or completeness.target_card_id != self.target_card_id
                or completeness.target_card_ref != self.target_card_ref
                or set(completeness.source_placement_ids)
                != set(self.source_placement_ids)
            ):
                raise ValueError(
                    "content Card completeness must bind the exact source and target Card"
                )
        elif (
            self.source_query_ids
            or self.content_ref is not None
            or self.content_completeness is not None
            or self.behavior_resolution_id is None
        ):
            raise ValueError("other Cards require one explicit behavior resolution")
        return self


class ApprovedBehaviorException(_StrictFrozenModel):
    exception_id: str = Field(pattern=_STABLE_ID_PATTERN)
    approval_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    approval_hash: str = Field(pattern=_SHA256_PATTERN)
    rationale: str = Field(min_length=1)


class DashboardConsumerDecisionBinding(_StrictFrozenModel):
    decision_id: str = Field(pattern=_STABLE_ID_PATTERN)
    behavior: Literal["preserved", "approved_change"]
    accepted_difference_ref: str | None

    @model_validator(mode="after")
    def change_has_exact_difference(self) -> "DashboardConsumerDecisionBinding":
        if self.behavior == "approved_change" and self.accepted_difference_ref is None:
            raise ValueError("approved consumer changes require an accepted difference")
        if self.behavior == "preserved" and self.accepted_difference_ref is not None:
            raise ValueError("preserved consumers cannot carry an accepted difference")
        return self


class TopicConsumerContract(_StrictFrozenModel):
    source_consumer_id: str = Field(min_length=1)
    target_consumer_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    topic_component_refs: tuple[str, ...] = Field(min_length=1)
    decision_bindings: tuple[DashboardConsumerDecisionBinding, ...] = Field(min_length=1)
    consumer_hash: str = Field(pattern=_SHA256_PATTERN)


class BehaviorResolution(_StrictFrozenModel):
    resolution_id: str = Field(pattern=_STABLE_ID_PATTERN)
    source_behavior_id: str = Field(pattern=_STABLE_ID_PATTERN)
    behavior_kind: SpecialBehaviorKind
    source_behavior_hash: str = Field(pattern=_SHA256_PATTERN)
    owner_ref: str = Field(pattern=_ACTOR_REF_PATTERN)
    disposition: ResolutionDisposition
    status: BehaviorResolutionStatus
    target_ref: str | None = Field(default=None, pattern=_NON_SECRET_REF_PATTERN)
    handoff_ref: str | None = Field(default=None, pattern=_NON_SECRET_REF_PATTERN)
    blocker_reason: str | None = None
    approved_exception: ApprovedBehaviorException | None
    evidence_refs: tuple[str, ...] = Field(min_length=1)
    resolution_hash: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def disposition_is_typed(self) -> "BehaviorResolution":
        if self.disposition == "mapped":
            valid = (
                self.target_ref is not None
                and self.handoff_ref is None
                and self.blocker_reason is None
                and self.approved_exception is None
            )
        elif self.disposition == "external_handoff":
            valid = (
                self.target_ref is None
                and self.handoff_ref is not None
                and self.blocker_reason is None
                and self.approved_exception is None
            )
        elif self.disposition == "blocked":
            valid = (
                self.target_ref is None
                and self.handoff_ref is None
                and bool(self.blocker_reason)
                and self.approved_exception is None
            )
        else:
            valid = (
                self.target_ref is None
                and self.handoff_ref is None
                and self.blocker_reason is None
                and self.approved_exception is not None
            )
        if not valid:
            raise ValueError("behavior resolution fields do not match disposition")
        if self.disposition == "blocked" and self.status != "blocked":
            raise ValueError("blocked behavior resolutions require blocked status")
        if self.disposition != "blocked" and self.status == "blocked":
            raise ValueError("non-blocked behavior resolutions cannot use blocked status")
        return self


class QueryDisposition(_StrictFrozenModel):
    disposition: Literal["blocked", "approved_exception"]
    owner_ref: str = Field(pattern=_ACTOR_REF_PATTERN)
    blocker_reason: str | None
    approved_exception: ApprovedBehaviorException | None
    evidence_refs: tuple[str, ...] = Field(min_length=1)
    disposition_hash: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def query_disposition_is_typed(self) -> "QueryDisposition":
        if self.disposition == "blocked":
            if not self.blocker_reason or self.approved_exception is not None:
                raise ValueError("blocked queries require only a blocker reason")
        elif self.blocker_reason is not None or self.approved_exception is None:
            raise ValueError("approved query exceptions require exact approval evidence")
        return self


class QueryRebuildMapping(_StrictFrozenModel):
    query_id: str = Field(min_length=1)
    query_revision_hash: str = Field(pattern=_SHA256_PATTERN)
    outcome: Literal["mapped", "blocked", "approved_exception"]
    topic_blueprint_id: str | None = Field(default=None, pattern=_STABLE_ID_PATTERN)
    target_card_id: str | None = Field(default=None, pattern=_STABLE_ID_PATTERN)
    consumer_contract: TopicConsumerContract | None
    query_disposition: QueryDisposition | None
    fields: tuple[FieldSelectionMapping, ...]
    measures: tuple[MeasureSelectionMapping, ...]
    groupings: tuple[GroupingMapping, ...]
    sorts: tuple[SortMapping, ...]
    filters: tuple[FilterMapping, ...]
    filter_contexts: tuple[FilterContextMapping, ...]
    controls: tuple[ControlMapping, ...]
    interactions: tuple[InteractionMapping, ...]
    drills: tuple[DrillMapping, ...]
    visualizations: tuple[VisualizationMapping, ...]
    formatting: tuple[FormattingMapping, ...]
    layouts: tuple[LayoutMapping, ...]
    responsive: tuple[ResponsiveMapping, ...]
    security: tuple[SecurityMapping, ...]
    personas: tuple[PersonaMapping, ...]
    operations: tuple[OperationMapping, ...]
    mapping_hash: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def outcome_is_structurally_closed(self) -> "QueryRebuildMapping":
        categories = (
            self.fields,
            self.measures,
            self.groupings,
            self.sorts,
            self.filters,
            self.filter_contexts,
            self.controls,
            self.interactions,
            self.drills,
            self.visualizations,
            self.formatting,
            self.layouts,
            self.responsive,
            self.security,
            self.personas,
            self.operations,
        )
        if self.outcome == "mapped":
            if (
                self.topic_blueprint_id is None
                or self.target_card_id is None
                or self.consumer_contract is None
                or self.query_disposition is not None
            ):
                raise ValueError("mapped queries require one Topic and no query disposition")
        else:
            if (
                self.topic_blueprint_id is not None
                or self.target_card_id is not None
                or self.consumer_contract is not None
                or self.query_disposition is None
                or self.query_disposition.disposition != self.outcome
                or any(categories)
            ):
                raise ValueError(
                    "blocked or excepted queries require one matching disposition and no mapping"
                )
        for values in categories:
            ids = [item.source_behavior_id for item in values]
            if len(ids) != len(set(ids)):
                raise ValueError("query mapping categories require unique source behavior IDs")
        if len({item.position for item in self.groupings}) != len(self.groupings):
            raise ValueError("groupings require unique positions")
        if len({item.priority for item in self.sorts}) != len(self.sorts):
            raise ValueError("sorts require unique priorities")
        return self


class DashboardPlanProvenance(_StrictFrozenModel):
    producer_ref: Literal["agent-ref://domo_to_omni_architect"]
    source_refs: tuple[str, ...] = Field(min_length=1)
    evidence_refs: tuple[str, ...] = Field(min_length=1)


class DashboardPlanSecurityMetadata(_StrictFrozenModel):
    classification: Literal["internal", "confidential", "restricted"]


class DashboardRebuildPlan(_StrictFrozenModel):
    """One complete dashboard reconstruction proposal; it grants no write authority."""

    contract_version: Literal["domo-to-omni.dashboard-rebuild-plan.v1"] = (
        "domo-to-omni.dashboard-rebuild-plan.v1"
    )
    plan_id: str = Field(pattern=_STABLE_ID_PATTERN)
    run_id: str = Field(pattern=_STABLE_ID_PATTERN)
    scope_id: str = Field(pattern=_STABLE_ID_PATTERN)
    migration_unit_id: str = Field(pattern=_STABLE_ID_PATTERN)
    validation_cycle_id: str = Field(pattern=_STABLE_ID_PATTERN)
    source: SourceDashboardDenominator
    target: TargetDashboardIntent
    page_mapping: PageRebuildMapping
    card_mappings: tuple[CardRebuildMapping, ...] = Field(min_length=1)
    topic_bindings: tuple[DashboardTopicBinding, ...]
    profile_bindings: tuple[DashboardProfileBinding, ...]
    decision_bindings: tuple[DashboardDecisionBinding, ...]
    validation_context: AssessmentValidationContext
    query_mappings: tuple[QueryRebuildMapping, ...]
    behavior_resolutions: tuple[BehaviorResolution, ...]
    proposal_only: Literal[True] = True
    authorizes_build: Literal[False] = False
    authorizes_content_creation: Literal[False] = False
    authorizes_source_decommission: Literal[False] = False
    plan_hash: str = Field(pattern=_SHA256_PATTERN)
    immutable: Literal[True] = True
    provenance: DashboardPlanProvenance
    security_metadata: DashboardPlanSecurityMetadata

    @model_validator(mode="after")
    def references_are_closed(self) -> "DashboardRebuildPlan":
        self._unique_by(self.topic_bindings, "blueprint_id", "topic bindings")
        self._unique_by(self.profile_bindings, "profile_id", "profile bindings")
        self._unique_by(self.decision_bindings, "decision_id", "decision bindings")
        self._unique_by(self.card_mappings, "source_card_id", "Card mappings")
        target_card_ids = [item.target_card_id for item in self.card_mappings]
        if len(target_card_ids) != len(set(target_card_ids)):
            raise ValueError("Card mappings require unique target_card_id values")
        self._unique_by(self.query_mappings, "query_id", "query mappings")
        self._unique_by(
            self.behavior_resolutions, "resolution_id", "behavior resolutions"
        )
        resolution_behavior_ids = [
            item.source_behavior_id for item in self.behavior_resolutions
        ]
        if len(resolution_behavior_ids) != len(set(resolution_behavior_ids)):
            raise ValueError("behavior resolutions require unique source_behavior_id values")
        denominator_queries = {item.query.object_id for item in self.source.queries}
        if {item.query_id for item in self.query_mappings} != denominator_queries:
            raise ValueError("every denominator query must be mapped exactly once")
        denominator_cards = {item.card.object_id: item for item in self.source.cards}
        if {item.source_card_id for item in self.card_mappings} != set(denominator_cards):
            raise ValueError("every denominator Card must be mapped exactly once")
        placements_by_card = {
            card_id: {
                placement.placement_id
                for placement in self.source.placements
                if placement.card_id == card_id
            }
            for card_id in denominator_cards
        }
        placement_by_id = {
            placement.placement_id: placement for placement in self.source.placements
        }
        for mapping in self.card_mappings:
            source_card = denominator_cards[mapping.source_card_id]
            if (
                mapping.source_card_revision_hash != source_card.card.revision_hash
                or mapping.source_query_ids != source_card.query_ids
                or set(mapping.source_placement_ids)
                != placements_by_card[mapping.source_card_id]
            ):
                raise ValueError("Card mappings must bind exact Card/query/placement evidence")
            completeness = mapping.content_completeness
            if completeness is None:
                continue
            if (
                completeness.source_card_evidence_ref != source_card.card.evidence_ref
                or completeness.source_card_evidence_hash
                != source_card.card.evidence_hash
            ):
                raise ValueError(
                    "content Card completeness changed its exact source Card evidence"
                )
            if (
                completeness.completeness_hash
                != content_card_completeness_hash(completeness)
            ):
                raise ValueError("content Card completeness hash is not canonical")
            for placement_mapping in completeness.placements:
                source_placement = placement_by_id.get(
                    placement_mapping.source_placement_id
                )
                if source_placement is None or (
                    placement_mapping.source_card_id != mapping.source_card_id
                    or placement_mapping.source_card_revision_hash
                    != mapping.source_card_revision_hash
                    or placement_mapping.source_placement_revision_hash
                    != source_placement.revision_hash
                    or placement_mapping.source_placement_evidence_ref
                    != source_placement.evidence_ref
                    or placement_mapping.source_placement_evidence_hash
                    != source_placement.evidence_hash
                    or placement_mapping.target_card_id != mapping.target_card_id
                ):
                    raise ValueError(
                        "content Card placement mapping changed its exact source evidence"
                    )
                if placement_mapping.layout is not None and (
                    placement_mapping.layout.source != source_placement.grid
                ):
                    raise ValueError(
                        "content Card layout source geometry differs from placement evidence"
                    )
                if placement_mapping.responsive is not None and (
                    placement_mapping.responsive.behavior
                    != source_placement.responsive_behavior
                    or tuple(placement_mapping.responsive.breakpoint_refs)
                    != tuple(source_placement.breakpoint_refs)
                ):
                    raise ValueError(
                        "content Card responsive mapping differs from placement evidence"
                    )
            if any(
                operation.source_card_id != mapping.source_card_id
                or operation.source_card_revision_hash
                != mapping.source_card_revision_hash
                for operation in completeness.operations
            ):
                raise ValueError(
                    "content Card operations must bind the exact source Card revision"
                )
        if (
            self.page_mapping.source_page_id != self.source.page.object_id
            or self.page_mapping.source_page_revision_hash
            != self.source.page.revision_hash
            or self.page_mapping.target_dashboard_ref != self.target.dashboard_ref
            or self.page_mapping.source_card_order
            != self.source.context.source_card_order
            or tuple(self.page_mapping.target_card_order)
            != tuple(
                next(
                    item.target_card_id
                    for item in self.card_mappings
                    if item.source_card_id == source_card_id
                )
                for source_card_id in self.page_mapping.source_card_order
            )
            or self.page_mapping.source_placement_ids
            != self.source.context.source_placement_order
        ):
            raise ValueError("Page mapping must exactly cover Page/Card/placement order")
        special_behaviors = {
            item.behavior_id: item for item in self.source.special_behaviors
        }
        if set(resolution_behavior_ids) != set(special_behaviors):
            raise ValueError("every special source behavior requires exactly one resolution")
        for resolution in self.behavior_resolutions:
            source = special_behaviors[resolution.source_behavior_id]
            if (
                source.kind != resolution.behavior_kind
                or source.behavior_hash != resolution.source_behavior_hash
            ):
                raise ValueError("behavior resolutions must bind exact special behavior evidence")
        for mapping in self.card_mappings:
            completeness = mapping.content_completeness
            if completeness is None:
                continue
            resolution_expectations = [
                *(
                    (item.layout_resolution_id, "layout", None)
                    for item in completeness.placements
                    if item.layout_resolution_id is not None
                ),
                *(
                    (item.responsive_resolution_id, "responsive", None)
                    for item in completeness.placements
                    if item.responsive_resolution_id is not None
                ),
                *(
                    (
                        item.behavior_resolution_id,
                        item.operation_kind,
                        item.source_behavior_id,
                    )
                    for item in completeness.operations
                    if item.behavior_resolution_id is not None
                ),
                *(
                    (resolution_id, behavior_kind, None)
                    for resolution_id, behavior_kind in (
                        (completeness.formatting_resolution_id, "formatting"),
                        (completeness.security_resolution_id, "security"),
                        (completeness.persona_resolution_id, "persona"),
                    )
                    if resolution_id is not None
                ),
            ]
            for resolution_id, expected_kind, expected_source_behavior_id in (
                resolution_expectations
            ):
                resolution = next(
                    (
                        item
                        for item in self.behavior_resolutions
                        if item.resolution_id == resolution_id
                    ),
                    None,
                )
                source_behavior = (
                    special_behaviors.get(resolution.source_behavior_id)
                    if resolution is not None
                    else None
                )
                if (
                    resolution is None
                    or source_behavior is None
                    or source_behavior.parent_type != "card"
                    or source_behavior.parent_id != mapping.source_card_id
                    or resolution.behavior_kind != expected_kind
                    or (
                        expected_source_behavior_id is not None
                        and resolution.source_behavior_id
                        != expected_source_behavior_id
                    )
                ):
                    raise ValueError(
                        "content Card dimension resolution must bind its exact source "
                        "Card, behavior, and dimension"
                    )
        topic_ids = {item.blueprint_id for item in self.topic_bindings}
        if any(
            mapping.topic_blueprint_id not in topic_ids
            for mapping in self.query_mappings
            if mapping.outcome == "mapped"
        ):
            raise ValueError("mapped queries must cite a bound accepted Topic")
        card_by_source_query = {
            query_id: card
            for card in self.card_mappings
            for query_id in card.source_query_ids
        }
        if any(
            mapping.outcome == "mapped"
            and mapping.target_card_id
            != card_by_source_query[mapping.query_id].target_card_id
            for mapping in self.query_mappings
        ):
            raise ValueError("query mappings must target their rebuilt Card")
        if self.source.queries and (
            not self.topic_bindings
            or not self.profile_bindings
            or not self.decision_bindings
        ):
            raise ValueError("query dashboards require Topic, profile, and decision bindings")
        return self

    @staticmethod
    def _unique_by(values: tuple[Any, ...], field: str, label: str) -> None:
        keys = [getattr(item, field) for item in values]
        if len(keys) != len(set(keys)):
            raise ValueError(f"{label} require unique {field} values")


class AcceptedSourceDashboardEvidence(_StrictFrozenModel):
    run_id: str = Field(pattern=_STABLE_ID_PATTERN)
    scope_id: str = Field(pattern=_STABLE_ID_PATTERN)
    migration_unit_id: str = Field(pattern=_STABLE_ID_PATTERN)
    page_id: str = Field(min_length=1)
    page_revision_hash: str = Field(pattern=_SHA256_PATTERN)
    page_profile_id: str | None = Field(default=None, pattern=_STABLE_ID_PATTERN)
    page_profile_hash: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    page_profile_asset_id: str | None = None
    card_ids: tuple[str, ...] = Field(min_length=1)
    placement_ids: tuple[str, ...] = Field(min_length=1)
    query_ids: tuple[str, ...]
    source_context_hash: str = Field(pattern=_SHA256_PATTERN)
    denominator_hash: str = Field(pattern=_SHA256_PATTERN)
    source_artifact_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    source_artifact_content_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    validation_context_hash: str = Field(pattern=_SHA256_PATTERN)
    acceptance_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    acceptance_hash: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def page_profile_binding_is_exact(self) -> "AcceptedSourceDashboardEvidence":
        values = (
            self.page_profile_id,
            self.page_profile_hash,
            self.page_profile_asset_id,
        )
        if any(value is not None for value in values) and not all(
            value is not None for value in values
        ):
            raise ValueError("accepted Page semantic-profile binding must be complete")
        return self


class AcceptedDashboardTopicEvidence(_StrictFrozenModel):
    run_id: str = Field(pattern=_STABLE_ID_PATTERN)
    scope_id: str = Field(pattern=_STABLE_ID_PATTERN)
    blueprint_id: str = Field(pattern=_STABLE_ID_PATTERN)
    blueprint_hash: str = Field(pattern=_SHA256_PATTERN)
    accepted_topic_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    accepted_topic_hash: str = Field(pattern=_SHA256_PATTERN)
    readiness_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    readiness_hash: str = Field(pattern=_SHA256_PATTERN)
    topic_validation_fingerprint: str = Field(pattern=_SHA256_PATTERN)
    registered_blueprint_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    registered_blueprint_hash: str = Field(pattern=_SHA256_PATTERN)
    producer_ref: Literal["agent-ref://domo_to_omni_architect"]
    build_ready: Literal[True] = True
    component_catalog_hash: str = Field(pattern=_SHA256_PATTERN)
    profile_ids: tuple[str, ...] = Field(min_length=1)
    decision_ids: tuple[str, ...] = Field(min_length=1)
    validation_cycle_ids: tuple[str, ...] = Field(min_length=1)
    validation_context_hash: str = Field(pattern=_SHA256_PATTERN)


class RegisteredDashboardTopicEvidence(_StrictFrozenModel):
    run_id: str = Field(pattern=_STABLE_ID_PATTERN)
    scope_id: str = Field(pattern=_STABLE_ID_PATTERN)
    validation_cycle_id: str = Field(pattern=_STABLE_ID_PATTERN)
    blueprint_id: str = Field(pattern=_STABLE_ID_PATTERN)
    blueprint_hash: str = Field(pattern=_SHA256_PATTERN)
    artifact_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    artifact_hash: str = Field(pattern=_SHA256_PATTERN)
    producer_ref: Literal["agent-ref://domo_to_omni_architect"]


class AcceptedDashboardTopicComponent(_StrictFrozenModel):
    run_id: str = Field(pattern=_STABLE_ID_PATTERN)
    scope_id: str = Field(pattern=_STABLE_ID_PATTERN)
    blueprint_id: str = Field(pattern=_STABLE_ID_PATTERN)
    blueprint_hash: str = Field(pattern=_SHA256_PATTERN)
    component_id: str = Field(pattern=_STABLE_ID_PATTERN)
    component_kind: ComponentKind
    component_hash: str = Field(pattern=_SHA256_PATTERN)
    validation_context_hash: str = Field(pattern=_SHA256_PATTERN)
    evidence_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    evidence_hash: str = Field(pattern=_SHA256_PATTERN)


class AcceptedBehaviorResolutionEvidence(_StrictFrozenModel):
    run_id: str = Field(pattern=_STABLE_ID_PATTERN)
    scope_id: str = Field(pattern=_STABLE_ID_PATTERN)
    plan_id: str = Field(pattern=_STABLE_ID_PATTERN)
    resolution_id: str = Field(pattern=_STABLE_ID_PATTERN)
    source_behavior_id: str = Field(pattern=_STABLE_ID_PATTERN)
    source_behavior_hash: str = Field(pattern=_SHA256_PATTERN)
    resolution_hash: str = Field(pattern=_SHA256_PATTERN)
    status: Literal["accepted", "completed"]
    validation_context_hash: str = Field(pattern=_SHA256_PATTERN)
    acceptance_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    acceptance_hash: str = Field(pattern=_SHA256_PATTERN)


class AcceptedQueryDispositionEvidence(_StrictFrozenModel):
    run_id: str = Field(pattern=_STABLE_ID_PATTERN)
    scope_id: str = Field(pattern=_STABLE_ID_PATTERN)
    plan_id: str = Field(pattern=_STABLE_ID_PATTERN)
    query_id: str = Field(min_length=1)
    query_revision_hash: str = Field(pattern=_SHA256_PATTERN)
    disposition_hash: str = Field(pattern=_SHA256_PATTERN)
    validation_context_hash: str = Field(pattern=_SHA256_PATTERN)
    acceptance_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    acceptance_hash: str = Field(pattern=_SHA256_PATTERN)


class AcceptedQueryMappingEvidence(_StrictFrozenModel):
    run_id: str = Field(pattern=_STABLE_ID_PATTERN)
    scope_id: str = Field(pattern=_STABLE_ID_PATTERN)
    plan_id: str = Field(pattern=_STABLE_ID_PATTERN)
    query_id: str = Field(min_length=1)
    query_revision_hash: str = Field(pattern=_SHA256_PATTERN)
    topic_blueprint_id: str = Field(pattern=_STABLE_ID_PATTERN)
    topic_blueprint_hash: str = Field(pattern=_SHA256_PATTERN)
    query_mapping_hash: str = Field(pattern=_SHA256_PATTERN)
    validation_fixture_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    validation_fixture_hash: str = Field(pattern=_SHA256_PATTERN)
    validation_context_hash: str = Field(pattern=_SHA256_PATTERN)
    acceptance_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    acceptance_hash: str = Field(pattern=_SHA256_PATTERN)


class AcceptedDashboardPlanRegistration(_StrictFrozenModel):
    run_id: str = Field(pattern=_STABLE_ID_PATTERN)
    scope_id: str = Field(pattern=_STABLE_ID_PATTERN)
    plan_id: str = Field(pattern=_STABLE_ID_PATTERN)
    migration_unit_id: str = Field(pattern=_STABLE_ID_PATTERN)
    validation_cycle_id: str = Field(pattern=_STABLE_ID_PATTERN)
    page_id: str = Field(min_length=1)
    plan_hash: str = Field(pattern=_SHA256_PATTERN)
    producer_ref: Literal["agent-ref://domo_to_omni_architect"]
    validation_context_hash: str = Field(pattern=_SHA256_PATTERN)
    registration_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    registration_hash: str = Field(pattern=_SHA256_PATTERN)


class DashboardEvidenceSnapshot(_StrictFrozenModel):
    """One durable, current evidence view used by the dashboard validator."""

    snapshot_id: str = Field(pattern=_STABLE_ID_PATTERN)
    tenant_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    run_id: str = Field(pattern=_STABLE_ID_PATTERN)
    scope_id: str = Field(pattern=_STABLE_ID_PATTERN)
    wave_id: str = Field(pattern=_STABLE_ID_PATTERN)
    migration_unit_id: str = Field(pattern=_STABLE_ID_PATTERN)
    validation_cycle_id: str = Field(pattern=_STABLE_ID_PATTERN)
    revision: int = Field(ge=1)
    snapshot_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    supersedes_snapshot_hash: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    validation_context: AssessmentValidationContext
    source_dashboards: tuple[AcceptedSourceDashboardEvidence, ...] = Field(min_length=1)
    topic_blueprints: tuple[TopicBlueprint, ...] = Field(min_length=1)
    registered_topics: tuple[RegisteredDashboardTopicEvidence, ...] = Field(
        min_length=1
    )
    accepted_topics: tuple[AcceptedDashboardTopicEvidence, ...] = Field(min_length=1)
    topic_components: tuple[AcceptedDashboardTopicComponent, ...] = Field(min_length=1)
    profiles: tuple[SemanticProfile, ...] = Field(min_length=1)
    decisions: tuple[ConsolidationDecision, ...] = Field(min_length=1)
    behavior_resolutions: tuple[AcceptedBehaviorResolutionEvidence, ...]
    query_dispositions: tuple[AcceptedQueryDispositionEvidence, ...]
    query_mappings: tuple[AcceptedQueryMappingEvidence, ...]
    plan_registrations: tuple[AcceptedDashboardPlanRegistration, ...] = Field(
        min_length=1
    )
    registered_at: str
    snapshot_hash: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def snapshot_is_partitioned_and_unique(self) -> "DashboardEvidenceSnapshot":
        parse_time(self.registered_at)
        if self.revision == 1 and self.supersedes_snapshot_hash is not None:
            raise ValueError("first dashboard evidence snapshot cannot supersede another")
        if self.revision > 1 and self.supersedes_snapshot_hash is None:
            raise ValueError("later dashboard evidence snapshots require an exact predecessor")

        keyed_collections: tuple[tuple[str, tuple[Any, ...], Any], ...] = (
            (
                "source dashboards",
                self.source_dashboards,
                lambda item: (item.migration_unit_id, item.page_id),
            ),
            (
                "Topic blueprints",
                self.topic_blueprints,
                lambda item: item.blueprint_id,
            ),
            (
                "registered Topics",
                self.registered_topics,
                lambda item: item.blueprint_id,
            ),
            (
                "accepted Topics",
                self.accepted_topics,
                lambda item: item.blueprint_id,
            ),
            (
                "Topic components",
                self.topic_components,
                lambda item: (
                    item.blueprint_id,
                    item.component_id,
                    item.component_kind,
                ),
            ),
            ("profiles", self.profiles, lambda item: item.profile_id),
            ("decisions", self.decisions, lambda item: item.decision_id),
            (
                "behavior resolutions",
                self.behavior_resolutions,
                lambda item: (item.plan_id, item.resolution_id),
            ),
            (
                "query dispositions",
                self.query_dispositions,
                lambda item: (item.plan_id, item.query_id),
            ),
            (
                "query mappings",
                self.query_mappings,
                lambda item: (item.plan_id, item.query_id),
            ),
            (
                "plan registrations",
                self.plan_registrations,
                lambda item: item.plan_id,
            ),
        )
        for label, records, key in keyed_collections:
            keys = [key(item) for item in records]
            if len(keys) != len(set(keys)):
                raise ValueError(f"dashboard evidence snapshot repeats {label}")

        partitioned = (
            *self.source_dashboards,
            *self.topic_blueprints,
            *self.registered_topics,
            *self.accepted_topics,
            *self.topic_components,
            *self.profiles,
            *self.decisions,
            *self.behavior_resolutions,
            *self.query_dispositions,
            *self.query_mappings,
            *self.plan_registrations,
        )
        if any(
            item.run_id != self.run_id or item.scope_id != self.scope_id
            for item in partitioned
        ):
            raise ValueError("dashboard evidence snapshot crosses run or scope partition")
        if any(
            item.validation_cycle_id != self.validation_cycle_id
            for item in (*self.registered_topics, *self.plan_registrations)
        ):
            raise ValueError("dashboard evidence snapshot crosses validation cycle")
        if any(
            item.migration_unit_id != self.migration_unit_id
            for item in (*self.source_dashboards, *self.plan_registrations)
        ):
            raise ValueError("dashboard evidence snapshot crosses migration unit")
        source_page_keys = {
            (item.migration_unit_id, item.page_id) for item in self.source_dashboards
        }
        plan_page_keys = [
            (item.migration_unit_id, item.page_id) for item in self.plan_registrations
        ]
        if len(plan_page_keys) != len(set(plan_page_keys)):
            raise ValueError(
                "dashboard evidence snapshot repeats a plan for one migration-unit Page"
            )
        if unmatched := sorted(set(plan_page_keys) - source_page_keys):
            raise ValueError(
                "dashboard plan registrations lack their exact source Page evidence: "
                f"{unmatched}"
            )
        return self


class DashboardPlanValidationRegistration(_StrictFrozenModel):
    """Durable proof that one registered plan passed the trusted validator."""

    tenant_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    run_id: str = Field(pattern=_STABLE_ID_PATTERN)
    scope_id: str = Field(pattern=_STABLE_ID_PATTERN)
    wave_id: str = Field(pattern=_STABLE_ID_PATTERN)
    validation_cycle_id: str = Field(pattern=_STABLE_ID_PATTERN)
    migration_unit_id: str = Field(pattern=_STABLE_ID_PATTERN)
    page_id: str = Field(min_length=1)
    plan_id: str = Field(pattern=_STABLE_ID_PATTERN)
    plan_hash: str = Field(pattern=_SHA256_PATTERN)
    plan_artifact_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    plan_artifact_content_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    evidence_snapshot_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    evidence_snapshot_hash: str = Field(pattern=_SHA256_PATTERN)
    evidence_snapshot_revision: int = Field(ge=1)
    checked_by_ref: str = Field(pattern=_ACTOR_REF_PATTERN)
    checked_at: str
    status: Literal["valid"] = "valid"
    dashboard_plan_ready: Literal[True] = True
    validation_fingerprint: str = Field(pattern=_SHA256_PATTERN)
    registration_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    registration_hash: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def validation_registration_is_time_aware(
        self,
    ) -> "DashboardPlanValidationRegistration":
        parse_time(self.checked_at)
        if self.validation_fingerprint != self.plan_hash:
            raise ValueError("dashboard validation fingerprint must bind the exact plan")
        return self


class DashboardRebuildEvidenceResolver(Protocol):
    """Trusted control-plane resolver; proposal data cannot mint acceptance."""

    def resolve_current_validation_context(
        self, *, run_id: str, scope_id: str, plan_id: str
    ) -> AssessmentValidationContext | None: ...

    def resolve_accepted_source_dashboard(
        self,
        *,
        run_id: str,
        scope_id: str,
        migration_unit_id: str,
        page_id: str,
    ) -> AcceptedSourceDashboardEvidence | None: ...

    def resolve_current_topic_blueprint(
        self, *, run_id: str, scope_id: str, blueprint_id: str
    ) -> TopicBlueprint | None: ...

    def resolve_accepted_topic_blueprint(
        self, *, run_id: str, scope_id: str, blueprint_id: str
    ) -> AcceptedDashboardTopicEvidence | None: ...

    def resolve_registered_topic_blueprint(
        self, *, run_id: str, scope_id: str, blueprint_id: str
    ) -> RegisteredDashboardTopicEvidence | None: ...

    def resolve_topic_component(
        self,
        *,
        run_id: str,
        scope_id: str,
        blueprint_id: str,
        component_id: str,
        component_kind: ComponentKind,
    ) -> AcceptedDashboardTopicComponent | None: ...

    def resolve_current_profile(
        self, *, run_id: str, scope_id: str, profile_id: str
    ) -> SemanticProfile | None: ...

    def resolve_current_decision(
        self, *, run_id: str, scope_id: str, decision_id: str
    ) -> ConsolidationDecision | None: ...

    def resolve_accepted_behavior_resolution(
        self, *, run_id: str, scope_id: str, plan_id: str, resolution_id: str
    ) -> AcceptedBehaviorResolutionEvidence | None: ...

    def resolve_accepted_query_disposition(
        self, *, run_id: str, scope_id: str, plan_id: str, query_id: str
    ) -> AcceptedQueryDispositionEvidence | None: ...

    def resolve_accepted_query_mapping(
        self, *, run_id: str, scope_id: str, plan_id: str, query_id: str
    ) -> AcceptedQueryMappingEvidence | None: ...

    def resolve_registered_dashboard_plan(
        self, *, run_id: str, scope_id: str, plan_id: str
    ) -> AcceptedDashboardPlanRegistration | None: ...


class DashboardRebuildPlanValidation(_StrictFrozenModel):
    valid: bool
    invalidated: bool
    errors: tuple[str, ...]
    invalidation_reasons: tuple[str, ...]
    dashboard_plan_ready: bool
    authorizes_build: Literal[False] = False
    authorizes_content_creation: Literal[False] = False
    plan_fingerprint: str = Field(pattern=_SHA256_PATTERN)


def source_behavior_hash(
    value: Mapping[str, Any] | SourceBehaviorBinding | SourceSpecialBehavior,
) -> str:
    raw = value.model_dump(mode="json") if isinstance(value, BaseModel) else dict(value)
    material = deepcopy(raw)
    material.pop("behavior_hash", None)
    return _sha256(material)


def source_dashboard_context_hash(
    value: Mapping[str, Any] | SourceDashboardContext,
) -> str:
    raw = value.model_dump(mode="json") if isinstance(value, BaseModel) else dict(value)
    material = deepcopy(raw)
    material.pop("context_hash", None)
    return _sha256(material)


def source_card_placement_hash(
    value: Mapping[str, Any] | SourceCardPlacement,
) -> str:
    raw = value.model_dump(mode="json") if isinstance(value, BaseModel) else dict(value)
    material = deepcopy(raw)
    material.pop("placement_hash", None)
    return _sha256(material)


def query_behavior_denominator_hash(
    value: Mapping[str, Any] | QueryBehaviorDenominator,
) -> str:
    raw = value.model_dump(mode="json") if isinstance(value, BaseModel) else dict(value)
    material = deepcopy(raw)
    material.pop("denominator_hash", None)
    for field_name, _ in _BEHAVIOR_FIELDS:
        material[field_name] = sorted(material.get(field_name, ()))
    return _sha256(material)


def source_dashboard_denominator_hash(
    value: Mapping[str, Any] | SourceDashboardDenominator,
) -> str:
    raw = value.model_dump(mode="json") if isinstance(value, BaseModel) else dict(value)
    material = deepcopy(raw)
    material.pop("denominator_hash", None)
    return _sha256(material)


def behavior_resolution_hash(
    value: Mapping[str, Any] | BehaviorResolution,
) -> str:
    raw = value.model_dump(mode="json") if isinstance(value, BaseModel) else dict(value)
    material = deepcopy(raw)
    material.pop("resolution_hash", None)
    return _sha256(material)


def query_disposition_hash(value: Mapping[str, Any] | QueryDisposition) -> str:
    raw = value.model_dump(mode="json") if isinstance(value, BaseModel) else dict(value)
    material = deepcopy(raw)
    material.pop("disposition_hash", None)
    return _sha256(material)


def page_rebuild_mapping_hash(
    value: Mapping[str, Any] | PageRebuildMapping,
) -> str:
    raw = value.model_dump(mode="json") if isinstance(value, BaseModel) else dict(value)
    material = deepcopy(raw)
    material.pop("mapping_hash", None)
    return _sha256(material)


def card_rebuild_mapping_hash(
    value: Mapping[str, Any] | CardRebuildMapping,
) -> str:
    raw = value.model_dump(mode="json") if isinstance(value, BaseModel) else dict(value)
    material = deepcopy(raw)
    material.pop("mapping_hash", None)
    return _sha256(material)


def content_card_completeness_hash(
    value: Mapping[str, Any] | ContentCardCompleteness,
) -> str:
    raw = value.model_dump(mode="json") if isinstance(value, BaseModel) else dict(value)
    material = deepcopy(raw)
    material.pop("completeness_hash", None)
    return _sha256(material)


def topic_consumer_contract_hash(
    value: Mapping[str, Any] | TopicConsumerContract,
) -> str:
    raw = value.model_dump(mode="json") if isinstance(value, BaseModel) else dict(value)
    material = deepcopy(raw)
    material.pop("consumer_hash", None)
    return _sha256(material)


def query_rebuild_mapping_hash(
    value: Mapping[str, Any] | QueryRebuildMapping,
) -> str:
    raw = value.model_dump(mode="json") if isinstance(value, BaseModel) else dict(value)
    material = deepcopy(raw)
    material.pop("mapping_hash", None)
    return _sha256(material)


def topic_component_catalog_hash(value: TopicBlueprint) -> str:
    return _sha256(
        sorted(
            (
                {
                    "component_id": item.field_id,
                    "component_kind": "field",
                    "component_hash": topic_component_hash(item),
                }
                for item in value.fields
            ),
            key=lambda item: item["component_id"],
        )
        + sorted(
            (
                {
                    "component_id": item.measure_id,
                    "component_kind": "measure",
                    "component_hash": topic_component_hash(item),
                }
                for item in value.measures
            ),
            key=lambda item: item["component_id"],
        )
    )


def _sort_records(values: Any, key: str) -> tuple[dict[str, Any], ...]:
    records = [deepcopy(dict(item)) for item in values or ()]
    return tuple(sorted(records, key=lambda item: str(item.get(key, ""))))


def _sorted_scalars(values: Any) -> tuple[str, ...]:
    return tuple(sorted(values or ()))


def _tupleize_json_arrays(value: Any) -> Any:
    """Convert JSON arrays to tuples without rewriting any declared fingerprint."""

    if isinstance(value, list):
        return tuple(_tupleize_json_arrays(item) for item in value)
    if isinstance(value, tuple):
        return tuple(_tupleize_json_arrays(item) for item in value)
    if isinstance(value, Mapping):
        return {key: _tupleize_json_arrays(item) for key, item in value.items()}
    return value


_SNAPSHOT_SORT_KEYS: dict[str, Any] = {
    "source_dashboards": lambda item: (
        str(item.get("migration_unit_id", "")),
        str(item.get("page_id", "")),
    ),
    "topic_blueprints": lambda item: str(item.get("blueprint_id", "")),
    "registered_topics": lambda item: str(item.get("blueprint_id", "")),
    "accepted_topics": lambda item: str(item.get("blueprint_id", "")),
    "topic_components": lambda item: (
        str(item.get("blueprint_id", "")),
        str(item.get("component_id", "")),
        str(item.get("component_kind", "")),
    ),
    "profiles": lambda item: str(item.get("profile_id", "")),
    "decisions": lambda item: str(item.get("decision_id", "")),
    "behavior_resolutions": lambda item: (
        str(item.get("plan_id", "")),
        str(item.get("resolution_id", "")),
    ),
    "query_dispositions": lambda item: (
        str(item.get("plan_id", "")),
        str(item.get("query_id", "")),
    ),
    "query_mappings": lambda item: (
        str(item.get("plan_id", "")),
        str(item.get("query_id", "")),
    ),
    "plan_registrations": lambda item: str(item.get("plan_id", "")),
}


def _normalize_dashboard_evidence_snapshot(value: Mapping[str, Any]) -> dict[str, Any]:
    normalized = deepcopy(dict(value))
    for field_name, key in _SNAPSHOT_SORT_KEYS.items():
        records = [deepcopy(dict(item)) for item in normalized.get(field_name, ())]
        normalized[field_name] = tuple(sorted(records, key=key))
    return normalized


def dashboard_evidence_snapshot_hash(
    value: Mapping[str, Any] | DashboardEvidenceSnapshot,
) -> str:
    raw = value.model_dump(mode="json") if isinstance(value, BaseModel) else value
    material = _normalize_dashboard_evidence_snapshot(raw)
    material.pop("snapshot_hash", None)
    return _sha256(material)


def dashboard_evidence_snapshot_content_sha256(
    value: Mapping[str, Any] | DashboardEvidenceSnapshot,
) -> str:
    """Hash the complete finalized snapshot for its immutable artifact envelope."""

    raw = value.model_dump(mode="json") if isinstance(value, BaseModel) else value
    return sha256_json(raw)


def finalize_dashboard_evidence_snapshot(
    value: Mapping[str, Any] | DashboardEvidenceSnapshot,
) -> DashboardEvidenceSnapshot:
    raw = value.model_dump(mode="json") if isinstance(value, BaseModel) else value
    normalized = _normalize_dashboard_evidence_snapshot(raw)
    normalized["snapshot_hash"] = _ZERO_HASH
    draft = DashboardEvidenceSnapshot.model_validate(_tupleize_json_arrays(normalized))
    result = draft.model_dump(mode="json")
    result["snapshot_hash"] = dashboard_evidence_snapshot_hash(result)
    return DashboardEvidenceSnapshot.model_validate(_tupleize_json_arrays(result))


def dashboard_plan_validation_registration_hash(
    value: Mapping[str, Any] | DashboardPlanValidationRegistration,
) -> str:
    raw = value.model_dump(mode="json") if isinstance(value, BaseModel) else value
    material = deepcopy(dict(raw))
    material.pop("registration_hash", None)
    return _sha256(material)


def dashboard_plan_content_sha256(
    value: Mapping[str, Any] | DashboardRebuildPlan,
) -> str:
    raw = value.model_dump(mode="json") if isinstance(value, BaseModel) else value
    return sha256_json(raw)


def _normalize_component_ref(value: Any) -> dict[str, Any]:
    return deepcopy(dict(value))


def _normalize_mapping_records(values: Any) -> tuple[dict[str, Any], ...]:
    records = [deepcopy(dict(item)) for item in values or ()]
    for record in records:
        for field_name in (
            "applies_to_filter_ids",
            "target_card_ids",
            "target_query_ids",
            "target_policy_refs",
        ):
            if field_name in record:
                record[field_name] = _sorted_scalars(record.get(field_name))
        if "breakpoint_refs" in record:
            record["breakpoint_refs"] = tuple(record.get("breakpoint_refs") or ())
        if "target" in record and isinstance(record["target"], Mapping):
            record["target"] = _normalize_component_ref(record["target"])
    return tuple(records)


def _normalize_content_card_completeness(value: Mapping[str, Any]) -> dict[str, Any]:
    content = deepcopy(dict(value))
    content["source_placement_ids"] = _sorted_scalars(
        content.get("source_placement_ids")
    )
    placements = list(
        _sort_records(content.get("placements"), "source_placement_id")
    )
    for placement in placements:
        placement["evidence_refs"] = _sorted_scalars(
            placement.get("evidence_refs")
        )
        responsive = placement.get("responsive")
        if isinstance(responsive, Mapping):
            responsive = deepcopy(dict(responsive))
            responsive["breakpoint_refs"] = tuple(
                responsive.get("breakpoint_refs") or ()
            )
            placement["responsive"] = responsive
    content["placements"] = tuple(placements)
    for field_name in ("formatting", "security", "personas"):
        content[field_name] = _normalize_mapping_records(content.get(field_name))
    operations = list(_sort_records(content.get("operations"), "source_behavior_id"))
    for operation in operations:
        operation["evidence_refs"] = _sorted_scalars(
            operation.get("evidence_refs")
        )
    content["operations"] = tuple(operations)
    content["evidence_refs"] = _sorted_scalars(content.get("evidence_refs"))
    content["completeness_hash"] = content_card_completeness_hash(content)
    return content


def _normalize_source(value: Mapping[str, Any]) -> dict[str, Any]:
    source = deepcopy(dict(value))
    context = source.get("context")
    if isinstance(context, Mapping):
        context = deepcopy(dict(context))
        context["source_card_order"] = tuple(
            context.get("source_card_order") or ()
        )
        context["source_placement_order"] = tuple(
            context.get("source_placement_order") or ()
        )
        context["context_hash"] = source_dashboard_context_hash(context)
        source["context"] = context
    cards = list(_sort_records(source.get("cards"), "card"))
    cards.sort(key=lambda item: str(item.get("card", {}).get("object_id", "")))
    for card in cards:
        card["query_ids"] = tuple(card.get("query_ids") or ())
        card["exact_query_set_hash"] = _sha256(sorted(card["query_ids"]))
    source["cards"] = tuple(cards)
    placements = list(_sort_records(source.get("placements"), "placement_id"))
    for placement in placements:
        placement["breakpoint_refs"] = tuple(
            placement.get("breakpoint_refs") or ()
        )
        placement["placement_hash"] = source_card_placement_hash(placement)
    source["placements"] = tuple(placements)
    queries = list(source.get("queries") or ())
    queries.sort(key=lambda item: str(item.get("query", {}).get("object_id", "")))
    for query in queries:
        query["placement_ids"] = _sorted_scalars(query.get("placement_ids"))
        query["decision_ids"] = _sorted_scalars(query.get("decision_ids"))
        behaviors = list(_sort_records(query.get("behaviors"), "behavior_id"))
        for behavior in behaviors:
            behavior["evidence_refs"] = _sorted_scalars(behavior.get("evidence_refs"))
            behavior["behavior_hash"] = source_behavior_hash(behavior)
        query["behaviors"] = tuple(behaviors)
        denominator = deepcopy(dict(query.get("behavior_denominator", {})))
        for field_name, _ in _BEHAVIOR_FIELDS:
            denominator[field_name] = _sorted_scalars(denominator.get(field_name))
        denominator["denominator_hash"] = query_behavior_denominator_hash(denominator)
        query["behavior_denominator"] = denominator
    source["queries"] = tuple(queries)
    special = list(_sort_records(source.get("special_behaviors"), "behavior_id"))
    for behavior in special:
        behavior["evidence_refs"] = _sorted_scalars(behavior.get("evidence_refs"))
        behavior["behavior_hash"] = source_behavior_hash(behavior)
    source["special_behaviors"] = tuple(special)
    source["denominator_hash"] = source_dashboard_denominator_hash(source)
    return source


_QUERY_MAPPING_ARRAYS = (
    "fields",
    "measures",
    "groupings",
    "sorts",
    "filters",
    "filter_contexts",
    "controls",
    "interactions",
    "drills",
    "visualizations",
    "formatting",
    "layouts",
    "responsive",
    "security",
    "personas",
    "operations",
)


def _normalize_plan(value: Mapping[str, Any]) -> dict[str, Any]:
    result = deepcopy(dict(value))
    if isinstance(result.get("source"), Mapping):
        result["source"] = _normalize_source(result["source"])
    result["topic_bindings"] = _sort_records(
        result.get("topic_bindings"), "blueprint_id"
    )
    result["profile_bindings"] = _sort_records(
        result.get("profile_bindings"), "profile_id"
    )
    result["decision_bindings"] = _sort_records(
        result.get("decision_bindings"), "decision_id"
    )
    page_mapping = result.get("page_mapping")
    if isinstance(page_mapping, Mapping):
        page_mapping = deepcopy(dict(page_mapping))
        page_mapping["source_card_order"] = tuple(
            page_mapping.get("source_card_order") or ()
        )
        page_mapping["target_card_order"] = tuple(
            page_mapping.get("target_card_order") or ()
        )
        page_mapping["source_placement_ids"] = tuple(
            page_mapping.get("source_placement_ids") or ()
        )
        page_mapping["evidence_refs"] = _sorted_scalars(
            page_mapping.get("evidence_refs")
        )
        page_mapping["mapping_hash"] = page_rebuild_mapping_hash(page_mapping)
        result["page_mapping"] = page_mapping
    card_mappings = list(
        _sort_records(result.get("card_mappings"), "source_card_id")
    )
    for card_mapping in card_mappings:
        card_mapping["source_query_ids"] = tuple(
            card_mapping.get("source_query_ids") or ()
        )
        card_mapping["source_placement_ids"] = _sorted_scalars(
            card_mapping.get("source_placement_ids")
        )
        card_mapping["evidence_refs"] = _sorted_scalars(
            card_mapping.get("evidence_refs")
        )
        content_completeness = card_mapping.get("content_completeness")
        if isinstance(content_completeness, Mapping):
            card_mapping["content_completeness"] = (
                _normalize_content_card_completeness(content_completeness)
            )
        card_mapping["mapping_hash"] = card_rebuild_mapping_hash(card_mapping)
    result["card_mappings"] = tuple(card_mappings)
    queries = list(_sort_records(result.get("query_mappings"), "query_id"))
    source_query_revisions = {
        str(item.get("query", {}).get("object_id", "")): str(
            item.get("query", {}).get("revision_hash", "")
        )
        for item in result.get("source", {}).get("queries", ())
    }
    for query in queries:
        query["query_revision_hash"] = source_query_revisions.get(
            str(query.get("query_id", "")), query.get("query_revision_hash")
        )
        consumer = query.get("consumer_contract")
        if isinstance(consumer, Mapping):
            consumer = deepcopy(dict(consumer))
            consumer["topic_component_refs"] = _sorted_scalars(
                consumer.get("topic_component_refs")
            )
            consumer["decision_bindings"] = _sort_records(
                consumer.get("decision_bindings"), "decision_id"
            )
            consumer["consumer_hash"] = topic_consumer_contract_hash(consumer)
            query["consumer_contract"] = consumer
        for field_name in _QUERY_MAPPING_ARRAYS:
            query[field_name] = _normalize_mapping_records(query.get(field_name))
        drills = list(query.get("drills") or ())
        for drill in drills:
            drill["ordered_components"] = tuple(
                _normalize_component_ref(item)
                for item in drill.get("ordered_components", ())
            )
        query["drills"] = tuple(drills)
        disposition = query.get("query_disposition")
        if isinstance(disposition, Mapping):
            disposition = deepcopy(dict(disposition))
            disposition["evidence_refs"] = _sorted_scalars(
                disposition.get("evidence_refs")
            )
            disposition["disposition_hash"] = query_disposition_hash(disposition)
            query["query_disposition"] = disposition
        query["mapping_hash"] = query_rebuild_mapping_hash(query)
    result["query_mappings"] = tuple(queries)
    resolutions = list(
        _sort_records(result.get("behavior_resolutions"), "resolution_id")
    )
    source_behavior_hashes = {
        str(item.get("behavior_id", "")): str(item.get("behavior_hash", ""))
        for item in result.get("source", {}).get("special_behaviors", ())
    }
    for resolution in resolutions:
        resolution["source_behavior_hash"] = source_behavior_hashes.get(
            str(resolution.get("source_behavior_id", "")),
            resolution.get("source_behavior_hash"),
        )
        resolution["evidence_refs"] = _sorted_scalars(
            resolution.get("evidence_refs")
        )
        resolution["resolution_hash"] = behavior_resolution_hash(resolution)
    result["behavior_resolutions"] = tuple(resolutions)
    provenance = result.get("provenance")
    if isinstance(provenance, Mapping):
        provenance = deepcopy(dict(provenance))
        provenance["source_refs"] = _sorted_scalars(provenance.get("source_refs"))
        provenance["evidence_refs"] = _sorted_scalars(
            provenance.get("evidence_refs")
        )
        result["provenance"] = provenance
    return result


def dashboard_rebuild_plan_hash(
    value: Mapping[str, Any] | DashboardRebuildPlan,
) -> str:
    raw = value.model_dump(mode="json") if isinstance(value, BaseModel) else value
    material = _normalize_plan(raw)
    material.pop("plan_hash", None)
    return _sha256(material)


def finalize_dashboard_rebuild_plan(
    value: Mapping[str, Any] | DashboardRebuildPlan,
) -> DashboardRebuildPlan:
    """Normalize and hash a dashboard proposal without granting write authority."""

    raw = value.model_dump(mode="json") if isinstance(value, BaseModel) else value
    result = _normalize_plan(raw)
    result.setdefault(
        "contract_version", "domo-to-omni.dashboard-rebuild-plan.v1"
    )
    result["proposal_only"] = True
    result["authorizes_build"] = False
    result["authorizes_content_creation"] = False
    result["authorizes_source_decommission"] = False
    result["immutable"] = True
    result["plan_hash"] = _ZERO_HASH
    draft = DashboardRebuildPlan.model_validate(result)
    normalized = _normalize_plan(draft.model_dump(mode="json"))
    normalized["plan_hash"] = dashboard_rebuild_plan_hash(normalized)
    return DashboardRebuildPlan.model_validate(normalized)


class StoreBackedDashboardEvidenceResolver:
    """Resolve dashboard evidence only from a verified append-only run ledger."""

    def __init__(
        self,
        *,
        store: AppendOnlyControlPlaneStore,
        tenant_ref: str,
        run_id: str,
        scope_id: str,
        validation_cycle_id: str,
        wave_id: str | None = None,
        migration_unit_id: str | None = None,
    ) -> None:
        from omni_migrator.control_plane.store import AppendOnlyControlPlaneStore

        if type(store) is not AppendOnlyControlPlaneStore:
            raise TypeError("dashboard resolver requires the canonical append-only store")
        records = store.records(tenant_ref, run_id)
        snapshots: list[DashboardEvidenceSnapshot] = []
        for record in records:
            payload = record.get("payload", {})
            if (
                record.get("record_type") != "event"
                or payload.get("event_type")
                != "dashboard_evidence_snapshot_registered"
            ):
                continue
            raw = {key: value for key, value in payload.items() if key != "event_type"}
            try:
                snapshot = DashboardEvidenceSnapshot.model_validate(
                    _tupleize_json_arrays(raw)
                )
            except (TypeError, ValueError) as exc:
                raise ValueError("stored dashboard evidence snapshot is invalid") from exc
            if (
                snapshot.tenant_ref == tenant_ref
                and snapshot.run_id == run_id
                and snapshot.scope_id == scope_id
                and snapshot.validation_cycle_id == validation_cycle_id
                and (wave_id is None or snapshot.wave_id == wave_id)
                and (
                    migration_unit_id is None
                    or snapshot.migration_unit_id == migration_unit_id
                )
            ):
                snapshots.append(snapshot)
        if not snapshots:
            raise ValueError("current dashboard evidence snapshot is unavailable")
        partitions = {
            (item.wave_id, item.migration_unit_id) for item in snapshots
        }
        if len(partitions) != 1:
            raise ValueError(
                "dashboard evidence scope is ambiguous across wave or migration unit"
            )
        snapshot_ids = {item.snapshot_id for item in snapshots}
        if len(snapshot_ids) != 1:
            raise ValueError("dashboard evidence scope has ambiguous snapshot identities")
        snapshots.sort(key=lambda item: item.revision)
        if [item.revision for item in snapshots] != list(
            range(1, len(snapshots) + 1)
        ):
            raise ValueError("dashboard evidence snapshot revisions are not contiguous")
        for index, snapshot in enumerate(snapshots):
            if snapshot.snapshot_hash != dashboard_evidence_snapshot_hash(snapshot):
                raise ValueError("dashboard evidence snapshot hash is not canonical")
            predecessor = snapshots[index - 1] if index else None
            if predecessor is not None and (
                snapshot.supersedes_snapshot_hash != predecessor.snapshot_hash
            ):
                raise ValueError("dashboard evidence snapshot predecessor is stale")
        self.store = store
        self.tenant_ref = tenant_ref
        self.run_id = run_id
        self.scope_id = scope_id
        self.validation_cycle_id = validation_cycle_id
        self.snapshot = snapshots[-1]
        self.wave_id = self.snapshot.wave_id
        self.migration_unit_id = self.snapshot.migration_unit_id
        try:
            store.assert_dashboard_evidence_snapshot_current(self.snapshot)
        except (RuntimeError, TypeError, ValueError) as exc:
            raise ValueError(
                "dashboard evidence snapshot prerequisites are unavailable or stale"
            ) from exc
        self._source_dashboards = {
            (item.migration_unit_id, item.page_id): item
            for item in self.snapshot.source_dashboards
        }
        self._topics = {
            item.blueprint_id: item for item in self.snapshot.topic_blueprints
        }
        self._registered_topics = {
            item.blueprint_id: item for item in self.snapshot.registered_topics
        }
        self._accepted_topics = {
            item.blueprint_id: item for item in self.snapshot.accepted_topics
        }
        self._components = {
            (item.blueprint_id, item.component_id, item.component_kind): item
            for item in self.snapshot.topic_components
        }
        self._profiles = {item.profile_id: item for item in self.snapshot.profiles}
        self._decisions = {item.decision_id: item for item in self.snapshot.decisions}
        self._resolutions = {
            (item.plan_id, item.resolution_id): item
            for item in self.snapshot.behavior_resolutions
        }
        self._query_dispositions = {
            (item.plan_id, item.query_id): item
            for item in self.snapshot.query_dispositions
        }
        self._query_mappings = {
            (item.plan_id, item.query_id): item
            for item in self.snapshot.query_mappings
        }
        self._plan_registrations = {
            item.plan_id: item for item in self.snapshot.plan_registrations
        }

    def _partition_matches(self, *, run_id: str, scope_id: str) -> bool:
        if run_id != self.run_id or scope_id != self.scope_id:
            return False
        try:
            self.store.assert_dashboard_evidence_snapshot_current(self.snapshot)
        except (RuntimeError, TypeError, ValueError):
            return False
        return True

    def resolve_current_validation_context(self, *, run_id: str, scope_id: str, **_):
        return self.snapshot.validation_context if self._partition_matches(
            run_id=run_id, scope_id=scope_id
        ) else None

    def resolve_accepted_source_dashboard(
        self, *, run_id: str, scope_id: str, migration_unit_id: str, page_id: str
    ):
        if not self._partition_matches(run_id=run_id, scope_id=scope_id):
            return None
        return self._source_dashboards.get((migration_unit_id, page_id))

    def resolve_current_topic_blueprint(
        self, *, run_id: str, scope_id: str, blueprint_id: str
    ):
        return self._topics.get(blueprint_id) if self._partition_matches(
            run_id=run_id, scope_id=scope_id
        ) else None

    def resolve_accepted_topic_blueprint(
        self, *, run_id: str, scope_id: str, blueprint_id: str
    ):
        return self._accepted_topics.get(blueprint_id) if self._partition_matches(
            run_id=run_id, scope_id=scope_id
        ) else None

    def resolve_registered_topic_blueprint(
        self, *, run_id: str, scope_id: str, blueprint_id: str
    ):
        return self._registered_topics.get(blueprint_id) if self._partition_matches(
            run_id=run_id, scope_id=scope_id
        ) else None

    def resolve_topic_component(
        self,
        *,
        run_id: str,
        scope_id: str,
        blueprint_id: str,
        component_id: str,
        component_kind: ComponentKind,
    ):
        if not self._partition_matches(run_id=run_id, scope_id=scope_id):
            return None
        return self._components.get((blueprint_id, component_id, component_kind))

    def resolve_current_profile(
        self, *, run_id: str, scope_id: str, profile_id: str
    ):
        return self._profiles.get(profile_id) if self._partition_matches(
            run_id=run_id, scope_id=scope_id
        ) else None

    def resolve_current_decision(
        self, *, run_id: str, scope_id: str, decision_id: str
    ):
        return self._decisions.get(decision_id) if self._partition_matches(
            run_id=run_id, scope_id=scope_id
        ) else None

    def resolve_accepted_behavior_resolution(
        self, *, run_id: str, scope_id: str, plan_id: str, resolution_id: str
    ):
        if not self._partition_matches(run_id=run_id, scope_id=scope_id):
            return None
        return self._resolutions.get((plan_id, resolution_id))

    def resolve_accepted_query_disposition(
        self, *, run_id: str, scope_id: str, plan_id: str, query_id: str
    ):
        if not self._partition_matches(run_id=run_id, scope_id=scope_id):
            return None
        return self._query_dispositions.get((plan_id, query_id))

    def resolve_accepted_query_mapping(
        self, *, run_id: str, scope_id: str, plan_id: str, query_id: str
    ):
        if not self._partition_matches(run_id=run_id, scope_id=scope_id):
            return None
        return self._query_mappings.get((plan_id, query_id))

    def resolve_registered_dashboard_plan(
        self, *, run_id: str, scope_id: str, plan_id: str
    ):
        return self._plan_registrations.get(plan_id) if self._partition_matches(
            run_id=run_id, scope_id=scope_id
        ) else None


def register_validated_dashboard_plan(
    *,
    store: AppendOnlyControlPlaneStore,
    resolver: StoreBackedDashboardEvidenceResolver,
    plan: Mapping[str, Any] | DashboardRebuildPlan,
    plan_artifact: Mapping[str, Any] | ArtifactEnvelope,
    checked_by_ref: str,
    checked_at: str,
    idempotency_key: str,
) -> DashboardPlanValidationRegistration:
    """Validate one current plan against stored evidence, then durably attest it."""

    from omni_migrator.control_plane.store import AppendOnlyControlPlaneStore

    if type(store) is not AppendOnlyControlPlaneStore or resolver.store is not store:
        raise TypeError("dashboard validation must use its exact canonical evidence store")
    dashboard_plan = (
        plan
        if isinstance(plan, DashboardRebuildPlan)
        else DashboardRebuildPlan.model_validate(_tupleize_json_arrays(plan))
    )
    artifact = (
        plan_artifact
        if isinstance(plan_artifact, ArtifactEnvelope)
        else ArtifactEnvelope.from_mapping(plan_artifact)
    )
    artifact.validate(expected_tenant_ref=resolver.tenant_ref, expected_run_id=resolver.run_id)
    producer = urlsplit(artifact.producer_ref)
    producer_identity = "/".join(
        part for part in (producer.netloc, producer.path.strip("/")) if part
    ).replace("-", "_")
    if (
        artifact.artifact_type != "dashboard_rebuild_plan"
        or artifact.migration_unit_id != dashboard_plan.migration_unit_id
        or artifact.validation_cycle_id != dashboard_plan.validation_cycle_id
        or producer.scheme != "agent-ref"
        or producer_identity != "domo_to_omni_architect"
        or artifact.content_sha256 != dashboard_plan_content_sha256(dashboard_plan)
    ):
        raise ValueError("dashboard plan artifact does not bind the exact architect proposal")
    stored_artifacts = [
        record.get("payload", {})
        for record in store.records(resolver.tenant_ref, resolver.run_id)
        if record.get("record_type") == "artifact"
        and record.get("payload", {}).get("artifact_id") == artifact.artifact_id
    ]
    if not any(item.get("ref") == artifact.ref for item in stored_artifacts):
        raise ValueError("dashboard plan artifact is not registered in the trusted store")
    if any(int(item.get("revision", 0)) > artifact.revision for item in stored_artifacts):
        raise ValueError("dashboard plan artifact has been superseded")
    checker = urlsplit(checked_by_ref)
    checker_identity = "/".join(
        part for part in (checker.netloc, checker.path.strip("/")) if part
    ).replace("-", "_")
    if checker.scheme not in {"human-ref", "person-ref"} and not (
        checker.scheme == "agent-ref" and checker_identity == "migration_qa"
    ):
        raise ValueError("dashboard plan validation requires independent QA or a human")
    checked_time = parse_time(checked_at)
    if checked_time < parse_time(artifact.created_at) or checked_time < parse_time(
        resolver.snapshot.registered_at
    ):
        raise ValueError("dashboard plan validation predates its current evidence")
    validation = validate_dashboard_rebuild_plan(
        dashboard_plan, evidence_resolver=resolver
    )
    if not validation.valid or not validation.dashboard_plan_ready:
        raise ValueError(
            "dashboard plan failed trusted validation: "
            f"{[*validation.errors, *validation.invalidation_reasons]}"
        )
    raw = {
        "tenant_ref": resolver.tenant_ref,
        "run_id": dashboard_plan.run_id,
        "scope_id": dashboard_plan.scope_id,
        "wave_id": resolver.snapshot.wave_id,
        "validation_cycle_id": dashboard_plan.validation_cycle_id,
        "migration_unit_id": dashboard_plan.migration_unit_id,
        "page_id": dashboard_plan.source.page.object_id,
        "plan_id": dashboard_plan.plan_id,
        "plan_hash": dashboard_plan.plan_hash,
        "plan_artifact_ref": artifact.ref,
        "plan_artifact_content_sha256": artifact.content_sha256,
        "evidence_snapshot_ref": resolver.snapshot.snapshot_ref,
        "evidence_snapshot_hash": resolver.snapshot.snapshot_hash,
        "evidence_snapshot_revision": resolver.snapshot.revision,
        "checked_by_ref": checked_by_ref,
        "checked_at": checked_at,
        "status": "valid",
        "dashboard_plan_ready": True,
        "validation_fingerprint": validation.plan_fingerprint,
        "registration_ref": (
            f"dashboard-plan-validation-ref://{dashboard_plan.run_id}/"
            f"{dashboard_plan.plan_id}/{dashboard_plan.plan_hash.removeprefix('sha256:')}"
        ),
        "registration_hash": _ZERO_HASH,
    }
    raw["registration_hash"] = dashboard_plan_validation_registration_hash(raw)
    registration = DashboardPlanValidationRegistration.model_validate(raw)
    registered_plans = [
        record.get("payload", {}).get("plan")
        for record in store.records(resolver.tenant_ref, resolver.run_id)
        if record.get("record_type") == "event"
        and record.get("payload", {}).get("event_type")
        == "dashboard_plan_payload_registered"
        and record.get("payload", {}).get("plan", {}).get("plan_id")
        == dashboard_plan.plan_id
    ]
    if not registered_plans:
        store.append_dashboard_plan_payload(
            dashboard_plan,
            artifact,
            idempotency_key=f"{idempotency_key}:plan-payload",
        )
    elif registered_plans != [dashboard_plan.model_dump(mode="json")]:
        raise ValueError("dashboard plan payload registration is stale or ambiguous")
    store.append_dashboard_plan_validation(
        registration,
        idempotency_key=idempotency_key,
    )
    return registration


def _component_ref_errors(
    *,
    component_ref: TargetTopicComponentRef,
    query_topic_id: str,
    plan: DashboardRebuildPlan,
    resolver: DashboardRebuildEvidenceResolver,
    topics: Mapping[str, TopicBlueprint],
    context: AssessmentValidationContext,
) -> tuple[set[str], set[str]]:
    errors: set[str] = set()
    invalidation: set[str] = set()
    if component_ref.blueprint_id != query_topic_id:
        errors.add(
            f"query component crosses its accepted Topic: {component_ref.component_id}"
        )
        return errors, invalidation
    topic = topics.get(component_ref.blueprint_id)
    if topic is None:
        invalidation.add(f"topic_unavailable:{component_ref.blueprint_id}")
        return errors, invalidation
    component: TopicField | TopicMeasure | None
    if component_ref.component_kind == "field":
        component = next(
            (item for item in topic.fields if item.field_id == component_ref.component_id),
            None,
        )
    else:
        component = next(
            (
                item
                for item in topic.measures
                if item.measure_id == component_ref.component_id
            ),
            None,
        )
    if component is None:
        invalidation.add(
            f"topic_component_missing:{component_ref.blueprint_id}:{component_ref.component_id}"
        )
        return errors, invalidation
    expected_hash = topic_component_hash(component)
    if component_ref.component_hash != expected_hash:
        invalidation.add(
            f"topic_component_changed:{component_ref.blueprint_id}:{component_ref.component_id}"
        )
    try:
        accepted = resolver.resolve_topic_component(
            run_id=plan.run_id,
            scope_id=plan.scope_id,
            blueprint_id=component_ref.blueprint_id,
            component_id=component_ref.component_id,
            component_kind=component_ref.component_kind,
        )
    except Exception:
        accepted = None
    if not isinstance(accepted, AcceptedDashboardTopicComponent):
        invalidation.add(
            f"topic_component_acceptance_unavailable:{component_ref.blueprint_id}:"
            f"{component_ref.component_id}"
        )
    elif (
        accepted.run_id != plan.run_id
        or accepted.scope_id != plan.scope_id
        or accepted.blueprint_id != component_ref.blueprint_id
        or accepted.blueprint_hash != topic.blueprint_hash
        or accepted.component_id != component_ref.component_id
        or accepted.component_kind != component_ref.component_kind
        or accepted.component_hash != expected_hash
        or accepted.validation_context_hash != context.context_hash
    ):
        invalidation.add(
            f"topic_component_acceptance_changed:{component_ref.blueprint_id}:"
            f"{component_ref.component_id}"
        )
    return errors, invalidation


def _mapping_behavior_sets(mapping: QueryRebuildMapping) -> dict[str, set[str]]:
    return {
        "field_ids": {item.source_behavior_id for item in mapping.fields},
        "measure_ids": {item.source_behavior_id for item in mapping.measures},
        "grouping_ids": {item.source_behavior_id for item in mapping.groupings},
        "sort_ids": {item.source_behavior_id for item in mapping.sorts},
        "filter_ids": {item.source_behavior_id for item in mapping.filters},
        "filter_context_ids": {
            item.source_behavior_id for item in mapping.filter_contexts
        },
        "control_ids": {item.source_behavior_id for item in mapping.controls},
        "interaction_ids": {
            item.source_behavior_id for item in mapping.interactions
        },
        "drill_ids": {item.source_behavior_id for item in mapping.drills},
        "visualization_ids": {
            item.source_behavior_id for item in mapping.visualizations
        },
        "formatting_ids": {item.source_behavior_id for item in mapping.formatting},
        "layout_ids": {item.source_behavior_id for item in mapping.layouts},
        "responsive_ids": {item.source_behavior_id for item in mapping.responsive},
        "security_ids": {item.source_behavior_id for item in mapping.security},
        "persona_ids": {item.source_behavior_id for item in mapping.personas},
        "operation_ids": {item.source_behavior_id for item in mapping.operations},
    }


def validate_dashboard_rebuild_plan(
    value: Mapping[str, Any] | DashboardRebuildPlan,
    *,
    evidence_resolver: DashboardRebuildEvidenceResolver,
) -> DashboardRebuildPlanValidation:
    """Derive readiness from current trusted evidence; never trust proposal status flags."""

    try:
        raw = (
            value.model_dump(mode="json")
            if isinstance(value, BaseModel)
            else dict(value)
        )
        fallback_hash = dashboard_rebuild_plan_hash(raw)
    except Exception:
        raw = {}
        fallback_hash = _sha256({"invalid_dashboard_plan_shape": True})
    try:
        plan = DashboardRebuildPlan.model_validate(_tupleize_json_arrays(raw))
    except (TypeError, ValueError) as exc:
        return DashboardRebuildPlanValidation(
            valid=False,
            invalidated=True,
            errors=(f"dashboard rebuild plan is invalid: {exc}",),
            invalidation_reasons=("plan_shape_invalid",),
            dashboard_plan_ready=False,
            plan_fingerprint=fallback_hash,
        )

    errors: set[str] = set()
    invalidation: set[str] = set()
    if plan.plan_hash != dashboard_rebuild_plan_hash(plan):
        invalidation.add("plan_hash_changed")
    if plan.source.context.context_hash != source_dashboard_context_hash(
        plan.source.context
    ):
        invalidation.add("source_context_hash_changed")
    if (
        plan.source.context.run_id != plan.run_id
        or plan.source.context.scope_id != plan.scope_id
        or plan.source.context.migration_unit_id != plan.migration_unit_id
        or plan.source.context.page_id != plan.source.page.object_id
        or plan.source.context.validation_context_hash
        != plan.validation_context.context_hash
    ):
        invalidation.add("source_context_partition_changed")
    if plan.page_mapping.mapping_hash != page_rebuild_mapping_hash(
        plan.page_mapping
    ):
        invalidation.add("page_mapping_hash_changed")
    for card_mapping in plan.card_mappings:
        if card_mapping.mapping_hash != card_rebuild_mapping_hash(card_mapping):
            invalidation.add(f"card_mapping_hash_changed:{card_mapping.source_card_id}")
    try:
        current_context = evidence_resolver.resolve_current_validation_context(
            run_id=plan.run_id, scope_id=plan.scope_id, plan_id=plan.plan_id
        )
    except Exception:
        current_context = None
    if not isinstance(current_context, AssessmentValidationContext):
        invalidation.add("trusted_validation_context_unavailable")
        current_context = plan.validation_context
    elif validate_validation_context(current_context):
        invalidation.add("trusted_validation_context_integrity_invalid")
    if plan.validation_context != current_context:
        invalidation.add("validation_context_changed")
    if current_context.inventory_closure.status != "complete":
        errors.add("dashboard planning requires complete source inventory closure")

    if plan.source.denominator_hash != source_dashboard_denominator_hash(plan.source):
        invalidation.add("source_denominator_hash_changed")
    for query in plan.source.queries:
        if query.behavior_denominator.denominator_hash != query_behavior_denominator_hash(
            query.behavior_denominator
        ):
            invalidation.add(
                f"query_behavior_denominator_hash_changed:{query.query.object_id}"
            )
        for behavior in query.behaviors:
            if behavior.behavior_hash != source_behavior_hash(behavior):
                invalidation.add(f"source_behavior_changed:{behavior.behavior_id}")
    for behavior in plan.source.special_behaviors:
        if behavior.behavior_hash != source_behavior_hash(behavior):
            invalidation.add(f"source_special_behavior_changed:{behavior.behavior_id}")
    for placement in plan.source.placements:
        if placement.placement_hash != source_card_placement_hash(placement):
            invalidation.add(f"source_placement_changed:{placement.placement_id}")
    try:
        accepted_source = evidence_resolver.resolve_accepted_source_dashboard(
            run_id=plan.run_id,
            scope_id=plan.scope_id,
            migration_unit_id=plan.migration_unit_id,
            page_id=plan.source.page.object_id,
        )
    except Exception:
        accepted_source = None
    source_card_ids = tuple(
        sorted(card.card.object_id for card in plan.source.cards)
    )
    source_placement_ids = tuple(
        sorted(placement.placement_id for placement in plan.source.placements)
    )
    source_query_ids = tuple(
        sorted(query.query.object_id for query in plan.source.queries)
    )
    if not isinstance(accepted_source, AcceptedSourceDashboardEvidence):
        invalidation.add("source_dashboard_acceptance_unavailable")
    elif (
        accepted_source.run_id != plan.run_id
        or accepted_source.scope_id != plan.scope_id
        or accepted_source.migration_unit_id != plan.migration_unit_id
        or accepted_source.page_id != plan.source.page.object_id
        or accepted_source.page_revision_hash != plan.source.page.revision_hash
        or accepted_source.page_profile_id != plan.source.page_profile_id
        or accepted_source.page_profile_hash != plan.source.page_profile_hash
        or accepted_source.page_profile_asset_id != plan.source.page_profile_asset_id
        or tuple(sorted(accepted_source.card_ids)) != source_card_ids
        or tuple(sorted(accepted_source.placement_ids)) != source_placement_ids
        or tuple(sorted(accepted_source.query_ids)) != source_query_ids
        or accepted_source.source_context_hash != plan.source.context.context_hash
        or accepted_source.denominator_hash != plan.source.denominator_hash
        or accepted_source.validation_context_hash != current_context.context_hash
    ):
        invalidation.add("source_dashboard_acceptance_changed")

    topics: dict[str, TopicBlueprint] = {}
    expected_profile_ids = {query.source_profile_id for query in plan.source.queries}
    if plan.source.page_profile_id is not None:
        expected_profile_ids.add(plan.source.page_profile_id)
    expected_decision_ids = {
        decision_id
        for query in plan.source.queries
        for decision_id in query.decision_ids
    }
    for binding in plan.topic_bindings:
        try:
            topic = evidence_resolver.resolve_current_topic_blueprint(
                run_id=plan.run_id,
                scope_id=plan.scope_id,
                blueprint_id=binding.blueprint_id,
            )
        except Exception:
            topic = None
        try:
            accepted_topic = evidence_resolver.resolve_accepted_topic_blueprint(
                run_id=plan.run_id,
                scope_id=plan.scope_id,
                blueprint_id=binding.blueprint_id,
            )
        except Exception:
            accepted_topic = None
        try:
            registered_topic = evidence_resolver.resolve_registered_topic_blueprint(
                run_id=plan.run_id,
                scope_id=plan.scope_id,
                blueprint_id=binding.blueprint_id,
            )
        except Exception:
            registered_topic = None
        if not isinstance(topic, TopicBlueprint):
            invalidation.add(f"topic_unavailable:{binding.blueprint_id}")
            continue
        topics[binding.blueprint_id] = topic
        expected_profile_ids.update(
            item.profile_id for item in topic.profile_bindings
        )
        expected_decision_ids.update(
            item.decision_id for item in topic.decision_bindings
        )
        catalog_hash = topic_component_catalog_hash(topic)
        if (
            topic.run_id != plan.run_id
            or topic.scope_id != plan.scope_id
            or topic.blueprint_hash != topic_blueprint_hash(topic)
            or topic.validation_context != current_context
            or binding.blueprint_hash != topic.blueprint_hash
            or binding.component_catalog_hash != catalog_hash
        ):
            invalidation.add(f"topic_changed:{binding.blueprint_id}")
        if not isinstance(accepted_topic, AcceptedDashboardTopicEvidence):
            invalidation.add(f"topic_acceptance_unavailable:{binding.blueprint_id}")
        elif not isinstance(registered_topic, RegisteredDashboardTopicEvidence):
            invalidation.add(f"topic_registration_unavailable:{binding.blueprint_id}")
        elif (
            accepted_topic.run_id != plan.run_id
            or accepted_topic.scope_id != plan.scope_id
            or accepted_topic.blueprint_id != binding.blueprint_id
            or accepted_topic.blueprint_hash != topic.blueprint_hash
            or accepted_topic.accepted_topic_ref != binding.accepted_topic_ref
            or accepted_topic.accepted_topic_hash != binding.accepted_topic_hash
            or accepted_topic.readiness_ref != binding.readiness_ref
            or accepted_topic.readiness_hash != binding.readiness_hash
            or accepted_topic.topic_validation_fingerprint
            != binding.topic_validation_fingerprint
            or accepted_topic.topic_validation_fingerprint != topic.blueprint_hash
            or accepted_topic.producer_ref
            != "agent-ref://domo_to_omni_architect"
            or accepted_topic.component_catalog_hash != catalog_hash
            or set(accepted_topic.profile_ids)
            != {item.profile_id for item in topic.profile_bindings}
            or set(accepted_topic.decision_ids)
            != {item.decision_id for item in topic.decision_bindings}
            or set(accepted_topic.validation_cycle_ids)
            != {item.validation_cycle_id for item in topic.decision_bindings}
            or accepted_topic.validation_context_hash != current_context.context_hash
            or registered_topic.run_id != plan.run_id
            or registered_topic.scope_id != plan.scope_id
            or registered_topic.validation_cycle_id != plan.validation_cycle_id
            or registered_topic.blueprint_id != binding.blueprint_id
            or registered_topic.blueprint_hash != topic.blueprint_hash
            or registered_topic.artifact_ref
            != accepted_topic.registered_blueprint_ref
            or registered_topic.artifact_hash
            != accepted_topic.registered_blueprint_hash
            or registered_topic.producer_ref
            != "agent-ref://domo_to_omni_architect"
        ):
            invalidation.add(f"topic_acceptance_changed:{binding.blueprint_id}")
    used_topic_ids = {
        mapping.topic_blueprint_id
        for mapping in plan.query_mappings
        if mapping.outcome == "mapped" and mapping.topic_blueprint_id is not None
    }
    if used_topic_ids != {item.blueprint_id for item in plan.topic_bindings}:
        invalidation.add("topic_binding_set_changed")

    profile_bindings = {item.profile_id: item for item in plan.profile_bindings}
    if set(profile_bindings) != expected_profile_ids:
        invalidation.add("profile_binding_set_changed")
    for profile_id, binding in profile_bindings.items():
        try:
            profile = evidence_resolver.resolve_current_profile(
                run_id=plan.run_id,
                scope_id=plan.scope_id,
                profile_id=profile_id,
            )
        except Exception:
            profile = None
        if not isinstance(profile, SemanticProfile):
            invalidation.add(f"profile_unavailable:{profile_id}")
            continue
        if validate_semantic_profile(profile):
            invalidation.add(f"profile_integrity_invalid:{profile_id}")
        if (
            profile.run_id != plan.run_id
            or profile.scope_id != plan.scope_id
            or profile.status != "ready"
            or profile.profile_hash != binding.profile_hash
            or profile.identity.system != binding.system
            or profile.identity.object_id != binding.asset_id
        ):
            invalidation.add(f"profile_changed:{profile_id}")
    for query in plan.source.queries:
        profile = None
        try:
            profile = evidence_resolver.resolve_current_profile(
                run_id=plan.run_id,
                scope_id=plan.scope_id,
                profile_id=query.source_profile_id,
            )
        except Exception:
            pass
        if not isinstance(profile, SemanticProfile):
            invalidation.add(f"query_profile_unavailable:{query.query.object_id}")
        elif (
            profile.identity.system != "domo"
            or profile.identity.kind != "dashboard_query"
            or profile.identity.object_id != query.source_profile_asset_id
            or profile.profile_hash != query.source_profile_hash
            or query.source_consumer_id not in set(profile.consumers)
        ):
            invalidation.add(f"query_profile_changed:{query.query.object_id}")
    if plan.source.page_profile_id is not None:
        page_profile = None
        try:
            page_profile = evidence_resolver.resolve_current_profile(
                run_id=plan.run_id,
                scope_id=plan.scope_id,
                profile_id=plan.source.page_profile_id,
            )
        except Exception:
            pass
        if not isinstance(page_profile, SemanticProfile):
            invalidation.add(f"page_profile_unavailable:{plan.source.page.object_id}")
        elif (
            page_profile.identity.system != "domo"
            or page_profile.identity.kind != "dashboard_query"
            or page_profile.identity.object_id != plan.source.page_profile_asset_id
            or page_profile.profile_hash != plan.source.page_profile_hash
            or page_profile.provenance.get("source_native_id")
            != plan.source.page.object_id
            or not {
                query.source_consumer_id for query in plan.source.queries
            }.issubset(set(page_profile.consumers))
        ):
            invalidation.add(f"page_profile_changed:{plan.source.page.object_id}")

    decision_bindings = {
        item.decision_id: item for item in plan.decision_bindings
    }
    if set(decision_bindings) != expected_decision_ids:
        invalidation.add("decision_binding_set_changed")
    decisions: dict[str, ConsolidationDecision] = {}
    for decision_id, binding in decision_bindings.items():
        try:
            decision = evidence_resolver.resolve_current_decision(
                run_id=plan.run_id,
                scope_id=plan.scope_id,
                decision_id=decision_id,
            )
        except Exception:
            decision = None
        if not isinstance(decision, ConsolidationDecision):
            invalidation.add(f"decision_unavailable:{decision_id}")
            continue
        decisions[decision_id] = decision
        if (
            decision.run_id != plan.run_id
            or decision.scope_id != plan.scope_id
            or decision.status != "approved"
            or not decision.authorizes_build
            or decision.validation_context != current_context
            or decision.decision_hash != consolidation_decision_hash(decision)
            or decision.input_fingerprint != consolidation_input_fingerprint(decision)
            or decision.decision_hash != binding.decision_hash
            or decision.input_fingerprint != binding.input_fingerprint
            or decision.validation_cycle_id != binding.validation_cycle_id
            or decision.validation_cycle_id != plan.validation_cycle_id
        ):
            invalidation.add(f"decision_changed:{decision_id}")

    source_queries = {item.query.object_id: item for item in plan.source.queries}
    special_by_id = {
        item.behavior_id: item for item in plan.source.special_behaviors
    }
    resolution_by_id = {
        item.resolution_id: item for item in plan.behavior_resolutions
    }
    for card_mapping in plan.card_mappings:
        resolution_id = card_mapping.behavior_resolution_id
        if resolution_id is None:
            continue
        resolution = resolution_by_id.get(resolution_id)
        source_behavior = (
            special_by_id.get(resolution.source_behavior_id)
            if resolution is not None
            else None
        )
        if (
            resolution is None
            or source_behavior is None
            or source_behavior.parent_type != "card"
            or source_behavior.parent_id != card_mapping.source_card_id
        ):
            errors.add(
                f"Card behavior resolution does not bind its source Card: "
                f"{card_mapping.source_card_id}"
            )
    for mapping in plan.query_mappings:
        source_query = source_queries[mapping.query_id]
        if mapping.mapping_hash != query_rebuild_mapping_hash(mapping):
            invalidation.add(f"query_mapping_hash_changed:{mapping.query_id}")
        if mapping.query_revision_hash != source_query.query.revision_hash:
            invalidation.add(f"query_revision_changed:{mapping.query_id}")
        if mapping.outcome != "mapped":
            disposition = mapping.query_disposition
            if disposition is None:
                errors.add(f"query disposition is missing: {mapping.query_id}")
                continue
            if disposition.disposition_hash != query_disposition_hash(disposition):
                invalidation.add(f"query_disposition_changed:{mapping.query_id}")
            if disposition.disposition == "blocked":
                errors.add(f"query remains blocked: {mapping.query_id}")
            else:
                try:
                    accepted_disposition = (
                        evidence_resolver.resolve_accepted_query_disposition(
                            run_id=plan.run_id,
                            scope_id=plan.scope_id,
                            plan_id=plan.plan_id,
                            query_id=mapping.query_id,
                        )
                    )
                except Exception:
                    accepted_disposition = None
                if not isinstance(
                    accepted_disposition, AcceptedQueryDispositionEvidence
                ):
                    invalidation.add(
                        f"query_disposition_acceptance_unavailable:{mapping.query_id}"
                    )
                elif (
                    accepted_disposition.run_id != plan.run_id
                    or accepted_disposition.scope_id != plan.scope_id
                    or accepted_disposition.plan_id != plan.plan_id
                    or accepted_disposition.query_id != mapping.query_id
                    or accepted_disposition.query_revision_hash
                    != mapping.query_revision_hash
                    or accepted_disposition.disposition_hash
                    != disposition.disposition_hash
                    or accepted_disposition.validation_context_hash
                    != current_context.context_hash
                ):
                    invalidation.add(
                        f"query_disposition_acceptance_changed:{mapping.query_id}"
                    )
            continue
        topic_id = mapping.topic_blueprint_id
        if topic_id is None or topic_id not in topics:
            invalidation.add(f"query_topic_unavailable:{mapping.query_id}")
            continue
        topic = topics[topic_id]
        topic_consumer = next(
            (
                consumer
                for consumer in topic.consumer_mappings
                if consumer.source_consumer_id == source_query.source_consumer_id
            ),
            None,
        )
        if topic_consumer is None:
            errors.add(
                f"query consumer is not covered by its accepted Topic: {mapping.query_id}"
            )
        elif mapping.consumer_contract is None:
            errors.add(f"query consumer contract is missing: {mapping.query_id}")
        else:
            contract = mapping.consumer_contract
            expected_decision_bindings = tuple(
                sorted(
                    (
                        item.decision_id,
                        item.behavior,
                        item.accepted_difference_ref,
                    )
                    for item in topic_consumer.decision_bindings
                )
            )
            actual_decision_bindings = tuple(
                sorted(
                    (
                        item.decision_id,
                        item.behavior,
                        item.accepted_difference_ref,
                    )
                    for item in contract.decision_bindings
                )
            )
            if (
                contract.consumer_hash != topic_consumer_contract_hash(contract)
                or contract.source_consumer_id != topic_consumer.source_consumer_id
                or contract.target_consumer_ref != topic_consumer.target_consumer_ref
                or contract.target_consumer_ref
                != next(
                    card.target_card_ref
                    for card in plan.card_mappings
                    if mapping.query_id in card.source_query_ids
                )
                or set(contract.topic_component_refs)
                != set(topic_consumer.topic_component_refs)
                or actual_decision_bindings != expected_decision_bindings
            ):
                invalidation.add(f"topic_consumer_contract_changed:{mapping.query_id}")
        actual_behavior_sets = _mapping_behavior_sets(mapping)
        for field_name, _ in _BEHAVIOR_FIELDS:
            expected = set(getattr(source_query.behavior_denominator, field_name))
            if actual_behavior_sets[field_name] != expected:
                errors.add(
                    f"query behavior coverage changed:{mapping.query_id}:{field_name}"
                )
        component_refs: list[TargetTopicComponentRef] = []
        component_refs.extend(item.target for item in mapping.fields)
        component_refs.extend(item.target for item in mapping.measures)
        component_refs.extend(item.target for item in mapping.groupings)
        component_refs.extend(item.target for item in mapping.sorts)
        component_refs.extend(item.target for item in mapping.filters)
        component_refs.extend(item.target for item in mapping.controls)
        component_refs.extend(
            component
            for drill in mapping.drills
            for component in drill.ordered_components
        )
        if any(item.target.component_kind != "field" for item in mapping.fields):
            errors.add(f"field selections must target Topic fields: {mapping.query_id}")
        if any(item.target.component_kind != "measure" for item in mapping.measures):
            errors.add(f"measure selections must target Topic measures: {mapping.query_id}")
        if any(item.target.component_kind != "field" for item in mapping.groupings):
            errors.add(f"groupings must target Topic fields: {mapping.query_id}")
        if any(item.target.component_kind != "field" for item in mapping.filters):
            errors.add(f"filters must target Topic fields: {mapping.query_id}")
        for component_ref in component_refs:
            component_errors, component_invalidation = _component_ref_errors(
                component_ref=component_ref,
                query_topic_id=topic_id,
                plan=plan,
                resolver=evidence_resolver,
                topics=topics,
                context=current_context,
            )
            errors.update(component_errors)
            invalidation.update(component_invalidation)
        if mapping.consumer_contract is not None:
            allowed_consumer_components = set(
                mapping.consumer_contract.topic_component_refs
            )
            for component_ref in component_refs:
                component: TopicField | TopicMeasure | None
                if component_ref.component_kind == "field":
                    component = next(
                        (
                            item
                            for item in topic.fields
                            if item.field_id == component_ref.component_id
                        ),
                        None,
                    )
                else:
                    component = next(
                        (
                            item
                            for item in topic.measures
                            if item.measure_id == component_ref.component_id
                        ),
                        None,
                    )
                if component is not None and not {
                    component_ref.component_id,
                    component.view_id,
                }.intersection(allowed_consumer_components):
                    errors.add(
                        "query uses components outside its accepted consumer contract: "
                        f"{mapping.query_id}:{component_ref.component_id}"
                    )
        known_filter_ids = {item.source_behavior_id for item in mapping.filters}
        if any(
            not set(item.applies_to_filter_ids).issubset(known_filter_ids)
            for item in mapping.filter_contexts
        ):
            errors.add(f"filter contexts reference unknown filters: {mapping.query_id}")
        known_source_card_ids = {card.card.object_id for card in plan.source.cards}
        known_query_ids = set(source_queries)
        known_target_card_ids = {
            item.target_card_id
            for item in plan.query_mappings
            if item.target_card_id is not None
        }
        if any(
            not set(item.target_card_ids).issubset(known_target_card_ids)
            or not set(item.target_query_ids).issubset(known_query_ids)
            for item in mapping.controls
        ):
            errors.add(f"controls reference unknown Cards or queries: {mapping.query_id}")
        if any(
            item.source_card_id != source_query.card_id
            or item.source_card_id not in known_source_card_ids
            or not set(item.target_card_ids).issubset(known_target_card_ids)
            or not set(item.target_query_ids).issubset(known_query_ids)
            for item in mapping.interactions
        ):
            errors.add(f"interactions reference unknown Cards or queries: {mapping.query_id}")
        if {
            item.source_placement_id for item in mapping.layouts
        } != set(source_query.placement_ids):
            errors.add(f"layout placement coverage changed: {mapping.query_id}")
        if any(
            item.target_card_id != mapping.target_card_id for item in mapping.layouts
        ):
            errors.add(f"layout targets the wrong rebuilt Card: {mapping.query_id}")
        topic_decisions = {
            item.decision_id for item in topic.decision_bindings
        }
        if not set(source_query.decision_ids).issubset(topic_decisions):
            errors.add(
                f"query decisions are not covered by its accepted Topic: {mapping.query_id}"
            )
        accepted_differences = {
            difference
            for decision_id in source_query.decision_ids
            if decision_id in decisions
            for difference in decisions[decision_id].accepted_differences
        }
        for security in mapping.security:
            if (
                security.target_security_domain
                != topic.security.target_security_domain
                or set(security.target_policy_refs)
                != set(topic.security.target_policy_refs)
            ):
                errors.add(
                    f"security mapping differs from its accepted Topic: {mapping.query_id}"
                )
            if security.behavior == "approved_change" and (
                security.accepted_difference_ref not in accepted_differences
            ):
                errors.add(
                    f"security mapping cites an unaccepted difference: {mapping.query_id}"
                )
        persona_expectations = {
            (
                item.persona_ref,
                item.access,
                item.derived_field_access,
            )
            for item in topic.security.persona_expectations
        }
        mapped_personas = {
            (item.persona_ref, item.access, item.derived_field_access)
            for item in mapping.personas
        }
        if mapped_personas != persona_expectations:
            errors.add(
                f"persona mappings differ from accepted Topic expectations: {mapping.query_id}"
            )
        if any(
            operation.behavior_resolution_id is None
            and operation.owner_ref not in set(topic.ownership.operations_owner_refs)
            for operation in mapping.operations
        ):
            errors.add(
                f"mapped operations require an accepted Topic operations owner: {mapping.query_id}"
            )
        resolution_ids = {
            item.behavior_resolution_id
            for item in (*mapping.visualizations, *mapping.operations)
            if item.behavior_resolution_id is not None
        }
        if any(resolution_id not in resolution_by_id for resolution_id in resolution_ids):
            errors.add(f"query references an unknown behavior resolution: {mapping.query_id}")
        for resolution_id in resolution_ids & set(resolution_by_id):
            resolution = resolution_by_id[resolution_id]
            source_behavior = special_by_id.get(resolution.source_behavior_id)
            if source_behavior is None or source_behavior.parent_id != mapping.query_id:
                errors.add(
                    f"query behavior resolution does not bind its source query: {mapping.query_id}"
                )
        for visual in mapping.visualizations:
            if visual.behavior_resolution_id is None:
                continue
            if visual.behavior_resolution_id not in resolution_by_id:
                continue
            if (
                resolution_by_id[visual.behavior_resolution_id].source_behavior_id
                != visual.source_behavior_id
            ):
                errors.add(
                    f"visual resolution binds the wrong source behavior: {mapping.query_id}"
                )
        for operation in mapping.operations:
            if operation.behavior_resolution_id is None:
                continue
            if operation.behavior_resolution_id not in resolution_by_id:
                continue
            if (
                resolution_by_id[operation.behavior_resolution_id].source_behavior_id
                != operation.source_behavior_id
            ):
                errors.add(
                    f"operation resolution binds the wrong source behavior: {mapping.query_id}"
                )
        try:
            accepted_mapping = evidence_resolver.resolve_accepted_query_mapping(
                run_id=plan.run_id,
                scope_id=plan.scope_id,
                plan_id=plan.plan_id,
                query_id=mapping.query_id,
            )
        except Exception:
            accepted_mapping = None
        if not isinstance(accepted_mapping, AcceptedQueryMappingEvidence):
            invalidation.add(
                f"query_mapping_acceptance_unavailable:{mapping.query_id}"
            )
        elif (
            accepted_mapping.run_id != plan.run_id
            or accepted_mapping.scope_id != plan.scope_id
            or accepted_mapping.plan_id != plan.plan_id
            or accepted_mapping.query_id != mapping.query_id
            or accepted_mapping.query_revision_hash != mapping.query_revision_hash
            or accepted_mapping.topic_blueprint_id != topic_id
            or accepted_mapping.topic_blueprint_hash != topic.blueprint_hash
            or accepted_mapping.query_mapping_hash != mapping.mapping_hash
            or accepted_mapping.validation_fixture_ref
            != plan.source.context.query_fixture_ref
            or accepted_mapping.validation_fixture_hash
            != plan.source.context.query_fixture_hash
            or accepted_mapping.validation_context_hash != current_context.context_hash
        ):
            invalidation.add(f"query_mapping_acceptance_changed:{mapping.query_id}")

    for resolution in plan.behavior_resolutions:
        if resolution.resolution_hash != behavior_resolution_hash(resolution):
            invalidation.add(f"behavior_resolution_changed:{resolution.resolution_id}")
        if resolution.status not in {"accepted", "completed"}:
            errors.add(
                f"source behavior resolution is not accepted: "
                f"{resolution.source_behavior_id}:{resolution.status}"
            )
        if resolution.disposition == "blocked":
            errors.add(f"source behavior remains blocked: {resolution.source_behavior_id}")
            continue
        try:
            accepted_resolution = (
                evidence_resolver.resolve_accepted_behavior_resolution(
                    run_id=plan.run_id,
                    scope_id=plan.scope_id,
                    plan_id=plan.plan_id,
                    resolution_id=resolution.resolution_id,
                )
            )
        except Exception:
            accepted_resolution = None
        if not isinstance(
            accepted_resolution, AcceptedBehaviorResolutionEvidence
        ):
            invalidation.add(
                f"behavior_resolution_acceptance_unavailable:{resolution.resolution_id}"
            )
        elif (
            accepted_resolution.run_id != plan.run_id
            or accepted_resolution.scope_id != plan.scope_id
            or accepted_resolution.plan_id != plan.plan_id
            or accepted_resolution.resolution_id != resolution.resolution_id
            or accepted_resolution.source_behavior_id != resolution.source_behavior_id
            or accepted_resolution.source_behavior_hash
            != resolution.source_behavior_hash
            or accepted_resolution.resolution_hash != resolution.resolution_hash
            or accepted_resolution.status != resolution.status
            or accepted_resolution.validation_context_hash
            != current_context.context_hash
        ):
            invalidation.add(
                f"behavior_resolution_acceptance_changed:{resolution.resolution_id}"
            )

    try:
        registration = evidence_resolver.resolve_registered_dashboard_plan(
            run_id=plan.run_id, scope_id=plan.scope_id, plan_id=plan.plan_id
        )
    except Exception:
        registration = None
    if not isinstance(registration, AcceptedDashboardPlanRegistration):
        invalidation.add("dashboard_plan_registration_unavailable")
    elif (
        registration.run_id != plan.run_id
        or registration.scope_id != plan.scope_id
        or registration.plan_id != plan.plan_id
        or registration.migration_unit_id != plan.migration_unit_id
        or registration.validation_cycle_id != plan.validation_cycle_id
        or registration.page_id != plan.source.page.object_id
        or registration.plan_hash != plan.plan_hash
        or registration.producer_ref != "agent-ref://domo_to_omni_architect"
        or registration.validation_context_hash != current_context.context_hash
    ):
        invalidation.add("dashboard_plan_registration_changed")

    invalidated = bool(invalidation)
    valid = not errors and not invalidated
    return DashboardRebuildPlanValidation(
        valid=valid,
        invalidated=invalidated,
        errors=tuple(sorted(errors)),
        invalidation_reasons=tuple(sorted(invalidation)),
        dashboard_plan_ready=valid,
        plan_fingerprint=dashboard_rebuild_plan_hash(plan),
    )


__all__ = [
    "AcceptedBehaviorResolutionEvidence",
    "AcceptedDashboardPlanRegistration",
    "AcceptedDashboardTopicComponent",
    "AcceptedDashboardTopicEvidence",
    "AcceptedQueryDispositionEvidence",
    "AcceptedQueryMappingEvidence",
    "AcceptedSourceDashboardEvidence",
    "ApprovedBehaviorException",
    "BehaviorResolution",
    "BehaviorResolutionStatus",
    "CardRebuildMapping",
    "ContentCardCompleteness",
    "ContentCardOperationMapping",
    "ContentCardPlacementMapping",
    "ControlMapping",
    "DashboardConsumerDecisionBinding",
    "DashboardDecisionBinding",
    "DashboardEvidenceSnapshot",
    "DashboardPlanProvenance",
    "DashboardPlanSecurityMetadata",
    "DashboardPlanValidationRegistration",
    "DashboardProfileBinding",
    "DashboardRebuildEvidenceResolver",
    "DashboardRebuildPlan",
    "DashboardRebuildPlanValidation",
    "DashboardTopicBinding",
    "DrillMapping",
    "FieldSelectionMapping",
    "FilterContextMapping",
    "FilterMapping",
    "FormattingMapping",
    "GridPlacement",
    "GroupingMapping",
    "InteractionMapping",
    "LayoutMapping",
    "MeasureSelectionMapping",
    "OperationMapping",
    "PageRebuildMapping",
    "PersonaMapping",
    "QueryBehaviorDenominator",
    "QueryDisposition",
    "QueryRebuildMapping",
    "RegisteredDashboardTopicEvidence",
    "ResponsiveMapping",
    "SecurityMapping",
    "SortMapping",
    "SourceArtifactRevision",
    "SourceBehaviorBinding",
    "SourceCardDenominator",
    "SourceCardPlacement",
    "SourceDashboardContext",
    "SourceDashboardDenominator",
    "SourceQueryDenominator",
    "SourceSpecialBehavior",
    "StoreBackedDashboardEvidenceResolver",
    "TargetDashboardIntent",
    "TargetTopicComponentRef",
    "TopicConsumerContract",
    "VisualizationMapping",
    "behavior_resolution_hash",
    "card_rebuild_mapping_hash",
    "content_card_completeness_hash",
    "dashboard_evidence_snapshot_content_sha256",
    "dashboard_evidence_snapshot_hash",
    "dashboard_plan_content_sha256",
    "dashboard_plan_validation_registration_hash",
    "dashboard_rebuild_plan_hash",
    "finalize_dashboard_evidence_snapshot",
    "finalize_dashboard_rebuild_plan",
    "page_rebuild_mapping_hash",
    "query_behavior_denominator_hash",
    "query_disposition_hash",
    "query_rebuild_mapping_hash",
    "register_validated_dashboard_plan",
    "source_behavior_hash",
    "source_card_placement_hash",
    "source_dashboard_context_hash",
    "source_dashboard_denominator_hash",
    "topic_component_catalog_hash",
    "topic_consumer_contract_hash",
    "validate_dashboard_rebuild_plan",
]

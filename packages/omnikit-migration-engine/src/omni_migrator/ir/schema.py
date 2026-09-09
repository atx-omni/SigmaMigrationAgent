"""The canonical, tool-agnostic intermediate representation (IR).

Every extractor's only job is to emit a `MigrationBundle`. Everything downstream
(deterministic YAML emit, AI prompting, fidelity reporting) is written once against
this schema. See plan §5 and Appendix A.

Field/enum vocabulary on the *Omni* side lives in `omni_migrator.deterministic.omni_enums`;
the IR itself is intentionally a bit richer (e.g. a `date` data type) and is mapped down
to Omni's vocabulary by the emitter.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

IR_VERSION = "2"

SourceKind = Literal["tableau", "powerbi", "looker", "sigma", "metabase", "domo", "other"]
Dialect = Literal[
    "bigquery", "snowflake", "redshift", "postgres", "databricks", "mysql", "other"
]
FieldKind = Literal["dimension", "measure", "calculation", "parameter"]
DataType = Literal["string", "number", "date", "timestamp", "boolean", "duration", "json"]
# Omni-side enums (mirrored in deterministic.omni_enums for validation at emit time):
Aggregate = Literal[
    "sum", "count", "average", "max", "min", "median", "count_distinct",
    "list", "percentile", "sum_distinct", "average_distinct", "none",
]
JoinType = Literal["always_left", "always_inner", "always_right", "always_full"]
RelationshipType = Literal["many_to_one", "one_to_many", "one_to_one", "many_to_many"]
Severity = Literal["info", "warning", "blocker"]
EvidenceRole = Literal["direct", "bundle_input", "derived"]
AcquisitionMode = Literal["manual", "api", "hybrid", "unknown"]
CoverageStatus = Literal["not_evaluated", "not_applicable", "complete", "partial", "blocked"]


class UntranslatableNote(BaseModel):
    object: str
    reason: str
    severity: Severity = "warning"
    hint: str | None = None


class SourceEvidence(BaseModel):
    """A content-addressed pointer back to source evidence.

    Extractors may provide an exact ``direct`` locator. The bridge fills any missing
    evidence with ``bundle_input`` references so downstream systems can distinguish
    exact evidence from the set of files that contributed to a parsed bundle.
    """

    artifact_name: str | None = None
    artifact_sha256: str | None = None
    locator: str
    content_sha256: str
    role: EvidenceRole = "direct"


class AcquisitionDependencyIR(BaseModel):
    kind: Literal[
        "model", "include", "explore", "view", "extension", "refinement",
        "manifest_dependency", "constant", "connection", "semantic_model", "source",
        "dashboard", "page", "visual", "field", "calculation", "filter", "query",
        "lineage", "permission", "schedule", "operation",
    ]
    reference: str
    source_file: str | None = None
    status: Literal["resolved", "missing", "review"]
    required: bool = True
    matched_files: list[str] = Field(default_factory=list)
    affected_dashboard_ids: list[str] = Field(default_factory=list)
    message: str


class AcquisitionEvidenceIR(BaseModel):
    """Sanitized acquisition/readiness evidence shared by every source path.

    The object is intentionally source-neutral. Source adapters may use their own
    versioned ``contract_version`` while downstream consumers retain one bridge
    shape for Manual and API acquisition.
    """

    contract_version: str
    mode: AcquisitionMode = "unknown"
    project_ids: list[str] = Field(default_factory=list)
    dashboard_ids: list[str] = Field(default_factory=list)
    look_ids: list[str] = Field(default_factory=list)
    query_ids: list[str] = Field(default_factory=list)
    source_files: list[str] = Field(default_factory=list)
    required_files: list[str] = Field(default_factory=list)
    unrelated_files: list[str] = Field(default_factory=list)
    dependencies: list[AcquisitionDependencyIR] = Field(default_factory=list)
    saved_look_coverage: CoverageStatus = "not_evaluated"
    dependency_closure_status: CoverageStatus = "not_evaluated"
    source_query_validation_status: CoverageStatus = "not_evaluated"
    diagnostics: list[str] = Field(default_factory=list)


class ConnectionRef(BaseModel):
    source_connection_name: str | None = None
    dialect: Dialect = "other"
    omni_connection_id: str | None = None  # resolved during the Map stage
    database: str | None = None  # resolved Omni connection's catalog/database name (Map stage)


class FieldIR(BaseModel):
    source_id: str | None = None
    source_locator: str | None = None
    evidence: list[SourceEvidence] = Field(default_factory=list)
    name: str  # canonical snake_case; [a-z0-9_], starts with a letter
    source_name: str | None = None
    kind: FieldKind
    data_type: DataType = "string"
    sql: str | None = None  # normalized to ${TABLE}.col / ${field} / ${view.field}
    aggregate: Aggregate | None = None
    value_format: str | None = None  # canonical token; mapped to Omni `format` at emit
    label: str | None = None
    description: str | None = None
    group_label: str | None = None
    hidden: bool = False
    primary_key: bool = False
    timeframes: list[str] | None = None  # source date-part list (dropped on emit; Omni derives)
    filters: dict[str, dict] | None = None  # filtered-measure conditions
    suggestion_list: list[dict[str, str]] | None = None  # filter-only field values
    filter_single_select_only: bool = False
    untranslatable: list[UntranslatableNote] = Field(default_factory=list)


class ViewIR(BaseModel):
    source_id: str | None = None
    source_locator: str | None = None
    evidence: list[SourceEvidence] = Field(default_factory=list)
    name: str
    source_table: str | None = None
    schema_name: str | None = None  # "schema" is reserved on pydantic BaseModel
    sql: str | None = None  # derived-table SQL (mutually exclusive with source_table)
    label: str | None = None
    description: str | None = None
    connection: ConnectionRef = Field(default_factory=ConnectionRef)
    fields: list[FieldIR] = Field(default_factory=list)
    untranslatable: list[UntranslatableNote] = Field(default_factory=list)

    @property
    def primary_key_field(self) -> str | None:
        for f in self.fields:
            if f.primary_key:
                return f.name
        return None


class JoinIR(BaseModel):
    source_id: str | None = None
    source_locator: str | None = None
    evidence: list[SourceEvidence] = Field(default_factory=list)
    join_from_view: str
    join_to_view: str
    join_type: JoinType = "always_left"
    relationship_type: RelationshipType = "many_to_one"
    on_sql: str
    reversible: bool = False


class TopicIR(BaseModel):
    source_id: str | None = None
    source_locator: str | None = None
    evidence: list[SourceEvidence] = Field(default_factory=list)
    name: str
    base_view: str
    label: str | None = None
    description: str | None = None
    joins: list[JoinIR] = Field(default_factory=list)
    always_where_filters: dict[str, dict] = Field(default_factory=dict)
    access_filters: list[dict] = Field(default_factory=list)


class SemanticRequirementIR(BaseModel):
    source_id: str | None = None
    source_locator: str | None = None
    evidence: list[SourceEvidence] = Field(default_factory=list)
    object_type: Literal[
        "parameter", "filtered_measure", "derived_table", "always_filter", "access_filter",
        "extension", "refinement", "liquid", "user_attribute", "dynamic_field", "control",
        "input_table", "action", "layout", "permission", "schedule", "query_validation",
        "lineage",
    ]
    name: str
    support_outcome: Literal["automatic", "decision_required", "manual", "unsupported"]
    reason: str
    target_file_hint: str | None = None
    dependencies: list[str] = Field(default_factory=list)
    config: dict = Field(default_factory=dict)


class ModelIR(BaseModel):
    views: list[ViewIR] = Field(default_factory=list)
    topics: list[TopicIR] = Field(default_factory=list)
    requirements: list[SemanticRequirementIR] = Field(default_factory=list)
    untranslatable: list[UntranslatableNote] = Field(default_factory=list)


# ---- dashboards (lighter for now; deterministic dashboard emit is Phase 2) ----

class FilterIR(BaseModel):
    source_id: str | None = None
    native_source_id: str | None = None
    source_locator: str | None = None
    evidence: list[SourceEvidence] = Field(default_factory=list)
    field: str
    operator: str
    values: list[str] = Field(default_factory=list)
    is_negative: bool = False
    label: str | None = None
    filter_type: str | None = None
    required: bool = False


class DynamicFieldIR(BaseModel):
    source_id: str | None = None
    native_source_id: str | None = None
    source_locator: str | None = None
    evidence: list[SourceEvidence] = Field(default_factory=list)
    name: str
    label: str | None = None
    category: Literal["group_by", "filtered_measure", "table_calculation", "expression", "unknown"]
    expression: str | None = None
    based_on: str | None = None
    filters: dict[str, str] = Field(default_factory=dict)
    dependencies: list[str] = Field(default_factory=list)
    support_outcome: Literal["automatic", "decision_required", "manual", "unsupported"]
    config: dict = Field(default_factory=dict)


class FilterBindingIR(BaseModel):
    source_id: str | None = None
    native_source_id: str | None = None
    source_locator: str | None = None
    evidence: list[SourceEvidence] = Field(default_factory=list)
    dashboard_filter_id: str
    dashboard_filter_label: str
    tile_id: str
    target_field: str | None = None
    excluded: bool = False


class QueryIR(BaseModel):
    source_id: str | None = None
    native_source_id: str | None = None
    source_locator: str | None = None
    evidence: list[SourceEvidence] = Field(default_factory=list)
    topic: str
    fields: list[str] = Field(default_factory=list)
    filters: list[FilterIR] = Field(default_factory=list)
    sorts: list[dict] = Field(default_factory=list)
    limit: int | None = None
    pivots: list[str] | None = None
    source_model: str | None = None
    source_explore: str | None = None
    filter_expression: str | None = None
    hidden_fields: list[str] = Field(default_factory=list)
    dynamic_fields: list[DynamicFieldIR] = Field(default_factory=list)
    calculation_dependencies: list[str] = Field(default_factory=list)
    query_origin: Literal["inline", "result_maker", "saved_look", "query_id", "unknown"] = "unknown"
    source_look_id: str | None = None


class GridRect(BaseModel):
    x: int = 0
    y: int = 0
    w: int = 12
    h: int = 4


class TileIR(BaseModel):
    source_id: str | None = None
    native_source_id: str | None = None
    source_locator: str | None = None
    evidence: list[SourceEvidence] = Field(default_factory=list)
    kind: Literal["query", "text", "markdown", "image"] = "query"
    title: str | None = None
    query: QueryIR | None = None
    chart_type: str | None = None
    vis_config: dict = Field(default_factory=dict)
    layout: GridRect = Field(default_factory=GridRect)
    untranslatable: list[UntranslatableNote] = Field(default_factory=list)


class DashboardIR(BaseModel):
    source_id: str | None = None
    native_source_id: str | None = None
    selection_aliases: list[str] = Field(default_factory=list)
    source_locator: str | None = None
    evidence: list[SourceEvidence] = Field(default_factory=list)
    name: str
    tiles: list[TileIR] = Field(default_factory=list)
    filters: list[FilterIR] = Field(default_factory=list)
    filter_bindings: list[FilterBindingIR] = Field(default_factory=list)
    filter_order: list[str] = Field(default_factory=list)
    tile_order: list[str] = Field(default_factory=list)
    folder_path: str | None = None
    owner: str | None = None
    updated_at: str | None = None
    usage_count: int | None = None
    source_url: str | None = None
    untranslatable: list[UntranslatableNote] = Field(default_factory=list)


class Provenance(BaseModel):
    run_id: str | None = None
    extracted_at: str | None = None
    source_artifact: str | None = None
    tool_version: str = "0.1.0"


class MigrationBundle(BaseModel):
    ir_version: Literal["1", "2"] = IR_VERSION
    source: SourceKind
    provenance: Provenance = Field(default_factory=Provenance)
    acquisition: AcquisitionEvidenceIR | None = None
    model: ModelIR = Field(default_factory=ModelIR)
    dashboards: list[DashboardIR] = Field(default_factory=list)

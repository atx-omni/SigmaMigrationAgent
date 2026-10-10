"""Pure, bounded Sigma -> reviewable Omni/dbt artifacts. Never calls a target.

Wire contracts checked 2026-09-09 against the vendor's documentation:
https://docs.omni.co/api/documents-v2/create-document
https://docs.omni.co/api/documents-v2/create-draft-and-patch-document
https://github.com/exploreomni/omni-agent-skills/blob/main/skills/omni-content-builder/references/documents-v2.md
https://github.com/exploreomni/omni-agent-skills/blob/main/skills/omni-content-builder/references/controls.md
https://github.com/exploreomni/omni-agent-skills/blob/main/skills/omni-content-builder/references/containers.md
https://github.com/exploreomni/omni-agent-skills/blob/main/skills/omni-content-builder/references/visConfig.md

IMPORTANT: the create request would PUBLISH a new document if invoked. These are
local request bodies, not previews, approvals, or proof of target compatibility.
Only single-view table/column/line/bar queries and string-equality controls are
compiled. Explicit reviewed source context supplies information Sigma REST does
not expose completely; it is hash-bound source enrichment, never an approval.
"""

from __future__ import annotations

import hashlib
import json
import re
from copy import deepcopy
from types import SimpleNamespace
from typing import Any, Literal
from uuid import UUID

import yaml
from pydantic import BaseModel, ConfigDict, Field, StrictInt

from omni_migrator.deterministic.model_emitter import emit_model, view_path
from omni_migrator.deterministic.sigma_translate import parse_ref
from omni_migrator.extractors.sigma.extractor import _build_bundle
from omni_migrator.ir.schema import FieldIR, TopicIR, ViewIR
from omni_migrator.prepush.reuse import source_fields, validate_target as validate_reuse_target
from omni_migrator.prepush.scope import validate_scope

ROUTES = {"omni_semantic_reconstruction", "warehouse_first_refactor"}
_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
_REFERENCE = re.compile(r"\$\{([^{}]+)\}")
_SECURITY_KEYS = {
    "security", "rls", "cls", "permissions", "rowLevelSecurity",
    "columnLevelSecurity", "pdp",
}
_ID_KEYS = (
    "dataModelId", "workbookId", "pageId", "elementId", "columnId", "metricId",
    "controlId", "relationshipId", "connectionId", "scheduleId", "grantId",
    "sourceId", "inodeId", "id",
)


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class Layout(_Strict):
    x: StrictInt = Field(ge=0, le=23)
    y: StrictInt = Field(ge=0, le=10000)
    w: StrictInt = Field(ge=1, le=24)
    h: StrictInt = Field(ge=1, le=1000)


class SourceSort(_Strict):
    field_locator: str
    descending: bool


class ElementContext(_Strict):
    field_locators: list[str] = Field(min_length=1, max_length=100)
    chart_type: Literal["table", "column", "line", "bar"]
    layout: Layout
    limit: StrictInt = Field(ge=1, le=50000)
    sorts: list[SourceSort]


class ControlContext(_Strict):
    field_locator: str
    target_element_ids: list[str] = Field(min_length=1, max_length=48)
    filter_type: Literal["string"]
    kind: Literal["EQUALS"]
    values: list[str] = Field(max_length=100)


class ReviewedSourceContext(_Strict):
    """A captured/reviewed supplement, not a self-asserted approval credential.

    source_sha256 hashes the entire snapshot except ``prepush_context``. Every
    key must identify an existing source element/control in workbook_id. Importing
    an updated supplement is a source revision and must invalidate prior review.
    """

    schema_version: Literal["sigma-prepush-context.v1"]
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    evidence_ref: str = Field(min_length=1, max_length=500)
    workbook_id: str
    elements: dict[str, ElementContext]
    controls: dict[str, ControlContext]


def source_context_hash(snapshot: dict) -> str:
    source = {key: value for key, value in snapshot.items() if key not in {"prepush_context", "_migration_scope"}}
    return hashlib.sha256(json.dumps(
        source, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")).hexdigest()


def _pointer(key: object) -> str:
    return str(key).replace("~", "~0").replace("/", "~1")


def source_inventory(snapshot: dict) -> list[dict]:
    """Source denominator: every object-list member, including unknown objects.

    Traverse dataModels/workbooks/connections, ignoring scalar lists. Security
    dictionaries are separate objects even when they are not array members.
    Array order is intentionally retained in source_path; reordering is a source
    revision. The independent package validator computes this itself.
    """
    result: list[dict] = []

    def add(row: dict, path: str, kind: str) -> None:
        native = next((str(row[key]) for key in _ID_KEYS if row.get(key) not in (None, "")), None)
        result.append({"source_path": path, "source_id": native or "path:" + path,
                       "source_kind": kind})

    def walk(value: Any, path: str, kind: str) -> None:
        if isinstance(value, list):
            for index, row in enumerate(value):
                child = f"{path}/{index}"
                if isinstance(row, dict):
                    add(row, child, kind)
                walk(row, child, kind)
        elif isinstance(value, dict):
            for key, child in value.items():
                child_path = f"{path}/{_pointer(key)}"
                if key in _SECURITY_KEYS and isinstance(child, dict) and child:
                    add(child, child_path, key)
                walk(child, child_path, key)

    for key in ("dataModels", "workbooks", "connections"):
        walk(snapshot.get(key, []), f"/{key}", key)
    return result


def _json(value: Any) -> str:
    return json.dumps(value, indent=2, ensure_ascii=False, allow_nan=False) + "\n"


def _ident(value: Any) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise ValueError("Target relation and column names must be simple SQL identifiers.")
    return value


def _quote(value: str) -> str:
    return '"' + _ident(value) + '"'


def _literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def physical_source_field(field: FieldIR, raw: dict) -> bool:
    """Identify a physical column from a fresh, source-bound extractor field.

    Call before applying target mappings. SigmaFieldBinder has already validated
    qualified references against the captured source table and column identity;
    physical/self references produce bare SQL identifiers, whereas references to
    another captured field produce ``${field}``. Do not reclassify a formula from
    its text alone or call this with arbitrary/unvalidated IR.
    """
    native_id = raw.get("columnId", raw.get("id"))
    if (field.kind != "dimension" or not field.source_id or str(native_id) != field.source_id
            or not isinstance(field.sql, str) or not _IDENTIFIER.fullmatch(field.sql)
            or field.aggregate is not None or field.filters):
        return False
    formula = raw.get("formula")
    return formula in (None, "") or (isinstance(formula, str) and parse_ref(formula) is not None)


def _physical_source_relation(source: Any) -> bool:
    if not isinstance(source, dict):
        return False
    kinds = [str(source[key]).casefold() for key in ("type", "kind") if key in source]
    # Current captured table type plus the authoritative spec's warehouse-table
    # kind. Conflicting/custom-SQL discriminators cannot be hidden by the other.
    return bool(kinds) and all(kind in {"table", "warehouse-table"} for kind in kinds)


def _target(value: dict, route: str) -> dict:
    if isinstance(value, dict) and "allowed_changes" in value:
        policy = value["allowed_changes"]
        if policy != "model_changes":
            raise ValueError("This artifact path requires model_changes; dashboard_only needs reviewed existing-topic evidence, and validation_only/topic_additions cannot emit model changes.")
        value = {key: child for key, child in value.items() if key != "allowed_changes"}
    if not isinstance(value, dict) or set(value) != {
        "model_id", "connection_id", "document_name", "relations"
    }:
        raise ValueError("Target requires model_id, connection_id, document_name and relations only.")
    for key in ("model_id", "connection_id"):
        try:
            UUID(value[key])
        except (ValueError, TypeError, AttributeError) as exc:
            raise ValueError("Target model and connection IDs must be UUID strings.") from exc
    if not isinstance(value["document_name"], str) or not 1 <= len(value["document_name"]) <= 144:
        raise ValueError("Target document_name must contain between 1 and 144 characters.")
    if not isinstance(value["relations"], dict):
        raise ValueError("Target relations must map exact source view locators to relation bindings.")
    for locator, binding in value["relations"].items():
        if (not isinstance(locator, str) or not isinstance(binding, dict)
                or not {"schema", "table", "columns"} <= set(binding)
                or set(binding) - {"schema", "table", "columns", "modeled_table"}):
            raise ValueError("Each relation needs schema, table and native-ID column mappings.")
        for key in ("schema", "table"):
            _ident(binding[key])
        if route == "warehouse_first_refactor" or "modeled_table" in binding:
            _ident(binding.get("modeled_table"))
        if not isinstance(binding["columns"], dict) or not binding["columns"]:
            raise ValueError("Every relation requires explicit physical column mappings.")
        for key, column in binding["columns"].items():
            if not isinstance(key, str) or not key:
                raise ValueError("Physical column mappings must use captured native column IDs.")
            _ident(column)
        if len(set(binding["columns"].values())) != len(binding["columns"]):
            raise ValueError("Physical columns must not collapse distinct source IDs.")
        if binding.get("modeled_table") == binding["table"]:
            raise ValueError("The modeled destination must not overwrite the captured source table.")
    return deepcopy(value)


def _field_sql(field: FieldIR, fields: dict[str, FieldIR], stack: tuple[str, ...] = ()) -> str:
    """Expand only the bounded IR emitted by the existing context-aware extractor."""
    if field.name in stack:
        raise ValueError("A semantic dependency cycle prevents executable output.")
    sql = field.sql
    if sql is None:
        if field.aggregate == "count":
            return "*"
        raise ValueError("A semantic field is missing its captured SQL binding.")

    def replace(match: re.Match) -> str:
        name = match.group(1)
        if name not in fields or fields[name].kind == "measure":
            raise ValueError("Cross-view and aggregate dependencies need an explicit implementation.")
        return _field_sql(fields[name], fields, (*stack, field.name))

    if _REFERENCE.search(sql):
        return _REFERENCE.sub(replace, sql)
    if sql in fields and fields[sql] is not field:
        return _field_sql(fields[sql], fields, (*stack, field.name))
    # Physical columns were replaced with quoted exact target mappings above.
    if re.fullmatch(r'"[A-Za-z_][A-Za-z0-9_]*"', sql):
        return sql
    raise ValueError("The local compiler does not support this SQL expression shape.")


def _measure_sql(field: FieldIR, fields: dict[str, FieldIR]) -> str:
    expression = _field_sql(field, fields)
    conditions = []
    for name, constraint in (field.filters or {}).items():
        if name not in fields or fields[name].kind == "measure":
            raise ValueError("A filtered measure references an unresolved dimension.")
        if not isinstance(constraint, dict) or set(constraint) != {"is"}:
            raise ValueError("This filtered-measure predicate needs an explicit implementation.")
        value = constraint["is"]
        left = _field_sql(fields[name], fields)
        if isinstance(value, str):
            right = _literal(value)
        elif value is None:
            conditions.append(left + " IS NULL")
            continue
        elif type(value) in (int, float, bool):
            right = str(int(value)) if type(value) is bool else str(value)
        else:
            raise ValueError("This filtered-measure value needs an explicit implementation.")
        conditions.append(left + " = " + right)
    if conditions:
        expression = "CASE WHEN " + " AND ".join(conditions) + " THEN " + (
            "1" if expression == "*" else expression
        ) + " ELSE NULL END"
    aggregates = {"sum": "SUM", "count": "COUNT", "average": "AVG", "max": "MAX", "min": "MIN"}
    if field.aggregate == "count_distinct":
        return f"COUNT(DISTINCT {expression})"
    if field.aggregate not in aggregates:
        raise ValueError("This aggregate is outside the independently executable local subset.")
    return f"{aggregates[field.aggregate]}({expression})"


def _vis(chart: str, dimensions: list[str], measures: list[str]) -> dict:
    fields = dimensions + measures
    if chart == "table":
        inner = {"visType": "omni-table", "config": {}}
    else:
        if len(dimensions) != 1 or len(measures) != 1:
            raise ValueError("Cartesian charts require exactly one dimension and one measure in this compiler.")
        horizontal = chart == "bar"
        axis = "x" if horizontal else "y"
        inner = {"visType": "basic", "config": {
            "configType": "cartesian", "_dependentAxis": axis,
            "y" if horizontal else "x": {"field": {"name": dimensions[0]}},
            "mark": {"type": "line" if chart == "line" else "bar"}, "color": {},
            "series": [{"field": {"name": measures[0]}, axis + "Axis": axis}],
            "tooltip": [{"field": {"name": name}} for name in fields],
        }}
    return {"chartType": chart, "fields": fields, "version": 0, "visConfig": inner}


def _tile_stack(key: str, name: str, layout: Layout) -> dict:
    return {"containerType": "stack", "style": "tile", "name": name, "fillSpace": True,
            "metadata": {"attachedQueryKey": key}, "gridPosition": layout.model_dump(),
            "instanceKey": "tile-stack-" + key,
            "children": [
                {"as": "metadata", "id": key, "type": "query", "format": "name",
                 "instanceKey": "tile-title-" + key},
                {"as": "chart", "id": key, "type": "query", "instanceKey": "tile-chart-" + key},
            ]}


def build(snapshot: dict, route: str, target: dict) -> dict:
    """Return text files and per-source dispositions, without I/O or approval.

    Invalid identities/context raise ValueError. Valid but unsupported objects stay
    in the exact source denominator as blocked; partial useful files do not make
    the package accepted. Direct mode never emits a dbt artifact.
    """
    if route not in ROUTES:
        raise ValueError("Choose one of the two explicit Sigma semantic routes before building.")
    if not isinstance(snapshot, dict):
        raise ValueError("A captured Sigma snapshot object is required.")
    scope = validate_scope(snapshot)
    if scope and scope["issues"]:
        raise ValueError("Selected scope has unresolved dependency evidence; review scope issues before compiling.")
    if isinstance(target, dict) and target.get("allowed_changes") == "dashboard_only":
        return _reuse_build(snapshot, route, target)
    target = _target(target, route)
    context = None
    if snapshot.get("prepush_context") is not None:
        context = ReviewedSourceContext.model_validate(snapshot["prepush_context"])
        if context.source_sha256 != source_context_hash(snapshot):
            raise ValueError("Reviewed source context is stale; recapture it for this exact source revision.")
    inventory = source_inventory(snapshot)
    dispositions = {row["source_path"]: {
        **row, "status": "blocked", "reason": "No supported executable implementation for this source object.",
        "target_paths": [],
    } for row in inventory}
    files: dict[str, str] = {}
    mappings: list[dict] = []
    dependencies = [{"kind": "target_model_and_connection", "status": "unverified",
                     "reason": "Existing model/connection identity and model publication require a separate live gate.",
                     "paths": []}]

    def implemented(path: str, artifacts: list[str], ref: str) -> None:
        if path not in dispositions:
            return
        row = dispositions[path]
        row.update(status="implemented", reason="Compiled from exact source identities and reviewed context.",
                   target_paths=sorted(set(artifacts)))
        for artifact in sorted(set(artifacts)):
            mappings.append({"source_path": path, "source_id": row["source_id"],
                             "target_path": artifact, "target_object_ref": ref})

    bundle = _build_bundle(deepcopy(snapshot), acquisition_mode="manual")
    model = bundle.model.model_copy(deep=True)
    model.topics = []  # Joins are not guessed; each supported view gets its own bounded topic.
    field_sources: dict[str, tuple[ViewIR, FieldIR]] = {}
    source_rows: dict[str, dict] = {}
    source_paths: dict[str, str] = {}
    view_paths: dict[str, str] = {}
    view_rows: dict[str, dict] = {}
    for di, dm in enumerate(snapshot.get("dataModels", [])):
        dm_id = str(dm.get("dataModelId", dm.get("id", "")))
        for pi, page in enumerate(dm.get("spec", {}).get("pages", [])):
            for ei, element in enumerate(page.get("elements", [])):
                element_id = str(element.get("elementId", element.get("id", "")))
                path = f"/dataModels/{di}/spec/pages/{pi}/elements/{ei}"
                view_locator = f"data-model:{dm_id}/source:{element_id}"
                if not dm_id or not element_id or view_locator in view_paths:
                    raise ValueError("Source model/element identities must be present and unique.")
                view_paths[view_locator] = path
                view_rows[view_locator] = element
                for plural, singular, key in (("columns", "column", "columnId"), ("metrics", "metric", "metricId")):
                    for fi, field in enumerate(element.get(plural, [])):
                        locator = f"data-model:{dm_id}/element:{element_id}/{singular}:{field.get(key, field.get('id', ''))}"
                        if locator in source_paths:
                            raise ValueError("Duplicate source field identities cannot be compiled.")
                        source_paths[locator] = f"{path}/{plural}/{fi}"
                        source_rows[locator] = field

    if set(target["relations"]) - set(view_paths):
        raise ValueError("A target relation mapping does not match a captured source view identity.")
    supported_views: list[ViewIR] = []
    for view in model.views:
        binding = target["relations"].get(view.source_locator)
        if binding is None or view.source_locator not in view_paths:
            continue
        raw_view = view_rows[view.source_locator]
        if (not _physical_source_relation(raw_view.get("source"))
                or any(raw_view.get(key) for key in (
                    "filters", "parameters", "security", "rls", "cls", "customSql",
                    "sql", "groupings", "groupBy", "pivot", "window", "cumulative",
                ))):
            dispositions[view_paths[view.source_locator]]["reason"] = (
                "This source relation or its transformations need an explicit supported implementation."
            )
            continue
        view.schema_name, view.source_table = binding["schema"], binding["table"]
        view.connection.database = None
        view.connection.omni_connection_id = target["connection_id"]
        fields = {field.name: field for field in view.fields}
        physical_ids: set[str] = set()
        for field in view.fields:
            raw = source_rows.get(field.source_locator, {})
            if physical_source_field(field, raw):
                physical_ids.add(field.source_id)
                if field.source_id in binding["columns"]:
                    field.sql = _quote(binding["columns"][field.source_id])
                else:
                    field.sql = None
        if set(binding["columns"]) - physical_ids:
            raise ValueError("A physical column mapping does not match a captured physical field identity.")
        # A measure's bare source column name must become a semantic reference.
        # Otherwise a physical target-column rename would affect our local SQL but
        # leave the emitted Omni measure pointing at the old source column.
        for field in view.fields:
            if field.kind == "measure" and field.sql in fields:
                field.sql = "${" + field.sql + "}"
        valid_fields = []
        for field in view.fields:
            try:
                (_measure_sql if field.kind == "measure" else _field_sql)(field, fields)
            except ValueError as exc:
                if field.source_locator in source_paths:
                    dispositions[source_paths[field.source_locator]]["reason"] = str(exc)
                continue
            valid_fields.append(field)
        view.fields = valid_fields
        if not view.fields:
            continue
        if route == "warehouse_first_refactor":
            dimensions = [field for field in view.fields if field.kind == "dimension"]
            if not dimensions:
                continue
            projection = ",\n  ".join(
                _field_sql(field, fields) + " AS " + _quote(field.name) for field in dimensions
            )
            select = f"SELECT\n  {projection}\nFROM {_quote(binding['schema'])}.{_quote(binding['table'])}"
            dbt_path = f"dbt/models/{view.name}.sql"
            files[dbt_path] = "{{ config(materialized='view', schema='" + binding["schema"] + "', alias='" + binding["modeled_table"] + "') }}\n" + select + "\n"
            cols = ", ".join(_quote(field.name) for field in dimensions)
            group = f"SELECT {cols}, COUNT(*) AS _sigma_row_count FROM "
            source_group = group + "source_rows GROUP BY " + cols
            target_group = group + "modeled_rows GROUP BY " + cols
            files[f"dbt/tests/{view.name}_row_equivalence.sql"] = (
                "WITH source_rows AS (\n" + select + "\n), modeled_rows AS (\nSELECT " + cols
                + " FROM {{ ref('" + view.name + "') }}\n), missing_rows AS (\n" + source_group
                + "\nEXCEPT\n" + target_group + "\n), extra_rows AS (\n" + target_group
                + "\nEXCEPT\n" + source_group
                + "\n) SELECT * FROM missing_rows UNION ALL SELECT * FROM extra_rows\n"
            )
            for field in dimensions:
                field.sql = _quote(field.name)
            # Measures stay aggregate functions at query grain, never pre-aggregated without evidence.
            for field in view.fields:
                if field.kind == "measure" and field.sql in fields:
                    field.sql = "${" + field.sql + "}"
            view.source_table = binding["modeled_table"]
        supported_views.append(view)
        model.topics.append(TopicIR(name=view.name, base_view=view.name, label=view.label))
        artifact = "omni/model/" + view_path(view)
        topic_path = f"omni/model/{view.name}.topic"
        implemented(view_paths[view.source_locator], [artifact, topic_path], view.name)
        for field in view.fields:
            if field.source_locator in source_paths:
                implemented(source_paths[field.source_locator], [artifact], f"{view.name}.{field.name}")
                field_sources[field.source_locator] = (view, field)
    model.views = supported_views
    files.update({"omni/model/" + name: text for name, text in emit_model(model).items()})

    if route == "warehouse_first_refactor" and supported_views:
        files["dbt/dbt_project.yml"] = yaml.safe_dump({
            "name": "sigma_prepush", "version": "1.0.0", "config-version": 2,
            "profile": "sigma_prepush", "model-paths": ["models"], "test-paths": ["tests"],
            "macro-paths": ["macros"],
        }, sort_keys=False)
        files["dbt/macros/generate_schema_name.sql"] = (
            "{% macro generate_schema_name(custom_schema_name, node) -%}\n"
            "{{ custom_schema_name if custom_schema_name is not none else target.schema }}\n"
            "{%- endmacro %}\n"
        )
        files["dbt/models/schema.yml"] = yaml.safe_dump({"version": 2, "models": [
            {"name": view.name, "description": "Row-preserving source-bound Sigma projection; not deployed.",
             "columns": [{"name": field.name} for field in view.fields if field.kind == "dimension"]}
            for view in supported_views
        ]}, sort_keys=False)
        dependencies.append({"kind": "warehouse_deployment", "status": "undeployed",
                             "reason": "Run and verify the supplied dbt project with separately configured credentials before target queries. Aggregations remain query-grain Omni measures.",
                             "paths": sorted(name for name in files if name.startswith("dbt/"))})

    _documents(snapshot, context, target, field_sources, files, dispositions, implemented)
    model_files = sorted(path for path in files if path.startswith("omni/model/"))
    if model_files:
        for row in inventory:
            if row["source_kind"] == "connections":
                implemented(row["source_path"], model_files, "connection:" + target["connection_id"])
            elif row["source_kind"] in {"dataModels", "pages"} and row["source_path"].startswith("/dataModels/"):
                children = [child for child in dispositions.values()
                            if child["source_path"].startswith(row["source_path"] + "/")]
                paths = sorted({path for child in children for path in child["target_paths"]})
                if paths:
                    implemented(row["source_path"], paths, "source-container")
    # Container coverage never conceals a blocked descendant.
    _apply_scope_dispositions(scope, dispositions)
    for path in sorted(dispositions, key=len, reverse=True):
        if any(row["status"] == "blocked" for child, row in dispositions.items() if child.startswith(path + "/")):
            dispositions[path].update(status="blocked", reason="One or more contained source objects remain blocked.")
    return {"schema_version": "sigma-prepush-build.v1", "route": route, "files": files,
            "dispositions": list(dispositions.values()), "source_mappings": mappings,
            "dependencies": dependencies, "target_write_authority": False, "production_ready": False}


def _reuse_build(snapshot, route, target):
    """Reuse reviewed target semantics; never emit model, physical SQL or dbt files."""
    target = validate_reuse_target(target, snapshot)
    if route != "omni_semantic_reconstruction":
        raise ValueError("Dashboard-only reuse cannot implement a warehouse-first refactor; choose direct reuse or explicitly allow model changes.")
    context = None
    if snapshot.get("prepush_context") is not None:
        context = ReviewedSourceContext.model_validate(snapshot["prepush_context"])
        if context.source_sha256 != source_context_hash(snapshot):
            raise ValueError("Reviewed source context is stale; recapture it for this exact source revision.")
    inventory = source_inventory(snapshot)
    dispositions = {row["source_path"]: {**row, "status": "blocked", "target_paths": [],
                    "reason": "No verified existing Topic mapping for this source object."} for row in inventory}
    mappings, files = [], {}

    def implemented(path, paths, reference):
        if path not in dispositions:
            return
        row = dispositions[path]
        row.update(status="implemented", target_paths=sorted(set(paths)),
                   reason="Bound to imported existing Topic evidence; live parity remains unverified.")
        mappings.extend({"source_path": path, "source_id": row["source_id"], "target_path": name,
                         "target_object_ref": reference} for name in sorted(set(paths)))

    topic = target["existing_topic"]["inventory"]
    raw_fields = source_fields(snapshot)
    field_sources = {}
    bundle = _build_bundle(deepcopy(snapshot), acquisition_mode="manual")
    existing_view = SimpleNamespace(name=topic["base_view"], fields=[])
    for view in bundle.model.views:
        source_prefix = view.source_locator.replace("/source:", "/element:") + "/"
        source_path = next((path.rsplit("/", 2)[0] for locator, (path, _, _) in raw_fields.items()
                            if locator.startswith(source_prefix)), None)
        # Reusing a Topic does not itself prove unrepresented source transforms.
        raw_view = None
        if source_path:
            raw_view = snapshot
            for part in source_path.strip("/").split("/"):
                raw_view = raw_view[int(part)] if isinstance(raw_view, list) else raw_view[part]
        if (not isinstance(raw_view, dict) or not _physical_source_relation(raw_view.get("source"))
                or any(raw_view.get(key) for key in (
                "filters", "parameters", "security", "rls", "cls", "customSql", "sql", "groupings",
                "groupBy", "pivot", "window", "cumulative"))):
            continue
        for field in view.fields:
            binding = target["existing_topic"]["field_mappings"].get(field.source_locator)
            if not binding or field.source_locator not in raw_fields:
                continue
            definition = topic["fields"][binding["target_field"]]
            path = raw_fields[field.source_locator][0]
            if field.kind != definition["kind"]:
                dispositions[path]["reason"] = "Source and existing Topic field kinds differ."
                continue
            copied = field.model_copy(deep=True)
            copied.name = binding["target_field"].split(".")[1]
            existing_view.fields.append(copied)
            field_sources[field.source_locator] = (existing_view, copied)
            implemented(path, ["target.json"], "existing-topic-field:" + binding["target_field"])
        if source_path and any(path.startswith(source_path + "/") and row["status"] == "implemented"
                               for path, row in dispositions.items()):
            implemented(source_path, ["target.json"], "existing-topic:" + topic["topic_name"])
    _documents(snapshot, context, target, field_sources, files, dispositions, implemented, semantic=topic)
    for path, row in dispositions.items():
        if row["source_kind"] == "connections":
            implemented(path, ["target.json"], "connection:" + target["connection_id"])
        elif row["source_kind"] in {"dataModels", "pages"} and path.startswith("/dataModels/"):
            if any(child.startswith(path + "/") and value["status"] == "implemented"
                   for child, value in dispositions.items()):
                implemented(path, ["target.json"], "source-container")
    _apply_scope_dispositions(validate_scope(snapshot), dispositions)
    for path in sorted(dispositions, key=len, reverse=True):
        if any(row["status"] == "blocked" for child, row in dispositions.items() if child.startswith(path + "/")):
            dispositions[path].update(status="blocked", reason="One or more contained source objects remain blocked.")
    return {"schema_version": "sigma-prepush-build.v1", "route": route, "files": files,
            "dispositions": list(dispositions.values()), "source_mappings": mappings,
            "dependencies": [{"kind": "existing_topic_live_parity", "status": "unverified", "paths": ["target.json"],
                              "reason": "Imported Topic evidence and compatibility notes require a separate live freshness, security and result-parity gate."}],
            "target_write_authority": False, "production_ready": False}


def _apply_scope_dispositions(scope, dispositions):
    if scope:
        for path in scope["excluded_source_paths"]:
            if path in dispositions:
                dispositions[path].update(status="excluded", target_paths=[],
                                          reason="Explicitly excluded from this reviewed pilot; original source evidence is retained.")


def _documents(snapshot, context, target, field_sources, files, dispositions, implemented, semantic=None):
    if context is None:
        return
    scope = validate_scope(snapshot)
    workbooks = snapshot.get("workbooks", [])
    matches = [(index, row) for index, row in enumerate(workbooks)
               if str(row.get("workbookId", row.get("id", ""))) == context.workbook_id]
    if len(matches) != 1:
        raise ValueError("Reviewed context must bind exactly one captured workbook.")
    wi, workbook = matches[0]
    elements = {}
    pages = workbook.get("pages", [])
    for pi, page in enumerate(pages):
        for ei, element in enumerate(page.get("elements", [])):
            identity = str(element.get("elementId", element.get("id", "")))
            if not identity or identity in elements:
                raise ValueError("Workbook element identities must be present and unique.")
            elements[identity] = (pi, element, f"/workbooks/{wi}/pages/{pi}/elements/{ei}")
    control_rows = {}
    for ci, control in enumerate(workbook.get("controls", [])):
        identity = str(control.get("controlId", control.get("id", "")))
        if not identity or identity in control_rows:
            raise ValueError("Workbook control identities must be present and unique.")
        control_rows[identity] = (control, f"/workbooks/{wi}/controls/{ci}")
    if set(context.elements) - set(elements) or set(context.controls) - set(control_rows):
        raise ValueError("Reviewed context references content absent from the captured workbook.")
    document = {"modelId": target["model_id"], "name": target["document_name"],
                "queryPresentations": {"data": {}, "order": []},
                "controls": {"data": {}, "order": []}, "containers": [], "settings": {}}
    tile_meta = {}
    page_children: dict[int, list] = {index: [] for index in range(len(pages))}
    for identity, (pi, element, path) in elements.items():
        if scope and identity not in scope["selected_chart_ids"]:
            continue
        setting = context.elements.get(identity)
        if setting is None:
            continue
        try:
            kind = str(element.get("type", element.get("kind", ""))).lower()
            if kind not in {"table", "chart", "visualization"}:
                raise ValueError("Actions, input tables, and unknown element kinds have no executable implementation.")
            if set(element) - {
                "elementId", "id", "type", "kind", "name", "description", "visualizationType",
                "columns", "filters", "sorts", "parameters", "actions", "drilldowns",
                "interactions", "cumulative", "window", "totals", "security",
            }:
                raise ValueError("Additional captured visual metadata needs an explicit implementation; it will not be silently discarded.")
            if setting.chart_type != (element.get("visualizationType") or ("table" if kind == "table" else None)):
                raise ValueError("Reviewed chart type must agree with the captured visualization type.")
            if any(element.get(key) for key in ("filters", "sorts", "parameters", "actions", "drilldowns", "interactions", "cumulative", "window", "totals", "security")):
                raise ValueError("Captured element behavior requires an explicit supported implementation.")
            if setting.layout.x + setting.layout.w > 24:
                raise ValueError("Reviewed layout exceeds Omni's 24-column grid.")
            box = setting.layout
            for placed in page_children[pi]:
                other = placed["gridPosition"]
                if (box.x < other["x"] + other["w"] and box.x + box.w > other["x"]
                        and box.y < other["y"] + other["h"] and box.y + box.h > other["y"]):
                    raise ValueError("Reviewed layout rectangles overlap; resolve the source layout explicitly.")
            if len(set(setting.field_locators)) != len(setting.field_locators):
                raise ValueError("Duplicate selected field identities are not supported.")
            selected = [field_sources[locator] for locator in setting.field_locators]
            if len({view.name for view, field in selected}) != 1:
                raise ValueError("Cross-view dashboard queries require a separately implemented join contract.")
            view = selected[0][0]
            fields = {field.name: field for field in view.fields}
            dimensions = [f"{view.name}.{field.name}" for _, field in selected if field.kind == "dimension"]
            measures = [f"{view.name}.{field.name}" for _, field in selected if field.kind == "measure"]
            key = str(len(tile_meta) + 1)
            if len(tile_meta) >= 48:
                raise ValueError("A v2 document cannot contain more than 48 query presentations.")
            name = str(element.get("name") or identity)
            if not 1 <= len(name) <= 144:
                raise ValueError("Captured tile name is outside the target length limit.")
            sorts = []
            for sort in setting.sorts:
                if sort.field_locator not in setting.field_locators:
                    raise ValueError("Sort fields must be selected source fields.")
                _, field = field_sources[sort.field_locator]
                sorts.append({"column_name": f"{view.name}.{field.name}", "descending": sort.descending})
            topic_name = semantic["topic_name"] if semantic else view.name
            tile = {"name": name, "type": "query", "topicName": topic_name,
                    "prefersChart": setting.chart_type != "table", "automaticVis": False,
                    "query": {"table": view.name, "fields": dimensions + measures,
                              "join_paths_from_topic_name": topic_name, "limit": setting.limit,
                              "sorts": sorts, "filters": {}, "pivots": [], "calculations": [],
                              "column_totals": {}, "row_totals": {}, "fill_fields": [], "userEditedSQL": False},
                    "visConfig": _vis(setting.chart_type, dimensions, measures), "resultConfig": {}}
            if "description" in element:
                if not isinstance(element["description"], str) or len(element["description"]) > 500:
                    raise ValueError("Captured tile description is outside the target contract.")
                tile["description"] = element["description"]
            document["queryPresentations"]["data"][key] = tile
            document["queryPresentations"]["order"].append(key)
            page_children[pi].append(_tile_stack(key, name, setting.layout))
            tile_meta[identity] = (key, view, selected, setting, path)
        except (KeyError, ValueError) as exc:
            dispositions[path]["reason"] = str(exc) if isinstance(exc, ValueError) else "A selected source field is unresolved or blocked."

    filter_children = []
    predicates: dict[str, list[str]] = {identity: [] for identity in tile_meta}
    used_control_fields: set[tuple[str, str]] = set()
    for identity, (raw, path) in control_rows.items():
        if scope and identity not in scope["required_control_ids"]:
            continue
        setting = context.controls.get(identity)
        if setting is None:
            continue
        if scope:
            selected_targets = [item for item in setting.target_element_ids if item in scope["selected_chart_ids"]]
            if not selected_targets:
                dispositions[path]["reason"] = "Required upstream control has no supported selected presentation target."
                continue
            setting = setting.model_copy(update={"target_element_ids": selected_targets})
        try:
            if str(raw.get("type", "")).lower() not in {"list", "list-control", "dropdown", "string"}:
                raise ValueError("This control type has no supported executable implementation.")
            if set(raw) - {"controlId", "id", "type", "name", "values", "description", "hidden", "required"}:
                raise ValueError("Additional captured control behavior needs an explicit implementation; it will not be silently discarded.")
            if any(key in raw and type(raw[key]) is not bool for key in ("hidden", "required")):
                raise ValueError("Captured control hidden/required flags must be explicit booleans.")
            if raw.get("values") != setting.values:
                raise ValueError("Reviewed control defaults must equal the captured source values.")
            view, field = field_sources[setting.field_locator]
            if field.kind != "dimension":
                raise ValueError("String controls require a dimension binding.")
            if set(setting.target_element_ids) - set(tile_meta):
                raise ValueError("Control targets include content without an executable query.")
            affected = set(setting.target_element_ids)
            field_name = f"{view.name}.{field.name}"
            scope = {}
            planned_predicates = []
            for element_id, (key, tile_view, selected, setting_tile, tile_path) in tile_meta.items():
                if element_id not in affected:
                    scope[key] = False
                    continue
                if tile_view.name != view.name or (element_id, field_name) in used_control_fields:
                    raise ValueError("Cross-view or duplicate-field control semantics require explicit implementation.")
                scope[key] = field_name
                if setting.values and not semantic:
                    expression = _field_sql(field, {item.name: item for item in view.fields})
                    planned_predicates.append((element_id, expression + " IN (" + ", ".join(map(_literal, setting.values)) + ")"))
            key = "control_" + str(len(document["controls"]["data"]) + 1)
            document["controls"]["data"][key] = {
                "config": {"id": key, "type": "string", "kind": "EQUALS", "values": setting.values,
                           "fieldName": field_name, "topic": semantic["topic_name"] if semantic else view.name, "base_view": view.name,
                           "label": str(raw.get("name") or identity)}, "map": scope}
            document["controls"]["data"][key]["config"].update({
                option: raw[option] for option in ("description", "hidden", "required") if option in raw
            })
            document["controls"]["order"].append(key)
            if not raw.get("hidden", False):
                filter_children.append({"type": "filter", "id": key, "instanceKey": "filter-" + key})
            for element_id in affected:
                used_control_fields.add((element_id, field_name))
            for element_id, predicate in planned_predicates:
                predicates[element_id].append(predicate)
            implemented(path, ["omni/document.create.json", "omni/document.patch.json"], "controls.data." + key)
        except (KeyError, ValueError) as exc:
            dispositions[path]["reason"] = str(exc) if isinstance(exc, ValueError) else "The control's source field is unresolved or blocked."

    if not tile_meta:
        return
    for identity, (key, view, selected, setting, path) in tile_meta.items():
        if semantic:
            query_path = f"queries/{key}.json"
            defaults = [{"field": control["map"][key], "kind": control["config"]["kind"], "values": control["config"]["values"]}
                        for control in document["controls"]["data"].values() if control["map"][key] is not False]
            files[query_path] = _json({"schema_version": "omni-existing-topic-query.v1", "model_id": target["model_id"],
                                      "connection_id": target["connection_id"], "topic_name": semantic["topic_name"],
                                      "inventory_sha256": target["existing_topic"]["inventory_sha256"],
                                      "query": document["queryPresentations"]["data"][key]["query"], "control_defaults": defaults})
            implemented(path, ["omni/document.create.json", "omni/document.patch.json", query_path], "queryPresentations.data." + key)
            continue
        fields = {field.name: field for field in view.fields}
        projection, groups = [], []
        # Query.fields order is dimensions then measures; SQL aliases use full Omni field names.
        ordered = sorted(selected, key=lambda item: item[1].kind == "measure")
        for _, field in ordered:
            expression = (_measure_sql if field.kind == "measure" else _field_sql)(field, fields)
            projection.append(expression + ' AS "' + view.name + "." + field.name + '"')
            if field.kind == "dimension":
                groups.append(expression)
        sql = "SELECT\n  " + ",\n  ".join(projection) + f"\nFROM {_quote(view.schema_name)}.{_quote(view.source_table)}"
        if predicates[identity]:
            sql += "\nWHERE " + " AND ".join(predicates[identity])
        if groups:
            sql += "\nGROUP BY " + ", ".join(groups)
        if setting.sorts:
            sql += "\nORDER BY " + ", ".join(
                '"' + view.name + "." + field_sources[sort.field_locator][1].name + '"'
                + (" DESC" if sort.descending else " ASC") for sort in setting.sorts
            )
        sql += "\nLIMIT " + str(setting.limit) + "\n"
        query_path = f"queries/{key}.sql"
        files[query_path] = sql
        implemented(path, ["omni/document.create.json", "omni/document.patch.json", query_path], "queryPresentations.data." + key)
    if filter_children:
        document["containers"].append({"instanceKey": "filter-bar", "containerType": "stack",
                                       "direction": "row", "children": filter_children})
    for pi, page in enumerate(pages):
        if not page_children[pi]:
            continue
        document["containers"].append({"containerType": "page", "instanceKey": f"page-{pi + 1}",
                                       "name": str(page.get("name") or page.get("pageId") or "Page"),
                                       "container": {"containerType": "grid", "instanceKey": f"page-{pi + 1}-grid",
                                                     "children": page_children[pi]}})
        implemented(f"/workbooks/{wi}/pages/{pi}", ["omni/document.create.json", "omni/document.patch.json"], f"containers.page-{pi + 1}")
    implemented(f"/workbooks/{wi}", ["omni/document.create.json", "omni/document.patch.json"], "document")
    files["omni/document.create.json"] = _json(document)
    files["omni/document.patch.json"] = _json({key: value for key, value in document.items() if key != "modelId"})

"""Sigma extractor: REST API snapshots (data models) -> canonical IR. Model-only (dashboards are
`extractors/sigma/dashboard.py`, same Phase-2 split every other source uses).

Sigma has no portable project-export format. Live acquisition uses `ApiInput`; manual acquisition
accepts exactly one bounded JSON file previously produced by `SigmaApi.snapshot()`. Both paths run
the same pure `_build_bundle` transform. An `ApiInput` whose `auth` dict carries a pre-fetched
`"snapshot"` also skips the network call, matching Metabase/Looker.

**Build against "data models," never the deprecated "datasets"** (plan §6.4) — datasets can't be
edited after 2026-06-02 and are gone entirely by 2026-09-15; `GET /v2/datasets/{id}` is already
marked deprecated in Sigma's own API reference.

Mapping (plan §6.4):
- A data model spec's `pages[].elements[]` (`kind: "table"`) -> `ViewIR`, one per element; its
  `source.path` (`[db, schema, table]`) -> `schema_name`/`source_table`, the same confidence tier
  as Looker's `sql_table_name` split or Metabase's `table.schema`.
- `columns[]` -> `FieldIR` dimensions. A column whose `formula` is empty, or a bare passthrough
  ref to its own name, is a plain physical column (bare `sql:`, Omni infers the rest). Any other
  formula is a genuine calculated column — no deterministic Omni equivalent for row-context
  expressions (same posture as Power BI's DAX calculated columns, `powerbi/extractor.py`
  `_add_calculated_columns`): flagged `untranslatable` with the formula as hint, no `FieldIR` added,
  always AI.
- **Metrics** (Sigma's reusable, standardized calcs — analogous to Omni measures, distinct from
  plain `columns[]`) -> a real measure via `deterministic.sigma_translate.translate_formula`,
  same "translate the clean aggregate wrapper, flag the rest" discipline as DAX/MBQL. This is
  where `SumIf`/`CountIf`/`AvgIf` become filtered measures — a genuinely tractable deterministic
  win Sigma's own formula-condition syntax gives us (plan §6.4).
- Metrics and relationships use Sigma's current code representation: each is nested on its source
  table element. Legacy top-level arrays remain readable for existing snapshots. Native object IDs
  and element-scoped source locators are retained in the IR.
- Connections -> `ConnectionRef.dialect` via `api.normalize_sigma_connection_type` — Sigma gives a
  real `type` field (not a heuristic sniffed from free text the way Power BI's Power Query M
  detection is), but the full enum of values wasn't found in the docs (only `"bigQuery"` appears
  in an inline example) — extend `api._TYPE_DIALECT` before relying on it beyond Snowflake/BigQuery.

Data Model ``/spec`` is the authoritative model representation. Workbook REST resources remain
content/query/lineage/governance evidence and are never labeled as an equivalent portable model
specification.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from omni_migrator.core.contracts import ApiInput, ExtractCtx, ExtractorInput, FileInput
from omni_migrator.deterministic.sigma_translate import parse_ref
from omni_migrator.extractors.sigma.api import SigmaApi, normalize_sigma_connection_type
from omni_migrator.extractors.sigma.field_binding import CapturedField, SigmaFieldBinder
from omni_migrator.ir.schema import (
    AcquisitionDependencyIR,
    AcquisitionEvidenceIR,
    ConnectionRef,
    FieldIR,
    JoinIR,
    MigrationBundle,
    ModelIR,
    Provenance,
    SemanticRequirementIR,
    TopicIR,
    UntranslatableNote,
    ViewIR,
)

MAX_SIGMA_SNAPSHOT_BYTES = 100 * 1024 * 1024
SIGMA_SNAPSHOT_CONTRACT = "sigma-api-v2"
MAX_OPERATIONAL_METADATA_DEPTH = 5
MAX_OPERATIONAL_METADATA_ITEMS = 40
MAX_OPERATIONAL_METADATA_STRING = 256

_SECRET_VALUE_RE = re.compile(
    r"(?i)(?:bearer\s+\S+|sk-[a-z0-9_-]{8,}|"
    r"(?:api[_-]?key|token|secret|password|authorization)\s*[:=]\s*\S+)"
)
_EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
_IDENTITY_KEYS = {
    "createdby",
    "email",
    "emails",
    "memberid",
    "ownerid",
    "principal",
    "principalid",
    "recipient",
    "recipients",
    "updatedby",
    "useremail",
    "userid",
    "username",
}


def _snake(text: str) -> str:
    s = re.sub(r"[^0-9a-zA-Z]+", "_", (text or "").strip()).strip("_").lower()
    if s and s[0].isdigit():
        s = f"f_{s}"
    return s or "field"


def _content_fingerprint(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _field_identity_suffix(source_id: str | None, fallback: object) -> str:
    if source_id:
        token = _snake(source_id)[:24]
        return f"{token}_{_content_fingerprint(source_id)[:8]}"
    return _content_fingerprint(fallback)[:10]


def _stable_field_name(
    *,
    base: str,
    source_id: str | None,
    fallback: object,
    used: set[str],
    force_suffix: bool,
) -> str:
    candidate = f"{base}__{_field_identity_suffix(source_id, fallback)}" if force_suffix else base
    if candidate not in used:
        used.add(candidate)
        return candidate
    discriminator = _content_fingerprint(
        {"source_id": source_id, "fallback": fallback, "candidate": candidate}
    )[:10]
    candidate = f"{base}__{discriminator}"
    suffix = 2
    while candidate in used:
        candidate = f"{base}__{discriminator}_{suffix}"
        suffix += 1
    used.add(candidate)
    return candidate


def _column_field_names(columns: list) -> tuple[list[tuple[dict, str, str]], set[str]]:
    records = [column for column in columns if isinstance(column, dict)]
    bases = [
        _snake(
            str(
                column.get("name")
                or column.get("label")
                or _row_id(column, "columnId", "id")
                or "field"
            )
        )
        for column in records
    ]
    counts: dict[str, int] = {}
    for base in bases:
        counts[base] = counts.get(base, 0) + 1
    collisions = {base for base, count in counts.items() if count > 1}
    used: set[str] = set()
    named: list[tuple[dict, str, str]] = []
    for index, (column, base) in enumerate(zip(records, bases, strict=True)):
        source_id = _row_id(column, "columnId", "id")
        name = _stable_field_name(
            base=base,
            source_id=source_id,
            fallback={"column": column, "ordinal": index},
            used=used,
            force_suffix=base in collisions,
        )
        named.append((column, name, base))
    return named, collisions


def _identity_summary(value: object) -> dict:
    values = value if isinstance(value, list) else [value]
    bounded = values[:MAX_OPERATIONAL_METADATA_ITEMS]
    summary: dict = {
        "redacted": "identity",
        "count": len(values),
        "sha256": [_content_fingerprint(item) for item in bounded],
    }
    if len(values) > len(bounded):
        summary["omitted_items"] = len(values) - len(bounded)
    return summary


def _bounded_review_metadata(value: object, *, key: str | None = None, depth: int = 0) -> object:
    """Keep review context deterministic and bounded while excluding credentials and identities."""
    normalized_key = re.sub(r"[^a-z0-9]", "", (key or "").casefold())
    if any(
        marker in normalized_key
        for marker in (
            "secret",
            "password",
            "token",
            "credential",
            "apikey",
            "privatekey",
            "authorization",
            "cookie",
        )
    ):
        return {"redacted": "secret"}
    if normalized_key in _IDENTITY_KEYS:
        return _identity_summary(value)
    if depth >= MAX_OPERATIONAL_METADATA_DEPTH:
        return {"truncated": "max_depth"}
    if isinstance(value, dict):
        items = sorted(value.items(), key=lambda item: str(item[0]))
        result = {
            str(child_key): _bounded_review_metadata(
                child_value,
                key=str(child_key),
                depth=depth + 1,
            )
            for child_key, child_value in items[:MAX_OPERATIONAL_METADATA_ITEMS]
        }
        if len(items) > MAX_OPERATIONAL_METADATA_ITEMS:
            result["_omitted_keys"] = len(items) - MAX_OPERATIONAL_METADATA_ITEMS
        return result
    if isinstance(value, list):
        result = [
            _bounded_review_metadata(item, key=key, depth=depth + 1)
            for item in value[:MAX_OPERATIONAL_METADATA_ITEMS]
        ]
        if len(value) > MAX_OPERATIONAL_METADATA_ITEMS:
            result.append({"_omitted_items": len(value) - MAX_OPERATIONAL_METADATA_ITEMS})
        return result
    if isinstance(value, str):
        if _EMAIL_RE.fullmatch(value.strip()):
            return _identity_summary(value)
        if _SECRET_VALUE_RE.search(value):
            return {"redacted": "secret"}
        if len(value) > MAX_OPERATIONAL_METADATA_STRING:
            return {
                "value": value[:MAX_OPERATIONAL_METADATA_STRING],
                "truncated": True,
                "sha256": _content_fingerprint(value),
            }
        return value
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return _bounded_review_metadata(str(value), key=key, depth=depth)


def _operational_config(row: dict, *, blocking: bool) -> dict:
    return {
        "blocking": blocking,
        "review_metadata": _bounded_review_metadata(row),
    }


def _workbook_query_evidence(workbook: dict) -> list[dict]:
    """Unify query rows and page-enriched generated SQL without retaining duplicate evidence."""
    rows: dict[str, dict] = {}

    def add(raw: object, element_id: str | None = None) -> None:
        if raw in (None, "", {}, []):
            return
        query = dict(raw) if isinstance(raw, dict) else {"sql": raw}
        if element_id:
            query.setdefault("elementId", element_id)
        key = _row_id(query, "queryId", "id") or (
            f"{_row_id(query, 'elementId') or 'query'}:{_content_fingerprint(query)}"
        )
        rows[key] = {**rows.get(key, {}), **query}

    for query in workbook.get("queries", []) or []:
        add(query)
    for page in workbook.get("pages", []) or []:
        for element in page.get("elements", []) or []:
            add(element.get("generatedSql"), _row_id(element, "elementId", "id"))
    return list(rows.values())


def _is_passthrough(formula: str | None, column_name: str) -> bool:
    """A column whose formula is empty, or a bare same-table ref to its own name, is a plain
    physical column — Omni infers the rest when the field name already matches (same rule
    `model_emitter._bare_sql` applies at emit time)."""
    if not formula:
        return True
    ref = parse_ref(formula)
    return (
        ref is not None and ref[0] is None and ref[1].strip().lower() == column_name.strip().lower()
    )


def _row_id(row: dict, *keys: str) -> str | None:
    for key in keys:
        value = row.get(key)
        if value not in (None, ""):
            return str(value)
    return None


def _merge_columns(summary: list, details: list[dict]) -> list[dict]:
    """Merge formula-bearing detail rows into source/spec column summaries by stable ID."""
    by_id = {
        column_id: dict(column)
        for column in details
        if (column_id := _row_id(column, "columnId", "id")) is not None
    }
    merged: list[dict] = []
    seen: set[str] = set()
    for raw in summary:
        base = dict(raw) if isinstance(raw, dict) else {"columnId": str(raw)}
        column_id = _row_id(base, "columnId", "id")
        detail = by_id.get(column_id or "")
        merged.append({**base, **detail} if detail else base)
        if column_id:
            seen.add(column_id)
    merged.extend(row for column_id, row in by_id.items() if column_id not in seen)
    return merged


def _data_model_elements(data_model: dict) -> list[dict]:
    """Combine spec elements with documented source/column inventories without inventing joins."""
    elements: list[dict] = []
    positions: dict[str, int] = {}
    for page in data_model.get("spec", {}).get("pages", []) or []:
        for raw in page.get("elements", []) or []:
            element = dict(raw)
            element_id = _row_id(element, "elementId", "id")
            if element_id is not None:
                positions[element_id] = len(elements)
            elements.append(element)

    for raw in data_model.get("sources", []) or []:
        source = dict(raw)
        element_id = _row_id(source, "elementId", "id", "sourceId", "inodeId")
        if element_id is None:
            continue
        normalized_source = dict(source.get("source") or {})
        for key in (
            "connectionId",
            "path",
            "sourcePath",
            "database",
            "schema",
            "schemaName",
            "table",
            "tableName",
            "inodeId",
            "type",
        ):
            if source.get(key) not in (None, ""):
                normalized_source.setdefault(key, source[key])
        if element_id in positions:
            index = positions[element_id]
            current = elements[index]
            elements[index] = {
                **source,
                **current,
                "source": {**normalized_source, **dict(current.get("source") or {})},
            }
        else:
            positions[element_id] = len(elements)
            elements.append(
                {
                    **source,
                    "id": source.get("id") or element_id,
                    "elementId": source.get("elementId") or element_id,
                    "kind": source.get("kind") or source.get("type") or "table",
                    "source": normalized_source,
                    "columns": [],
                }
            )

    columns_by_element: dict[str, list[dict]] = {}
    for column in data_model.get("columns", []) or []:
        if element_id := _row_id(column, "elementId", "sourceId"):
            columns_by_element.setdefault(element_id, []).append(dict(column))
    for element in elements:
        element_id = _row_id(element, "elementId", "id")
        element["columns"] = _merge_columns(
            list(element.get("columns") or []), columns_by_element.get(element_id or "", [])
        )
    return elements


def _metric_records(data_model: dict) -> list[tuple[str | None, dict, str]]:
    """Return current nested metrics first, then non-duplicate legacy top-level metrics."""
    records: list[tuple[str | None, dict, str]] = []
    seen: dict[tuple[str | None, str], tuple[str, str]] = {}

    def add(element_id: str | None, raw: object, representation: str) -> None:
        if not isinstance(raw, dict):
            return
        metric = dict(raw)
        metric_id = _row_id(metric, "metricId", "id")
        identity = metric_id or _content_fingerprint(metric)
        key = (element_id, identity)
        fingerprint = _content_fingerprint({
            name: value for name, value in metric.items()
            if name not in {"elementId", "sourceElementId"}
        })
        # Deduplicate only an identical legacy copy of a current nested metric. Conflicting
        # definitions or repeated IDs within one representation must reach the binding gate.
        if representation == "legacy" and seen.get(key) == ("nested", fingerprint):
            return
        seen[key] = (representation, fingerprint)
        records.append((element_id, metric, representation))

    for element in _data_model_elements(data_model):
        element_id = _row_id(element, "elementId", "id")
        for metric in element.get("metrics", []) or []:
            add(element_id, metric, "nested")
    for metric in data_model.get("spec", {}).get("metrics", []) or []:
        element_id = _row_id(metric, "elementId", "sourceElementId") if isinstance(metric, dict) else None
        add(element_id, metric, "legacy")
    return records


def _relationship_records(data_model: dict) -> list[tuple[str | None, dict, str]]:
    """Return current element-nested relationships plus legacy top-level compatibility rows."""
    records: list[tuple[str | None, dict, str]] = []
    seen: set[tuple[str | None, str]] = set()

    def add(source_element_id: str | None, raw: object, representation: str) -> None:
        if not isinstance(raw, dict):
            return
        relationship = dict(raw)
        relationship_id = _row_id(relationship, "relationshipId", "id")
        identity = relationship_id or _content_fingerprint(relationship)
        key = (source_element_id, identity)
        if key in seen:
            return
        seen.add(key)
        records.append((source_element_id, relationship, representation))

    for element in _data_model_elements(data_model):
        element_id = _row_id(element, "elementId", "id")
        for relationship in element.get("relationships", []) or []:
            add(element_id, relationship, "nested")
    for relationship in data_model.get("spec", {}).get("relationships", []) or []:
        source_element_id = (
            _row_id(relationship, "fromElementId", "sourceElementId")
            if isinstance(relationship, dict)
            else None
        )
        add(source_element_id, relationship, "legacy")
    return records


def _workbook_version_evidence(workbook: dict) -> tuple[str, str] | None:
    """Recognize explicit acquisition pins, not merely tags listed on a mutable workbook."""
    evidence = workbook.get("_omnikit_version_evidence")
    if not isinstance(evidence, dict):
        return None
    tag_name = _row_id(evidence, "tagName", "tag")
    if str(evidence.get("kind") or "").casefold() == "tag" and tag_name:
        return "tag", tag_name
    bookmark_id = _row_id(evidence, "bookmarkId", "bookmark")
    if str(evidence.get("kind") or "").casefold() == "bookmark" and bookmark_id:
        return "bookmark", bookmark_id
    return None


def _source_location(source: dict) -> tuple[str | None, str | None]:
    path = source.get("path") or source.get("sourcePath") or []
    if isinstance(path, str):
        path = [part for part in path.split(".") if part]
    if not isinstance(path, list):
        path = []
    table = path[-1] if path else source.get("table") or source.get("tableName")
    schema = path[-2] if len(path) >= 2 else source.get("schema") or source.get("schemaName")
    return str(table) if table else None, str(schema) if schema else None


def _unique_view_name(base: str, scope: str, element_id: str | None, used: set[str]) -> str:
    candidates = [base, f"{scope}__{base}"]
    if element_id:
        candidates.append(f"{scope}__{base}__{_snake(element_id)}")
    for candidate in candidates:
        if candidate not in used:
            used.add(candidate)
            return candidate
    suffix = 2
    while f"{candidates[-1]}_{suffix}" in used:
        suffix += 1
    name = f"{candidates[-1]}_{suffix}"
    used.add(name)
    return name


def _formula_requirement(
    *, data_model_id: str | None, element_id: str | None, column: dict, reason: str,
    field_kind: str = "column", binding_issues: list[dict] | None = None,
) -> SemanticRequirementIR:
    column_id = _row_id(column, "columnId", "metricId", "id")
    label = column.get("name") or column.get("label") or column_id or "column"
    return SemanticRequirementIR(
        source_id=column_id,
        source_locator=(
            f"data-model:{data_model_id}/element:{element_id}/{field_kind}:{column_id}"
            if data_model_id and element_id and column_id
            else None
        ),
        object_type="dynamic_field",
        name=f"sigma_formula_{_snake(str(label))}",
        support_outcome="decision_required",
        reason=reason,
        config={
            "formula": column.get("formula"), "source_label": label,
            "source_element_id": element_id, "source_field_id": column_id,
            "blocking": True, "binding_issues": binding_issues or [],
        },
    )


def _build_views(
    data_model: dict,
    dialects: dict[str, str],
    used_names: set[str] | None = None,
) -> tuple[
    dict[str, ViewIR],
    dict[str, str],
    dict[str, tuple[str, str]],
    list[SemanticRequirementIR],
]:
    """Build views from merged spec/source evidence and retain unresolved formulas as decisions."""
    views: dict[str, ViewIR] = {}
    element_view: dict[str, str] = {}
    column_ref: dict[str, tuple[str, str]] = {}
    requirements: list[SemanticRequirementIR] = []
    captured_fields: list[CapturedField] = []
    used_names = used_names if used_names is not None else set()
    data_model_id = _row_id(data_model, "dataModelId", "id")
    scope = _snake(str(data_model.get("name") or data_model_id or "sigma_model"))

    for element in _data_model_elements(data_model):
        element_kind = str(element.get("kind") or element.get("type") or "").casefold()
        if element_kind not in {"table", "warehouse-table", "warehousetable", "source"}:
            continue
        source = dict(element.get("source") or {})
        table, schema = _source_location(source)
        element_id = _row_id(element, "elementId", "id")
        base_name = _snake(
            str(element.get("name") or source.get("name") or table or element_id or "")
        )
        name = _unique_view_name(base_name, scope, element_id, used_names)
        if element_id:
            element_view[element_id] = name
        connection_id = source.get("connectionId") or element.get("connectionId")
        view = ViewIR(
            source_id=element_id,
            source_locator=(
                f"data-model:{data_model_id}/source:{element_id}"
                if data_model_id and element_id
                else None
            ),
            name=name,
            label=element.get("name") or source.get("name") or None,
            source_table=table,
            schema_name=schema,
            connection=ConnectionRef(
                source_connection_name=connection_id,
                dialect=dialects.get(str(connection_id), "other"),
            ),
        )
        if table is None:
            view.untranslatable.append(
                UntranslatableNote(
                    object=f"Sigma source {element.get('name') or element_id}",
                    reason="The acquired source has no physical table/path locator; map or create "
                    "its Omni view explicitly.",
                    severity="blocker",
                    hint=str(source.get("type") or element.get("type") or "unknown source"),
                )
            )

        named_columns, field_name_collisions = _column_field_names(
            list(element.get("columns", []) or [])
        )
        if field_name_collisions:
            view.untranslatable.append(
                UntranslatableNote(
                    object=f"Sigma view {element.get('name') or element_id}",
                    reason="Multiple source fields normalize to the same Omni field name. "
                    "OmniKit retained each source ID and applied deterministic identity suffixes; "
                    "review the physical SQL bindings before deployment.",
                    severity="warning",
                    hint=", ".join(sorted(field_name_collisions)),
                )
            )

        for index, (col, col_name, source_sql_name) in enumerate(named_columns):
            column_id = _row_id(col, "columnId", "id")
            captured_fields.append(CapturedField(
                key=f"{name}/column/{index}", element_id=element_id, view_name=name,
                source_id=column_id, field_name=col_name, sql_name=source_sql_name,
                row=col, element=element,
            ))
        views[name] = view

    _capture_metrics(data_model, views, element_view, captured_fields, requirements)
    binder = SigmaFieldBinder(captured_fields)
    duplicate_ids: set[str] = set()
    for captured in captured_fields:
        result = binder.compile(captured.key)
        view = views[captured.view_name]
        field_kind = "metric" if captured.is_metric else "column"
        label = captured.row.get("name") or captured.row.get("label") or captured.source_id
        if result.issues:
            issues = [{"reference": issue.reference, "reason": issue.reason}
                      for issue in result.issues]
            reason = "; ".join(f"{item['reference']}: {item['reason']}" for item in issues)
            view.untranslatable.append(UntranslatableNote(
                object=f"{'metric' if captured.is_metric else 'calculated column'} {label}",
                severity="blocker", reason=reason, hint=captured.row.get("formula"),
            ))
            requirements.append(_formula_requirement(
                data_model_id=data_model_id, element_id=captured.element_id,
                column=captured.row, reason=reason, field_kind=field_kind, binding_issues=issues,
            ))
            continue
        locator = (
            f"data-model:{data_model_id}/element:{captured.element_id}/{field_kind}:{captured.source_id}"
            if captured.representation != "legacy"
            else f"data-model:{data_model_id}/metric:{captured.source_id}"
        )
        view.fields.append(FieldIR(
            source_id=captured.source_id, source_locator=locator,
            name=captured.field_name, source_name=str(label), kind=result.kind,
            data_type="number" if result.kind == "measure" else "string",
            sql=result.sql, aggregate=result.aggregate, filters=result.filters,
            description=captured.row.get("description") or None,
            **({"hidden": captured.row["hidden"]} if "hidden" in captured.row else {}),
        ))
        if captured.source_id in column_ref or captured.source_id in duplicate_ids:
            column_ref.pop(captured.source_id, None)
            duplicate_ids.add(captured.source_id)
        else:
            column_ref[captured.source_id] = (captured.view_name, captured.field_name)
    for view in views.values():
        # Record the now-compiled collection as set for exclude_unset source-preserving exports.
        view.fields = list(view.fields)
    return views, element_view, column_ref, requirements


def _build_relationships(
    data_model: dict,
    views: dict[str, ViewIR],
    element_view: dict[str, str],
    column_ref: dict[str, tuple[str, str]],
) -> tuple[dict[str, TopicIR], list[UntranslatableNote]]:
    """Translate current element-nested relationship keys and legacy top-level rows."""
    topics: dict[str, TopicIR] = {}
    notes: list[UntranslatableNote] = []
    data_model_id = _row_id(data_model, "dataModelId", "id")
    for source_element_id, relationship, representation in _relationship_records(data_model):
        relationship_id = _row_id(relationship, "relationshipId", "id")
        target_element_id = _row_id(relationship, "targetElementId", "toElementId")
        from_view = element_view.get(source_element_id or "")
        to_view = element_view.get(target_element_id or "")
        raw_keys = relationship.get("keys", []) if representation == "nested" else []
        if representation == "legacy":
            raw_keys = [
                {
                    "sourceColumnId": relationship.get("fromColumnId"),
                    "targetColumnId": relationship.get("toColumnId"),
                }
            ]
        key_pairs: list[tuple[tuple[str, str], tuple[str, str]]] = []
        unresolved_keys: list[str] = []
        for index, raw_key in enumerate(raw_keys or []):
            if not isinstance(raw_key, dict):
                unresolved_keys.append(str(index))
                continue
            source_column_id = _row_id(raw_key, "sourceColumnId", "fromColumnId")
            target_column_id = _row_id(raw_key, "targetColumnId", "toColumnId")
            source_column = column_ref.get(source_column_id or "")
            target_column = column_ref.get(target_column_id or "")
            if (
                source_column is None
                or target_column is None
                or source_column[0] != from_view
                or target_column[0] != to_view
            ):
                unresolved_keys.append(
                    f"{source_column_id or 'missing'}->{target_column_id or 'missing'}"
                )
                continue
            key_pairs.append((source_column, target_column))

        locator = (
            f"data-model:{data_model_id}/element:{source_element_id}/relationship:"
            f"{relationship_id}"
            if data_model_id and source_element_id and relationship_id
            else (
                f"data-model:{data_model_id}/relationship:{relationship_id}"
                if data_model_id and relationship_id
                else None
            )
        )
        if not (from_view and to_view and key_pairs) or unresolved_keys:
            notes.append(
                UntranslatableNote(
                    object=f"relationship {relationship.get('name') or relationship_id or 'unknown'}",
                    reason="Sigma relationship IDs or join keys did not resolve exactly; the "
                    "relationship was not emitted.",
                    severity="blocker",
                    hint=", ".join(unresolved_keys) or locator,
                )
            )
            continue
        rel_type = relationship.get("type") or relationship.get("relationshipType")
        if rel_type not in {"many-to-one", "many_to_one", "one-to-one", "one_to_one"}:
            if not rel_type and representation == "nested":
                # Sigma's documented code representation omits cardinality. Its directional
                # relationship contract guarantees at most one target row, so many_to_one is the
                # behavior-preserving Omni representation for both supported Sigma variants.
                rel_type = "many-to-one"
                notes.append(
                    UntranslatableNote(
                        object=f"relationship {relationship.get('name') or relationship_id or 'unknown'}",
                        reason="Sigma's documented relationship representation omits whether the "
                        "at-most-one target is one-to-one or many-to-one; OmniKit preserved the "
                        "directional behavior as many-to-one.",
                        severity="info",
                        hint=locator,
                    )
                )
            else:
                notes.append(
                    UntranslatableNote(
                        object=f"relationship {relationship.get('name') or relationship_id or 'unknown'}",
                        reason=f"Unsupported Sigma relationship cardinality {rel_type!r}; relationship "
                        "was not emitted.",
                        severity="blocker",
                        hint=locator,
                    )
                )
                continue
        relationship_type = (
            "one_to_one" if rel_type in ("one-to-one", "one_to_one") else "many_to_one"
        )
        topic = topics.setdefault(from_view, TopicIR(name=from_view, base_view=from_view))
        on_sql = " AND ".join(
            f"${{{from_view}.{source_column[1]}}} = ${{{to_view}.{target_column[1]}}}"
            for source_column, target_column in key_pairs
        )
        topic.joins.append(
            JoinIR(
                source_id=relationship_id,
                source_locator=locator,
                join_from_view=from_view,
                join_to_view=to_view,
                relationship_type=relationship_type,
                on_sql=on_sql,
            )
        )
        if representation == "legacy":
            source_field = key_pairs[0][0][1]
            target_field = key_pairs[0][1][1]
            views[from_view].untranslatable.append(
                UntranslatableNote(
                    object=f"join {from_view}.{source_field} -> {to_view}.{target_field}",
                    reason="Legacy top-level Sigma relationship compatibility shape is not the "
                    "current documented representation; confirm direction and cardinality.",
                    severity="info",
                )
            )
    return topics, notes


def _capture_metrics(
    data_model: dict,
    views: dict[str, ViewIR],
    element_view: dict[str, str],
    captured_fields: list[CapturedField],
    requirements: list[SemanticRequirementIR],
) -> None:
    """Register metrics before compilation so dependency checks cover the entire model."""
    metrics_by_view: dict[str, list[tuple[str | None, dict, str]]] = {}
    for element_id, metric, representation in _metric_records(data_model):
        view_name = element_view.get(element_id or "")
        if view_name is None:
            requirements.append(_formula_requirement(
                data_model_id=_row_id(data_model, "dataModelId", "id"), element_id=element_id,
                column=metric, field_kind="metric",
                reason="Metric source element is absent or unsupported; metric was not emitted.",
            ))
            continue
        metrics_by_view.setdefault(view_name, []).append((element_id, metric, representation))

    elements = {
        _row_id(element, "elementId", "id"): element
        for element in _data_model_elements(data_model)
    }
    for view_name, metric_records in metrics_by_view.items():
        view = views[view_name]
        columns = [item for item in captured_fields if item.view_name == view_name]
        occupied_bases = {item.sql_name for item in columns}
        metric_bases = [
            _snake(str(metric.get("name") or f"metric_{_row_id(metric, 'metricId', 'id')}"))
            for _, metric, _ in metric_records
        ]
        counts: dict[str, int] = {}
        for base in metric_bases:
            counts[base] = counts.get(base, 0) + 1
        used_names = {item.field_name for item in columns}
        for index, ((element_id, metric, representation), base) in enumerate(
            zip(metric_records, metric_bases, strict=True)
        ):
            metric_id = _row_id(metric, "metricId", "id")
            field_name = _stable_field_name(
                base=base,
                source_id=metric_id,
                fallback={"metric": metric, "ordinal": index},
                used=used_names,
                force_suffix=base in occupied_bases or counts[base] > 1,
            )
            if field_name != base:
                view.untranslatable.append(
                    UntranslatableNote(
                        object=f"metric {metric.get('name') or metric_id}",
                        severity="warning",
                        reason="Metric name collided with another normalized field name. OmniKit "
                        "retained the source ID and applied a deterministic identity suffix.",
                        hint=field_name,
                    )
                )
            captured_fields.append(CapturedField(
                key=f"{view_name}/metric/{index}", element_id=element_id, view_name=view_name,
                source_id=metric_id, field_name=field_name, sql_name=base, row=metric,
                element=elements[element_id], is_metric=True, representation=representation,
            ))


def _requested_ids(ctx: ExtractCtx) -> set[str]:
    requested = (
        ctx.scope.get("workbook_ids")
        or ctx.scope.get("dashboard_ids")
        or ctx.scope.get("selected_dashboard_ids")
        or []
    )
    if isinstance(requested, str):
        return {requested}
    if isinstance(requested, list):
        return {str(item) for item in requested if str(item).strip()}
    return set()


def _scoped_workbooks(snapshot: dict, selected_ids: set[str]) -> list[dict]:
    scoped: list[dict] = []
    for raw in snapshot.get("workbooks", []) or []:
        workbook = dict(raw)
        workbook_id = _row_id(workbook, "workbookId", "id")
        workbook_selected = not selected_ids or workbook_id in selected_ids
        pages = []
        for raw_page in workbook.get("pages", []) or []:
            page = dict(raw_page)
            page_id = _row_id(page, "pageId", "id")
            if workbook_selected or (page_id is not None and page_id in selected_ids):
                pages.append(page)
        if pages:
            workbook["pages"] = pages
            scoped.append(workbook)
    return scoped


def _dependency(
    *,
    kind: str,
    reference: str | None,
    locator: str,
    message: str,
    status: str = "resolved",
    required: bool = True,
    dashboard_ids: list[str] | None = None,
) -> AcquisitionDependencyIR:
    return AcquisitionDependencyIR(
        kind=kind,
        reference=reference or locator,
        source_file=locator,
        status=status,
        required=required,
        affected_dashboard_ids=dashboard_ids or [],
        message=message,
    )


def _feature_kind(element: dict) -> str | None:
    raw = str(element.get("type") or element.get("kind") or "").casefold().replace("_", " ")
    compact = raw.replace("-", " ").strip()
    if compact == "control":
        return "control"
    if compact in {"input table", "inputtable"} or element.get("inputTable") is not None:
        return "input_table"
    if compact in {"action", "button", "action button"} or any(
        key in element for key in ("action", "actions", "actionType")
    ):
        return "action"
    if element.get("writeback") is not None or element.get("writeBack") is not None:
        return "input_table"
    return None


def _requirement(
    *,
    object_type: str,
    source_id: str | None,
    locator: str,
    name: str,
    outcome: str,
    reason: str,
    config: dict | None = None,
) -> SemanticRequirementIR:
    return SemanticRequirementIR(
        source_id=source_id,
        source_locator=locator,
        object_type=object_type,
        name=name,
        support_outcome=outcome,
        reason=reason,
        config=config or {},
    )


def _scope_dependencies_and_requirements(
    snapshot: dict,
    scoped_workbooks: list[dict],
    column_ref: dict[str, tuple[str, str]],
) -> tuple[list[AcquisitionDependencyIR], list[SemanticRequirementIR], list[UntranslatableNote]]:
    """Create an explicit extraction manifest; acquired evidence must never disappear silently."""
    from omni_migrator.extractors.sigma.dashboard import (
        sigma_element_blocker_reason,
        sigma_element_can_emit_tile,
        sigma_generated_sql_evidence,
    )

    dependencies: list[AcquisitionDependencyIR] = []
    requirements: list[SemanticRequirementIR] = []
    notes: list[UntranslatableNote] = []

    for connection in snapshot.get("connections", []) or []:
        connection_id = _row_id(connection, "connectionId", "id")
        dependencies.append(
            _dependency(
                kind="connection",
                reference=connection_id,
                locator=f"connection:{connection_id or connection.get('name') or 'unknown'}",
                message="Sigma connection metadata was acquired for source-to-target mapping.",
            )
        )

    for data_model in snapshot.get("dataModels", []) or []:
        data_model_id = _row_id(data_model, "dataModelId", "id")
        model_locator = f"data-model:{data_model_id or data_model.get('name') or 'unknown'}"
        dependencies.append(
            _dependency(
                kind="semantic_model",
                reference=data_model_id,
                locator=model_locator,
                message="Sigma data model metadata and specification were acquired.",
            )
        )
        source_rows = list(data_model.get("sources", []) or [])
        source_ids: set[str] = set()
        for source in source_rows:
            source_id = _row_id(source, "sourceId", "elementId", "id", "inodeId")
            if source_id:
                source_ids.add(source_id)
            dependencies.append(
                _dependency(
                    kind="source",
                    reference=source_id,
                    locator=f"{model_locator}/source:{source_id or 'unknown'}",
                    message="Sigma data-model source was acquired for view mapping.",
                )
            )
        column_rows = list(data_model.get("columns", []) or [])
        column_ids: set[str] = set()
        for column in column_rows:
            column_id = _row_id(column, "columnId", "id")
            if column_id:
                column_ids.add(column_id)
            formula = column.get("formula")
            dependencies.append(
                _dependency(
                    kind="calculation" if formula else "field",
                    reference=column_id,
                    locator=f"{model_locator}/column:{column_id or 'unknown'}",
                    message=(
                        "Sigma formula-bearing column was acquired for deterministic translation "
                        "or explicit review."
                        if formula
                        else "Sigma data-model column was acquired for field mapping."
                    ),
                )
            )
        for element in _data_model_elements(data_model):
            element_id = _row_id(element, "elementId", "id")
            if element_id not in source_ids:
                dependencies.append(
                    _dependency(
                        kind="source",
                        reference=element_id,
                        locator=f"{model_locator}/source:{element_id or 'unknown'}",
                        message="Sigma spec source element was acquired for view mapping.",
                    )
                )
                if element_id:
                    source_ids.add(element_id)
            for column in element.get("columns", []) or []:
                if not isinstance(column, dict):
                    continue
                column_id = _row_id(column, "columnId", "id")
                if column_id in column_ids:
                    continue
                formula = column.get("formula")
                dependencies.append(
                    _dependency(
                        kind="calculation" if formula else "field",
                        reference=column_id,
                        locator=f"{model_locator}/column:{column_id or 'unknown'}",
                        message=(
                            "Sigma spec formula was acquired for translation or explicit review."
                            if formula
                            else "Sigma spec column was acquired for field mapping."
                        ),
                    )
                )
                if column_id:
                    column_ids.add(column_id)
        for index, lineage in enumerate(data_model.get("lineage", []) or []):
            lineage_id = _row_id(lineage, "lineageId", "elementId", "nodeId")
            locator = f"{model_locator}/lineage:{lineage_id or index}"
            dependencies.append(
                _dependency(
                    kind="lineage",
                    reference=lineage_id,
                    locator=locator,
                    message="Sigma lineage is retained as validation evidence, not executable SQL.",
                    status="review",
                )
            )
            requirements.append(
                _requirement(
                    object_type="lineage",
                    source_id=lineage_id,
                    locator=locator,
                    name=f"sigma_lineage_{_snake(lineage_id or str(index))}",
                    outcome="manual",
                    reason="Confirm the translated Omni lineage against this source evidence.",
                    config={"evidence_only": True},
                )
            )
        for index, grant in enumerate(data_model.get("grants", []) or []):
            grant_id = _row_id(grant, "grantId", "id")
            locator = f"{model_locator}/grant:{grant_id or index}"
            dependencies.append(
                _dependency(
                    kind="permission",
                    reference=grant_id,
                    locator=locator,
                    message="Sigma model grant requires governed target permission mapping.",
                    status="review",
                )
            )
            requirements.append(
                _requirement(
                    object_type="permission",
                    source_id=grant_id,
                    locator=locator,
                    name=f"sigma_permission_{_snake(grant_id or str(index))}",
                    outcome="decision_required",
                    reason="Map this Sigma model grant to an approved Omni access policy.",
                    config={
                        **_operational_config(grant, blocking=True),
                        "permission": grant.get("permission"),
                        "principal_type": grant.get("principalType"),
                    },
                )
            )
        for index, schedule in enumerate(data_model.get("materializationSchedules", []) or []):
            schedule_id = _row_id(schedule, "scheduleId", "id", "sheetId")
            locator = f"{model_locator}/materialization-schedule:{schedule_id or index}"
            dependencies.append(
                _dependency(
                    kind="schedule",
                    reference=schedule_id,
                    locator=locator,
                    message="Sigma materialization schedule requires an explicit upstream plan.",
                    status="review",
                )
            )
            requirements.append(
                _requirement(
                    object_type="schedule",
                    source_id=schedule_id,
                    locator=locator,
                    name=f"sigma_materialization_schedule_{_snake(schedule_id or str(index))}",
                    outcome="unsupported",
                    reason="OmniKit does not deploy Sigma materialization schedules.",
                    config=_operational_config(schedule, blocking=True),
                )
            )
            notes.append(
                UntranslatableNote(
                    object=f"Sigma materialization schedule {schedule_id or index}",
                    reason="Schedule migration requires an upstream orchestration decision.",
                    severity="blocker",
                )
            )

    for workbook in scoped_workbooks:
        workbook_id = _row_id(workbook, "workbookId", "id")
        workbook_locator = f"workbook:{workbook_id or workbook.get('name') or 'unknown'}"
        page_ids = [
            page_id
            for page in workbook.get("pages", []) or []
            if (page_id := _row_id(page, "pageId", "id")) is not None
        ]
        controls_by_key: dict[str, dict] = {}
        for index, raw_control in enumerate(workbook.get("controls", []) or []):
            control = dict(raw_control)
            key = _row_id(control, "controlId", "elementId", "id") or f"control-{index}"
            controls_by_key[key] = control
        query_evidence = _workbook_query_evidence(workbook)
        dependencies.append(
            _dependency(
                kind="dashboard",
                reference=workbook_id,
                locator=workbook_locator,
                message="Selected Sigma workbook was acquired for dashboard migration.",
                dashboard_ids=page_ids,
            )
        )
        version_evidence = _workbook_version_evidence(workbook)
        if version_evidence is None:
            dependencies.append(
                _dependency(
                    kind="operation",
                    reference=f"{workbook_id or 'unknown'}:source-version",
                    locator=f"{workbook_locator}/version",
                    message="Sigma workbook evidence was acquired without an explicit tagName or "
                    "bookmarkId pin; dependency closure cannot be called complete.",
                    status="review",
                    dashboard_ids=page_ids,
                )
            )
            notes.append(
                UntranslatableNote(
                    object=f"Sigma workbook version {workbook_id or workbook.get('name') or 'unknown'}",
                    reason="Workbook evidence is not pinned to a version tag or bookmark. Reacquire "
                    "with explicit pin evidence before claiming complete source coverage.",
                    severity="blocker",
                )
            )
        else:
            pin_kind, pin_value = version_evidence
            dependencies.append(
                _dependency(
                    kind="operation",
                    reference=f"{workbook_id or 'unknown'}:source-version",
                    locator=f"{workbook_locator}/version:{pin_kind}:{pin_value}",
                    message=f"Sigma workbook evidence is pinned by {pin_kind} {pin_value}.",
                    dashboard_ids=page_ids,
                )
            )
        for index, source in enumerate(workbook.get("sources", []) or []):
            source_id = _row_id(source, "sourceId", "elementId", "id", "inodeId")
            dependencies.append(
                _dependency(
                    kind="source",
                    reference=source_id,
                    locator=f"{workbook_locator}/source:{source_id or index}",
                    message="Selected Sigma workbook source was acquired for dependency mapping.",
                    dashboard_ids=page_ids,
                )
            )
        scoped_element_ids: set[str] = set()
        for page in workbook.get("pages", []) or []:
            page_id = _row_id(page, "pageId", "id")
            page_locator = f"{workbook_locator}/page:{page_id or page.get('name') or 'unknown'}"
            affected = [page_id] if page_id else []
            dependencies.append(
                _dependency(
                    kind="page",
                    reference=page_id,
                    locator=page_locator,
                    message="Selected Sigma workbook page was acquired.",
                    dashboard_ids=affected,
                )
            )
            requirements.append(
                _requirement(
                    object_type="layout",
                    source_id=page_id,
                    locator=f"{page_locator}/layout",
                    name=f"sigma_layout_{_snake(page_id or str(page.get('name') or 'page'))}",
                    outcome="manual",
                    reason="Sigma does not expose authoritative workbook layout through this API; "
                    "OmniKit uses an explicit naive stack pending human layout review.",
                    config={"fallback": "naive_stack", "blocking": True},
                )
            )
            for index, element in enumerate(page.get("elements", []) or []):
                element_id = _row_id(element, "elementId", "id")
                if element_id:
                    scoped_element_ids.add(element_id)
                feature = _feature_kind(element)
                if feature == "control":
                    key = element_id or f"page-control-{page_id or 'page'}-{index}"
                    controls_by_key[key] = {**dict(element), **controls_by_key.get(key, {})}
                dep_kind = "filter" if feature == "control" else "visual"
                locator = f"{page_locator}/element:{element_id or index}"
                can_emit = feature is None and sigma_element_can_emit_tile(element, column_ref)
                blocker_reason = (
                    sigma_element_blocker_reason(element, column_ref)
                    if feature is None
                    else None
                )
                dependencies.append(
                    _dependency(
                        kind=dep_kind,
                        reference=element_id,
                        locator=locator,
                        message=(
                            f"Sigma {feature} element was acquired for explicit human review."
                            if feature
                            else (
                                "Sigma visual element was acquired and can emit a provisional tile."
                                if can_emit
                                else "Sigma visual element requires review because "
                                f"{blocker_reason or 'its source behavior is unsupported'}; source "
                                "evidence remains available for review."
                            )
                        ),
                        status="resolved" if can_emit else "review",
                        dashboard_ids=affected,
                    )
                )
                for column_index, column in enumerate(element.get("columns", []) or []):
                    if not isinstance(column, dict):
                        column = {"columnId": str(column)}
                    column_id = _row_id(column, "columnId", "id")
                    formula = column.get("formula")
                    field_resolved = column_id is not None and column_id in column_ref
                    dependencies.append(
                        _dependency(
                            kind="calculation" if formula else "field",
                            reference=column_id,
                            locator=f"{locator}/column:{column_id or column_index}",
                            message=(
                                "Sigma visual formula was acquired for translation or review."
                                if formula
                                else (
                                    "Sigma visual field reference resolved to the extracted model."
                                    if field_resolved
                                    else "Sigma visual field reference was acquired but did not resolve "
                                    "to an extracted model field."
                                )
                            ),
                            status="review" if formula or not field_resolved else "resolved",
                            dashboard_ids=affected,
                        )
                    )
                if feature in {"input_table", "action"}:
                    requirements.append(
                        _requirement(
                            object_type=feature,
                            source_id=element_id,
                            locator=locator,
                            name=f"sigma_{feature}_{_snake(element_id or str(index))}",
                            outcome="unsupported",
                            reason=f"Sigma {feature.replace('_', ' ')} behavior cannot be inferred "
                            "or deployed safely by OmniKit.",
                            config=_operational_config(element, blocking=True),
                        )
                    )
                    notes.append(
                        UntranslatableNote(
                            object=f"Sigma {feature.replace('_', ' ')} {element_id or index}",
                            reason="Provide a reviewed target behavior or explicitly waive this object.",
                            severity="blocker",
                        )
                    )

        for index, control in enumerate(controls_by_key.values()):
            control_id = _row_id(control, "controlId", "elementId", "id")
            locator = f"{workbook_locator}/control:{control_id or index}"
            dependencies.append(
                _dependency(
                    kind="filter",
                    reference=control_id,
                    locator=locator,
                    message="Sigma control was acquired for filter binding review.",
                    status="review",
                    dashboard_ids=page_ids,
                )
            )
            candidate_ids = {
                str(value)
                for value in (
                    control.get("columnId"),
                    control.get("targetColumnId"),
                )
                if value not in (None, "")
            }
            for raw in control.get("columns", []) or []:
                value = _row_id(raw, "columnId", "id") if isinstance(raw, dict) else str(raw)
                if value:
                    candidate_ids.add(value)
            requirements.append(
                _requirement(
                    object_type="control",
                    source_id=control_id,
                    locator=locator,
                    name=f"sigma_control_{_snake(control_id or str(control.get('name') or index))}",
                    outcome="unsupported",
                    reason="Sigma's documented workbook-controls response does not expose an "
                    "authoritative field binding. Configure the Omni filter explicitly or waive it.",
                    config={
                        **_operational_config(control, blocking=True),
                        "unverified_candidate_column_ids": sorted(candidate_ids),
                        "proposed_target_fields": [],
                    },
                )
            )

        for index, query in enumerate(query_evidence):
            element_id = _row_id(query, "elementId", "id")
            if scoped_element_ids and element_id and element_id not in scoped_element_ids:
                continue
            query_id = _row_id(query, "queryId", "id", "elementId")
            locator = f"{workbook_locator}/query:{query_id or index}"
            generated_sql = sigma_generated_sql_evidence(query)
            dependencies.append(
                _dependency(
                    kind="query",
                    reference=query_id,
                    locator=locator,
                    message="Generated SQL was acquired only as reconciliation evidence.",
                    status="review",
                    dashboard_ids=page_ids,
                )
            )
            requirements.append(
                _requirement(
                    object_type="query_validation",
                    source_id=query_id,
                    locator=locator,
                    name=f"sigma_query_validation_{_snake(query_id or str(index))}",
                    outcome="manual",
                    reason=(
                        "Compare target behavior to this generated-SQL fingerprint; do not compile "
                        "generated SQL as semantic truth."
                        if generated_sql
                        else "The query was identified without a generated-SQL payload; obtain live "
                        "validation evidence before approval."
                    ),
                    config={
                        "evidence_only": True,
                        "related_element_id": element_id,
                        "generated_sql": generated_sql or {"available": False},
                    },
                )
            )

        for index, lineage in enumerate(workbook.get("lineage", []) or []):
            element_id = _row_id(lineage, "elementId", "nodeId")
            if scoped_element_ids and element_id and element_id not in scoped_element_ids:
                continue
            lineage_id = _row_id(lineage, "lineageId", "elementId", "nodeId")
            locator = f"{workbook_locator}/lineage:{lineage_id or index}"
            dependencies.append(
                _dependency(
                    kind="lineage",
                    reference=lineage_id,
                    locator=locator,
                    message="Workbook lineage was acquired as reconciliation evidence.",
                    status="review",
                    dashboard_ids=page_ids,
                )
            )
            requirements.append(
                _requirement(
                    object_type="lineage",
                    source_id=lineage_id,
                    locator=locator,
                    name=f"sigma_workbook_lineage_{_snake(lineage_id or str(index))}",
                    outcome="manual",
                    reason="Validate translated workbook dependencies against source lineage.",
                    config={"evidence_only": True},
                )
            )

        for index, grant in enumerate(workbook.get("grants", []) or []):
            grant_id = _row_id(grant, "grantId", "id")
            locator = f"{workbook_locator}/grant:{grant_id or index}"
            dependencies.append(
                _dependency(
                    kind="permission",
                    reference=grant_id,
                    locator=locator,
                    message="Workbook grant requires governed target permission mapping.",
                    status="review",
                    dashboard_ids=page_ids,
                )
            )
            requirements.append(
                _requirement(
                    object_type="permission",
                    source_id=grant_id,
                    locator=locator,
                    name=f"sigma_workbook_permission_{_snake(grant_id or str(index))}",
                    outcome="decision_required",
                    reason="Map this Sigma workbook grant to an approved Omni permission policy.",
                    config={
                        **_operational_config(grant, blocking=True),
                        "permission": grant.get("permission"),
                        "principal_type": grant.get("principalType"),
                    },
                )
            )

        schedules = [
            *(workbook.get("schedules", []) or []),
            *(workbook.get("materializationSchedules", []) or []),
        ]
        for index, schedule in enumerate(schedules):
            schedule_id = _row_id(
                schedule, "scheduledNotificationId", "scheduleId", "id", "sheetId"
            )
            locator = f"{workbook_locator}/schedule:{schedule_id or index}"
            dependencies.append(
                _dependency(
                    kind="schedule",
                    reference=schedule_id,
                    locator=locator,
                    message="Sigma schedule was acquired but requires a target operating decision.",
                    status="review",
                    dashboard_ids=page_ids,
                )
            )
            requirements.append(
                _requirement(
                    object_type="schedule",
                    source_id=schedule_id,
                    locator=locator,
                    name=f"sigma_schedule_{_snake(schedule_id or str(index))}",
                    outcome="unsupported",
                    reason="OmniKit does not deploy Sigma workbook or materialization schedules.",
                    config=_operational_config(schedule, blocking=True),
                )
            )
            notes.append(
                UntranslatableNote(
                    object=f"Sigma workbook schedule {schedule_id or index}",
                    reason="Choose an Omni delivery or upstream orchestration replacement.",
                    severity="blocker",
                )
            )

    for index, diagnostic in enumerate(snapshot.get("diagnostics", []) or []):
        operation = str(diagnostic.get("operation") or f"operation-{index}")
        dependencies.append(
            _dependency(
                kind="operation",
                reference=operation,
                locator=f"acquisition:{operation}",
                message="Optional Sigma evidence endpoint was unavailable; coverage is partial.",
                status="review",
            )
        )
        notes.append(
            UntranslatableNote(
                object=f"Sigma acquisition {operation}",
                reason="Optional source evidence was unavailable; review coverage before approval.",
                severity="warning",
                hint=f"status {diagnostic.get('status_code', 'unknown')}",
            )
        )
    return dependencies, requirements, notes


def _build_bundle(
    snapshot: dict,
    ctx: ExtractCtx | None = None,
    *,
    acquisition_mode: str = "unknown",
    source_artifact: str | None = None,
) -> MigrationBundle:
    """Pure transform: a plain-dict Sigma `snapshot` (see `SigmaApi.snapshot()`) -> `MigrationBundle`."""
    ctx = ctx or ExtractCtx()
    selected_ids = _requested_ids(ctx)
    scoped_workbooks = _scoped_workbooks(snapshot, selected_ids)
    dialects = {
        str(c["connectionId"]): normalize_sigma_connection_type(c.get("type"))
        for c in snapshot.get("connections", [])
        if c.get("connectionId") not in (None, "")
    }
    all_views: dict[str, ViewIR] = {}
    all_topics: dict[str, TopicIR] = {}
    all_column_refs: dict[str, tuple[str, str]] = {}
    ambiguous_column_ids: set[str] = set()
    model_requirements: list[SemanticRequirementIR] = []
    model_notes: list[UntranslatableNote] = []
    used_view_names: set[str] = set()
    for dm in snapshot.get("dataModels", []):
        views, element_view, column_ref, formula_requirements = _build_views(
            dm, dialects, used_view_names
        )
        topics, relationship_notes = _build_relationships(dm, views, element_view, column_ref)
        all_views.update(views)
        all_topics.update(topics)
        model_requirements.extend(formula_requirements)
        model_notes.extend(relationship_notes)
        for column_id, reference in column_ref.items():
            if column_id in ambiguous_column_ids:
                continue
            existing = all_column_refs.get(column_id)
            if existing is not None and existing != reference:
                all_column_refs.pop(column_id, None)
                ambiguous_column_ids.add(column_id)
                model_notes.append(
                    UntranslatableNote(
                        object=f"Sigma column ID {column_id}",
                        reason="The same source column ID resolved to multiple scoped views; "
                        "dashboard field binding is blocked instead of being overwritten.",
                        severity="blocker",
                    )
                )
            else:
                all_column_refs[column_id] = reference

    dependencies, coverage_requirements, coverage_notes = _scope_dependencies_and_requirements(
        snapshot, scoped_workbooks, all_column_refs
    )
    model_requirements.extend(coverage_requirements)
    model_notes.extend(coverage_notes)
    model = ModelIR(
        views=list(all_views.values()),
        topics=list(all_topics.values()),
        requirements=model_requirements,
        untranslatable=model_notes,
    )
    from omni_migrator.extractors.sigma.dashboard import translate_sigma_page

    dashboards = []
    for workbook in scoped_workbooks:
        workbook_id = _row_id(workbook, "workbookId", "id")
        for page in workbook.get("pages", []):
            dashboards.append(
                translate_sigma_page(
                    page,
                    column_ref=all_column_refs,
                    source_url=workbook.get("url") or workbook.get("name"),
                    workbook_id=workbook_id,
                    controls=list(workbook.get("controls", []) or []),
                    workbook_grants=list(workbook.get("grants", []) or []),
                    workbook_schedules=[
                        *(workbook.get("schedules", []) or []),
                        *(workbook.get("materializationSchedules", []) or []),
                    ],
                )
            )

    dashboard_ids = [
        dashboard.native_source_id
        for dashboard in dashboards
        if dashboard.native_source_id is not None
    ]
    query_ids = [dependency.reference for dependency in dependencies if dependency.kind == "query"]
    has_review = any(dependency.status != "resolved" for dependency in dependencies)
    acquisition = AcquisitionEvidenceIR(
        contract_version=SIGMA_SNAPSHOT_CONTRACT,
        mode=acquisition_mode,
        project_ids=[
            data_model_id
            for data_model in snapshot.get("dataModels", []) or []
            if (data_model_id := _row_id(data_model, "dataModelId", "id")) is not None
        ],
        dashboard_ids=dashboard_ids,
        query_ids=query_ids,
        source_files=[source_artifact] if source_artifact and acquisition_mode == "manual" else [],
        required_files=[source_artifact]
        if source_artifact and acquisition_mode == "manual"
        else [],
        dependencies=dependencies,
        dependency_closure_status="partial" if has_review else "complete",
        source_query_validation_status="partial" if query_ids else "not_evaluated",
        diagnostics=[
            f"{item.get('operation', 'unknown')}: optional endpoint status "
            f"{item.get('status_code', 'unknown')}"
            for item in snapshot.get("diagnostics", []) or []
        ],
    )
    return MigrationBundle(
        source="sigma",
        provenance=Provenance(source_artifact=source_artifact),
        acquisition=acquisition,
        model=model,
        dashboards=dashboards,
    )


class SigmaExtractor:
    source = "sigma"

    def detect(self, inp: ExtractorInput) -> bool:
        return isinstance(inp, ApiInput) or (
            isinstance(inp, FileInput)
            and len(inp.paths) == 1
            and str(inp.paths[0]).lower().endswith(".json")
        )

    def extract(self, inp: ExtractorInput, ctx: ExtractCtx | None = None) -> MigrationBundle:
        ctx = ctx or ExtractCtx()
        if isinstance(inp, FileInput):
            if len(inp.paths) != 1:
                raise ValueError(
                    "Sigma manual acquisition requires exactly one Sigma API snapshot JSON file."
                )
            path = Path(inp.paths[0])
            if path.suffix.casefold() != ".json":
                raise ValueError("Sigma manual acquisition accepts only a .json API snapshot.")
            if not path.is_file():
                raise ValueError(f"Sigma snapshot file does not exist: {path}")
            size = path.stat().st_size
            if size > MAX_SIGMA_SNAPSHOT_BYTES:
                raise ValueError(
                    f"Sigma API snapshot exceeds the {MAX_SIGMA_SNAPSHOT_BYTES} byte limit."
                )
            try:
                snapshot = json.loads(path.read_text(encoding="utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                raise ValueError("Sigma API snapshot must be valid UTF-8 JSON.") from error
            if not isinstance(snapshot, dict):
                raise ValueError("Sigma API snapshot JSON must contain one object.")
            contract = (snapshot.get("_omnikit_acquisition") or {}).get("contract")
            if contract != SIGMA_SNAPSHOT_CONTRACT:
                raise ValueError(
                    "Sigma manual acquisition requires an OmniKit sigma-api-v2 snapshot, not a "
                    "portable Sigma export."
                )
            return _build_bundle(
                snapshot,
                ctx,
                acquisition_mode="manual",
                source_artifact=str(path),
            )
        if not isinstance(inp, ApiInput):
            raise TypeError("SigmaExtractor supports ApiInput or one Sigma API snapshot FileInput.")
        snapshot = inp.auth.get("snapshot")
        if snapshot is None:
            raw_data_model_ids = (
                ctx.scope.get("data_model_ids")
                or ctx.scope.get("semantic_model_ids")
                or []
            )
            if isinstance(raw_data_model_ids, str):
                data_model_ids = [raw_data_model_ids]
            elif isinstance(raw_data_model_ids, list):
                data_model_ids = [
                    str(item) for item in raw_data_model_ids if str(item).strip()
                ]
            else:
                data_model_ids = []
            raw_workbook_ids = (
                ctx.scope.get("workbook_ids")
                or ctx.scope.get("dashboard_ids")
                or ctx.scope.get("selected_dashboard_ids")
                or []
            )
            if isinstance(raw_workbook_ids, str):
                workbook_ids = [raw_workbook_ids]
            elif isinstance(raw_workbook_ids, list):
                workbook_ids = [
                    str(item) for item in raw_workbook_ids if str(item).strip()
                ]
            else:
                workbook_ids = []
            api = SigmaApi(
                base_url=inp.base_url,
                client_id=inp.auth.get("client_id"),
                client_secret=inp.auth.get("client_secret"),
            )
            try:
                snapshot = api.snapshot(
                    data_model_ids=data_model_ids,
                    workbook_ids=workbook_ids,
                )
            finally:
                api.close()
        if not isinstance(snapshot, dict):
            raise ValueError("Sigma API snapshot must contain one object.")
        acquisition = snapshot.get("_omnikit_acquisition")
        if not isinstance(acquisition, dict) or acquisition.get("contract") != SIGMA_SNAPSHOT_CONTRACT:
            raise ValueError("Sigma API extraction requires an OmniKit sigma-api-v2 snapshot.")
        if acquisition.get("workbookSpecClaimed") is True:
            raise ValueError(
                "Sigma API evidence must identify Data Model /spec as the authoritative model "
                "representation and must not claim workbook /spec."
            )
        return _build_bundle(
            snapshot,
            ctx,
            acquisition_mode="api",
            source_artifact=inp.base_url,
        )

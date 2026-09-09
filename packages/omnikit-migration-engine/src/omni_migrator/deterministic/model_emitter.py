"""Deterministic ModelIR -> Omni model YAML (stage 1 of the translation sandwich).

Produces an *approximate* but well-formed draft per plan Appendix A.1. The output is
either written directly (high-confidence) or handed to the agentic modeling sub-agent
as seed context (plan §7). Pure and offline — exhaustively unit-tested.
"""

from __future__ import annotations

import yaml

from omni_migrator.deterministic.omni_enums import AGGREGATES_DEFAULT_NUMBER_0, OMNI_AGGREGATES
from omni_migrator.deterministic.sql_cleanup import clean_sql
from omni_migrator.ir.schema import FieldIR, ModelIR, TopicIR, ViewIR


def _dump(data: dict) -> str:
    return yaml.dump(data, sort_keys=False, default_flow_style=False, allow_unicode=True)


def _bare_sql(f: FieldIR) -> str | None:
    """`f.sql`, or `None` if it's a bare column ref that already matches the field name.

    Every extractor already runs `clean_sql` at the source; calling it again here is a
    backstop, not the primary mechanism — it guarantees `${TABLE}` references and known
    source-function quirks (`ISNULL`, `DATEPART`, ...) can never reach the agentic API's
    prompt even if a future/third-party extractor forgets to normalize them.

    Omni infers a field's column from its name when they match (verified against real
    Omni YAML, e.g. a `sale_price` dimension over a `sale_price` column has no `sql:` at
    all) — emitting it anyway is just noise the AI (or a human) has to read past.
    """
    sql = clean_sql(f.sql)
    if not sql or "${" in sql:
        return sql
    return None if sql.lower() == f.name.lower() else sql


def _dimension_dict(f: FieldIR) -> dict:
    d: dict = {}
    sql = _bare_sql(f)
    if sql:
        d["sql"] = sql
    if f.primary_key:
        d["primary_key"] = True
    if f.label:
        d["label"] = f.label
    if f.description:
        d["description"] = f.description
    if f.group_label:
        d["group_label"] = f.group_label
    if f.value_format:
        d["format"] = f.value_format
    if f.hidden or "hidden" in f.model_fields_set:
        d["hidden"] = f.hidden
    return d


def _measure_dict(f: FieldIR) -> dict:
    d: dict = {}
    sql = _bare_sql(f)
    if sql:
        d["sql"] = sql
    agg = f.aggregate if f.aggregate in OMNI_AGGREGATES else None
    # Omni supports compound/raw SQL measures without aggregate_type. A missing
    # aggregate is only defaulted to count when there is no SQL expression at all.
    if agg:
        d["aggregate_type"] = agg
    elif not sql:
        agg = "count"
        d["aggregate_type"] = agg
    # count/count_distinct default to NUMBER_0; only emit a format if it differs.
    if f.value_format and not (agg in AGGREGATES_DEFAULT_NUMBER_0 and f.value_format == "NUMBER_0"):
        d["format"] = f.value_format
    if f.filters:
        d["filters"] = f.filters
    if f.label:
        d["label"] = f.label
    if f.description:
        d["description"] = f.description
    if f.hidden or "hidden" in f.model_fields_set:
        d["hidden"] = f.hidden
    return d


def _filter_only_dict(f: FieldIR) -> dict:
    data: dict = {"type": "timestamp" if f.data_type == "date" else f.data_type}
    if f.label:
        data["label"] = f.label
    if f.description:
        data["description"] = f.description
    if f.hidden or "hidden" in f.model_fields_set:
        data["hidden"] = f.hidden
    if f.suggestion_list:
        data["suggestion_list"] = f.suggestion_list
    if f.filter_single_select_only:
        data["filter_single_select_only"] = True
    return data


def emit_view(view: ViewIR, include_review_required: bool = True) -> str:
    """Render one `<view>.view.yaml`."""
    out: dict = {}
    if view.connection.database:
        out["catalog"] = view.connection.database
    if view.schema_name:
        out["schema"] = view.schema_name
    if view.source_table:
        out["table_name"] = view.source_table
    if view.sql:
        out["sql"] = clean_sql(view.sql)
    if view.label:
        out["label"] = view.label
    if view.description:
        out["description"] = view.description

    dims = {f.name: _dimension_dict(f) for f in view.fields if f.kind in ("dimension", "calculation")}
    meas = {f.name: _measure_dict(f) for f in view.fields if f.kind == "measure"}
    filters = {
        f.name: _filter_only_dict(f)
        for f in view.fields
        if include_review_required and f.kind == "parameter"
    }
    if dims:
        out["dimensions"] = dims
    if meas:
        out["measures"] = meas
    if filters:
        out["filters"] = filters
    return _dump(out)


def _view_ref_name(view: ViewIR) -> str:
    """The name used to *reference* this view from relationships/topics/`${view.field}` —
    scoped with catalog+schema when the connection requires it, e.g. `ecomm_public__order_items`
    for a view at `ecomm.public/order_items.view` — NOT the bare IR name (`order_items`).

    Verified live, 2026-07-10: Omni's own `GET .../yaml` response includes a `viewNames` map
    giving this exact `{database}_{schema}__{name}` scoped form for every view on a connection
    with `alwaysScopeViewNames: true` (the same connection property `view_path()` already keys
    off of for the file path prefix). Referencing a view by its bare name in `relationships`/
    `.topic` produces a live validation warning ("No such view 'order_items'. Did you mean
    'ecomm_public__order_items'?") — every AI-refine call that happened to touch a topic or
    relationships file had to correct this by hand; this emits it right the first time instead
    of relying on the AI to notice and fix it."""
    if view.connection.database:
        return f"{view.connection.database}_{view.schema_name}__{view.name}"
    return view.name


def _rewrite_cross_view_refs(sql: str, ref_name: dict[str, str]) -> str:
    """Rewrite `${bare_view.field}` cross-view references to use each view's scoped
    reference name (see `_view_ref_name`) — `${field}` same-view refs are untouched."""
    for bare, scoped in ref_name.items():
        if scoped != bare:
            sql = sql.replace(f"${{{bare}.", f"${{{scoped}.")
    return sql


def emit_topic(
    topic: TopicIR,
    ref_name: dict[str, str] | None = None,
    include_review_required: bool = True,
) -> str:
    """Render one `<topic>.topic.yaml` with a nested join tree (best-effort flat tree).

    No `name:` key — a topic's name comes from its file path (`{name}.topic`), the same
    reference-by-path convention as views. Emitting one anyway used to 400 with a generic
    "Property must be a list" (verified live 2026-07-09 by diffing our output against a topic
    the modeling sub-agent wrote and validated successfully, which omitted it)."""
    ref_name = ref_name or {}
    out: dict = {"base_view": ref_name.get(topic.base_view, topic.base_view)}
    if topic.label:
        out["label"] = topic.label
    if topic.description:
        out["description"] = topic.description
    if include_review_required and topic.always_where_filters:
        out["always_where_filters"] = topic.always_where_filters
    if include_review_required and topic.access_filters:
        out["access_filters"] = topic.access_filters
    if topic.joins:
        # Flat one-level tree from base_view's direct joins; deeper graphs handled in Phase 2.
        joins: dict = {}
        for j in topic.joins:
            joins.setdefault(ref_name.get(j.join_to_view, j.join_to_view), {})
        out["joins"] = joins
    return _dump(out)


def emit_relationships(model: ModelIR) -> str | None:
    """Render the model-level relationships file from all topics' joins."""
    rels = []
    seen = set()
    ref_name = {v.name: _view_ref_name(v) for v in model.views}
    for topic in model.topics:
        for j in topic.joins:
            key = (j.join_from_view, j.join_to_view, j.on_sql)
            if key in seen:
                continue
            seen.add(key)
            rels.append(
                {
                    "join_from_view": ref_name.get(j.join_from_view, j.join_from_view),
                    "join_to_view": ref_name.get(j.join_to_view, j.join_to_view),
                    "join_type": j.join_type,
                    "relationship_type": j.relationship_type,
                    "on_sql": _rewrite_cross_view_refs(clean_sql(j.on_sql), ref_name),
                    **({"reversible": True} if j.reversible else {}),
                }
            )
    if not rels:
        return None
    # The `relationships` file's real Omni shape is a *bare* top-level list, not `{relationships:
    # [...]}` — verified live 2026-07-09: wrapping it produced `"Property  must be a list"` (400),
    # while probing with the modeling sub-agent confirmed the same content unwrapped validates and
    # writes cleanly.
    return _dump(rels)


def view_path(view: ViewIR) -> str:
    """A view's real Omni file path: `{catalog}.{schema}/{name}.view` when the connection's
    catalog/database is known (verified live 2026-07-09 against test.thundersalmon.com: the
    connection has `alwaysScopeViewNames: true` and its schema-synced views live at
    `ecomm.public/<name>.view` with `catalog: ecomm` in the YAML body — a bare `{schema}/{name}.view`
    write, which is what this function produced before, lands as a *second*, wrongly-named
    file rather than updating the real schema-discovered view). Falls back to `{schema}/{name}.view`
    (no `views/` folder, no `.yaml` extension either way) when no catalog is known yet — e.g.
    before the Map stage has resolved a connection."""
    prefix = f"{view.connection.database}.{view.schema_name}" if view.connection.database else view.schema_name
    return f"{prefix}/{view.name}.view" if prefix else f"{view.name}.view"


def topic_path(topic: TopicIR) -> str:
    return f"{topic.name}.topic"


def emit_model(model: ModelIR, include_review_required: bool = True) -> dict[str, str]:
    """ModelIR -> {relative_path: yaml_text} for the whole model.

    Order matters when these are written sequentially (`core/translator.py`'s deterministic
    batch, `OmniApiLoader.write_model_files`): a topic's `joins:` entry validates against the
    `relationships` file, so `relationships` must land *before* any topic that references one of
    its joins — verified live 2026-07-09 (writing a topic ahead of its relationship 400'd with
    the same generic "Property must be a list" error the wrong `relationships` wrapper shape
    produced, which is what made this dependency easy to miss at first)."""
    files: dict[str, str] = {}
    for v in model.views:
        files[view_path(v)] = emit_view(v, include_review_required=include_review_required)
    rels = emit_relationships(model)
    if rels:
        files["relationships"] = rels
    ref_name = {v.name: _view_ref_name(v) for v in model.views}
    for t in model.topics:
        files[topic_path(t)] = emit_topic(
            t,
            ref_name,
            include_review_required=include_review_required,
        )
    return files

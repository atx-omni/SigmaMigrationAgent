"""Deterministic, source-specific bridge conformance contracts.

The fixtures in this module exercise each extractor using representative source-native
shapes. Their normalized output is compared with independently reviewed JSON contracts in
``contracts/conformance``. This is intentionally a read-only self-test: it contacts no source,
uses no credentials, and has no Omni write path.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, Literal

from omni_migrator import __version__
from omni_migrator.bridge import CAPABILITIES, LIMITATIONS
from omni_migrator.core.contracts import ExtractCtx, FileInput
from omni_migrator.ir.schema import MigrationBundle, ModelIR, Provenance, UntranslatableNote

CONFORMANCE_SCHEMA_VERSION = "omnikit.migration.conformance.v1"
CONFORMANCE_RUN_SCHEMA_VERSION = "omnikit.migration.conformance-run.v1"
CONFORMANCE_SOURCES = ("sigma",)
ConformanceSource = Literal["looker", "powerbi", "tableau", "metabase", "sigma"]


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode()).hexdigest()


def _filter_manifest(item) -> dict[str, Any]:
    return {
        "field": item.field,
        "operator": item.operator,
        "values": sorted(item.values),
        "is_negative": item.is_negative,
    }


def _note_entries(bundle: MigrationBundle) -> list[UntranslatableNote]:
    notes = list(bundle.model.untranslatable)
    for view in bundle.model.views:
        notes.extend(view.untranslatable)
        for field in view.fields:
            notes.extend(field.untranslatable)
    for dashboard in bundle.dashboards:
        notes.extend(dashboard.untranslatable)
        for tile in dashboard.tiles:
            notes.extend(tile.untranslatable)
    return notes


def canonical_conformance_manifest(bundle: MigrationBundle) -> dict[str, Any]:
    """Project volatile extractor output into the reviewed cross-source contract."""
    source = "powerbi" if bundle.source == "power_bi" else bundle.source
    if source not in CONFORMANCE_SOURCES:
        raise ValueError(f"Unsupported conformance source: {source}")
    capability = CAPABILITIES[source]
    coverage = dict(sorted(capability["artifact_coverage"].items()))
    fidelity = {
        level: sorted(name for name, value in coverage.items() if value == level)
        for level in ("full", "partial", "unsupported")
    }
    views = []
    for view in sorted(bundle.model.views, key=lambda item: item.name):
        fields = [
            {
                "name": field.name,
                "kind": field.kind,
                "data_type": field.data_type,
                "sql": field.sql,
                "aggregate": field.aggregate,
                "filters": field.filters or {},
                "primary_key": field.primary_key,
            }
            for field in sorted(view.fields, key=lambda item: (item.kind, item.name))
        ]
        views.append({
            "name": view.name,
            "schema": view.schema_name,
            "source_table": view.source_table,
            "derived_sql": view.sql,
            "connection": {
                "source_name": view.connection.source_connection_name,
                "dialect": view.connection.dialect,
            },
            "fields": fields,
        })
    topics = []
    for topic in sorted(bundle.model.topics, key=lambda item: item.name):
        topics.append({
            "name": topic.name,
            "base_view": topic.base_view,
            "joins": [
                {
                    "from": join.join_from_view,
                    "to": join.join_to_view,
                    "join_type": join.join_type,
                    "relationship_type": join.relationship_type,
                    "on_sql": join.on_sql,
                }
                for join in sorted(
                    topic.joins,
                    key=lambda item: (item.join_from_view, item.join_to_view, item.on_sql),
                )
            ],
        })
    dashboards = []
    for dashboard in sorted(bundle.dashboards, key=lambda item: item.name):
        tiles = []
        for tile in sorted(
            dashboard.tiles,
            key=lambda item: (item.layout.y, item.layout.x, item.title or "", item.kind),
        ):
            query = None
            if tile.query:
                query = {
                    "topic": tile.query.topic,
                    "fields": sorted(tile.query.fields),
                    "filters": sorted(
                        (_filter_manifest(item) for item in tile.query.filters),
                        key=lambda item: (item["field"], item["operator"], item["values"]),
                    ),
                    "limit": tile.query.limit,
                    "pivots": sorted(tile.query.pivots or []),
                }
            tiles.append({
                "title": tile.title,
                "kind": tile.kind,
                "chart_type": tile.chart_type,
                "query": query,
                "layout": {
                    "x": tile.layout.x,
                    "y": tile.layout.y,
                    "w": tile.layout.w,
                    "h": tile.layout.h,
                },
            })
        dashboards.append({
            "name": dashboard.name,
            "filters": sorted(
                (_filter_manifest(item) for item in dashboard.filters),
                key=lambda item: (item["field"], item["operator"], item["values"]),
            ),
            "tiles": tiles,
        })
    notes = _note_entries(bundle)
    severity_counts = Counter(item.severity for item in notes)
    return {
        "schema_version": CONFORMANCE_SCHEMA_VERSION,
        "source": source,
        "objects": {"views": views, "topics": topics, "dashboards": dashboards},
        "review": {
            "counts": {level: severity_counts.get(level, 0) for level in ("info", "warning", "blocker")},
            "objects": sorted(f"{item.severity}:{item.object}" for item in notes),
            "limitations": list(LIMITATIONS[source]),
        },
        "coverage": {"artifacts": coverage, "fidelity_classes": fidelity},
    }


def _looker_bundle() -> MigrationBundle:
    from omni_migrator.extractors.looker.extractor import LookerExtractor, resolve_dialects

    model = """connection: \"ecommerce\"

view: orders {
  sql_table_name: analytics.orders ;;
  dimension: id { primary_key: yes type: number sql: ${TABLE}.id ;; }
  dimension: customer_id { type: number sql: ${TABLE}.customer_id ;; }
  dimension_group: created { type: time timeframes: [date, month] sql: ${TABLE}.created_at ;; }
  measure: total_revenue { type: sum sql: ${TABLE}.amount ;; }
  measure: gross_margin { type: sum sql: ${TABLE}.gross_margin ;; }
  measure: margin_pct { type: number sql: ${gross_margin} / NULLIF(${total_revenue}, 0) ;; }
  measure: running_revenue { type: running_total sql: ${total_revenue} ;; }
}

view: customers {
  sql_table_name: analytics.customers ;;
  dimension: id { primary_key: yes type: number sql: ${TABLE}.id ;; }
  dimension: name { type: string sql: ${TABLE}.name ;; }
}

explore: orders {
  label: \"Orders\"
  join: customers {
    type: left_outer
    relationship: many_to_one
    sql_on: ${orders.customer_id} = ${customers.id} ;;
  }
}
"""
    dashboard = """- dashboard: revenue_overview
  title: Revenue overview
  filters:
  - name: Date
    field: orders.created_date
    default_value: 30 days
  elements:
  - name: revenue
    title: Revenue trend
    explore: orders
    type: looker_line
    fields: [orders.created_date, orders.total_revenue]
    filters:
      orders.created_date: 30 days
    width: 16
    height: 6
  - name: notes
    title: Notes
    type: text
    body_text: Migrated from Looker.
    row: 6
    width: 24
    height: 2
"""
    with TemporaryDirectory(prefix="omni-migrator-conformance-looker-") as root_text:
        root = Path(root_text)
        model_path = root / "commerce.model.lkml"
        dashboard_path = root / "revenue.dashboard.lookml"
        model_path.write_text(model)
        dashboard_path.write_text(dashboard)
        bundle = LookerExtractor().extract(
            FileInput(paths=[model_path, dashboard_path]),
            ExtractCtx(),
        )
    resolve_dialects(bundle.model, {"ecommerce": "snowflake"})
    return bundle


def _powerbi_bundle() -> MigrationBundle:
    import json as json_module

    import pandas as pd

    from omni_migrator.extractors.powerbi.dashboard import (
        attach_visual_aggregate_hints,
        translate_powerbi_layout,
    )
    from omni_migrator.extractors.powerbi.extractor import _build_bundle

    class FixtureModel:
        def __init__(self, **frames):
            self.frames = frames

        def __getattr__(self, name):
            return self.frames.get(name, pd.DataFrame())

    schema = pd.DataFrame([
        {"TableName": "Orders", "ColumnName": "OrderID", "PandasDataType": "Int64"},
        {"TableName": "Orders", "ColumnName": "CustomerID", "PandasDataType": "Int64"},
        {"TableName": "Orders", "ColumnName": "Amount", "PandasDataType": "Float64"},
        {"TableName": "Orders", "ColumnName": "CreatedAt", "PandasDataType": "datetime64[ns]"},
        {"TableName": "Customers", "ColumnName": "CustomerID", "PandasDataType": "Int64"},
        {"TableName": "Customers", "ColumnName": "Name", "PandasDataType": "string"},
        {"TableName": "Date", "ColumnName": "DateKey", "PandasDataType": "datetime64[ns]"},
    ])
    fixture = FixtureModel(
        schema=schema,
        dax_measures=pd.DataFrame([
            {"TableName": "Orders", "Name": "Total Amount", "Expression": "SUM ( Orders[Amount] )"},
            {"TableName": "Orders", "Name": "Order Count", "Expression": "COUNTROWS ( Orders )"},
            {"TableName": "Orders", "Name": "Margin Pct", "Expression": "DIVIDE ( [Margin], [Total Amount] )"},
        ]),
        dax_columns=pd.DataFrame([
            {"TableName": "Orders", "ColumnName": "Amount Tax", "Expression": "Orders[Amount] * 1.1"},
        ]),
        dax_tables=pd.DataFrame([
            {"TableName": "Date", "Expression": "CALENDAR ( DATE(2020,1,1), DATE(2030,1,1) )"},
        ]),
        relationships=pd.DataFrame([{
            "FromTableName": "Orders",
            "FromColumnName": "CustomerID",
            "ToTableName": "Customers",
            "ToColumnName": "CustomerID",
            "IsActive": 1,
            "Cardinality": "M:1",
        }]),
        power_query=pd.DataFrame([{
            "TableName": "Orders",
            "Expression": 'Snowflake.Databases("acct.snowflakecomputing.com", "WH")',
        }]),
    )
    partial = _build_bundle(fixture)

    def visual(name: str, visual_type: str, selects: list[dict], x: int, y: int) -> dict:
        return {
            "x": x,
            "y": y,
            "width": 600,
            "height": 260,
            "config": json_module.dumps({
                "name": name,
                "singleVisual": {
                    "visualType": visual_type,
                    "prototypeQuery": {
                        "From": [{"Name": "o", "Entity": "Orders"}],
                        "Select": selects,
                    },
                },
            }),
        }

    layout = {
        "sections": [{
            "displayName": "Sales overview",
            "width": 1200,
            "height": 720,
            "visualContainers": [
                visual("revenue", "columnChart", [
                    {"Column": {"Expression": {"SourceRef": {"Source": "o"}}, "Property": "CreatedAt"}, "Name": "Orders.CreatedAt"},
                    {"Measure": {"Expression": {"SourceRef": {"Source": "o"}}, "Property": "Total Amount"}, "Name": "Orders.Total Amount"},
                ], 0, 0),
                visual("implicit-count", "card", [{
                    "Aggregation": {
                        "Expression": {"Column": {"Expression": {"SourceRef": {"Source": "o"}}, "Property": "OrderID"}},
                        "Function": 4,
                    },
                    "Name": "Count(Orders.OrderID)",
                }], 600, 0),
                {
                    "x": 0,
                    "y": 300,
                    "width": 1200,
                    "height": 80,
                    "config": json_module.dumps({
                        "name": "notes",
                        "singleVisual": {
                            "visualType": "textbox",
                            "objects": {"general": [{"properties": {"paragraphs": [{"textRuns": [{"value": "Migrated from Power BI."}]}]}}]},
                        },
                    }),
                },
                visual("status-filter", "slicer", [
                    {"Column": {"Expression": {"SourceRef": {"Source": "o"}}, "Property": "CustomerID"}, "Name": "Orders.CustomerID"},
                ], 0, 400),
            ],
        }],
    }
    attach_visual_aggregate_hints(layout, {item.name: item for item in partial.views})
    return MigrationBundle(
        source="powerbi",
        provenance=Provenance(),
        model=ModelIR(
            views=partial.views,
            topics=partial.topics,
            untranslatable=partial.untranslatable,
        ),
        dashboards=translate_powerbi_layout(layout),
    )


def _tableau_bundle() -> MigrationBundle:
    from omni_migrator.extractors.tableau.extractor import TableauExtractor

    workbook = """<?xml version='1.0' encoding='utf-8' ?>
<workbook>
  <datasources>
    <datasource caption='commerce' name='federated.commerce' version='18.1'>
      <connection class='snowflake' dbname='ANALYTICS'>
        <relation type='join' join='left'>
          <clause type='join'><expression op='='><expression op='[Orders].[Customer_Id]' /><expression op='[Customers].[Id]' /></expression></clause>
          <relation name='Orders' table='[PUBLIC].[ORDERS]' type='table' />
          <relation name='Customers' table='[PUBLIC].[CUSTOMERS]' type='table' />
        </relation>
        <metadata-records>
          <metadata-record class='column'><remote-name>ID</remote-name><local-name>[Order Id]</local-name><parent-name>[Orders]</parent-name></metadata-record>
          <metadata-record class='column'><remote-name>AMOUNT</remote-name><local-name>[Amount]</local-name><parent-name>[Orders]</parent-name></metadata-record>
          <metadata-record class='column'><remote-name>CREATED_AT</remote-name><local-name>[Created At]</local-name><parent-name>[Orders]</parent-name></metadata-record>
          <metadata-record class='column'><remote-name>NAME</remote-name><local-name>[Customer Name]</local-name><parent-name>[Customers]</parent-name></metadata-record>
        </metadata-records>
      </connection>
      <column caption='Order Id' datatype='integer' name='[Order Id]' role='dimension' type='ordinal' />
      <column caption='Amount' datatype='real' name='[Amount]' role='measure' type='quantitative' />
      <column caption='Created At' datatype='datetime' name='[Created At]' role='dimension' type='ordinal' />
      <column caption='Customer Name' datatype='string' name='[Customer Name]' role='dimension' type='nominal' />
      <column caption='Total Amount' datatype='real' name='[Total Amount]' role='measure' type='quantitative'><calculation class='tableau' formula='SUM([Amount])' /></column>
      <column caption='Big Order' datatype='boolean' name='[Big Order]' role='dimension' type='nominal'><calculation class='tableau' formula='[Amount] &gt; 100' /></column>
      <column caption='Region Sales' datatype='real' name='[Region Sales]' role='measure' type='quantitative'><calculation class='tableau' formula='{ FIXED [Customer Name] : SUM([Amount]) }' /></column>
    </datasource>
  </datasources>
  <worksheets>
    <worksheet name='Revenue by customer'><table><view><datasources><datasource caption='commerce' name='federated.commerce' /></datasources><datasource-dependencies datasource='federated.commerce'><column caption='Customer Name' datatype='string' name='[Customer Name]' role='dimension' type='nominal' /><column caption='Amount' datatype='real' name='[Amount]' role='measure' type='quantitative' /></datasource-dependencies></view><rows>[federated.commerce].[none:Customer Name:nk]</rows><cols>[federated.commerce].[sum:Amount:qk]</cols><panes><pane><mark class='Bar' /></pane></panes></table></worksheet>
  </worksheets>
  <dashboards>
    <dashboard name='Commerce overview'><size maxheight='800' maxwidth='1200' minheight='800' minwidth='1200' /><zones><zone h='100000' id='1' type-v2='layout-basic' w='100000' x='0' y='0'><zone h='90000' id='2' name='Revenue by customer' w='100000' x='0' y='0' /><zone h='5000' id='3' type-v2='text' w='100000' x='0' y='90000'><formatted-text><run>Migrated from Tableau.</run></formatted-text></zone><zone h='5000' id='4' type-v2='filter' name='Customer filter' w='100000' x='0' y='95000' /></zone></zones></dashboard>
  </dashboards>
</workbook>
"""
    with TemporaryDirectory(prefix="omni-migrator-conformance-tableau-") as root_text:
        path = Path(root_text) / "commerce.twb"
        path.write_text(workbook)
        return TableauExtractor().extract(FileInput(paths=[path]), ExtractCtx())


def _metabase_bundle() -> MigrationBundle:
    from omni_migrator.extractors.metabase.extractor import _build_bundle

    metric = {
        "id": 5,
        "table_id": 100,
        "name": "Total Revenue",
        "definition": {"aggregation": [["sum", ["field", 11, None]]]},
    }
    question = {
        "id": 1,
        "type": "question",
        "name": "Revenue by status",
        "display": "bar",
        "dataset_query": {
            "type": "query",
            "query": {
                "source-table": 100,
                "aggregation": [["metric", 5]],
                "breakout": [["field", 12, None]],
                "filter": ["=", ["field", 12, None], "completed"],
            },
        },
    }
    snapshot = {
        "databases": [{"id": 1, "name": "Warehouse", "engine": "postgres"}],
        "tables": [
            {
                "id": 100,
                "db_id": 1,
                "name": "orders",
                "schema": "public",
                "fields": [
                    {"id": 10, "name": "id", "base_type": "type/BigInteger", "semantic_type": "type/PK"},
                    {"id": 11, "name": "amount", "base_type": "type/Float"},
                    {"id": 12, "name": "status", "base_type": "type/Text"},
                    {"id": 13, "name": "customer_id", "base_type": "type/Integer", "semantic_type": "type/FK", "fk_target_field_id": 20},
                ],
            },
            {
                "id": 200,
                "db_id": 1,
                "name": "customers",
                "schema": "public",
                "fields": [
                    {"id": 20, "name": "id", "base_type": "type/BigInteger", "semantic_type": "type/PK"},
                    {"id": 21, "name": "name", "base_type": "type/Text"},
                ],
            },
        ],
        "segments": [{
            "id": 1,
            "table_id": 100,
            "name": "Completed orders",
            "definition": {"filter": ["=", ["field", 12, None], "completed"]},
        }],
        "metrics": [metric],
        "cards": [question],
        "dashboards": [{
            "id": 10,
            "name": "Operations overview",
            "parameters": [{"id": "p1", "name": "Status", "slug": "status", "default": "completed"}],
            "dashcards": [{
                "id": 1000,
                "card_id": 1,
                "card": question,
                "row": 0,
                "col": 0,
                "size_x": 9,
                "size_y": 4,
                "parameter_mappings": [{"parameter_id": "p1", "card_id": 1, "target": ["dimension", ["field", 12, None]]}],
            }],
        }],
    }
    return _build_bundle(snapshot)


def _sigma_bundle() -> MigrationBundle:
    from omni_migrator.extractors.sigma.extractor import _build_bundle

    snapshot = {
        "connections": [{"connectionId": "c1", "name": "Warehouse", "type": "bigQuery"}],
        "dataModels": [{
            "dataModelId": "dm1",
            "spec": {
                "pages": [{"elements": [
                    {
                        "id": "e1",
                        "kind": "table",
                        "name": "Order Items",
                        "source": {"connectionId": "c1", "kind": "warehouse-table", "path": ["db", "public", "order_items"]},
                        "columns": [
                            {"id": "col-id", "name": "id"},
                            {"id": "col-price", "name": "Sale Price"},
                            {"id": "col-status", "name": "Status"},
                            {"id": "col-calc", "name": "Full Name", "formula": '[First Name] + " " + [Last Name]'},
                        ],
                    },
                    {
                        "id": "e2",
                        "kind": "table",
                        "name": "Inventory Items",
                        "source": {"connectionId": "c1", "kind": "warehouse-table", "path": ["db", "public", "inventory_items"]},
                        "columns": [{"id": "col-inv-id", "name": "id"}],
                    },
                ]}],
                "relationships": [{
                    "fromElementId": "e1",
                    "fromColumnId": "col-id",
                    "toElementId": "e2",
                    "toColumnId": "col-inv-id",
                    "type": "many-to-one",
                }],
                "metrics": [{
                    "id": "m1",
                    "name": "Completed Revenue",
                    "elementId": "e1",
                    "formula": 'SumIf([Sale Price], [Status] = "Complete")',
                }],
            },
        }],
        "workbooks": [{
            "name": "Commerce workbook",
            "url": "https://example.invalid/workbook",
            "pages": [{
                "name": "Commerce overview",
                "elements": [
                    {"elementId": "chart-1", "name": "Revenue", "vizualizationType": "Bar", "columns": [{"columnId": "col-price"}]},
                    {"elementId": "chart-2", "name": "Status", "vizualizationType": "Pie/Donut", "columns": [{"columnId": "col-status"}]},
                    {"elementId": "chart-3", "name": "Custom", "vizualizationType": "Sunburst", "columns": [{"columnId": "col-id"}]},
                ],
            }],
        }],
    }
    return _build_bundle(snapshot)


_BUNDLE_BUILDERS = {
    "looker": _looker_bundle,
    "powerbi": _powerbi_bundle,
    "tableau": _tableau_bundle,
    "metabase": _metabase_bundle,
    "sigma": _sigma_bundle,
}


def build_conformance_manifest(source: ConformanceSource) -> dict[str, Any]:
    if source not in _BUNDLE_BUILDERS:
        raise ValueError(f"Unsupported conformance source: {source}")
    return canonical_conformance_manifest(_BUNDLE_BUILDERS[source]())


def _default_contract_root() -> Path:
    return Path(__file__).resolve().parents[2] / "contracts" / "conformance"


def _difference_paths(expected: Any, actual: Any, prefix: str = "$") -> list[str]:
    if type(expected) is not type(actual):
        return [f"{prefix}: expected {type(expected).__name__}, received {type(actual).__name__}"]
    if isinstance(expected, dict):
        errors = []
        for key in sorted(set(expected) | set(actual)):
            if key not in expected:
                errors.append(f"{prefix}.{key}: unexpected")
            elif key not in actual:
                errors.append(f"{prefix}.{key}: missing")
            else:
                errors.extend(_difference_paths(expected[key], actual[key], f"{prefix}.{key}"))
            if len(errors) >= 20:
                break
        return errors[:20]
    if isinstance(expected, list):
        if len(expected) != len(actual):
            return [f"{prefix}: expected {len(expected)} items, received {len(actual)}"]
        errors = []
        for index, (left, right) in enumerate(zip(expected, actual, strict=True)):
            errors.extend(_difference_paths(left, right, f"{prefix}[{index}]"))
            if len(errors) >= 20:
                break
        return errors[:20]
    return [] if expected == actual else [f"{prefix}: values differ"]


def run_conformance(
    source: ConformanceSource | None = None,
    *,
    contract_root: Path | None = None,
) -> dict[str, Any]:
    root = contract_root or _default_contract_root()
    selected = (source,) if source else CONFORMANCE_SOURCES
    results: dict[str, Any] = {}
    for item in selected:
        try:
            actual = build_conformance_manifest(item)
            expected_path = root / f"{item}.json"
            expected = json.loads(expected_path.read_text())
            errors = _difference_paths(expected, actual)
            results[item] = {
                "passed": not errors,
                "manifest_sha256": _sha256(actual),
                "expected_sha256": _sha256(expected),
                "errors": errors,
                "coverage": actual["coverage"],
            }
        except Exception as error:  # noqa: BLE001 - self-test reports a per-source failure
            results[item] = {
                "passed": False,
                "manifest_sha256": None,
                "expected_sha256": None,
                "errors": [f"{type(error).__name__}: {error}"],
            }
    return {
        "schema_version": CONFORMANCE_RUN_SCHEMA_VERSION,
        "engine": {"name": "omni-migrator", "version": __version__},
        "passed": all(item["passed"] for item in results.values()),
        "sources": results,
    }

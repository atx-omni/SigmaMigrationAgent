"""Sigma data-model spec -> IR using fictional, official-shape examples.

Current Sigma code representations nest ``metrics`` and ``relationships`` on table elements.
Legacy top-level arrays remain covered separately so older saved snapshots stay readable.
"""

from __future__ import annotations

import hashlib
import json

import pytest

from omni_migrator.core.contracts import ExtractCtx, FileInput
from omni_migrator.extractors.sigma import extractor as sigma_extractor
from omni_migrator.extractors.sigma.extractor import SigmaExtractor, _build_bundle


def _snapshot(**overrides) -> dict:
    base = {
        "connections": [{"connectionId": "c1", "name": "Warehouse", "type": "bigQuery"}],
        "dataModels": [
            {
                "dataModelId": "dm1",
                "spec": {
                    "pages": [
                        {
                            "elements": [
                                {
                                    "id": "e1",
                                    "kind": "table",
                                    "name": "Order Items",
                                    "source": {
                                        "connectionId": "c1",
                                        "kind": "warehouse-table",
                                        "path": ["db", "public", "order_items"],
                                    },
                                    "columns": [
                                        {"id": "col-id", "name": "id"},
                                        {"id": "col-price", "name": "Sale Price"},
                                    ],
                                },
                                {
                                    "id": "e2",
                                    "kind": "table",
                                    "name": "Inventory Items",
                                    "source": {
                                        "connectionId": "c1",
                                        "kind": "warehouse-table",
                                        "path": ["db", "public", "inventory_items"],
                                    },
                                    "columns": [{"id": "col-inv-id", "name": "id"}],
                                },
                            ],
                        }
                    ],
                    "relationships": [],
                    "metrics": [],
                },
            }
        ],
    }
    base.update(overrides)
    return base


def test_physical_columns_and_dialect():
    bundle = _build_bundle(_snapshot())
    orders = next(v for v in bundle.model.views if v.name == "order_items")
    assert orders.connection.dialect == "bigquery"
    assert orders.schema_name == "public" and orders.source_table == "order_items"
    assert {f.name for f in orders.fields} == {"id", "sale_price"}
    price = next(f for f in orders.fields if f.name == "sale_price")
    assert price.sql == "sale_price"


def test_normalized_field_collisions_are_identity_stable_and_keep_dashboard_references():
    snapshot = _snapshot()
    columns = snapshot["dataModels"][0]["spec"]["pages"][0]["elements"][0]["columns"]
    columns.extend(
        [
            {"id": "gross-margin-space", "name": "Gross Margin"},
            {"id": "gross-margin-dash", "name": "Gross-Margin"},
        ]
    )
    snapshot["workbooks"] = [
        {
            "workbookId": "wb-collision",
            "pages": [
                {
                    "pageId": "page-collision",
                    "name": "Collision",
                    "elements": [
                        {
                            "elementId": "visual-collision",
                            "type": "visualization",
                            "vizualizationType": "Table",
                            "columns": [
                                {"columnId": "gross-margin-space"},
                                {"columnId": "gross-margin-dash"},
                            ],
                        }
                    ],
                }
            ],
        }
    ]

    first = _build_bundle(snapshot)
    reversed_snapshot = json.loads(json.dumps(snapshot))
    reversed_snapshot["dataModels"][0]["spec"]["pages"][0]["elements"][0]["columns"].reverse()
    second = _build_bundle(reversed_snapshot)

    def collision_fields(bundle):
        view = next(item for item in bundle.model.views if item.name == "order_items")
        return {
            field.source_id: field
            for field in view.fields
            if field.source_id in {"gross-margin-space", "gross-margin-dash"}
        }

    first_fields = collision_fields(first)
    second_fields = collision_fields(second)
    first_names = {source_id: field.name for source_id, field in first_fields.items()}
    second_names = {source_id: field.name for source_id, field in second_fields.items()}

    assert first_names == second_names
    assert len(set(first_names.values())) == 2
    assert all(name.startswith("gross_margin__") for name in first_names.values())
    assert {field.sql for field in first_fields.values()} == {"gross_margin"}
    assert first.dashboards[0].tiles[0].query.fields == [
        first_names["gross-margin-space"],
        first_names["gross-margin-dash"],
    ]
    assert any(
        "deterministic identity suffixes" in note.reason
        for note in first.model.views[0].untranslatable
    )


def test_workbook_scope_expands_only_selected_workbook_pages_with_aliases():
    workbooks = [
        {
            "workbookId": "wb-1",
            "name": "Keep",
            "pages": [{"id": "page-1", "name": "Overview", "elements": []}],
        },
        {
            "workbookId": "wb-2",
            "name": "Exclude",
            "pages": [{"id": "page-2", "name": "Other", "elements": []}],
        },
    ]
    bundle = _build_bundle(
        _snapshot(workbooks=workbooks), ExtractCtx(scope={"selected_dashboard_ids": ["wb-1"]})
    )
    assert [dashboard.name for dashboard in bundle.dashboards] == ["Overview"]
    assert bundle.dashboards[0].native_source_id == "page-1"
    assert bundle.dashboards[0].selection_aliases == ["wb-1", "page-1"]


def test_documented_page_id_can_select_one_page_directly():
    workbooks = [
        {
            "workbookId": "wb-1",
            "name": "Workbook",
            "pages": [
                {"pageId": "page-1", "name": "Keep", "elements": []},
                {"pageId": "page-2", "name": "Exclude", "elements": []},
            ],
        },
    ]

    bundle = _build_bundle(
        _snapshot(workbooks=workbooks),
        ExtractCtx(scope={"selected_dashboard_ids": ["page-1"]}),
    )

    assert [dashboard.name for dashboard in bundle.dashboards] == ["Keep"]
    assert bundle.dashboards[0].native_source_id == "page-1"


def test_workbook_tag_inventory_alone_does_not_claim_pinned_version_completeness():
    workbook = {
        "workbookId": "wb-versioned",
        "name": "Versioned workbook",
        "tags": [{"name": "release-candidate"}],
        "pages": [{"pageId": "page-1", "name": "Overview", "elements": []}],
    }

    bundle = _build_bundle(_snapshot(workbooks=[workbook]))

    version_dependency = next(
        dependency
        for dependency in bundle.acquisition.dependencies
        if dependency.reference == "wb-versioned:source-version"
    )
    assert version_dependency.status == "review"
    assert bundle.acquisition.dependency_closure_status == "partial"
    assert any(
        note.severity == "blocker" and "not pinned" in note.reason
        for note in bundle.model.untranslatable
    )


@pytest.mark.parametrize(
    "evidence",
    [
        {"kind": "tag", "tagName": "release-candidate"},
        {"kind": "bookmark", "bookmarkId": "bookmark-123"},
    ],
)
def test_explicit_tag_or_bookmark_evidence_marks_source_version_dependency_resolved(evidence):
    workbook = {
        "workbookId": "wb-pinned",
        "name": "Pinned workbook",
        "_omnikit_version_evidence": evidence,
        "pages": [{"pageId": "page-1", "name": "Overview", "elements": []}],
    }

    bundle = _build_bundle(_snapshot(workbooks=[workbook]))

    version_dependency = next(
        dependency
        for dependency in bundle.acquisition.dependencies
        if dependency.reference == "wb-pinned:source-version"
    )
    assert version_dependency.status == "resolved"
    assert bundle.acquisition.dependency_closure_status == "complete"
    assert not any("not pinned" in note.reason for note in bundle.model.untranslatable)


def test_calculated_column_becomes_note_not_field():
    """Mirrors Power BI's DAX-calculated-column posture — a formula that isn't a bare passthrough
    is row-context Sigma-formula logic with no deterministic Omni equivalent; flagged, never a
    fabricated `FieldIR`."""
    snapshot = _snapshot()
    snapshot["dataModels"][0]["spec"]["pages"][0]["elements"][0]["columns"].append(
        {"id": "col-calc", "name": "Full Name", "formula": '[First Name] + " " + [Last Name]'}
    )
    bundle = _build_bundle(snapshot)
    orders = next(v for v in bundle.model.views if v.name == "order_items")
    assert not any(f.name == "full_name" for f in orders.fields)
    assert any(
        "calculated column" in n.object and "Full Name" in n.object for n in orders.untranslatable
    )


def test_passthrough_formula_is_treated_as_plain_column():
    snapshot = _snapshot()
    snapshot["dataModels"][0]["spec"]["pages"][0]["elements"][0]["columns"].append(
        {"id": "col-status", "name": "Status", "formula": "[Status]"}
    )
    bundle = _build_bundle(snapshot)
    orders = next(v for v in bundle.model.views if v.name == "order_items")
    assert any(f.name == "status" for f in orders.fields)
    assert not any("Status" in n.object for n in orders.untranslatable if "calculated" in n.reason)


def test_legacy_top_level_metric_resolves_to_real_measure():
    snapshot = _snapshot()
    snapshot["dataModels"][0]["spec"]["metrics"] = [
        {"id": "m1", "name": "Total Revenue", "elementId": "e1", "formula": "Sum([Sale Price])"}
    ]
    bundle = _build_bundle(snapshot)
    orders = next(v for v in bundle.model.views if v.name == "order_items")
    measure = next(f for f in orders.fields if f.name == "total_revenue")
    assert measure.kind == "measure" and measure.aggregate == "sum" and measure.sql == "sale_price"


def test_metric_sum_if_becomes_filtered_measure():
    snapshot = _snapshot()
    snapshot["dataModels"][0]["spec"]["metrics"] = [
        {
            "id": "m2",
            "name": "Completed Revenue",
            "elementId": "e1",
            "formula": 'SumIf([Sale Price], [Status] = "Complete")',
        }
    ]
    snapshot["dataModels"][0]["spec"]["pages"][0]["elements"][0]["columns"].append(
        {"id": "col-status", "name": "Status"}
    )
    bundle = _build_bundle(snapshot)
    orders = next(v for v in bundle.model.views if v.name == "order_items")
    measure = next(f for f in orders.fields if f.name == "completed_revenue")
    assert measure.aggregate == "sum" and measure.filters == {"status": {"is": "Complete"}}


def test_unresolvable_metric_is_untranslatable():
    snapshot = _snapshot()
    snapshot["dataModels"][0]["spec"]["metrics"] = [
        {"id": "m3", "name": "Bad Metric", "elementId": "e1", "formula": "Lookup(x, y, z)"}
    ]
    bundle = _build_bundle(snapshot)
    orders = next(v for v in bundle.model.views if v.name == "order_items")
    assert not any(f.name == "bad_metric" for f in orders.fields)
    assert any("Bad Metric" in n.object for n in orders.untranslatable)


def test_legacy_top_level_relationship_becomes_topic_join_with_scoped_names():
    snapshot = _snapshot()
    snapshot["dataModels"][0]["spec"]["relationships"] = [
        {
            "fromElementId": "e1",
            "fromColumnId": "col-price",
            "toElementId": "e2",
            "toColumnId": "col-inv-id",
            "type": "many-to-one",
        }
    ]
    bundle = _build_bundle(snapshot)
    (topic,) = bundle.model.topics
    assert topic.base_view == "order_items"
    (join,) = topic.joins
    assert join.join_from_view == "order_items" and join.join_to_view == "inventory_items"
    assert join.relationship_type == "many_to_one"
    assert join.on_sql == "${order_items.sale_price} = ${inventory_items.id}"
    orders = next(v for v in bundle.model.views if v.name == "order_items")
    assert any("legacy top-level" in n.reason.lower() for n in orders.untranslatable)


def test_relationship_one_to_one_type():
    snapshot = _snapshot()
    snapshot["dataModels"][0]["spec"]["relationships"] = [
        {
            "fromElementId": "e1",
            "fromColumnId": "col-price",
            "toElementId": "e2",
            "toColumnId": "col-inv-id",
            "type": "one-to-one",
        }
    ]
    bundle = _build_bundle(snapshot)
    (topic,) = bundle.model.topics
    assert topic.joins[0].relationship_type == "one_to_one"


def test_documented_nested_metrics_and_relationships_preserve_native_identity():
    snapshot = _snapshot()
    elements = snapshot["dataModels"][0]["spec"]["pages"][0]["elements"]
    orders = next(element for element in elements if element["id"] == "e1")
    orders["metrics"] = [
        {
            "id": "metric-unique-orders",
            "name": "Unique Orders",
            "formula": "CountDistinct([id])",
        }
    ]
    orders["relationships"] = [
        {
            "id": "relationship-orders-inventory",
            "name": "Orders to Inventory",
            "targetElementId": "e2",
            "keys": [
                {
                    "sourceColumnId": "col-id",
                    "targetColumnId": "col-inv-id",
                }
            ],
        }
    ]

    bundle = _build_bundle(snapshot)

    order_view = next(view for view in bundle.model.views if view.name == "order_items")
    measure = next(field for field in order_view.fields if field.source_id == "metric-unique-orders")
    assert measure.kind == "measure"
    assert measure.aggregate == "count_distinct"
    assert measure.source_locator == "data-model:dm1/element:e1/metric:metric-unique-orders"

    (topic,) = bundle.model.topics
    (join,) = topic.joins
    assert join.source_id == "relationship-orders-inventory"
    assert join.source_locator == (
        "data-model:dm1/element:e1/relationship:relationship-orders-inventory"
    )
    assert join.join_from_view == "order_items"
    assert join.join_to_view == "inventory_items"
    assert join.on_sql == "${order_items.id} = ${inventory_items.id}"


def test_documented_nested_relationship_preserves_all_join_keys():
    snapshot = _snapshot()
    elements = snapshot["dataModels"][0]["spec"]["pages"][0]["elements"]
    orders = next(element for element in elements if element["id"] == "e1")
    inventory = next(element for element in elements if element["id"] == "e2")
    orders["columns"].append({"id": "col-store", "name": "Store Id"})
    inventory["columns"].append({"id": "col-inv-store", "name": "Store Id"})
    orders["relationships"] = [
        {
            "id": "relationship-composite",
            "targetElementId": "e2",
            "keys": [
                {"sourceColumnId": "col-id", "targetColumnId": "col-inv-id"},
                {"sourceColumnId": "col-store", "targetColumnId": "col-inv-store"},
            ],
        }
    ]

    bundle = _build_bundle(snapshot)

    join = bundle.model.topics[0].joins[0]
    assert join.on_sql == (
        "${order_items.id} = ${inventory_items.id} AND "
        "${order_items.store_id} = ${inventory_items.store_id}"
    )


def test_element_missing_source_path_still_gets_a_view():
    """An element name (not the physical table name) can still anchor a view even with no
    schema/table path — matches how a derived/no-path element degrades gracefully rather than
    being dropped."""
    snapshot = _snapshot()
    snapshot["dataModels"][0]["spec"]["pages"][0]["elements"].append(
        {
            "id": "e3",
            "kind": "table",
            "name": "Ad Hoc",
            "source": {},
            "columns": [{"id": "col-x", "name": "X"}],
        }
    )
    bundle = _build_bundle(snapshot)
    assert any(v.name == "ad_hoc" for v in bundle.model.views)


def test_normalize_unknown_connection_type_falls_back_to_other():
    snapshot = _snapshot(
        connections=[{"connectionId": "c1", "name": "Mystery", "type": "some-future-warehouse"}]
    )
    bundle = _build_bundle(snapshot)
    orders = next(v for v in bundle.model.views if v.name == "order_items")
    assert orders.connection.dialect == "other"


def test_richer_data_model_sources_and_formula_columns_are_consumed():
    snapshot = _snapshot(
        dataModels=[
            {
                "dataModelId": "dm-rich",
                "name": "Sales",
                "spec": {"pages": [], "relationships": [], "metrics": []},
                "sources": [
                    {
                        "elementId": "src-orders",
                        "name": "Orders",
                        "type": "table",
                        "connectionId": "c1",
                        "path": ["warehouse", "analytics", "orders"],
                    }
                ],
                "columns": [
                    {
                        "columnId": "amount",
                        "elementId": "src-orders",
                        "name": "Amount",
                    },
                    {
                        "columnId": "revenue",
                        "elementId": "src-orders",
                        "name": "Revenue",
                        "formula": "Sum([Orders/Amount])",
                    },
                ],
            }
        ]
    )

    bundle = _build_bundle(snapshot)

    (orders,) = bundle.model.views
    assert orders.name == "orders"
    assert orders.schema_name == "analytics"
    assert orders.source_table == "orders"
    assert {(field.name, field.kind) for field in orders.fields} == {
        ("amount", "dimension"),
        ("revenue", "measure"),
    }
    assert any(
        dependency.kind == "calculation" and dependency.reference == "revenue"
        for dependency in bundle.acquisition.dependencies
    )


def test_same_named_views_are_stably_scoped_instead_of_overwritten():
    first = _snapshot()["dataModels"][0]
    second = json.loads(json.dumps(first))
    second["dataModelId"] = "dm2"
    second["name"] = "Inventory Domain"
    for element in second["spec"]["pages"][0]["elements"]:
        if element["id"] == "e1":
            element["id"] = "e3"
            element["columns"] = [{"id": "dm2-col-id", "name": "id"}]
        else:
            element["id"] = "e4"
            element["name"] = "Supplier Items"
            element["columns"] = [{"id": "dm2-col-supplier", "name": "supplier"}]

    bundle = _build_bundle(_snapshot(dataModels=[first, second]))
    names = [view.name for view in bundle.model.views]

    assert "order_items" in names
    assert "inventory_domain__order_items" in names
    assert len(names) == len(set(names))


def test_duplicate_column_ids_become_blockers_and_do_not_bind_dashboard_fields():
    first = _snapshot()["dataModels"][0]
    second = json.loads(json.dumps(first))
    second["dataModelId"] = "dm2"
    second["name"] = "Second Domain"
    second["spec"]["pages"][0]["elements"][0]["id"] = "other-element"
    second["spec"]["pages"][0]["elements"][0]["name"] = "Other Orders"
    second["spec"]["pages"][0]["elements"] = [second["spec"]["pages"][0]["elements"][0]]
    workbooks = [
        {
            "workbookId": "wb1",
            "pages": [
                {
                    "pageId": "p1",
                    "name": "Overview",
                    "elements": [
                        {
                            "elementId": "visual1",
                            "type": "visualization",
                            "vizualizationType": "Table",
                            "columns": [{"columnId": "col-id"}],
                        }
                    ],
                }
            ],
        }
    ]

    bundle = _build_bundle(_snapshot(dataModels=[first, second], workbooks=workbooks))

    assert any("same source column ID" in note.reason for note in bundle.model.untranslatable)
    assert bundle.dashboards[0].tiles == []
    assert any(
        "Unresolved column reference" in note.reason for note in bundle.dashboards[0].untranslatable
    )


def test_acquisition_manifest_is_scoped_and_uses_typed_requirements():
    selected = {
        "workbookId": "wb1",
        "pages": [
            {
                "pageId": "p1",
                "name": "Overview",
                "elements": [
                    {
                        "elementId": "visual1",
                        "type": "visualization",
                        "vizualizationType": "Table",
                        "columns": ["col-id"],
                    },
                    {"elementId": "input1", "type": "input_table", "columns": []},
                    {"elementId": "action1", "type": "button", "columns": []},
                ],
            }
        ],
        "controls": [{"controlId": "control1", "name": "Region"}],
        "queries": [{"queryId": "query1", "elementId": "visual1", "sql": "select 1"}],
        "lineage": [{"elementId": "visual1", "sourceIds": ["e1"]}],
        "grants": [{"grantId": "grant1", "permission": "view"}],
        "schedules": [{"scheduledNotificationId": "schedule1"}],
    }
    excluded = {
        "workbookId": "wb2",
        "pages": [{"pageId": "p2", "name": "Excluded", "elements": []}],
        "schedules": [{"scheduledNotificationId": "excluded-schedule"}],
    }

    bundle = _build_bundle(
        _snapshot(workbooks=[selected, excluded]),
        ExtractCtx(scope={"selected_dashboard_ids": ["p1"]}),
    )

    dependencies = bundle.acquisition.dependencies
    assert {dependency.reference for dependency in dependencies} >= {
        "wb1",
        "p1",
        "visual1",
        "input1",
        "action1",
        "control1",
        "query1",
        "grant1",
        "schedule1",
    }
    assert not any(dependency.reference == "wb2" for dependency in dependencies)
    assert not any(dependency.reference == "excluded-schedule" for dependency in dependencies)
    requirement_types = {requirement.object_type for requirement in bundle.model.requirements}
    assert {
        "control",
        "input_table",
        "action",
        "layout",
        "permission",
        "schedule",
        "query_validation",
        "lineage",
    } <= requirement_types
    assert all(
        requirement.support_outcome == "unsupported"
        for requirement in bundle.model.requirements
        if requirement.object_type in {"input_table", "action", "schedule"}
    )


def test_unresolved_visual_retains_generated_sql_fingerprint_and_review_dependencies():
    generated = {
        "queryId": "query-unresolved",
        "elementId": "visual-unresolved",
        "sql": "select private_value from confidential_source",
    }
    workbook = {
        "workbookId": "wb-unresolved",
        "pages": [
            {
                "pageId": "page-unresolved",
                "name": "Unresolved",
                "elements": [
                    {
                        "elementId": "visual-unresolved",
                        "name": "Unresolved visual",
                        "type": "visualization",
                        "vizualizationType": "Table",
                        "columns": [{"columnId": "missing-source-field"}],
                        "generatedSql": generated,
                    }
                ],
            }
        ],
        "queries": [],
    }

    bundle = _build_bundle(_snapshot(workbooks=[workbook]))
    expected = hashlib.sha256(
        json.dumps(generated, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()

    visual = next(
        dependency
        for dependency in bundle.acquisition.dependencies
        if dependency.kind == "visual" and dependency.reference == "visual-unresolved"
    )
    field = next(
        dependency
        for dependency in bundle.acquisition.dependencies
        if dependency.kind == "field" and dependency.reference == "missing-source-field"
    )
    requirement = next(
        item
        for item in bundle.model.requirements
        if item.object_type == "query_validation" and item.source_id == "query-unresolved"
    )

    assert visual.status == "review"
    assert "fields did not resolve" in visual.message
    assert field.status == "review"
    assert requirement.config["related_element_id"] == "visual-unresolved"
    assert requirement.config["generated_sql"] == {
        "sha256": expected,
        "role": "validation_evidence_only",
    }
    assert bundle.dashboards[0].tiles == []
    assert any(expected in (note.hint or "") for note in bundle.dashboards[0].untranslatable)
    serialized = json.dumps(bundle.model_dump(mode="json"), sort_keys=True)
    assert expected in serialized
    assert "private_value" not in serialized
    assert "confidential_source" not in serialized


def test_operational_handoffs_keep_safe_bounded_metadata_and_redact_sensitive_values():
    snapshot = _snapshot()
    snapshot["dataModels"][0]["grants"] = [
        {
            "grantId": "grant-model-reviewers",
            "principalId": "team-sensitive-reviewers",
            "principalType": "team",
            "permission": "explore",
        }
    ]
    snapshot["dataModels"][0]["materializationSchedules"] = [
        {
            "scheduleId": "schedule-model-refresh",
            "cron": "0 5 * * *",
            "timezone": "America/Chicago",
            "enabled": True,
        }
    ]
    snapshot["workbooks"] = [
        {
            "workbookId": "wb-operations",
            "pages": [
                {
                    "pageId": "page-operations",
                    "name": "Operations",
                    "elements": [
                        {
                            "elementId": "input-plan",
                            "name": "Planning input",
                            "type": "inputTable",
                            "writeDestination": {
                                "connectionId": "warehouse-connection",
                                "schema": "PLANNING",
                                "table": "PLAN_INPUT",
                            },
                            "apiToken": "synthetic-input-token",
                        },
                        {
                            "elementId": "action-approve",
                            "name": "Approve",
                            "type": "button",
                            "action": {
                                "target": "approval-workflow",
                                "configuration": {"mode": "append"},
                                "authorization": "Bearer synthetic-action-secret",
                            },
                        },
                    ],
                }
            ],
            "controls": [
                {
                    "controlId": "control-region",
                    "name": "Region",
                    "controlType": "list",
                    "columnId": "col-id",
                    "targetElementIds": ["input-plan", "action-approve"],
                    "ownerId": "user-sensitive-owner",
                }
            ],
            "grants": [
                {
                    "grantId": "grant-workbook-reviewers",
                    "principalId": "user-sensitive-reviewer",
                    "principalType": "user",
                    "permission": "manage",
                }
            ],
            "schedules": [
                {
                    "scheduleId": "schedule-weekly",
                    "cron": "0 7 * * 1",
                    "timezone": "America/Chicago",
                    "format": "pdf",
                    "recipients": [f"reviewer-{index}@example.invalid" for index in range(45)],
                    "enabled": True,
                    "credential": "synthetic-schedule-credential",
                }
            ],
        }
    ]

    bundle = _build_bundle(snapshot)
    by_source_id = {requirement.source_id: requirement for requirement in bundle.model.requirements}
    control = by_source_id["control-region"]
    model_grant = by_source_id["grant-model-reviewers"]
    workbook_grant = by_source_id["grant-workbook-reviewers"]
    schedule = by_source_id["schedule-weekly"]
    input_table = by_source_id["input-plan"]
    action = by_source_id["action-approve"]

    assert control.support_outcome == "unsupported"
    assert control.config["unverified_candidate_column_ids"] == ["col-id"]
    assert control.config["proposed_target_fields"] == []
    assert control.config["review_metadata"]["targetElementIds"] == [
        "input-plan",
        "action-approve",
    ]
    assert control.config["review_metadata"]["ownerId"]["redacted"] == "identity"
    assert model_grant.config["principal_type"] == "team"
    assert workbook_grant.config["principal_type"] == "user"
    assert model_grant.config["review_metadata"]["principalId"]["count"] == 1
    schedule_metadata = schedule.config["review_metadata"]
    assert schedule_metadata["cron"] == "0 7 * * 1"
    assert schedule_metadata["timezone"] == "America/Chicago"
    assert schedule_metadata["format"] == "pdf"
    assert schedule_metadata["enabled"] is True
    recipients = schedule.config["review_metadata"]["recipients"]
    assert recipients["redacted"] == "identity"
    assert recipients["count"] == 45
    assert len(recipients["sha256"]) == sigma_extractor.MAX_OPERATIONAL_METADATA_ITEMS
    assert recipients["omitted_items"] == 5
    assert input_table.config["review_metadata"]["writeDestination"] == {
        "connectionId": "warehouse-connection",
        "schema": "PLANNING",
        "table": "PLAN_INPUT",
    }
    assert input_table.config["review_metadata"]["apiToken"] == {"redacted": "secret"}
    assert action.config["review_metadata"]["action"]["configuration"] == {"mode": "append"}
    assert action.config["review_metadata"]["action"]["authorization"] == {"redacted": "secret"}
    assert all(
        requirement.support_outcome != "automatic"
        for requirement in (control, model_grant, workbook_grant, schedule, input_table, action)
    )

    serialized = json.dumps(bundle.model_dump(mode="json"), sort_keys=True)
    for sensitive in (
        "team-sensitive-reviewers",
        "user-sensitive-reviewer",
        "user-sensitive-owner",
        "reviewer-0@example.invalid",
        "synthetic-input-token",
        "synthetic-action-secret",
        "synthetic-schedule-credential",
    ):
        assert sensitive not in serialized


def _snapshot_file(tmp_path, payload: object, name: str = "sigma-snapshot.json"):
    path = tmp_path / name
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_manual_sigma_snapshot_runs_the_same_transform(tmp_path):
    payload = _snapshot(
        _omnikit_acquisition={"contract": "sigma-api-v2"},
        workbooks=[
            {"workbookId": "wb1", "pages": [{"pageId": "p1", "name": "Overview", "elements": []}]}
        ],
    )
    path = _snapshot_file(tmp_path, payload)

    bundle = SigmaExtractor().extract(FileInput(paths=[path]), ExtractCtx())

    assert bundle.acquisition.mode == "manual"
    assert bundle.acquisition.source_files == [str(path)]
    assert bundle.provenance.source_artifact == str(path)
    assert [view.name for view in bundle.model.views] == ["order_items", "inventory_items"]


def test_manual_sigma_snapshot_rejects_multiple_non_json_invalid_and_wrong_contract(tmp_path):
    valid = _snapshot_file(
        tmp_path,
        _snapshot(_omnikit_acquisition={"contract": "sigma-api-v2"}),
    )
    second = _snapshot_file(
        tmp_path,
        _snapshot(_omnikit_acquisition={"contract": "sigma-api-v2"}),
        "second.json",
    )
    wrong_extension = tmp_path / "snapshot.txt"
    wrong_extension.write_text("{}", encoding="utf-8")
    invalid = tmp_path / "invalid.json"
    invalid.write_text("{not-json", encoding="utf-8")
    wrong_contract = _snapshot_file(
        tmp_path,
        _snapshot(_omnikit_acquisition={"contract": "some-other-contract"}),
        "wrong-contract.json",
    )

    with pytest.raises(ValueError, match="exactly one"):
        SigmaExtractor().extract(FileInput(paths=[valid, second]), ExtractCtx())
    with pytest.raises(ValueError, match="only a .json"):
        SigmaExtractor().extract(FileInput(paths=[wrong_extension]), ExtractCtx())
    with pytest.raises(ValueError, match="valid UTF-8 JSON"):
        SigmaExtractor().extract(FileInput(paths=[invalid]), ExtractCtx())
    with pytest.raises(ValueError, match="sigma-api-v2"):
        SigmaExtractor().extract(FileInput(paths=[wrong_contract]), ExtractCtx())


def test_manual_sigma_snapshot_rejects_oversized_file(tmp_path, monkeypatch):
    path = tmp_path / "large.json"
    path.write_text('{"_omnikit_acquisition":{"contract":"sigma-api-v2"}}', encoding="utf-8")
    monkeypatch.setattr(sigma_extractor, "MAX_SIGMA_SNAPSHOT_BYTES", 8)

    with pytest.raises(ValueError, match="byte limit"):
        SigmaExtractor().extract(FileInput(paths=[path]), ExtractCtx())

"""Reviewable pilot selection without deleting or rewriting captured source evidence.

The scope is a deterministic description, never approval or proof of completeness.
Unknown lineage stays blocked. Consumers must rederive it before trusting exclusions.
This module deliberately does not import the builder, target clients, or providers.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json

from omni_migrator.extractors.sigma.field_binding import CapturedField, SigmaFieldBinder
from omni_migrator.deterministic.sigma_translate import _snake

SCOPE_KEY = "_migration_scope"
SCHEMA = "sigma-migration-scope.v1"


def _hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=False, allow_nan=False).encode()).hexdigest()


def original_source_hash(snapshot):
    return _hash({key: value for key, value in snapshot.items()
                  if key not in {SCOPE_KEY, "prepush_context"}})


def _id(row, *keys):
    for key in keys:
        value = row.get(key)
        if isinstance(value, str) and value.strip():
            return value
    raise ValueError("Scope requires stable, nonempty captured identities")


def _selection(values, label):
    if isinstance(values, str) or not isinstance(values, (list, tuple)):
        raise ValueError(f"{label} must be a list of exact IDs")
    if any(not isinstance(value, str) or not value.strip() for value in values):
        raise ValueError(f"{label} must contain nonempty exact IDs")
    if len(set(values)) != len(values):
        raise ValueError(f"{label} contains duplicate IDs")
    return sorted(values)


def _workbook(snapshot, workbook_id):
    matches = [(index, row) for index, row in enumerate(snapshot.get("workbooks", []))
               if _id(row, "workbookId", "id") == workbook_id]
    if len(matches) != 1:
        raise ValueError("Select exactly one captured workbook by its exact ID")
    return matches[0]


def _workbook_elements(workbook, wi):
    elements, pages = {}, {}
    for pi, page in enumerate(workbook.get("pages", [])):
        page_id = _id(page, "pageId", "id")
        if page_id in pages:
            raise ValueError("Duplicate workbook page identity makes scope ambiguous")
        page_path = f"/workbooks/{wi}/pages/{pi}"
        pages[page_id] = {"path": page_path, "elements": []}
        for ei, raw in enumerate(page.get("elements", [])):
            identity = _id(raw, "elementId", "id")
            if identity in elements:
                raise ValueError("Duplicate workbook element identity makes scope ambiguous")
            elements[identity] = {"raw": deepcopy(raw), "page_id": page_id,
                                  "paths": [f"{page_path}/elements/{ei}"]}
            pages[page_id]["elements"].append(identity)
    seen_bulk = set()
    for ei, raw in enumerate(workbook.get("elements", [])):
        identity = _id(raw, "elementId", "id")
        if identity in seen_bulk:
            raise ValueError("Duplicate bulk workbook element identity makes scope ambiguous")
        seen_bulk.add(identity)
        path = f"/workbooks/{wi}/elements/{ei}"
        if identity in elements:
            row = elements[identity]
            # API page/bulk representations are additive. Keep both full originals;
            # inspect lineage in both representations rather than dropping either.
            row.setdefault("additional_raw", []).append(raw)
            row["paths"].append(path)
        else:
            elements[identity] = {"raw": deepcopy(raw), "page_id": raw.get("pageId"),
                                  "paths": [path]}
    return elements, pages


def chart_inventory(snapshot, *, workbook_id):
    """Include unsupported visual kinds so page selection cannot hide them."""
    wi, workbook = _workbook(snapshot, workbook_id)
    elements, _ = _workbook_elements(workbook, wi)
    return [{"source_id": identity, "name": row["raw"].get("name", identity),
             "kind": row["raw"].get("type", row["raw"].get("kind", "unknown")),
             "page_id": row["page_id"], "source_path": row["paths"][0],
             "source_paths": row["paths"]}
            for identity, row in elements.items()
            if str(row["raw"].get("type", row["raw"].get("kind", ""))).lower()
            not in {"control", "list-control", "dropdown"}]


def _object_paths(value, path):
    """Exact object-list members and security objects; mirrors source identities."""
    paths = set()
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = path + "/" + str(key).replace("~", "~0").replace("/", "~1")
            if key in {"security", "rls", "cls", "permissions", "rowLevelSecurity",
                       "columnLevelSecurity", "pdp"} and isinstance(child, dict) and child:
                paths.add(child_path)
            paths.update(_object_paths(child, child_path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            child_path = f"{path}/{index}"
            if isinstance(child, dict):
                paths.add(child_path)
            paths.update(_object_paths(child, child_path))
    return paths


def _at(snapshot, path):
    value = snapshot
    for segment in path.strip("/").split("/"):
        segment = segment.replace("~1", "/").replace("~0", "~")
        value = value[int(segment)] if isinstance(value, list) else value[segment]
    return value


def derive_scope(snapshot, *, workbook_id, chart_ids=(), page_ids=()):
    """Recompute selection, dependency closure, exclusions and blockers from source."""
    if not isinstance(snapshot, dict):
        raise ValueError("Scope requires a captured snapshot object")
    requested_charts = _selection(chart_ids, "Chart IDs")
    requested_pages = _selection(page_ids, "Page IDs")
    if not requested_charts and not requested_pages:
        raise ValueError("Explicitly select at least one chart or page; scope has no default")
    wi, workbook = _workbook(snapshot, workbook_id)
    elements, pages = _workbook_elements(workbook, wi)
    chart_ids_all = {row["source_id"] for row in chart_inventory(snapshot, workbook_id=workbook_id)}
    if set(requested_charts) - chart_ids_all or set(requested_pages) - set(pages):
        raise ValueError("Scope selection references an absent chart or page")
    selected = set(requested_charts)
    for page_id in requested_pages:
        selected.update(set(pages[page_id]["elements"]) & chart_ids_all)
    if not selected:
        raise ValueError("Selected pages contain no captured chart or table elements")
    issues = []

    def issue(code, path, message):
        row = {"code": code, "path": path, "message": message}
        if row not in issues:
            issues.append(row)

    def checked_lineage(value, known_ids, path):
        if not isinstance(value, list):
            issue("scope_unknown_lineage", path,
                  "Top-level lineage must identify its captured owner for safe dependency closure.")
            return []
        valid = []
        for index, row in enumerate(value):
            if (not isinstance(row, dict) or not isinstance(row.get("elementId"), str)
                    or row["elementId"] not in known_ids):
                issue("scope_unknown_lineage", f"{path}/{index}",
                      "Lineage owner is missing or unknown; its effect on selected charts cannot be excluded.")
            else:
                valid.append(row)
        return valid

    workbook_lineage = checked_lineage(workbook.get("lineage", []), set(elements),
                                       f"/workbooks/{wi}/lineage")

    source_hash = original_source_hash(snapshot)
    context = snapshot.get("prepush_context") or {}
    context_usable = (isinstance(context, dict) and context.get("source_sha256") == source_hash
                      and context.get("workbook_id") == workbook_id)
    if not context_usable:
        issue("scope_context_missing_or_stale", "/prepush_context",
              "Source-bound observed field and control context is required for this pilot.")
    element_context = context.get("elements", {}) if context_usable else {}
    control_context = context.get("controls", {}) if context_usable else {}
    if not isinstance(element_context, dict) or not isinstance(control_context, dict):
        raise ValueError("Observed scope context must contain element/control mappings")
    if len(selected) > 48:
        issue("scope_document_limit", SCOPE_KEY, "Selected scope exceeds 48 query presentations; select a smaller pilot.")

    model_elements, field_records, binders, model_lineages = {}, {}, {}, {}
    for di, dm in enumerate(snapshot.get("dataModels", [])):
        model_id = _id(dm, "dataModelId", "id")
        if model_id in binders:
            raise ValueError("Duplicate data-model identity makes scope ambiguous")
        records = []
        for page in dm.get("spec", {}).get("pages", []):
            for raw in page.get("elements", []):
                element_id = _id(raw, "elementId", "id")
                element_locator = f"data-model:{model_id}/element:{element_id}"
                if element_locator in model_elements:
                    raise ValueError("Duplicate model element identity makes scope ambiguous")
                model_elements[element_locator] = (model_id, element_id, raw, dm)
                for plural, singular, key in (("columns", "column", "columnId"), ("metrics", "metric", "metricId")):
                    rows = list(raw.get(plural, []))
                    if plural == "metrics":
                        rows.extend(row for row in dm.get("spec", {}).get("metrics", [])
                                    if row.get("elementId") == element_id)
                    for field in rows:
                        field_id = _id(field, key, "id")
                        locator = f"{element_locator}/{singular}:{field_id}"
                        if locator in field_records:
                            raise ValueError("Duplicate model field identity makes scope ambiguous")
                        record = CapturedField(key=locator, element_id=element_id,
                                              view_name=element_locator, source_id=field_id,
                                              field_name=field.get("name", field_id),
                                              sql_name=_snake(field.get("name", field_id)),
                                              row=field, element=raw, is_metric=singular == "metric")
                        field_records[locator] = (record, model_id, element_locator)
                        records.append(record)
        binders[model_id] = SigmaFieldBinder(records)
        model_lineages[model_id] = checked_lineage(
            dm.get("lineage", []),
            {eid for mid, eid, _, _ in model_elements.values() if mid == model_id},
            f"/dataModels/{di}/lineage",
        )

    needed_elements, needed_fields, visited, active = set(), set(), set(), set()
    workbook_prefix = f"workbook:{workbook_id}/element:"

    def resolve_element(identity, model_id=None):
        candidates = []
        if model_id is None and identity in elements:
            candidates.append(workbook_prefix + identity)
        candidates.extend(locator for locator, (mid, eid, _, _) in model_elements.items()
                          if eid == identity and (model_id is None or model_id == mid))
        if len(candidates) != 1:
            issue("scope_ambiguous_or_missing_dependency", str(identity),
                  "Upstream element must resolve to exactly one captured compound identity.")
            return None
        return candidates[0]

    def visit_field(locator):
        if locator in needed_fields:
            return
        if locator not in field_records:
            issue("scope_missing_field", str(locator), "Observed field identity is absent from the captured model.")
            return
        needed_fields.add(locator)
        _, model_id, element_locator = field_records[locator]
        visit_element(element_locator)
        result = binders[model_id].compile(locator)
        for problem in result.issues:
            issue("scope_unresolved_formula_dependency", locator, problem.reason)
        for dependency in result.dependencies:
            visit_field(dependency)

    def follow(reference, owner, source_rows):
        if isinstance(reference, str):
            locator = resolve_element(reference)
            if locator:
                visit_element(locator)
            return True
        if not isinstance(reference, dict):
            issue("scope_unknown_lineage", owner, "Lineage must use a supported explicit element/source identity.")
            return False
        source_id = reference.get("sourceId")
        source_matches = [row for row in source_rows if row.get("sourceId", row.get("id")) == source_id] if source_id else []
        if source_id and len(source_matches) != 1:
            issue("scope_ambiguous_or_missing_source", owner, "Lineage source ID must resolve to one captured source.")
        source = source_matches[0] if len(source_matches) == 1 else {}
        model_id = reference.get("dataModelId", source.get("dataModelId"))
        identities = []
        for key in ("sourceElementId", "parentElementId", "upstreamElementId"):
            if reference.get(key):
                identities.append(reference[key])
        for key in ("elementIds", "sourceElementIds", "upstreamElementIds"):
            if key in reference:
                if not isinstance(reference[key], list) or not reference[key]:
                    issue("scope_unknown_lineage", owner, "Dependency element IDs must be a nonempty list.")
                else:
                    identities.extend(reference[key])
        kind = str(reference.get("type", reference.get("kind", ""))).lower()
        if reference.get("elementId") and kind in {"element", "data-model", "workbook-element"}:
            identities.append(reference["elementId"])
        if identities:
            for identity in identities:
                if not isinstance(identity, str):
                    issue("scope_unknown_lineage", owner, "Dependency identities must be exact strings.")
                    continue
                locator = resolve_element(identity, model_id)
                if locator:
                    visit_element(locator)
            return True
        if model_id:
            matching = [locator for locator, (mid, _, _, _) in model_elements.items() if mid == model_id]
            if not matching:
                issue("scope_missing_model", owner, "Referenced data model is absent from the captured snapshot.")
            for locator in matching:
                visit_element(locator)
                for field_locator, (_, _, field_element) in field_records.items():
                    if field_element == locator:
                        visit_field(field_locator)
            return True
        if kind in {"table", "warehouse-table"} and any(reference.get(key) for key in ("path", "tableId", "inodeId", "table", "tableName")):
            return True
        if source:
            return follow(source, owner, [])
        issue("scope_unknown_lineage", owner,
              "Captured lineage/source shape cannot establish a complete dependency closure.")
        return False

    def visit_element(locator):
        if locator in active:
            issue("scope_dependency_cycle", locator, "Captured element dependencies contain a cycle.")
            return
        if locator in visited:
            return
        if len(active) >= 200:
            issue("scope_dependency_depth", locator, "Dependency depth exceeds the bounded traversal limit.")
            return
        active.add(locator)
        needed_elements.add(locator)
        if locator.startswith(workbook_prefix):
            identity = locator[len(workbook_prefix):]
            entry = elements[identity]
            raw_items = [entry["raw"], *entry.get("additional_raw", [])]
            source_rows = workbook.get("sources", [])
            owner_lineage = [row for row in workbook_lineage if row.get("elementId") == identity]
            setting = element_context.get(identity)
            if isinstance(setting, dict) and isinstance(setting.get("field_locators"), list) and setting["field_locators"]:
                for field_locator in setting["field_locators"]:
                    visit_field(field_locator)
            else:
                issue("scope_missing_field_context", locator,
                      "Selected or upstream workbook element lacks observed field identities.")
        else:
            model_id, identity, raw, dm = model_elements[locator]
            raw_items = [raw]
            source_rows = dm.get("sources", [])
            owner_lineage = [row for row in model_lineages[model_id] if row.get("elementId") == identity]
        for raw in raw_items:
            for key in ("source", "sources", "dependencies", "lineage"):
                if raw.get(key):
                    values = raw[key] if isinstance(raw[key], list) else [raw[key]]
                    for value in values:
                        follow(value, locator, source_rows)
            for key in ("sourceElementId", "parentElementId", "upstreamElementId", "upstreamElementIds"):
                if raw.get(key):
                    follow({key: raw[key]}, locator, source_rows)
        for row in owner_lineage:
            follow(row, locator, source_rows)
        active.remove(locator)
        visited.add(locator)

    for identity in sorted(selected):
        visit_element(workbook_prefix + identity)

    required_controls, excluded_controls, control_rows, shared_controls = set(), set(), {}, []
    for ci, control in enumerate(workbook.get("controls", [])):
        identity = _id(control, "controlId", "id")
        if identity in control_rows:
            raise ValueError("Duplicate control identity makes scope ambiguous")
        control_rows[identity] = {"raw": control, "paths": [f"/workbooks/{wi}/controls/{ci}"]}
    for identity, entry in elements.items():
        if identity not in chart_ids_all:
            if identity in control_rows:
                control_rows[identity]["paths"].extend(entry["paths"])
            else:
                control_rows[identity] = entry
    needed_workbook_ids = {locator[len(workbook_prefix):] for locator in needed_elements if locator.startswith(workbook_prefix)}
    for identity, row in control_rows.items():
        setting = control_context.get(identity)
        targets = setting.get("target_element_ids") if isinstance(setting, dict) else None
        if not isinstance(targets, list) or not targets or any(not isinstance(item, str) or item not in elements for item in targets):
            required_controls.add(identity)
            issue("scope_unknown_control_targets", row["paths"][0],
                  "Observed control targets are incomplete; this control cannot be safely excluded.")
            continue
        if needed_workbook_ids.intersection(targets):
            required_controls.add(identity)
            if not isinstance(setting.get("field_locator"), str):
                issue("scope_missing_control_field", row["paths"][0], "Observed control field identity is required.")
            else:
                visit_field(setting["field_locator"])
            shared_controls.append({"control_id": identity, "target_element_ids": sorted(set(targets)),
                                    "selected_target_ids": sorted(selected.intersection(targets)),
                                    "excluded_target_ids": sorted(set(targets) - needed_workbook_ids)})
        else:
            excluded_controls.add(identity)

    # Dependencies can themselves be charts: retain them even when not selected for
    # presentation. They are not silently counted as completed target tiles.
    needed_workbook_ids = {locator[len(workbook_prefix):] for locator in needed_elements if locator.startswith(workbook_prefix)}
    excluded = chart_ids_all - selected - needed_workbook_ids
    excluded_paths = set()
    for identity in excluded | excluded_controls:
        row = control_rows[identity] if identity in excluded_controls else elements[identity]
        for path in row["paths"]:
            excluded_paths.add(path)
            excluded_paths.update(_object_paths(_at(snapshot, path), path))
    for page in pages.values():
        if page["elements"] and set(page["elements"]) <= (excluded | excluded_controls):
            excluded_paths.add(page["path"])
    selected_paths = sorted({path for identity in selected for path in elements[identity]["paths"]})
    return {"schema_version": SCHEMA, "workbook_id": workbook_id,
            "original_source_sha256": source_hash, "context_sha256": _hash(snapshot.get("prepush_context")),
            "requested_chart_ids": requested_charts, "requested_page_ids": requested_pages,
            "selected_chart_ids": sorted(selected), "excluded_chart_ids": sorted(excluded),
            "dependency_element_locators": sorted(needed_elements - {workbook_prefix + item for item in selected}),
            "dependency_field_locators": sorted(needed_fields),
            "required_control_ids": sorted(required_controls), "excluded_control_ids": sorted(excluded_controls),
            "shared_controls": sorted(shared_controls, key=lambda row: row["control_id"]),
            "selected_source_paths": selected_paths, "excluded_source_paths": sorted(excluded_paths),
            "assembly_intent": "selected_charts_single_document",
            "issues": sorted(issues, key=lambda row: (row["path"], row["code"], row["message"])),
            "target_write_authority": False, "live_validation": "not_performed"}


def create_scope(snapshot, *, workbook_id, chart_ids=(), page_ids=()):
    scoped = deepcopy(snapshot)
    scoped[SCOPE_KEY] = derive_scope(snapshot, workbook_id=workbook_id, chart_ids=chart_ids, page_ids=page_ids)
    return scoped


def validate_scope(snapshot):
    """Reject stale hashes, altered closure, invented exclusions and unknown fields."""
    metadata = snapshot.get(SCOPE_KEY)
    if metadata is None:
        return None
    if not isinstance(metadata, dict) or metadata.get("schema_version") != SCHEMA:
        raise ValueError("Unsupported migration scope metadata")
    derived = derive_scope(snapshot, workbook_id=metadata.get("workbook_id"),
                           chart_ids=metadata.get("requested_chart_ids", ()),
                           page_ids=metadata.get("requested_page_ids", ()))
    if metadata != derived:
        raise ValueError("Migration scope is stale or modified; recreate scope from current evidence and review again")
    return derived


def scoped_source_paths(snapshot):
    scope = validate_scope(snapshot)
    return {"selected": set(scope["selected_source_paths"]),
            "excluded": set(scope["excluded_source_paths"])} if scope else {"selected": set(), "excluded": set()}

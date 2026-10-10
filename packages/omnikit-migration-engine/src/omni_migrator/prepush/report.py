"""Observed local preparation progress, with no invented execution or live parity."""
from __future__ import annotations

from copy import deepcopy

from omni_migrator.prepush.scope import chart_inventory, validate_scope


def _resume(state, validation, scope):
    if state.get("revoked"):
        return {"operation": "route", "reason": "Review was withdrawn; select the route and obtain fresh review."}
    if not state.get("route"):
        return {"operation": "route", "reason": "Choose one of the two migration routes; there is no default."}
    review = state.get("review")
    decision = review.get("decision") if isinstance(review, dict) else review
    if decision != "accept":
        return {"operation": "review", "reason": "A current human review is required before local build."}
    if scope and scope["issues"]:
        return {"operation": "remediate_source", "reason": "Resolve scope dependencies, import the revised source and review again."}
    if validation is None:
        return {"operation": "build", "reason": "Build the reviewed package; prior interrupted attempts remain preserved."}
    if validation.get("status") == "blocked":
        return {"operation": "remediate", "reason": "Resolve the reported blockers and review changed inputs before rebuilding."}
    return {"operation": "export", "reason": "Local validation passed; export for review. Live development needs separate authority."}


def migration_report(snapshot, proposal=None, validation=None, state=None):
    """Project actual dispositions and checks onto stable source chart identities.

    ``validation`` must be the actual independent package-validation result. This
    function does not convert compiler output into validation or live acceptance.
    """
    scope = validate_scope(snapshot)
    state = state or {}
    proposal = proposal or {}
    dispositions = proposal.get("dispositions", [])
    mappings = proposal.get("source_mappings", [])
    validation_issues = deepcopy(validation.get("issues", [])) if validation else []
    scope_issues = deepcopy(scope["issues"]) if scope else []
    selected = set(scope["selected_chart_ids"]) if scope else None
    excluded = set(scope["excluded_chart_ids"]) if scope else set()
    required_elements = set(scope["dependency_element_locators"]) if scope else set()
    rows = []
    for workbook in snapshot.get("workbooks", []):
        workbook_id = workbook.get("workbookId", workbook.get("id"))
        for chart in chart_inventory(snapshot, workbook_id=workbook_id):
            source_id = chart["source_id"]
            paths = set(chart["source_paths"])
            related = [row for row in dispositions if row.get("source_path") in paths]
            target_paths = sorted({path for row in related for path in row.get("target_paths", [])})
            target_refs = sorted({row["target_object_ref"] for row in mappings
                                  if row.get("source_path") in paths and row.get("target_object_ref")})
            if scope and workbook_id != scope["workbook_id"]:
                selection = "outside_selected_workbook"
            elif source_id in excluded:
                selection = "excluded"
            elif selected is None or source_id in selected:
                selection = "selected"
            elif f"workbook:{workbook_id}/element:{source_id}" in required_elements:
                selection = "dependency"
            else:
                selection = "unresolved_scope"
            if selection in {"excluded", "outside_selected_workbook"}:
                preparation = "not_selected"
            elif not related:
                preparation = "not_built"
            elif any(row.get("status") == "blocked" for row in related):
                preparation = "blocked"
            elif all(row.get("status") == "implemented" for row in related):
                preparation = "compiled"
            else:
                preparation = "unresolved"
            chart_issues = [issue for issue in validation_issues
                            if issue.get("path") in target_paths
                            or any(issue.get("path", "") == path or issue.get("path", "").startswith(path + "/")
                                   for path in paths)]
            if selection in {"excluded", "outside_selected_workbook"}:
                offline = "not_in_pilot"
            elif validation is None:
                offline = "not_performed"
            elif chart_issues or preparation != "compiled":
                offline = "blocked"
            elif validation.get("status") == "offline_preflight_passed":
                offline = "offline_preflight_passed"
            else:
                offline = "package_blocked"
            rows.append({**chart, "workbook_id": workbook_id, "selection": selection,
                         "preparation": preparation, "offline_validation": offline,
                         "target_paths": target_paths, "target_object_refs": target_refs,
                         "reasons": sorted({row["reason"] for row in related if row.get("reason")}),
                         "validation_issues": chart_issues, "live_validation": "not_performed"})
    counts = {"captured_charts": len(rows), "selected_charts": sum(row["selection"] == "selected" for row in rows),
              "dependency_charts": sum(row["selection"] == "dependency" for row in rows),
              "excluded_charts": sum(row["selection"] == "excluded" for row in rows),
              "compiled_selected_charts": sum(row["selection"] == "selected" and row["preparation"] == "compiled" for row in rows),
              "blocked_selected_charts": sum(row["selection"] == "selected" and row["preparation"] == "blocked" for row in rows)}
    return {"schema_version": "sigma-migration-report.v1", "route": state.get("route"),
            "synthetic": bool(state.get("synthetic", snapshot.get("synthetic", False))),
            "scope": deepcopy(scope), "counts": counts, "charts": rows,
            "assembly_intent": scope["assembly_intent"] if scope else "captured_workbook_preparation",
            "package_validation": deepcopy(validation),
            "discrepancies": validation_issues + [issue for issue in scope_issues if issue not in validation_issues],
            "resume": _resume(state, validation, scope),
            "target_write_authority": False, "migration_accepted": False,
            "live_validation": "not_performed", "duration": "not_measured", "cost": "not_measured"}


def report_run(run_dir):
    """Reopen the real session; source drift and stale review remain hard errors."""
    from omni_migrator.prepush.session import Session, read_json

    session = Session(run_dir)
    state = session.state()
    snapshot = session.load(state["source_sha256"])
    proposal, validation = None, None
    if state.get("package") and not state.get("revoked"):
        path, validation = session.validate_package()
        proposal = read_json(path / "manifest.json")["build"]
    elif state.get("route") and not state.get("revoked"):
        proposal = session.proposal()
    return migration_report(snapshot, proposal, validation, state)

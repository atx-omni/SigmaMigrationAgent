"""Actual translator preflight; local synthetic checks never establish migration acceptance.

The SQLite adapter consumes existing translator output only. It neither parses Sigma
formulas nor supplies replacements for unsupported calculations. Discovered unsafe
outcomes fail tests normally (no xfail or converted expected-pass migration result).
"""

from __future__ import annotations

from collections import Counter
import hashlib
import json
from pathlib import Path
import sqlite3

import pytest

import omni_migrator
from omni_migrator.deterministic import sigma_translate
from omni_migrator.extractors.sigma import extractor


ROOT = Path(__file__).resolve().parents[1]
ENGINE_ROOT = ROOT.parents[1] / "packages/omnikit-migration-engine/src"
CASES_PATH = ROOT / "artifacts/formula-cases.json"
FIXTURE = json.loads(CASES_PATH.read_text())
for imported in (omni_migrator, sigma_translate, extractor):
    assert Path(imported.__file__).resolve().is_relative_to(ENGINE_ROOT.resolve()), (
        "Preflight must import only the separate Sigma repository engine"
    )


def _evaluate_translated_tuple(sql, aggregate, filters):
    """Execute a narrow aggregate/filter result under declared SQLite fixture semantics."""
    names = set(FIXTURE["columns"])
    references = {sql} if sql is not None else set()
    references.update(filters or {})
    if not references <= names:
        return {"status": "unbound_reference", "missing_fields": sorted(references - names)}
    functions = {"sum": "SUM", "average": "AVG", "count": "COUNT", "min": "MIN", "max": "MAX"}
    if aggregate not in {*functions, "count_distinct"}:
        return {"status": "not_locally_evaluated", "reason": "outside stdlib SQLite subset"}
    operand = "*" if sql is None else f'"{sql}"'
    expression = f"COUNT(DISTINCT {operand})" if aggregate == "count_distinct" else f"{functions[aggregate]}({operand})"
    clauses, values = [], []
    for column, condition in (filters or {}).items():
        assert len(condition) == 1
        operation, value = next(iter(condition.items()))
        assert operation in {"is", "is_not"}
        clauses.append(f'"{column}" {"=" if operation == "is" else "<>"} ?')
        values.append(value)
    query = f"SELECT {expression} FROM fictional_orders"
    if clauses:
        query += " WHERE " + " AND ".join(clauses)
    with sqlite3.connect(":memory:") as database:
        database.execute("CREATE TABLE fictional_orders (row_id INTEGER, amount REAL, quantity REAL, status TEXT, region TEXT, denominator REAL)")
        database.executemany("INSERT INTO fictional_orders VALUES (?, ?, ?, ?, ?, ?)", FIXTURE["rows"])
        actual = database.execute(query, values).fetchone()[0]
    return {"status": "evaluated", "sqlite_query": query, "parameters": values, "actual_result": actual}


def _formula_result(case):
    sql, aggregate, filters, reason = sigma_translate.translate_formula(case["formula"], home_table="Fictional Orders")
    result = {
        "id": case["id"], "category": case["category"], "formula": case["formula"],
        "expected_disposition": case["expected_disposition"], "expected_result": case["expected_result"],
        "translator": {"sql": sql, "aggregate": aggregate, "filters": filters, "reason": reason},
    }
    if reason:
        result["classification"] = "explicit_unsupported" if sql is None and aggregate is None and filters is None else "unsafe_partial_translation"
        result["expectation_met"] = case["expected_disposition"] == "explicit_unsupported" and result["classification"] == "explicit_unsupported"
        return result
    evaluation = _evaluate_translated_tuple(sql, aggregate, filters)
    result["local_evaluation"] = evaluation
    tuple_matches = all(result["translator"][key] == case.get(f"expected_{key}") for key in ("sql", "aggregate", "filters"))
    if evaluation["status"] == "unbound_reference":
        # The parser is schema-free. The source-aware extractor must block the same
        # unsafe input rather than teaching the parser our fixture's missing name.
        context_blocked = _extractor_results()["outcomes"]["missing_metric_explicit_review"]
        result.update(classification="source_bound_rejection" if context_blocked else "silent_unbound_reference",
                      expectation_met=context_blocked and case["formula"] == "Sum([Never Captured])")
    elif evaluation["status"] == "not_locally_evaluated":
        result.update(classification="translated_not_locally_evaluated", expectation_met=tuple_matches and case["expected_disposition"] == "translated_without_local_evaluation")
    else:
        correct = tuple_matches and evaluation["actual_result"] == case["expected_result"]
        result.update(classification="locally_verified_synthetic_result" if correct else "incorrect_local_result", expectation_met=correct and case["expected_disposition"] == "translated")
    return result


def _extractor_results():
    snapshot = {
        "connections": [{"connectionId": "fictional-connection", "type": "bigQuery"}],
        "dataModels": [{"dataModelId": "fictional-model", "spec": {
            "dataModelId": "fictional-model", "documentVersion": 1,
            "pages": [{"elements": [{
                "id": "fictional-orders", "kind": "table", "name": "Fictional Orders",
                "source": {"connectionId": "fictional-connection", "kind": "warehouse-table", "path": ["fictional", "shop", "orders"]},
                "columns": FIXTURE["extractor_columns"], "metrics": FIXTURE["extractor_metrics"],
            }]}],
        }}],
    }
    bundle = extractor._build_bundle(snapshot)
    view, = bundle.model.views
    fields = {field.source_id: field for field in view.fields}
    notes = [note.model_dump(mode="json") for note in view.untranslatable]
    hints = {note["hint"] for note in notes}
    requirements = [requirement.model_dump(mode="json") for requirement in bundle.model.requirements]
    outcomes = {
        "self_passthrough_preserved": "fictional-amount" in fields and fields["fictional-amount"].kind == "dimension" and fields["fictional-amount"].sql == "amount",
        "row_formula_explicit_review": "fictional-row-product" not in fields and "[Amount] * [Quantity]" in hints and any(item["config"].get("formula") == "[Amount] * [Quantity]" for item in requirements),
        "unknown_metric_explicit_review": "fictional-unknown" not in fields and "WarpDrive([Amount])" in hints,
        "hidden_aggregate_preserved": "fictional-hidden-total" in fields and fields["fictional-hidden-total"].hidden is True,
        "missing_metric_explicit_review": "fictional-missing" not in fields and "Sum([Never Captured])" in hints,
    }
    return {
        "outcomes": outcomes, "expected": FIXTURE["extractor_expectations"],
        "fields": [field.model_dump(mode="json") for field in fields.values()],
        "untranslatable_notes": notes, "requirements": requirements,
        "failed_expectations": [key for key, expected in FIXTURE["extractor_expectations"].items() if outcomes[key] != expected],
    }


@pytest.fixture(scope="session")
def report():
    formulas = [_formula_result(case) for case in FIXTURE["formula_cases"]]
    boundaries = _extractor_results()
    result = {
        "schema_version": "synthetic-sigma-formula-preflight-result.v1",
        "overall_status": "blocked_pre_omni_push",
        "synthetic_only": True, "live_sigma_evaluated": False, "live_omni_evaluated": False,
        "target_write_authority": False, "migration_accepted": False,
        "engine_import_root": str(ENGINE_ROOT),
        "source_fingerprints": {
            str(Path(module.__file__).relative_to(ENGINE_ROOT)): hashlib.sha256(Path(module.__file__).read_bytes()).hexdigest()
            for module in (sigma_translate, extractor)
        },
        "fixture_sha256": hashlib.sha256(CASES_PATH.read_bytes()).hexdigest(),
        "expected_result_basis": FIXTURE["expected_result_basis"],
        "classification_counts": dict(Counter(item["classification"] for item in formulas)),
        "formula_cases": formulas, "extractor_boundary_checks": boundaries,
        "unsafe_formula_cases": [item["id"] for item in formulas if not item["expectation_met"]],
        "remaining_acceptance_requirements": [
            "Resolve failed preflight expectations before treating output as target-ready.",
            "Unsupported row, window, null, division and unknown functions require explicit reviewed handling.",
            "Translated median lacks local execution evidence.",
            "SQLite checks do not certify Sigma or Omni aggregate/filter/null behavior.",
            "No source/target query parity, customer acceptance, or target write was performed.",
        ],
    }
    return result


@pytest.mark.parametrize("case_id", [case["id"] for case in FIXTURE["formula_cases"]])
def test_actual_formula_translation(case_id, report):
    result = next(item for item in report["formula_cases"] if item["id"] == case_id)
    assert result["expectation_met"], json.dumps(result, indent=2)


@pytest.mark.parametrize("boundary", list(FIXTURE["extractor_expectations"]))
def test_actual_extractor_preserves_or_explicitly_flags_boundary(boundary, report):
    result = report["extractor_boundary_checks"]
    assert result["outcomes"][boundary] == result["expected"][boundary], (
        f"Unsafe extractor boundary: {boundary}. See artifacts/formula-results.json."
    )

"""Deterministic Sigma formula -> Omni measure mapping. No live instance to verify wire shapes
against (plan §6.4) — these lock in behavior against the worked examples Sigma's own public docs
give (`SumIf`, `Lookup`) plus the documented function-index vocabulary."""

from __future__ import annotations

from omni_migrator.deterministic.sigma_translate import (
    parse_ref,
    translate_condition,
    translate_formula,
)


def test_parse_ref_same_table():
    assert parse_ref("[Sales]") == (None, "Sales")


def test_parse_ref_cross_table():
    assert parse_ref("[Sales Amounts/Sales Amount]") == ("Sales Amounts", "Sales Amount")


def test_parse_ref_rejects_non_ref_text():
    assert parse_ref("Sum([Sales])") is None
    assert parse_ref("([Sales])") is None


def test_parse_ref_rejects_ambiguous_multi_table_path():
    assert parse_ref("[Orders/Customers/Name]") is None


def test_plain_sum_wrapper():
    sql, agg, filters, reason = translate_formula("Sum([Sale Price])", home_table="order_items")
    assert (sql, agg, filters, reason) == ("sale_price", "sum", None, None)


def test_bare_count_no_args():
    assert translate_formula("Count()") == (None, "count", None, None)


def test_count_distinct():
    sql, agg, filters, reason = translate_formula("CountDistinct([User Id])")
    assert (sql, agg) == ("user_id", "count_distinct")


def test_sum_if_doc_example_with_or_is_untranslatable():
    """The exact worked example from `help.sigmacomputing.com/reference/sumif` — OR conditions
    have no deterministic Omni measure-filter equivalent, same posture as MBQL's `translate_measure_filter`."""
    sql, agg, filters, reason = translate_formula(
        'SumIf([Sales], [Store State] = "Michigan" or [Store State] = "California")'
    )
    assert sql is None and agg is None and filters is None
    assert "OR" in reason


def test_sum_if_and_condition_resolves_to_filters_dict():
    sql, agg, filters, reason = translate_formula(
        'SumIf([Sale Price], [Status] = "Complete" and [Region] = "West")',
        home_table="order_items",
    )
    assert reason is None
    assert (sql, agg) == ("sale_price", "sum")
    assert filters == {"status": {"is": "Complete"}, "region": {"is": "West"}}


def test_count_if_condition_only_arity():
    sql, agg, filters, reason = translate_formula('CountIf([Status] = "Complete")')
    assert reason is None
    assert (sql, agg, filters) == (None, "count", {"status": {"is": "Complete"}})


def test_count_if_multiple_conditions_uses_implicit_and():
    sql, agg, filters, reason = translate_formula(
        'CountIf([Status] = "Complete", [Region] = "West")'
    )
    assert reason is None
    assert (sql, agg, filters) == (
        None,
        "count",
        {"status": {"is": "Complete"}, "region": {"is": "West"}},
    )


def test_count_if_value_plus_condition_shape_fails_closed():
    sql, agg, filters, reason = translate_formula('CountIf([Order Id], [Status] = "Complete")')
    assert (sql, agg, filters) == (None, None, None)
    assert reason is not None and "condition" in reason.lower()


def test_avg_if_not_equals():
    sql, agg, filters, reason = translate_formula('AvgIf([Sale Price], [Status] != "Cancelled")')
    assert reason is None
    assert filters == {"status": {"is_not": "Cancelled"}}


def test_lookup_doc_example_is_untranslatable():
    """The exact worked example from `help.sigmacomputing.com/reference/lookup`."""
    _, _, _, reason = translate_formula(
        "Lookup(Sum([Sales Amounts/Sales Amount]), [Order Number], [Sales Amounts/Order Number])"
    )
    assert reason is not None and "Lookup" in reason


def test_window_family_is_untranslatable():
    _, _, _, reason = translate_formula("WindowSum([Sales])")
    assert reason is not None and "Window" in reason


def test_cross_table_reference_needs_ai():
    _, _, _, reason = translate_formula(
        "Sum([Sales Amounts/Sales Amount])", home_table="order_items"
    )
    assert reason is not None and "another table" in reason


def test_table_qualified_reference_without_home_table_is_ambiguous():
    _, _, _, reason = translate_formula("Sum([Sales Amounts/Sales Amount])")
    assert reason is not None and "another table" in reason


def test_table_qualified_reference_matching_home_table_translates():
    result = translate_formula("Sum([Order Items/Sale Price])", home_table="order_items")
    assert result == ("sale_price", "sum", None, None)


def test_nested_or_in_condition_is_untranslatable():
    filters, reason = translate_condition('[A] = "x" or [B] = "y"')
    assert filters is None and "OR" in reason


def test_not_condition_is_untranslatable():
    filters, reason = translate_condition('not ([Status] = "Cancelled")')
    assert filters is None and "NOT" in reason


def test_duplicate_field_condition_needs_ai():
    filters, reason = translate_condition('[Status] = "A" and [Status] = "B"')
    assert filters is None and "Multiple conditions" in reason


def test_grouped_and_condition_preserves_typed_literals():
    filters, reason = translate_condition(
        '([Status] = "Ready and Complete") and '
        "(([Active] = true) and ([Retries] != -2) and ([Ratio] = 1.5))"
    )
    assert reason is None
    assert filters == {
        "status": {"is": "Ready and Complete"},
        "active": {"is": True},
        "retries": {"is_not": -2},
        "ratio": {"is": 1.5},
    }


def test_operator_word_inside_literal_is_not_boolean_syntax():
    sql, agg, filters, reason = translate_formula('CountIf([Disposition] = "Ready or Waiting")')
    assert reason is None
    assert (sql, agg, filters) == (
        None,
        "count",
        {"disposition": {"is": "Ready or Waiting"}},
    )


def test_non_equality_comparison_remains_untranslatable():
    filters, reason = translate_condition("[Sales] >= 100")
    assert filters is None and "simple equals/not-equals" in reason


def test_column_to_column_comparison_remains_untranslatable():
    filters, reason = translate_condition("[Booked] = [Target]")
    assert filters is None and "scalar literal" in reason


def test_nested_call_is_parsed_but_not_guessed_as_an_aggregate_argument():
    sql, agg, filters, reason = translate_formula("Sum(Coalesce([Sales], 0))")
    assert sql is None and agg is None and filters is None
    assert reason is not None and "single column reference" in reason


def test_nested_window_call_remains_untranslatable():
    sql, agg, filters, reason = translate_formula("Sum(WindowSum([Sales]))")
    assert sql is None and agg is None and filters is None
    assert reason is not None and "Window" in reason


def test_malformed_nested_formula_returns_reason_instead_of_raising():
    sql, agg, filters, reason = translate_formula('SumIf([Sales], ([Status] = "Complete")')
    assert sql is None and agg is None and filters is None
    assert reason is not None and "Could not parse" in reason


def test_unrecognized_formula_is_untranslatable():
    _, _, _, reason = translate_formula('[First Name] + " " + [Last Name]')
    assert reason is not None


def test_empty_formula_is_untranslatable():
    assert translate_formula("")[3] is not None
    assert translate_formula(None)[3] is not None

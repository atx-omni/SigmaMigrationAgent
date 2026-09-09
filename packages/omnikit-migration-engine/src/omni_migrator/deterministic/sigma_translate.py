"""Deterministic Sigma formula -> Omni measure/dimension mapping (Appendix A.7-style, §6.4).

Same scoping discipline as `dax_translate.py`/`mbql_translate.py`: translate only the clean,
unambiguous shapes; everything else (Lookup, Window* functions, OR conditions, multi-table
expressions) is flagged `untranslatable` with the raw formula as the AI hint, never guessed.

Sigma formulas use bracket-notation column refs -- `[Column Name]` for the same table and
`[Table Name/Column Name]` cross-table (plan §6.4). `SumIf` and `AvgIf` use a value plus
condition, while `CountIf` accepts one or more conditions. Those shapes become the same Omni
measure `filters:` wire shape `mbql_translate.translate_measure_filter` already produces
(`{field: {is: value}}` -- the one shape verified against real Omni YAML, Appendix A.11).

The parser below intentionally covers more syntax than the deterministic translator emits. It
builds a small AST for references, nested calls, literals, comparisons, and boolean operators so
unsupported formulas are rejected based on structure rather than regex/string splitting.

**Not verified against a live Sigma instance** -- built from `help.sigmacomputing.com`'s public
docs (function index plus worked `SumIf`, `CountIf`, and `Lookup` examples) only, since no live
access exists yet (plan §6.4). Treat with the same skepticism as Tableau's dashboard translator
until spot-checked live.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass
from typing import TypeAlias


def _snake(text: str) -> str:
    s = re.sub(r"[^0-9a-zA-Z]+", "_", (text or "").strip()).strip("_").lower()
    if s and s[0].isdigit():
        s = f"f_{s}"
    return s or "field"


@dataclass(frozen=True)
class _Reference:
    table: str | None
    column: str


@dataclass(frozen=True)
class _Literal:
    value: object


@dataclass(frozen=True)
class _Call:
    name: str
    args: tuple[_Expression, ...]


@dataclass(frozen=True)
class _Comparison:
    left: _Expression
    operator: str
    right: _Expression


@dataclass(frozen=True)
class _BooleanOp:
    operator: str
    operands: tuple[_Expression, ...]


@dataclass(frozen=True)
class _UnaryOp:
    operator: str
    operand: _Expression


_Expression: TypeAlias = _Reference | _Literal | _Call | _Comparison | _BooleanOp | _UnaryOp


class _ParseError(ValueError):
    pass


_NUMBER = re.compile(r"[+-]?(?:(?:\d+(?:\.\d*)?)|(?:\.\d+))(?:[eE][+-]?\d+)?")
_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_COMPARISON_OPERATORS = ("!=", "<>", ">=", "<=", "=", ">", "<")


class _FormulaParser:
    """Small recursive-descent parser for the Sigma subset needed by deterministic metrics."""

    def __init__(self, text: str):
        self.text = text
        self.pos = 0

    def parse(self) -> _Expression:
        expression = self._parse_or()
        self._skip_whitespace()
        if self.pos != len(self.text):
            raise _ParseError(f"Unexpected token at position {self.pos}")
        return expression

    def _parse_or(self) -> _Expression:
        operands = [self._parse_and()]
        while self._consume_keyword("or"):
            operands.append(self._parse_and())
        if len(operands) == 1:
            return operands[0]
        return _BooleanOp("or", tuple(operands))

    def _parse_and(self) -> _Expression:
        operands = [self._parse_not()]
        while self._consume_keyword("and"):
            operands.append(self._parse_not())
        if len(operands) == 1:
            return operands[0]
        return _BooleanOp("and", tuple(operands))

    def _parse_not(self) -> _Expression:
        if self._consume_keyword("not"):
            return _UnaryOp("not", self._parse_not())
        return self._parse_comparison()

    def _parse_comparison(self) -> _Expression:
        left = self._parse_primary()
        operator = self._consume_comparison_operator()
        if operator is None:
            return left
        return _Comparison(left, operator, self._parse_primary())

    def _parse_primary(self) -> _Expression:
        self._skip_whitespace()
        if self.pos >= len(self.text):
            raise _ParseError("Expected an expression")

        char = self.text[self.pos]
        if char == "(":
            self.pos += 1
            expression = self._parse_or()
            self._expect(")")
            return expression
        if char == "[":
            return self._parse_reference()
        if char == '"':
            return self._parse_string()

        number = _NUMBER.match(self.text, self.pos)
        if number:
            self.pos = number.end()
            raw = number.group(0)
            value = float(raw) if any(marker in raw.lower() for marker in (".", "e")) else int(raw)
            return _Literal(value)

        identifier = _IDENTIFIER.match(self.text, self.pos)
        if not identifier:
            raise _ParseError(f"Expected a reference, call, or literal at position {self.pos}")
        self.pos = identifier.end()
        name = identifier.group(0)
        self._skip_whitespace()
        if self._consume("("):
            return self._parse_call(name)

        keyword = name.casefold()
        if keyword == "true":
            return _Literal(True)
        if keyword == "false":
            return _Literal(False)
        if keyword in ("null", "blank"):
            return _Literal(None)
        if keyword in ("and", "or", "not"):
            raise _ParseError(f"Unexpected boolean operator {name!r}")
        return _Literal(name)

    def _parse_call(self, name: str) -> _Call:
        args: list[_Expression] = []
        self._skip_whitespace()
        if self._consume(")"):
            return _Call(name, ())
        while True:
            args.append(self._parse_or())
            self._skip_whitespace()
            if self._consume(","):
                continue
            self._expect(")")
            return _Call(name, tuple(args))

    def _parse_reference(self) -> _Reference:
        start = self.pos
        end = self.text.find("]", start + 1)
        if end < 0:
            raise _ParseError(f"Unterminated bracket reference at position {start}")
        content = self.text[start + 1 : end]
        self.pos = end + 1
        if "[" in content:
            raise _ParseError(f"Nested '[' in bracket reference at position {start}")
        parts = content.split("/")
        if len(parts) == 1:
            table, column = None, parts[0].strip()
        elif len(parts) == 2:
            table, column = parts[0].strip(), parts[1].strip()
        else:
            raise _ParseError(f"Ambiguous bracket reference at position {start}")
        if not column or (table is not None and not table):
            raise _ParseError(f"Empty table or column in bracket reference at position {start}")
        return _Reference(table, column)

    def _parse_string(self) -> _Literal:
        start = self.pos
        self.pos += 1
        value: list[str] = []
        escapes = {'"': '"', "\\": "\\", "n": "\n", "r": "\r", "t": "\t"}
        while self.pos < len(self.text):
            char = self.text[self.pos]
            if char == "\\":
                self.pos += 1
                if self.pos >= len(self.text) or self.text[self.pos] not in escapes:
                    raise _ParseError(f"Unsupported string escape at position {self.pos}")
                value.append(escapes[self.text[self.pos]])
                self.pos += 1
                continue
            if char == '"':
                if self.pos + 1 < len(self.text) and self.text[self.pos + 1] == '"':
                    value.append('"')
                    self.pos += 2
                    continue
                self.pos += 1
                return _Literal("".join(value))
            value.append(char)
            self.pos += 1
        raise _ParseError(f"Unterminated string literal at position {start}")

    def _consume_keyword(self, keyword: str) -> bool:
        self._skip_whitespace()
        end = self.pos + len(keyword)
        if self.text[self.pos : end].casefold() != keyword:
            return False
        if end < len(self.text) and (self.text[end].isalnum() or self.text[end] == "_"):
            return False
        self.pos = end
        return True

    def _consume_comparison_operator(self) -> str | None:
        self._skip_whitespace()
        for operator in _COMPARISON_OPERATORS:
            if self.text.startswith(operator, self.pos):
                self.pos += len(operator)
                return operator
        return None

    def _consume(self, expected: str) -> bool:
        if self.text.startswith(expected, self.pos):
            self.pos += len(expected)
            return True
        return False

    def _expect(self, expected: str) -> None:
        self._skip_whitespace()
        if not self._consume(expected):
            raise _ParseError(f"Expected {expected!r} at position {self.pos}")

    def _skip_whitespace(self) -> None:
        while self.pos < len(self.text) and self.text[self.pos].isspace():
            self.pos += 1


def _parse_expression(text: str) -> _Expression:
    return _FormulaParser(text).parse()


def parse_ref(text: str) -> tuple[str | None, str] | None:
    """A bracket ref spanning the *whole* string -> `(table_or_None, column)`, else `None`."""
    try:
        raw = text.strip()
    except AttributeError:
        return None
    if not raw.startswith("[") or not raw.endswith("]"):
        return None
    try:
        expression = _parse_expression(raw)
    except _ParseError:
        return None
    if not isinstance(expression, _Reference):
        return None
    return expression.table, expression.column


_AGG_MAP = {
    "sum": "sum",
    "average": "average",
    "avg": "average",
    "count": "count",
    "countdistinct": "count_distinct",
    "min": "min",
    "max": "max",
    "median": "median",
}
_IF_AGG_MAP = {"sumif": "sum", "countif": "count", "avgif": "average", "averageif": "average"}


@dataclass(frozen=True)
class _AggregateSemantics:
    aggregate: str
    value: _Reference | None
    condition: _Expression | None
    row_count: bool
    source_name: str


def _walk(expression: _Expression) -> Iterator[_Expression]:
    yield expression
    if isinstance(expression, _Call):
        for arg in expression.args:
            yield from _walk(arg)
    elif isinstance(expression, _Comparison):
        yield from _walk(expression.left)
        yield from _walk(expression.right)
    elif isinstance(expression, _BooleanOp):
        for operand in expression.operands:
            yield from _walk(operand)
    elif isinstance(expression, _UnaryOp):
        yield from _walk(expression.operand)


def _unsupported_call(expression: _Expression) -> str | None:
    for node in _walk(expression):
        if isinstance(node, _Call):
            name = node.name.casefold()
            if name == "lookup" or name.startswith("window"):
                return node.name
    return None


def _contains_boolean(expression: _Expression, operator: str) -> bool:
    return any(
        isinstance(node, _BooleanOp) and node.operator == operator for node in _walk(expression)
    )


def _and_operands(expression: _Expression) -> list[_Expression]:
    if isinstance(expression, _BooleanOp) and expression.operator == "and":
        operands: list[_Expression] = []
        for child in expression.operands:
            operands.extend(_and_operands(child))
        return operands
    return [expression]


def _resolve_reference(
    reference: _Reference, home_table: str | None
) -> tuple[str | None, str | None]:
    table = _snake(reference.table) if reference.table else None
    if table and (home_table is None or table != _snake(home_table)):
        return None, table
    return _snake(reference.column), None


def _reference_text(reference: _Reference) -> str:
    prefix = f"{reference.table}/" if reference.table else ""
    return f"[{prefix}{reference.column}]"


def _translate_condition_ast(
    expression: _Expression, raw: str, home_table: str | None
) -> tuple[dict[str, dict] | None, str | None]:
    unsupported = _unsupported_call(expression)
    if unsupported:
        return None, (
            f"No deterministic Omni equivalent for function {unsupported!r} in condition "
            f"{raw!r}; needs AI translation."
        )
    if _contains_boolean(expression, "or"):
        return None, (
            f"OR conditions have no deterministic Omni measure-filter equivalent: {raw!r}; "
            "needs AI translation."
        )
    if any(isinstance(node, _UnaryOp) for node in _walk(expression)):
        return (
            None,
            f"NOT conditions have no deterministic Omni measure-filter equivalent: {raw!r}; needs AI translation.",
        )

    out: dict[str, dict] = {}
    for condition in _and_operands(expression):
        if not isinstance(condition, _Comparison) or condition.operator not in ("=", "!=", "<>"):
            return None, (
                f"Condition is not a simple equals/not-equals: {raw!r}; needs AI translation."
            )
        if not isinstance(condition.left, _Reference):
            return None, (
                f"Left-hand side is not a single column reference: {raw!r}; needs AI translation."
            )
        if not isinstance(condition.right, _Literal) or condition.right.value is None:
            return None, (
                f"Right-hand side is not a supported scalar literal: {raw!r}; needs AI translation."
            )

        column, other_table = _resolve_reference(condition.left, home_table)
        if other_table:
            ref = _reference_text(condition.left)
            return None, f"Cross-table condition ({ref}); needs AI translation."
        if column in out:
            return None, f"Multiple conditions on the same field {column!r}; needs AI translation."
        key = "is" if condition.operator == "=" else "is_not"
        out[column] = {key: condition.right.value}
    return out, None


def translate_condition(
    expr: str, home_table: str | None = None
) -> tuple[dict[str, dict] | None, str | None]:
    """A Sigma boolean condition -> Omni's verified `filters:` equals/not-equals dict.

    Distinct-field comparisons may be ANDed and grouped. OR, NOT, range comparisons, calculated
    operands, null checks, and cross-table references remain deliberately unsupported.
    """
    raw = (expr or "").strip()
    if not raw:
        return None, "Empty condition; needs AI translation."
    try:
        expression = _parse_expression(raw)
    except _ParseError as error:
        return None, f"Could not parse Sigma condition {raw!r}: {error}; needs AI translation."
    return _translate_condition_ast(expression, raw, home_table)


def _classify_aggregate(
    expression: _Expression, raw: str
) -> tuple[_AggregateSemantics | None, str | None]:
    if not isinstance(expression, _Call):
        return None, f"Not a recognized clean aggregate wrapper: {raw!r}; needs AI translation."

    name = expression.name.casefold()
    if name in _AGG_MAP:
        if name == "count" and not expression.args:
            return _AggregateSemantics("count", None, None, True, expression.name), None
        if len(expression.args) != 1 or not isinstance(expression.args[0], _Reference):
            return None, (
                f"Argument is not a single column reference: {raw!r}; needs AI translation."
            )
        return _AggregateSemantics(
            _AGG_MAP[name], expression.args[0], None, False, expression.name
        ), None

    if name not in _IF_AGG_MAP:
        return None, f"Not a recognized clean aggregate wrapper: {raw!r}; needs AI translation."

    if name == "countif":
        if not expression.args:
            return None, f"Unexpected CountIf argument count: {raw!r}; needs AI translation."
        condition = (
            expression.args[0]
            if len(expression.args) == 1
            else _BooleanOp("and", expression.args)
        )
        return _AggregateSemantics("count", None, condition, True, expression.name), None

    if len(expression.args) != 2:
        return None, (
            f"Unexpected {expression.name} argument count: {raw!r}; needs AI translation."
        )
    value, condition = expression.args
    if not isinstance(value, _Reference):
        return None, (
            f"{expression.name}'s value argument is not a single column reference: {raw!r}; "
            "needs AI translation."
        )
    return _AggregateSemantics(_IF_AGG_MAP[name], value, condition, False, expression.name), None


def translate_formula(
    formula: str, home_table: str | None = None
) -> tuple[str | None, str | None, dict[str, dict] | None, str | None]:
    """Try to deterministically translate a Sigma measure formula.

    Returns `(sql, aggregate, filters, reason)` -- exactly one of `(sql?, aggregate, filters?)`
    or `reason` is meaningfully set. `sql` is `None` for row-counting aggregates (bare `Count()`
    or a condition-only `CountIf(...)`), matching Omni's count-of-rows convention.
    """
    raw = (formula or "").strip()
    if not raw:
        return None, None, None, "Empty formula."
    try:
        expression = _parse_expression(raw)
    except _ParseError as error:
        return (
            None,
            None,
            None,
            (f"Could not parse Sigma formula {raw!r}: {error}; needs AI translation."),
        )

    unsupported = _unsupported_call(expression)
    if unsupported:
        return (
            None,
            None,
            None,
            (f"No deterministic Omni equivalent for this function: {raw!r}; needs AI translation."),
        )

    semantics, reason = _classify_aggregate(expression, raw)
    if reason:
        return None, None, None, reason
    assert semantics is not None

    column = None
    if semantics.value is not None:
        column, other_table = _resolve_reference(semantics.value, home_table)
        if other_table:
            if semantics.condition is not None:
                reason = (
                    f"{semantics.source_name} references another table ({other_table}); "
                    "needs AI translation."
                )
            else:
                reason = f"References another table ({other_table}); needs AI translation."
            return None, None, None, reason

    filters = None
    if semantics.condition is not None:
        filters, reason = _translate_condition_ast(semantics.condition, raw, home_table)
        if reason:
            return None, None, None, reason

    sql = None if semantics.row_count else column
    return sql, semantics.aggregate, filters, None

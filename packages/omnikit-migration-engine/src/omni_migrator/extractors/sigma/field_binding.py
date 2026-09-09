"""Source-context validation for the existing, intentionally small Sigma formula grammar.

This layer binds identifiers before translation. It does not extend the schema-free translator
or infer joins, warehouse columns, aggregate-of-aggregate behavior, or new formula semantics.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from omni_migrator.deterministic import sigma_translate as syntax


@dataclass(frozen=True)
class CapturedField:
    key: str
    element_id: str | None
    view_name: str
    source_id: str | None
    field_name: str
    sql_name: str
    row: dict
    element: dict
    is_metric: bool = False
    representation: str = "column"


@dataclass(frozen=True)
class BindingIssue:
    reference: str
    reason: str


@dataclass
class BoundField:
    kind: str | None = None
    sql: str | None = None
    aggregate: str | None = None
    filters: dict | None = None
    issues: list[BindingIssue] = field(default_factory=list)
    dependencies: list[str] = field(default_factory=list)


def _aliases(row: dict) -> set[str]:
    """Only captured names/labels and explicitly supplied aliases, never guessed snake names."""
    values = [row.get("name"), row.get("label"), row.get("alias")]
    aliases = row.get("aliases")
    if isinstance(aliases, list):
        values.extend(aliases)
    return {value.strip().casefold() for value in values if isinstance(value, str) and value.strip()}


def _source_table(element: dict) -> str | None:
    source = element.get("source") or {}
    path = source.get("path") or source.get("sourcePath")
    if isinstance(path, list) and path:
        return str(path[-1])
    if isinstance(path, str) and path:
        return path.rsplit(".", 1)[-1]
    table = source.get("table") or source.get("tableName")
    return str(table) if table else None


def _reference_text(reference) -> str:
    return f"[{reference.table + '/' if reference.table else ''}{reference.column}]"


class SigmaFieldBinder:
    """Bind one captured model's fields, including nested and standalone metrics.

    IDs are element-scoped. Exact IDs take precedence over case-insensitive source aliases.
    Ambiguity, missing identities, unsupported dependencies and cycles never yield usable SQL.
    """

    def __init__(self, records: list[CapturedField]):
        self.records = {record.key: record for record in records}
        self.results: dict[str, BoundField] = {}
        self.ids: dict[tuple[str, str], set[str]] = {}
        self.aliases: dict[tuple[str, str], set[str]] = {}
        self.qualifiers: dict[str, set[str]] = {}
        for record in records:
            if record.source_id:
                self.ids.setdefault((record.view_name, record.source_id), set()).add(record.key)
            for alias in _aliases(record.row):
                self.aliases.setdefault((record.view_name, alias), set()).add(record.key)
            qualifiers = _aliases(record.element) | {record.view_name.casefold()}
            if record.element_id:
                qualifiers.add(record.element_id.casefold())
            if table := _source_table(record.element):
                qualifiers.add(table.casefold())
            for qualifier in qualifiers:
                self.qualifiers.setdefault(qualifier, set()).add(record.view_name)

    def _resolve(self, owner: CapturedField, reference) -> tuple[str | None, str | None]:
        view_name = owner.view_name
        if reference.table:
            views = self.qualifiers.get(reference.table.casefold(), set())
            if len(views) != 1:
                return None, "Ambiguous table qualifier" if views else "Unknown table qualifier"
            view_name = next(iter(views))
            if view_name != owner.view_name:
                return None, "Cross-table reference requires reviewed join and evaluation context"
        candidates = self.ids.get((view_name, reference.column))
        if not candidates:
            candidates = self.aliases.get((view_name, reference.column.casefold()), set())
        if len(candidates) != 1:
            return None, "Ambiguous captured field reference" if candidates else "Unknown captured field reference"
        return next(iter(candidates)), None

    def _physical_reference(self, owner: CapturedField, expression) -> bool:
        if owner.is_metric or not isinstance(expression, syntax._Reference):
            return False
        # A spec's explicit warehouse-qualified self mapping is authoritative only when its
        # column matches this captured field; arbitrary absent warehouse names are not invented.
        table = _source_table(owner.element)
        return bool(
            table
            and expression.table
            and expression.table.casefold() == table.casefold()
            and syntax._snake(expression.column) == owner.sql_name
        )

    def compile(self, key: str, stack: tuple[str, ...] = ()) -> BoundField:
        if key in self.results:
            return self.results[key]
        if key in stack:
            return BoundField(issues=[BindingIssue(key, "Calculated-field dependency cycle")])
        if len(stack) >= 200:
            return BoundField(issues=[BindingIssue(key, "Calculated-field dependency depth exceeds 200")])
        owner = self.records[key]
        result = BoundField()

        def fail(reference: str, reason: str) -> BoundField:
            result.issues.append(BindingIssue(reference, reason))
            self.results[key] = result
            return result

        if not owner.element_id or not owner.source_id:
            return fail(owner.source_id or key, "Missing stable source element or field identity")
        if len(self.ids.get((owner.view_name, owner.source_id), set())) != 1:
            return fail(owner.source_id, "Duplicate source field identity in one element")
        if "hidden" in owner.row and type(owner.row["hidden"]) is not bool:
            return fail("hidden", "Visibility must be true, false, or absent; no truthiness coercion")
        formula = owner.row.get("formula")
        if formula in (None, "") and not owner.is_metric:
            result.kind, result.sql = "dimension", owner.sql_name
            self.results[key] = result
            return result
        if not isinstance(formula, str) or not formula.strip():
            return fail("formula", "Expected a nonempty formula string")
        try:
            expression = syntax._parse_expression(formula)
        except (syntax._ParseError, RecursionError) as error:
            return fail("formula", f"Unsupported Sigma formula syntax: {error}")
        if self._physical_reference(owner, expression):
            result.kind, result.sql = "dimension", syntax._snake(expression.column)
            self.results[key] = result
            return result

        bound: dict[tuple[str | None, str], CapturedField] = {}
        for reference in syntax._walk(expression):
            if not isinstance(reference, syntax._Reference):
                continue
            text = _reference_text(reference)
            target_key, reason = self._resolve(owner, reference)
            if reason:
                result.issues.append(BindingIssue(text, reason))
                continue
            assert target_key is not None
            target = self.records[target_key]
            if target_key == key and isinstance(expression, syntax._Reference) and not owner.is_metric:
                result.kind, result.sql = "dimension", owner.sql_name
                self.results[key] = result
                return result
            result.dependencies.append(target_key)
            dependency = self.compile(target_key, (*stack, key))
            if dependency.issues:
                result.issues.append(BindingIssue(text, f"Unresolved dependency {target.source_id}: {dependency.issues[0].reason}"))
            elif dependency.kind != "dimension":
                result.issues.append(BindingIssue(text, "Measure dependency needs reviewed aggregate/evaluation context"))
            else:
                bound[(reference.table, reference.column)] = target
        if result.issues:
            self.results[key] = result
            return result

        # Translator normalization deliberately collapses punctuation/underscores. Use private
        # safe symbols, then restore exact identity-derived output names (including suffixes).
        targets = {target.key: target for target in bound.values()}
        symbols = {target_key: f"sigma_bound_{index}" for index, target_key in enumerate(targets)}
        by_symbol = {symbols[target_key]: target for target_key, target in targets.items()}

        def render(node) -> str:
            if isinstance(node, syntax._Reference):
                return f"[{symbols[bound[(node.table, node.column)].key]}]"
            if isinstance(node, syntax._Literal):
                return json.dumps(node.value, ensure_ascii=False)
            if isinstance(node, syntax._Call):
                return f"{node.name}({', '.join(render(arg) for arg in node.args)})"
            if isinstance(node, syntax._Comparison):
                return f"({render(node.left)} {node.operator} {render(node.right)})"
            if isinstance(node, syntax._BooleanOp):
                return "(" + f" {node.operator} ".join(render(item) for item in node.operands) + ")"
            if isinstance(node, syntax._UnaryOp):
                return f"{node.operator} ({render(node.operand)})"
            raise TypeError("Unsupported Sigma expression node")

        if isinstance(expression, syntax._Reference) and not owner.is_metric:
            target = bound[(expression.table, expression.column)]
            result.kind = "dimension"
            result.sql = "${" + target.field_name + "}"
        else:
            sql, aggregate, filters, reason = syntax.translate_formula(render(expression))
            if reason or aggregate is None:
                return fail("formula", reason or "Formula requires an explicit migration decision")
            result.kind, result.aggregate = "measure", aggregate
            if filters:
                result.filters = {by_symbol[name].field_name: value for name, value in filters.items()}
            if sql:
                target = by_symbol[sql]
                dependency = self.results[target.key]
                result.sql = (
                    target.field_name if dependency.sql == target.field_name
                    else "${" + target.field_name + "}"
                )
        self.results[key] = result
        return result

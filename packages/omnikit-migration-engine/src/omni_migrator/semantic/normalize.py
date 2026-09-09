"""Conservative, versioned canonicalization that never executes source code."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Literal

import yaml

from omni_migrator.control_plane.canonical import canonical_json, sha256_json

CANONICALIZER_VERSION = "semantic-lexical-v1"


@dataclass(frozen=True)
class CanonicalizationResult:
    state: Literal["supported", "unknown"]
    version: str
    form: str | None
    content_hash: str | None
    reason: str | None


def _unknown(reason: str) -> CanonicalizationResult:
    return CanonicalizationResult(
        state="unknown",
        version=CANONICALIZER_VERSION,
        form=None,
        content_hash=None,
        reason=reason,
    )


def _supported(form: str) -> CanonicalizationResult:
    return CanonicalizationResult(
        state="supported",
        version=CANONICALIZER_VERSION,
        form=form,
        content_hash=f"sha256:{sha256_json(form)}",
        reason=None,
    )


def _normalize_sqlish(text: str, *, allow_statement: bool) -> CanonicalizationResult:
    if not text.strip():
        return _unknown("empty_definition")
    if "\x00" in text:
        return _unknown("nul_byte")
    if "{{" in text or "{%" in text:
        return _unknown("uncompiled_template_syntax")
    if "--" in text or "/*" in text or "*/" in text:
        return _unknown("comment_or_hint_requires_parser")

    normalized: list[str] = []
    quote: str | None = None
    pending_space = False
    semicolons = 0
    index = 0
    while index < len(text):
        character = text[index]
        if quote is not None:
            normalized.append(character)
            if character == quote:
                if index + 1 < len(text) and text[index + 1] == quote:
                    normalized.append(text[index + 1])
                    index += 1
                else:
                    quote = None
            index += 1
            continue
        if character in {"'", '"', "`"}:
            if pending_space and normalized and normalized[-1] not in "(,.":
                normalized.append(" ")
            pending_space = False
            quote = character
            normalized.append(character)
        elif character.isspace():
            pending_space = True
        elif character == ";":
            semicolons += 1
            pending_space = False
        else:
            if pending_space and normalized and normalized[-1] not in "(,.":
                normalized.append(" ")
            pending_space = False
            if character in ",)" and normalized and normalized[-1] == " ":
                normalized.pop()
            normalized.append(character)
        index += 1
    if quote is not None:
        return _unknown("unterminated_quoted_value")
    if semicolons > (1 if allow_statement else 0):
        return _unknown("multiple_or_statement_terminator_not_allowed")
    form = "".join(normalized).strip()
    if not form:
        return _unknown("empty_definition")
    return _supported(form)


def canonicalize_definition(
    definition: str | dict[str, Any] | list[Any] | None,
    *,
    language: str,
    dialect: str | None = None,
) -> CanonicalizationResult:
    """Return a lexical/structural candidate fingerprint or an explicit unknown.

    The result is suitable for candidate ranking and invalidation.  It is not an
    assertion of SQL semantic equivalence.
    """

    if language in {"sql", "query"}:
        if dialect not in {None, "ansi", "mysql", "redshift", "snowflake"}:
            return _unknown(f"unsupported_sql_dialect:{dialect}")
        if not isinstance(definition, str):
            return _unknown("sql_definition_is_not_text")
        return _normalize_sqlish(definition, allow_statement=True)
    if language == "beast_mode":
        if not isinstance(definition, str):
            return _unknown("beast_mode_definition_is_not_text")
        return _normalize_sqlish(definition, allow_statement=False)
    if language in {"magic_etl", "workflow"}:
        value: Any = definition
        if isinstance(definition, str):
            try:
                value = json.loads(definition)
            except json.JSONDecodeError:
                return _unknown("graph_definition_is_not_valid_json")
        if not isinstance(value, (dict, list)):
            return _unknown("graph_definition_is_not_structured")
        return _supported(canonical_json(value))
    if language == "omni_yaml":
        if not isinstance(definition, str):
            return _unknown("omni_definition_is_not_text")
        try:
            value = yaml.safe_load(definition)
        except yaml.YAMLError:
            return _unknown("omni_definition_is_not_valid_yaml")
        if not isinstance(value, (dict, list)):
            return _unknown("omni_definition_is_not_structured")
        return _supported(canonical_json(value))
    return _unknown(f"unsupported_definition_language:{language}")

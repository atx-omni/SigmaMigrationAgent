"""One offline secret policy for imports, persisted artifacts, and outgoing bytes.

The maintained detect-secrets regex plugins are called through analyze_string,
not analyze_line/scan_file: the latter can invoke network verification and
allowlist filters. There are no environment, pragma, baseline, or caller bypasses.
Findings contain no matched value, input key, filename, source line, or excerpt.
Detection reduces accidental leakage; it does not declassify customer evidence.
"""
from __future__ import annotations

import importlib
import ast
import json
import re
from dataclasses import dataclass
from functools import lru_cache
from importlib.metadata import version
from typing import Any
from urllib.parse import unquote

import yaml

POLICY_VERSION = "sigma-secret-policy.v2"
ENGINE_VERSION = "1.5.0"
MAX_BYTES = 25 * 1024 * 1024
MAX_NODES = 200_000
MAX_DEPTH = 100
MAX_FINDINGS = 100

# Explicit selection is intentional: entropy-only plugins misclassify source IDs,
# checksums and compiled expressions. Credential format and property checks cover
# those surfaces without weakening the preservation of source evidence.
_PLUGINS = (
    ("aws", "AWSKeyDetector"),
    ("basic_auth", "BasicAuthDetector"),
    ("github_token", "GitHubTokenDetector"),
    ("gitlab_token", "GitLabTokenDetector"),
    ("jwt", "JwtTokenDetector"),
    ("private_key", "PrivateKeyDetector"),
    ("slack", "SlackDetector"),
    ("stripe", "StripeDetector"),
    ("sendgrid", "SendGridDetector"),
    ("twilio", "TwilioKeyDetector"),
)
# One alias vocabulary drives structured properties, free-text assignments and
# URL query parameters. Preserve v1's contained-name matches (including backup
# and value suffixes); generic words remain exact keys so authorization metadata
# or ordinary tokenizer/credential-description fields are not misclassified.
_CONTAINED_ALIASES = (
    ("password",), ("passwd",),
    ("api", "token"), ("api", "key"),
    ("access", "token"), ("refresh", "token"), ("id", "token"),
    ("session", "token"),
    ("client", "secret"), ("private", "key"), ("secret", "key"),
    ("connection", "string"),
)
_EXACT_ALIASES = (
    ("token",), ("secret",), ("cookie",), ("authorization",),
    ("credential",), ("credentials",),
)
_CREDENTIAL_ALIASES = _CONTAINED_ALIASES + _EXACT_ALIASES
_NORMALIZED_CONTAINED = frozenset("".join(parts) for parts in _CONTAINED_ALIASES)
_NORMALIZED_EXACT = frozenset("".join(parts) for parts in _EXACT_ALIASES)
_ALIAS_PATTERN = "(?:" + "|".join(
    r"[_. -]*".join(parts) for parts in _CREDENTIAL_ALIASES
) + ")"
_ASSIGNMENT_PREFIX = (
    r'''(?i)(?<![^\s"'])(?:["']?)(?P<key>(?:[A-Za-z][A-Za-z0-9_.-]{0,96}?)?'''
    + _ALIAS_PATTERN
    + r'''[A-Za-z0-9_.-]{0,96})["']?\s*[:=]\s*'''
)
_ASSIGNMENT = re.compile(
    _ASSIGNMENT_PREFIX + r'''(?:["'](?P<quoted>[^"'\r\n]+)["']|'''
    r'''(?P<reference>\$\{[A-Z_][A-Z0-9_]*\})(?=$|\s|[,;])|(?P<bare>[^\s,;<>\[\]\{\}]+))'''
)
_CONTAINER_ASSIGNMENT = re.compile(_ASSIGNMENT_PREFIX + r"(?P<container>[\[{])")
_BEARER = re.compile(r"\b(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{4,}", re.I)
_OPENAI = re.compile(r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{24,}")
# The pinned engine predates GitHub fine-grained personal access token coverage.
_GITHUB_FINE_GRAINED = re.compile(r"\bgithub_pat_[A-Za-z0-9_]{30,}")
_URL_AUTH = re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s/@:]+:[^\s/@]+@", re.I)
_URL_QUERY = re.compile(
    r'''[?&](?P<key>[A-Za-z0-9_.%+~-]{1,256})=(?P<value>[^\s&#"'<>]*)'''
)
# Public digital-signature metadata is not a secret property; signed URL
# parameters, by contrast, can themselves authorize access to customer data.
_SIGNED_URL_KEYS = frozenset({"sig", "signature", "xamzsignature", "xgoogsignature"})
_SAFE_LITERAL = frozenset({"", "[REDACTED]", "<REDACTED>", "null", "None", "false", "False"})
_ENV_REFERENCE = re.compile(r"\$(?:[A-Z_][A-Z0-9_]*|\{[A-Z_][A-Z0-9_]*\})\Z")
_ASCII_ESCAPE = re.compile(r"\\(?:u([0-9a-fA-F]{4})|x([0-9a-fA-F]{2}))")
_REDACTED_CONTAINER = re.compile(
    r'''\{\s*(?:redacted|"redacted"|'redacted')\s*:\s*(?:secret|"secret"|'secret')\s*\}'''
)


@dataclass(frozen=True)
class Finding:
    """Only trusted policy labels and integer positions are safe to report."""
    code: str
    location: str
    line: int = 0


class SecurityScanError(ValueError):
    def __init__(self, message: str = "Security scan blocked; remove credential material privately."):
        super().__init__(message)


@lru_cache(maxsize=1)
def _plugins():
    try:
        if version("detect-secrets") != ENGINE_VERSION:
            raise SecurityScanError("Security scanner version mismatch; install the reviewed locked dependencies.")
        return tuple(getattr(importlib.import_module("detect_secrets.plugins." + module), name)()
                     for module, name in _PLUGINS)
    except SecurityScanError:
        raise
    except Exception:
        raise SecurityScanError("Security scanner unavailable; install the reviewed locked dependencies.") from None


def _safe_literal(value: Any) -> bool:
    return (value is None or value is False or value == {"redacted": "secret"}
            or isinstance(value, str) and (value in _SAFE_LITERAL or bool(_ENV_REFERENCE.fullmatch(value))))


def _decoded(value: str) -> str:
    """Bounded decoding for inspection only; never replace the outgoing bytes."""
    for _ in range(4):
        decoded = unquote(value)
        decoded = _ASCII_ESCAPE.sub(
            lambda match: chr(int(match.group(1) or match.group(2), 16))
            if int(match.group(1) or match.group(2), 16) < 128 else match.group(), decoded
        ).replace(r"\/", "/")
        if decoded == value:
            return value
        value = decoded
    if unquote(value) != value or _ASCII_ESCAPE.search(value):
        raise SecurityScanError("Security scan encoded input exceeds the supported limit.")
    return value


def _normalized_key(key: str) -> str:
    return re.sub(r"[^a-z]", "", _decoded(key).lower())


def _credential_key(key: str) -> bool:
    normalized = _normalized_key(key)
    return normalized in _NORMALIZED_EXACT or any(alias in normalized for alias in _NORMALIZED_CONTAINED)


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate key in credential container")
        result[key] = value
    return result


def _container_findings(text: str, location: str) -> list[Finding]:
    """Inspect inline/multiline credential containers even in plain-text notes."""
    result = []
    decoder = json.JSONDecoder(object_pairs_hook=_unique_pairs)
    for match in _CONTAINER_ASSIGNMENT.finditer(text):
        if not _credential_key(match.group("key")):
            continue
        try:
            value, _ = decoder.raw_decode(text, match.start("container"))
        except (ValueError, RecursionError):
            # An unparseable credential-bearing container is not evidence of
            # redaction. Do not execute expressions or guess at its contents.
            value = {"redacted": "secret"} if _REDACTED_CONTAINER.match(text, match.start("container")) else object()
        if not _safe_literal(value):
            result.append(Finding("credential_assignment", location))
        if len(result) >= MAX_FINDINGS:
            break
    return result


def _text_findings(text: str, location: str, plugins, *, assignments: bool = True) -> list[Finding]:
    result: list[Finding] = []
    # Percent-encoded URL userinfo/query values must not hide a credential.
    decoded = _decoded(text)
    candidates = (text, decoded) if decoded != text else (text,)
    for candidate in candidates:
        if assignments:
            result.extend(_container_findings(candidate, location))
            if len(result) >= MAX_FINDINGS:
                return result[:MAX_FINDINGS]
        for number, line in enumerate(candidate.splitlines(), 1):
            # Do not let an enormous logical line feed third-party expressions.
            if len(line) > 1024 * 1024:
                raise SecurityScanError("Security scan input line exceeds the supported limit.")
            for plugin in plugins:
                if next(plugin.analyze_string(line), None) is not None:
                    result.append(Finding("credential_format", location, number))
                    break
            if _BEARER.search(line) or _OPENAI.search(line) or _GITHUB_FINE_GRAINED.search(line):
                result.append(Finding("credential_format", location, number))
            if _URL_AUTH.search(line):
                result.append(Finding("credential_url", location, number))
            for match in _URL_QUERY.finditer(line):
                key, value = match.group("key"), _decoded(match.group("value"))
                if (_credential_key(key) or _normalized_key(key) in _SIGNED_URL_KEYS) and not _safe_literal(value):
                    result.append(Finding("credential_url", location, number))
                    break
            if assignments:
                for match in _ASSIGNMENT.finditer(line):
                    value = match.group("quoted") or match.group("reference") or match.group("bare")
                    if _credential_key(match.group("key")) and not _safe_literal(_decoded(value)):
                        result.append(Finding("credential_assignment", location, number))
                        break
            if len(result) >= MAX_FINDINGS:
                return result[:MAX_FINDINGS]
    return result


def _python_findings(text: str, plugins) -> list[Finding]:
    """Separate executable references from literal credentials, without file skips.

    Every string and comment still receives format/URL checks. Only syntactically
    valid Python receives this treatment; naming a data dump .py cannot bypass it.
    """
    tree = ast.parse(text)
    result: list[Finding] = []

    def credential_literal(node):
        # No eval: literal_eval accepts only Python data literals, not code or
        # environment lookups. Inspect nested literals when .py is a renamed dump.
        try:
            value = ast.literal_eval(node)
        except (ValueError, TypeError, SyntaxError):
            # A single environment expression must not hide another opaque
            # literal in the same credential container. Walk data values only;
            # do not execute or treat expression arguments as credential values.
            if isinstance(node, ast.Dict):
                return any(credential_literal(value) for value in node.values)
            if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
                return any(credential_literal(value) for value in node.elts)
            return False
        return not _safe_literal(value)

    for index, node in enumerate(ast.walk(tree)):
        if index > MAX_NODES:
            raise SecurityScanError("Security scan code input exceeds the supported limit.")
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            result.extend(_text_findings(node.value, "content", plugins))
        if isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values):
                if (isinstance(key, ast.Constant) and isinstance(key.value, str)
                        and _credential_key(key.value) and credential_literal(value)):
                    result.append(Finding("credential_property", "property", node.lineno))
        if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                name = target.id if isinstance(target, ast.Name) else target.attr if isinstance(target, ast.Attribute) else ""
                if name and _credential_key(name) and credential_literal(node.value):
                    result.append(Finding("credential_assignment", "content", node.lineno))
        if len(result) >= MAX_FINDINGS:
            return result[:MAX_FINDINGS]
    return result


def _value_findings(value: Any, plugins) -> list[Finding]:
    result: list[Finding] = []
    pending = [(value, 0)]
    nodes = 0
    while pending:
        child, depth = pending.pop()
        nodes += 1
        if nodes > MAX_NODES or depth > MAX_DEPTH:
            raise SecurityScanError("Security scan structured input exceeds the supported limit.")
        if isinstance(child, dict):
            for key, item in child.items():
                if _credential_key(str(key)) and not _safe_literal(item):
                    result.append(Finding("credential_property", "property"))
                # Keys can themselves carry secrets; never return them in a finding.
                pending.extend(((str(key), depth + 1), (item, depth + 1)))
        elif isinstance(child, (list, tuple)):
            pending.extend((item, depth + 1) for item in child)
        elif isinstance(child, str):
            result.extend(_text_findings(child, "content", plugins))
        if len(result) >= MAX_FINDINGS:
            return result[:MAX_FINDINGS]
    return result


def scan_bytes(data: bytes, *, filename: str = "artifact") -> tuple[Finding, ...]:
    """Inspect the exact outgoing UTF-8 bytes and member name; never modify them.

    Exceptions, absent/wrong engines, non-text and over-limit data fail closed.
    A successful empty result means no recognized secrets, NOT safe-to-share data.
    """
    try:
        if not isinstance(data, bytes) or len(data) > MAX_BYTES or len(filename) > 4096:
            raise SecurityScanError("Security scan input exceeds the supported limit.")
        plugins = _plugins()
        # A UTF-8 BOM must not hide an escaped credential property from parsing.
        text = data.decode("utf-8-sig")
        if "\x00" in text or "\x00" in filename:
            raise SecurityScanError("Security scan requires supported text artifacts.")
        findings = _text_findings(filename, "filename", plugins)
        code = filename.endswith(".py")
        findings.extend(_text_findings(text, "content", plugins, assignments=not code))
        if code:
            findings.extend(_python_findings(text, plugins))
        if text.lstrip().startswith(("{", "[", '"')):
            try:
                value = json.loads(text)
            except (ValueError, RecursionError):
                value = None  # The independent format validator rejects malformed JSON.
            if value is not None:
                findings.extend(_value_findings(value, plugins))
        if not code and filename.endswith((".yaml", ".yml", ".view", ".topic", "/relationships")):
            # Decoded YAML string escapes require the same structural checks as
            # JSON. Forbid aliases before construction to avoid recursive input.
            if any(isinstance(event, yaml.events.AliasEvent) for event in yaml.parse(text)):
                raise SecurityScanError("Security scan does not accept YAML aliases.")
            for index, value in enumerate(yaml.safe_load_all(text)):
                if index >= 100:
                    raise SecurityScanError("Security scan YAML document count exceeds the supported limit.")
                findings.extend(_value_findings(value, plugins))
        return tuple(dict.fromkeys(findings))[:MAX_FINDINGS]
    except SecurityScanError:
        raise
    except Exception:
        raise SecurityScanError("Security scanner could not complete; sharing is blocked.") from None


def assert_safe_bytes(data: bytes, *, filename: str = "artifact") -> None:
    if scan_bytes(data, filename=filename):
        raise SecurityScanError()


def assert_safe_value(value: Any) -> None:
    try:
        data = json.dumps(value, ensure_ascii=True, allow_nan=False, indent=2).encode("utf-8")
    except (ValueError, TypeError, RecursionError):
        raise SecurityScanError("Security scanner requires a bounded serializable value.") from None
    assert_safe_bytes(data)

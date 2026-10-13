"""Independent, read-only checks over a reopened local Sigma build package.

No builder, provider, target adapter, credentials, or network client is imported.
Hashes provide consistency inside the explicitly local-operator trust boundary;
they are not signatures and do not establish source freshness or live acceptance.
"""

from __future__ import annotations

import hashlib
import ast
import json
import re
import sqlite3
from itertools import islice
from pathlib import Path, PurePosixPath
from typing import Any

import yaml

from omni_migrator.prepush.reuse import source_fields, validate_target as validate_reuse_target
from omni_migrator.prepush.scope import validate_scope
from omni_migrator.security.scanner import (
    POLICY_VERSION,
    SecurityScanError,
    assert_safe_bytes,
    assert_safe_value,
)

ROUTES = {"omni_semantic_reconstruction", "warehouse_first_refactor"}
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
_REFERENCE = re.compile(r"\$\{([^{}]+)\}")
_MAX_FILE_BYTES = 10 * 1024 * 1024
_MAX_PACKAGE_BYTES = 50 * 1024 * 1024
_MAX_FILES = 1000
_UNSAFE_EXPORT_CODES = frozenset({
    "unsafe_package_path", "unreadable_package", "package_limit", "symlink",
    "unsafe_file", "unreadable_file", "invalid_manifest", "manifest_version",
    "invalid_inventory", "unsafe_manifest_path", "invalid_file_hash", "missing_file",
    "file_hash_mismatch", "unlisted_file", "unsupported_file", "invalid_document",
    "missing_bound_input", "input_hash_mismatch", "missing_review", "stale_review",
    "invalid_authority", "stale_proposal_review", "unreadable_proposal",
})


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_sha(value: Any) -> str:
    return _sha(json.dumps(value, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False, allow_nan=False).encode("utf-8"))


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate key: {key}")
        result[key] = value
    return result


def _bad_constant(value: str) -> None:
    raise ValueError(f"nonfinite JSON number: {value}")


def _json(raw: bytes) -> Any:
    return json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs,
                      parse_constant=_bad_constant)


class _UniqueSafeLoader(yaml.SafeLoader):
    pass


def _yaml_mapping(loader: _UniqueSafeLoader, node: yaml.MappingNode,
                  deep: bool = False) -> dict[str, Any]:
    # Reject merge keys/aliases instead of permitting hidden duplicate overrides.
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if not isinstance(key, str) or key in result:
            raise ValueError("YAML mapping keys must be unique strings")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_UniqueSafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _yaml_mapping
)


def _yaml(raw: bytes) -> Any:
    text = raw.decode("utf-8")
    if any(isinstance(event, yaml.events.AliasEvent) for event in yaml.parse(text)):
        raise ValueError("YAML aliases are not supported in pre-push packages")
    # SafeLoader subclass also rejects duplicate keys; no unsafe YAML constructors.
    return yaml.load(text, Loader=_UniqueSafeLoader)  # nosec B506


def _relative(value: Any) -> bool:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        return False
    path = PurePosixPath(value)
    return (not path.is_absolute() and all(part not in {".", ".."} for part in value.split("/"))
            and path.as_posix() == value and ":" not in value)


def _strings(value: Any):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for child in value.values():
            yield from _strings(child)
    elif isinstance(value, list):
        for child in value:
            yield from _strings(child)


def _sql_tokens(sql: str) -> list[str]:
    """Lex a bounded SELECT subset; never execute statements during validation."""
    if not sql.strip() or len(sql) > 250_000:
        raise ValueError("query SQL is empty or exceeds the local validation bound")
    tokens = []
    position = 0
    pattern = re.compile(
        r"\s+|'(?:''|[^'])*'|\"(?:\"\"|[^\"])*\"|[A-Za-z_][A-Za-z0-9_]*|"
        r":[A-Za-z_][A-Za-z0-9_]*|\d+(?:\.\d+)?|<=|>=|<>|!=|[-+*/%=<>()\[\],.;]"
    )
    while position < len(sql):
        match = pattern.match(sql, position)
        if match is None:
            raise ValueError("SQL contains unsupported or unsafe syntax")
        token = match.group()
        position = match.end()
        if not token.isspace():
            tokens.append(token)
    return tokens


def _validate_sql(sql: Any, path: str, issue) -> list[str]:
    if not isinstance(sql, str):
        issue("invalid_sql", path, "SQL must be a nonempty string.")
        return []
    try:
        tokens = _sql_tokens(sql)
    except ValueError as exc:
        issue("invalid_sql", path, str(exc))
        return []
    words = {item.upper() for item in tokens if _IDENTIFIER.fullmatch(item)}
    prohibited = {
        "INSERT", "UPDATE", "DELETE", "DROP", "ALTER", "CREATE", "ATTACH", "DETACH",
        "PRAGMA", "REPLACE", "TRUNCATE", "MERGE", "GRANT", "REVOKE", "COPY", "CALL",
        "EXEC", "EXECUTE", "LOAD_EXTENSION", "READFILE", "WRITEFILE", "VACUUM",
    }
    body = tokens[:-1] if tokens and tokens[-1] == ";" else tokens
    if (not tokens or tokens[0].upper() not in {"SELECT", "WITH"} or ";" in body
            or words & prohibited or "--" in sql or "/*" in sql or "*/" in sql
            or "${" in sql or "{{" in sql):
        issue("unsafe_sql", path, "Only bounded, fully resolved read-only SELECT queries are allowed.")
    if re.search(r"\b(?:TODO|FIXME|PLACEHOLDER|NOT_IMPLEMENTED)\b", sql, re.I):
        issue("placeholder_sql", path, "Placeholder SQL cannot pass preflight.")
    depth = 0
    for token in tokens:
        depth += (token == "(") - (token == ")")
        if depth < 0:
            break
    if depth != 0 or "SELECT" not in words or "FROM" not in words:
        issue("invalid_sql", path, "Query requires a balanced SELECT over a bound relation.")
    return tokens


def _sqlite_sql(sql: str) -> str:
    """Use strict SQLite identifier tokens even on Python 3.11's SQLite API.

    SQLite can silently interpret an unknown double-quoted identifier as a
    string. Its bracket identifiers have no such fallback. The lexer keeps SQL
    single-quoted values intact, and our bounded identifier grammar excludes
    brackets and quoting escapes. Only the offline parse copy is transformed.
    """
    parts = []
    for token in _sql_tokens(sql):
        if token.startswith('"'):
            identifier = token[1:-1]
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)?", identifier):
                raise ValueError("Unsupported quoted SQL identifier")
            parts.append("[" + identifier + "]")
        else:
            parts.append(token)
    return " ".join(parts)


def validate(package_dir: Path) -> dict[str, Any]:
    """Reopen a local package and return an honest offline-only verdict."""
    issues: list[dict[str, str]] = []
    security_failed = False

    def issue(code: str, path: str, message: str) -> None:
        entry = {"code": code, "path": path, "message": message}
        if entry not in issues:
            issues.append(entry)

    def result() -> dict[str, Any]:
        return {
            "schema_version": "sigma-prepush-validation.v1",
            "status": "blocked" if issues else "offline_preflight_passed",
            "issues": issues,
            "security_status": "blocked" if security_failed or any(
                entry["code"] in _UNSAFE_EXPORT_CODES for entry in issues
            ) else "passed",
            "security_policy": POLICY_VERSION,
            "migration_accepted": False,
            "target_write_authority": False,
            "production_ready": False,
            "live_validation": "not_performed",
            "source_freshness": "not_verified_by_package_validator",
        }

    def scan(raw: bytes, name: str) -> bool:
        nonlocal security_failed
        try:
            assert_safe_bytes(raw, filename=name)
            return True
        except SecurityScanError:
            security_failed = True
            # Names, source strings and engine errors must not enter diagnostics.
            issue("embedded_credential", ".", "Security scan blocked; inspect credential material privately.")
            return False

    if not scan(b"", "artifact"):
        return result()

    root = Path(package_dir)
    if root.is_symlink() or not root.is_dir():
        issue("unsafe_package_path", ".", "Package must be an existing non-symlink directory.")
        return result()
    root = root.resolve()
    try:
        entries = list(islice(root.rglob("*"), _MAX_FILES * 2 + 1))
    except OSError:
        issue("unreadable_package", ".", "Package directory could not be read.")
        return result()
    if len(entries) > _MAX_FILES * 2:
        issue("package_limit", ".", "Package exceeds the bounded file inventory.")
        return result()
    raw_files: dict[str, bytes] = {}
    total = 0
    for entry in entries:
        name = entry.relative_to(root).as_posix()
        if not scan(b"", name):
            return result()
        if entry.is_symlink():
            issue("symlink", name, "Package symlinks are forbidden.")
            continue
        if entry.is_dir():
            continue
        if not entry.is_file() or not _relative(name):
            issue("unsafe_file", name, "Package members must be safe regular files.")
            continue
        try:
            size = entry.stat().st_size
            total += size
            if size > _MAX_FILE_BYTES or total > _MAX_PACKAGE_BYTES:
                issue("package_limit", name, "Package exceeds the local size limit.")
                continue
            with entry.open("rb") as stream:
                raw = stream.read(_MAX_FILE_BYTES + 1)
            if len(raw) > _MAX_FILE_BYTES:
                issue("package_limit", ".", "Package content grew beyond the local size limit.")
                return result()
            total += len(raw) - size
            if total > _MAX_PACKAGE_BYTES:
                issue("package_limit", ".", "Package exceeds the local size limit.")
                return result()
            raw_files[name] = raw
            if not scan(raw_files[name], name):
                return result()
        except OSError:
            issue("unreadable_file", name, "Package member could not be read.")
    if len(raw_files) > _MAX_FILES:
        issue("package_limit", ".", "Package exceeds the file count limit.")
    try:
        manifest = _json(raw_files.get("manifest.json", b""))
        if not isinstance(manifest, dict):
            raise ValueError("manifest must be an object")
    except (ValueError, UnicodeError, RecursionError):
        issue("invalid_manifest", "manifest.json", "Manifest is missing, malformed, or contains duplicate keys.")
        return result()
    if manifest.get("schema_version") != "sigma-prepush-package.v1":
        issue("manifest_version", "manifest.json", "Unsupported package schema version.")
    route = manifest.get("route")
    if not isinstance(route, str) or route not in ROUTES:
        issue("invalid_route", "manifest.json", "An explicit supported migration route is required.")
    if type(manifest.get("synthetic")) is not bool:
        issue("missing_evidence_class", "manifest.json", "Synthetic evidence classification must be explicit.")
    if (manifest.get("migration_accepted") is not False
            or manifest.get("target_write_authority") is not False
            or manifest.get("live_validation") != "not_performed"):
        issue("invalid_authority", "manifest.json", "Offline packages cannot authorize writes or claim live acceptance.")
    inventory = manifest.get("files")
    if not isinstance(inventory, dict):
        issue("invalid_inventory", "manifest.json", "Manifest files must map paths to exact SHA256 hashes.")
        return result()
    for name, digest in inventory.items():
        if not _relative(name) or name == "manifest.json":
            issue("unsafe_manifest_path", "manifest.json", "Manifest contains an unsafe or recursive member path.")
            continue
        if not isinstance(digest, str) or not _HASH.fullmatch(digest):
            issue("invalid_file_hash", name, "File hash must be a lowercase SHA256 value.")
        elif name not in raw_files:
            issue("missing_file", name, "Manifest member is missing.")
        elif _sha(raw_files[name]) != digest:
            issue("file_hash_mismatch", name, "Persisted bytes differ from the reviewed inventory.")
    for name in raw_files.keys() - inventory.keys() - {"manifest.json"}:
        issue("unlisted_file", name, "Package contains a file outside the sealed inventory.")
    parsed = {}
    for name, raw in raw_files.items():
        if name == "manifest.json":
            continue
        try:
            if name.endswith(".json"):
                parsed[name] = _json(raw)
            elif name.endswith((".yml", ".yaml", ".view", ".topic")) or name.endswith("/relationships"):
                parsed[name] = _yaml(raw)
            elif name.startswith("queries/") and name.endswith(".sql"):
                _validate_sql(raw.decode("utf-8"), name, issue)
            elif name.startswith("dbt/") and name.endswith(".sql"):
                raw.decode("utf-8")
            else:
                issue("unsupported_file", name, "File type is outside the reviewed package contract.")
        except (ValueError, UnicodeError, RecursionError, yaml.YAMLError):
            issue("invalid_document", name, "Document is malformed, unsafe, or contains duplicate keys.")
        if name in parsed:
            try:
                assert_safe_value(parsed[name])
            except SecurityScanError:
                security_failed = True
                issue("embedded_credential", ".", "Security scan blocked; inspect credential material privately.")
                return result()
    for name, key in (("source.json", "source_sha256"), ("target.json", "target_sha256")):
        if name not in inventory or not isinstance(parsed.get(name), dict):
            issue("missing_bound_input", name, "Package requires an inventoried input object.")
        elif manifest.get(key) != _canonical_sha(parsed[name]):
            issue("input_hash_mismatch", name, "Canonical input hash differs from the manifest.")
    review = manifest.get("review")
    if not isinstance(review, dict):
        review = {}
    actor = review.get("actor") if isinstance(review.get("actor"), dict) else {}
    if (review.get("decision") != "accept" or type(actor.get("uid")) is not int
            or actor.get("uid", -1) < 0 or not isinstance(actor.get("name"), str)
            or not actor.get("name", "").strip()):
        issue("missing_review", "manifest.json", "An accepted OS-operator review binding is required.")
    if any(review.get(key) != manifest.get(key) for key in ("source_sha256", "target_sha256", "route")):
        issue("stale_review", "manifest.json", "Review does not bind this exact source, target, and route.")
    build = manifest.get("build")
    if not isinstance(build, dict):
        build = {}
    if (build.get("schema_version") != "sigma-prepush-build.v1" or build.get("route") != route
            or build.get("target_write_authority") is not False
            or build.get("production_ready") is not False):
        issue("invalid_build_contract", "manifest.json", "Build version, route, or authority barriers are invalid.")
    try:
        proposal = {**build, "files": {
            name: raw_files[name].decode("utf-8")
            for name in inventory if name not in {"source.json", "target.json"}
        }}
        if review.get("proposal_sha256") != _canonical_sha(proposal):
            issue("stale_proposal_review", "manifest.json", "Review does not bind the exact persisted build proposal.")
    except (KeyError, UnicodeError, ValueError):
        issue("unreadable_proposal", "manifest.json", "Reviewed build proposal could not be reconstructed from persisted files.")
    try:
        _validate_artifacts(parsed, raw_files, build, route, issue)
    except (TypeError, KeyError, AttributeError, IndexError, RecursionError, ValueError, UnicodeError):
        issue("malformed_artifact", "manifest.json", "Artifact structure is malformed or outside the bounded validation contract.")
    return result()


def _validate_artifacts(parsed, raw_files, build, route, issue):
    source = parsed.get("source.json", {})
    target = parsed.get("target.json", {})
    reuse = isinstance(target, dict) and target.get("allowed_changes") == "dashboard_only"
    policy = target.get("allowed_changes", "model_changes") if isinstance(target, dict) else None
    if policy not in {"model_changes", "dashboard_only"}:
        issue("unsupported_change_policy", "target.json", "Validation-only and topic-only permissions cannot authorize model or dashboard compilation.")
    if reuse:
        try:
            validate_reuse_target(target, source)
        except (ValueError, TypeError, KeyError, AttributeError):
            issue("invalid_topic_evidence", "target.json", "Existing Topic evidence, fingerprints or compatibility mappings are invalid.")
        if route != "omni_semantic_reconstruction":
            issue("reuse_route_conflict", "target.json", "Dashboard-only reuse cannot authorize warehouse-first changes.")
        for name in raw_files:
            if (name not in {"manifest.json", "source.json", "target.json", "omni/document.create.json", "omni/document.patch.json"}
                    and not re.fullmatch(r"queries/[1-9][0-9]*\.json", name)):
                issue("forbidden_dashboard_only_artifact", name, "Dashboard-only reuse forbids model, view, topic, dbt and raw-SQL artifacts.")
    elif not any(name.startswith("omni/model/") and name.endswith(".view") for name in parsed):
        issue("missing_model", "omni/model", "Package must contain concrete Omni model views.")
    if route == "omni_semantic_reconstruction" and any(name.startswith("dbt/") for name in raw_files):
        issue("direct_route_dbt", "dbt", "Direct reconstruction cannot contain dbt artifacts.")
    if not reuse and route == "warehouse_first_refactor" and not any(name.startswith("dbt/models/") and name.endswith(".sql") for name in raw_files):
        issue("missing_data_layer", "dbt/models", "Modeled reconstruction requires concrete data-layer SQL.")
    denominator = _source_denominator(source, issue)
    scope = None
    try:
        scope = validate_scope(source)
        if scope and scope["issues"]:
            issue("unresolved_scope", "source.json", "Selected pilot has unresolved dependency evidence.")
    except (ValueError, TypeError, KeyError, AttributeError):
        issue("invalid_scope", "source.json", "Scope selection, source revision or dependency closure is stale or modified.")
    excluded = set(scope["excluded_source_paths"]) if scope else set()
    dispositions = build.get("dispositions")
    if not isinstance(dispositions, list):
        dispositions = []
    accounted = {}
    for row in dispositions:
        if not isinstance(row, dict) or not isinstance(row.get("source_path"), str):
            issue("invalid_disposition", "manifest.json", "Every disposition needs a source pointer.")
            continue
        pointer = row["source_path"]
        if pointer in accounted:
            issue("duplicate_disposition", pointer, "Source object has duplicate dispositions.")
        accounted[pointer] = row
        expected = denominator.get(pointer)
        if expected is None or any(row.get(key) != expected[key] for key in ("source_id", "source_kind")):
            issue("foreign_disposition", pointer, "Disposition identity does not match captured source scope.")
        paths = row.get("target_paths")
        if pointer in excluded:
            if row.get("status") != "excluded" or paths != []:
                issue("invalid_exclusion", pointer, "Explicitly excluded source objects must retain exclusion status without target artifacts.")
        elif row.get("status") != "implemented":
            issue("unresolved_source", pointer, "A scoped source object remains blocked or unsupported.")
        elif row.get("source_kind") not in {"connections", "dataModels", "workbooks", "pages", "elements", "columns", "metrics", "controls"}:
            issue("unsupported_disposition", pointer, "This source behavior has no validated implementation in the bounded package contract.")
        elif not isinstance(paths, list) or not paths or any(not isinstance(name, str) or name not in raw_files for name in paths):
            issue("missing_disposition_target", pointer, "Implemented source objects require concrete inventoried targets.")
        if not isinstance(row.get("reason"), str) or not row["reason"].strip():
            issue("missing_disposition_reason", pointer, "A disposition must explain its supported mapping or blocker.")
    for pointer in denominator.keys() - accounted.keys():
        issue("missing_disposition", pointer, "Source object was silently omitted from the scope denominator.")
    if not denominator:
        issue("empty_source_scope", "source.json", "Captured source scope contains no migratable objects.")
    mappings = build.get("source_mappings")
    if not isinstance(mappings, list):
        mappings = []
        issue("missing_lineage", "manifest.json", "Build must enumerate source-to-target mappings.")
    mapped = set()
    mapping_keys = set()
    for row in mappings:
        if not isinstance(row, dict):
            issue("invalid_mapping", "manifest.json", "Source mappings must be typed objects.")
            continue
        pointer, name, reference = (row.get(key) for key in ("source_path", "target_path", "target_object_ref"))
        if not all(isinstance(item, str) for item in (pointer, name, reference)):
            issue("invalid_mapping", "manifest.json", "Source mapping identities and references must be strings.")
            continue
        expected = denominator.get(pointer)
        if pointer in excluded:
            issue("excluded_source_mapping", pointer, "Excluded source objects cannot produce target artifacts.")
        if expected is None or row.get("source_id") != expected["source_id"]:
            issue("foreign_mapping", str(pointer), "Mapping does not bind a captured source object.")
        if not isinstance(name, str) or name not in raw_files or not isinstance(reference, str) or not reference:
            issue("missing_mapping_target", str(pointer), "Source mapping needs an existing target and object reference.")
        key = (pointer, name, reference)
        if key in mapping_keys:
            issue("duplicate_mapping", str(pointer), "Duplicate source-target mapping.")
        mapping_keys.add(key)
        mapped.add(pointer)
        if pointer in accounted and isinstance(accounted[pointer].get("target_paths"), list) and name not in accounted[pointer]["target_paths"]:
            issue("inconsistent_mapping", str(pointer), "Mapping target is absent from its source disposition.")
    for pointer, row in accounted.items():
        if row.get("status") == "implemented" and pointer not in mapped:
            issue("missing_lineage", pointer, "Implemented source object lacks source-to-target lineage.")
    if reuse:
        topic = target.get("existing_topic", {}).get("inventory", {})
        fields = {key.split(".")[-1]: {**value.get("definition", {}), "hidden": value.get("hidden")}
                  for key, value in topic.get("fields", {}).items() if isinstance(value, dict)}
        views = {topic.get("base_view"): {"path": "target.json", "body": {}, "fields": fields}}
        topics = {topic.get("topic_name"): {"base_view": topic.get("base_view")}}
        _validate_reuse_lineage(source, target, mappings, issue)
    else:
        views, topics = _validate_model(parsed, issue)
    _validate_mapping_refs(mappings, parsed, denominator, views, issue)
    _validate_documents(parsed, raw_files, views, topics, target, mappings, denominator, issue)
    if reuse:
        _validate_reuse_queries(parsed, target, issue)
    else:
        _validate_queries(raw_files, parsed, target, views, route, issue)
    dependencies = build.get("dependencies")
    if not isinstance(dependencies, list):
        issue("invalid_dependencies", "manifest.json", "Build dependencies must be explicit.")
    elif route == "warehouse_first_refactor":
        if not any(isinstance(row, dict) and row.get("kind") == "warehouse_deployment"
                   and row.get("status") == "undeployed" for row in dependencies):
            issue("missing_warehouse_dependency", "manifest.json", "Modeled route must retain its undeployed warehouse dependency.")
    elif any(isinstance(row, dict) and row.get("kind") == "warehouse_deployment" for row in dependencies):
        issue("direct_route_dependency", "manifest.json", "Direct route cannot require warehouse deployment.")


def _source_denominator(source, issue):
    result = {}
    security = {"security", "rls", "cls", "permissions", "rowLevelSecurity", "columnLevelSecurity", "pdp"}
    id_keys = {"dataModels": "dataModelId", "workbooks": "workbookId", "connections": "connectionId",
               "pages": "pageId", "elements": "elementId", "columns": "columnId", "metrics": "metricId",
               "relationships": "relationshipId", "controls": "controlId", "grants": "grantId",
               "sources": "sourceId", "schedules": "scheduleId", "actions": "actionId"}

    def token(value):
        return str(value).replace("~", "~0").replace("/", "~1")

    def add(value, pointer, kind):
        identity = value.get(id_keys.get(kind, "id")) or value.get("id") or "path:" + pointer
        if not isinstance(identity, str) or not identity:
            issue("invalid_source_identity", pointer, "Captured source identities must be nonempty strings.")
            identity = "path:" + pointer
        result[pointer] = {"source_id": identity, "source_kind": kind, "value": value}

    def walk(value, pointer):
        if not isinstance(value, dict):
            return
        for key, child in value.items():
            if key == "reviewed_enrichment":
                continue
            path = pointer + "/" + token(key)
            if isinstance(child, list):
                identities = set()
                for index, item in enumerate(child):
                    if isinstance(item, dict):
                        item_path = path + "/" + str(index)
                        add(item, item_path, key)
                        identity = result[item_path]["source_id"]
                        if identity in identities:
                            issue("duplicate_source_identity", path, "Source collection contains duplicate stable identities.")
                        identities.add(identity)
                        walk(item, item_path)
            elif isinstance(child, dict):
                if key in security and child:
                    add(child, path, key)
                walk(child, path)
    if isinstance(source, dict):
        for key in ("dataModels", "workbooks", "connections"):
            walk({key: source.get(key, [])}, "")
    return result


def _validate_model(parsed, issue):
    views = {}
    topics = {}
    for name, value in parsed.items():
        if not name.startswith("omni/model/"):
            continue
        if name.endswith(".view"):
            alias = PurePosixPath(name).stem
            if alias in views:
                issue("duplicate_view", name, "View aliases must be unique across the model.")
            if not isinstance(value, dict):
                issue("invalid_view", name, "View YAML must contain a mapping.")
                continue
            dimensions = value.get("dimensions", {})
            measures = value.get("measures", {})
            if (not isinstance(dimensions, dict) or not isinstance(measures, dict)
                    or not dimensions or set(dimensions) & set(measures)):
                issue("invalid_fields", name, "View requires concrete, uniquely named dimensions and measures.")
                continue
            if not value.get("table_name") and not value.get("sql"):
                issue("missing_relation", name, "View must bind an existing or generated relation.")
            fields = {**dimensions, **measures}
            for field, definition in fields.items():
                if not _IDENTIFIER.fullmatch(field) or not isinstance(definition, dict):
                    issue("invalid_field", name, "Fields need safe names and structured definitions.")
                    continue
                if "hidden" in definition and type(definition["hidden"]) is not bool:
                    issue("invalid_visibility", name, "Visibility metadata must be boolean.")
                if "sql" in definition and (not isinstance(definition["sql"], str) or not definition["sql"].strip()):
                    issue("empty_field_sql", name, "Explicit field SQL cannot be an empty placeholder.")
            views[alias] = {"path": name, "body": value, "fields": fields}
        elif name.endswith(".topic"):
            topics[PurePosixPath(name).stem] = value
    if not topics:
        issue("missing_topic", "omni/model", "At least one concrete Topic is required.")
    for alias, view in views.items():
        for text in _strings(view["body"]):
            for reference in _REFERENCE.findall(text):
                parts = reference.split(".")
                owner, field = (parts if len(parts) == 2 else (alias, reference))
                if owner not in views or field not in views[owner]["fields"]:
                    issue("missing_field_reference", view["path"], "Model SQL references an undefined field.")
    relationships = parsed.get("omni/model/relationships", [])
    if not isinstance(relationships, list):
        issue("invalid_relationships", "omni/model/relationships", "Relationships must be a YAML list.")
        relationships = []
    joined = set()
    for row in relationships:
        if (not isinstance(row, dict) or not isinstance(row.get("join_from_view"), str)
                or not isinstance(row.get("join_to_view"), str)
                or row["join_from_view"] not in views or row["join_to_view"] not in views):
            issue("invalid_join", "omni/model/relationships", "Relationship endpoints must resolve to emitted views.")
            continue
        joined.add((row["join_from_view"], row["join_to_view"]))
        sql = row.get("on_sql")
        if not isinstance(sql, str) or not sql.strip():
            issue("empty_join", "omni/model/relationships", "Join predicate is required.")
        else:
            for reference in _REFERENCE.findall(sql):
                parts = reference.split(".")
                if len(parts) != 2 or parts[0] not in views or parts[1] not in views[parts[0]]["fields"]:
                    issue("missing_join_field", "omni/model/relationships", "Join predicate references an undefined field.")
    for alias, topic in topics.items():
        path = f"omni/model/{alias}.topic"
        if (not isinstance(topic, dict) or not isinstance(topic.get("base_view"), str)
                or topic["base_view"] not in views):
            issue("invalid_topic", path, "Topic must bind an emitted base view.")
            continue
        joins = topic.get("joins", {})
        if not isinstance(joins, dict):
            issue("invalid_topic_joins", path, "Topic joins must form a reference map.")
        else:
            for join in joins:
                if join not in views or (topic["base_view"], join) not in joined:
                    issue("missing_relationship", path, "Topic join lacks its model relationship.")
    return views, topics


def _validate_mapping_refs(mappings, parsed, denominator, views, issue):
    for row in mappings:
        if not isinstance(row, dict):
            continue
        name, reference = row.get("target_path"), row.get("target_object_ref")
        if not isinstance(name, str) or not isinstance(reference, str):
            continue
        source = denominator.get(row.get("source_path"), {})
        if name == "target.json" and parsed.get(name, {}).get("allowed_changes") == "dashboard_only":
            inventory = parsed[name].get("existing_topic", {}).get("inventory", {})
            if reference.startswith("existing-topic-field:"):
                if reference.removeprefix("existing-topic-field:") not in inventory.get("fields", {}):
                    issue("invalid_topic_mapping", name, "Mapping refers to an absent existing Topic field.")
                continue
            if reference == "existing-topic:" + str(inventory.get("topic_name")) and source.get("source_kind") == "elements":
                continue
        if reference == "source-container" and source.get("source_kind") in {"dataModels", "pages"} and str(row.get("source_path")).startswith("/dataModels/"):
            continue
        if (reference.startswith("connection:") and source.get("source_kind") == "connections"
                and reference == "connection:" + str(parsed.get("target.json", {}).get("connection_id"))):
            continue
        if (re.fullmatch(r"queries/[1-9][0-9]*\.json", name)
                and parsed.get("target.json", {}).get("allowed_changes") == "dashboard_only"):
            key = PurePosixPath(name).stem
            if (reference != "queryPresentations.data." + key
                    or key not in parsed.get("omni/document.create.json", {}).get("queryPresentations", {}).get("data", {})):
                issue("invalid_document_mapping", name, "Typed query lineage does not bind its exact dashboard query presentation.")
            continue
        if name.endswith(".view"):
            alias = PurePosixPath(name).stem
            if reference == alias:
                continue
            parts = reference.split(".")
            if len(parts) != 2 or parts[0] != alias or alias not in views or parts[1] not in views[alias]["fields"]:
                issue("invalid_model_mapping", name, "Source mapping does not resolve to an emitted model field.")
                continue
            source_value = denominator.get(row.get("source_path"), {}).get("value", {})
            if "hidden" in source_value and source_value["hidden"] != views[alias]["fields"][parts[1]].get("hidden", False):
                issue("visibility_changed", name, "Source hidden metadata differs from its mapped field.")
        elif name.endswith(".json") and name in parsed:
            if reference == "document" and source.get("source_kind") == "workbooks":
                continue
            if reference.startswith("containers.page-") and source.get("source_kind") == "pages":
                key = reference.removeprefix("containers.")
                containers = parsed[name].get("containers", []) if isinstance(parsed[name], dict) else []
                if not any(isinstance(item, dict) and item.get("instanceKey") == key for item in containers):
                    issue("invalid_page_mapping", name, "Source page maps to a missing layout container.")
                continue
            value = parsed[name]
            for part in reference.split("."):
                if isinstance(value, dict) and part in value:
                    value = value[part]
                elif isinstance(value, list) and part.isdigit() and int(part) < len(value):
                    value = value[int(part)]
                else:
                    issue("invalid_document_mapping", name, "Source mapping references a missing document object.")
                    break


def _validate_documents(parsed, raw_files, views, topics, target, mappings, denominator, issue):
    path = "omni/document.create.json"
    document = parsed.get(path)
    if not isinstance(document, dict):
        issue("missing_document", "omni/document.create.json", "Concrete Documents v2 create payload is required.")
        return
    if set(document) != {"modelId", "name", "queryPresentations", "controls", "containers", "settings"}:
        issue("invalid_document_schema", path, "Document does not match the pinned, supported v2 create payload subset.")
    if document.get("modelId") != target.get("model_id") or document.get("name") != target.get("document_name"):
        issue("wrong_document_target", path, "Document identity differs from the reviewed target.")
    patch = parsed.get("omni/document.patch.json")
    if patch != {key: value for key, value in document.items() if key != "modelId"}:
        issue("divergent_patch", "omni/document.patch.json", "Create and patch content must agree exactly.")

    def ordered_map(key):
        value = document.get(key)
        if not isinstance(value, dict) or set(value) != {"data", "order"}:
            issue("invalid_ordered_map", path, f"{key} requires data and order.")
            return {}
        data, order = value["data"], value["order"]
        if (not isinstance(data, dict) or not isinstance(order, list)
                or any(not isinstance(item, str) for item in order)
                or len(order) != len(set(order)) or set(order) != set(data)):
            issue("invalid_ordered_map", path, f"{key} order must account for each unique object exactly once.")
            return {}
        return data

    tiles, controls = ordered_map("queryPresentations"), ordered_map("controls")
    if not 1 <= len(tiles) <= 48:
        issue("invalid_tile_count", path, "Document requires 1–48 concrete query presentations.")

    def field_exists(reference):
        if not isinstance(reference, str) or len(reference.split(".")) != 2:
            return False
        owner, field = reference.split(".")
        return owner in views and field in views[owner]["fields"]

    for key, tile in tiles.items():
        if not isinstance(tile, dict) or tile.get("type") != "query" or not isinstance(tile.get("query"), dict):
            issue("invalid_query_presentation", path, "Every tile requires a typed query presentation.")
            continue
        query = tile["query"]
        required = {"table", "fields", "join_paths_from_topic_name", "limit", "sorts", "filters", "pivots",
                    "calculations", "column_totals", "row_totals", "fill_fields", "userEditedSQL"}
        if set(query) != required or query.get("userEditedSQL") is not False:
            issue("invalid_query_schema", path, "Query does not match the supported typed query contract.")
        fields = query.get("fields")
        if (not isinstance(fields, list) or not fields or any(not field_exists(item) for item in fields)
                or len(fields) != len(set(fields))):
            issue("missing_query_field", path, "Query fields must uniquely resolve to emitted model fields.")
            fields = []
        if (not isinstance(query.get("table"), str) or query.get("table") not in views
                or tile.get("topicName") not in topics
                or query.get("join_paths_from_topic_name") != tile.get("topicName")
                or any(item.split(".")[0] != query.get("table") for item in fields)):
            issue("invalid_query_topic", path, "Query table/Topic/field scope must agree.")
        if type(query.get("limit")) is not int or not 1 <= query.get("limit", 0) <= 50000:
            issue("invalid_query_limit", path, "Query needs a bounded integer row limit.")
        for unsupported in ("filters", "pivots", "calculations", "column_totals", "row_totals", "fill_fields"):
            if query.get(unsupported):
                issue("unsupported_query_behavior", path, "Unexpected query behavior needs its own source-bound implementation.")
        sorts = query.get("sorts")
        if not isinstance(sorts, list) or any(not isinstance(row, dict) or set(row) != {"column_name", "descending"}
                or row.get("column_name") not in fields or type(row.get("descending")) is not bool for row in sorts):
            issue("invalid_query_sort", path, "Sorts must reference selected fields with explicit direction.")
        visual = tile.get("visConfig")
        if not isinstance(visual, dict) or visual.get("fields") != fields or visual.get("version") != 0:
            issue("invalid_visual_fields", path, "Visual configuration must bind the exact selected query fields.")
        else:
            chart = visual.get("chartType")
            inner = visual.get("visConfig")
            if chart not in {"table", "column", "line", "bar"} or not isinstance(inner, dict):
                issue("invalid_visual_schema", path, "Visual configuration is outside the supported subset.")
            elif (chart == "table" and inner != {"visType": "omni-table", "config": {}}) or (chart != "table" and inner.get("visType") != "basic"):
                issue("invalid_visual_schema", path, "Visual type does not match its declared chart.")
            elif chart != "table":
                config = inner.get("config", {})
                if not isinstance(config, dict) or config.get("configType") != "cartesian" or not config.get("series"):
                    issue("invalid_visual_schema", path, "Cartesian visual requires populated axes and series.")
                else:
                    def visual_fields(value):
                        if isinstance(value, dict):
                            if "field" in value:
                                ref = value["field"]
                                if not isinstance(ref, dict) or ref.get("name") not in fields:
                                    issue("missing_visual_field", path, "Visual axis/series/tooltip references an unselected field.")
                            for child in value.values():
                                visual_fields(child)
                        elif isinstance(value, list):
                            for child in value:
                                visual_fields(child)
                    visual_fields(config)
        reuse = target.get("allowed_changes") == "dashboard_only"
        query_path = f"queries/{key}.json" if reuse else f"queries/{key}.sql"
        if query_path not in raw_files:
            issue("missing_query_sql", query_path, "Every query presentation requires a concrete query artifact.")
        elif not reuse:
            sql = raw_files[query_path].decode("utf-8")
            aliases = re.findall(r'\bAS\s+"([^"]+)"', sql, re.I)
            if aliases != fields:
                issue("query_projection_mismatch", query_path, "Executable SQL aliases differ from the document's ordered query fields.")
            limit = re.search(r"\bLIMIT\s+(\d+)\s*;?\s*$", sql, re.I)
            if limit is None or int(limit.group(1)) != query.get("limit"):
                issue("query_limit_mismatch", query_path, "Executable SQL row limit differs from its query presentation.")

    for key, control in controls.items():
        if not isinstance(control, dict) or set(control) != {"config", "map"}:
            issue("invalid_control", path, "Controls require explicit typed configuration and tile scope.")
            continue
        config, scope = control["config"], control["map"]
        if (not isinstance(config, dict) or config.get("id") != key or config.get("type") != "string"
                or config.get("kind") != "EQUALS" or not field_exists(config.get("fieldName"))
                or not isinstance(config.get("values"), list) or any(not isinstance(value, str) for value in config.get("values", []))):
            issue("invalid_control", path, "Control configuration has missing fields or unsupported semantics.")
        if not isinstance(scope, dict) or set(scope) != set(tiles) or any(value is not False and not field_exists(value) for value in scope.values()):
            issue("invalid_control_scope", path, "Every control must explicitly include or exclude each existing tile.")

    containers = document.get("containers")
    if not isinstance(containers, list) or not containers:
        issue("missing_layout", path, "Document requires concrete page/layout containers.")
        containers = []
    instance_keys, stacks, filters, charts = set(), {}, [], []
    page_rectangles = {}

    def visit(node, page=None):
        if not isinstance(node, dict):
            issue("invalid_layout", path, "Layout children must be structured objects.")
            return
        identity = node.get("instanceKey")
        if not isinstance(identity, str) or not identity or identity in instance_keys:
            issue("duplicate_layout_identity", path, "Layout instance identities must be nonempty and unique.")
        else:
            instance_keys.add(identity)
        kind = node.get("containerType")
        if kind == "page":
            visit(node.get("container"), identity)
            return
        if kind in {"grid", "stack"}:
            attached = node.get("metadata", {}).get("attachedQueryKey") if isinstance(node.get("metadata", {}), dict) else None
            if attached is not None:
                if attached not in tiles or attached in stacks:
                    issue("invalid_tile_layout", path, "Layout stack must attach to one existing unique tile.")
                layout = node.get("gridPosition")
                if (not isinstance(layout, dict) or set(layout) != {"x", "y", "w", "h"}
                        or any(type(value) is not int for value in layout.values())
                        or layout.get("x", -1) < 0 or layout.get("y", -1) < 0
                        or layout.get("w", 0) <= 0 or layout.get("h", 0) <= 0
                        or layout.get("x", 24) + layout.get("w", 1) > 24):
                    issue("invalid_grid_position", path, "Tile layout must fit a positive 24-column grid.")
                else:
                    for other in page_rectangles.setdefault(page, []):
                        if (layout["x"] < other["x"] + other["w"] and other["x"] < layout["x"] + layout["w"]
                                and layout["y"] < other["y"] + other["h"] and other["y"] < layout["y"] + layout["h"]):
                            issue("overlapping_tiles", path, "Tile rectangles overlap within the same page.")
                    page_rectangles[page].append(layout)
                    stacks[attached] = layout
            children = node.get("children")
            if not isinstance(children, list) or not children:
                issue("empty_layout_container", path, "Layout containers cannot be empty placeholders.")
            else:
                for child in children:
                    visit(child, page)
        elif node.get("type") == "filter":
            filters.append(node.get("id"))
        elif node.get("type") == "query":
            if node.get("id") not in tiles:
                issue("missing_layout_query", path, "Layout references a missing query presentation.")
            if node.get("as") == "chart":
                charts.append(node.get("id"))
        else:
            issue("unsupported_layout", path, "Unknown layout children require explicit supported implementation.")
    for container in containers:
        visit(container)
    visible_controls = {key for key, value in controls.items()
                        if not isinstance(value, dict) or value.get("config", {}).get("hidden") is not True}
    if set(stacks) != set(tiles) or sorted(charts) != sorted(tiles) or sorted(filters) != sorted(visible_controls):
        issue("incomplete_layout", path, "Every tile and control must be represented exactly once in the layout.")
    _validate_source_context(parsed.get("source.json", {}), document, mappings, denominator, stacks, raw_files, issue)


def _validate_source_context(source, document, mappings, denominator, stacks, raw_files, issue):
    context = source.get("prepush_context") if isinstance(source, dict) else None
    if (not isinstance(context, dict) or context.get("schema_version") != "sigma-prepush-context.v1"
            or context.get("source_sha256") != _canonical_sha({key: value for key, value in source.items() if key not in {"prepush_context", "_migration_scope"}})):
        issue("stale_source_context", "source.json", "Display/control context must bind the exact captured source revision.")
        return
    by_source = {}
    field_locators = {}
    for mapping in mappings:
        if not isinstance(mapping, dict) or not isinstance(mapping.get("source_path"), str):
            continue
        pointer = mapping["source_path"]
        native = denominator.get(pointer, {}).get("source_id")
        if mapping.get("target_path") == "omni/document.create.json":
            by_source[native] = mapping.get("target_object_ref")
        match = re.fullmatch(r"/dataModels/(\d+)/spec/pages/(\d+)/elements/(\d+)/(columns|metrics)/(\d+)", pointer)
        reuse_ref = mapping.get("target_path") == "target.json" and str(mapping.get("target_object_ref")).startswith("existing-topic-field:")
        if match and (str(mapping.get("target_path")).endswith(".view") or reuse_ref):
            di, pi, ei, kind, _ = match.groups()
            dm = source["dataModels"][int(di)]
            element = dm["spec"]["pages"][int(pi)]["elements"][int(ei)]
            dm_id, element_id = dm.get("dataModelId", dm.get("id")), element.get("elementId", element.get("id"))
            locator = f"data-model:{dm_id}/element:{element_id}/{'column' if kind == 'columns' else 'metric'}:{native}"
            reference = mapping.get("target_object_ref")
            field_locators[locator] = reference.removeprefix("existing-topic-field:") if reuse_ref else reference
    tiles = document.get("queryPresentations", {}).get("data", {})
    controls = document.get("controls", {}).get("data", {})
    try:
        scope = validate_scope(source)
    except (ValueError, TypeError, KeyError, AttributeError):
        scope = None
    element_keys = {}
    for identity, setting in context.get("elements", {}).items():
        if scope and identity not in scope["selected_chart_ids"]:
            continue
        ref = by_source.get(identity)
        if not isinstance(setting, dict) or not isinstance(ref, str) or not ref.startswith("queryPresentations.data."):
            issue("unmapped_context_element", "source.json", "A reviewed element lacks its exact persisted query mapping.")
            continue
        key = ref.removeprefix("queryPresentations.data.")
        element_keys[identity] = key
        tile = tiles.get(key, {})
        expected = [field_locators.get(locator) for locator in setting.get("field_locators", [])]
        actual = tile.get("query", {}).get("fields", [])
        if None in expected or len(expected) != len(actual) or set(expected) != set(actual):
            issue("source_query_fields_changed", "source.json", "Query fields differ from the reviewed source field identities.")
        if setting.get("layout") != stacks.get(key) or setting.get("chart_type") != tile.get("visConfig", {}).get("chartType"):
            issue("source_layout_changed", "source.json", "Persisted visual/layout differs from reviewed source intent.")
    for identity, setting in context.get("controls", {}).items():
        if scope and identity not in scope["required_control_ids"]:
            continue
        ref = by_source.get(identity)
        if not isinstance(setting, dict) or not isinstance(ref, str) or not ref.startswith("controls.data."):
            issue("unmapped_context_control", "source.json", "A reviewed control lacks its persisted target mapping.")
            continue
        control = controls.get(ref.removeprefix("controls.data."), {})
        field = field_locators.get(setting.get("field_locator"))
        targets = setting.get("target_element_ids", [])
        if scope:
            targets = [identity for identity in targets if identity in scope["selected_chart_ids"]]
        affected = {element_keys.get(identity) for identity in targets}
        expected_map = {key: field if key in affected else False for key in tiles}
        if (None in affected or field is None or control.get("map") != expected_map
                or control.get("config", {}).get("fieldName") != field
                or control.get("config", {}).get("values") != setting.get("values")):
            issue("source_control_scope_changed", "source.json", "Control scope/defaults differ from reviewed source behavior, including excluded global tiles.")
    for key in tiles:
        expected_filtered = any(isinstance(control, dict) and control.get("map", {}).get(key) is not False
                                and control.get("config", {}).get("values") for control in controls.values())
        raw = raw_files.get(f"queries/{key}.sql")
        if raw is not None:
            try:
                tokens = _sql_tokens(raw.decode("utf-8"))
            except (ValueError, UnicodeError):
                issue("invalid_sql", f"queries/{key}.sql", "SQL is outside the supported read-only grammar.")
                continue
            # WHERE is deliberately distinct from CASE-filtered measures.
            actual_filtered = any(token.upper() == "WHERE" for token in tokens)
            if bool(expected_filtered) != actual_filtered:
                issue("query_control_effect_mismatch", f"queries/{key}.sql", "SQL business-filter presence differs from the explicit control-to-tile scope.")


def _validate_reuse_lineage(source, target, mappings, issue):
    """Check persisted lineage against the imported mappings, without compilation."""
    fields = source_fields(source)
    expected_by_path = {path: (locator, raw, kind) for locator, (path, raw, kind) in fields.items()}
    profile = target.get("existing_topic", {}).get("field_mappings", {})
    definitions = target.get("existing_topic", {}).get("inventory", {}).get("fields", {})
    for mapping in mappings:
        pointer = mapping.get("source_path")
        if pointer not in expected_by_path:
            continue
        locator, raw, kind = expected_by_path[pointer]
        binding = profile.get(locator, {})
        reference = binding.get("target_field")
        if (mapping.get("target_path") != "target.json"
                or mapping.get("target_object_ref") != "existing-topic-field:" + str(reference)):
            issue("inconsistent_topic_lineage", str(pointer), "Source field lineage differs from the exact reviewed existing Topic mapping.")
        definition = definitions.get(reference, {})
        if kind == "metrics" and definition.get("kind") != "measure":
            issue("incompatible_topic_kind", str(pointer), "A captured metric cannot map to a target dimension.")
        if "hidden" in raw and raw["hidden"] != definition.get("hidden"):
            issue("visibility_changed", str(pointer), "Existing Topic visibility differs from the source field.")


def _validate_reuse_queries(parsed, target, issue):
    document = parsed.get("omni/document.create.json", {})
    topic = target.get("existing_topic", {}).get("inventory", {})
    tiles = document.get("queryPresentations", {}).get("data", {})
    controls = document.get("controls", {}).get("data", {})
    expected_paths = {f"queries/{key}.json" for key in tiles}
    actual_paths = {name for name in parsed if name.startswith("queries/")}
    if expected_paths != actual_paths or not expected_paths:
        issue("existing_topic_query_inventory", "queries", "Existing-topic query artifacts must correspond exactly to persisted dashboard tiles.")
    for key, tile in tiles.items():
        path = f"queries/{key}.json"
        query = parsed.get(path)
        defaults = [{"field": control["map"][key], "kind": control["config"]["kind"], "values": control["config"]["values"]}
                    for control in controls.values() if control.get("map", {}).get(key) is not False]
        expected = {"schema_version": "omni-existing-topic-query.v1", "model_id": target.get("model_id"),
                    "connection_id": target.get("connection_id"), "topic_name": topic.get("topic_name"),
                    "inventory_sha256": target.get("existing_topic", {}).get("inventory_sha256"),
                    "query": tile.get("query"), "control_defaults": defaults}
        if query != expected:
            issue("existing_topic_query_mismatch", path, "Typed query, target identities and control defaults must match the sealed dashboard and Topic evidence.")
        if (tile.get("topicName") != topic.get("topic_name")
                or tile.get("query", {}).get("table") != topic.get("base_view")):
            issue("wrong_existing_topic", path, "Queries must use the exact imported Topic and its base view.")


def _validate_queries(raw_files, parsed, target, views, route, issue):
    if not any(name.startswith("queries/") and name.endswith(".sql") for name in raw_files):
        issue("missing_queries", "queries", "Package requires executable query artifacts.")
    relations = target.get("relations", {}) if isinstance(target, dict) else {}
    if not isinstance(relations, dict) or not relations:
        issue("missing_relation_bindings", "target.json", "Explicit reviewed physical relation bindings are required.")
        return
    relation_columns = {}
    for locator, binding in relations.items():
        if not isinstance(binding, dict):
            issue("invalid_relation_binding", "target.json", "Relation bindings must be structured objects.")
            continue
        schema, table, columns = (binding.get(key) for key in ("schema", "table", "columns"))
        if (not isinstance(schema, str) or not _IDENTIFIER.fullmatch(schema)
                or not isinstance(table, str) or not _IDENTIFIER.fullmatch(table)
                or not isinstance(columns, dict) or not columns
                or any(not isinstance(column, str) or not _IDENTIFIER.fullmatch(column) for column in columns.values())):
            issue("invalid_relation_binding", "target.json", "Bindings require safe schema/table/column identifiers.")
            continue
        relation_columns.setdefault((schema, table), set()).update(columns.values())
    connection = sqlite3.connect(":memory:")

    def quote(value):
        return '"' + value.replace('"', '""') + '"'

    def compile_query(sql, path):
        errors = []
        _validate_sql(sql, path, lambda *entry: errors.append(entry))
        for entry in errors:
            issue(*entry)
        if errors:
            return False
        parameters = {name: None for name in re.findall(r":([A-Za-z_][A-Za-z0-9_]*)", sql)}
        try:
            connection.execute("EXPLAIN " + _sqlite_sql(sql), parameters).fetchall()
        except (sqlite3.Error, ValueError):
            issue("query_schema_error", path, "SQL does not compile against the captured column bindings in the supported offline dialect.")
            return False
        return True

    try:
        for schema in sorted({item[0] for item in relation_columns}):
            if schema not in {"main", "temp"}:
                connection.execute("ATTACH DATABASE ':memory:' AS " + quote(schema))
        for (schema, table), columns in relation_columns.items():
            statement = "CREATE TABLE " + quote(schema) + "." + quote(table)
            statement += " (" + ", ".join(quote(column) for column in sorted(columns)) + ")"
            connection.execute(statement)
        dbt_relations = {}
        for path, raw in raw_files.items():
            if not path.startswith("dbt/models/") or not path.endswith(".sql"):
                continue
            sql, config = _dbt_model_sql(raw, path, issue)
            if not config:
                continue
            alias = PurePosixPath(path).stem
            dbt_relations[alias] = (config["schema"], config["alias"])
            if not compile_query(sql, path):
                continue
            if (config["schema"], config["alias"]) in relation_columns:
                issue("modeled_relation_collision", path, "Modeled output cannot overwrite its source relation.")
                continue
            if not any(isinstance(binding, dict) and binding.get("schema") == config["schema"]
                       and binding.get("modeled_table") == config["alias"] for binding in relations.values()):
                issue("unbound_modeled_relation", path, "dbt output differs from the reviewed modeled relation.")
                continue
            try:
                connection.execute("CREATE VIEW " + quote(config["schema"]) + "." + quote(config["alias"]) + " AS " + _sqlite_sql(sql))
            except sqlite3.Error:
                issue("invalid_modeled_view", path, "Generated data-layer relation could not be defined in the offline scratch schema.")
        for path, raw in raw_files.items():
            if path.startswith("queries/") and path.endswith(".sql"):
                compile_query(raw.decode("utf-8"), path)
            elif path.startswith("dbt/tests/") and path.endswith(".sql"):
                sql = raw.decode("utf-8")

                def replace_ref(match):
                    relation = dbt_relations.get(match.group(1))
                    if relation is None:
                        issue("missing_dbt_ref", path, "Data-layer test references an unemitted dbt model.")
                        return "__unresolved_model__"
                    return quote(relation[0]) + "." + quote(relation[1])

                sql = re.sub(r"\{\{\s*ref\(['\"]([A-Za-z_][A-Za-z0-9_]*)['\"]\)\s*\}\}", replace_ref, sql)
                compile_query(sql, path)
            elif path.startswith("dbt/macros/") and path.endswith(".sql"):
                _validate_dbt_macro(raw.decode("utf-8"), path, issue)
        for alias, view in views.items():
            body = view["body"]
            schema, table = body.get("schema"), body.get("table_name")
            expected = relation_columns if route == "omni_semantic_reconstruction" else set(dbt_relations.values())
            if not isinstance(schema, str) or not isinstance(table, str) or (schema, table) not in expected:
                issue("unbound_view_relation", view["path"], "Omni view does not bind an explicitly reviewed relation.")
                continue
            # Expressions are read back from YAML, independently parsed by SQLite.
            # A semantic substitution is resolved only to known emitted field names.
            for name, field in body.get("dimensions", {}).items():
                if not isinstance(field, dict):
                    continue
                expression = field.get("sql", quote(name))
                if not isinstance(expression, str):
                    continue
                expression = _REFERENCE.sub(lambda match: quote(match.group(1).split(".")[-1]), expression)
                compile_query("SELECT " + expression + " FROM " + quote(schema) + "." + quote(table), view["path"])
    except sqlite3.Error:
        issue("invalid_scratch_schema", "target.json", "Reviewed relation bindings cannot form an unambiguous offline schema.")
    finally:
        connection.close()


def _dbt_model_sql(raw, path, issue):
    sql = raw.decode("utf-8")
    match = re.match(r"\s*\{\{\s*config\((.*?)\)\s*\}\}\s*", sql, re.S)
    if not match:
        issue("missing_dbt_config", path, "dbt models must explicitly declare their reviewed materialization/schema/alias.")
        return sql, None
    try:
        call = ast.parse("config(" + match.group(1) + ")", mode="eval").body
        if not isinstance(call, ast.Call) or call.args:
            raise ValueError("invalid config")
        values = {}
        for keyword in call.keywords:
            if keyword.arg in values or keyword.arg is None or not isinstance(keyword.value, ast.Constant) or not isinstance(keyword.value.value, str):
                raise ValueError("invalid config value")
            values[keyword.arg] = keyword.value.value
        if (set(values) != {"materialized", "schema", "alias"} or values["materialized"] != "view"
                or not _IDENTIFIER.fullmatch(values["schema"]) or not _IDENTIFIER.fullmatch(values["alias"])):
            raise ValueError("unsupported config")
    except (ValueError, SyntaxError):
        issue("unsafe_dbt_config", path, "Only static, reviewed view/schema/alias configuration is supported.")
        return sql, None
    return sql[match.end():], values


def _validate_dbt_macro(sql, path, issue):
    # Only the non-executing custom-schema name projection belongs in this kit.
    normalized = re.sub(r"\s+", "", sql)
    permitted = {
        "{%macrogenerate_schema_name(custom_schema_name,node)%}{{custom_schema_name}}{%endmacro%}",
        "{%macrogenerate_schema_name(custom_schema_name,node)-%}{{custom_schema_name}}{%-endmacro%}",
        "{%macrogenerate_schema_name(custom_schema_name,node)-%}{{custom_schema_nameifcustom_schema_nameisnotnoneelsetarget.schema}}{%-endmacro%}",
    }
    if normalized not in permitted:
        issue("unsupported_dbt_macro", path, "Unreviewed dbt macro logic or executable Jinja cannot pass offline preflight.")

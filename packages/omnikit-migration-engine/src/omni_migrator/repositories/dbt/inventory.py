"""Read-only, fail-closed dbt repository inventory.

This module consumes already-generated dbt artifacts and repository source files.  It
never invokes dbt, git, Jinja, Python, a warehouse adapter, project hooks, or macros.
Repository identity is supplied as an external immutable attestation and is preserved
with raw-file hashes in the resulting inventory contract.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping, Sequence

from pydantic import ValidationError

from omni_migrator.control_plane.canonical import canonical_json, sha256_json
from omni_migrator.repositories.dbt.models import (
    SUPPORTED_ARTIFACT_SCHEMA_VERSIONS,
    ArtifactFileRecord,
    RepositoryIdentity,
    RepositoryInventory,
    SecurityMetadata,
    repository_inventory_hash,
    resource_record_hash,
)


DEFAULT_MAX_ARTIFACT_BYTES = 256 * 1024 * 1024
DEFAULT_MAX_SOURCE_BYTES = 32 * 1024 * 1024


class RepositoryInventoryError(ValueError):
    """A sanitized, deterministic inventory failure."""

    def __init__(self, code: str, message: str, *, subject: str | None = None) -> None:
        self.code = code
        self.subject = subject
        suffix = f" ({subject})" if subject else ""
        super().__init__(f"{code}: {message}{suffix}")


@dataclass(frozen=True)
class _LoadedFile:
    relative_path: str
    content: bytes
    content_hash: str


@dataclass(frozen=True)
class _LoadedArtifact:
    artifact_type: str
    record: dict[str, Any]
    payload: Mapping[str, Any]


def _hash_bytes(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _hash_text(value: str) -> str:
    return _hash_bytes(value.encode("utf-8"))


def _canonical_hash(value: Any) -> str:
    return f"sha256:{sha256_json(value)}"


def _short_identity(prefix: str, value: Any) -> str:
    return f"{prefix}.{sha256_json(value)[:20]}"


def _validate_relative_posix_path(value: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value or "\\" in value:
        raise RepositoryInventoryError(
            "unsafe_repository_path", "path must be a non-empty relative POSIX path"
        )
    path = PurePosixPath(value)
    if path.is_absolute() or value.startswith(("/", "\\")):
        raise RepositoryInventoryError(
            "unsafe_repository_path", "absolute repository paths are forbidden", subject=value
        )
    if any(part in {"", ".", ".."} for part in value.split("/")):
        raise RepositoryInventoryError(
            "unsafe_repository_path",
            "dot, parent, and empty path segments are forbidden",
            subject=value,
        )
    return value


def _resolve_project_root(project_root: str | Path) -> Path:
    candidate = Path(project_root)
    try:
        if candidate.is_symlink():
            raise RepositoryInventoryError(
                "unsafe_repository_root", "a symlink cannot be used as the repository root"
            )
        resolved = candidate.resolve(strict=True)
    except RepositoryInventoryError:
        raise
    except OSError as exc:
        raise RepositoryInventoryError(
            "repository_root_unavailable", "repository root is unavailable"
        ) from exc
    if not resolved.is_dir():
        raise RepositoryInventoryError(
            "repository_root_unavailable", "repository root must be a directory"
        )
    return resolved


def _secure_file_path(root: Path, relative_path: str, *, required: bool) -> Path | None:
    relative_path = _validate_relative_posix_path(relative_path)
    current = root
    parts = relative_path.split("/")
    for index, part in enumerate(parts):
        current = current / part
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            if not required:
                return None
            raise RepositoryInventoryError(
                "repository_file_missing", "required repository file is missing", subject=relative_path
            ) from None
        except OSError as exc:
            raise RepositoryInventoryError(
                "repository_file_unavailable",
                "repository file cannot be inspected",
                subject=relative_path,
            ) from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise RepositoryInventoryError(
                "repository_symlink_forbidden",
                "repository file paths cannot traverse symlinks",
                subject=relative_path,
            )
        is_leaf = index == len(parts) - 1
        if not is_leaf and not stat.S_ISDIR(metadata.st_mode):
            raise RepositoryInventoryError(
                "repository_path_not_directory",
                "a repository path ancestor is not a directory",
                subject=relative_path,
            )
        if is_leaf and not stat.S_ISREG(metadata.st_mode):
            raise RepositoryInventoryError(
                "repository_file_not_regular",
                "repository input must be a regular file",
                subject=relative_path,
            )
    try:
        current.resolve(strict=True).relative_to(root)
    except (OSError, ValueError) as exc:
        raise RepositoryInventoryError(
            "repository_path_escape", "repository path resolves outside the project", subject=relative_path
        ) from exc
    return current


def _read_file(
    root: Path,
    relative_path: str,
    *,
    required: bool,
    max_bytes: int,
) -> _LoadedFile | None:
    if max_bytes < 1:
        raise RepositoryInventoryError("invalid_size_limit", "file-size limits must be positive")
    path = _secure_file_path(root, relative_path, required=required)
    if path is None:
        return None
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise RepositoryInventoryError(
                "repository_file_not_regular",
                "repository input must be a regular file",
                subject=relative_path,
            )
        if before.st_size > max_bytes:
            raise RepositoryInventoryError(
                "repository_file_too_large",
                "repository input exceeds the configured size limit",
                subject=relative_path,
            )
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        content = b"".join(chunks)
        if len(content) > max_bytes:
            raise RepositoryInventoryError(
                "repository_file_too_large",
                "repository input exceeds the configured size limit",
                subject=relative_path,
            )
        after = os.fstat(descriptor)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise RepositoryInventoryError(
                "repository_file_changed",
                "repository input changed during acquisition",
                subject=relative_path,
            )
    except RepositoryInventoryError:
        raise
    except OSError as exc:
        raise RepositoryInventoryError(
            "repository_file_unavailable", "repository file cannot be read", subject=relative_path
        ) from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
    return _LoadedFile(relative_path, content, _hash_bytes(content))


def _reject_duplicate_object_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RepositoryInventoryError(
                "duplicate_json_key", "JSON objects cannot contain duplicate keys"
            )
        result[key] = value
    return result


def _reject_non_finite_number(value: str) -> None:
    raise RepositoryInventoryError(
        "non_finite_json_number", "JSON artifacts cannot contain NaN or infinity"
    )


def _parse_json(loaded: _LoadedFile) -> Mapping[str, Any]:
    try:
        text = loaded.content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RepositoryInventoryError(
            "artifact_not_utf8", "artifact must use UTF-8", subject=loaded.relative_path
        ) from exc
    try:
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_object_keys,
            parse_constant=_reject_non_finite_number,
        )
    except RepositoryInventoryError:
        raise
    except (json.JSONDecodeError, RecursionError) as exc:
        raise RepositoryInventoryError(
            "artifact_invalid_json", "artifact is not valid bounded JSON", subject=loaded.relative_path
        ) from exc
    if not isinstance(value, Mapping):
        raise RepositoryInventoryError(
            "artifact_invalid_root", "artifact root must be a JSON object", subject=loaded.relative_path
        )
    return value


def _mapping(value: Any, *, label: str, required: bool = True) -> Mapping[str, Any]:
    if value is None and not required:
        return {}
    if not isinstance(value, Mapping):
        raise RepositoryInventoryError("artifact_shape_invalid", f"{label} must be an object")
    return value


def _sequence(value: Any, *, label: str, required: bool = True) -> Sequence[Any]:
    if value is None and not required:
        return []
    if not isinstance(value, list):
        raise RepositoryInventoryError("artifact_shape_invalid", f"{label} must be an array")
    return value


def _optional_string(value: Any, *, label: str) -> str | None:
    if value is None or value == "":
        return None
    if not isinstance(value, str):
        raise RepositoryInventoryError("artifact_shape_invalid", f"{label} must be a string")
    return value


def _required_string(value: Any, *, label: str) -> str:
    result = _optional_string(value, label=label)
    if result is None:
        raise RepositoryInventoryError("artifact_shape_invalid", f"{label} is required")
    return result


def _load_artifact(
    root: Path,
    *,
    artifact_type: str,
    relative_path: str,
    required: bool,
    max_bytes: int,
    declared_schema_version: str | None = None,
) -> _LoadedArtifact | None:
    loaded = _read_file(root, relative_path, required=required, max_bytes=max_bytes)
    if loaded is None:
        return None
    payload = _parse_json(loaded)
    metadata = _mapping(payload.get("metadata"), label=f"{artifact_type}.metadata", required=False)
    if artifact_type == "semantic_manifest":
        if declared_schema_version is None:
            raise RepositoryInventoryError(
                "semantic_manifest_profile_required",
                "semantic manifest parser profile must be declared explicitly",
                subject=relative_path,
            )
        schema_version = declared_schema_version
    else:
        schema_version = _required_string(
            metadata.get("dbt_schema_version"),
            label=f"{artifact_type}.metadata.dbt_schema_version",
        )
    if schema_version not in SUPPORTED_ARTIFACT_SCHEMA_VERSIONS[artifact_type]:
        raise RepositoryInventoryError(
            "unsupported_artifact_schema",
            f"unsupported {artifact_type} schema version",
            subject=schema_version,
        )
    record = {
        "artifact_type": artifact_type,
        "relative_path": relative_path,
        "schema_version": schema_version,
        "content_hash": loaded.content_hash,
        "byte_count": len(loaded.content),
        "generated_at": _optional_string(
            metadata.get("generated_at"), label=f"{artifact_type}.metadata.generated_at"
        ),
        "invocation_id": _optional_string(
            metadata.get("invocation_id"), label=f"{artifact_type}.metadata.invocation_id"
        ),
    }
    try:
        ArtifactFileRecord.model_validate(record)
    except ValidationError as exc:
        raise RepositoryInventoryError(
            "artifact_metadata_invalid", "artifact metadata does not satisfy the contract", subject=relative_path
        ) from exc
    return _LoadedArtifact(artifact_type, record, payload)


def _diagnostic(
    code: str,
    severity: str,
    message: str,
    *subjects: str,
) -> dict[str, Any]:
    return {
        "code": code,
        "severity": severity,
        "message": message,
        "subject_refs": sorted(set(subjects)),
    }


def _resource_entries(manifest: Mapping[str, Any]) -> tuple[dict[str, Mapping[str, Any]], list[dict[str, Any]]]:
    entries: dict[str, Mapping[str, Any]] = {}
    tests: list[dict[str, Any]] = []
    sections = (
        "nodes",
        "sources",
        "macros",
        "metrics",
        "semantic_models",
        "saved_queries",
        "unit_tests",
    )
    for section in sections:
        section_value = _mapping(manifest.get(section), label=f"manifest.{section}", required=False)
        for unique_id, raw in section_value.items():
            if not isinstance(unique_id, str) or not isinstance(raw, Mapping):
                raise RepositoryInventoryError(
                    "manifest_resource_invalid", f"manifest.{section} entries must be named objects"
                )
            nested_id = _required_string(raw.get("unique_id"), label=f"manifest.{section}.unique_id")
            if unique_id != nested_id:
                raise RepositoryInventoryError(
                    "manifest_unique_id_mismatch",
                    "manifest map key does not match nested unique_id",
                    subject=unique_id,
                )
            if unique_id in entries or any(item["unique_id"] == unique_id for item in tests):
                raise RepositoryInventoryError(
                    "manifest_unique_id_duplicate", "manifest unique_id appears more than once", subject=unique_id
                )
            resource_type = _required_string(
                raw.get("resource_type"), label=f"manifest.{section}.resource_type"
            )
            if not unique_id.startswith(f"{resource_type}."):
                raise RepositoryInventoryError(
                    "manifest_unique_id_type_mismatch",
                    "manifest unique_id prefix does not match resource_type",
                    subject=unique_id,
                )
            if resource_type in {"test", "unit_test"}:
                tests.append(dict(raw))
            else:
                entries[unique_id] = raw
    return entries, tests


def _manifest_exposures(manifest: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    result: dict[str, Mapping[str, Any]] = {}
    exposures = _mapping(manifest.get("exposures"), label="manifest.exposures", required=False)
    for unique_id, raw in exposures.items():
        if not isinstance(unique_id, str) or not isinstance(raw, Mapping):
            raise RepositoryInventoryError(
                "manifest_exposure_invalid", "manifest exposures must be named objects"
            )
        nested_id = _required_string(raw.get("unique_id"), label="manifest.exposure.unique_id")
        if nested_id != unique_id:
            raise RepositoryInventoryError(
                "manifest_unique_id_mismatch",
                "manifest exposure key does not match nested unique_id",
                subject=unique_id,
            )
        resource_type = _required_string(
            raw.get("resource_type"), label="manifest.exposure.resource_type"
        )
        if resource_type != "exposure" or not unique_id.startswith("exposure."):
            raise RepositoryInventoryError(
                "manifest_unique_id_type_mismatch",
                "manifest exposure identity does not match resource_type",
                subject=unique_id,
            )
        result[unique_id] = raw
    return result


def _manifest_dependencies(raw: Mapping[str, Any]) -> list[str]:
    depends_on = _mapping(raw.get("depends_on"), label="resource.depends_on", required=False)
    result: list[str] = []
    for kind in ("nodes", "macros"):
        values = _sequence(depends_on.get(kind), label=f"resource.depends_on.{kind}", required=False)
        for value in values:
            if not isinstance(value, str) or not value:
                raise RepositoryInventoryError(
                    "manifest_dependency_invalid", "manifest dependencies must be non-empty strings"
                )
            result.append(value)
    return sorted(set(result))


def _manifest_meta(raw: Mapping[str, Any]) -> Mapping[str, Any]:
    direct = _mapping(raw.get("meta"), label="resource.meta", required=False)
    config = _mapping(raw.get("config"), label="resource.config", required=False)
    configured = _mapping(config.get("meta"), label="resource.config.meta", required=False)
    return {**configured, **direct}


def _owner_name(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        return value or None
    if isinstance(value, Mapping):
        for key in ("name", "email"):
            candidate = value.get(key)
            if isinstance(candidate, str) and candidate:
                return candidate
    raise RepositoryInventoryError("artifact_shape_invalid", "owner must be a string or named object")


def _group_metadata(manifest: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    groups = _mapping(manifest.get("groups"), label="manifest.groups", required=False)
    result: dict[str, Mapping[str, Any]] = {}
    for unique_id, raw in groups.items():
        if not isinstance(unique_id, str) or not isinstance(raw, Mapping):
            raise RepositoryInventoryError("manifest_group_invalid", "manifest groups must be named objects")
        name = _required_string(raw.get("name"), label="manifest.group.name")
        if name in result:
            raise RepositoryInventoryError(
                "manifest_group_duplicate", "manifest group name appears more than once", subject=name
            )
        result[name] = raw
    return result


def _catalog_entries(
    catalog: Mapping[str, Any] | None,
    manifest_resources: Mapping[str, Mapping[str, Any]],
    diagnostics: list[dict[str, Any]],
) -> dict[str, Mapping[str, Any]]:
    if catalog is None:
        return {}
    result: dict[str, Mapping[str, Any]] = {}
    for section in ("nodes", "sources"):
        values = _mapping(catalog.get(section), label=f"catalog.{section}", required=False)
        for unique_id, raw in values.items():
            if not isinstance(unique_id, str) or not isinstance(raw, Mapping):
                raise RepositoryInventoryError(
                    "catalog_entry_invalid", f"catalog.{section} entries must be named objects"
                )
            nested_id = raw.get("unique_id")
            if nested_id is not None and nested_id != unique_id:
                raise RepositoryInventoryError(
                    "catalog_unique_id_mismatch",
                    "catalog map key does not match nested unique_id",
                    subject=unique_id,
                )
            if unique_id in result:
                raise RepositoryInventoryError(
                    "catalog_unique_id_duplicate", "catalog unique_id appears more than once", subject=unique_id
                )
            if unique_id not in manifest_resources:
                diagnostics.append(
                    _diagnostic(
                        "catalog_orphan_unique_id",
                        "blocking",
                        "Catalog entry has no canonical manifest resource.",
                        unique_id,
                    )
                )
                continue
            expected_section = (
                "sources" if manifest_resources[unique_id].get("resource_type") == "source" else "nodes"
            )
            if section != expected_section:
                diagnostics.append(
                    _diagnostic(
                        "catalog_namespace_mismatch",
                        "blocking",
                        "Catalog entry is in the wrong resource namespace.",
                        unique_id,
                    )
                )
                continue
            result[unique_id] = raw
    return result


def _run_result_entries(
    run_results: Mapping[str, Any] | None,
    manifest_resources: Mapping[str, Mapping[str, Any]],
    manifest_tests: Sequence[Mapping[str, Any]],
    diagnostics: list[dict[str, Any]],
) -> dict[str, Mapping[str, Any]]:
    if run_results is None:
        return {}
    known = set(manifest_resources) | {str(item["unique_id"]) for item in manifest_tests}
    result: dict[str, Mapping[str, Any]] = {}
    for raw in _sequence(run_results.get("results"), label="run_results.results"):
        if not isinstance(raw, Mapping):
            raise RepositoryInventoryError(
                "run_result_invalid", "run_results.results entries must be objects"
            )
        unique_id = _required_string(raw.get("unique_id"), label="run_result.unique_id")
        if unique_id in result:
            raise RepositoryInventoryError(
                "run_result_unique_id_duplicate",
                "run result unique_id appears more than once",
                subject=unique_id,
            )
        if unique_id not in known:
            diagnostics.append(
                _diagnostic(
                    "run_result_orphan_unique_id",
                    "blocking",
                    "Run result has no canonical manifest resource.",
                    unique_id,
                )
            )
            continue
        result[unique_id] = raw
    return result


def _catalog_columns(raw: Mapping[str, Any] | None) -> dict[str, Mapping[str, Any]]:
    if raw is None:
        return {}
    columns = raw.get("columns")
    result: dict[str, Mapping[str, Any]] = {}
    if columns is None:
        return result
    if isinstance(columns, Mapping):
        iterable: Iterable[tuple[Any, Any]] = columns.items()
    elif isinstance(columns, list):
        iterable = ((item.get("name") if isinstance(item, Mapping) else None, item) for item in columns)
    else:
        raise RepositoryInventoryError("catalog_columns_invalid", "catalog columns must be an object or array")
    for key, value in iterable:
        if not isinstance(key, str) or not key or not isinstance(value, Mapping):
            raise RepositoryInventoryError("catalog_columns_invalid", "catalog columns must be named objects")
        name = value.get("name", key)
        if not isinstance(name, str) or name != key:
            raise RepositoryInventoryError(
                "catalog_column_name_mismatch", "catalog column key does not match its name"
            )
        if name in result:
            raise RepositoryInventoryError(
                "catalog_column_duplicate", "catalog column name appears more than once", subject=name
            )
        result[name] = value
    return result


def _columns(raw: Mapping[str, Any], catalog: Mapping[str, Any] | None) -> list[dict[str, Any]]:
    declared = _mapping(raw.get("columns"), label="resource.columns", required=False)
    observed = _catalog_columns(catalog)
    names = sorted(set(declared) | set(observed))
    result: list[dict[str, Any]] = []
    for name in names:
        declared_column = _mapping(declared.get(name), label="resource.column", required=False)
        catalog_column = observed.get(name, {})
        data_type = declared_column.get("data_type") or catalog_column.get("type")
        description = declared_column.get("description") or catalog_column.get("comment")
        ordinal = catalog_column.get("index")
        if data_type is not None and not isinstance(data_type, str):
            raise RepositoryInventoryError("column_metadata_invalid", "column data type must be a string")
        if description is not None and not isinstance(description, str):
            raise RepositoryInventoryError("column_metadata_invalid", "column description must be a string")
        if ordinal is not None and (not isinstance(ordinal, int) or isinstance(ordinal, bool) or ordinal < 0):
            raise RepositoryInventoryError("column_metadata_invalid", "column ordinal must be non-negative")
        result.append(
            {
                "name": name,
                "data_type": data_type,
                "description": description,
                "ordinal": ordinal,
            }
        )
    return result


def _source_kind(path: str, referenced_types: set[str]) -> str:
    lower = path.lower()
    suffix = PurePosixPath(lower).suffix
    if lower in {"dbt_project.yml", "dbt_project.yaml"}:
        return "project_config"
    if suffix == ".py":
        return "python"
    if suffix == ".md":
        return "markdown"
    if suffix in {".csv", ".tsv"} or lower.startswith("seeds/"):
        return "seed"
    if suffix == ".sql":
        if lower.startswith("macros/") or "macro" in referenced_types:
            return "macro"
        if lower.startswith("tests/") or referenced_types & {"test", "unit_test"}:
            return "test"
        return "sql"
    if suffix in {".yml", ".yaml"}:
        if "exposure" in referenced_types:
            return "exposure"
        if referenced_types & {"test", "unit_test"}:
            return "test"
        return "yaml"
    return "other"


def _source_files(
    root: Path,
    resources: Mapping[str, Mapping[str, Any]],
    tests: Sequence[Mapping[str, Any]],
    exposures: Mapping[str, Mapping[str, Any]],
    additional_source_paths: Sequence[str],
    diagnostics: list[dict[str, Any]],
    *,
    max_bytes: int,
) -> tuple[list[dict[str, Any]], dict[str, str]]:
    references: dict[str, set[str]] = defaultdict(set)
    types: dict[str, set[str]] = defaultdict(set)
    for unique_id, raw in list(resources.items()) + list(exposures.items()):
        path = raw.get("original_file_path")
        if path is None:
            continue
        path = _required_string(path, label="resource.original_file_path")
        _validate_relative_posix_path(path)
        references[path].add(unique_id)
        types[path].add(str(raw.get("resource_type")))
    for raw in tests:
        path = raw.get("original_file_path")
        if path is None:
            continue
        path = _required_string(path, label="test.original_file_path")
        _validate_relative_posix_path(path)
        unique_id = _required_string(raw.get("unique_id"), label="test.unique_id")
        references[path].add(unique_id)
        types[path].add(str(raw.get("resource_type")))
    for path in additional_source_paths:
        path = _validate_relative_posix_path(path)
        references.setdefault(path, set())
    if _secure_file_path(root, "dbt_project.yml", required=False) is not None:
        references.setdefault("dbt_project.yml", set())
    result: list[dict[str, Any]] = []
    hashes: dict[str, str] = {}
    for path in sorted(references):
        loaded = _read_file(root, path, required=False, max_bytes=max_bytes)
        if loaded is None:
            diagnostics.append(
                _diagnostic(
                    "source_file_missing",
                    "warning",
                    "Manifest-referenced source file was not present in the attested repository.",
                    path,
                    *references[path],
                )
            )
            continue
        hashes[path] = loaded.content_hash
        result.append(
            {
                "relative_path": path,
                "file_kind": _source_kind(path, types[path]),
                "content_hash": loaded.content_hash,
                "byte_count": len(loaded.content),
                "referenced_by_unique_ids": sorted(references[path]),
            }
        )
    return result, hashes


def _constraint_records(resources: Mapping[str, Mapping[str, Any]]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    seen_material: set[str] = set()
    for unique_id, raw in resources.items():
        declarations: list[tuple[str | None, Mapping[str, Any]]] = []
        for constraint in _sequence(raw.get("constraints"), label="resource.constraints", required=False):
            if not isinstance(constraint, Mapping):
                raise RepositoryInventoryError(
                    "constraint_invalid", "resource constraints must be objects", subject=unique_id
                )
            declarations.append((None, constraint))
        columns = _mapping(raw.get("columns"), label="resource.columns", required=False)
        for column_name, column in columns.items():
            if not isinstance(column_name, str) or not isinstance(column, Mapping):
                raise RepositoryInventoryError(
                    "constraint_invalid", "resource columns must be named objects", subject=unique_id
                )
            for constraint in _sequence(
                column.get("constraints"), label="resource.column.constraints", required=False
            ):
                if not isinstance(constraint, Mapping):
                    raise RepositoryInventoryError(
                        "constraint_invalid", "column constraints must be objects", subject=unique_id
                    )
                declarations.append((column_name, constraint))
        for column_name, constraint in declarations:
            constraint_type = _required_string(constraint.get("type"), label="constraint.type")
            columns_value = _sequence(constraint.get("columns"), label="constraint.columns", required=False)
            normalized_columns: list[str] = []
            for column in columns_value:
                if not isinstance(column, str) or not column:
                    raise RepositoryInventoryError(
                        "constraint_invalid", "constraint columns must be non-empty strings"
                    )
                normalized_columns.append(column)
            expression = _optional_string(constraint.get("expression"), label="constraint.expression")
            material = {
                "resource_unique_id": unique_id,
                "column_name": column_name,
                "constraint_type": constraint_type,
                "name": _optional_string(constraint.get("name"), label="constraint.name"),
                "columns": sorted(set(normalized_columns)),
                "expression_hash": _hash_text(expression) if expression is not None else None,
                "warn_unenforced": constraint.get("warn_unenforced"),
                "warn_unsupported": constraint.get("warn_unsupported"),
            }
            for flag in ("warn_unenforced", "warn_unsupported"):
                if material[flag] is not None and not isinstance(material[flag], bool):
                    raise RepositoryInventoryError(
                        "constraint_invalid", f"constraint {flag} must be boolean"
                    )
            fingerprint = canonical_json(material)
            if fingerprint in seen_material:
                raise RepositoryInventoryError(
                    "constraint_duplicate", "identical constraint is declared more than once", subject=unique_id
                )
            seen_material.add(fingerprint)
            result.append({"constraint_id": _short_identity("constraint", material), **material})
    return sorted(result, key=lambda item: item["constraint_id"])


def _test_records(
    tests: Sequence[Mapping[str, Any]],
    run_results: Mapping[str, Mapping[str, Any]],
    resource_ids: set[str],
    source_hashes: Mapping[str, str],
    diagnostics: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for raw in tests:
        unique_id = str(raw["unique_id"])
        dependencies = _manifest_dependencies(raw)
        targets = sorted(dependency for dependency in dependencies if dependency in resource_ids)
        missing = sorted(dependency for dependency in dependencies if dependency not in resource_ids)
        if missing:
            diagnostics.append(
                _diagnostic(
                    "test_target_unresolved",
                    "blocking",
                    "Test references resources absent from the canonical manifest inventory.",
                    unique_id,
                    *missing,
                )
            )
        if not targets:
            diagnostics.append(
                _diagnostic(
                    "test_without_resolved_target",
                    "blocking",
                    "Test has no resolvable resource target and was omitted.",
                    unique_id,
                )
            )
            continue
        metadata = _mapping(raw.get("test_metadata"), label="test.test_metadata", required=False)
        kwargs = _mapping(metadata.get("kwargs"), label="test.test_metadata.kwargs", required=False)
        config = _mapping(raw.get("config"), label="test.config", required=False)
        original_path = _optional_string(raw.get("original_file_path"), label="test.original_file_path")
        raw_code = raw.get("raw_code", raw.get("raw_sql"))
        if raw_code is not None and not isinstance(raw_code, str):
            raise RepositoryInventoryError("test_invalid", "test source code must be a string")
        run = run_results.get(unique_id, {})
        status = run.get("status")
        if status is not None and not isinstance(status, str):
            raise RepositoryInventoryError("run_result_invalid", "run result status must be a string")
        result.append(
            {
                "unique_id": unique_id,
                "name": _required_string(raw.get("name"), label="test.name"),
                "test_type": _optional_string(metadata.get("name"), label="test.test_metadata.name")
                or str(raw.get("resource_type", "test")),
                "target_unique_ids": targets,
                "column_name": _optional_string(kwargs.get("column_name"), label="test.column_name"),
                "severity": _optional_string(config.get("severity"), label="test.config.severity"),
                "status": status,
                "original_file_path": original_path,
                "source_file_hash": source_hashes.get(original_path) if original_path else None,
                "definition_hash": _hash_text(raw_code)
                if raw_code is not None
                else (source_hashes.get(original_path) if original_path else None),
            }
        )
    return sorted(result, key=lambda item: item["unique_id"])


def _exposure_records(
    exposures: Mapping[str, Mapping[str, Any]],
    resource_ids: set[str],
    source_hashes: Mapping[str, str],
    diagnostics: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for unique_id, raw in exposures.items():
        dependencies = _manifest_dependencies(raw)
        resolved = sorted(dependency for dependency in dependencies if dependency in resource_ids)
        missing = sorted(dependency for dependency in dependencies if dependency not in resource_ids)
        if missing:
            diagnostics.append(
                _diagnostic(
                    "exposure_dependency_unresolved",
                    "blocking",
                    "Exposure references resources absent from the canonical manifest inventory.",
                    unique_id,
                    *missing,
                )
            )
        owner = _mapping(raw.get("owner"), label="exposure.owner", required=False)
        email = _optional_string(owner.get("email"), label="exposure.owner.email")
        path = _optional_string(raw.get("original_file_path"), label="exposure.original_file_path")
        result.append(
            {
                "unique_id": unique_id,
                "name": _required_string(raw.get("name"), label="exposure.name"),
                "exposure_type": _required_string(raw.get("type"), label="exposure.type"),
                "maturity": _optional_string(raw.get("maturity"), label="exposure.maturity"),
                "owner_name": _optional_string(owner.get("name"), label="exposure.owner.name"),
                "owner_email_hash": _hash_text(email) if email else None,
                "url": _optional_string(raw.get("url"), label="exposure.url"),
                "depends_on_unique_ids": resolved,
                "original_file_path": path,
                "source_file_hash": source_hashes.get(path) if path else None,
            }
        )
    return sorted(result, key=lambda item: item["unique_id"])


def _resource_records(
    resources: Mapping[str, Mapping[str, Any]],
    catalog: Mapping[str, Mapping[str, Any]],
    run_results: Mapping[str, Mapping[str, Any]],
    tests: Sequence[Mapping[str, Any]],
    exposures: Sequence[Mapping[str, Any]],
    source_hashes: Mapping[str, str],
    groups: Mapping[str, Mapping[str, Any]],
) -> list[dict[str, Any]]:
    tests_by_target: dict[str, list[str]] = defaultdict(list)
    for test in tests:
        for target in test["target_unique_ids"]:
            tests_by_target[target].append(str(test["unique_id"]))
    exposures_by_target: dict[str, list[str]] = defaultdict(list)
    for exposure in exposures:
        for target in exposure["depends_on_unique_ids"]:
            exposures_by_target[target].append(str(exposure["unique_id"]))
    result: list[dict[str, Any]] = []
    for unique_id, raw in resources.items():
        catalog_entry = catalog.get(unique_id)
        catalog_metadata = _mapping(
            catalog_entry.get("metadata") if catalog_entry else None,
            label="catalog.entry.metadata",
            required=False,
        )
        config = _mapping(raw.get("config"), label="resource.config", required=False)
        meta = _manifest_meta(raw)
        group = _optional_string(raw.get("group"), label="resource.group")
        group_record = groups.get(group, {}) if group else {}
        owner = _owner_name(meta.get("owner"))
        if owner is None:
            owner = _owner_name(group_record.get("owner")) if group_record else None
        if owner is None:
            owner = _optional_string(catalog_metadata.get("owner"), label="catalog.metadata.owner")
        domain = _optional_string(meta.get("domain"), label="resource.meta.domain") or group
        path = _optional_string(raw.get("original_file_path"), label="resource.original_file_path")
        raw_code = raw.get("raw_code", raw.get("raw_sql"))
        compiled_code = raw.get("compiled_code", raw.get("compiled_sql"))
        if raw_code is not None and not isinstance(raw_code, str):
            raise RepositoryInventoryError("manifest_resource_invalid", "resource source code must be a string")
        if compiled_code is not None and not isinstance(compiled_code, str):
            raise RepositoryInventoryError("manifest_resource_invalid", "compiled code must be a string")
        run = run_results.get(unique_id, {})
        if run.get("compiled_code") is not None:
            if not isinstance(run["compiled_code"], str):
                raise RepositoryInventoryError("run_result_invalid", "compiled code must be a string")
            compiled_code = run["compiled_code"]
        run_status = run.get("status")
        if run_status is not None and not isinstance(run_status, str):
            raise RepositoryInventoryError("run_result_invalid", "run result status must be a string")
        execution_time = run.get("execution_time")
        if execution_time is not None and (
            isinstance(execution_time, bool)
            or not isinstance(execution_time, (int, float))
            or execution_time < 0
        ):
            raise RepositoryInventoryError(
                "run_result_invalid", "run result execution_time must be non-negative"
            )
        tags = raw.get("tags", config.get("tags", []))
        if tags is None:
            tags = []
        if not isinstance(tags, list) or any(not isinstance(tag, str) for tag in tags):
            raise RepositoryInventoryError("manifest_resource_invalid", "resource tags must be strings")
        enabled = config.get("enabled", True)
        if not isinstance(enabled, bool):
            raise RepositoryInventoryError("manifest_resource_invalid", "resource enabled must be boolean")
        relation_name = raw.get("relation_name") or catalog_metadata.get("relation_name")
        compiled_relation_name = run.get("relation_name")
        for label, value in (
            ("resource.relation_name", relation_name),
            ("run_result.relation_name", compiled_relation_name),
        ):
            if value is not None and not isinstance(value, str):
                raise RepositoryInventoryError("artifact_shape_invalid", f"{label} must be a string")
        record: dict[str, Any] = {
            "unique_id": unique_id,
            "resource_type": _required_string(raw.get("resource_type"), label="resource.resource_type"),
            "package_name": _required_string(raw.get("package_name"), label="resource.package_name"),
            "name": _required_string(raw.get("name"), label="resource.name"),
            "original_file_path": path,
            "source_file_hash": source_hashes.get(path) if path else None,
            "definition_hash": _hash_text(raw_code)
            if raw_code is not None
            else (source_hashes.get(path) if path else None),
            "compiled_code_hash": _hash_text(compiled_code) if compiled_code is not None else None,
            "database": _optional_string(
                raw.get("database") or catalog_metadata.get("database"), label="resource.database"
            ),
            "schema_name": _optional_string(
                raw.get("schema") or catalog_metadata.get("schema"), label="resource.schema"
            ),
            "alias": _optional_string(
                raw.get("alias") or catalog_metadata.get("name"), label="resource.alias"
            ),
            "relation_name": relation_name,
            "compiled_relation_name": compiled_relation_name,
            "materialization": _optional_string(config.get("materialized"), label="resource.materialized"),
            "enabled": enabled,
            "owner": owner,
            "domain": domain,
            "group": group,
            "tags": sorted(set(tags)),
            "depends_on_unique_ids": _manifest_dependencies(raw),
            "test_unique_ids": sorted(set(tests_by_target[unique_id])),
            "exposure_unique_ids": sorted(set(exposures_by_target[unique_id])),
            "columns": _columns(raw, catalog_entry),
            "run_status": run_status,
            "execution_time_seconds": execution_time,
        }
        record["resource_hash"] = resource_record_hash(record)
        result.append(record)
    return sorted(result, key=lambda item: item["unique_id"])


def _lineage_records(
    resources: Sequence[Mapping[str, Any]],
    exposures: Sequence[Mapping[str, Any]],
    diagnostics: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    resource_ids = {str(item["unique_id"]) for item in resources}
    pairs: set[tuple[str, str]] = set()
    for resource in resources:
        downstream = str(resource["unique_id"])
        for upstream in resource["depends_on_unique_ids"]:
            if upstream not in resource_ids:
                diagnostics.append(
                    _diagnostic(
                        "lineage_dependency_unresolved",
                        "blocking",
                        "Resource dependency is absent from the canonical manifest inventory.",
                        upstream,
                        downstream,
                    )
                )
                continue
            pairs.add((upstream, downstream))
    for exposure in exposures:
        for upstream in exposure["depends_on_unique_ids"]:
            pairs.add((str(upstream), str(exposure["unique_id"])))
    result: list[dict[str, Any]] = []
    for upstream, downstream in pairs:
        material = {
            "from_unique_id": upstream,
            "to_unique_id": downstream,
            "relationship": "depends_on",
        }
        result.append(
            {
                "edge_id": _short_identity("edge", material),
                **material,
                "edge_hash": _canonical_hash(material),
            }
        )
    return sorted(result, key=lambda item: item["edge_id"])


def _validate_manifest_maps(
    manifest: Mapping[str, Any],
    resources: Mapping[str, Mapping[str, Any]],
    diagnostics: list[dict[str, Any]],
) -> None:
    resource_ids = set(resources)
    for map_name in ("parent_map", "child_map"):
        values = _mapping(manifest.get(map_name), label=f"manifest.{map_name}", required=False)
        for unique_id, related in values.items():
            if not isinstance(unique_id, str):
                raise RepositoryInventoryError(
                    "manifest_lineage_map_invalid", f"manifest.{map_name} keys must be strings"
                )
            if unique_id not in resource_ids:
                diagnostics.append(
                    _diagnostic(
                        "manifest_lineage_map_orphan",
                        "warning",
                        f"Manifest {map_name} contains an identity outside the resource inventory.",
                        unique_id,
                    )
                )
            for target in _sequence(related, label=f"manifest.{map_name}.{unique_id}"):
                if not isinstance(target, str):
                    raise RepositoryInventoryError(
                        "manifest_lineage_map_invalid", f"manifest.{map_name} values must be strings"
                    )


def _semantic_dependency_names(raw: Mapping[str, Any], asset_type: str) -> list[str]:
    result: list[str] = []

    def add(values: Any, label: str) -> None:
        for value in _sequence(values, label=label, required=False):
            if isinstance(value, str) and value:
                result.append(value)
            elif isinstance(value, Mapping):
                name = value.get("name") or value.get("metric")
                if not isinstance(name, str) or not name:
                    raise RepositoryInventoryError(
                        "semantic_manifest_invalid", f"{label} entries must identify a metric"
                    )
                result.append(name)
            else:
                raise RepositoryInventoryError(
                    "semantic_manifest_invalid", f"{label} entries must identify a metric"
                )

    add(raw.get("depends_on_metrics"), "semantic_asset.depends_on_metrics")
    if asset_type == "saved_query":
        add(raw.get("metrics"), "saved_query.metrics")
    if asset_type == "metric":
        type_params = _mapping(raw.get("type_params"), label="metric.type_params", required=False)
        add(type_params.get("metrics"), "metric.type_params.metrics")
        add(type_params.get("input_metrics"), "metric.type_params.input_metrics")
    return sorted(set(result))


def _semantic_assets(
    semantic_manifest: Mapping[str, Any] | None,
    resources: Sequence[Mapping[str, Any]],
    diagnostics: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    if semantic_manifest is None:
        return []
    relation_to_resource: dict[str, list[str]] = defaultdict(list)
    for resource in resources:
        for key in ("relation_name", "compiled_relation_name"):
            relation = resource.get(key)
            if isinstance(relation, str) and relation:
                relation_to_resource[relation].append(str(resource["unique_id"]))
    raw_assets: list[tuple[str, Mapping[str, Any]]] = []
    for section, asset_type in (
        ("semantic_models", "semantic_model"),
        ("metrics", "metric"),
        ("saved_queries", "saved_query"),
    ):
        for raw in _sequence(
            semantic_manifest.get(section), label=f"semantic_manifest.{section}", required=False
        ):
            if not isinstance(raw, Mapping):
                raise RepositoryInventoryError(
                    "semantic_manifest_invalid", f"semantic_manifest.{section} entries must be objects"
                )
            raw_assets.append((asset_type, raw))
    identities: dict[tuple[str, str], str] = {}
    name_to_ids: dict[str, list[str]] = defaultdict(list)
    for asset_type, raw in raw_assets:
        name = _required_string(raw.get("name"), label=f"semantic_manifest.{asset_type}.name")
        key = (asset_type, name)
        if key in identities:
            raise RepositoryInventoryError(
                "semantic_asset_duplicate", "semantic asset type and name appear more than once", subject=name
            )
        asset_id = _short_identity(f"semantic.{asset_type}", {"type": asset_type, "name": name})
        identities[key] = asset_id
        name_to_ids[name].append(asset_id)
    result: list[dict[str, Any]] = []
    for asset_type, raw in raw_assets:
        name = str(raw["name"])
        asset_id = identities[(asset_type, name)]
        meta = _mapping(raw.get("meta"), label="semantic_asset.meta", required=False)
        node_relation = _mapping(
            raw.get("node_relation"), label="semantic_model.node_relation", required=False
        )
        relation = raw.get("relation_name") or node_relation.get("relation_name")
        if relation is not None and not isinstance(relation, str):
            raise RepositoryInventoryError(
                "semantic_manifest_invalid", "semantic relation_name must be a string"
            )
        related_resources: list[str] = []
        if relation:
            candidates = sorted(set(relation_to_resource.get(relation, [])))
            if len(candidates) == 1:
                related_resources = candidates
            elif len(candidates) > 1:
                diagnostics.append(
                    _diagnostic(
                        "semantic_relation_ambiguous",
                        "blocking",
                        "Semantic relation matches more than one manifest resource.",
                        asset_id,
                        *candidates,
                    )
                )
            else:
                diagnostics.append(
                    _diagnostic(
                        "semantic_relation_unresolved",
                        "warning",
                        "Semantic relation did not match an exact manifest relation identity.",
                        asset_id,
                    )
                )
        dependencies: list[str] = []
        for dependency_name in _semantic_dependency_names(raw, asset_type):
            candidates = sorted(set(name_to_ids.get(dependency_name, [])))
            if len(candidates) == 1:
                dependencies.extend(candidates)
            elif len(candidates) > 1:
                diagnostics.append(
                    _diagnostic(
                        "semantic_dependency_ambiguous",
                        "blocking",
                        "Semantic dependency name matches more than one asset.",
                        asset_id,
                        *candidates,
                    )
                )
            else:
                diagnostics.append(
                    _diagnostic(
                        "semantic_dependency_unresolved",
                        "blocking",
                        "Semantic dependency has no matching asset in the semantic manifest.",
                        asset_id,
                        dependency_name,
                    )
                )
        result.append(
            {
                "asset_id": asset_id,
                "asset_type": asset_type,
                "name": name,
                "description": _optional_string(raw.get("description"), label="semantic.description"),
                "owner": _owner_name(meta.get("owner")),
                "domain": _optional_string(meta.get("domain"), label="semantic.domain"),
                "relation_name": relation,
                "related_resource_unique_ids": sorted(set(related_resources)),
                "depends_on_asset_ids": sorted(set(dependencies)),
                "definition_hash": _canonical_hash(raw),
            }
        )
    return sorted(result, key=lambda item: item["asset_id"])


def inventory_dbt_repository(
    project_root: str | Path,
    *,
    inventory_id: str,
    run_id: str,
    repository_ref: str,
    git_ref: str,
    commit_sha: str,
    identity_evidence_ref: str,
    acquired_at: str,
    security: SecurityMetadata | Mapping[str, Any],
    manifest_path: str = "target/manifest.json",
    catalog_path: str | None = "target/catalog.json",
    run_results_path: str | None = "target/run_results.json",
    semantic_manifest_path: str | None = None,
    semantic_manifest_schema_version: str | None = None,
    additional_source_paths: Sequence[str] = (),
    max_artifact_bytes: int = DEFAULT_MAX_ARTIFACT_BYTES,
    max_source_bytes: int = DEFAULT_MAX_SOURCE_BYTES,
) -> RepositoryInventory:
    """Inventory a pinned dbt repository using only raw files already on disk.

    ``repository_ref``, ``git_ref``, ``commit_sha``, and ``identity_evidence_ref``
    must come from the caller's acquisition boundary.  This function intentionally
    has no fallback that shells out to git or dbt to discover or repair them.
    """

    root = _resolve_project_root(project_root)
    diagnostics: list[dict[str, Any]] = []
    loaded_artifacts: list[_LoadedArtifact] = []
    manifest_artifact = _load_artifact(
        root,
        artifact_type="manifest",
        relative_path=manifest_path,
        required=True,
        max_bytes=max_artifact_bytes,
    )
    assert manifest_artifact is not None
    loaded_artifacts.append(manifest_artifact)

    def optional_artifact(artifact_type: str, path: str | None) -> _LoadedArtifact | None:
        if path is None:
            return None
        artifact = _load_artifact(
            root,
            artifact_type=artifact_type,
            relative_path=path,
            required=False,
            max_bytes=max_artifact_bytes,
            declared_schema_version=(
                semantic_manifest_schema_version if artifact_type == "semantic_manifest" else None
            ),
        )
        if artifact is None:
            diagnostics.append(
                _diagnostic(
                    f"{artifact_type}_artifact_missing",
                    "warning",
                    f"Optional {artifact_type} artifact was not present; related observations are incomplete.",
                    path,
                )
            )
        else:
            loaded_artifacts.append(artifact)
        return artifact

    catalog_artifact = optional_artifact("catalog", catalog_path)
    run_results_artifact = optional_artifact("run_results", run_results_path)
    semantic_artifact = optional_artifact("semantic_manifest", semantic_manifest_path)

    manifest = manifest_artifact.payload
    metadata = _mapping(manifest.get("metadata"), label="manifest.metadata")
    project_name = _required_string(metadata.get("project_name"), label="manifest.metadata.project_name")
    project_id = _optional_string(metadata.get("project_id"), label="manifest.metadata.project_id")
    dbt_version = _required_string(metadata.get("dbt_version"), label="manifest.metadata.dbt_version")
    try:
        repository = RepositoryIdentity.model_validate(
            {
                "repository_ref": repository_ref,
                "git_ref": git_ref,
                "commit_sha": commit_sha,
                "identity_evidence_ref": identity_evidence_ref,
                "project_name": project_name,
                "project_id": project_id,
                "dbt_version": dbt_version,
                "worktree_state": "clean",
            }
        )
        security_record = (
            security if isinstance(security, SecurityMetadata) else SecurityMetadata.model_validate(security)
        )
    except ValidationError as exc:
        raise RepositoryInventoryError(
            "repository_attestation_invalid",
            "repository identity or security metadata does not satisfy the contract",
        ) from exc

    manifest_resources, manifest_tests = _resource_entries(manifest)
    manifest_exposures = _manifest_exposures(manifest)
    groups = _group_metadata(manifest)
    source_files, source_hashes = _source_files(
        root,
        manifest_resources,
        manifest_tests,
        manifest_exposures,
        tuple(additional_source_paths),
        diagnostics,
        max_bytes=max_source_bytes,
    )
    catalog_entries = _catalog_entries(
        catalog_artifact.payload if catalog_artifact else None,
        manifest_resources,
        diagnostics,
    )
    run_entries = _run_result_entries(
        run_results_artifact.payload if run_results_artifact else None,
        manifest_resources,
        manifest_tests,
        diagnostics,
    )
    test_records = _test_records(
        manifest_tests, run_entries, set(manifest_resources), source_hashes, diagnostics
    )
    exposure_records = _exposure_records(
        manifest_exposures, set(manifest_resources), source_hashes, diagnostics
    )
    resource_records = _resource_records(
        manifest_resources,
        catalog_entries,
        run_entries,
        test_records,
        exposure_records,
        source_hashes,
        groups,
    )
    constraint_records = _constraint_records(manifest_resources)
    lineage_records = _lineage_records(resource_records, exposure_records, diagnostics)
    _validate_manifest_maps(manifest, manifest_resources, diagnostics)
    semantic_records = _semantic_assets(
        semantic_artifact.payload if semantic_artifact else None,
        resource_records,
        diagnostics,
    )

    artifact_records = sorted(
        (artifact.record for artifact in loaded_artifacts), key=lambda item: item["artifact_type"]
    )
    diagnostics = sorted(
        diagnostics,
        key=lambda item: (
            item["severity"],
            item["code"],
            tuple(item["subject_refs"]),
            item["message"],
        ),
    )
    summary = {
        "artifact_count": len(artifact_records),
        "source_file_count": len(source_files),
        "resource_count": len(resource_records),
        "model_count": sum(item["resource_type"] == "model" for item in resource_records),
        "source_count": sum(item["resource_type"] == "source" for item in resource_records),
        "test_count": len(test_records),
        "constraint_count": len(constraint_records),
        "exposure_count": len(exposure_records),
        "semantic_asset_count": len(semantic_records),
        "diagnostic_count": len(diagnostics),
    }
    payload: dict[str, Any] = {
        "contract_version": "domo-to-omni.repository-inventory.v1",
        "inventory_id": inventory_id,
        "run_id": run_id,
        "repository": repository.model_dump(mode="json"),
        "status": "partial"
        if any(item["severity"] in {"warning", "blocking"} for item in diagnostics)
        else "complete",
        "artifact_files": artifact_records,
        "source_files": source_files,
        "resources": resource_records,
        "lineage_edges": lineage_records,
        "tests": test_records,
        "constraints": constraint_records,
        "exposures": exposure_records,
        "semantic_assets": semantic_records,
        "diagnostics": diagnostics,
        "summary": summary,
        "provenance": {
            "acquisition_method": "read_only_dbt_artifacts",
            "parser_version": "dbt-repository-inventory-v1",
            "executed_repository_code": False,
            "acquired_at": acquired_at,
            "source_artifact_refs": sorted(
                f"artifact-ref://dbt/{item['artifact_type']}/{item['content_hash'].removeprefix('sha256:')}"
                for item in artifact_records
            ),
        },
        "security": security_record.model_dump(mode="json"),
        "immutable": True,
    }
    payload["inventory_hash"] = repository_inventory_hash(payload)
    try:
        return RepositoryInventory.model_validate(payload)
    except ValidationError as exc:
        raise RepositoryInventoryError(
            "repository_inventory_contract_invalid",
            "constructed repository inventory failed its integrity contract",
        ) from exc


__all__ = [
    "DEFAULT_MAX_ARTIFACT_BYTES",
    "DEFAULT_MAX_SOURCE_BYTES",
    "RepositoryInventoryError",
    "inventory_dbt_repository",
]

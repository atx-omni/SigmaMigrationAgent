"""Sigma's documented source variants and version values at the acquisition boundary.

Source response contracts differ between data models and workbooks. Keep their discriminators
and identity rules shared by observations, closure checks, and persisted source graphs.
"""

from __future__ import annotations

import json
import math
import re
from collections.abc import Mapping
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter

SourceOwner = Literal["data_model", "workbook"]
SourceId = Annotated[str, Field(strict=True, pattern=r"^[A-Za-z0-9_-][A-Za-z0-9._~-]{0,2047}$")]


class _Source(BaseModel):
    model_config = ConfigDict(extra="allow", frozen=True)


class DataModelSource(_Source):
    type: Literal["data-model"]
    dataModelId: SourceId
    elementIds: tuple[SourceId, ...] = Field(min_length=1)
    versionTagId: SourceId | None = None


class ModelTableSource(_Source):
    type: Literal["table"]
    tableId: SourceId


class ModelDatasetSource(_Source):
    type: Literal["dataset"]
    datasetId: SourceId


class WorkbookTableSource(_Source):
    type: Literal["table"]
    inodeId: SourceId


class WorkbookDatasetSource(_Source):
    type: Literal["dataset"]
    inodeId: SourceId
    url: str = Field(strict=True, min_length=1)


class CustomSqlSource(_Source):
    type: Literal["custom-sql"]
    customSqlId: SourceId
    connectionId: SourceId
    definition: str = Field(strict=True, min_length=1)


class _Binding(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class DataModelElementBinding(_Binding):
    type: Literal["data-model"]
    dataModelId: SourceId
    elementId: SourceId
    versionTagId: SourceId | None = None


class ModelTableBinding(_Binding):
    type: Literal["table"]
    tableId: SourceId


class ModelDatasetBinding(_Binding):
    type: Literal["dataset"]
    datasetId: SourceId


class CustomSqlBinding(_Binding):
    type: Literal["custom-sql"]
    customSqlId: SourceId
    connectionId: SourceId


DataModelSourceBinding = Annotated[
    DataModelElementBinding | ModelTableBinding | ModelDatasetBinding | CustomSqlBinding,
    Field(discriminator="type"),
]


_MODEL_SOURCE = TypeAdapter(
    Annotated[
        DataModelSource | ModelTableSource | ModelDatasetSource | CustomSqlSource,
        Field(discriminator="type"),
    ]
)
_WORKBOOK_SOURCE = TypeAdapter(
    Annotated[
        DataModelSource | WorkbookTableSource | WorkbookDatasetSource | CustomSqlSource,
        Field(discriminator="type"),
    ]
)


def parse_sigma_source(value: Mapping[str, Any], *, owner: SourceOwner) -> _Source:
    """Validate identity-bearing fields without discarding additive provider metadata."""

    adapter = _MODEL_SOURCE if owner == "data_model" else _WORKBOOK_SOURCE
    return adapter.validate_python(value)


def sigma_source_bindings(source: _Source) -> tuple[dict[str, str], ...]:
    """Return one compound identity per referenced model element (including the tag)."""

    if isinstance(source, DataModelSource):
        return tuple(
            {
                "type": source.type,
                "dataModelId": source.dataModelId,
                "elementId": element_id,
                **({"versionTagId": source.versionTagId} if source.versionTagId else {}),
            }
            for element_id in source.elementIds
        )
    if isinstance(source, CustomSqlSource):
        return (
            {
                "type": source.type,
                "customSqlId": source.customSqlId,
                "connectionId": source.connectionId,
            },
        )
    identity_key = (
        "tableId"
        if isinstance(source, ModelTableSource)
        else "datasetId"
        if isinstance(source, ModelDatasetSource)
        else "inodeId"
    )
    return ({"type": source.type, identity_key: getattr(source, identity_key)},)


def sigma_source_binding_key(binding: Mapping[str, str]) -> str:
    """Canonical, reversible identity; JSON boundaries prevent opaque-ID collisions."""

    return json.dumps(dict(binding), sort_keys=True, separators=(",", ":"))


def normalize_sigma_document_version(value: object) -> str | None:
    """Normalize integral provider numbers; never coerce booleans or fractional versions."""

    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return str(value) if value >= 1 else None
    if isinstance(value, float):
        if math.isfinite(value) and value.is_integer() and 1 <= value <= 2**53 - 1:
            return str(int(value))
        return None
    if isinstance(value, str) and re.fullmatch(r"[1-9][0-9]*", value):
        return value
    return None


def selected_sigma_document_version(metadata: Mapping[str, Any], *keys: str) -> str | None:
    """A malformed preferred version must not fall through to a different version field."""

    for key in keys:
        if key in metadata:
            return normalize_sigma_document_version(metadata[key])
    return None

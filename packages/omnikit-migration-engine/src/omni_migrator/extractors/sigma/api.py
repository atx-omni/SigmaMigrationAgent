"""Read-only Sigma REST API acquisition for migration snapshots.

Live Sigma acquisition uses OAuth2 client credentials. The API host is organization/region
specific, so callers must provide it. This client intentionally keeps the transport injectable:
tests use ``httpx.MockTransport`` and production callers use httpx's default transport. Offline
manual acquisition consumes the versioned snapshot produced by this client.

The snapshot is evidence, not a portable Sigma definition. It combines data-model specs with
document sources, formula-bearing columns, workbook controls, generated SQL, lineage, grants,
and schedules. Newer or permission-gated endpoints are optional and produce sanitized
diagnostics instead of making an otherwise usable snapshot fail.
"""

from __future__ import annotations

import hashlib
import json
import random
import re
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import TypeVar
from urllib.parse import quote

import httpx

from omni_migrator.control_plane.canonical import sha256_json
from omni_migrator.extractors.sigma.source_contracts import (
    parse_sigma_source,
    sigma_source_binding_key,
    sigma_source_bindings,
)

MAX_GET_ATTEMPTS = 3
MAX_RETRY_DELAY_SECONDS = 60.0
MAX_CLIENT_BACKOFF_SECONDS = 2.0
MAX_PAGINATION_PAGES = 10_000
MAX_SELECTED_DATA_MODELS = 100
MAX_SELECTED_WORKBOOKS = 100
RETRYABLE_STATUS_CODES = {429, 500, 502, 503, 504}
OPTIONAL_ENDPOINT_STATUS_CODES = {400, 403, 404, 405, 422, 501}

_T = TypeVar("_T")

_OBSERVABLE_ID_KEYS = frozenset(
    {
        "bookmarkId",
        "columnId",
        "connectionId",
        "controlId",
        "customSqlId",
        "dataModelId",
        "datasetId",
        "elementId",
        "embedId",
        "folderId",
        "grantId",
        "inodeId",
        "organizationId",
        "pageId",
        "queryId",
        "reportId",
        "scheduleId",
        "scheduledNotificationId",
        "sourceId",
        "tagId",
        "tableId",
        "templateId",
        "workbookId",
        "versionTagId",
        "workspaceId",
    }
)
_SAFE_QUERY_VALUES = frozenset(
    {
        "bookmarkId",
        "documentVersion",
        "format",
        "inodeId",
        "limit",
        "pageSize",
        "skipPermissionCheck",
        "tag",
        "tagName",
    }
)
_ROW_ID_PRIORITY = (
    "bookmarkId",
    "columnId",
    "controlId",
    "grantId",
    "queryId",
    "scheduleId",
    "scheduledNotificationId",
    "elementId",
    "inodeId",
    "pageId",
    "workbookId",
    "dataModelId",
    "reportId",
    "sourceId",
    "connectionId",
    "embedId",
    "datasetId",
    "tagId",
    "templateId",
    "workspaceId",
    "folderId",
    "organizationId",
)
_ENDPOINT_PRIMARY_ID_PRIORITY = {
    "bookmarks": ("bookmarkId",),
    "columns": ("columnId",),
    "controls": ("controlId",),
    "elements": ("elementId",),
    "embeds": ("embedId",),
    "grants": ("grantId",),
    "pages": ("pageId",),
    "queries": ("queryId",),
    "schedules": ("scheduleId", "scheduledNotificationId"),
    "sources": ("sourceId", "inodeId", "elementId"),
    "tags": ("tagId",),
}
_SAFE_STRUCTURAL_KEY = re.compile(r"^[A-Za-z0-9_.~-]{1,256}$")
_SENSITIVE_STRUCTURAL_KEY = re.compile(r"(?i)(bearer|sk-[a-z0-9_-]{8,}|secret|password|token)")
_SAFE_OBSERVABLE_ID = re.compile(r"^[A-Za-z0-9_-][A-Za-z0-9._~-]{0,2047}$")
_CONTINUATION_QUERY_KEYS = frozenset({"cursor", "page", "pageToken", "nextPage", "nextPageToken"})

# Sigma connection `type` -> IR `Dialect`. Only `bigQuery` is confirmed verbatim in Sigma's
# public examples; unknown future values deliberately remain `other`.
_TYPE_DIALECT = {
    "bigquery": "bigquery",
    "snowflake": "snowflake",
    "redshift": "redshift",
    "postgresql": "postgres",
    "postgres": "postgres",
    "databricks": "databricks",
    "mysql": "mysql",
}


def normalize_sigma_connection_type(type_: str | None) -> str:
    if not type_:
        return "other"
    return _TYPE_DIALECT.get(type_.lower(), "other")


def _row_id(row: dict, *keys: str) -> str | None:
    for key in keys:
        value = row.get(key)
        if isinstance(value, (str, int)) and not isinstance(value, bool) and str(value).strip():
            return str(value)
    return None


def _safe_observable_id(value: object) -> str | None:
    if not isinstance(value, (str, int)) or isinstance(value, bool):
        return None
    rendered = str(value)
    return rendered if _SAFE_OBSERVABLE_ID.fullmatch(rendered) else None


def _path_segment(value: object, *, label: str) -> str:
    """Encode one untrusted Sigma path segment without permitting route changes."""

    if not isinstance(value, (str, int)) or isinstance(value, bool):
        raise ValueError(f"Sigma {label} is not a safe URL path segment")
    rendered = str(value)
    if (
        not rendered
        or len(rendered) > 2_048
        or rendered in {".", ".."}
        or any(character in rendered for character in "/\\?#%")
        or any(ord(character) < 32 or ord(character) == 127 for character in rendered)
    ):
        raise ValueError(f"Sigma {label} is not a safe URL path segment")
    return quote(rendered, safe="-._~")


def _json_shape_paths(value: object, *, max_items: int = 25) -> list[dict[str, object]]:
    """Return bounded structural evidence without retaining response values."""

    observed: dict[str, set[str]] = {}

    def safe_key(value: object) -> str:
        rendered = str(value)
        if _SAFE_STRUCTURAL_KEY.fullmatch(rendered) and not _SENSITIVE_STRUCTURAL_KEY.search(
            rendered
        ):
            return rendered
        digest = hashlib.sha256(rendered.encode("utf-8")).hexdigest()[:16]
        return f"<redacted-key:{digest}>"

    def visit(item: object, path: str) -> None:
        kind = (
            "null"
            if item is None
            else "boolean"
            if isinstance(item, bool)
            else "integer"
            if isinstance(item, int)
            else "number"
            if isinstance(item, float)
            else "string"
            if isinstance(item, str)
            else "object"
            if isinstance(item, dict)
            else "array"
            if isinstance(item, list)
            else type(item).__name__
        )
        observed.setdefault(path, set()).add(kind)
        if isinstance(item, dict):
            for key, child in sorted(item.items(), key=lambda pair: str(pair[0])):
                visit(child, f"{path}.{safe_key(key)}")
        elif isinstance(item, list):
            for child in item[:max_items]:
                visit(child, f"{path}[]")

    visit(value, "$")
    return [{"path": path, "types": sorted(types)} for path, types in sorted(observed.items())]


def _observable_ids(value: object, *, max_ids_per_type: int = 10_000) -> dict[str, list[str]]:
    """Collect only source-object IDs; member identities and recipient data are excluded."""

    found: dict[str, set[str]] = {}

    def visit(item: object) -> None:
        if isinstance(item, dict):
            for key, child in item.items():
                if key == "elementIds" and isinstance(child, list):
                    bucket = found.setdefault("elementId", set())
                    for element_id in child:
                        safe_id = _safe_observable_id(element_id)
                        if safe_id is not None and len(bucket) < max_ids_per_type:
                            bucket.add(safe_id)
                if key in _OBSERVABLE_ID_KEYS and child not in (None, ""):
                    safe_id = _safe_observable_id(child)
                    if safe_id is not None:
                        bucket = found.setdefault(key, set())
                        if len(bucket) < max_ids_per_type:
                            bucket.add(safe_id)
                visit(child)
        elif isinstance(item, list):
            for child in item:
                visit(child)

    visit(value)
    return {key: sorted(values) for key, values in sorted(found.items())}


def _top_level_primary_id_evidence(
    value: object, *, endpoint: str
) -> tuple[dict[str, list[str]], int]:
    """Collect primary IDs in page entries without treating foreign-key repeats as duplicates."""

    rows: object = value
    if isinstance(value, dict):
        containers = [value]
        if isinstance(value.get("data"), dict):
            containers.insert(0, value["data"])
        rows = []
        for container in containers:
            candidate = next(
                (
                    container[key]
                    for key in ("entries", "items", "results")
                    if isinstance(container.get(key), list)
                ),
                None,
            )
            if candidate is not None:
                rows = candidate
                break
        if rows == [] and isinstance(value.get("data"), list):
            rows = value["data"]
    if not isinstance(rows, list):
        return {}, 0
    seen: set[tuple[str, str]] = set()
    found: dict[str, set[str]] = {}
    duplicates = 0
    endpoint_collection = endpoint.rstrip("/").rsplit("/", 1)[-1]
    priority = _ENDPOINT_PRIMARY_ID_PRIORITY.get(endpoint_collection, _ROW_ID_PRIORITY)
    for row in rows:
        if not isinstance(row, dict):
            continue
        if endpoint_collection == "sources" and endpoint.startswith(
            ("/v2/dataModels/", "/v2/workbooks/")
        ):
            try:
                source = parse_sigma_source(
                    row,
                    owner="data_model" if endpoint.startswith("/v2/dataModels/") else "workbook",
                )
            except ValueError:
                # The capability spike reports invalid source contracts as explicit blockers.
                continue
            for binding in sigma_source_bindings(source):
                identity = ("sourceBinding", sigma_source_binding_key(binding))
                if identity in seen:
                    duplicates += 1
                seen.add(identity)
                found.setdefault(identity[0], set()).add(identity[1])
            continue
        identity = next(
            (
                (key, safe_id)
                for key in priority
                if (safe_id := _safe_observable_id(row.get(key))) is not None
            ),
            None,
        )
        if identity is None:
            continue
        if identity in seen:
            duplicates += 1
        seen.add(identity)
        found.setdefault(identity[0], set()).add(identity[1])
    return {key: sorted(values) for key, values in sorted(found.items())}, duplicates


def _safe_request_query(url: httpx.URL) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in sorted(url.params.multi_items()):
        if key in _CONTINUATION_QUERY_KEYS:
            result[key] = {
                "present": True,
                "sha256": hashlib.sha256(value.encode("utf-8")).hexdigest(),
            }
        elif key in _SAFE_QUERY_VALUES:
            result[key] = value
        else:
            result[key] = {"redacted": True}
    return result


def _safe_response_observation(response: httpx.Response, *, attempt: int) -> dict[str, object]:
    """Summarize one HTTP response for a secret-free immutable observation artifact."""

    try:
        body: object = response.json()
        json_valid = True
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
        body = None
        json_valid = False

    declared_total: int | None = None
    entry_count: int | None = None
    continuation: dict[str, object] = {"present": False, "kind": None, "sha256": None}
    if isinstance(body, dict):
        containers = [body]
        if isinstance(body.get("data"), dict):
            containers.insert(0, body["data"])
        for container in containers:
            if declared_total is None and isinstance(container.get("total"), int):
                declared_total = container["total"]
            for key in ("entries", "items", "results"):
                if isinstance(container.get(key), list):
                    entry_count = len(container[key])
                    break
            for key in ("nextPage", "nextPageToken", "next_page"):
                token = container.get(key)
                if token not in (None, ""):
                    rendered = str(token)
                    continuation = {
                        "present": True,
                        "kind": key,
                        "sha256": hashlib.sha256(rendered.encode("utf-8")).hexdigest(),
                    }
                    break
            if not continuation["present"]:
                links = container.get("links") if isinstance(container.get("links"), dict) else {}
                link = container.get("next") or links.get("next")
                if isinstance(link, dict):
                    link = link.get("href")
                if link not in (None, ""):
                    rendered = str(link)
                    continuation = {
                        "present": True,
                        "kind": "url",
                        "sha256": hashlib.sha256(rendered.encode("utf-8")).hexdigest(),
                    }
    elif isinstance(body, list):
        entry_count = len(body)

    exact_ids = _observable_ids(body)
    if response.request.url.path == "/v2/whoami" and isinstance(body, dict):
        user_id = _safe_observable_id(body.get("userId"))
        if user_id is not None:
            exact_ids["userId"] = [user_id]
    primary_ids, duplicate_id_count = _top_level_primary_id_evidence(
        body,
        endpoint=response.request.url.path,
    )
    exact_id_set_sha256 = sha256_json(exact_ids)
    return {
        "method": response.request.method,
        "endpoint": response.request.url.path,
        "request_query": _safe_request_query(response.request.url),
        "status_code": response.status_code,
        "attempt": attempt,
        "retryable": response.status_code in RETRYABLE_STATUS_CODES,
        "response_body_sha256": hashlib.sha256(response.content).hexdigest(),
        "response_bytes": len(response.content),
        "json_valid": json_valid,
        "response_shape": _json_shape_paths(body) if json_valid else [],
        "exact_ids": exact_ids,
        "exact_id_set_sha256": exact_id_set_sha256,
        "primary_ids": primary_ids,
        "duplicate_id_count": duplicate_id_count,
        "entry_count": entry_count,
        "declared_total": declared_total,
        "continuation": continuation,
        "redaction_state": "structural_only",
    }


@dataclass
class SigmaApi:
    base_url: str
    client_id: str = field(repr=False)
    client_secret: str = field(repr=False)
    transport: httpx.BaseTransport | None = None  # inject a MockTransport in tests
    observation_sink: Callable[[dict[str, object]], None] | None = field(default=None, repr=False)
    request_budget: int | None = field(default=None, repr=False)
    per_endpoint_request_budget: int | None = field(default=None, repr=False)
    _http: httpx.Client = field(init=False, repr=False)
    _token: str | None = field(init=False, default=None, repr=False)
    _refresh_token: str | None = field(init=False, default=None, repr=False)
    _request_count: int = field(init=False, default=0, repr=False)
    _endpoint_request_counts: dict[str, int] = field(init=False, default_factory=dict, repr=False)

    def __post_init__(self) -> None:
        self._http = httpx.Client(
            base_url=self.base_url.rstrip("/"), transport=self.transport, timeout=60.0
        )

    # --- auth and transport ---
    def _consume_request_budget(self, endpoint: str | httpx.URL) -> None:
        if self.request_budget is not None and self._request_count >= self.request_budget:
            raise RuntimeError("Sigma API request budget exhausted")
        endpoint_path = (
            endpoint.path if isinstance(endpoint, httpx.URL) else httpx.URL(endpoint).path
        )
        endpoint_count = self._endpoint_request_counts.get(endpoint_path, 0)
        if (
            self.per_endpoint_request_budget is not None
            and endpoint_count >= self.per_endpoint_request_budget
        ):
            raise RuntimeError("Sigma API per-endpoint request budget exhausted")
        self._request_count += 1
        self._endpoint_request_counts[endpoint_path] = endpoint_count + 1

    @property
    def request_count(self) -> int:
        return self._request_count

    def _post_token(self, data: dict[str, str]) -> httpx.Response:
        response: httpx.Response | None = None
        for attempt in range(MAX_GET_ATTEMPTS):
            self._consume_request_budget("/v2/auth/token")
            response = self._http.post("/v2/auth/token", data=data)
            if response.status_code not in RETRYABLE_STATUS_CODES:
                response.raise_for_status()
                return response
            if attempt + 1 < MAX_GET_ATTEMPTS:
                time.sleep(self._retry_delay(response, attempt))
        assert response is not None
        response.raise_for_status()
        return response

    def login(self) -> str:
        response = self._post_token(
            {
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
            }
        )
        body = response.json()
        self._token = body["access_token"]
        self._refresh_token = body.get("refresh_token")
        self._http.headers["Authorization"] = f"Bearer {self._token}"
        return self._token

    def refresh(self) -> str:
        """Refresh an expired token, falling back to a new client-credentials login."""
        if not self._refresh_token:
            return self.login()
        response = self._post_token(
            {"grant_type": "refresh_token", "refresh_token": self._refresh_token}
        )
        body = response.json()
        self._token = body["access_token"]
        self._refresh_token = body.get("refresh_token", self._refresh_token)
        self._http.headers["Authorization"] = f"Bearer {self._token}"
        return self._token

    def _ensure_auth(self) -> None:
        if not self._token:
            self.login()

    @staticmethod
    def _retry_delay(response: httpx.Response, attempt: int) -> float:
        raw_delay = response.headers.get("Retry-After")
        if raw_delay is None:
            ceiling = min(0.2 * (2**attempt), MAX_CLIENT_BACKOFF_SECONDS)
            return random.uniform(0.0, ceiling)
        try:
            delay = float(raw_delay)
        except ValueError:
            try:
                retry_at = parsedate_to_datetime(raw_delay)
                if retry_at.tzinfo is None or retry_at.utcoffset() is None:
                    retry_at = retry_at.replace(tzinfo=UTC)
                raw_now = response.headers.get("Date")
                now = parsedate_to_datetime(raw_now) if raw_now else datetime.now(UTC)
                if now.tzinfo is None or now.utcoffset() is None:
                    now = now.replace(tzinfo=UTC)
                delay = (retry_at - now).total_seconds()
            except (TypeError, ValueError, OverflowError) as error:
                raise RuntimeError("Sigma returned an invalid Retry-After value") from error
        delay = max(0.0, delay)
        if delay > MAX_RETRY_DELAY_SECONDS:
            raise RuntimeError("Sigma Retry-After exceeds the bounded retry window")
        return delay

    def _get(self, path: str | httpx.URL, **kwargs) -> httpx.Response:
        self._ensure_auth()
        refreshed = False
        response: httpx.Response | None = None
        for attempt in range(MAX_GET_ATTEMPTS):
            self._consume_request_budget(path)
            response = self._http.get(path, **kwargs)
            if self.observation_sink is not None:
                self.observation_sink(_safe_response_observation(response, attempt=attempt + 1))
            if response.status_code == 401 and not refreshed:
                self.refresh()
                refreshed = True
                self._consume_request_budget(path)
                response = self._http.get(path, **kwargs)
                if self.observation_sink is not None:
                    self.observation_sink(_safe_response_observation(response, attempt=attempt + 1))
            if response.status_code not in RETRYABLE_STATUS_CODES:
                response.raise_for_status()
                return response
            if attempt + 1 < MAX_GET_ATTEMPTS:
                time.sleep(self._retry_delay(response, attempt))
        assert response is not None
        response.raise_for_status()
        return response

    def close(self) -> None:
        self._http.close()

    # --- pagination ---
    @staticmethod
    def _page_parts(
        body: object, path: str
    ) -> tuple[list[dict], tuple[str, str] | None, bool | None, int | None]:
        if isinstance(body, list):
            if not all(isinstance(row, dict) for row in body):
                raise ValueError(f"Sigma pagination at {path} returned non-object rows")
            return list(body), None, None, None
        if not isinstance(body, dict):
            raise ValueError(f"Sigma pagination at {path} returned a non-list/object payload")

        containers = [body]
        nested = body.get("data")
        if isinstance(nested, dict):
            containers.insert(0, nested)

        page = next(
            (
                container
                for container in containers
                if any(key in container for key in ("entries", "items", "results"))
            ),
            None,
        )
        if page is None and isinstance(body.get("data"), list):
            rows: object = body["data"]
            page = body
        elif page is not None:
            rows = next((page[key] for key in ("entries", "items", "results") if key in page), [])
        else:
            raise ValueError(f"Sigma pagination at {path} omitted its entries collection")
        if not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows):
            raise ValueError(f"Sigma pagination at {path} returned malformed entries")

        continuation: tuple[str, str] | None = None
        for container in containers:
            token = container.get(
                "nextPage",
                container.get("next_page", container.get("nextPageToken")),
            )
            if token not in (None, ""):
                continuation = (
                    "pageToken" if container.get("nextPageToken") not in (None, "") else "page",
                    str(token),
                )
                break
            links = container.get("links") if isinstance(container.get("links"), dict) else {}
            link = container.get("next") or links.get("next")
            if isinstance(link, dict):
                link = link.get("href")
            if link not in (None, ""):
                continuation = ("url", str(link))
                break

        has_more: bool | None = None
        total: int | None = None
        for container in containers:
            if has_more is None and isinstance(container.get("hasMore"), bool):
                has_more = container["hasMore"]
            raw_total = container.get("total")
            if total is None and isinstance(raw_total, (int, float)):
                numeric_total = float(raw_total)
                if numeric_total.is_integer() and numeric_total >= 0:
                    total = int(numeric_total)
        return list(rows), continuation, has_more, total

    def _same_origin_url(
        self,
        link: str,
        current_url: httpx.URL,
        *,
        base_params: dict[str, object],
        page_size_param: str,
    ) -> httpx.URL:
        target = current_url.join(link)
        base = self._http.base_url
        if (target.scheme, target.host, target.port) != (base.scheme, base.host, base.port):
            raise RuntimeError("Sigma pagination refused a continuation URL on another origin")
        if target.path != current_url.path:
            raise RuntimeError("Sigma pagination refused a continuation URL on another endpoint")
        immutable_selectors = {
            key: str(value) for key, value in base_params.items() if key != page_size_param
        }
        target_values: dict[str, list[str]] = {}
        for key, value in target.params.multi_items():
            target_values.setdefault(key, []).append(value)

        for key, expected in immutable_selectors.items():
            observed = target_values.get(key)
            if observed is not None and observed != [expected]:
                raise RuntimeError("Sigma pagination refused changed selector context")
        observed_page_size = target_values.get(page_size_param)
        if observed_page_size is not None and observed_page_size != [
            str(base_params[page_size_param])
        ]:
            raise RuntimeError("Sigma pagination refused changed selector context")

        allowed_keys = {
            *immutable_selectors,
            page_size_param,
            *_CONTINUATION_QUERY_KEYS,
        }
        if any(key not in allowed_keys for key in target_values):
            raise RuntimeError("Sigma pagination refused changed selector context")
        if any(
            len(values) != 1
            for key, values in target_values.items()
            if key in _CONTINUATION_QUERY_KEYS
        ):
            raise RuntimeError("Sigma pagination refused ambiguous continuation context")

        canonical_params = [
            (key, value)
            for key, values in target_values.items()
            if key in _CONTINUATION_QUERY_KEYS
            for value in values
        ]
        canonical_params.extend((key, value) for key, value in base_params.items())
        return target.copy_with(params=canonical_params)

    def _paginate(
        self,
        path: str,
        *,
        page_size: int = 1000,
        params: dict | None = None,
        page_size_param: str = "limit",
    ) -> list[dict]:
        """Follow Sigma cursor or same-origin link pagination without silently truncating."""
        if not 1 <= page_size <= 1000:
            raise ValueError("Sigma page_size must be between 1 and 1000")
        if page_size_param not in {"limit", "pageSize"}:
            raise ValueError("Sigma page_size_param must be limit or pageSize")

        base_params = dict(params or {})
        base_params[page_size_param] = page_size
        request_path: str | httpx.URL = path
        request_params: dict | None = dict(base_params)
        results: list[dict] = []
        seen: set[tuple[str, str]] = set()
        expected_total: int | None = None

        for _ in range(MAX_PAGINATION_PAGES):
            response = self._get(request_path, params=request_params)
            rows, continuation, has_more, total = self._page_parts(response.json(), path)
            results.extend(rows)
            if total is not None:
                expected_total = total

            if continuation is None:
                if has_more is True:
                    raise RuntimeError(
                        f"Sigma pagination at {path} reported hasMore without a continuation"
                    )
                if expected_total is not None and len(results) != expected_total:
                    raise RuntimeError(
                        f"Sigma pagination at {path} stopped after {len(results)} of "
                        f"{expected_total} entries"
                    )
                return results
            if continuation in seen:
                raise RuntimeError(f"Sigma pagination at {path} repeated its continuation")
            seen.add(continuation)

            kind, value = continuation
            if kind in ("page", "pageToken"):
                request_path = path
                request_params = {**base_params, kind: value}
            else:
                request_path = self._same_origin_url(
                    value,
                    response.request.url,
                    base_params=base_params,
                    page_size_param=page_size_param,
                )
                request_params = None
        raise RuntimeError(f"Sigma pagination at {path} exceeded its page safety limit")

    # --- inventory and data models ---
    def whoami(self) -> dict:
        return self._get("/v2/whoami").json()

    def list_connections(self) -> list[dict]:
        return self._paginate("/v2/connections")

    def list_data_models(self, *, skip_permission_check: bool = False) -> list[dict]:
        params = {"skipPermissionCheck": "true"} if skip_permission_check else None
        return self._paginate("/v2/dataModels", params=params)

    def get_data_model(self, data_model_id: str) -> dict:
        model = _path_segment(data_model_id, label="data model ID")
        return self._get(f"/v2/dataModels/{model}").json()

    def data_model_spec(self, data_model_id: str, *, document_version: int | None = None) -> dict:
        model = _path_segment(data_model_id, label="data model ID")
        params: dict[str, object] = {"format": "json"}
        if document_version is not None:
            params["documentVersion"] = document_version
        return self._get(f"/v2/dataModels/{model}/spec", params=params).json()

    def data_model_sources(self, data_model_id: str) -> list[dict]:
        model = _path_segment(data_model_id, label="data model ID")
        return self._paginate(
            f"/v2/dataModels/{model}/sources",
            page_size=500,
            page_size_param="pageSize",
        )

    def data_model_columns(self, data_model_id: str) -> list[dict]:
        model = _path_segment(data_model_id, label="data model ID")
        return self._paginate(f"/v2/dataModels/{model}/columns")

    def data_model_elements(self, data_model_id: str) -> list[dict]:
        model = _path_segment(data_model_id, label="data model ID")
        return self._paginate(f"/v2/dataModels/{model}/elements")

    def data_model_element_query(self, data_model_id: str, element_id: str) -> dict:
        model = _path_segment(data_model_id, label="data model ID")
        element = _path_segment(element_id, label="element ID")
        return self._get(f"/v2/dataModels/{model}/elements/{element}/query").json()

    def data_model_lineage(self, data_model_id: str) -> list[dict]:
        model = _path_segment(data_model_id, label="data model ID")
        return self._paginate(f"/v2/dataModels/{model}/lineage")

    def data_model_materialization_schedules(self, data_model_id: str) -> list[dict]:
        model = _path_segment(data_model_id, label="data model ID")
        return self._paginate(
            f"/v2/dataModels/{model}/materializationSchedules",
            page_size=500,
            page_size_param="pageSize",
        )

    def data_model_grants(self, data_model_id: str) -> list[dict]:
        return self.list_grants(data_model_id)

    def data_model_tags(self, data_model_id: str) -> list[dict]:
        model = _path_segment(data_model_id, label="data model ID")
        return self._paginate(f"/v2/dataModels/{model}/tags")

    # --- workbooks ---
    def list_workbooks(self, *, skip_permission_check: bool = False) -> list[dict]:
        params = {"skipPermissionCheck": "true"} if skip_permission_check else None
        return self._paginate("/v2/workbooks", params=params)

    def get_workbook(self, workbook_id: str) -> dict:
        workbook = _path_segment(workbook_id, label="workbook ID")
        return self._get(f"/v2/workbooks/{workbook}").json()

    def workbook_sources(self, workbook_id: str) -> list[dict]:
        workbook = _path_segment(workbook_id, label="workbook ID")
        return self._paginate(f"/v2/workbooks/{workbook}/sources")

    def workbook_pages(self, workbook_id: str, *, tag: str | None = None) -> list[dict]:
        workbook = _path_segment(workbook_id, label="workbook ID")
        params = {"tag": tag} if tag else None
        return self._paginate(f"/v2/workbooks/{workbook}/pages", params=params)

    def workbook_page_elements(
        self, workbook_id: str, page_id: str, *, tag: str | None = None
    ) -> list[dict]:
        workbook = _path_segment(workbook_id, label="workbook ID")
        page = _path_segment(page_id, label="page ID")
        params = {"tag": tag} if tag else None
        return self._paginate(f"/v2/workbooks/{workbook}/pages/{page}/elements", params=params)

    def workbook_elements(self, workbook_id: str, *, tag_name: str | None = None) -> list[dict]:
        workbook = _path_segment(workbook_id, label="workbook ID")
        params = {"tagName": tag_name} if tag_name else None
        return self._paginate(f"/v2/workbooks/{workbook}/elements", params=params)

    def workbook_columns(self, workbook_id: str) -> list[dict]:
        workbook = _path_segment(workbook_id, label="workbook ID")
        return self._paginate(f"/v2/workbooks/{workbook}/columns")

    def workbook_element_columns(self, workbook_id: str, element_id: str) -> list[dict]:
        workbook = _path_segment(workbook_id, label="workbook ID")
        element = _path_segment(element_id, label="element ID")
        return self._paginate(f"/v2/workbooks/{workbook}/elements/{element}/columns")

    def workbook_controls(self, workbook_id: str) -> list[dict]:
        workbook = _path_segment(workbook_id, label="workbook ID")
        return self._paginate(f"/v2/workbooks/{workbook}/controls")

    def workbook_queries(self, workbook_id: str) -> list[dict]:
        workbook = _path_segment(workbook_id, label="workbook ID")
        return self._paginate(f"/v2/workbooks/{workbook}/queries")

    def workbook_element_query(self, workbook_id: str, element_id: str) -> dict:
        workbook = _path_segment(workbook_id, label="workbook ID")
        element = _path_segment(element_id, label="element ID")
        return self._get(f"/v2/workbooks/{workbook}/elements/{element}/query").json()

    def workbook_lineage(self, workbook_id: str) -> list[dict]:
        workbook = _path_segment(workbook_id, label="workbook ID")
        return self._paginate(f"/v2/workbooks/{workbook}/lineage")

    def workbook_element_lineage(self, workbook_id: str, element_id: str) -> dict:
        workbook = _path_segment(workbook_id, label="workbook ID")
        element = _path_segment(element_id, label="element ID")
        return self._get(f"/v2/workbooks/{workbook}/lineage/elements/{element}").json()

    def list_grants(self, inode_id: str) -> list[dict]:
        return self._paginate("/v2/grants", params={"inodeId": inode_id})

    def workbook_grants(self, workbook_id: str) -> list[dict]:
        return self.list_grants(workbook_id)

    def workbook_schedules(self, workbook_id: str) -> list[dict]:
        workbook = _path_segment(workbook_id, label="workbook ID")
        return self._paginate(f"/v2/workbooks/{workbook}/schedules")

    def workbook_schedules_v21(self, workbook_id: str) -> list[dict]:
        workbook = _path_segment(workbook_id, label="workbook ID")
        return self._paginate(f"/v2.1/workbooks/{workbook}/schedules")

    def workbook_version_history(self, workbook_id: str) -> list[dict]:
        workbook = _path_segment(workbook_id, label="workbook ID")
        return self._paginate(f"/v2/workbooks/{workbook}/version-history")

    def workbook_tags(self, workbook_id: str) -> list[dict]:
        workbook = _path_segment(workbook_id, label="workbook ID")
        return self._paginate(f"/v2/workbooks/{workbook}/tags")

    def workbook_bookmarks(self, workbook_id: str) -> list[dict]:
        workbook = _path_segment(workbook_id, label="workbook ID")
        return self._paginate(f"/v2/workbooks/{workbook}/bookmarks")

    def workbook_tagged_bookmarks(self, workbook_id: str, tag_name: str) -> list[dict]:
        workbook = _path_segment(workbook_id, label="workbook ID")
        tag = _path_segment(tag_name, label="workbook tag name")
        return self._paginate(f"/v2/workbooks/{workbook}/tags/{tag}/bookmarks")

    def workbook_embeds(self, workbook_id: str) -> list[dict]:
        workbook = _path_segment(workbook_id, label="workbook ID")
        return self._paginate(f"/v2/workbooks/{workbook}/embeds")

    def workbook_materialization_schedules(self, workbook_id: str) -> list[dict]:
        workbook = _path_segment(workbook_id, label="workbook ID")
        return self._paginate(f"/v2/workbooks/{workbook}/materialization-schedules")

    # --- optional endpoint handling and snapshot assembly ---
    def _optional(
        self,
        diagnostics: list[dict],
        *,
        operation: str,
        endpoint: str,
        fetch: Callable[[], _T],
        default: _T,
    ) -> _T:
        try:
            return fetch()
        except httpx.HTTPStatusError as error:
            status_code = error.response.status_code
            if status_code not in OPTIONAL_ENDPOINT_STATUS_CODES:
                raise
            diagnostics.append(
                {
                    "operation": operation,
                    "endpoint": endpoint,
                    "status_code": status_code,
                    "status": "unavailable",
                }
            )
            return default

    @staticmethod
    def _combine_elements(bulk: list[dict], pages: list[dict]) -> list[dict]:
        combined: list[dict] = []
        positions: dict[str, int] = {}
        for element in [*bulk, *(item for page in pages for item in page.get("elements", []))]:
            record = dict(element)
            element_id = _row_id(record, "elementId", "id")
            if element_id is None or element_id not in positions:
                if element_id is not None:
                    positions[element_id] = len(combined)
                combined.append(record)
                continue
            index = positions[element_id]
            combined[index] = {**combined[index], **record}
        return combined

    @staticmethod
    def _merge_element_columns(element: dict, columns: list[dict]) -> None:
        if not columns:
            return
        detail_by_id = {
            column_id: column
            for column in columns
            if (column_id := _row_id(column, "columnId", "id")) is not None
        }
        original = element.get("columns")
        merged: list[object] = []
        seen: set[str] = set()
        if isinstance(original, list):
            for summary in original:
                column_id = (
                    _row_id(summary, "columnId", "id")
                    if isinstance(summary, dict)
                    else str(summary)
                )
                detail = detail_by_id.get(column_id)
                if detail is None:
                    merged.append(summary)
                    continue
                base = dict(summary) if isinstance(summary, dict) else {"columnId": column_id}
                merged.append({**base, **detail})
                seen.add(column_id)
        merged.extend(dict(column) for key, column in detail_by_id.items() if key not in seen)
        element["columns"] = merged

    @classmethod
    def _enrich_elements(
        cls, elements: list[dict], columns: list[dict], queries: list[dict], lineage: list[dict]
    ) -> list[dict]:
        columns_by_element: dict[str, list[dict]] = {}
        lineage_by_element: dict[str, list[dict]] = {}
        queries_by_element: dict[str, dict] = {}
        for column in columns:
            if element_id := _row_id(column, "elementId"):
                columns_by_element.setdefault(element_id, []).append(column)
        for query in queries:
            if element_id := _row_id(query, "elementId"):
                queries_by_element[element_id] = query
        for item in lineage:
            if element_id := _row_id(item, "elementId"):
                lineage_by_element.setdefault(element_id, []).append(item)

        enriched: list[dict] = []
        for raw in elements:
            element = dict(raw)
            element_id = _row_id(element, "elementId", "id")
            if element_id is not None:
                cls._merge_element_columns(element, columns_by_element.get(element_id, []))
                if element_id in queries_by_element:
                    element["generatedSql"] = dict(queries_by_element[element_id])
                if element_id in lineage_by_element:
                    element["lineage"] = [dict(item) for item in lineage_by_element[element_id]]
            enriched.append(element)
        return enriched

    @staticmethod
    def _select_inventory(
        rows: list[dict],
        selected_ids: list[str] | None,
        *,
        id_keys: tuple[str, ...],
        label: str,
        limit: int,
    ) -> list[dict]:
        selected = list(
            dict.fromkeys(str(item) for item in (selected_ids or []) if str(item).strip())
        )
        if selected and len(selected) > limit:
            raise ValueError(f"Select at most {limit} Sigma {label} per acquisition run")
        by_id = {
            row_id: dict(row) for row in rows if (row_id := _row_id(row, *id_keys)) is not None
        }
        if selected:
            missing = sorted(set(selected) - set(by_id))
            if missing:
                raise ValueError(
                    f"Selected Sigma {label} were not found or accessible: {', '.join(missing)}"
                )
            return [by_id[item] for item in selected]
        if len(by_id) > limit:
            raise ValueError(
                f"Sigma exposes {len(by_id)} accessible {label}; select {limit} or fewer "
                "before preparing migration evidence"
            )
        return list(by_id.values())

    def snapshot(
        self,
        *,
        data_model_ids: list[str] | None = None,
        workbook_ids: list[str] | None = None,
    ) -> dict:
        """Acquire a bounded, source-faithful, secret-free Sigma evidence snapshot.

        Data Model ``/spec`` responses are the authoritative modeling representation. Workbook
        endpoints contribute content, query, lineage, grant, and schedule evidence only; this
        collector deliberately does not call or claim a workbook ``/spec`` endpoint.
        """
        diagnostics: list[dict] = []
        connections = self.list_connections()

        selected_data_models = self._select_inventory(
            self.list_data_models(),
            data_model_ids,
            id_keys=("dataModelId", "id"),
            label="data models",
            limit=MAX_SELECTED_DATA_MODELS,
        )
        selected_workbooks = self._select_inventory(
            self.list_workbooks(),
            workbook_ids,
            id_keys=("workbookId", "id"),
            label="workbooks",
            limit=MAX_SELECTED_WORKBOOKS,
        )

        data_models: list[dict] = []
        for raw_model in selected_data_models:
            model = dict(raw_model)
            data_model_id = _row_id(model, "dataModelId", "id")
            if data_model_id is None:
                raise ValueError("Sigma data model inventory entry omitted dataModelId")
            model_segment = _path_segment(data_model_id, label="data model ID")
            prefix = f"/v2/dataModels/{model_segment}"
            model.update(
                {
                    "spec": self.data_model_spec(data_model_id),
                    "sources": self._optional(
                        diagnostics,
                        operation="data_model_sources",
                        endpoint=f"{prefix}/sources",
                        fetch=lambda data_model_id=data_model_id: self.data_model_sources(
                            data_model_id
                        ),
                        default=[],
                    ),
                    "columns": self._optional(
                        diagnostics,
                        operation="data_model_columns",
                        endpoint=f"{prefix}/columns",
                        fetch=lambda data_model_id=data_model_id: self.data_model_columns(
                            data_model_id
                        ),
                        default=[],
                    ),
                    "lineage": self._optional(
                        diagnostics,
                        operation="data_model_lineage",
                        endpoint=f"{prefix}/lineage",
                        fetch=lambda data_model_id=data_model_id: self.data_model_lineage(
                            data_model_id
                        ),
                        default=[],
                    ),
                    "grants": self._optional(
                        diagnostics,
                        operation="data_model_grants",
                        endpoint="/v2/grants",
                        fetch=lambda data_model_id=data_model_id: self.data_model_grants(
                            data_model_id
                        ),
                        default=[],
                    ),
                    "materializationSchedules": self._optional(
                        diagnostics,
                        operation="data_model_materialization_schedules",
                        endpoint=f"{prefix}/materializationSchedules",
                        fetch=lambda data_model_id=data_model_id: (
                            self.data_model_materialization_schedules(data_model_id)
                        ),
                        default=[],
                    ),
                }
            )
            data_models.append(model)

        workbooks: list[dict] = []
        for raw_workbook in selected_workbooks:
            workbook = dict(raw_workbook)
            workbook_id = _row_id(workbook, "workbookId", "id")
            if workbook_id is None:
                raise ValueError("Sigma workbook inventory entry omitted workbookId")
            workbook_segment = _path_segment(workbook_id, label="workbook ID")
            prefix = f"/v2/workbooks/{workbook_segment}"

            pages: list[dict] = []
            for raw_page in self.workbook_pages(workbook_id):
                page = dict(raw_page)
                page_id = _row_id(page, "pageId", "id")
                if page_id is None:
                    raise ValueError("Sigma workbook page omitted pageId")
                page["elements"] = [
                    dict(element) for element in self.workbook_page_elements(workbook_id, page_id)
                ]
                pages.append(page)

            sources = self._optional(
                diagnostics,
                operation="workbook_sources",
                endpoint=f"{prefix}/sources",
                fetch=lambda workbook_id=workbook_id: self.workbook_sources(workbook_id),
                default=[],
            )
            bulk_elements = self._optional(
                diagnostics,
                operation="workbook_elements",
                endpoint=f"{prefix}/elements",
                fetch=lambda workbook_id=workbook_id: self.workbook_elements(workbook_id),
                default=[],
            )
            raw_elements = self._combine_elements(bulk_elements, pages)

            bulk_columns = self._optional(
                diagnostics,
                operation="workbook_columns",
                endpoint=f"{prefix}/columns",
                fetch=lambda workbook_id=workbook_id: self.workbook_columns(workbook_id),
                default=None,
            )
            columns = list(bulk_columns or [])
            if bulk_columns is None:
                for element in raw_elements:
                    element_id = _row_id(element, "elementId", "id")
                    if element_id is None or str(element.get("type", "")).lower() == "control":
                        continue
                    element_columns = self._optional(
                        diagnostics,
                        operation="workbook_element_columns",
                        endpoint=(
                            f"{prefix}/elements/"
                            f"{_path_segment(element_id, label='element ID')}/columns"
                        ),
                        fetch=lambda workbook_id=workbook_id, element_id=element_id: (
                            self.workbook_element_columns(workbook_id, element_id)
                        ),
                        default=[],
                    )
                    columns.extend(
                        {**column, "elementId": column.get("elementId") or element_id}
                        for column in element_columns
                    )
            controls = self._optional(
                diagnostics,
                operation="workbook_controls",
                endpoint=f"{prefix}/controls",
                fetch=lambda workbook_id=workbook_id: self.workbook_controls(workbook_id),
                default=[],
            )
            bulk_queries = self._optional(
                diagnostics,
                operation="workbook_queries",
                endpoint=f"{prefix}/queries",
                fetch=lambda workbook_id=workbook_id: self.workbook_queries(workbook_id),
                default=None,
            )
            queries = list(bulk_queries or [])
            if bulk_queries is None:
                for element in raw_elements:
                    element_id = _row_id(element, "elementId", "id")
                    if element_id is None or str(element.get("type", "")).lower() == "control":
                        continue
                    query = self._optional(
                        diagnostics,
                        operation="workbook_element_query",
                        endpoint=(
                            f"{prefix}/elements/"
                            f"{_path_segment(element_id, label='element ID')}/query"
                        ),
                        fetch=lambda workbook_id=workbook_id, element_id=element_id: (
                            self.workbook_element_query(workbook_id, element_id)
                        ),
                        default=None,
                    )
                    if query is not None:
                        queries.append({**query, "elementId": query.get("elementId") or element_id})

            bulk_lineage = self._optional(
                diagnostics,
                operation="workbook_lineage",
                endpoint=f"{prefix}/lineage",
                fetch=lambda workbook_id=workbook_id: self.workbook_lineage(workbook_id),
                default=None,
            )
            lineage = list(bulk_lineage or [])
            if bulk_lineage is None:
                for element in raw_elements:
                    element_id = _row_id(element, "elementId", "id")
                    if element_id is None or str(element.get("type", "")).lower() == "control":
                        continue
                    element_lineage = self._optional(
                        diagnostics,
                        operation="workbook_element_lineage",
                        endpoint=(
                            f"{prefix}/lineage/elements/"
                            f"{_path_segment(element_id, label='element ID')}"
                        ),
                        fetch=lambda workbook_id=workbook_id, element_id=element_id: (
                            self.workbook_element_lineage(workbook_id, element_id)
                        ),
                        default=None,
                    )
                    if element_lineage is not None:
                        lineage.append(
                            {
                                **element_lineage,
                                "elementId": element_lineage.get("elementId") or element_id,
                            }
                        )
            grants = self._optional(
                diagnostics,
                operation="workbook_grants",
                endpoint="/v2/grants",
                fetch=lambda workbook_id=workbook_id: self.workbook_grants(workbook_id),
                default=[],
            )
            schedules = self._optional(
                diagnostics,
                operation="workbook_schedules",
                endpoint=f"{prefix}/schedules",
                fetch=lambda workbook_id=workbook_id: self.workbook_schedules(workbook_id),
                default=[],
            )
            materialization_schedules = self._optional(
                diagnostics,
                operation="workbook_materialization_schedules",
                endpoint=f"{prefix}/materialization-schedules",
                fetch=lambda workbook_id=workbook_id: self.workbook_materialization_schedules(
                    workbook_id
                ),
                default=[],
            )

            elements = self._enrich_elements(raw_elements, columns, queries, lineage)
            elements_by_id = {
                element_id: element
                for element in elements
                if (element_id := _row_id(element, "elementId", "id")) is not None
            }
            for page in pages:
                page_elements = []
                for raw_element in page["elements"]:
                    element_id = _row_id(raw_element, "elementId", "id")
                    base = elements_by_id.get(element_id, {})
                    page_elements.append({**base, **raw_element} if base else dict(raw_element))
                page["elements"] = self._enrich_elements(page_elements, columns, queries, lineage)

            if not controls:
                controls = [
                    dict(element)
                    for element in elements
                    if str(element.get("type", "")).lower() == "control"
                ]
            workbook.update(
                {
                    "sources": sources,
                    "pages": pages,
                    "elements": elements,
                    "columns": columns,
                    "controls": controls,
                    "queries": queries,
                    "lineage": lineage,
                    "grants": grants,
                    "schedules": schedules,
                    "materializationSchedules": materialization_schedules,
                }
            )
            workbooks.append(workbook)

        return {
            "connections": connections,
            "dataModels": data_models,
            "workbooks": workbooks,
            "diagnostics": diagnostics,
            "_omnikit_acquisition": {
                "contract": "sigma-api-v2",
                "definitionClass": "authoritative_definition",
                "dataModelDefinitionEndpoint": "/v2/dataModels/{dataModelId}/spec?format=json",
                "workbookDefinitionClass": "content_evidence",
                "workbookSpecClaimed": False,
                "selectedDataModelIds": [
                    item
                    for model in data_models
                    if (item := _row_id(model, "dataModelId", "id")) is not None
                ],
                "selectedWorkbookIds": [
                    item
                    for workbook in workbooks
                    if (item := _row_id(workbook, "workbookId", "id")) is not None
                ],
                "optional_endpoint_diagnostic_count": len(diagnostics),
            },
        }

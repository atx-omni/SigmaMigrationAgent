"""Explicit, bounded, read-only connection probes. No target write operations."""
from __future__ import annotations

import os
import re
import shutil
from datetime import UTC, datetime

import httpx

from omni_migrator.prepush.session import private_write, reject_secrets
from omni_migrator.prepush.settings import load_profile, resolve
from omni_migrator.security.transport import (
    ByteBudget,
    JsonResponseError,
    ResourceLimitError,
    bounded_process,
    bounded_request,
    parse_json_bytes,
    response_json,
)
from omni_migrator.security.workspace import assert_private_output


class DiscoveryError(ValueError):
    """Known-safe diagnostic; remote response bodies never become this message."""


def safe_failure(exc: Exception) -> ValueError:
    from omni_migrator.extractors.sigma.api import ConnectionLineageError
    if isinstance(exc, ConnectionLineageError):
        return ValueError(str(exc))
    if isinstance(exc, (ResourceLimitError, JsonResponseError)):
        return ValueError(str(exc))
    status = exc.response.status_code if isinstance(exc, httpx.HTTPStatusError) else None
    labels = {401: "Credentials rejected or expired; update your local credential or complete browser login",
              403: "Authenticated read is not permitted for this identity; check its platform role and selected resource access",
              404: "Selected resource not found; verify the organization and IDs",
              429: "Rate limit reached; retry later without increasing the request budget"}
    return ValueError(labels.get(status, "Connection check failed safely; check host, TLS, network, credential, and CLI capability. Remote details withheld"))


class OmniReader:
    def __init__(self, profile, values):
        self.profile, self.values, self.requests = profile, values, 0
        self.byte_budget = ByteBudget()

    def read(self, path, command, params=None):
        self.requests += 1
        if self.requests > 25:
            raise DiscoveryError("Read-only discovery request budget exhausted; narrow the selected model")
        if self.profile["target_auth"] == "token" and path is not None:
            with httpx.Client(base_url=self.profile["omni_origin"], follow_redirects=False,
                              timeout=20, trust_env=False) as client:
                response = bounded_request(client, "GET", path, params=params,
                    headers={"Authorization": "Bearer " + self.values["OMNI_API_TOKEN"]},
                    budget=self.byte_budget, timeout_seconds=20)
                response.raise_for_status()
                try:
                    return response_json(response)
                except JsonResponseError:
                    raise DiscoveryError("Omni returned invalid JSON; response details withheld") from None
        # Use only the documented fixed read commands; never read the CLI's credential store.
        if not shutil.which("omni"):
            raise DiscoveryError("This read requires the official Omni CLI. Install it for OAuth or topic discovery; token model/connection discovery works without it")
        env = {key: value for key, value in os.environ.items() if not key.startswith("OMNI_") and not key.startswith("SIGMA_")}
        if self.profile["target_auth"] == "token":
            env["OMNI_API_TOKEN"] = self.values["OMNI_API_TOKEN"]
        args = ["omni", *command, "--base-url", self.profile["omni_origin"], "-o", "json"]
        if self.profile["target_auth"] == "oauth":
            args += ["--profile", self.profile["omni_profile"]]
        result = bounded_process(args, env=env, timeout=30, budget=self.byte_budget)
        if result.returncode:
            raise DiscoveryError("Omni CLI read failed. Confirm it supports whoami and browser login, then log in to the selected profile; output withheld")
        try:
            return parse_json_bytes(result.stdout)
        except JsonResponseError:
            raise DiscoveryError("Omni CLI returned invalid JSON; output withheld") from None


def check_connections(profile, env_file, *, source=False, target=False):
    result = {}
    if source:
        if profile["source_mode"] != "api":
            raise ValueError("This profile uses local snapshots; no Sigma connection is configured")
        values = resolve(profile, env_file, source=True)
        from omni_migrator.extractors.sigma.api import SigmaApi
        api = SigmaApi(base_url=profile["sigma_origin"], client_id=values["SIGMA_CLIENT_ID"],
                       client_secret=values["SIGMA_CLIENT_SECRET"], request_budget=6)
        try:
            api.get_workbook(profile["workbook_id"])
            api.get_data_model(profile["data_model_id"])
            result["source_connection"] = "selected_workbook_and_data_model_readable_lineage_not_verified"
        except Exception as exc:
            raise safe_failure(exc) from None
        finally:
            api.close()
    if target:
        if profile["target_auth"] == "offline":
            raise ValueError("This profile is offline; create a separate connected setup to authorize discovery")
        values = resolve(profile, env_file, target=True)
        try:
            identity = OmniReader(profile, values).read("/api/v1/whoami", ["whoami", "whoami"])
            if identity.get("keyScope") not in {"user", "organization"}:
                raise DiscoveryError("Unexpected identity response")
            result["target_connection"] = "identity_verified_model_access_not_yet_checked"
            result["target_identity_scope"] = identity["keyScope"]
            result["target_org_role"] = identity.get("orgRole", "not_returned")
        except DiscoveryError:
            raise
        except Exception as exc:
            raise safe_failure(exc) from None
    return result


def discover(args):
    if not args.allow_target_read:
        raise ValueError("Add --allow-target-read to authorize read-only Omni discovery")
    assert_private_output(args.output)
    if args.output.exists() or args.output.is_symlink():
        raise ValueError("Discovery output exists; select a new file")
    profile = load_profile(args.profile)
    if profile["target_auth"] == "offline":
        raise ValueError("This profile has no target connection configured")
    values = resolve(profile, args.env_file, target=True)
    reader = OmniReader(profile, values)
    try:
        identity = reader.read("/api/v1/whoami", ["whoami", "whoami"])
        if identity.get("keyScope") not in {"user", "organization"}:
            raise DiscoveryError("Unexpected identity response")
        connections = reader.read("/api/v1/connections", ["connections", "list"])
        models, cursor, seen = [], None, set()
        for _ in range(20):
            params = {"pageSize": 100, "modelKind": "SHARED"}
            command = ["models", "list", "--pagesize", "100", "--modelkind", "SHARED"]
            if cursor:
                params["cursor"] = cursor
                command += ["--cursor", cursor]
            page = reader.read("/api/v1/models", command, params)
            models.extend(page["records"])
            if not page.get("pageInfo", {}).get("hasNextPage"):
                break
            cursor = page["pageInfo"].get("nextCursor")
            if not isinstance(cursor, str) or not cursor or cursor in seen:
                raise DiscoveryError("Invalid discovery continuation")
            seen.add(cursor)
        else:
            raise DiscoveryError("Discovery pagination limit reached")
        result = {"schema_version": "omni-discovery.v1", "origin": profile["omni_origin"],
                  "captured_at": datetime.now(UTC).isoformat(), "identity_scope": identity["keyScope"],
                  "connections": [{key: row.get(key) for key in ("id", "name", "dialect")} for row in connections["connections"]],
                  "models": [{key: row.get(key) for key in ("id", "name", "connectionId", "modelKind")} for row in models],
                  "target_write_authority": False}
        if args.model_id:
            if not any(row["id"] == args.model_id for row in result["models"]):
                raise DiscoveryError("Selected model is not in discovered shared models")
            result["selected_model_id"] = args.model_id
            result["topics_response"] = reader.read(None, ["models", "list-topics", args.model_id])
            if args.topic:
                if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", args.topic):
                    raise DiscoveryError("Invalid topic name")
                result["topic_response"] = reader.read(None, ["models", "get-topic", args.model_id, args.topic])
        elif args.topic:
            raise DiscoveryError("Select a model before a topic")
        reject_secrets(result)
        private_write(args.output, result)
    except DiscoveryError:
        raise
    except Exception as exc:
        raise safe_failure(exc) from None
    return {"status": "discovery_saved_requires_mapping_review", "output": str(args.output),
            "models": result["models"], "connections": result["connections"],
            "topic_inventory": "review_and_normalize_observed_topic_definitions_before_reuse",
            "target_write_authority": False}

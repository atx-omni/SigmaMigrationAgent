"""Explicit source-only visual capture CLI; never resolves target settings."""
from __future__ import annotations

import os

from omni_migrator.prepush.session import read_json


def capture(args):
    if not args.allow_source_read or not args.allow_source_query:
        raise ValueError("Use --allow-source-read and --allow-source-query for the selected exports")
    from omni_migrator.extractors.sigma.api import SigmaApi
    from omni_migrator.extractors.sigma.visual_capture import capture_visual
    from omni_migrator.extractors.sigma.visual_contracts import parse_visual_request
    raw = read_json(args.request)
    request = parse_visual_request(raw)
    client_id, secret = os.environ.get("SIGMA_CLIENT_ID"), os.environ.get("SIGMA_CLIENT_SECRET")
    if not client_id or not secret:
        raise ValueError("Set SIGMA_CLIENT_ID and SIGMA_CLIENT_SECRET outside the request file")
    api = SigmaApi(request.api_base_url, client_id, secret,
                   request_budget=request.max_requests_per_invocation)
    try:
        result = capture_visual(raw, api=api, directory=args.directory,
            allow_source_read=True, allow_source_query=True, resume=args.resume)
        # Do not print source payloads, parameters or result rows to the terminal.
        return {"status": result["status"], "output": result["output"],
                "target_write_authority": False, "native_validation": "not_performed"}
    finally:
        api.close()

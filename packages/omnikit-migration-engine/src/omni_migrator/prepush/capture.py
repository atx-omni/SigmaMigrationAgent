"""Explicit read-only source acquisition. Imported only by the capture command."""
import os
import re
from urllib.parse import urlsplit

from omni_migrator.prepush.session import private_write, reject_secrets


def capture(args):
    if not args.allow_source_read:
        raise ValueError("Add --allow-source-read to authorize the selected Sigma metadata read")
    url = urlsplit(args.api_url)
    host = args.trusted_api_host.lower()
    # This independent operator argument prevents source files choosing credential destinations.
    if (url.scheme != "https" or url.hostname != host or url.port not in (None, 443)
            or url.username or url.password or url.query or url.fragment or url.path not in ("", "/")
            or not re.fullmatch(r"[a-z0-9.-]+", host)):
        raise ValueError("Use an exact HTTPS Sigma API origin and matching trusted-api-host")
    if args.output.exists() or args.output.is_symlink():
        raise ValueError("Capture output already exists; use a new filename")
    if not args.workbook_id.strip() or not args.data_model_id.strip():
        raise ValueError("Select exactly one workbook and its data model")
    client_id, secret = os.environ.get("SIGMA_CLIENT_ID"), os.environ.get("SIGMA_CLIENT_SECRET")
    if not client_id or not secret:
        raise ValueError("Set SIGMA_CLIENT_ID and SIGMA_CLIENT_SECRET in this terminal")
    from omni_migrator.extractors.sigma.api import SigmaApi
    api = SigmaApi(base_url=args.api_url, client_id=client_id, client_secret=secret, request_budget=100)
    try:
        result = api.snapshot(workbook_ids=[args.workbook_id], data_model_ids=[args.data_model_id])
        # Capture is metadata, not evidence of full UI/security behavior or version acceptance.
        result["_prepush_capture"] = {"source": "sigma_read_only_api", "live_validation": "not_performed",
                                     "version_freeze_validated": False, "target_write_authority": False}
        reject_secrets(result)
        private_write(args.output, result)
    except Exception as exc:
        raise ValueError("Sigma capture failed safely. Check host, selected IDs, access and request budget; no credential details emitted") from exc
    finally:
        api.close()
    return {"status": "captured_requires_review", "output": str(args.output), "target_write_authority": False}

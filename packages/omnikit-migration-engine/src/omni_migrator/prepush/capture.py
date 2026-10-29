"""Explicit read-only source acquisition. Imported only by the capture command."""
import os
import re
from urllib.parse import urlsplit

from omni_migrator.prepush.session import private_write, reject_secrets


def capture(args):
    if not args.allow_source_read:
        raise ValueError("Add --allow-source-read to authorize the selected Sigma metadata read")
    from omni_migrator.security.workspace import assert_private_output
    assert_private_output(args.output)
    profile_path = getattr(args, "profile", None)
    env_file = getattr(args, "env_file", None)
    if profile_path:
        from omni_migrator.prepush.settings import load_profile, resolve
        profile = load_profile(profile_path)
        if profile["source_mode"] != "api":
            raise ValueError("This setup uses local source snapshots, not Sigma API capture")
        values = resolve(profile, env_file, source=True)
        for attr, key in (("api_url", "sigma_origin"), ("workbook_id", "workbook_id"), ("data_model_id", "data_model_id")):
            setattr(args, attr, getattr(args, attr, None) or profile.get(key))
        # Do not permit an origin override to silently redirect profile credentials.
        from omni_migrator.prepush.settings import origin
        if origin(args.api_url) != origin(profile["sigma_origin"]):
            raise ValueError("Capture origin conflicts with the confirmed setup profile")
        args.trusted_api_host = args.trusted_api_host or urlsplit(profile["sigma_origin"]).hostname
        client_id, secret = values["SIGMA_CLIENT_ID"], values["SIGMA_CLIENT_SECRET"]
    else:
        if env_file:
            raise ValueError("Use --profile when explicitly loading a .env file")
        client_id, secret = os.environ.get("SIGMA_CLIENT_ID"), os.environ.get("SIGMA_CLIENT_SECRET")
    if not all((args.api_url, args.trusted_api_host, args.workbook_id)):
        raise ValueError("Select a setup profile or provide API URL, trusted host and workbook ID")
    url = urlsplit(args.api_url)
    host = args.trusted_api_host.lower()
    # This independent operator argument prevents source files choosing credential destinations.
    if (url.scheme != "https" or url.hostname != host or url.port not in (None, 443)
            or url.username or url.password or url.query or url.fragment or url.path not in ("", "/")
            or not re.fullmatch(r"[a-z0-9.-]+", host)):
        raise ValueError("Use an exact HTTPS Sigma API origin and matching trusted-api-host")
    if args.output.exists() or args.output.is_symlink():
        raise ValueError("Capture output already exists; use a new filename")
    if not args.workbook_id.strip() or (args.data_model_id is not None and not args.data_model_id.strip()):
        raise ValueError("Select exactly one workbook and an optional explicit data model")
    if not client_id or not secret:
        raise ValueError("Set SIGMA_CLIENT_ID and SIGMA_CLIENT_SECRET in this terminal")
    from omni_migrator.extractors.sigma.api import SigmaApi
    budget = getattr(args, "request_budget", 100)
    if not 5 <= budget <= 1000:
        raise ValueError("Request budget must be between 5 and 1000; use a small pilot first")
    api = SigmaApi(base_url=args.api_url, client_id=client_id, client_secret=secret, request_budget=budget)
    try:
        result = api.snapshot(workbook_ids=[args.workbook_id],
                              data_model_ids=[args.data_model_id] if args.data_model_id else [],
                              allow_unresolved_dependencies=not args.data_model_id)
        # Capture is metadata, not evidence of full UI/security behavior or version acceptance.
        result["_prepush_capture"] = {"source": "sigma_read_only_api", "live_validation": "not_performed",
                                     "version_freeze_validated": False, "target_write_authority": False}
        reject_secrets(result)
        private_write(args.output, result)
    except Exception as exc:
        from omni_migrator.prepush.discovery import safe_failure
        raise safe_failure(exc) from None
    finally:
        api.close()
    return {"status": "captured_requires_review", "output": str(args.output), "target_write_authority": False}

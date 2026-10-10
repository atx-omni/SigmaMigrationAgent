"""Resumable, platform-owner setup. Credentials are entered locally, never in chat."""
from __future__ import annotations

import shutil

from omni_migrator.prepush.session import private_write
from omni_migrator.prepush.settings import POLICIES, ROUTES, load_profile, origin, required_keys, write_private_text

GUIDANCE = {
    "SIGMA_API_URL": "Sigma: Administration > Developer access. Copy the API base URL shown for this organization/region.",
    "SIGMA_CLIENT_ID": "On the same page, create REST API credentials, select the intended owner, then copy Client ID.",
    "SIGMA_CLIENT_SECRET": "Copy the newly created Client Secret into the local .env. Save it securely; Sigma shows it once.",
    "OMNI_BASE_URL": "Copy the intended Omni organization origin, for example https://your-org.omniapp.co, without a workbook path.",
    "OMNI_API_TOKEN": "Omni: User profile > Manage account > Generate token. Use a personal token with the needed read access; put it only in your local .env.",
}


def choose(ask, question, values, labels):
    print(question)
    for index, label in enumerate(labels, 1):
        print(f"{index}. {label}")
    selected = ask("Choose a number (no default): ")
    if selected not in {str(index) for index in range(1, len(values) + 1)}:
        raise ValueError("No choice selected; run setup again and select one of the listed numbers")
    return values[int(selected) - 1]


def setup(args, ask):
    if any(path.is_symlink() for path in (args.directory, *args.directory.parents)):
        raise ValueError("Symbolic links are not accepted for setup directories")
    directory = args.directory.resolve()
    directory.mkdir(parents=True, exist_ok=True)
    profile_path, env_path = directory / "migration-profile.json", directory / ".env"
    if profile_path.exists() or profile_path.is_symlink():
        profile = load_profile(profile_path)
        resumed = True
    else:
        print("Setup prepares local files only. Do not paste credentials into this conversation.")
        profile = {"schema_version": "sigma-migration-profile.v1"}
        profile["source_mode"] = choose(ask, "Where is the Sigma source?", ("api", "snapshot"),
                                        ("Read one workbook from Sigma", "Use an existing local snapshot (including fictional examples)"))
        profile["route"] = choose(ask, "Do you want this semantic layer fully modeled or lift and shifted to Omni directly?",
                                   ROUTES, ("Lift and shift directly to Omni; no dbt changes", "Model upstream first, then Omni"))
        profile["allowed_changes"] = choose(ask, "What may the proposed package contain?", POLICIES,
                                             ("Assessment only; do not build artifacts", "Dashboards using an existing topic; no model or topic changes", "Model/topic and dashboard artifacts (and dbt for modeled route)"))
        if profile["route"] == ROUTES[1] and profile["allowed_changes"] == "dashboard_only":
            raise ValueError("Dashboard-only reuse requires the direct route; no files were created")
        profile["target_auth"] = choose(ask, "How should read-only Omni discovery connect?", ("offline", "oauth", "token"),
                                         ("Stay offline; supply reviewed target details", "Existing Omni CLI OAuth profile (browser login)", "Personal access token in local .env"))
        if profile["source_mode"] == "api":
            print(GUIDANCE["SIGMA_API_URL"])
            profile["sigma_origin"] = origin(ask("Confirmed Sigma API origin: "))
            profile["workbook_id"] = ask("Sigma workbook ID (from its URL or workbook API): ")
            profile["data_model_id"] = ask("Associated Sigma data-model ID (verify the workbook's source): ")
        if profile["target_auth"] != "offline":
            print(GUIDANCE["OMNI_BASE_URL"])
            profile["omni_origin"] = origin(ask("Confirmed Omni organization origin: "))
        if profile["target_auth"] == "oauth":
            profile["omni_profile"] = ask("Name of your Omni CLI OAuth profile: ")
        # Validate before persisting without creating an invalid intermediate profile.
        from omni_migrator.prepush.settings import validate_profile
        validate_profile(profile)
        private_write(profile_path, profile)
        resumed = False
    keys = required_keys(profile)
    ignore_path = directory / ".gitignore"
    ignore_created = False
    if not ignore_path.exists() and not ignore_path.is_symlink():
        write_private_text(ignore_path, "# Local migration credentials and private working files\n.env\n.env.*\n*.local.json\n")
        ignore_created = True
    created_env = False
    if keys and not env_path.exists() and not env_path.is_symlink():
        lines = ["# Private local credentials. Do not commit, share, source, or paste this file into chat.",
                 "# This file is parsed as data. Process environment overrides these values."]
        for key in keys:
            lines.append("# " + GUIDANCE[key])
            value = {"SIGMA_API_URL": profile.get("sigma_origin"), "OMNI_BASE_URL": profile.get("omni_origin")}.get(key)
            lines.append(f"{key}={value or 'REPLACE_LOCALLY'}")
        write_private_text(env_path, "\n".join(lines) + "\n")
        created_env = True
    guide_path = directory / "SETUP-NEXT-STEPS.txt"
    if not guide_path.exists():
        lines = ["YOUR MIGRATION SETUP", "", "1. Confirm the non-secret migration-profile.json choices."]
        if keys:
            lines += ["2. Open .env locally and replace REPLACE_LOCALLY values. Keep this file private."]
            lines += [f"   {key}: {GUIDANCE[key]}" for key in keys]
        if profile["target_auth"] == "oauth":
            lines += ["Use a current official Omni CLI. Complete its browser login yourself:",
                      f"omni config init --name {profile['omni_profile']} --endpoint {profile['omni_origin']} --auth oauth",
                      f"For an existing profile: omni config login {profile['omni_profile']}",
                      "Tokens stay with the Omni CLI; this migrator never reads its credential store."]
        lines += ["3. Run sigma-migrate doctor --profile migration-profile.json for local setup status.",
                  "4. To test connections explicitly, add --env-file .env and --allow-source-read and/or --allow-target-read as applicable.",
                  "5. Capture/import your source; inspect it and choose a small pilot scope.",
                  "6. Configure reviewed mappings, initialize a run, personally review, build, validate, and export.",
                  "Assessment-only stops before artifact build. Nothing here writes to Omni or your warehouse.",
                  "Re-run setup with the same directory to resume. Existing .env/profile files are never overwritten.",
                  "For changed choices, create a new setup directory; existing runs require import and fresh review.",
                  "Official help:", "https://help.sigmacomputing.com/reference/generate-client-credentials",
                  "https://docs.omni.co/developers/cli/authentication", "https://docs.omni.co/api/authentication"]
        write_private_text(guide_path, "\n".join(lines) + "\n")
    return {"status": "setup_resumed" if resumed else "setup_created", "profile": str(profile_path),
            "env_file": str(env_path) if keys else None, "env_created": created_env,
            "required_variables": keys, "guide": str(guide_path), "connections": "not_checked",
            "ignore_protection": "created" if ignore_created else "existing_gitignore_preserved_verify_env_is_ignored",
            "target_write_authority": False}


def doctor(args):
    profile = load_profile(args.profile)
    result = {"status": "setup_incomplete", "profile_valid": True, "required_variables": required_keys(profile),
              "env_file_selected": bool(args.env_file), "omni_cli_installed": bool(shutil.which("omni")),
              "source_connection": "not_checked", "target_connection": "not_checked",
              "migration_ready": False, "target_write_authority": False}
    from omni_migrator.prepush.settings import resolve
    if args.env_file is not None or required_keys(profile):
        # Explicit doctor may validate local secret presence; never print their values.
        try:
            resolve(profile, args.env_file, source=True, target=True)
            result["credentials"] = "required_values_present_not_authenticated"
        except (ValueError, OSError):
            result["credentials"] = "missing_placeholders_or_unsafe_file_check_local_env"
            if not args.allow_source_read and not args.allow_target_read:
                return result
    if args.allow_source_read or args.allow_target_read:
        from omni_migrator.prepush.discovery import check_connections
        result.update(check_connections(profile, args.env_file, source=args.allow_source_read, target=args.allow_target_read))
        result["status"] = "connections_checked_not_migration_acceptance"
    else:
        result["status"] = "local_profile_valid_connections_not_checked"
    return result

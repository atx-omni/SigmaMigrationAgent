"""Configuration-first flow, secret boundaries and real public CLI wiring."""
import argparse
import json
from pathlib import Path
from unittest.mock import Mock

import httpx
import pytest

from omni_migrator.prepush import cli
from omni_migrator.prepush.discovery import OmniReader, check_connections, discover
from omni_migrator.prepush.onboarding import setup
from omni_migrator.prepush.session import private_write
from omni_migrator.prepush.settings import load_profile, origin, parse_dotenv, resolve, write_private_text

ROOT = Path(__file__).resolve().parents[3]


def profile(**changes):
    return {"schema_version": "sigma-migration-profile.v1", "source_mode": "snapshot",
            "route": "omni_semantic_reconstruction", "allowed_changes": "model_changes",
            "target_auth": "offline", **changes}


def save_profile(tmp_path, **changes):
    path = tmp_path / "migration-profile.json"
    private_write(path, profile(**changes))
    return path


def test_setup_offline_resumes_without_prompts_or_credentials(tmp_path):
    answers = iter(["2", "1", "3", "1"])
    result = setup(argparse.Namespace(directory=tmp_path), lambda _: next(answers))
    assert result["required_variables"] == [] and not (tmp_path / ".env").exists()
    assert load_profile(tmp_path / "migration-profile.json")["route"] == "omni_semantic_reconstruction"
    assert setup(argparse.Namespace(directory=tmp_path), lambda _: pytest.fail("asked on resume"))["status"] == "setup_resumed"


def test_setup_generates_only_selected_variables_and_never_overwrites(tmp_path):
    answers = iter(["1", "1", "2", "3", "https://api.example.com", "book", "model", "https://tenant.example.com"])
    result = setup(argparse.Namespace(directory=tmp_path), lambda _: next(answers))
    env = tmp_path / ".env"
    before = env.read_bytes()
    assert set(parse_dotenv(env)) == set(result["required_variables"])
    assert env.stat().st_mode & 0o777 == 0o600
    setup(argparse.Namespace(directory=tmp_path), lambda _: pytest.fail("unexpected question"))
    assert env.read_bytes() == before
    with pytest.raises(ValueError, match="Provide these variables"):
        resolve(load_profile(tmp_path / "migration-profile.json"), env, source=True, environ={})


@pytest.mark.parametrize("text", ["SIGMA_CLIENT_ID=$(command)\n", "export SIGMA_CLIENT_ID=x\n",
    "SIGMA_CLIENT_ID=a\nSIGMA_CLIENT_ID=b\n", "UNKNOWN=x\n", "SIGMA_CLIENT_ID=`command`\n",
    'SIGMA_CLIENT_ID="unterminated\n'])
def test_dotenv_is_not_shell(tmp_path, text):
    env = tmp_path / ".env"
    write_private_text(env, text)
    with pytest.raises(ValueError):
        parse_dotenv(env)


def test_dotenv_permissions_symlink_and_precedence(tmp_path):
    env = tmp_path / ".env"
    write_private_text(env, "OMNI_BASE_URL=https://tenant.example.com\nOMNI_API_TOKEN=file-value\n")
    config = profile(target_auth="token", omni_origin="https://tenant.example.com")
    assert resolve(config, env, target=True, environ={"OMNI_API_TOKEN": "process-value"})["OMNI_API_TOKEN"] == "process-value"
    with pytest.raises(ValueError, match="conflicts"):
        resolve(config, env, target=True, environ={"OMNI_BASE_URL": "https://different.example.com"})
    link = tmp_path / "link"
    link.symlink_to(env)
    with pytest.raises(OSError):
        parse_dotenv(link)
    env.chmod(0o644)
    with pytest.raises(ValueError, match="owner-only"):
        parse_dotenv(env)


@pytest.mark.parametrize("value", ["http://api.example.com", "https://a.example.com/other", "https://user:secret@a.example.com", "https://a.example.com:8443", "https://a.example.com?token=secret"])
def test_invalid_origins(value):
    with pytest.raises(ValueError):
        origin(value)


def test_local_doctor_never_loads_env_or_connects(tmp_path, monkeypatch):
    path = save_profile(tmp_path)
    monkeypatch.setattr("omni_migrator.prepush.settings.parse_dotenv", lambda _: pytest.fail("loaded credentials"))
    monkeypatch.setattr(httpx.Client, "get", lambda *a, **k: pytest.fail("connected"))
    result = cli.run(cli.parser().parse_args(["doctor", "--profile", str(path)]))
    assert result["source_connection"] == result["target_connection"] == "not_checked"
    assert result["migration_ready"] is False


def test_local_doctor_reports_missing_credentials_without_network(tmp_path, monkeypatch):
    path = save_profile(tmp_path, target_auth="token", omni_origin="https://tenant.example.com")
    monkeypatch.delenv("OMNI_BASE_URL", raising=False)
    monkeypatch.delenv("OMNI_API_TOKEN", raising=False)
    monkeypatch.setattr(httpx.Client, "get", lambda *a, **k: pytest.fail("connected"))
    result = cli.run(cli.parser().parse_args(["doctor", "--profile", str(path)]))
    assert result["status"] == "setup_incomplete"
    assert result["credentials"] == "missing_placeholders_or_unsafe_file_check_local_env"


def test_read_only_token_doctor_redacts_remote_error(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNI_BASE_URL", "https://tenant.example.com")
    monkeypatch.setenv("OMNI_API_TOKEN", "fictional-secret")
    original = httpx.Client
    requests = []
    def handler(request):
        requests.append(request)
        return httpx.Response(401, json={"error": "fictional-secret"})
    monkeypatch.setattr(httpx, "Client", lambda **kwargs: original(**kwargs, transport=httpx.MockTransport(handler)))
    with pytest.raises(ValueError) as exc:
        check_connections(profile(target_auth="token", omni_origin="https://tenant.example.com"), None, target=True)
    assert "fictional-secret" not in str(exc.value) and "rejected" in str(exc.value)
    assert len(requests) == 1 and requests[0].method == "GET"


def test_read_only_token_discovery_paginates_and_saves_no_secrets(tmp_path, monkeypatch):
    path = save_profile(tmp_path, target_auth="token", omni_origin="https://tenant.example.com")
    monkeypatch.setenv("OMNI_BASE_URL", "https://tenant.example.com")
    monkeypatch.setenv("OMNI_API_TOKEN", "fictional-secret")
    original = httpx.Client
    requests = []
    def handler(request):
        requests.append(request)
        if request.url.path.endswith("whoami"):
            return httpx.Response(200, json={"keyScope": "user", "orgRole": "MEMBER"})
        if request.url.path.endswith("connections"):
            return httpx.Response(200, json={"connections": [{"id": "c", "name": "Warehouse", "password": "never-save"}]})
        after = bool(request.url.params.get("cursor"))
        return httpx.Response(200, json={"records": [{"id": "m2" if after else "m1", "connectionId": "c"}],
                                        "pageInfo": {"hasNextPage": not after, "nextCursor": "next"}})
    monkeypatch.setattr(httpx, "Client", lambda **kwargs: original(**kwargs, transport=httpx.MockTransport(handler)))
    out = tmp_path / "discovery.json"
    result = discover(argparse.Namespace(profile=path, env_file=None, output=out, model_id=None, topic=None, allow_target_read=True))
    assert len(result["models"]) == 2 and all(r.method == "GET" for r in requests)
    assert "fictional-secret" not in out.read_text() and "never-save" not in out.read_text()


def test_oauth_delegates_fixed_read_command_without_ambient_credentials(monkeypatch):
    monkeypatch.setenv("OMNI_API_TOKEN", "ambient-secret")
    runner = Mock(return_value=argparse.Namespace(returncode=0, stdout=b'{"keyScope":"user"}', stderr=b""))
    monkeypatch.setattr("omni_migrator.prepush.discovery.bounded_process", runner)
    monkeypatch.setattr("shutil.which", lambda _: "/fictional/omni")
    reader = OmniReader(profile(target_auth="oauth", omni_origin="https://tenant.example.com", omni_profile="migration"), {})
    reader.read("/api/v1/whoami", ["whoami", "whoami"])
    args, kwargs = runner.call_args
    assert args[0][:3] == ["omni", "whoami", "whoami"]
    assert "--token" not in args[0] and "OMNI_API_TOKEN" not in kwargs["env"]
    assert kwargs["timeout"] == 30


def test_profile_initialization_retains_selected_route(tmp_path):
    path = save_profile(tmp_path)
    result = cli.run(cli.parser().parse_args(["init", "--profile", str(path), "--run-dir", str(tmp_path / "run"),
        "--source", str(ROOT / "examples/retail-supported.json"), "--target", str(ROOT / "examples/target.json"), "--synthetic"]))
    assert result["route"] == "omni_semantic_reconstruction"


def test_direct_configure_never_prompts_for_modeled_table(tmp_path):
    from omni_migrator.prepush.configure import configure
    path = save_profile(tmp_path)
    expected = json.loads((ROOT / "examples/target.json").read_text())
    answers = [expected["model_id"], expected["connection_id"], "Pilot"]
    for relation in expected["relations"].values():
        answers += [relation["schema"], relation["table"], *relation["columns"].values()]
    iterator = iter(answers)
    prompts = []
    def ask(prompt):
        prompts.append(prompt)
        return next(iterator)
    configure(argparse.Namespace(source=ROOT / "examples/retail-supported.json", output=tmp_path / "target.json", profile=path), ask)
    assert not any("Modeled destination" in prompt for prompt in prompts)


def test_customer_topic_template_matches_typed_contract():
    from omni_migrator.prepush.reuse import TopicInventory
    inventory = json.loads((ROOT / "examples/retail-topic-inventory.json").read_text())
    assert TopicInventory.model_validate(inventory).topic_name == "retail"


def test_discovery_requires_explicit_authorization_before_any_credentials(tmp_path, monkeypatch):
    monkeypatch.setattr("omni_migrator.prepush.discovery.resolve", lambda *a, **k: pytest.fail("credentials loaded"))
    with pytest.raises(ValueError, match="allow-target-read"):
        discover(argparse.Namespace(allow_target_read=False))


def test_token_redirect_never_forwards_credentials(tmp_path, monkeypatch):
    original = httpx.Client
    requests = []
    def handler(request):
        requests.append(request)
        return httpx.Response(302, headers={"Location": "https://other.example.com/api/v1/whoami"})
    monkeypatch.setattr(httpx, "Client", lambda **kwargs: original(**kwargs, transport=httpx.MockTransport(handler)))
    reader = OmniReader(profile(target_auth="token", omni_origin="https://tenant.example.com"), {"OMNI_API_TOKEN": "fictional"})
    with pytest.raises(httpx.HTTPStatusError):
        reader.read("/api/v1/whoami", ["whoami", "whoami"])
    assert len(requests) == 1 and requests[0].url.host == "tenant.example.com"

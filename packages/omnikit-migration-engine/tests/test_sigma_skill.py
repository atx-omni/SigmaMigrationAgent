"""Keep the shipped skill tied to the installed runtime and real public commands."""

from pathlib import Path
import re
import shlex
import tomllib

import yaml

from omni_migrator.prepush.cli import parser
from omni_migrator.prepush.session import MODES


ROOT = Path(__file__).resolve().parents[3]
SKILL = ROOT / ".agents/skills/sigma-to-omni-migration"


def test_skill_metadata_tracks_runtime_and_resources_resolve():
    text = (SKILL / "SKILL.md").read_text()
    metadata = yaml.safe_load(text.split("---", 2)[1])
    project = tomllib.loads((ROOT / "packages/omnikit-migration-engine/pyproject.toml").read_text())
    assert metadata["name"] == SKILL.name
    assert metadata["metadata"]["runtime-package"] == project["project"]["name"]
    assert metadata["metadata"]["runtime-version"] == project["project"]["version"]
    assert isinstance(metadata["description"], str) and metadata["description"].strip()
    for path in SKILL.rglob("*.md"):
        for target in re.findall(r"\[[^\]]+\]\(([^)]+)\)", path.read_text()):
            if target.startswith("https://"):
                continue
            resolved = (path.parent / target).resolve(strict=True)
            assert resolved.is_relative_to(SKILL.resolve()) and resolved.is_file()
    ui = yaml.safe_load((SKILL / "agents/openai.yaml").read_text())
    assert "$" + SKILL.name in ui["interface"]["default_prompt"]
    assert ui.get("policy", {}).get("allow_implicit_invocation", True) is True


def test_skill_walkthrough_commands_parse_against_public_cli():
    """Check usable documented invocations, not merely the presence of headings."""
    workflow = (SKILL / "references/runtime-workflow.md").read_text()
    operations, modes = set(), set()
    cli = parser()
    for block in re.findall(r"```sh\n(.*?)\n```", workflow, re.DOTALL):
        for line in block.splitlines():
            tokens = shlex.split(line)
            if not tokens or tokens[0] != ".venv/bin/sigma-migrate":
                continue
            if tokens[1:] == ["--help"]:
                continue
            args = cli.parse_args(tokens[1:])
            operations.add(args.operation)
            if args.operation == "route":
                modes.add(args.mode)
            if args.operation == "init" and args.run_dir == Path("demo-run"):
                assert args.synthetic is True
                assert (ROOT / args.source).is_file() and (ROOT / args.target).is_file()
    assert modes == set(MODES)
    assert operations == {
        "capture", "inspect", "configure", "import-context", "init", "route", "review",
        "status", "build", "validate", "export", "import-source", "import-target", "revoke",
        "setup", "doctor", "discover", "scope", "report",
    }

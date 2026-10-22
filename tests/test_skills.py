"""Keep the skills well-formed: frontmatter, tool names, README listing, templates."""

import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
SKILLS = sorted(p for p in (ROOT / "skills").iterdir() if p.is_dir())
TOOLS = {"arcane_run", "arcane_help", "arcane_api_get", "arcane_environments"}


def frontmatter(path: Path) -> dict:
    text = path.read_text()
    match = re.match(r"^---\n(.*?)\n---\n", text, re.S)
    assert match, f"{path} has no YAML frontmatter"
    return yaml.safe_load(match.group(1))


@pytest.mark.parametrize("skill", SKILLS, ids=lambda p: p.name)
def test_frontmatter(skill):
    meta = frontmatter(skill / "SKILL.md")
    assert meta["name"] == skill.name
    assert isinstance(meta["description"], str) and 40 < len(meta["description"]) <= 1024


@pytest.mark.parametrize("skill", SKILLS, ids=lambda p: p.name)
def test_only_real_tools_referenced(skill):
    named = set(re.findall(r"\barcane_[a-z_]+\b", (skill / "SKILL.md").read_text()))
    assert named <= TOOLS, named - TOOLS


@pytest.mark.parametrize("skill", SKILLS, ids=lambda p: p.name)
def test_listed_in_readme(skill):
    assert f"skills/{skill.name}/SKILL.md" in (ROOT / "README.md").read_text()


def _filled(path: Path) -> str:
    return re.sub(r"<[a-z-]+>", lambda m: "8080" if m.group(0) == "<container-port>" else "example",
                  path.read_text())


def test_deploy_templates_parse():
    templates = ROOT / "skills" / "arcane-github-deploy" / "templates"
    workflow = yaml.safe_load(_filled(templates / "github-workflow.yml"))
    assert set(workflow["jobs"]) == {"test", "image"}
    assert workflow["jobs"]["image"]["permissions"]["packages"] == "write"
    compose = yaml.safe_load(_filled(templates / "compose.yaml"))
    service = compose["services"]["example"]
    assert service["image"] == "ghcr.io/example/example:latest"
    assert service["env_file"] == ".env" and "build" not in service


def test_template_matches_this_repos_workflow():
    # The template is this repo's own (proven) workflow with a generic test job.
    ours = yaml.safe_load((ROOT / ".github" / "workflows" / "image.yml").read_text())
    template = yaml.safe_load((ROOT / "skills" / "arcane-github-deploy" / "templates" / "github-workflow.yml").read_text())
    assert ours["jobs"]["image"] == template["jobs"]["image"]


def test_readme_project_compose_parses():
    # The compose file README section 3b tells the user to paste into Arcane.
    readme = (ROOT / "README.md").read_text()
    section = readme[readme.index("## 3b. Deploy as an Arcane project"):readme.index("## 4. Connect Claude")]
    block = re.search(r"```yaml\n(.*?)```", section, re.S).group(1)
    service = yaml.safe_load(re.sub(r"(?m)^   ", "", block))["services"]["arcane-cli-mcp"]
    assert service["image"] == "ghcr.io/joshnewman17/arcane-mcp:latest"
    assert service["env_file"] == ".env" and service["read_only"] is True and "build" not in service

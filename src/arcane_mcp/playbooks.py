"""Operational playbooks served over MCP, from the same files the Claude plugin ships as skills."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

_FRONTMATTER = re.compile(r"^---\n(.*?)\n---\n", re.S)
_FENCE = {".yml": "yaml", ".yaml": "yaml"}


@dataclass(frozen=True)
class Playbook:
    name: str
    description: str
    path: Path


def default_root() -> Path:
    """The wheel bundles ``skills/`` as ``arcane_mcp/skills``; a source checkout has it at the repo root."""
    bundled = Path(__file__).parent / "skills"
    return bundled if bundled.is_dir() else Path(__file__).resolve().parents[2] / "skills"


class Playbooks:
    def __init__(self, root: Path | None = None) -> None:
        self._items: dict[str, Playbook] = {}
        root = root or default_root()
        for skill in sorted(root.glob("*/SKILL.md")) if root.is_dir() else []:
            match = _FRONTMATTER.match(skill.read_text())
            meta = yaml.safe_load(match.group(1)) if match else {}
            name = meta.get("name") or skill.parent.name
            self._items[name] = Playbook(name, str(meta.get("description", "")), skill)

    def __iter__(self):
        return iter(self._items.values())

    def __bool__(self) -> bool:
        return bool(self._items)

    def listing(self) -> dict[str, Any]:
        return {"playbooks": [{"name": p.name, "use_when": p.description} for p in self]}

    def text(self, name: str) -> str | None:
        playbook = self._items.get(name)
        if playbook is None:
            return None
        body = _FRONTMATTER.sub("", playbook.path.read_text(), count=1).strip()
        templates = sorted((playbook.path.parent / "templates").glob("*"))
        for template in templates:
            lang = _FENCE.get(template.suffix, "")
            body += f"\n\n### templates/{template.name}\n\n```{lang}\n{template.read_text().rstrip()}\n```"
        return body

    def get(self, name: str | None) -> dict[str, Any]:
        if not name:
            return {"ok": True, **self.listing()}
        text = self.text(name)
        if text is None:
            return {"ok": False, "error": f"unknown playbook {name!r}", **self.listing()}
        return {"ok": True, "name": name, "playbook": text}

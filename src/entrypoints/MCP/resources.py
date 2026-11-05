"""Read-only MCP resources backed by Markdown files under src/skills."""

from __future__ import annotations

from pathlib import Path
from urllib.parse import quote


SKILLS_ROOT = Path(__file__).resolve().parents[2] / "skills"
URI_PREFIX = "apre://skills/"
MIME_TYPE = "text/markdown"


class SkillResources:
    def __init__(self, root: Path = SKILLS_ROOT):
        self.root = root.resolve()

    def _paths(self):
        for path in sorted(self.root.rglob("*.md")):
            try:
                # Reject links even when they happen to point inside the root.
                relative_path = path.relative_to(self.root)
                if any((self.root / Path(*relative_path.parts[:i])).is_symlink()
                       for i in range(1, len(relative_path.parts) + 1)):
                    continue
                resolved = path.resolve()
                resolved.relative_to(self.root)
            except (OSError, RuntimeError, ValueError):
                continue
            if not resolved.is_file():
                continue
            relative = path.relative_to(self.root).as_posix()
            yield URI_PREFIX + quote(relative, safe="/"), relative, resolved

    @staticmethod
    def _description(text: str, fallback: str) -> str:
        # Skill metadata uses single-line frontmatter; Markdown stays unmodified.
        lines = text.splitlines()
        if lines and lines[0] == "---":
            for line in lines[1:]:
                if line == "---":
                    break
                key, separator, value = line.partition(":")
                if separator and key == "description" and value.strip():
                    return value.strip()
        return fallback

    def list_resources(self) -> list[dict]:
        return [
            {
                "uri": uri,
                "name": relative,
                "description": self._description(
                    path.read_text(encoding="utf-8"), "APRE Skill: " + relative,
                ),
                "mimeType": MIME_TYPE,
            }
            for uri, relative, path in self._paths()
        ]

    def read_resource(self, uri: str) -> dict:
        # Match only published URIs; never turn a client URI into a filesystem path.
        for known_uri, _, path in self._paths():
            if uri == known_uri:
                return {
                    "uri": known_uri,
                    "mimeType": MIME_TYPE,
                    "text": path.read_text(encoding="utf-8"),
                }
        raise FileNotFoundError("Unknown Skill resource")

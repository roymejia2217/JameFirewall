"""Contracts for Release Please tag-first publication."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT / "release-please-config.json"
WORKFLOW = ROOT / ".github/workflows/ci-build-release.yml"


def test_release_please_precreates_release_tag() -> None:
    config = json.loads(CONFIG.read_text(encoding="utf-8"))
    package = config["packages"]["."]

    assert package["force-tag-creation"] is True
    assert package.get("skip-github-release", False) is False


def test_tag_first_release_uses_explicit_release_authority() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")
    release = workflow.split("  release-please:\n", 1)[1].split("  publish-windows:\n", 1)[0]

    assert "create-github-app-token" in release
    assert "steps.release-app-token.outputs.token" in release
    assert "token: ${{ secrets.GITHUB_TOKEN }}" not in release

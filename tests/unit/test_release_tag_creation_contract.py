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


def test_tag_first_release_keeps_builtin_token_boundary() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")
    release = workflow.split("  release-please:\n", 1)[1].split("  publish-windows:\n", 1)[0]

    for permission in ("contents: write", "issues: write", "pull-requests: write"):
        assert permission in release
    assert "secrets.GITHUB_TOKEN" in release
    for forbidden in ("workflows: write", "id-token: write", "actions: write"):
        assert forbidden not in release
    assert "create-github-app-token" not in release

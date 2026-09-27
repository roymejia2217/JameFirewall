"""Contracts for Release Please publication authority."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/ci-build-release.yml"


def _job_block(text: str, start: str, end: str) -> str:
    return text.split(start, maxsplit=1)[1].split(end, maxsplit=1)[0]


def test_release_please_builtin_token_is_read_only() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")
    release = _job_block(
        workflow,
        "  release-please:\n",
        "  publish-windows:\n",
    )

    assert "      contents: read" in release
    assert "      contents: write" not in release
    assert "      issues: write" not in release
    assert "      pull-requests: write" not in release


def test_publish_asset_job_does_not_inherit_release_or_issue_permissions() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")
    publish = workflow.split("  publish-windows:\n", maxsplit=1)[1]

    assert "      contents: write" in publish
    assert "      issues: write" not in publish
    assert "      pull-requests: write" not in publish

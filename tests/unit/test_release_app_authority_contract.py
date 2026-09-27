"""Contracts for the dedicated GitHub App release authority."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/ci-build-release.yml"
APP_ACTION_SHA = "bcd2ba49218906704ab6c1aa796996da409d3eb1"


def _release_job() -> str:
    workflow = WORKFLOW.read_text(encoding="utf-8")
    return workflow.split("  release-please:\n", 1)[1].split("  publish-windows:\n", 1)[0]


def test_release_job_uses_pinned_github_app_token() -> None:
    release = _release_job()

    assert f"actions/create-github-app-token@{APP_ACTION_SHA}" in release
    assert "id: release-app-token" in release
    assert "vars.JAMEFIREWALL_RELEASE_APP_CLIENT_ID" in release
    assert "secrets.JAMEFIREWALL_RELEASE_APP_PRIVATE_KEY" in release
    assert "permission-contents: write" in release
    assert "permission-workflows: write" in release
    assert "permission-issues: write" in release
    assert "permission-pull-requests: write" in release

    token_step = release.split("- name: Create scoped release GitHub App token", 1)[1].split(
        "- name: Run Release-Please Engine", 1
    )[0]
    assert "owner:" not in token_step
    assert "repositories:" not in token_step
    assert "skip-token-revoke:" not in token_step


def test_release_please_consumes_app_token_only() -> None:
    release = _release_job()

    assert "steps.release-app-token.outputs.token" in release
    assert "token: ${{ secrets.GITHUB_TOKEN }}" not in release


def test_builtin_token_is_read_only_for_release_orchestration() -> None:
    release = _release_job()

    assert "      contents: read" in release
    for forbidden in (
        "      contents: write",
        "      issues: write",
        "      pull-requests: write",
        "      workflows: write",
    ):
        assert forbidden not in release


def test_release_app_credentials_do_not_escape_orchestration_job() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")
    release = _release_job()
    publish = workflow.split("  publish-windows:\n", 1)[1]

    assert workflow.count("JAMEFIREWALL_RELEASE_APP_CLIENT_ID") == 1
    assert workflow.count("JAMEFIREWALL_RELEASE_APP_PRIVATE_KEY") == 1
    assert "JAMEFIREWALL_RELEASE_APP_CLIENT_ID" not in publish
    assert "JAMEFIREWALL_RELEASE_APP_PRIVATE_KEY" not in publish
    assert "release-app-token.outputs.token" not in publish
    assert "continue-on-error" not in release

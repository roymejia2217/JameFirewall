"""Governance contracts for immutable Windows asset recovery."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RECOVERY = ROOT / ".github/workflows/release-asset-recovery.yml"
PIPELINE = ROOT / ".github/workflows/ci-build-release.yml"


def test_regular_publisher_uses_shared_staging_adapter() -> None:
    workflow = PIPELINE.read_text(encoding="utf-8")
    publish = workflow.split("  publish-windows:\n", 1)[1]

    assert "scripts/stage_release_assets.py" in publish
    assert "candidate/JameFirewall.exe" not in publish
    assert "candidate/dist/JameFirewall.exe" not in publish


def test_recovery_downloads_prior_verified_artifact_without_rebuild() -> None:
    workflow = RECOVERY.read_text(encoding="utf-8")

    for required in (
        "source_run_id:",
        "source_run_head_sha:",
        "release_tag:",
        "release_target_sha:",
        "release_version:",
        "expected_sha256:",
        "windows-release-candidate",
        "run-id: ${{ inputs.source_run_id }}",
        "github-token: ${{ github.token }}",
        "scripts/stage_release_assets.py",
    ):
        assert required in workflow

    for provenance_check in (
        'test "$GITHUB_REF" = "refs/heads/main"',
        """test "$(jq -r '.path' <<<"$RUN_METADATA")" = ".github/workflows/ci-build-release.yml" """.strip(),
        """test "$(jq -r '.head_branch' <<<"$RUN_METADATA")" = "main" """.strip(),
        """test "$(jq -r '.event' <<<"$RUN_METADATA")" = "push" """.strip(),
        """test "$(jq -r '.status' <<<"$RUN_METADATA")" = "completed" """.strip(),
        """test "$(jq -r '.conclusion' <<<"$RUN_METADATA")" = "failure" """.strip(),
        """test "$(jq -r '.head_sha' <<<"$RUN_METADATA")" = "$SOURCE_RUN_HEAD_SHA" """.strip(),
        """test "$(jq -r '.target_commitish' <<<"$RELEASE_METADATA")" = "$RELEASE_TARGET_SHA" """.strip(),
        """test "$(jq -r '.object.sha' <<<"$TAG_METADATA")" = "$RELEASE_TARGET_SHA" """.strip(),
    ):
        assert provenance_check in workflow

    for forbidden in ("pyinstaller", "Build production Windows executable", "uv sync"):
        assert forbidden not in workflow


def test_recovery_is_fail_closed_and_does_not_replace_assets() -> None:
    workflow = RECOVERY.read_text(encoding="utf-8")

    assert "actions: read" in workflow
    assert "contents: write" in workflow
    assert "gh release upload" in workflow
    assert "--clobber" not in workflow
    assert "existing release asset" in workflow
    assert 'test "$RELEASE_TAG" = "v$RELEASE_VERSION"' in workflow

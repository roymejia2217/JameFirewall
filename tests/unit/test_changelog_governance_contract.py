"""Contracts for standards-backed changelog governance."""

from __future__ import annotations

import json
import tomllib
from pathlib import Path
from typing import Any, cast

ROOT = Path(__file__).resolve().parents[2]
PYPROJECT = ROOT / "pyproject.toml"
RELEASE_PLEASE = ROOT / "release-please-config.json"
PRE_COMMIT = ROOT / ".pre-commit-config.yaml"
CI = ROOT / ".github/workflows/ci.yml"
CHANGELOG = ROOT / "CHANGELOG.md"
TEMPLATE = ROOT / "changelog.d/towncrier-template.md"
CONTRIBUTING = ROOT / "CONTRIBUTING.md"
OWNERSHIP = ROOT / "scripts/validate_changelog_ownership.py"

TOWNCRIER_VERSION = "26.9.0"
TOWNCRIER_HOOK_SHA = "12e95a9ecf4f6a8091e751238fb81144b37f064c"
PUBLIC_TYPES = [
    ("added", "Added"),
    ("changed", "Changed"),
    ("deprecated", "Deprecated"),
    ("removed", "Removed"),
    ("fixed", "Fixed"),
    ("security", "Security"),
]


def _pyproject() -> dict[str, Any]:
    return tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))


def test_towncrier_is_pinned_and_owns_keep_a_changelog_rendering() -> None:
    project = _pyproject()
    dev = cast(list[str], project["project"]["optional-dependencies"]["dev"])
    towncrier = cast(dict[str, Any], project["tool"]["towncrier"])

    assert f"towncrier=={TOWNCRIER_VERSION}" in dev
    assert towncrier["package"] == "jame_firewall"
    assert towncrier["package_dir"] == "src"
    assert towncrier["directory"] == "changelog.d"
    assert towncrier["filename"] == "CHANGELOG.md"
    assert towncrier["template"] == "changelog.d/towncrier-template.md"
    assert towncrier["start_string"] == "<!-- towncrier release notes start -->\n"

    types = cast(list[dict[str, Any]], towncrier["type"])
    assert [(item["directory"], item["name"]) for item in types[:6]] == PUBLIC_TYPES
    assert types[6] == {
        "directory": "internal",
        "name": "Internal",
        "showcontent": True,
    }


def test_release_please_no_longer_writes_or_styles_changelog() -> None:
    config = json.loads(RELEASE_PLEASE.read_text(encoding="utf-8"))
    package = config["packages"]["."]

    assert package["skip-changelog"] is True
    assert "changelog-sections" not in package


def test_pre_commit_uses_immutable_towncrier_hook() -> None:
    config = PRE_COMMIT.read_text(encoding="utf-8")

    assert "repo: https://github.com/twisted/towncrier" in config
    assert f"rev: {TOWNCRIER_HOOK_SHA}" in config
    assert "id: towncrier-check" in config
    assert "files: ^changelog\\.d/" in config


def test_changelog_is_keep_a_changelog_without_decorative_sections() -> None:
    text = CHANGELOG.read_text(encoding="utf-8")

    assert text.startswith("# Changelog\n")
    assert "Keep a Changelog" in text
    assert "Semantic Versioning" in text
    assert "<!-- towncrier release notes start -->" in text
    assert "## [0.2.0]" in text

    for heading in ("Added", "Changed", "Deprecated", "Removed", "Fixed", "Security"):
        assert f"### {heading}" in text or heading in {"Deprecated", "Removed", "Security"}

    for forbidden in ("✨", "🐛", "⚡", "♻️", "📚", "🔧", "Nuevas Funcionalidades"):
        assert forbidden not in text


def test_internal_fragments_are_filtered_by_towncrier_template() -> None:
    template = TEMPLATE.read_text(encoding="utf-8")

    assert 'category != "internal"' in template
    assert "sections" in template
    assert "definitions" in template


def test_changelog_governance_is_required_ci() -> None:
    workflow = CI.read_text(encoding="utf-8")

    assert "changelog:" in workflow
    assert "name: Changelog Governance" in workflow
    assert "uv run towncrier check --compare-with" in workflow
    assert "bash scripts/test-changelog-governance.sh" in workflow

    required = workflow.split("  required-ci:", maxsplit=1)[1]
    assert "      - changelog" in required
    assert "CHANGELOG_RESULT:" in required
    assert 'test "$CHANGELOG_RESULT" = "success"' in required


def test_changelog_single_writer_ownership_is_enforced() -> None:
    validator = OWNERSHIP.read_text(encoding="utf-8")
    workflow = CI.read_text(encoding="utf-8")

    assert "ordinary pull requests must not edit CHANGELOG.md" in validator
    assert "release/changelog-" in validator
    assert "Release Please must not modify CHANGELOG.md" in validator
    assert "scripts/validate_changelog_ownership.py" in workflow


def test_release_preparation_scope_is_explicit_in_commit_and_pr_profiles() -> None:
    commitlint = (ROOT / ".commitlintrc.json").read_text(encoding="utf-8")
    pr_workflow = (ROOT / ".github/workflows/pr-audit-gate.yml").read_text(encoding="utf-8")

    assert '"release"' in commitlint
    standard_profile = pr_workflow.split(
        "- name: Validate standard Conventional Commits pull request title", maxsplit=1
    )[1].split("- name: Validate Release Please pull request title", maxsplit=1)[0]
    assert "\n            release\n" in standard_profile


def test_contributor_policy_declares_single_changelog_authority() -> None:
    text = CONTRIBUTING.read_text(encoding="utf-8")

    for required in (
        "Towncrier",
        "Keep a Changelog",
        "changelog.d",
        "internal",
        "Release Please",
        "skip-changelog",
    ):
        assert required in text

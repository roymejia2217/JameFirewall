"""Repository contract for standards-backed commit message governance."""

from __future__ import annotations

import json
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
COMMITLINT_JSON = REPOSITORY_ROOT / ".commitlintrc.json"
RELEASE_CONFIG = REPOSITORY_ROOT / "commitlint.release.config.cjs"
PACKAGE_JSON = REPOSITORY_ROOT / "package.json"
PACKAGE_LOCK = REPOSITORY_ROOT / "package-lock.json"
PRE_COMMIT = REPOSITORY_ROOT / ".pre-commit-config.yaml"
CI_WORKFLOW = REPOSITORY_ROOT / ".github/workflows/ci.yml"
SELF_TEST = REPOSITORY_ROOT / "scripts/test-commitlint.sh"
RANGE_VALIDATOR = REPOSITORY_ROOT / "scripts/validate_commit_range.sh"

EXPECTED_HOOK_SHA = "1f1ac45c93d1c2ce36b71330252c489a5f4f2724"


def test_commitlint_profile_requires_a_meaningful_body() -> None:
    config = json.loads(COMMITLINT_JSON.read_text(encoding="utf-8"))
    rules = config["rules"]

    assert config["extends"] == ["@commitlint/config-conventional"]
    assert config["defaultIgnores"] is False
    assert rules["body-empty"] == [2, "never"]
    assert rules["body-min-length"] == [2, "always", 20]
    assert rules["body-leading-blank"] == [2, "always"]
    assert rules["body-max-line-length"] == [2, "always", 100]
    assert rules["header-max-length"] == [2, "always", 72]
    assert "main" not in rules["scope-enum"][2]


def test_official_commitlint_dependencies_are_exactly_locked() -> None:
    package = json.loads(PACKAGE_JSON.read_text(encoding="utf-8"))
    lock = json.loads(PACKAGE_LOCK.read_text(encoding="utf-8"))

    dev_dependencies = package["devDependencies"]
    assert dev_dependencies["@commitlint/cli"] == "21.2.2"
    assert dev_dependencies["@commitlint/config-conventional"] == "21.2.2"
    packages = lock["packages"]
    assert packages["node_modules/@commitlint/cli"]["version"] == "21.2.2"
    assert packages["node_modules/@commitlint/config-conventional"]["version"] == "21.2.2"


def test_commitlint_pre_commit_integration_is_immutable_and_version_pinned() -> None:
    config = PRE_COMMIT.read_text(encoding="utf-8")

    assert f"rev: {EXPECTED_HOOK_SHA}" in config
    assert "@commitlint/cli@21.2.2" in config
    assert "@commitlint/config-conventional@21.2.2" in config


def test_commitlint_self_test_proves_required_body_and_line_contracts() -> None:
    harness = SELF_TEST.read_text(encoding="utf-8")

    for required in (
        "missing body",
        "body below minimum length",
        "body without leading blank",
        "body line over 100 characters",
        "release commit under the normal profile",
        "release_commitlint",
    ):
        assert required in harness


def test_release_profile_is_narrower_than_the_normal_profile() -> None:
    config = RELEASE_CONFIG.read_text(encoding="utf-8")

    assert "'type-enum': [2, 'always', ['chore']]" in config
    assert "'scope-enum': [2, 'always', ['main']]" in config
    assert "'body-empty': [0]" in config
    assert "'body-min-length': [0]" in config


def test_ci_uses_official_commitlint_for_the_complete_pr_range() -> None:
    workflow = CI_WORKFLOW.read_text(encoding="utf-8")
    validator = RANGE_VALIDATOR.read_text(encoding="utf-8")

    assert "commit-messages:" in workflow
    assert "name: Commit Message Governance" in workflow
    assert "actions/setup-node@249970729cb0ef3589644e2896645e5dc5ba9c38" in workflow
    assert "node-version: 24" in workflow
    assert "npm ci --ignore-scripts --no-audit --no-fund" in workflow
    assert "scripts/test-commitlint.sh" in workflow
    assert "bash scripts/validate_commit_range.sh" in workflow
    assert "github.event.pull_request.base.sha" in workflow
    assert "github.event.pull_request.head.sha" in workflow
    assert "git rev-list --reverse" in validator
    assert "npm exec --prefix" in validator
    assert ".commitlintrc.json" in validator
    assert "uv run cz check --rev-range" not in workflow


def test_release_please_exception_is_identity_and_branch_bound() -> None:
    workflow = CI_WORKFLOW.read_text(encoding="utf-8")
    validator = RANGE_VALIDATOR.read_text(encoding="utf-8")

    assert "PR_AUTHOR:" in workflow
    assert "github-actions[bot]" in validator
    assert "release-please--branches--main--components--JameFirewall" in validator
    assert "41898282+github-actions[bot]@users.noreply.github.com" in validator
    assert "Release Please PR must contain exactly one generated release commit." in validator
    assert "commitlint.release.config.cjs" in validator


def test_required_ci_includes_commit_governance() -> None:
    workflow = CI_WORKFLOW.read_text(encoding="utf-8")

    required_ci = workflow.split("  required-ci:", maxsplit=1)[1]
    assert "      - commit-messages" in required_ci
    assert "COMMIT_MESSAGES_RESULT:" in required_ci
    assert 'test "$COMMIT_MESSAGES_RESULT" = "success"' in required_ci

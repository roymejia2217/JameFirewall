"""Contracts for immutable published agent branches."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RULESET = ROOT / ".github/rulesets/agent-branch-immutability.json"
CI = ROOT / ".github/workflows/ci.yml"
VALIDATOR = ROOT / "scripts/validate_commit_range.sh"
HARNESS = ROOT / "scripts/test-commit-range.sh"
CONTRIBUTING = ROOT / "CONTRIBUTING.md"

RELEASE_BRANCH = "refs/heads/release-please--branches--main--components--JameFirewall"


def test_agent_branch_ruleset_blocks_history_rewrites_without_blocking_deletion() -> None:
    ruleset = json.loads(RULESET.read_text(encoding="utf-8"))

    assert ruleset["name"] == "agent-branch-immutability"
    assert ruleset["target"] == "branch"
    assert ruleset["enforcement"] == "active"
    assert ruleset["bypass_actors"] == []
    assert ruleset["conditions"]["ref_name"] == {
        "include": ["~ALL"],
        "exclude": ["~DEFAULT_BRANCH", RELEASE_BRANCH],
    }
    assert ruleset["rules"] == [{"type": "non_fast_forward"}]


def test_commit_range_governance_is_centralized_and_self_tested() -> None:
    workflow = CI.read_text(encoding="utf-8")

    assert "bash scripts/test-commit-range.sh" in workflow
    assert "bash scripts/validate_commit_range.sh" in workflow
    assert "git merge-tree --write-tree" not in workflow
    assert VALIDATOR.is_file()
    assert HARNESS.is_file()


def test_validator_uses_git_topology_and_pinned_commitlint_authority() -> None:
    validator = VALIDATOR.read_text(encoding="utf-8")

    for required in (
        "git merge-base --is-ancestor",
        "git merge-tree --write-tree",
        "npm exec --prefix",
        ".commitlintrc.json",
        "commitlint.release.config.cjs",
    ):
        assert required in validator


def test_contributor_contract_forbids_rewriting_published_agent_branches() -> None:
    contributing = CONTRIBUTING.read_text(encoding="utf-8")

    for required in (
        "published agent branch",
        "non-fast-forward",
        "Update branch",
        "force-with-lease",
        "Release Please",
    ):
        assert required in contributing

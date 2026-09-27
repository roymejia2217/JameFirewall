"""Repository-host governance contract for the protected default branch."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
RULESET_PATH = REPOSITORY_ROOT / ".github/rulesets/main-protection.json"
CODEOWNERS_PATH = REPOSITORY_ROOT / ".github/CODEOWNERS"

REQUIRED_STATUS_CONTEXTS = {"PR Governance", "Required CI"}


def _ruleset() -> dict[str, Any]:
    raw = json.loads(RULESET_PATH.read_text(encoding="utf-8"))
    return cast(dict[str, Any], raw)


def _rule(ruleset: dict[str, Any], rule_type: str) -> dict[str, Any]:
    rules = cast(list[dict[str, Any]], ruleset["rules"])
    matches = [rule for rule in rules if rule["type"] == rule_type]
    assert len(matches) == 1, f"expected exactly one {rule_type!r} rule"
    return matches[0]


def test_main_ruleset_is_active_default_branch_fail_closed() -> None:
    ruleset = _ruleset()

    assert ruleset["name"] == "main-protection"
    assert ruleset["target"] == "branch"
    assert ruleset["enforcement"] == "active"
    assert ruleset["bypass_actors"] == []
    assert ruleset["conditions"]["ref_name"] == {
        "include": ["~DEFAULT_BRANCH"],
        "exclude": [],
    }

    rule_types = {rule["type"] for rule in ruleset["rules"]}
    assert {"deletion", "non_fast_forward", "required_linear_history"} <= rule_types


def test_pull_requests_are_rebase_only_without_single_maintainer_review_deadlock() -> None:
    parameters = _rule(_ruleset(), "pull_request")["parameters"]

    assert parameters["allowed_merge_methods"] == ["rebase"]
    assert parameters["required_review_thread_resolution"] is True
    assert parameters["dismiss_stale_reviews_on_push"] is True
    assert parameters["required_approving_review_count"] == 0
    assert parameters["require_last_push_approval"] is False

    # The sole CODEOWNER is also the identity used by repository agents. GitHub
    # forbids authors from approving their own PR, so requiring CODEOWNER review
    # would make native agent auto-merge impossible rather than safer.
    assert parameters["require_code_owner_review"] is False


def test_required_checks_are_strict_and_exact() -> None:
    parameters = _rule(_ruleset(), "required_status_checks")["parameters"]

    assert parameters["strict_required_status_checks_policy"] is True
    assert parameters["do_not_enforce_on_create"] is False
    contexts = {item["context"] for item in parameters["required_status_checks"]}
    assert contexts == REQUIRED_STATUS_CONTEXTS


def test_codeowners_remains_an_explicit_ownership_map() -> None:
    codeowners = CODEOWNERS_PATH.read_text(encoding="utf-8")

    assert "/.github/ @roymejia2217" in codeowners
    assert "/tests/windows/ @roymejia2217" in codeowners
    assert "/scripts/validate_pr_description.py @roymejia2217" in codeowners

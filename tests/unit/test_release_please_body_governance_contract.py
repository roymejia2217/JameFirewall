"""Contracts preserving Release Please's native pull-request body format."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PACKAGE = ROOT / "package.json"
PACKAGE_LOCK = ROOT / "package-lock.json"
ADAPTER = ROOT / "scripts/validate_release_please_pr.cjs"
PR_WORKFLOW = ROOT / ".github/workflows/pr-audit-gate.yml"
CI_WORKFLOW = ROOT / ".github/workflows/ci.yml"
VERIFY_GATE = ROOT / "verify_gate.sh"

RELEASE_BRANCH = "release-please--branches--main--components--JameFirewall"


def test_release_please_parser_version_matches_action_runtime() -> None:
    package = json.loads(PACKAGE.read_text(encoding="utf-8"))

    assert package["devDependencies"]["release-please"] == "17.3.0"
    lock = json.loads(PACKAGE_LOCK.read_text(encoding="utf-8"))
    assert lock["packages"]["node_modules/release-please"]["version"] == "17.3.0"
    assert package["scripts"]["test:release-please-body"] == (
        "node scripts/validate_release_please_pr.cjs --self-test"
    )


def test_release_body_adapter_delegates_to_upstream_parsers() -> None:
    adapter = ADAPTER.read_text(encoding="utf-8")

    assert "release-please/build/src/util/pull-request-body.js" in adapter
    assert "release-please/build/src/util/pull-request-title.js" in adapter
    assert "PullRequestBody.parse" in adapter
    assert "PullRequestTitle.parse" in adapter


def test_pr_governance_routes_release_body_to_upstream_adapter() -> None:
    workflow = PR_WORKFLOW.read_text(encoding="utf-8")

    assert "Validate standard pull request description" in workflow
    assert "Validate Release Please pull request body" in workflow
    assert "jamefirewall-release-roymejia2217[bot]" in workflow
    assert "github-actions[bot]" not in workflow
    assert RELEASE_BRANCH in workflow
    assert "node scripts/validate_release_please_pr.cjs" in workflow
    assert "--body-file" in workflow
    assert "--title" in workflow


def test_ci_does_not_apply_human_body_template_to_release_please_pr() -> None:
    workflow = CI_WORKFLOW.read_text(encoding="utf-8")

    step = workflow.split("- name: Validate current pull request description", maxsplit=1)[1]
    step = step.split("- name: Validate formatting and lint", maxsplit=1)[0]

    assert "jamefirewall-release-roymejia2217[bot]" in step
    assert RELEASE_BRANCH in step
    assert "!=" in step or "!(" in step


def test_local_gate_self_tests_upstream_release_body_adapter() -> None:
    gate = VERIFY_GATE.read_text(encoding="utf-8")

    assert "npm run test:release-please-body" in gate

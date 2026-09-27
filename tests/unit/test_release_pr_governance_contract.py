"""Contracts for typed Release Please pull-request title governance."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/pr-audit-gate.yml"
ACTION_PIN = "amannn/action-semantic-pull-request@48f256284bd46cdaab1048c3721360e808335d50"
RELEASE_BRANCH = "release-please--branches--main--components--JameFirewall"


def test_release_pr_identity_is_closed_over_bot_repo_and_branch() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")

    assert "github-actions[bot]" in workflow
    assert "github.event.pull_request.head.repo.full_name == github.repository" in workflow
    assert RELEASE_BRANCH in workflow


def test_standard_and_release_titles_use_the_same_pinned_semantic_action() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")

    assert workflow.count(ACTION_PIN) == 2
    assert "Validate standard Conventional Commits pull request title" in workflow
    assert "Validate Release Please pull request title" in workflow


def test_release_title_profile_is_chore_main_with_semver_subject() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")

    release_step = workflow.split("- name: Validate Release Please pull request title", maxsplit=1)[
        1
    ]
    release_step = release_step.split("- name: Validate pull request description", maxsplit=1)[0]

    assert "chore" in release_step
    assert "main" in release_step
    assert "requireScope: true" in release_step
    assert "subjectPattern:" in release_step
    assert "release [0-9]+" in release_step


def test_standard_profile_does_not_add_main_scope() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")

    standard_step = workflow.split(
        "- name: Validate standard Conventional Commits pull request title", maxsplit=1
    )[1]
    standard_step = standard_step.split(
        "- name: Validate Release Please pull request title", maxsplit=1
    )[0]

    assert "\n            main\n" not in standard_step

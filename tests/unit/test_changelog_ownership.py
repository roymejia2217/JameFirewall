"""Behavioral contracts for CHANGELOG.md single-writer ownership."""

from __future__ import annotations

import pytest
from scripts import validate_changelog_ownership as ownership


def _common() -> dict[str, str]:
    return {
        "base_sha": "base",
        "head_sha": "head",
        "pr_title": "fix(core): ordinary change",
        "pr_author": "roymejia2217",
        "head_branch": "fix/ordinary-change",
        "head_repository": "roymejia2217/JameFirewall",
        "repository": "roymejia2217/JameFirewall",
    }


def test_standard_pull_request_rejects_direct_changelog_edit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        ownership,
        "changes",
        lambda _base, _head: [ownership.Change("M", "CHANGELOG.md")],
    )
    monkeypatch.setattr(ownership, "base_has_towncrier", lambda _base: True)

    with pytest.raises(
        ownership.ChangelogOwnershipError,
        match=r"ordinary pull requests must not edit CHANGELOG\.md",
    ):
        ownership.validate(**_common())


def test_towncrier_bootstrap_is_structural_and_self_extinguishing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        ownership,
        "changes",
        lambda _base, _head: [ownership.Change("M", "CHANGELOG.md")],
    )
    monkeypatch.setattr(ownership, "base_has_towncrier", lambda _base: False)
    monkeypatch.setattr(ownership, "head_has_towncrier_authority", lambda: True)

    assert ownership.validate(**_common()) == "towncrier-bootstrap"


def test_release_please_must_not_modify_changelog(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        ownership,
        "changes",
        lambda _base, _head: [
            ownership.Change("M", "pyproject.toml"),
            ownership.Change("M", "CHANGELOG.md"),
        ],
    )
    kwargs = _common()
    kwargs.update(
        {
            "pr_title": "chore(main): release 0.3.0",
            "pr_author": "github-actions[bot]",
            "head_branch": ownership.RELEASE_BRANCH,
        }
    )

    with pytest.raises(
        ownership.ChangelogOwnershipError,
        match=r"outside version metadata|must not modify CHANGELOG",
    ):
        ownership.validate(**kwargs)


def test_release_preparation_consumes_only_towncrier_fragments(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        ownership,
        "changes",
        lambda _base, _head: [
            ownership.Change("M", "CHANGELOG.md"),
            ownership.Change("D", "changelog.d/101.fixed.md"),
            ownership.Change("D", "changelog.d/+internal.internal.md"),
        ],
    )
    monkeypatch.setattr(ownership, "validate_release_changelog", lambda *_args, **_kwargs: None)

    kwargs = _common()
    kwargs.update(
        {
            "pr_title": "chore(release): prepare changelog 0.3.0",
            "head_branch": "release/changelog-0.3.0",
        }
    )

    assert ownership.validate(**kwargs) == "release-preparation"


def test_release_preparation_rejects_template_or_new_fragment_changes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        ownership,
        "changes",
        lambda _base, _head: [
            ownership.Change("M", "CHANGELOG.md"),
            ownership.Change("M", "changelog.d/towncrier-template.md"),
            ownership.Change("A", "changelog.d/102.fixed.md"),
        ],
    )

    kwargs = _common()
    kwargs.update(
        {
            "pr_title": "chore(release): prepare changelog 0.3.0",
            "head_branch": "release/changelog-0.3.0",
        }
    )

    with pytest.raises(
        ownership.ChangelogOwnershipError,
        match="may only delete consumed fragments",
    ):
        ownership.validate(**kwargs)

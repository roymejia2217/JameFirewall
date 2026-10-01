#!/usr/bin/env python3
"""Enforce single-writer ownership of CHANGELOG.md around Towncrier."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

from scripts.validate_release_changelog import validate as validate_release_changelog

ROOT = Path(__file__).resolve().parents[1]
CHANGELOG = "CHANGELOG.md"
FRAGMENT_PREFIX = "changelog.d/"
RELEASE_BRANCH = "release-please--branches--main--components--JameFirewall"
RELEASE_PREP_BRANCH = re.compile(
    r"^release/changelog-(?P<version>[0-9]+\.[0-9]+\.[0-9]+"
    r"(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?)$"
)
RELEASE_PREP_TITLE = re.compile(
    r"^chore\(release\): prepare changelog (?P<version>[0-9]+\.[0-9]+\.[0-9]+"
    r"(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?)$"
)
RELEASE_PLEASE_FILES = {
    ".release-please-manifest.json",
    "pyproject.toml",
    "src/jame_firewall/__init__.py",
}


class ChangelogOwnershipError(ValueError):
    """Raised when a pull request violates changelog ownership."""


@dataclass(frozen=True)
class Change:
    status: str
    path: str


def git_text(*args: str) -> str:
    completed = subprocess.run(
        ["git", *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout


def changes(base_sha: str, head_sha: str) -> list[Change]:
    output = git_text("diff", "--name-status", f"{base_sha}...{head_sha}")
    result: list[Change] = []
    for raw in output.splitlines():
        fields = raw.split("\t")
        if len(fields) < 2:
            continue
        status = fields[0]
        path = fields[-1]
        result.append(Change(status=status, path=path))
    return result


def base_has_towncrier(base_sha: str) -> bool:
    completed = subprocess.run(
        ["git", "show", f"{base_sha}:pyproject.toml"],
        check=True,
        capture_output=True,
        text=True,
    )
    return "[tool.towncrier]" in completed.stdout


def head_has_towncrier_authority() -> bool:
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    release_config = json.loads((ROOT / "release-please-config.json").read_text(encoding="utf-8"))
    package = release_config["packages"]["."]
    return "[tool.towncrier]" in pyproject and package.get("skip-changelog") is True


def is_release_please(
    *,
    pr_author: str,
    head_branch: str,
    head_repository: str,
    repository: str,
) -> bool:
    return (
        pr_author == "jamefirewall-release-roymejia2217[bot]"
        and head_branch == RELEASE_BRANCH
        and head_repository == repository
    )


def release_prep_version(*, head_branch: str, pr_title: str) -> str | None:
    branch_match = RELEASE_PREP_BRANCH.fullmatch(head_branch)
    title_match = RELEASE_PREP_TITLE.fullmatch(pr_title)
    if branch_match is None or title_match is None:
        return None
    branch_version = branch_match.group("version")
    title_version = title_match.group("version")
    if branch_version != title_version:
        raise ChangelogOwnershipError(
            f"release preparation version mismatch: branch={branch_version}, title={title_version}"
        )
    return branch_version


def validate_release_please_files(items: list[Change]) -> None:
    paths = {item.path for item in items}
    unexpected = sorted(paths - RELEASE_PLEASE_FILES)
    if unexpected:
        raise ChangelogOwnershipError(
            f"Release Please changed files outside version metadata: {unexpected}"
        )
    if CHANGELOG in paths:
        raise ChangelogOwnershipError("Release Please must not modify CHANGELOG.md")


def validate_release_prep(items: list[Change], version: str) -> None:
    paths = {item.path for item in items}
    if CHANGELOG not in paths:
        raise ChangelogOwnershipError("release preparation must update CHANGELOG.md")

    fragment_changes = [item for item in items if item.path.startswith(FRAGMENT_PREFIX)]
    if not fragment_changes:
        raise ChangelogOwnershipError("release preparation must consume Towncrier fragments")

    support_files = {
        "changelog.d/.gitkeep",
        "changelog.d/towncrier-template.md",
    }
    fragment_pattern = re.compile(
        r"^changelog\.d/[^/]+\."
        r"(added|changed|deprecated|removed|fixed|security|internal)\.md$"
    )
    invalid_fragment_changes = [
        item
        for item in fragment_changes
        if item.path in support_files
        or not item.status.startswith("D")
        or fragment_pattern.fullmatch(item.path) is None
    ]
    if invalid_fragment_changes:
        rendered = [f"{item.status}:{item.path}" for item in invalid_fragment_changes]
        raise ChangelogOwnershipError(
            f"release preparation may only delete consumed fragments: {rendered}"
        )

    allowed = {CHANGELOG} | {item.path for item in fragment_changes}
    unexpected = sorted(paths - allowed)
    if unexpected:
        raise ChangelogOwnershipError(
            f"release preparation changed files outside Towncrier output: {unexpected}"
        )

    validate_release_changelog(version, require_clean_fragments=True)


def validate(
    *,
    base_sha: str,
    head_sha: str,
    pr_title: str,
    pr_author: str,
    head_branch: str,
    head_repository: str,
    repository: str,
) -> str:
    items = changes(base_sha, head_sha)
    paths = {item.path for item in items}

    if is_release_please(
        pr_author=pr_author,
        head_branch=head_branch,
        head_repository=head_repository,
        repository=repository,
    ):
        validate_release_please_files(items)
        return "release-please"

    prep_version = release_prep_version(head_branch=head_branch, pr_title=pr_title)
    if prep_version is not None:
        if head_repository != repository:
            raise ChangelogOwnershipError("release preparation must originate in this repository")
        validate_release_prep(items, prep_version)
        return "release-preparation"

    if CHANGELOG in paths:
        if not base_has_towncrier(base_sha) and head_has_towncrier_authority():
            return "towncrier-bootstrap"
        raise ChangelogOwnershipError(
            "ordinary pull requests must not edit CHANGELOG.md; add a Towncrier fragment instead"
        )

    return "standard"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-sha", required=True)
    parser.add_argument("--head-sha", required=True)
    parser.add_argument("--pr-title", required=True)
    parser.add_argument("--pr-author", required=True)
    parser.add_argument("--head-branch", required=True)
    parser.add_argument("--head-repository", required=True)
    parser.add_argument("--repository", required=True)
    args = parser.parse_args()

    mode = validate(
        base_sha=args.base_sha,
        head_sha=args.head_sha,
        pr_title=args.pr_title,
        pr_author=args.pr_author,
        head_branch=args.head_branch,
        head_repository=args.head_repository,
        repository=args.repository,
    )
    print(f"changelog_mode={mode}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

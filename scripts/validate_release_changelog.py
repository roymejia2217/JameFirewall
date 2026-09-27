#!/usr/bin/env python3
"""Validate the Keep a Changelog release boundary owned by Towncrier."""

from __future__ import annotations

import argparse
import re
import tempfile
import tomllib
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CHANGELOG = ROOT / "CHANGELOG.md"
PYPROJECT = ROOT / "pyproject.toml"
FRAGMENTS = ROOT / "changelog.d"

ALLOWED_CATEGORIES = ("Added", "Changed", "Deprecated", "Removed", "Fixed", "Security")
FORBIDDEN_DECORATION = ("✨", "🐛", "⚡", "♻️", "📚", "🔧")
RELEASE_HEADING = re.compile(
    r"^## \[(?P<version>[^\]]+)\]\([^\n]+\) - (?P<date>\d{4}-\d{2}-\d{2})$",
    re.MULTILINE,
)


class ChangelogContractError(ValueError):
    """Raised when release changelog metadata violates the repository contract."""


def project_version(path: Path = PYPROJECT) -> str:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    return str(data["project"]["version"])


def validate_preamble(text: str) -> None:
    for required in (
        "# Changelog",
        "Keep a Changelog 1.1.0",
        "Semantic Versioning 2.0.0",
        "## [Unreleased]",
        "<!-- towncrier release notes start -->",
    ):
        if required not in text:
            raise ChangelogContractError(
                f"CHANGELOG.md is missing required declaration: {required}"
            )

    for token in FORBIDDEN_DECORATION:
        if token in text:
            raise ChangelogContractError(f"decorative changelog token is forbidden: {token}")


def release_block(text: str, version: str) -> str:
    matches = [
        match for match in RELEASE_HEADING.finditer(text) if match.group("version") == version
    ]
    if len(matches) != 1:
        raise ChangelogContractError(
            f"CHANGELOG.md must contain exactly one release entry for {version}"
        )

    match = matches[0]
    date.fromisoformat(match.group("date"))
    next_release = RELEASE_HEADING.search(text, match.end())
    end = next_release.start() if next_release else len(text)
    return text[match.end() : end]


def validate_release_categories(block: str) -> None:
    headings = re.findall(r"^### (.+)$", block, flags=re.MULTILINE)
    if not headings:
        raise ChangelogContractError("release changelog must contain at least one category")

    unknown = [heading for heading in headings if heading not in ALLOWED_CATEGORIES]
    if unknown:
        raise ChangelogContractError(f"unsupported changelog categories: {unknown}")

    positions = [ALLOWED_CATEGORIES.index(heading) for heading in headings]
    if positions != sorted(positions):
        raise ChangelogContractError("changelog categories are not in Keep a Changelog order")

    bullets = [line for line in block.splitlines() if line.startswith("- ")]
    if not bullets:
        raise ChangelogContractError("release changelog must contain at least one notable change")


def pending_fragments(directory: Path = FRAGMENTS) -> list[Path]:
    ignored = {".gitkeep", "towncrier-template.md"}
    return sorted(
        path for path in directory.iterdir() if path.is_file() and path.name not in ignored
    )


def validate(version: str, *, require_clean_fragments: bool = False) -> None:
    text = CHANGELOG.read_text(encoding="utf-8")
    validate_preamble(text)
    block = release_block(text, version)
    validate_release_categories(block)

    if require_clean_fragments:
        pending = pending_fragments()
        if pending:
            names = ", ".join(path.name for path in pending)
            raise ChangelogContractError(f"release has unconsumed Towncrier fragments: {names}")


def self_test() -> None:
    valid = """# Changelog

The format is based on Keep a Changelog 1.1.0.
This project follows Semantic Versioning 2.0.0.

## [Unreleased]

<!-- towncrier release notes start -->

## [1.2.3](https://example.invalid/v1.2.3) - 2026-01-02

### Added

- Added a fixture.
"""
    validate_preamble(valid)
    validate_release_categories(release_block(valid, "1.2.3"))

    invalid = valid.replace("### Added", "### ✨ Added")
    try:
        validate_preamble(invalid)
    except ChangelogContractError:
        pass
    else:
        raise AssertionError("decorative changelog heading was accepted")

    wrong_order = valid.replace(
        "### Added\n\n- Added a fixture.",
        "### Fixed\n\n- Fixed a fixture.\n\n### Added\n\n- Added a fixture.",
    )
    try:
        validate_release_categories(release_block(wrong_order, "1.2.3"))
    except ChangelogContractError:
        pass
    else:
        raise AssertionError("out-of-order changelog categories were accepted")

    with tempfile.TemporaryDirectory(prefix="jamefirewall-changelog-") as temp:
        directory = Path(temp)
        (directory / ".gitkeep").write_text("", encoding="utf-8")
        (directory / "towncrier-template.md").write_text("", encoding="utf-8")
        if pending_fragments(directory):
            raise AssertionError("ignored Towncrier support files were treated as fragments")

        (directory / "101.fixed.md").write_text("Fixture\n", encoding="utf-8")
        names = [path.name for path in pending_fragments(directory)]
        if names != ["101.fixed.md"]:
            raise AssertionError(f"unexpected pending fragment set: {names}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version")
    parser.add_argument("--require-clean-fragments", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        self_test()
        return 0

    version = args.version or project_version()
    validate(version, require_clean_fragments=args.require_clean_fragments)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

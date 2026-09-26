#!/usr/bin/env python3
"""Validate the repository's standards-based pull-request description contract.

Policy sources:
- Google Engineering Practices: a change description must explain what changed and why.
- GitHub pull-request guidance: templates should capture change context, testing notes,
  and related issues.

This module is only the deterministic adapter that turns those documented expectations
into a required status check. It is not the source of the policy.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

REQUIRED_HEADINGS = ("What", "Why", "Testing", "Related issues")
HEADING_PATTERN = re.compile(r"^##\s+(.+?)\s*$", re.MULTILINE)
COMMENT_PATTERN = re.compile(r"<!--.*?-->", re.DOTALL)
PLACEHOLDER_PATTERN = re.compile(r"^(?:todo|tbd|n/?a|[-\u2013\u2014])\.?$", re.IGNORECASE)


class DescriptionError(ValueError):
    """Raised when a pull-request description violates the documented contract."""


def sections(body: str) -> dict[str, str]:
    matches = list(HEADING_PATTERN.finditer(body))
    headings = [match.group(1).strip() for match in matches]

    unexpected = [heading for heading in headings if heading not in REQUIRED_HEADINGS]
    if unexpected:
        raise DescriptionError(f"unexpected level-2 section(s): {', '.join(unexpected)}")

    duplicates = [heading for heading in REQUIRED_HEADINGS if headings.count(heading) > 1]
    if duplicates:
        raise DescriptionError(f"duplicate required section(s): {', '.join(duplicates)}")

    missing = [heading for heading in REQUIRED_HEADINGS if heading not in headings]
    if missing:
        raise DescriptionError(f"missing required section(s): {', '.join(missing)}")

    if tuple(headings) != REQUIRED_HEADINGS:
        raise DescriptionError("required sections are out of order")

    found: dict[str, str] = {}
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(body)
        found[headings[index]] = body[match.end() : end]
    return found


def normalized_content(value: str) -> str:
    return COMMENT_PATTERN.sub("", value).strip()


def validate_description(body: str) -> None:
    found = sections(body)

    for heading in ("What", "Why", "Testing"):
        content = normalized_content(found[heading])
        if not content:
            raise DescriptionError(f"required section is empty: {heading}")
        if PLACEHOLDER_PATTERN.fullmatch(content):
            raise DescriptionError(f"required section contains only a placeholder: {heading}")

    related = normalized_content(found["Related issues"])
    if not related:
        raise DescriptionError("required section is empty: Related issues")
    if PLACEHOLDER_PATTERN.fullmatch(related) and related.casefold().rstrip(".") != "n/a":
        raise DescriptionError("Related issues contains only a placeholder")


def self_test() -> None:
    valid = """## What

Harden the native Windows acceptance boundary.

## Why

A successful build must not be treated as proof that the packaged application works.

## Testing

Required CI passed on Linux and native Windows, including the packaged-runtime contract.

## Related issues

None.
"""
    validate_description(valid)

    invalid_heading = valid.replace("## Testing", "## Verification")
    try:
        validate_description(invalid_heading)
    except DescriptionError:
        pass
    else:
        raise AssertionError("unknown headings must be rejected")

    invalid_order = valid.replace(
        "## Why\n\nA successful build must not be treated as proof that the packaged application works.\n\n"
        "## Testing",
        "## Testing\n\nRequired CI passed on Linux and native Windows, including the packaged-runtime contract.\n\n"
        "## Why",
    )
    try:
        validate_description(invalid_order)
    except DescriptionError:
        pass
    else:
        raise AssertionError("out-of-order sections must be rejected")

    placeholder = valid.replace(
        "Required CI passed on Linux and native Windows, including the packaged-runtime contract.",
        "TBD",
    )
    try:
        validate_description(placeholder)
    except DescriptionError:
        pass
    else:
        raise AssertionError("placeholder-only required content must be rejected")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--body-file", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        self_test()
        print("pull request description contract: ok")
        return 0

    if args.body_file is None:
        parser.error("--body-file is required unless --self-test is used")

    try:
        validate_description(args.body_file.read_text(encoding="utf-8"))
    except (DescriptionError, OSError) as exc:
        print(f"pull request description contract: failed: {exc}", file=sys.stderr)
        return 2

    print("pull request description contract: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

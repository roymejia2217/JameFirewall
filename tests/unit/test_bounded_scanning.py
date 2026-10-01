"""Bounded traversal must retain errors and never resolve links out of scope."""

import os
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from jame_firewall.infrastructure.os.filesystem import OSFileSystemAdapter, ScanLimits


def test_complete_scan_deduplicates_overlapping_roots_and_ignores_nonexecutables(
    tmp_path: Path,
) -> None:
    child = tmp_path / "child"
    child.mkdir()
    executable = child / "app.EXE"
    executable.touch()
    (child / "readme.txt").touch()
    result = OSFileSystemAdapter().find_executables([child, tmp_path, child])
    assert result.complete
    assert result.executables == (executable,)
    assert result.visited_directories == 2
    assert result.visited_entries == 3


@pytest.mark.parametrize("root_kind", ["missing", "file", "link", "ancestor-link"])
def test_unexamined_root_is_reported(tmp_path: Path, root_kind: str) -> None:
    root = tmp_path / "root"
    if root_kind == "file":
        root.touch()
    elif "link" in root_kind:
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "app.exe").touch()
        root.symlink_to(outside, target_is_directory=True)
        if root_kind == "ancestor-link":
            nested = outside / "nested"
            nested.mkdir()
            (nested / "other.exe").touch()
            root = root / "nested"
    result = OSFileSystemAdapter().find_executables([root])
    assert not result.complete
    assert not result.executables
    assert result.issues


def test_child_links_and_cycles_are_not_followed(tmp_path: Path) -> None:
    root, outside = tmp_path / "root", tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (outside / "escaped.exe").touch()
    (root / "local.exe").touch()
    (root / "junction").symlink_to(outside, target_is_directory=True)
    (root / "cycle").symlink_to(root, target_is_directory=True)
    (root / "alias.exe").symlink_to(outside / "escaped.exe")
    result = OSFileSystemAdapter().find_executables([root])
    assert not result.complete
    assert result.executables == (root / "local.exe",)
    assert len(result.issues) == 3


@pytest.mark.parametrize(
    "limits",
    [ScanLimits(max_directories=1), ScanLimits(max_entries=1), ScanLimits(max_executables=1)],
)
def test_resource_limits_report_incomplete_results(tmp_path: Path, limits: ScanLimits) -> None:
    child = tmp_path / "child"
    child.mkdir()
    (tmp_path / "first.exe").touch()
    (child / "second.exe").touch()
    result = OSFileSystemAdapter(limits=limits).find_executables([tmp_path])
    assert not result.complete
    assert result.visited_directories <= limits.max_directories
    assert result.visited_entries <= limits.max_entries
    assert len(result.executables) <= limits.max_executables
    assert "Límite" in result.detail


def test_deadline_is_checked_before_any_filesystem_call(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = MagicMock(side_effect=[0.0, 2.0, 2.0])
    read = MagicMock(side_effect=AssertionError("deadline must stop traversal"))
    monkeypatch.setattr(os, "scandir", read)
    result = OSFileSystemAdapter(limits=ScanLimits(max_seconds=1), clock=clock).find_executables(
        [tmp_path]
    )
    assert not result.complete
    assert "duración" in result.detail
    read.assert_not_called()


def test_access_error_is_reported_and_other_roots_continue(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    denied, allowed = tmp_path / "denied", tmp_path / "allowed"
    denied.mkdir()
    allowed.mkdir()
    target = allowed / "app.exe"
    target.touch()
    original = os.scandir

    def read(path: Path) -> AbstractContextManager[Iterator[os.DirEntry[str]]]:
        if path == denied:
            raise PermissionError("denied by fixture")
        return original(path)

    monkeypatch.setattr(os, "scandir", read)
    result = OSFileSystemAdapter().find_executables([denied, allowed])
    assert not result.complete
    assert result.executables == (target,)
    assert result.issues[0].path == denied


def test_issue_storage_is_bounded(tmp_path: Path) -> None:
    result = OSFileSystemAdapter(limits=ScanLimits(max_issues=2)).find_executables(
        [tmp_path / f"missing-{number}" for number in range(10)]
    )
    assert not result.complete
    assert len(result.issues) == 2


def test_retained_path_memory_is_bounded(tmp_path: Path) -> None:
    (tmp_path / "app.exe").touch()
    result = OSFileSystemAdapter(limits=ScanLimits(max_retained_chars=1)).find_executables(
        [tmp_path]
    )
    assert not result.complete
    assert "memoria" in result.detail
    assert not result.executables


@pytest.mark.parametrize(
    "create",
    [
        lambda: ScanLimits(max_entries=0),
        lambda: ScanLimits(max_seconds=float("inf")),
        lambda: ScanLimits(max_roots=-1),
    ],
)
def test_invalid_limits_fail_at_construction(create: Callable[[], ScanLimits]) -> None:
    with pytest.raises(ValueError):
        create()


def test_missing_configured_child_is_reported_even_with_its_parent(tmp_path: Path) -> None:
    (tmp_path / "app.exe").touch()
    missing = tmp_path / "missing"
    result = OSFileSystemAdapter().find_executables([tmp_path, missing])
    assert not result.complete
    assert any(issue.path == missing for issue in result.issues)

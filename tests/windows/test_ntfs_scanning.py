"""Native NTFS traversal boundaries and finite scanner budgets."""

from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from jame_firewall.core.cancellation import CancellationToken
from jame_firewall.core.exceptions import OperationCancelledError
from jame_firewall.infrastructure.os.filesystem import OSFileSystemAdapter, ScanLimits

pytestmark = [
    pytest.mark.windows_only,
    pytest.mark.skipif(sys.platform != "win32", reason="requires native NTFS semantics"),
]


def _native_command(name: str, *args: str) -> None:
    executable = Path(os.environ["SystemRoot"]) / "System32" / name
    result = subprocess.run(
        [str(executable), *args],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    assert result.returncode == 0, (
        f"{name} failed ({result.returncode}): {result.stdout}; {result.stderr}"
    )


def _junction(link: Path, target: Path) -> None:
    _native_command("cmd.exe", "/d", "/c", "mklink", "/J", str(link), str(target))


def test_scan_omits_external_junction_and_cycle_without_following_them(tmp_path: Path) -> None:
    root = tmp_path / "root"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    inside_exe = root / "inside.exe"
    outside_exe = outside / "outside.exe"
    inside_exe.write_bytes(b"fixture")
    outside_exe.write_bytes(b"fixture")
    external_link = root / "external-link"
    cycle = root / "cycle"
    created: list[Path] = []
    try:
        for link, target in ((external_link, outside), (cycle, root)):
            _junction(link, target)
            created.append(link)
        result = OSFileSystemAdapter().find_executables([root])
        assert result.executables == (inside_exe,)
        assert result.complete is False
        assert {issue.path for issue in result.issues} == {external_link, cycle}
        assert all("reanálisis" in issue.reason for issue in result.issues)
        assert result.visited_directories == 1
        assert result.visited_entries == 3
        assert outside_exe.is_file()
    finally:
        # Remove the reparse point itself; never recurse through it during cleanup.
        for link in reversed(created):
            os.rmdir(link)


@pytest.mark.parametrize("descendant", [False, True], ids=["root-junction", "ancestor-junction"])
def test_scan_rejects_junction_roots_and_junction_ancestors(
    tmp_path: Path, descendant: bool
) -> None:
    outside = tmp_path / "outside"
    child = outside / "child"
    child.mkdir(parents=True)
    outside_exe = child / "outside.exe"
    outside_exe.write_bytes(b"fixture")
    link = tmp_path / "linked-root"
    _junction(link, outside)
    try:
        configured_root = link / "child" if descendant else link
        result = OSFileSystemAdapter().find_executables([configured_root])
        assert result.executables == ()
        assert result.complete is False
        assert len(result.issues) == 1
        assert result.issues[0].path == configured_root
        assert "reanálisis" in result.issues[0].reason
        assert result.visited_directories == 0
        assert result.visited_entries == 0
        assert outside_exe.is_file()
    finally:
        os.rmdir(link)


def test_scan_reports_real_ntfs_directory_list_access_denial(tmp_path: Path) -> None:
    root = tmp_path / "root"
    denied = root / "denied"
    denied.mkdir(parents=True)
    visible_exe = root / "visible.exe"
    visible_exe.write_bytes(b"fixture")
    (denied / "hidden.exe").write_bytes(b"fixture")
    try:
        # Explicit Everyone deny overrides the runner's administrative group grants.
        _native_command("icacls.exe", str(denied), "/deny", "*S-1-1-0:(RD)")
        with pytest.raises(PermissionError), os.scandir(denied) as entries:
            next(entries, None)
        result = OSFileSystemAdapter().find_executables([root])
        assert result.executables == (visible_exe,)
        assert result.complete is False
        assert any(
            issue.path == denied and "PermissionError" in issue.reason for issue in result.issues
        ), result
        assert "Escaneo incompleto" in result.detail
    finally:
        _native_command("icacls.exe", str(denied), "/remove:d", "*S-1-1-0")
    # ACL restoration is itself verified before pytest cleans the real directory.
    with os.scandir(denied) as restored:
        assert [entry.name for entry in restored] == ["hidden.exe"]


@pytest.mark.parametrize(
    ("budget", "reason"),
    [
        ("entries", "entradas"),
        ("directories", "carpetas"),
        ("executables", "ejecutables"),
    ],
)
def test_scan_applies_finite_budgets_to_real_windows_trees(
    tmp_path: Path, budget: str, reason: str
) -> None:
    root = tmp_path / "large-tree"
    root.mkdir()
    if budget == "directories":
        for index in range(40):
            child = root / f"child-{index:03d}"
            child.mkdir()
            (child / "program.exe").write_bytes(b"fixture")
        limits = ScanLimits(max_directories=5)
    else:
        for index in range(200):
            (root / f"program-{index:03d}.exe").write_bytes(b"fixture")
        limits = (
            ScanLimits(max_entries=17) if budget == "entries" else ScanLimits(max_executables=7)
        )

    result = OSFileSystemAdapter(limits=limits).find_executables([root])
    assert result.complete is False
    assert any(f"Límite de {reason}" in issue.reason for issue in result.issues), result
    assert result.visited_entries <= limits.max_entries
    assert result.visited_directories <= limits.max_directories
    assert len(result.executables) <= limits.max_executables
    assert len(result.issues) <= limits.max_issues
    if budget == "entries":
        assert result.visited_entries == 17
    elif budget == "executables":
        assert len(result.executables) == 7


def test_scan_honors_cancellation_during_real_directory_enumeration(tmp_path: Path) -> None:
    root = tmp_path / "cancellation-tree"
    root.mkdir()
    for index in range(200):
        (root / f"program-{index:03d}.exe").write_bytes(b"fixture")
    token = CancellationToken()
    clock_calls = 0

    def cancellation_clock() -> float:
        nonlocal clock_calls
        clock_calls += 1
        # Deterministic cancellation after traversal has started, without replacing I/O.
        if clock_calls == 40:
            token.cancel()
        return time.monotonic()

    scanner = OSFileSystemAdapter(cancellation=token, clock=cancellation_clock)
    with pytest.raises(OperationCancelledError):
        scanner.find_executables([root])
    assert clock_calls == 40
    assert len(list(root.iterdir())) == 200


def test_scan_rejects_pre_cancelled_operation_on_windows(tmp_path: Path) -> None:
    token = CancellationToken()
    token.cancel()
    with pytest.raises(OperationCancelledError):
        OSFileSystemAdapter(cancellation=token).find_executables([tmp_path])

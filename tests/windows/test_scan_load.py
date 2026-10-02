"""Real NTFS workload profiles for the bounded executable scanner."""

from __future__ import annotations

import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import psutil
import pytest

from jame_firewall.infrastructure.os.filesystem import OSFileSystemAdapter

pytestmark = [
    pytest.mark.windows_only,
    pytest.mark.windows_load,
    pytest.mark.skipif(sys.platform != "win32", reason="requires native NTFS"),
]


@pytest.mark.parametrize(
    ("entry_count", "executable_count"),
    [(1_000, 100), (10_000, 1_000), (200_000, 5_000)],
    ids=["small", "large", "huge"],
)
def test_scanner_handles_real_ntfs_load_profiles(
    tmp_path: Path,
    benchmark: Any,
    record_testsuite_property: Callable[[str, object], None],
    entry_count: int,
    executable_count: int,
) -> None:
    """Measure a single real scan; fixture creation stays outside the timed region."""
    root = tmp_path / "load"
    root.mkdir()
    preparation_started = time.perf_counter()
    for index in range(entry_count):
        extension = "exe" if index < executable_count else "dat"
        (root / f"{index:06d}.{extension}").touch()
    preparation_seconds = time.perf_counter() - preparation_started

    scanner = OSFileSystemAdapter()
    process = psutil.Process()
    rss_before = process.memory_info().rss
    result = benchmark.pedantic(
        scanner.find_executables,
        args=([root],),
        iterations=1,
        rounds=1,
        warmup_rounds=0,
    )
    rss_after = process.memory_info().rss

    assert result.complete, result.detail
    assert result.visited_directories == 1
    assert result.visited_entries == entry_count
    assert len(result.executables) == executable_count
    assert len(set(result.executables)) == executable_count

    profile = workload_profile(entry_count)
    record_testsuite_property(f"scan_{profile}_entries", result.visited_entries)
    record_testsuite_property(f"scan_{profile}_executables", len(result.executables))
    record_testsuite_property(f"scan_{profile}_fixture_seconds", round(preparation_seconds, 3))
    record_testsuite_property(f"scan_{profile}_benchmark_seconds", benchmark.stats.stats.mean)
    record_testsuite_property(f"scan_{profile}_rss_before_bytes", rss_before)
    record_testsuite_property(f"scan_{profile}_rss_after_bytes", rss_after)


def workload_profile(entry_count: int) -> str:
    """Give stable report names for the three checked-in workload tiers."""
    return {1_000: "small", 10_000: "large", 200_000: "huge"}[entry_count]

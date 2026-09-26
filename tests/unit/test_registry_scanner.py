"""Pruebas unitarias para WindowsRegistryAdapter."""

from pathlib import Path

import pytest

from jame_firewall.infrastructure.os.registry_scanner import WindowsRegistryAdapter


def test_registry_scanner_discovers_standard_roots(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Simular directorios existentes
    pf = tmp_path / "ProgramFiles"
    adobe_dir = pf / "Adobe"
    adobe_dir.mkdir(parents=True)
    monkeypatch.setenv("ProgramFiles", str(pf))

    adapter = WindowsRegistryAdapter()
    paths = adapter.discover_creative_paths()

    assert any("Adobe" in str(p) for p in paths)


def test_registry_scanner_queries_winreg(monkeypatch: pytest.MonkeyPatch) -> None:
    adapter = WindowsRegistryAdapter()
    paths = adapter.discover_creative_paths()
    assert isinstance(paths, list)

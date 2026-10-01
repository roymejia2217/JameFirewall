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


def test_discovery_checks_shutdown_cancellation() -> None:
    from jame_firewall.core.cancellation import CancellationToken
    from jame_firewall.core.exceptions import OperationCancelledError

    token = CancellationToken()
    token.cancel()
    with pytest.raises(OperationCancelledError):
        WindowsRegistryAdapter(cancellation=token).discover_creative_paths()


def test_discovery_reports_deadline_instead_of_partial_success() -> None:
    from jame_firewall.infrastructure.os.registry_scanner import DiscoveryError

    ticks = iter([0.0, 31.0])
    with pytest.raises(DiscoveryError, match="duración"):
        WindowsRegistryAdapter(clock=lambda: next(ticks)).discover_creative_paths()


def test_discovery_keeps_links_visible(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    pf = tmp_path / "pf"
    pf.mkdir()
    link = pf / "Adobe"
    link.symlink_to(outside, target_is_directory=True)
    monkeypatch.setenv("ProgramFiles", str(pf))
    assert link in WindowsRegistryAdapter().discover_creative_paths()


def test_registry_limit_refuses_partial_result(monkeypatch: pytest.MonkeyPatch) -> None:
    import sys
    from unittest.mock import MagicMock

    from jame_firewall.infrastructure.os.registry_scanner import DiscoveryError

    registry = MagicMock()
    registry.QueryInfoKey.return_value = (4097, 0, 0)
    monkeypatch.setitem(sys.modules, "winreg", registry)
    with pytest.raises(DiscoveryError, match="claves"):
        WindowsRegistryAdapter().discover_creative_paths()


def test_denied_registry_is_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    import sys
    from unittest.mock import MagicMock

    from jame_firewall.infrastructure.os.registry_scanner import DiscoveryError

    registry = MagicMock()
    registry.OpenKey.side_effect = PermissionError("denied")
    monkeypatch.setitem(sys.modules, "winreg", registry)
    with pytest.raises(DiscoveryError, match="inaccesible"):
        WindowsRegistryAdapter().discover_creative_paths()

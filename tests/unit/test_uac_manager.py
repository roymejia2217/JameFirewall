"""Pruebas unitarias para WindowsUACAdapter."""

import sys
from unittest.mock import MagicMock

import pytest

from jame_firewall.infrastructure.os.uac_manager import WindowsUACAdapter


def test_uac_manager_non_windows_behavior() -> None:
    if sys.platform != "win32":
        adapter = WindowsUACAdapter()
        assert adapter.is_admin() is True
        assert adapter.request_elevation() is True


def test_uac_manager_windows_mock(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "win32")
    adapter = WindowsUACAdapter()

    # Simular ctypes
    mock_windll = MagicMock()
    mock_windll.shell32.IsUserAnAdmin.return_value = 1
    mock_windll.shell32.ShellExecuteW.return_value = 42

    import ctypes

    monkeypatch.setattr(ctypes, "windll", mock_windll, raising=False)

    assert adapter.is_admin() is True
    assert adapter.request_elevation() is True

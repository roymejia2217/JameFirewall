"""Configuración global de Pytest y fixtures para JameFirewall."""

import sys
import types
from unittest.mock import MagicMock

import pytest

# 1. Protección de importación para entornos no-Windows (Linux/macOS CI)
if sys.platform != "win32" and "winreg" not in sys.modules:
    mock_winreg = types.ModuleType("winreg")
    mock_winreg.HKEY_LOCAL_MACHINE = 0x80000002  # type: ignore[attr-defined]
    mock_winreg.HKEY_CURRENT_USER = 0x80000001  # type: ignore[attr-defined]
    mock_winreg.KEY_READ = 0x20019  # type: ignore[attr-defined]
    mock_winreg.OpenKey = MagicMock()  # type: ignore[attr-defined]
    mock_winreg.QueryInfoKey = MagicMock(return_value=(0, 0, 0))  # type: ignore[attr-defined]
    mock_winreg.EnumKey = MagicMock()  # type: ignore[attr-defined]
    mock_winreg.QueryValueEx = MagicMock(return_value=("", 1))  # type: ignore[attr-defined]
    sys.modules["winreg"] = mock_winreg

from tests.fakes.fake_config import MemoryConfigAdapter
from tests.fakes.fake_firewall import InMemoryFirewallAdapter
from tests.fakes.fake_registry import FakeRegistryAdapter
from tests.fakes.fake_uac import FakeUACAdapter


@pytest.fixture
def fake_firewall() -> InMemoryFirewallAdapter:
    """Retorna una instancia doble en memoria de FirewallPort."""
    return InMemoryFirewallAdapter()


@pytest.fixture
def fake_uac() -> FakeUACAdapter:
    """Retorna un doble de UAC con privilegios administrativos por defecto."""
    return FakeUACAdapter(initial_is_admin=True)


@pytest.fixture
def fake_registry() -> FakeRegistryAdapter:
    """Retorna un doble de Registro de Windows."""
    return FakeRegistryAdapter()


@pytest.fixture
def fake_config_repo() -> MemoryConfigAdapter:
    """Retorna un doble de persistencia de configuración en memoria."""
    return MemoryConfigAdapter()

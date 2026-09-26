"""Windows-native Tk/ttk UI contract tests executed with pytest."""

import sys
from unittest.mock import MagicMock

import pytest

from jame_firewall.infrastructure.container import AppContainer
from jame_firewall.presentation import constants as C
from jame_firewall.presentation.windows.config_window import ConfigWindow
from jame_firewall.presentation.windows.main_window import JameFirewallApp

pytestmark = [
    pytest.mark.windows_only,
    pytest.mark.skipif(sys.platform != "win32", reason="requires native Windows Tk"),
]


def test_main_window_exposes_and_wires_primary_controls(monkeypatch: pytest.MonkeyPatch) -> None:
    """Build the real Tk widget tree and invoke every primary command binding."""
    events: list[str] = []

    monkeypatch.setattr(JameFirewallApp, "_start_async_init", lambda self: None)
    monkeypatch.setattr(
        JameFirewallApp, "_on_refresh_clicked", lambda self: events.append("refresh")
    )
    monkeypatch.setattr(JameFirewallApp, "_on_config_clicked", lambda self: events.append("config"))
    monkeypatch.setattr(JameFirewallApp, "_on_block_clicked", lambda self: events.append("block"))
    monkeypatch.setattr(
        JameFirewallApp, "_on_unblock_clicked", lambda self: events.append("unblock")
    )

    container = MagicMock(spec=AppContainer)
    app = JameFirewallApp(container)

    try:
        app.root.update_idletasks()
        assert app.root.title() == C.APP_TITLE
        assert app.root.winfo_exists() == 1
        assert app.refresh_button.cget("text") == C.BTN_REFRESH
        assert app.config_button.cget("text") == C.BTN_CONFIG
        assert app.block_button.cget("text") == C.BTN_BLOCK
        assert app.unblock_button.cget("text") == C.BTN_UNBLOCK

        app.refresh_button.invoke()
        app.config_button.invoke()
        app.block_button.invoke()
        app.unblock_button.invoke()

        assert events == ["refresh", "config", "block", "unblock"]
    finally:
        app.dispatcher.shutdown()
        app.root.destroy()


def test_config_window_exposes_expected_controls(monkeypatch: pytest.MonkeyPatch) -> None:
    """Build the real configuration modal and verify its actionable controls."""
    monkeypatch.setattr(JameFirewallApp, "_start_async_init", lambda self: None)

    container = MagicMock(spec=AppContainer)
    app = JameFirewallApp(container)
    manage_config = MagicMock()
    manage_config.get_directories.return_value = []

    try:
        dialog = ConfigWindow(parent=app.root, manage_config_uc=manage_config)
        dialog.update_idletasks()

        assert dialog.title() == C.LBL_CONFIG_TITLE
        assert dialog.btn_add.cget("text") == C.BTN_ADD
        assert dialog.btn_remove.cget("text") == C.BTN_REMOVE
        assert dialog.btn_auto.cget("text") == C.BTN_AUTODETECT
        assert dialog.btn_save.cget("text") == C.BTN_SAVE
        assert dialog.btn_cancel.cget("text") == C.BTN_CANCEL

        dialog.btn_cancel.invoke()
        app.root.update_idletasks()
        assert dialog.winfo_exists() == 0
    finally:
        app.dispatcher.shutdown()
        app.root.destroy()

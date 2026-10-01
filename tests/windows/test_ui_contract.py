"""Windows-native Tk/ttk UI contract tests executed with pytest."""

import sys
import time
from pathlib import Path
from threading import Event
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

        manage_config = MagicMock()
        manage_config.get_directories.return_value = []
        dialog = ConfigWindow(
            parent=app.root,
            manage_config_uc=manage_config,
            dispatcher=app.dispatcher,
        )
        dialog.update_idletasks()

        assert dialog.title() == C.LBL_CONFIG_TITLE
        assert dialog.btn_add.cget("text") == C.BTN_ADD
        assert dialog.btn_remove.cget("text") == C.BTN_REMOVE
        assert dialog.btn_auto.cget("text") == C.BTN_AUTODETECT
        assert dialog.btn_save.cget("text") == C.BTN_SAVE
        assert dialog.btn_cancel.cget("text") == C.BTN_CANCEL

        discovery_started = Event()
        release_discovery = Event()
        heartbeat = Event()

        def slow_discovery(paths: list[Path]) -> list[Path]:
            discovery_started.set()
            assert release_discovery.wait(10), "discovery was never released"
            return [*paths, Path("C:/discovered")]

        manage_config.discover_directories.side_effect = slow_discovery
        notice = MagicMock()
        monkeypatch.setattr(
            "jame_firewall.presentation.windows.config_window.messagebox.showinfo", notice
        )
        monkeypatch.setattr(
            "jame_firewall.presentation.windows.config_window.messagebox.showerror", notice
        )
        try:
            dialog.btn_auto.invoke()
            deadline = time.monotonic() + 5
            while not discovery_started.is_set() and time.monotonic() < deadline:
                app.root.update()
                time.sleep(0.01)
            assert discovery_started.is_set()
            assert str(dialog.btn_add.cget("state")) == "disabled"
            assert str(dialog.btn_remove.cget("state")) == "disabled"
            assert str(dialog.btn_auto.cget("state")) == "disabled"
            assert str(dialog.btn_save.cget("state")) == "disabled"

            app.root.after(0, heartbeat.set)
            app.root.update()
            assert heartbeat.is_set(), "Tk heartbeat stopped during registry discovery"
            assert not release_discovery.is_set()

            dialog.btn_cancel.invoke()
            app.root.update_idletasks()
            assert dialog.winfo_exists() == 0
        finally:
            release_discovery.set()
            deadline = time.monotonic() + 5
            while not app.dispatcher.is_idle and time.monotonic() < deadline:
                app.root.update()
                time.sleep(0.01)
            assert app.dispatcher.is_idle
            app.dispatcher.drain_queues()
            app.dispatcher.shutdown(wait=True)
        notice.assert_not_called()
    finally:
        app.dispatcher.shutdown()
        app.root.destroy()

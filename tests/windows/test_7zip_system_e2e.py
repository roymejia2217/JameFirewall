"""Windows system E2E using a real 7-Zip install and Windows Defender Firewall."""

from __future__ import annotations

import contextlib
import json
import os
import sys
import time
import tkinter as tk
from collections.abc import Callable
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from tests.windows.firewall_probe import (
    FirewallRuleSnapshot,
    managed_rule_names,
    probe_firewall_rules,
)

from jame_firewall.infrastructure.container import AppContainer
from jame_firewall.infrastructure.persistence.json_config import JsonConfigAdapter
from jame_firewall.presentation import constants as C
from jame_firewall.presentation.windows.config_window import ConfigWindow
from jame_firewall.presentation.windows.main_window import JameFirewallApp

pytestmark = [
    pytest.mark.windows_only,
    pytest.mark.windows_system,
    pytest.mark.skipif(sys.platform != "win32", reason="requires native Windows"),
]

STARTUP_TIMEOUT_SECONDS = 60.0
FIREWALL_OPERATION_TIMEOUT_SECONDS = 120.0


def _pump_until(
    app: JameFirewallApp,
    predicate: Callable[[], bool],
    *,
    timeout: float,
) -> None:
    """Pump the real Tk event loop until an asynchronous UI condition becomes true."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        app.root.update()
        if predicate():
            return
        time.sleep(0.05)
    diagnostics = (
        f"status={app.status_label.cget('text')!r}; "
        f"block_state={app.block_button.cget('state')!r}; "
        f"unblock_state={app.unblock_button.cget('state')!r}; "
        f"log={_log_text(app)!r}"
    )
    raise AssertionError(f"timed out waiting for JameFirewall UI state; {diagnostics}")


def _log_text(app: JameFirewallApp) -> str:
    return str(app.log_text.text.get("1.0", "end-1c"))


def _rules_for_programs(
    rule_names: tuple[str, ...],
    programs: set[str],
) -> list[FirewallRuleSnapshot]:
    return [
        rule
        for rule in probe_firewall_rules(rule_names)
        if rule.get("Program", "").casefold() in programs
    ]


def _find_config_dialog(app: JameFirewallApp) -> ConfigWindow:
    dialogs = [child for child in app.root.winfo_children() if isinstance(child, ConfigWindow)]
    assert len(dialogs) == 1
    return dialogs[0]


def test_7zip_path_toggle_creates_and_removes_real_firewall_rules(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Exercise settings -> add 7-Zip -> activate -> verify -> deactivate -> verify."""
    program_files = os.environ.get("ProgramFiles")
    assert program_files, "ProgramFiles must exist on the Windows runner"

    seven_zip_dir = Path(program_files) / "7-Zip"
    seven_zip_cli = seven_zip_dir / "7z.exe"
    assert seven_zip_cli.is_file(), "the pinned 7-Zip fixture was not installed"

    expected_paths = {path.resolve() for path in seven_zip_dir.rglob("*.exe") if path.is_file()}
    expected_executables = {str(path).casefold() for path in expected_paths}
    expected_rule_names = managed_rule_names(expected_paths)
    assert str(seven_zip_cli.resolve()).casefold() in expected_executables

    baseline_dir = tmp_path / "baseline-empty"
    baseline_dir.mkdir()
    config_path = tmp_path / "jamefirewall-system-e2e.json"
    config_path.write_text(
        json.dumps({"directories": [str(baseline_dir)]}),
        encoding="utf-8",
    )

    container = AppContainer.create_production(config_path=config_path)
    container.unblock_use_case.execute()
    assert not _rules_for_programs(expected_rule_names, expected_executables)

    app: JameFirewallApp | None = None
    try:
        app = JameFirewallApp(container)
        _pump_until(
            app,
            lambda: app.status_label.cget("text") != C.STATUS_LOADING,
            timeout=STARTUP_TIMEOUT_SECONDS,
        )

        monkeypatch.setattr(
            "jame_firewall.presentation.windows.config_window.filedialog.askdirectory",
            lambda **_: str(seven_zip_dir),
        )

        original_config = config_path.read_bytes()
        original_directories = container.config_use_case.get_directories()

        # Cancel discards an edited draft without persisting or reporting success.
        app.config_button.invoke()
        app.root.update()
        cancelled_dialog = _find_config_dialog(app)
        cancelled_dialog.btn_add.invoke()
        assert str(seven_zip_dir) in cancelled_dialog.current_dirs
        cancelled_dialog.btn_cancel.invoke()
        app.root.update()
        assert not cancelled_dialog.winfo_exists()
        assert config_path.read_bytes() == original_config
        assert container.config_use_case.get_directories() == original_directories
        assert C.MSG_CONF_SAVED not in _log_text(app)

        app.config_button.invoke()
        app.root.update()
        dialog = _find_config_dialog(app)
        dialog.btn_add.invoke()
        edited_directories = list(dialog.current_dirs)
        assert str(seven_zip_dir) in edited_directories

        # A real atomic-write failure must leave the modal open for a safe retry.
        error_notice = MagicMock()

        def fail_replace(source: object, destination: object) -> None:
            raise OSError("injected configuration replacement failure")

        with monkeypatch.context() as failing_save:
            failing_save.setattr(
                "jame_firewall.infrastructure.persistence.json_config.os.replace", fail_replace
            )
            failing_save.setattr(
                "jame_firewall.presentation.windows.config_window.messagebox.showerror",
                error_notice,
            )
            dialog.btn_save.invoke()
            app.root.update()

        error_notice.assert_called_once()
        assert dialog.winfo_exists()
        assert dialog.current_dirs == edited_directories
        assert config_path.read_bytes() == original_config
        assert container.config_use_case.get_directories() == original_directories
        assert C.MSG_CONF_SAVED not in _log_text(app)

        dialog.btn_save.invoke()
        app.root.update()
        assert not dialog.winfo_exists()
        assert seven_zip_dir.resolve() in container.config_use_case.get_directories()
        assert seven_zip_dir.resolve() in JsonConfigAdapter(config_path).load_paths()
        assert C.MSG_CONF_SAVED in _log_text(app)

        # A configured folder can disappear after saving: partial scans must not mutate.
        missing_root = tmp_path / "removed-after-configuration"
        missing_root.mkdir()
        monkeypatch.setattr(
            "jame_firewall.presentation.windows.config_window.filedialog.askdirectory",
            lambda **_: str(missing_root),
        )
        app.config_button.invoke()
        app.root.update()
        incomplete_dialog = _find_config_dialog(app)
        incomplete_dialog.btn_add.invoke()
        incomplete_dialog.btn_save.invoke()
        app.root.update()
        assert missing_root in container.config_use_case.get_directories()
        assert missing_root in JsonConfigAdapter(config_path).load_paths()
        missing_root.rmdir()

        app.block_button.invoke()
        _pump_until(
            app,
            lambda: str(app.block_button.cget("state")) == "normal",
            timeout=FIREWALL_OPERATION_TIMEOUT_SECONDS,
        )
        incomplete_log = _log_text(app)
        assert app.status_label.cget("text") == C.STATUS_PARTIAL, incomplete_log
        assert "Escaneo incompleto" in incomplete_log, incomplete_log
        assert str(missing_root) in incomplete_log, incomplete_log
        assert "no se crearon reglas" in incomplete_log, incomplete_log
        assert C.MSG_SUCCESS_BLOCK not in incomplete_log, incomplete_log
        assert not _rules_for_programs(expected_rule_names, expected_executables)

        app.config_button.invoke()
        app.root.update()
        repaired_dialog = _find_config_dialog(app)
        missing_index = repaired_dialog.current_dirs.index(str(missing_root))
        repaired_dialog.listbox.selection_set(missing_index)
        repaired_dialog.btn_remove.invoke()
        repaired_dialog.btn_save.invoke()
        app.root.update()
        assert missing_root not in container.config_use_case.get_directories()
        assert missing_root not in JsonConfigAdapter(config_path).load_paths()

        app.block_button.invoke()
        _pump_until(
            app,
            lambda: str(app.block_button.cget("state")) == "normal",
            timeout=FIREWALL_OPERATION_TIMEOUT_SECONDS,
        )

        block_log = _log_text(app)
        assert "Error de bloqueo:" not in block_log, block_log
        assert C.MSG_SUCCESS_BLOCK in block_log, block_log

        created_rules = _rules_for_programs(expected_rule_names, expected_executables)
        assert created_rules, "JameFirewall created no 7-Zip firewall rules"

        by_program: dict[str, list[FirewallRuleSnapshot]] = {}
        for rule in created_rules:
            by_program.setdefault(rule["Program"].casefold(), []).append(rule)

        assert set(by_program) == expected_executables
        for executable, rules in by_program.items():
            assert {rule["Direction"] for rule in rules} == {"Inbound", "Outbound"}, executable
            assert all(rule["Action"] == "Block" for rule in rules), executable
            assert all(rule["Enabled"] == "True" for rule in rules), executable

        assert app.status_label.cget("text") == C.STATUS_PROTECTED
        assert app.rule_count_label.cget("text") == (
            f"Reglas: {2 * len(expected_executables)}; "
            f"ejecutables cubiertos: {len(expected_executables)}/{len(expected_executables)}"
        )

        app.unblock_button.invoke()
        _pump_until(
            app,
            lambda: str(app.unblock_button.cget("state")) == "normal",
            timeout=FIREWALL_OPERATION_TIMEOUT_SECONDS,
        )

        unblock_log = _log_text(app)
        assert "Error de desbloqueo:" not in unblock_log, unblock_log
        assert C.MSG_SUCCESS_UNBLOCK in unblock_log, unblock_log
        assert not _rules_for_programs(expected_rule_names, expected_executables)
        assert app.status_label.cget("text") == C.STATUS_UNPROTECTED
    finally:
        with contextlib.suppress(Exception):
            container.unblock_use_case.execute()
        if app is not None:
            with contextlib.suppress(Exception):
                app.dispatcher.shutdown()
            with contextlib.suppress(tk.TclError):
                app.root.destroy()

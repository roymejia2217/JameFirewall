"""Windows system E2E using a real 7-Zip install and Windows Defender Firewall."""

from __future__ import annotations

import contextlib
import json
import os
import subprocess
import sys
import time
import tkinter as tk
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

import pytest

from jame_firewall.infrastructure.container import AppContainer
from jame_firewall.presentation import constants as C
from jame_firewall.presentation.windows.config_window import ConfigWindow
from jame_firewall.presentation.windows.main_window import JameFirewallApp

pytestmark = [
    pytest.mark.windows_only,
    pytest.mark.windows_system,
    pytest.mark.skipif(sys.platform != "win32", reason="requires native Windows"),
]

STARTUP_TIMEOUT_SECONDS = 60.0
FIREWALL_OPERATION_TIMEOUT_SECONDS = 240.0


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


def _firewall_rules() -> list[dict[str, str]]:
    """Read JameFirewall rules through the native Windows Firewall PowerShell API."""
    script = r"""
$rules = Get-NetFirewallRule -DisplayName '* jame-block' -ErrorAction SilentlyContinue
$items = foreach ($rule in $rules) {
    $filters = @(Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $rule)
    foreach ($filter in $filters) {
        [PSCustomObject]@{
            DisplayName = $rule.DisplayName
            Direction = [string]$rule.Direction
            Action = [string]$rule.Action
            Enabled = [string]$rule.Enabled
            Program = [string]$filter.Program
        }
    }
}
if ($items) {
    $items | ConvertTo-Json -Compress
} else {
    '[]'
}
"""
    completed = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    raw: Any = json.loads(completed.stdout)
    if isinstance(raw, dict):
        raw = [raw]
    return cast(list[dict[str, str]], raw)


def _rules_for_programs(programs: set[str]) -> list[dict[str, str]]:
    return [rule for rule in _firewall_rules() if rule.get("Program", "").casefold() in programs]


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

    expected_executables = {
        str(path.resolve()).casefold() for path in seven_zip_dir.glob("*.exe") if path.is_file()
    }
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
    assert not _rules_for_programs(expected_executables)

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

        app.config_button.invoke()
        app.root.update()
        dialog = _find_config_dialog(app)

        dialog.btn_add.invoke()
        assert str(seven_zip_dir) in dialog.current_dirs

        dialog.btn_save.invoke()
        app.root.update()
        assert seven_zip_dir.resolve() in container.config_use_case.get_directories()

        app.block_button.invoke()
        _pump_until(
            app,
            lambda: app.block_button.cget("state") == "normal",
            timeout=FIREWALL_OPERATION_TIMEOUT_SECONDS,
        )

        block_log = _log_text(app)
        assert "Error de bloqueo:" not in block_log, block_log
        assert C.MSG_SUCCESS_BLOCK in block_log, block_log

        created_rules = _rules_for_programs(expected_executables)
        assert created_rules, "JameFirewall created no 7-Zip firewall rules"

        by_program: dict[str, list[dict[str, str]]] = {}
        for rule in created_rules:
            by_program.setdefault(rule["Program"].casefold(), []).append(rule)

        assert set(by_program) == expected_executables
        for executable, rules in by_program.items():
            assert {rule["Direction"] for rule in rules} == {"Inbound", "Outbound"}, executable
            assert all(rule["Action"] == "Block" for rule in rules), executable
            assert all(rule["Enabled"] == "True" for rule in rules), executable

        assert app.status_label.cget("text") == C.STATUS_PROTECTED
        assert app.rule_count_label.cget("text") == f"Reglas: {len(expected_executables)}"

        app.unblock_button.invoke()
        _pump_until(
            app,
            lambda: app.unblock_button.cget("state") == "normal",
            timeout=FIREWALL_OPERATION_TIMEOUT_SECONDS,
        )

        unblock_log = _log_text(app)
        assert "Error de desbloqueo:" not in unblock_log, unblock_log
        assert C.MSG_SUCCESS_UNBLOCK in unblock_log, unblock_log
        assert not _rules_for_programs(expected_executables)
        assert app.status_label.cget("text") == C.STATUS_UNPROTECTED
    finally:
        with contextlib.suppress(Exception):
            container.unblock_use_case.execute()
        if app is not None:
            with contextlib.suppress(Exception):
                app.dispatcher.shutdown()
            with contextlib.suppress(tk.TclError):
                app.root.destroy()

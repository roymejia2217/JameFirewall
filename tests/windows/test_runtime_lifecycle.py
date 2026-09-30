"""Native proofs for protected PowerShell selection and responsive Tk shutdown."""

import json
import sys
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from jame_firewall.core.cancellation import CancellationToken
from jame_firewall.infrastructure.container import AppContainer
from jame_firewall.infrastructure.os.process_runner import SystemProcessRunner
from jame_firewall.presentation.windows.main_window import JameFirewallApp

pytestmark = [
    pytest.mark.windows_only,
    pytest.mark.skipif(sys.platform != "win32", reason="requires Windows PowerShell and Tk"),
]


def test_native_powershell_cannot_load_user_executable_or_module(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "powershell.exe").write_bytes(b"untrusted executable")
    module = tmp_path / "modules" / "NetSecurity"
    module.mkdir(parents=True)
    (module / "NetSecurity.psm1").write_text(
        "function Get-NetFirewallRule { throw 'Untrusted module loaded' }; "
        "Export-ModuleMember -Function Get-NetFirewallRule",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PATH", str(tmp_path))
    monkeypatch.setenv("PSModulePath", str(module.parent))
    code, output, error = SystemProcessRunner().run(
        [
            "powershell",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "$ErrorActionPreference = 'Stop'; "
            "$command = Get-Command Get-NetFirewallRule; "
            "Get-NetFirewallRule -PolicyStore ActiveStore | Out-Null; "
            "[PSCustomObject]@{ModulePath=$command.Module.Path; "
            "SearchPath=$env:PSModulePath; PSHome=$PSHOME} | ConvertTo-Json -Compress",
        ]
    )
    assert code == 0, error
    result = json.loads(output)
    trusted = Path(result["PSHome"]) / "Modules"
    assert Path(result["SearchPath"]) == trusted
    assert Path(result["ModulePath"]).is_relative_to(trusted)


def test_native_close_waits_for_worker_and_drops_late_ui_updates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(JameFirewallApp, "_start_async_init", lambda self: None)
    container = MagicMock(spec=AppContainer)
    container.cancellation = CancellationToken()
    app = JameFirewallApp(container)
    started = threading.Event()
    release = threading.Event()
    finished = threading.Event()
    destroyed = threading.Event()
    late_updates: list[str] = []
    original_destroy = app.root.destroy

    def destroy() -> None:
        original_destroy()
        destroyed.set()

    monkeypatch.setattr(app.root, "destroy", destroy)

    def worker() -> None:
        started.set()
        assert release.wait(5)
        app.dispatcher.post_ui_update(lambda: late_updates.append("unsafe update"))
        finished.set()

    try:
        assert app.dispatcher.submit_background_task(worker)
        assert started.wait(5)
        app._on_close()
        app._on_close()
        app.root.update()
        assert app.root.winfo_exists() == 1
        assert not destroyed.is_set()
        release.set()
        assert finished.wait(5)
        deadline = time.monotonic() + 5
        while not destroyed.is_set() and time.monotonic() < deadline:
            app.root.update()
            destroyed.wait(0.01)
        assert destroyed.is_set()
        assert late_updates == []
    finally:
        release.set()
        app.dispatcher.shutdown(wait=True)
        if not destroyed.is_set():
            app.root.destroy()

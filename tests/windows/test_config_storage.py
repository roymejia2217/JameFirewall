"""Native Windows storage proofs using real ACLs and replacement failures."""

import ctypes
import subprocess
import sys
import time
from pathlib import Path

import pytest

from jame_firewall.core.exceptions import ConfigStorageError
from jame_firewall.infrastructure.persistence.json_config import JsonConfigAdapter
from jame_firewall.infrastructure.persistence.windows_security import WindowsConfigSecurity

pytestmark = [
    pytest.mark.windows_only,
    pytest.mark.skipif(sys.platform != "win32", reason="requires Windows filesystem security"),
]


def test_native_config_has_protected_acl_and_survives_sharing_violation(tmp_path: Path) -> None:
    security = WindowsConfigSecurity()
    config = tmp_path / "secure" / "config.json"
    adapter = JsonConfigAdapter(config, security=security)
    first = tmp_path / "first"
    assert adapter.save_paths([first])
    security.verify_file(config)
    assert adapter.load_paths() == [first.resolve()]
    previous = config.read_bytes()

    # A real reader that denies FILE_SHARE_DELETE must prevent Windows replacement.
    loader = getattr(ctypes, "WinDLL", None)
    assert loader is not None
    kernel = loader("kernel32", use_last_error=True, winmode=0x800)
    create = kernel.CreateFileW
    create.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
    ]
    create.restype = ctypes.c_void_p
    close = kernel.CloseHandle
    close.argtypes, close.restype = [ctypes.c_void_p], ctypes.c_int32
    handle = create(str(config), 0x80000000, 1, None, 3, 0, None)
    assert handle not in (None, ctypes.c_void_p(-1).value)
    try:
        assert not adapter.save_paths([tmp_path / "second"])
        assert config.read_bytes() == previous
        assert adapter.load_paths() == [first.resolve()]
        assert list(config.parent.iterdir()) == [config]
    finally:
        assert close(handle)
    assert adapter.save_paths([tmp_path / "second"])
    security.verify_file(config)
    assert adapter.load_paths() == [(tmp_path / "second").resolve()]


def test_native_storage_refuses_precreated_untrusted_directory(tmp_path: Path) -> None:
    directory = tmp_path / "precreated"
    directory.mkdir()
    sentinel = directory / "sentinel"
    sentinel.write_bytes(b"preserve")
    with pytest.raises(ConfigStorageError):
        WindowsConfigSecurity().ensure_directory(directory)
    assert sentinel.read_bytes() == b"preserve"


def test_native_storage_refuses_unprotected_existing_file(tmp_path: Path) -> None:
    security = WindowsConfigSecurity()
    directory = tmp_path / "secure"
    security.ensure_directory(directory)
    config = directory / "config.json"
    original = b'{"directories": []}'
    config.write_bytes(original)
    adapter = JsonConfigAdapter(config, security=security)
    with pytest.raises(ConfigStorageError):
        adapter.load_paths()
    assert not adapter.save_paths([tmp_path])
    assert config.read_bytes() == original


def test_native_location_ignores_programdata_environment_override(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ProgramData", str(tmp_path / "untrusted"))
    directory = WindowsConfigSecurity().default_directory()
    assert directory.name == "JameFirewall"
    assert directory.parent.is_dir()
    assert not directory.is_relative_to(tmp_path)


def test_native_termination_before_replace_preserves_previous_configuration(tmp_path: Path) -> None:
    config = tmp_path / "secure" / "config.json"
    adapter = JsonConfigAdapter(config, security=WindowsConfigSecurity())
    assert adapter.save_paths([tmp_path / "previous"])
    original = config.read_bytes()
    ready = tmp_path / "ready"
    script = """
import os, sys, time
from pathlib import Path
from jame_firewall.infrastructure.persistence.json_config import JsonConfigAdapter
from jame_firewall.infrastructure.persistence.windows_security import WindowsConfigSecurity
def pause_before_replace(source, destination):
    Path(sys.argv[2]).write_text('ready', encoding='utf-8')
    time.sleep(30)
    raise RuntimeError('fixture was not terminated')
os.replace = pause_before_replace
JsonConfigAdapter(Path(sys.argv[1]), security=WindowsConfigSecurity()).save_paths([Path(sys.argv[3])])
"""
    child = subprocess.Popen(
        [sys.executable, "-c", script, str(config), str(ready), str(tmp_path / "next")],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        deadline = time.monotonic() + 15
        while not ready.exists() and child.poll() is None and time.monotonic() < deadline:
            time.sleep(0.05)
        assert ready.exists(), "writer must reach the flushed temporary before termination"
        child.kill()
        child.communicate(timeout=5)
        assert config.read_bytes() == original
        assert adapter.load_paths() == [(tmp_path / "previous").resolve()]
    finally:
        if child.poll() is None:
            child.kill()
        child.communicate(timeout=5)

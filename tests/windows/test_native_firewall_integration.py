"""Native Windows Firewall round-trip contract using the real OS adapters."""

import shutil
import sys
import uuid
from pathlib import Path

import pytest

from jame_firewall.core.entities import SystemStatus
from jame_firewall.core.use_cases.audit_status import AuditFirewallStatusUseCase
from jame_firewall.core.use_cases.block_executables import BlockExecutablesUseCase
from jame_firewall.core.use_cases.unblock_rules import UnblockRulesUseCase
from jame_firewall.infrastructure.firewall.netsh_adapter import WindowsNetshAdapter
from jame_firewall.infrastructure.os.filesystem import OSFileSystemAdapter
from jame_firewall.infrastructure.os.process_runner import SystemProcessRunner
from jame_firewall.infrastructure.os.uac_manager import WindowsUACAdapter

pytestmark = [
    pytest.mark.windows_only,
    pytest.mark.skipif(sys.platform != "win32", reason="requires Windows Defender Firewall"),
]


def test_real_windows_firewall_block_audit_unblock_round_trip(tmp_path: Path) -> None:
    """Exercise scan -> netsh IN/OUT rules -> audit -> cleanup on an ephemeral rule namespace."""
    uac = WindowsUACAdapter()
    assert uac.is_admin(), "windows-native CI must run with administrative privileges"

    source_exe = Path(sys.executable)
    probe_exe = tmp_path / "jame-ci-probe.exe"
    shutil.copy2(source_exe, probe_exe)

    suffix = f"jame-ci-{uuid.uuid4().hex[:12]}"
    runner = SystemProcessRunner()
    firewall = WindowsNetshAdapter(runner=runner)
    scanner = OSFileSystemAdapter()

    block = BlockExecutablesUseCase(
        firewall=firewall,
        scanner=scanner,
        uac=uac,
        primary_suffix=suffix,
    )
    audit = AuditFirewallStatusUseCase(
        firewall=firewall,
        uac=uac,
        primary_suffix=suffix,
    )
    unblock = UnblockRulesUseCase(
        firewall=firewall,
        uac=uac,
        primary_suffix=suffix,
    )

    try:
        block_summary = block.execute([tmp_path])
        assert block_summary.blocked_count == 1
        assert block_summary.failed_count == 0

        rules = firewall.list_rules_with_suffix(suffix)
        assert rules == [f"{probe_exe.stem} {suffix}"]

        snapshot = audit.execute()
        assert snapshot.status == SystemStatus.PROTECTED
        assert snapshot.rule_count == 1
    finally:
        unblock.execute()

    final_snapshot = audit.execute()
    assert final_snapshot.status == SystemStatus.UNPROTECTED
    assert final_snapshot.rule_count == 0

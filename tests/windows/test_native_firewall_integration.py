"""Native Windows Firewall round-trip contract using the real OS adapters."""

import shutil
import sys
import uuid
from pathlib import Path

import pytest

from jame_firewall.core.entities import RuleDirection, SystemStatus
from jame_firewall.core.rule_identity import managed_rule_name
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


class NativeProbeRunner(SystemProcessRunner):
    """Preserva errores del proveedor para diagnosticar fallos de aceptación."""

    def run(self, args: list[str], timeout: float | None = 30.0) -> tuple[int, str, str]:
        result = super().run(args, timeout)
        if result[0] != 0:
            print("Firewall provider failure:", result[2])
        return result


def test_real_windows_firewall_block_audit_unblock_round_trip(tmp_path: Path) -> None:
    """Exercise scan -> netsh IN/OUT rules -> audit -> cleanup on an ephemeral rule namespace."""
    uac = WindowsUACAdapter()
    assert uac.is_admin(), "windows-native CI must run with administrative privileges"

    source_exe = Path(sys.executable)
    probe_exe = tmp_path / "jame-ci-probe.exe"
    shutil.copy2(source_exe, probe_exe)
    for directory in ("A", "B"):
        target = tmp_path / directory / "helper.exe"
        target.parent.mkdir()
        shutil.copy2(source_exe, target)

    suffix = f"jame-ci-{uuid.uuid4().hex[:12]}"
    runner = NativeProbeRunner()
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
        scanner=scanner,
        primary_suffix=suffix,
    )
    unblock = UnblockRulesUseCase(
        firewall=firewall,
        uac=uac,
        primary_suffix=suffix,
    )

    try:
        block_summary = block.execute([tmp_path])
        inventory = firewall.list_inventory([suffix])
        assert block_summary.blocked_count == 3, inventory
        assert block_summary.failed_count == 0, inventory
        assert len(inventory.rules) == 6
        assert {r.direction for r in inventory.rules} == set(RuleDirection)

        snapshot = audit.execute([tmp_path])
        assert snapshot.status == SystemStatus.PROTECTED
        assert snapshot.rule_count == 6

        inbound = managed_rule_name(probe_exe, RuleDirection.IN, suffix)
        outbound = managed_rule_name(probe_exe, RuleDirection.OUT, suffix)
        code, _, error = runner.run(
            [
                "powershell",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "$ErrorActionPreference = 'Stop'; "
                f"Remove-NetFirewallRule -Name '{inbound}' -PolicyStore PersistentStore; "
                f"Disable-NetFirewallRule -Name '{outbound}' -PolicyStore PersistentStore; "
                f"Set-NetFirewallRule -Name '{outbound}' -PolicyStore PersistentStore "
                "-Protocol TCP -RemotePort 443",
            ]
        )
        assert code == 0, error
        assert audit.execute([tmp_path]).status == SystemStatus.PARTIAL
        repaired = block.execute([tmp_path])
        assert repaired.blocked_count == 1
        assert repaired.skipped_count == 2
        assert repaired.failed_count == 0
        assert audit.execute([tmp_path]).status == SystemStatus.PROTECTED

        # Una regla habilitada pero restringida tampoco acredita cobertura completa.
        code, _, error = runner.run(
            [
                "powershell",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "$ErrorActionPreference = 'Stop'; "
                f"Set-NetFirewallRule -Name '{outbound}' -PolicyStore PersistentStore "
                "-Protocol TCP -RemotePort 443",
            ]
        )
        assert code == 0, error
        assert audit.execute([tmp_path]).status == SystemStatus.PARTIAL
        assert block.execute([tmp_path]).failed_count == 0
        assert audit.execute([tmp_path]).status == SystemStatus.PROTECTED
    finally:
        unblock.execute()

    final_snapshot = audit.execute([tmp_path])
    assert final_snapshot.status == SystemStatus.UNPROTECTED
    assert final_snapshot.rule_count == 0
